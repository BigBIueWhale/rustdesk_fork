#[cfg(not(target_os = "android"))]
use arboard::{ClipboardData, ClipboardFormat};
// R-X13 (§8): arboard LinuxClipboardKind/SetExtLinux were used only by the removed
// set_with_owner_marker_for_linux (Wayland uinput clipboard-paste SET) — import dropped.
#[cfg(target_os = "android")]
use hbb_common::protobuf::Message as _;
use hbb_common::{bail, log, message_proto::*, ResultType};
#[cfg(not(target_os = "android"))]
use std::sync::{
    mpsc::{self, SyncSender, TrySendError},
    OnceLock,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

pub const CLIPBOARD_NAME: &'static str = "clipboard";
#[cfg(feature = "unix-file-copy-paste")]
pub const FILE_CLIPBOARD_NAME: &'static str = "file-clipboard";
pub const CLIPBOARD_INTERVAL: u64 = 333;

// This format is used to store the flag in the clipboard.
const RUSTDESK_CLIPBOARD_OWNER_FORMAT: &'static str = "dyn.com.rustdesk.owner";

// Add special format for Excel XML Spreadsheet
const CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET: &'static str = "XML Spreadsheet";
/// Maximum bytes handed to native/platform clipboard handlers for one peer
/// clipboard item after optional zstd decompression. This mirrors the R-S7
/// decompression ceiling and makes the native clipboard handoff length-bounded;
/// it is not a process sandbox.
pub(crate) const MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_NATIVE_CLIPBOARD_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_NATIVE_CLIPBOARD_ITEMS: usize = 16;
pub(crate) const MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES: usize = 256;
#[cfg(all(target_os = "linux", feature = "unix-file-copy-paste"))]
pub(crate) const MAX_FILE_CLIPBOARD_URLS: usize = 1024;
#[cfg(all(target_os = "linux", feature = "unix-file-copy-paste"))]
pub(crate) const MAX_FILE_CLIPBOARD_URL_BYTES: usize = 4096;
#[cfg(all(target_os = "linux", feature = "unix-file-copy-paste"))]
pub(crate) const MAX_FILE_CLIPBOARD_TOTAL_BYTES: usize = 4 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const CLIPBOARD_UPDATE_QUEUE_CAPACITY: usize = 1;
#[cfg(target_os = "android")]
const ANDROID_SANITIZED_CLIPBOARD_MAGIC: [u8; 4] = *b"RDCB";
#[cfg(target_os = "android")]
const ANDROID_SANITIZED_CLIPBOARD_VERSION: u8 = 1;
#[cfg(target_os = "android")]
const ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES: usize = 16;

#[cfg(not(target_os = "android"))]
enum ClipboardUpdateRequest {
    SetMulti {
        multi_clipboards: Vec<Clipboard>,
        side: ClipboardSide,
    },
    #[cfg(all(target_os = "linux", feature = "unix-file-copy-paste"))]
    SetFiles {
        files: Vec<String>,
        side: ClipboardSide,
    },
    #[cfg(all(feature = "unix-file-copy-paste", not(target_os = "windows")))]
    TryEmptyFiles { side: ClipboardSide, conn_id: i32 },
}

fn rgba_clipboard_len(width: i32, height: i32) -> Option<usize> {
    let width = usize::try_from(width).ok()?;
    let height = usize::try_from(height).ok()?;
    if width == 0 || height == 0 {
        return None;
    }
    width.checked_mul(height)?.checked_mul(4)
}

pub(crate) fn native_clipboard_payload_within_limit(
    format: hbb_common::message_proto::ClipboardFormat,
    width: i32,
    height: i32,
    len: usize,
) -> bool {
    if len > MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES {
        return false;
    }
    if format == hbb_common::message_proto::ClipboardFormat::ImageRgba {
        return rgba_clipboard_len(width, height).is_some_and(|expected| expected == len);
    }
    true
}

fn clipboard_content_for_native(
    clipboard: &hbb_common::message_proto::Clipboard,
) -> ResultType<Vec<u8>> {
    let format = clipboard
        .format
        .enum_value()
        .map_err(|e| hbb_common::anyhow::anyhow!("invalid clipboard format: {e}"))?;
    let data = if clipboard.compress {
        hbb_common::compress::try_decompress(&clipboard.content)?
    } else {
        clipboard.content.to_vec()
    };
    if !native_clipboard_payload_within_limit(format, clipboard.width, clipboard.height, data.len())
    {
        bail!(
            "oversized or invalid clipboard payload before native handoff: format={format:?}, width={}, height={}, bytes={}",
            clipboard.width,
            clipboard.height,
            data.len()
        );
    }
    Ok(data)
}

fn sanitize_clipboard_for_native_proto(
    mut clipboard: hbb_common::message_proto::Clipboard,
) -> ResultType<Option<hbb_common::message_proto::Clipboard>> {
    let format = clipboard
        .format
        .enum_value()
        .map_err(|e| hbb_common::anyhow::anyhow!("invalid clipboard format: {e}"))?;
    if format == hbb_common::message_proto::ClipboardFormat::Special {
        if clipboard.special_name.len() > MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES {
            bail!(
                "clipboard special format has oversized name before native handoff: {} > {}",
                clipboard.special_name.len(),
                MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES
            );
        }
        if clipboard.special_name != CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET {
            log::warn!(
                "dropping unsupported clipboard special format before native handoff: bytes={}",
                clipboard.special_name.len()
            );
            return Ok(None);
        }
    } else {
        clipboard.special_name.clear();
    }
    let data = clipboard_content_for_native(&clipboard)?;
    clipboard.content = data.into();
    clipboard.compress = false;
    Ok(Some(clipboard))
}

fn sanitize_multi_clipboards_for_native_proto(
    clipboards: Vec<hbb_common::message_proto::Clipboard>,
) -> Option<MultiClipboards> {
    if clipboards.len() > MAX_NATIVE_CLIPBOARD_ITEMS {
        log::warn!(
            "dropping clipboard update with too many items before native handoff: {} > {}",
            clipboards.len(),
            MAX_NATIVE_CLIPBOARD_ITEMS
        );
        return None;
    }

    let mut total = 0usize;
    let mut sanitized = Vec::with_capacity(clipboards.len());
    for clipboard in clipboards {
        let clipboard = match sanitize_clipboard_for_native_proto(clipboard) {
            Ok(Some(clipboard)) => clipboard,
            Ok(None) => {
                log::warn!("dropping unsupported clipboard item before native handoff");
                continue;
            }
            Err(error) => {
                log::warn!("refusing invalid clipboard update before native handoff: {error}");
                return None;
            }
        };
        total = match total.checked_add(clipboard.content.len()) {
            Some(total) => total,
            None => {
                log::warn!("dropping clipboard update with overflowing aggregate payload size");
                return None;
            }
        };
        if total > MAX_NATIVE_CLIPBOARD_TOTAL_BYTES {
            log::warn!(
                "dropping clipboard update with oversized aggregate payload before native handoff: {} > {}",
                total,
                MAX_NATIVE_CLIPBOARD_TOTAL_BYTES
            );
            return None;
        }
        sanitized.push(clipboard);
    }
    if sanitized.is_empty() {
        return None;
    }
    Some(MultiClipboards {
        clipboards: sanitized,
        ..Default::default()
    })
}

#[cfg(all(target_os = "linux", feature = "unix-file-copy-paste"))]
fn is_linux_file_clipboard_url_for_side(file: &str, side: ClipboardSide) -> bool {
    if file.is_empty() || file.len() > MAX_FILE_CLIPBOARD_URL_BYTES || file.as_bytes().contains(&0)
    {
        return false;
    }
    let exclude_path =
        clipboard::platform::unix::fuse::get_exclude_paths(side == ClipboardSide::Client);
    let prefix = exclude_path.as_str();
    let Some(relative) = file
        .strip_prefix(prefix)
        .and_then(|value| value.strip_prefix('/'))
    else {
        return false;
    };
    if relative.is_empty() {
        return false;
    }
    !relative
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
}

#[cfg(all(target_os = "linux", feature = "unix-file-copy-paste"))]
pub(crate) fn sanitize_linux_file_clipboard_urls(
    files: Vec<String>,
    side: ClipboardSide,
) -> ResultType<Vec<String>> {
    if files.is_empty() {
        bail!("Linux file clipboard SET had no FUSE URLs");
    }
    if files.len() > MAX_FILE_CLIPBOARD_URLS {
        bail!(
            "Linux file clipboard SET had too many URLs: {} > {}",
            files.len(),
            MAX_FILE_CLIPBOARD_URLS
        );
    }

    let mut total = 0usize;
    let mut sanitized = Vec::with_capacity(files.len());
    for file in files {
        total = total
            .checked_add(file.len())
            .ok_or_else(|| hbb_common::anyhow::anyhow!("Linux file clipboard URL size overflow"))?;
        if total > MAX_FILE_CLIPBOARD_TOTAL_BYTES {
            bail!(
                "Linux file clipboard SET exceeded aggregate URL bytes: {} > {}",
                total,
                MAX_FILE_CLIPBOARD_TOTAL_BYTES
            );
        }
        if !is_linux_file_clipboard_url_for_side(&file, side) {
            bail!("Linux file clipboard SET contained a non-local RustDesk FUSE URL");
        }
        sanitized.push(file);
    }
    Ok(sanitized)
}

#[cfg(target_os = "android")]
fn write_android_sanitized_clipboard_payload(
    text: &[u8],
    html: Option<&[u8]>,
) -> ResultType<Vec<u8>> {
    if text.is_empty() {
        bail!("Android sanitized clipboard payload requires text");
    }
    let html = html.filter(|value| !value.is_empty());
    let html_len = html.map_or(0usize, |value| value.len());
    let total = text
        .len()
        .checked_add(html_len)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("Android clipboard payload length overflow"))?;
    if total > MAX_NATIVE_CLIPBOARD_TOTAL_BYTES {
        bail!(
            "oversized Android sanitized clipboard payload: {} > {}",
            total,
            MAX_NATIVE_CLIPBOARD_TOTAL_BYTES
        );
    }

    let mut out = Vec::with_capacity(ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES + total);
    out.extend_from_slice(&ANDROID_SANITIZED_CLIPBOARD_MAGIC);
    out.push(ANDROID_SANITIZED_CLIPBOARD_VERSION);
    out.push(if html.is_some() { 1 } else { 0 });
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(text.len())
            .map_err(|_| hbb_common::anyhow::anyhow!("Android clipboard text too large"))?
            .to_le_bytes(),
    );
    out.extend_from_slice(
        &u32::try_from(html_len)
            .map_err(|_| hbb_common::anyhow::anyhow!("Android clipboard HTML too large"))?
            .to_le_bytes(),
    );
    out.extend_from_slice(text);
    if let Some(html) = html {
        out.extend_from_slice(html);
    }
    Ok(out)
}

#[cfg(target_os = "android")]
fn android_sanitized_clipboard_payload_slices(data: &[u8]) -> ResultType<(&[u8], Option<&[u8]>)> {
    if data.len() < ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES {
        bail!("Android sanitized clipboard payload is too short");
    }
    if data.get(..4) != Some(&ANDROID_SANITIZED_CLIPBOARD_MAGIC) {
        bail!("bad Android sanitized clipboard magic");
    }
    if data[4] != ANDROID_SANITIZED_CLIPBOARD_VERSION {
        bail!(
            "unsupported Android sanitized clipboard version {}",
            data[4]
        );
    }
    let flags = data[5];
    if flags & !1 != 0 {
        bail!("unsupported Android sanitized clipboard flags {flags}");
    }
    if data[6] != 0 || data[7] != 0 {
        bail!("non-zero Android sanitized clipboard reserved bytes");
    }
    let text_len = u32::from_le_bytes(
        data[8..12]
            .try_into()
            .map_err(|_| hbb_common::anyhow::anyhow!("bad Android clipboard text length"))?,
    ) as usize;
    let html_len = u32::from_le_bytes(
        data[12..16]
            .try_into()
            .map_err(|_| hbb_common::anyhow::anyhow!("bad Android clipboard HTML length"))?,
    ) as usize;
    if text_len == 0 {
        bail!("Android sanitized clipboard payload has no text");
    }
    let total = text_len
        .checked_add(html_len)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("Android clipboard payload length overflow"))?;
    if total > MAX_NATIVE_CLIPBOARD_TOTAL_BYTES {
        bail!(
            "oversized Android sanitized clipboard aggregate payload: {} > {}",
            total,
            MAX_NATIVE_CLIPBOARD_TOTAL_BYTES
        );
    }
    let expected = ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES
        .checked_add(total)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("Android clipboard payload length overflow"))?;
    if data.len() != expected {
        bail!("Android sanitized clipboard payload length mismatch");
    }
    let text_start = ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES;
    let html_start = text_start + text_len;
    let text = &data[text_start..html_start];
    std::str::from_utf8(text)
        .map_err(|e| hbb_common::anyhow::anyhow!("Android clipboard text is not UTF-8: {e}"))?;
    let html = if html_len > 0 {
        let html = &data[html_start..];
        std::str::from_utf8(html)
            .map_err(|e| hbb_common::anyhow::anyhow!("Android clipboard HTML is not UTF-8: {e}"))?;
        Some(html)
    } else {
        None
    };
    if flags == 0 && html.is_some() {
        bail!("Android sanitized clipboard HTML present without flag");
    }
    if flags == 1 && html.is_none() {
        bail!("Android sanitized clipboard HTML flag set without data");
    }
    Ok((text, html))
}

#[cfg(target_os = "android")]
pub(crate) fn android_validate_sanitized_clipboard_payload(data: &[u8]) -> ResultType<()> {
    let _ = android_sanitized_clipboard_payload_slices(data)?;
    Ok(())
}

#[cfg(target_os = "android")]
pub fn android_service_clipboard_sanitize_payload(data: &[u8]) -> ResultType<Vec<u8>> {
    if data.len() > MAX_NATIVE_CLIPBOARD_TOTAL_BYTES {
        bail!(
            "oversized Android clipboard sanitize request: {} > {}",
            data.len(),
            MAX_NATIVE_CLIPBOARD_TOTAL_BYTES
        );
    }
    let multi_clipboards = MultiClipboards::parse_from_bytes(data).map_err(|e| {
        hbb_common::anyhow::anyhow!("failed to parse Android clipboard request: {e}")
    })?;
    if multi_clipboards.clipboards.len() > MAX_NATIVE_CLIPBOARD_ITEMS {
        bail!(
            "too many Android clipboard items: {} > {}",
            multi_clipboards.clipboards.len(),
            MAX_NATIVE_CLIPBOARD_ITEMS
        );
    }

    let mut text = None;
    let mut html = None;
    let mut aggregate = 0usize;
    let mut duplicate_items = 0usize;
    let mut unsupported_items = 0usize;
    for clipboard in multi_clipboards.clipboards {
        let format = clipboard
            .format
            .enum_value()
            .map_err(|e| hbb_common::anyhow::anyhow!("invalid Android clipboard format: {e}"))?;
        let target = match format {
            ClipboardFormat::Text if text.is_none() => Some(&mut text),
            ClipboardFormat::Html if html.is_none() => Some(&mut html),
            ClipboardFormat::Text | ClipboardFormat::Html => {
                duplicate_items += 1;
                None
            }
            _ => {
                unsupported_items += 1;
                None
            }
        };
        let Some(target) = target else {
            continue;
        };
        let data = clipboard_content_for_native(&clipboard)?;
        std::str::from_utf8(&data).map_err(|e| {
            hbb_common::anyhow::anyhow!("Android clipboard {format:?} is not UTF-8: {e}")
        })?;
        aggregate = aggregate
            .checked_add(data.len())
            .ok_or_else(|| hbb_common::anyhow::anyhow!("Android clipboard aggregate overflow"))?;
        if aggregate > MAX_NATIVE_CLIPBOARD_TOTAL_BYTES {
            bail!(
                "oversized Android clipboard aggregate payload: {} > {}",
                aggregate,
                MAX_NATIVE_CLIPBOARD_TOTAL_BYTES
            );
        }
        *target = Some(data);
    }
    if duplicate_items != 0 || unsupported_items != 0 {
        log::debug!(
            "dropped Android peer clipboard items before isolated SET handoff: duplicates={}, unsupported={}",
            duplicate_items,
            unsupported_items
        );
    }

    let text =
        text.ok_or_else(|| hbb_common::anyhow::anyhow!("Android clipboard SET has no text"))?;
    let payload = write_android_sanitized_clipboard_payload(&text, html.as_deref())?;
    android_validate_sanitized_clipboard_payload(&payload)?;
    Ok(payload)
}

#[cfg(target_os = "android")]
pub fn android_service_clipboard_self_test() -> bool {
    (|| -> ResultType<bool> {
        let mut multi = MultiClipboards::new();
        multi.clipboards.push(Clipboard {
            format: ClipboardFormat::Text.into(),
            content: b"rd-clipboard-self-test".to_vec().into(),
            ..Default::default()
        });
        let request = multi.write_to_bytes().map_err(|e| {
            hbb_common::anyhow::anyhow!("clipboard self-test serialize failed: {e}")
        })?;
        let payload = android_service_clipboard_sanitize_payload(&request)?;
        let (text, html) = android_sanitized_clipboard_payload_slices(&payload)?;
        Ok(text == b"rd-clipboard-self-test" && html.is_none())
    })()
    .unwrap_or(false)
}

#[cfg(not(target_os = "android"))]
lazy_static::lazy_static! {
    static ref ARBOARD_MTX: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
    // cache the clipboard msg
    static ref LAST_MULTI_CLIPBOARDS: Arc<Mutex<MultiClipboards>> = Arc::new(Mutex::new(MultiClipboards::new()));
    // For updating in server and getting content in cm.
    // Clipboard on Linux is "server--clients" mode.
    // The clipboard content is owned by the server and passed to the clients when requested.
    // Plain text is the only exception, it does not require the server to be present.
    static ref CLIPBOARD_CTX: Arc<Mutex<Option<ClipboardContext>>> = Arc::new(Mutex::new(None));
}

#[cfg(not(target_os = "android"))]
static CLIPBOARD_UPDATE_TX: OnceLock<Result<SyncSender<ClipboardUpdateRequest>, String>> =
    OnceLock::new();

#[cfg(not(target_os = "android"))]
const CLIPBOARD_GET_MAX_RETRY: usize = 3;
#[cfg(not(target_os = "android"))]
const CLIPBOARD_GET_RETRY_INTERVAL_DUR: Duration = Duration::from_millis(33);

#[cfg(not(target_os = "android"))]
const SUPPORTED_FORMATS: &[ClipboardFormat] = &[
    ClipboardFormat::Text,
    ClipboardFormat::Html,
    ClipboardFormat::Rtf,
    ClipboardFormat::ImageRgba,
    ClipboardFormat::ImagePng,
    ClipboardFormat::ImageSvg,
    #[cfg(feature = "unix-file-copy-paste")]
    ClipboardFormat::FileUrl,
    ClipboardFormat::Special(CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET),
    ClipboardFormat::Special(RUSTDESK_CLIPBOARD_OWNER_FORMAT),
];

#[cfg(not(target_os = "android"))]
pub fn check_clipboard(
    ctx: &mut Option<ClipboardContext>,
    side: ClipboardSide,
    force: bool,
) -> Option<Message> {
    let (msg, clipboards) = read_clipboard_message(ctx, side, force)?;
    *LAST_MULTI_CLIPBOARDS.lock().unwrap() = clipboards;
    Some(msg)
}

#[cfg(target_os = "linux")]
pub fn peek_clipboard(
    ctx: &mut Option<ClipboardContext>,
    side: ClipboardSide,
    force: bool,
) -> Option<Message> {
    let (msg, _) = read_clipboard_message(ctx, side, force)?;
    Some(msg)
}

#[cfg(not(target_os = "android"))]
fn read_clipboard_message(
    ctx: &mut Option<ClipboardContext>,
    side: ClipboardSide,
    force: bool,
) -> Option<(Message, MultiClipboards)> {
    if ctx.is_none() {
        *ctx = ClipboardContext::new().ok();
    }
    let ctx2 = ctx.as_mut()?;
    match ctx2.get(side, force) {
        Ok(content) => {
            if !content.is_empty() {
                let mut msg = Message::new();
                let clipboards = proto::create_multi_clipboards(content);
                msg.set_multi_clipboards(clipboards.clone());
                return Some((msg, clipboards));
            }
        }
        Err(e) => {
            log::error!("Failed to get clipboard content. {}", e);
        }
    }
    None
}

#[cfg(all(feature = "unix-file-copy-paste", target_os = "macos"))]
pub fn is_file_url_set_by_rustdesk(url: &Vec<String>) -> bool {
    if url.len() != 1 {
        return false;
    }
    url.iter()
        .next()
        .map(|s| {
            for prefix in &["file:///tmp/.rustdesk_", "//tmp/.rustdesk_"] {
                if s.starts_with(prefix) {
                    return s[prefix.len()..].parse::<uuid::Uuid>().is_ok();
                }
            }
            false
        })
        .unwrap_or(false)
}

#[cfg(feature = "unix-file-copy-paste")]
pub fn check_clipboard_files(
    ctx: &mut Option<ClipboardContext>,
    side: ClipboardSide,
    force: bool,
) -> Option<Vec<String>> {
    if ctx.is_none() {
        *ctx = ClipboardContext::new().ok();
    }
    let ctx2 = ctx.as_mut()?;
    match ctx2.get_files(side, force) {
        Ok(Some(urls)) => {
            if !urls.is_empty() {
                return Some(urls);
            }
        }
        Err(e) => {
            log::error!("Failed to get clipboard file urls. {}", e);
        }
        _ => {}
    }
    None
}

#[cfg(all(target_os = "linux", feature = "unix-file-copy-paste"))]
pub fn update_clipboard_files(files: Vec<String>, side: ClipboardSide) {
    if !files.is_empty() {
        enqueue_clipboard_update(
            ClipboardUpdateRequest::SetFiles { files, side },
            "native clipboard dispatcher busy; refusing to queue peer file-clipboard SET",
        );
    }
}

#[cfg(test)]
mod native_clipboard_limit_tests {
    use super::{
        native_clipboard_payload_within_limit, sanitize_multi_clipboards_for_native_proto,
        CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET, MAX_NATIVE_CLIPBOARD_ITEMS,
        MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES, MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES,
        MAX_NATIVE_CLIPBOARD_TOTAL_BYTES, RUSTDESK_CLIPBOARD_OWNER_FORMAT,
    };
    use hbb_common::message_proto::{Clipboard, ClipboardFormat};

    #[test]
    fn accepts_bounded_text_payload() {
        assert!(native_clipboard_payload_within_limit(
            ClipboardFormat::Text,
            0,
            0,
            MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES
        ));
    }

    #[test]
    fn rejects_payload_over_native_clipboard_cap() {
        assert!(!native_clipboard_payload_within_limit(
            ClipboardFormat::Text,
            0,
            0,
            MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES + 1
        ));
    }

    #[test]
    fn rejects_rgba_with_invalid_dimensions_or_length() {
        assert!(native_clipboard_payload_within_limit(
            ClipboardFormat::ImageRgba,
            2,
            3,
            2 * 3 * 4
        ));
        assert!(!native_clipboard_payload_within_limit(
            ClipboardFormat::ImageRgba,
            2,
            3,
            2 * 3 * 4 - 1
        ));
        assert!(!native_clipboard_payload_within_limit(
            ClipboardFormat::ImageRgba,
            0,
            3,
            0
        ));
    }

    #[test]
    fn rejects_too_many_clipboard_items_before_native_handoff() {
        let clips = (0..=MAX_NATIVE_CLIPBOARD_ITEMS)
            .map(|_| Clipboard {
                content: vec![b'a'].into(),
                format: ClipboardFormat::Text.into(),
                ..Default::default()
            })
            .collect();
        assert!(sanitize_multi_clipboards_for_native_proto(clips).is_none());
    }

    #[test]
    fn rejects_aggregate_clipboard_payload_over_cap() {
        let half = MAX_NATIVE_CLIPBOARD_TOTAL_BYTES / 2 + 1;
        let clips = vec![
            Clipboard {
                content: vec![b'a'; half].into(),
                format: ClipboardFormat::Text.into(),
                ..Default::default()
            },
            Clipboard {
                content: vec![b'b'; half].into(),
                format: ClipboardFormat::Text.into(),
                ..Default::default()
            },
        ];
        assert!(sanitize_multi_clipboards_for_native_proto(clips).is_none());
    }

    #[test]
    fn rejects_unallowlisted_special_clipboard_format_before_native_handoff() {
        let clips = vec![Clipboard {
            content: vec![b'a'].into(),
            format: ClipboardFormat::Special.into(),
            special_name: "attacker-native-format".to_owned(),
            ..Default::default()
        }];
        assert!(sanitize_multi_clipboards_for_native_proto(clips).is_none());
    }

    #[test]
    fn rejects_peer_supplied_owner_marker_before_native_handoff() {
        let clips = vec![Clipboard {
            content: vec![b'a'].into(),
            format: ClipboardFormat::Special.into(),
            special_name: RUSTDESK_CLIPBOARD_OWNER_FORMAT.to_owned(),
            ..Default::default()
        }];
        assert!(sanitize_multi_clipboards_for_native_proto(clips).is_none());
    }

    #[test]
    fn rejects_oversized_special_clipboard_name_before_native_handoff() {
        let clips = vec![Clipboard {
            content: vec![b'a'].into(),
            format: ClipboardFormat::Special.into(),
            special_name: "x".repeat(MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES + 1),
            ..Default::default()
        }];
        assert!(sanitize_multi_clipboards_for_native_proto(clips).is_none());
    }

    #[test]
    fn accepts_allowlisted_excel_special_clipboard_format() {
        let clips = vec![Clipboard {
            content: vec![b'a'].into(),
            format: ClipboardFormat::Special.into(),
            special_name: CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET.to_owned(),
            ..Default::default()
        }];
        let sanitized = sanitize_multi_clipboards_for_native_proto(clips)
            .expect("allowlisted Excel clipboard format should survive");
        assert_eq!(sanitized.clipboards.len(), 1);
        assert_eq!(
            sanitized.clipboards[0].special_name,
            CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET
        );
    }

    #[test]
    fn strips_irrelevant_special_name_from_non_special_clipboard_format() {
        let clips = vec![Clipboard {
            content: vec![b'a'].into(),
            format: ClipboardFormat::Text.into(),
            special_name: "attacker-native-format".to_owned(),
            ..Default::default()
        }];
        let sanitized = sanitize_multi_clipboards_for_native_proto(clips)
            .expect("bounded text clipboard should survive");
        assert_eq!(sanitized.clipboards.len(), 1);
        assert!(sanitized.clipboards[0].special_name.is_empty());
    }

    #[test]
    fn r_s7_malformed_compressed_clipboard_refuses_the_complete_update() {
        let clips = vec![
            Clipboard {
                content: b"valid text".to_vec().into(),
                format: ClipboardFormat::Text.into(),
                ..Default::default()
            },
            Clipboard {
                content: b"not a zstd frame".to_vec().into(),
                compress: true,
                format: ClipboardFormat::Html.into(),
                ..Default::default()
            },
        ];
        assert!(sanitize_multi_clipboards_for_native_proto(clips).is_none());
    }

    #[test]
    fn r_s7_truncated_compressed_clipboard_refuses_native_handoff() {
        let mut compressed = hbb_common::compress::compress(b"clipboard text");
        assert!(!compressed.is_empty());
        compressed.truncate(compressed.len() / 2);
        let clips = vec![Clipboard {
            content: compressed.into(),
            compress: true,
            format: ClipboardFormat::Text.into(),
            ..Default::default()
        }];
        assert!(sanitize_multi_clipboards_for_native_proto(clips).is_none());
    }

    #[test]
    fn r_s7_valid_compressed_clipboard_preserves_text_and_empty_content() {
        let clips = [
            (ClipboardFormat::Text, &b"clipboard text"[..]),
            (ClipboardFormat::Html, &b""[..]),
        ]
        .into_iter()
        .map(|(format, content)| {
            let compressed = hbb_common::compress::compress(content);
            assert!(!compressed.is_empty());
            Clipboard {
                content: compressed.into(),
                compress: true,
                format: format.into(),
                ..Default::default()
            }
        })
        .collect();
        let sanitized = sanitize_multi_clipboards_for_native_proto(clips)
            .expect("valid compressed clipboard content must survive");
        assert_eq!(sanitized.clipboards.len(), 2);
        assert_eq!(&sanitized.clipboards[0].content[..], b"clipboard text");
        assert!(sanitized.clipboards[1].content.is_empty());
        assert!(sanitized.clipboards.iter().all(|item| !item.compress));
    }
}

#[cfg(all(feature = "unix-file-copy-paste", not(target_os = "windows")))]
pub fn try_empty_clipboard_files(_side: ClipboardSide, _conn_id: i32) {
    enqueue_clipboard_update(
        ClipboardUpdateRequest::TryEmptyFiles {
            side: _side,
            conn_id: _conn_id,
        },
        "native clipboard dispatcher busy; refusing to queue peer file-clipboard empty",
    );
}

#[cfg(all(feature = "unix-file-copy-paste", not(target_os = "windows")))]
fn try_empty_clipboard_files_(_side: ClipboardSide, _conn_id: i32) {
    #[cfg(target_os = "linux")]
    {
        use clipboard::platform::unix;
        if unix::fuse::empty_local_files(_side == ClipboardSide::Client, _conn_id) {
            match ClipboardContext::new() {
                Ok(mut ctx) => ctx.try_empty_clipboard_files(_side),
                Err(e) => log::debug!("Failed to empty file clipboard: {}", e),
            }
        }
        return;
    }

    #[cfg(target_os = "macos")]
    {
        let mut ctx = CLIPBOARD_CTX.lock().unwrap();
        if ctx.is_none() {
            match ClipboardContext::new() {
                Ok(x) => {
                    *ctx = Some(x);
                }
                Err(e) => {
                    log::error!("Failed to create clipboard context: {}", e);
                    return;
                }
            }
        }
        #[allow(unused_mut)]
        if let Some(mut ctx) = ctx.as_mut() {
            ctx.try_empty_clipboard_files(_side);
            // No need to make sure the context is enabled.
            clipboard::ContextSend::proc(|context| -> ResultType<()> {
                context.empty_clipboard(_conn_id).ok();
                Ok(())
            })
            .ok();
        }
    }
}

#[cfg(target_os = "windows")]
pub fn try_empty_clipboard_files(side: ClipboardSide, conn_id: i32) {
    log::debug!("try to empty {} cliprdr for conn_id {}", side, conn_id);
    let _ = clipboard::ContextSend::proc(|context| -> ResultType<()> {
        context.empty_clipboard(conn_id)?;
        Ok(())
    });
}

#[cfg(target_os = "windows")]
pub fn check_clipboard_cm() -> ResultType<MultiClipboards> {
    let mut ctx = CLIPBOARD_CTX.lock().unwrap();
    if ctx.is_none() {
        match ClipboardContext::new() {
            Ok(x) => {
                *ctx = Some(x);
            }
            Err(e) => {
                hbb_common::bail!("Failed to create clipboard context: {}", e);
            }
        }
    }
    if let Some(ctx) = ctx.as_mut() {
        let content = ctx.get(ClipboardSide::Host, false)?;
        let clipboards = proto::create_multi_clipboards(content);
        Ok(clipboards)
    } else {
        hbb_common::bail!("Failed to create clipboard context");
    }
}

#[cfg(not(target_os = "android"))]
fn update_clipboard_(multi_clipboards: Vec<Clipboard>, side: ClipboardSide) {
    let Some(multi_clipboards) = sanitize_multi_clipboards_for_native_proto(multi_clipboards)
    else {
        return;
    };
    let data = native_clipboard_data_from_multi_clipboards(multi_clipboards.clipboards);
    if let Err(e) = set_native_clipboard_data(data, side) {
        log::warn!("failed to set native clipboard: {}", e);
    }
}

#[cfg(not(target_os = "android"))]
pub(crate) fn set_native_clipboard_data(
    mut to_update_data: Vec<ClipboardData>,
    side: ClipboardSide,
) -> ResultType<()> {
    let mut ctx = CLIPBOARD_CTX.lock().unwrap();
    if ctx.is_none() {
        *ctx = Some(ClipboardContext::new()?);
    }
    if let Some(ctx) = ctx.as_mut() {
        to_update_data = append_owner_marker(to_update_data, side);
        ctx.set(&to_update_data)?;
        log::debug!("{} updated on {}", CLIPBOARD_NAME, side);
        Ok(())
    } else {
        bail!("Failed to create clipboard context");
    }
}

#[cfg(not(target_os = "android"))]
pub(crate) fn native_clipboard_data_from_multi_clipboards(
    multi_clipboards: Vec<Clipboard>,
) -> Vec<ClipboardData> {
    proto::from_multi_clipboards(multi_clipboards)
}

#[cfg(not(target_os = "android"))]
fn append_owner_marker(mut data: Vec<ClipboardData>, side: ClipboardSide) -> Vec<ClipboardData> {
    data.push(ClipboardData::Special((
        RUSTDESK_CLIPBOARD_OWNER_FORMAT.to_owned(),
        side.get_owner_data(),
    )));
    data
}

// R-X13 (§8): set_text_clipboard_with_owner_sync + the set_with_owner_marker_for_linux method (the
// owner-marked clipboard SET used only by the excised Wayland uinput clipboard-paste input) are
// removed. append_owner_marker stays — the live clipboard-sync still marks its own writes.

#[cfg(not(target_os = "android"))]
pub fn update_clipboard(multi_clipboards: Vec<Clipboard>, side: ClipboardSide) {
    // R-T0: peer clipboard SET is a hostile-peer path. Spawning a fresh OS
    // thread for each peer message would be a thread-amplification DoS, so use
    // one bounded dispatcher and shed newest excess while a previous clipboard
    // update is still being processed.
    enqueue_clipboard_update(
        ClipboardUpdateRequest::SetMulti {
            multi_clipboards,
            side,
        },
        "native clipboard dispatcher busy; refusing to queue peer clipboard SET",
    )
}

#[cfg(not(target_os = "android"))]
fn enqueue_clipboard_update(request: ClipboardUpdateRequest, busy_message: &'static str) {
    let sender = CLIPBOARD_UPDATE_TX.get_or_init(|| {
        let (tx, rx) =
            mpsc::sync_channel::<ClipboardUpdateRequest>(CLIPBOARD_UPDATE_QUEUE_CAPACITY);
        match std::thread::Builder::new()
            .name("rd-native-clipboard-dispatch".to_owned())
            .spawn(move || {
                while let Ok(request) = rx.recv() {
                    handle_clipboard_update_request(request);
                }
            }) {
            Ok(_) => Ok(tx),
            Err(e) => Err(format!("failed to spawn native clipboard dispatcher: {e}")),
        }
    });
    let sender = match sender {
        Ok(sender) => sender,
        Err(err) => {
            log::warn!("native clipboard dispatcher unavailable; refusing clipboard SET: {err}");
            return;
        }
    };
    match sender.try_send(request) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            log::warn!("{busy_message}");
        }
        Err(TrySendError::Disconnected(_)) => {
            log::warn!("native clipboard dispatcher stopped; refusing clipboard SET");
        }
    }
}

#[cfg(not(target_os = "android"))]
fn handle_clipboard_update_request(request: ClipboardUpdateRequest) {
    match request {
        ClipboardUpdateRequest::SetMulti {
            multi_clipboards,
            side,
        } => update_clipboard_(multi_clipboards, side),
        #[cfg(all(target_os = "linux", feature = "unix-file-copy-paste"))]
        ClipboardUpdateRequest::SetFiles { files, side } => {
            match sanitize_linux_file_clipboard_urls(files, side) {
                Ok(files) => {
                    if let Err(e) =
                        set_native_clipboard_data(vec![ClipboardData::FileUrl(files)], side)
                    {
                        log::debug!("Failed to set file clipboard: {}", e);
                    }
                }
                Err(e) => log::debug!("dropping invalid file clipboard URLs: {}", e),
            }
        }
        #[cfg(all(feature = "unix-file-copy-paste", not(target_os = "windows")))]
        ClipboardUpdateRequest::TryEmptyFiles { side, conn_id } => {
            try_empty_clipboard_files_(side, conn_id);
        }
    }
}

#[cfg(not(target_os = "android"))]
pub struct ClipboardContext {
    inner: arboard::Clipboard,
}

#[cfg(not(target_os = "android"))]
#[allow(unreachable_code)]
impl ClipboardContext {
    pub fn new() -> ResultType<ClipboardContext> {
        let board;
        #[cfg(not(target_os = "linux"))]
        {
            board = arboard::Clipboard::new()?;
        }
        #[cfg(target_os = "linux")]
        {
            let mut i = 1;
            loop {
                // Try 5 times to create clipboard
                // Arboard::new() connect to X server or Wayland compositor, which should be OK most times
                // But sometimes, the connection may fail, so we retry here.
                match arboard::Clipboard::new() {
                    Ok(x) => {
                        board = x;
                        break;
                    }
                    Err(e) => {
                        if i == 5 {
                            return Err(e.into());
                        } else {
                            std::thread::sleep(std::time::Duration::from_millis(30 * i));
                        }
                    }
                }
                i += 1;
            }
        }

        Ok(ClipboardContext { inner: board })
    }

    fn get_formats(&mut self, formats: &[ClipboardFormat]) -> ResultType<Vec<ClipboardData>> {
        // If there're multiple threads or processes trying to access the clipboard at the same time,
        // the previous clipboard owner will fail to access the clipboard.
        // `GetLastError()` will return `ERROR_CLIPBOARD_NOT_OPEN` (OSError(1418): Thread does not have a clipboard open) at this time.
        // See https://github.com/rustdesk-org/arboard/blob/747ab2d9b40a5c9c5102051cf3b0bb38b4845e60/src/platform/windows.rs#L34
        //
        // This is a common case on Windows, so we retry here.
        // Related issues:
        // https://github.com/rustdesk/rustdesk/issues/9263
        // https://github.com/rustdesk/rustdesk/issues/9222#issuecomment-2329233175
        for i in 0..CLIPBOARD_GET_MAX_RETRY {
            match self.inner.get_formats(formats) {
                Ok(data) => {
                    return Ok(data
                        .into_iter()
                        .filter(|c| !matches!(c, arboard::ClipboardData::None))
                        .collect())
                }
                Err(e) => match e {
                    arboard::Error::ClipboardOccupied => {
                        log::debug!("Failed to get clipboard formats, clipboard is occupied, retrying... {}", i + 1);
                        std::thread::sleep(CLIPBOARD_GET_RETRY_INTERVAL_DUR);
                    }
                    _ => {
                        log::error!("Failed to get clipboard formats, {}", e);
                        return Err(e.into());
                    }
                },
            }
        }
        bail!("Failed to get clipboard formats, clipboard is occupied, {CLIPBOARD_GET_MAX_RETRY} retries failed");
    }

    pub fn get(&mut self, side: ClipboardSide, force: bool) -> ResultType<Vec<ClipboardData>> {
        let data = self.get_formats_filter(SUPPORTED_FORMATS, side, force)?;
        // We have a separate service named `file-clipboard` to handle file copy-paste.
        // We need to read the file urls because file copy may set the other clipboard formats such as text.
        #[cfg(feature = "unix-file-copy-paste")]
        {
            if data.iter().any(|c| matches!(c, ClipboardData::FileUrl(_))) {
                return Ok(vec![]);
            }
        }
        Ok(data)
    }

    fn get_formats_filter(
        &mut self,
        formats: &[ClipboardFormat],
        side: ClipboardSide,
        force: bool,
    ) -> ResultType<Vec<ClipboardData>> {
        let _lock = ARBOARD_MTX.lock().unwrap();
        let data = self.get_formats(formats)?;
        if data.is_empty() {
            return Ok(data);
        }
        if !force {
            for c in data.iter() {
                if let ClipboardData::Special((s, d)) = c {
                    if s == RUSTDESK_CLIPBOARD_OWNER_FORMAT && side.is_owner(d) {
                        return Ok(vec![]);
                    }
                }
            }
        }
        Ok(data
            .into_iter()
            .filter(|c| match c {
                ClipboardData::Special((s, _)) => s != RUSTDESK_CLIPBOARD_OWNER_FORMAT,
                // Skip synchronizing empty text to the remote clipboard
                ClipboardData::Text(text) => !text.is_empty(),
                _ => true,
            })
            .collect())
    }

    #[cfg(feature = "unix-file-copy-paste")]
    pub fn get_files(
        &mut self,
        side: ClipboardSide,
        force: bool,
    ) -> ResultType<Option<Vec<String>>> {
        let data = self.get_formats_filter(
            &[
                ClipboardFormat::FileUrl,
                ClipboardFormat::Special(RUSTDESK_CLIPBOARD_OWNER_FORMAT),
            ],
            side,
            force,
        )?;
        Ok(data.into_iter().find_map(|c| match c {
            ClipboardData::FileUrl(urls) => Some(urls),
            _ => None,
        }))
    }

    fn set(&mut self, data: &[ClipboardData]) -> ResultType<()> {
        let _lock = ARBOARD_MTX.lock().unwrap();
        self.inner.set_formats(data)?;
        Ok(())
    }

    // R-X13 (§8): set_with_owner_marker_for_linux removed with set_text_clipboard_with_owner_sync
    // (the excised Wayland uinput clipboard-paste SET path).

    #[cfg(all(feature = "unix-file-copy-paste", target_os = "macos"))]
    fn get_file_urls_set_by_rustdesk(
        data: Vec<ClipboardData>,
        _side: ClipboardSide,
    ) -> Vec<String> {
        for item in data.into_iter() {
            if let ClipboardData::FileUrl(urls) = item {
                if is_file_url_set_by_rustdesk(&urls) {
                    return urls;
                }
            }
        }
        vec![]
    }

    #[cfg(all(feature = "unix-file-copy-paste", target_os = "linux"))]
    fn get_file_urls_set_by_rustdesk(data: Vec<ClipboardData>, side: ClipboardSide) -> Vec<String> {
        data.into_iter()
            .filter_map(|c| match c {
                ClipboardData::FileUrl(urls) => Some(
                    urls.into_iter()
                        .filter(|s| is_linux_file_clipboard_url_for_side(s, side))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    #[cfg(feature = "unix-file-copy-paste")]
    pub(crate) fn try_empty_clipboard_files(&mut self, side: ClipboardSide) {
        let _lock = ARBOARD_MTX.lock().unwrap();
        if let Ok(data) = self.get_formats(&[ClipboardFormat::FileUrl]) {
            let urls = Self::get_file_urls_set_by_rustdesk(data, side);
            if !urls.is_empty() {
                // FIXME:
                // The host-side clear file clipboard `let _ = self.inner.clear();`,
                // does not work on KDE Plasma for the installed version.

                // Don't use `hbb_common::platform::linux::is_kde()` here.
                // It's not correct in the server process.
                #[cfg(target_os = "linux")]
                let is_kde_x11 = hbb_common::platform::linux::is_kde_session()
                    && crate::platform::linux::is_x11();
                #[cfg(target_os = "macos")]
                let is_kde_x11 = false;
                let clear_holder_text = if is_kde_x11 {
                    "RustDesk placeholder to clear the file clipboard"
                } else {
                    ""
                }
                .to_string();
                self.inner
                    .set_formats(&[
                        ClipboardData::Text(clear_holder_text),
                        ClipboardData::Special((
                            RUSTDESK_CLIPBOARD_OWNER_FORMAT.to_owned(),
                            side.get_owner_data(),
                        )),
                    ])
                    .ok();
            }
        }
    }
}

pub fn is_support_multi_clipboard(peer_version: &str, peer_platform: &str) -> bool {
    use hbb_common::get_version_number;
    if get_version_number(peer_version) < get_version_number("1.3.0") {
        return false;
    }
    if ["", &hbb_common::whoami::Platform::Ios.to_string()].contains(&peer_platform) {
        return false;
    }
    if "Android" == peer_platform && get_version_number(peer_version) < get_version_number("1.3.3")
    {
        return false;
    }
    true
}

#[cfg(not(target_os = "android"))]
pub fn get_current_clipboard_msg(
    peer_version: &str,
    peer_platform: &str,
    side: ClipboardSide,
) -> Option<Message> {
    let mut multi_clipboards = LAST_MULTI_CLIPBOARDS.lock().unwrap();
    if multi_clipboards.clipboards.is_empty() {
        let mut ctx = ClipboardContext::new().ok()?;
        *multi_clipboards = proto::create_multi_clipboards(ctx.get(side, true).ok()?);
    }
    if multi_clipboards.clipboards.is_empty() {
        return None;
    }

    if is_support_multi_clipboard(peer_version, peer_platform) {
        let mut msg = Message::new();
        msg.set_multi_clipboards(multi_clipboards.clone());
        Some(msg)
    } else {
        // Find the first text clipboard and send it.
        multi_clipboards
            .clipboards
            .iter()
            .find(|c| c.format.enum_value() == Ok(hbb_common::message_proto::ClipboardFormat::Text))
            .map(|c| {
                let mut msg = Message::new();
                msg.set_clipboard(c.clone());
                msg
            })
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum ClipboardSide {
    Host,
    Client,
}

impl ClipboardSide {
    // 01: the clipboard is owned by the host
    // 10: the clipboard is owned by the client
    fn get_owner_data(&self) -> Vec<u8> {
        match self {
            ClipboardSide::Host => vec![0b01],
            ClipboardSide::Client => vec![0b10],
        }
    }

    fn is_owner(&self, data: &[u8]) -> bool {
        if data.len() == 0 {
            return false;
        }
        data[0] & 0b11 != 0
    }
}

impl std::fmt::Display for ClipboardSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClipboardSide::Host => write!(f, "host"),
            ClipboardSide::Client => write!(f, "client"),
        }
    }
}

pub use proto::get_msg_if_not_support_multi_clip;
mod proto {
    #[cfg(not(target_os = "android"))]
    use arboard::ClipboardData;
    use hbb_common::{
        compress::compress as compress_func,
        log,
        message_proto::{Clipboard, ClipboardFormat, Message, MultiClipboards},
    };

    fn plain_to_proto(s: String, format: ClipboardFormat) -> Clipboard {
        let compressed = compress_func(s.as_bytes());
        let compress = compressed.len() < s.as_bytes().len();
        let content = if compress {
            compressed
        } else {
            s.bytes().collect::<Vec<u8>>()
        };
        Clipboard {
            compress,
            content: content.into(),
            format: format.into(),
            ..Default::default()
        }
    }

    #[cfg(not(target_os = "android"))]
    fn image_to_proto(a: arboard::ImageData) -> Clipboard {
        match &a {
            arboard::ImageData::Rgba(rgba) => {
                let compressed = compress_func(&a.bytes());
                let compress = compressed.len() < a.bytes().len();
                let content = if compress {
                    compressed
                } else {
                    a.bytes().to_vec()
                };
                Clipboard {
                    compress,
                    content: content.into(),
                    width: rgba.width as _,
                    height: rgba.height as _,
                    format: ClipboardFormat::ImageRgba.into(),
                    ..Default::default()
                }
            }
            arboard::ImageData::Png(png) => Clipboard {
                compress: false,
                content: png.to_owned().to_vec().into(),
                format: ClipboardFormat::ImagePng.into(),
                ..Default::default()
            },
            arboard::ImageData::Svg(_) => {
                let compressed = compress_func(&a.bytes());
                let compress = compressed.len() < a.bytes().len();
                let content = if compress {
                    compressed
                } else {
                    a.bytes().to_vec()
                };
                Clipboard {
                    compress,
                    content: content.into(),
                    format: ClipboardFormat::ImageSvg.into(),
                    ..Default::default()
                }
            }
        }
    }

    fn special_to_proto(d: Vec<u8>, s: String) -> Clipboard {
        let compressed = compress_func(&d);
        let compress = compressed.len() < d.len();
        let content = if compress { compressed } else { d };
        Clipboard {
            compress,
            content: content.into(),
            format: ClipboardFormat::Special.into(),
            special_name: s,
            ..Default::default()
        }
    }

    #[cfg(not(target_os = "android"))]
    fn clipboard_data_to_proto(data: ClipboardData) -> Option<Clipboard> {
        let d = match data {
            ClipboardData::Text(s) => plain_to_proto(s, ClipboardFormat::Text),
            ClipboardData::Rtf(s) => plain_to_proto(s, ClipboardFormat::Rtf),
            ClipboardData::Html(s) => plain_to_proto(s, ClipboardFormat::Html),
            ClipboardData::Image(a) => image_to_proto(a),
            ClipboardData::Special((s, d)) => special_to_proto(d, s),
            _ => return None,
        };
        Some(d)
    }

    #[cfg(not(target_os = "android"))]
    pub fn create_multi_clipboards(vec_data: Vec<ClipboardData>) -> MultiClipboards {
        MultiClipboards {
            clipboards: vec_data
                .into_iter()
                .filter_map(clipboard_data_to_proto)
                .collect(),
            ..Default::default()
        }
    }

    #[cfg(not(target_os = "android"))]
    fn from_clipboard(clipboard: Clipboard) -> Option<ClipboardData> {
        let data = match super::clipboard_content_for_native(&clipboard) {
            Ok(data) => data,
            Err(error) => {
                log::warn!("dropping invalid clipboard item before native conversion: {error}");
                return None;
            }
        };
        match clipboard.format.enum_value() {
            Ok(ClipboardFormat::Text) => String::from_utf8(data).ok().map(ClipboardData::Text),
            Ok(ClipboardFormat::Rtf) => String::from_utf8(data).ok().map(ClipboardData::Rtf),
            Ok(ClipboardFormat::Html) => String::from_utf8(data).ok().map(ClipboardData::Html),
            Ok(ClipboardFormat::ImageRgba) => Some(ClipboardData::Image(arboard::ImageData::rgba(
                clipboard.width as _,
                clipboard.height as _,
                data.into(),
            ))),
            Ok(ClipboardFormat::ImagePng) => {
                Some(ClipboardData::Image(arboard::ImageData::png(data.into())))
            }
            Ok(ClipboardFormat::ImageSvg) => Some(ClipboardData::Image(arboard::ImageData::svg(
                std::str::from_utf8(&data).unwrap_or_default(),
            ))),
            Ok(ClipboardFormat::Special) => {
                Some(ClipboardData::Special((clipboard.special_name, data)))
            }
            _ => None,
        }
    }

    #[cfg(not(target_os = "android"))]
    pub fn from_multi_clipboards(multi_clipboards: Vec<Clipboard>) -> Vec<ClipboardData> {
        multi_clipboards
            .into_iter()
            .filter_map(from_clipboard)
            .collect()
    }

    pub fn get_msg_if_not_support_multi_clip(
        version: &str,
        platform: &str,
        multi_clipboards: &MultiClipboards,
    ) -> Option<Message> {
        if crate::clipboard::is_support_multi_clipboard(version, platform) {
            return None;
        }

        // Find the first text clipboard and send it.
        multi_clipboards
            .clipboards
            .iter()
            .find(|c| c.format.enum_value() == Ok(ClipboardFormat::Text))
            .map(|c| {
                let mut msg = Message::new();
                msg.set_clipboard(c.clone());
                msg
            })
    }
}

#[cfg(target_os = "android")]
pub fn handle_msg_clipboard(cb: Clipboard) {
    handle_msg_multi_clipboards(MultiClipboards {
        clipboards: vec![cb],
        ..Default::default()
    });
}

#[cfg(target_os = "android")]
pub fn handle_msg_multi_clipboards(mcb: MultiClipboards) {
    let payload = match mcb.write_to_bytes() {
        Ok(payload) => payload,
        Err(err) => {
            log::warn!(
                "failed to serialize Android peer clipboard SET for isolated service: {err}"
            );
            return;
        }
    };
    let sanitized = match android_service_clipboard_sanitize_payload(&payload) {
        Ok(sanitized) => sanitized,
        Err(err) => {
            log::warn!("Android peer clipboard SET sanitize failed: {err}");
            return;
        }
    };
    if let Err(err) = android_validate_sanitized_clipboard_payload(&sanitized) {
        log::warn!("Android isolated clipboard SET service returned invalid payload: {err}");
        return;
    }
    if let Err(err) =
        scrap::android::ffi::call_clipboard_manager_update_sanitized_clipboard(&sanitized)
    {
        log::warn!("Android sanitized clipboard SET platform handoff failed: {err}");
    }
}

#[cfg(target_os = "android")]
pub fn get_clipboards_msg(client: bool) -> Option<Message> {
    let mut clipboards = scrap::android::ffi::get_clipboards(client)?;
    let mut msg = Message::new();
    for c in &mut clipboards.clipboards {
        let compressed = hbb_common::compress::compress(&c.content);
        let compress = compressed.len() < c.content.len();
        if compress {
            c.content = compressed.into();
        }
        c.compress = compress;
    }
    msg.set_multi_clipboards(clipboards);
    Some(msg)
}

// We need this mod to notify multiple subscribers when the clipboard changes.
// Because only one clipboard master(listener) can trigger the clipboard change event multiple listeners are created on Linux(x11).
#[cfg(not(target_os = "android"))]
pub mod clipboard_listener {
    use clipboard_master::{CallbackResult, ClipboardHandler};
    #[cfg(not(target_os = "linux"))]
    use clipboard_master::{Master, Shutdown};
    #[cfg(target_os = "linux")]
    use self::linux::{Master, Shutdown};
    use hbb_common::{bail, log, ResultType};
    use std::{
        collections::HashMap,
        io,
        sync::mpsc::{channel, Sender},
        sync::{Arc, Condvar, Mutex},
        thread::JoinHandle,
        time::Duration,
    };

    lazy_static::lazy_static! {
        pub static ref CLIPBOARD_LISTENER: Arc<Mutex<ClipboardListener>> = Default::default();
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::{CallbackResult, ClipboardHandler};
        use hbb_common::{libc, platform::x11_display::unix_display_name};
        use std::{
            cell::Cell,
            fs::OpenOptions,
            io::{self, IoSlice, Read},
            os::{fd::{AsRawFd, FromRawFd}, unix::{fs::{MetadataExt, OpenOptionsExt}, net::UnixStream}},
            path::PathBuf,
            sync::{atomic::{AtomicBool, Ordering}, mpsc::{self, Receiver, SyncSender}, Arc},
            time::{Duration, Instant},
        };
        use x11rb_listener::{
            connection::Connection,
            protocol::{
                xfixes,
                xproto::{ConnectionExt, CreateWindowAux, WindowClass},
                Event,
            },
            reexports::x11rb_protocol::{parse_display::{self, ConnectAddress}, xauth},
            rust_connection::{DefaultStream, PollMode, RustConnection, Stream},
            utils::RawFdContainer,
        };

        pub enum Master<H> {
            X11(X11Master<H>),
            Wayland(clipboard_master::Master<H>),
        }

        pub enum Shutdown {
            X11(SyncSender<()>, Arc<AtomicBool>),
            Wayland(clipboard_master::Shutdown),
        }

        impl Drop for Shutdown {
            fn drop(&mut self) {
                if let Self::X11(sender, stopped) = self {
                    // Also cancel native I/O, which may not return to the event loop.
                    stopped.store(true, Ordering::Release);
                    // A disconnected receiver means the owned worker already retired.
                    match sender.send(()) {
                        Ok(()) | Err(_) => {}
                    }
                }
            }
        }

        impl Shutdown {
            pub fn signal(self) {
                drop(self);
            }
        }

        pub struct X11Master<H> {
            connection: RustConnection<NativeStream>,
            window: u32,
            selection: u32,
            handler: H,
            sender: SyncSender<()>,
            receiver: Receiver<()>,
        }

        fn native_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
            io::Error::new(io::ErrorKind::Other, error)
        }

        struct NativeStream {
            stream: DefaultStream,
            startup_deadline: Cell<Option<Instant>>,
            stopped: Arc<AtomicBool>,
        }

        fn check_startup_deadline(deadline: Instant) -> io::Result<()> {
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut,
                    "X11 clipboard startup deadline expired"));
            }
            Ok(())
        }

        impl NativeStream {
            fn check_live(&self) -> io::Result<()> {
                if self.stopped.load(Ordering::Acquire) {
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted,
                        "X11 clipboard connection retired"));
                }
                if let Some(deadline) = self.startup_deadline.get() {
                    check_startup_deadline(deadline)?;
                }
                Ok(())
            }
        }

        impl Stream for NativeStream {
            fn poll(&self, mode: PollMode) -> io::Result<()> {
                let mut events = 0;
                if mode.readable() { events |= libc::POLLIN; }
                if mode.writable() { events |= libc::POLLOUT; }
                let mut socket = libc::pollfd { fd: self.stream.as_raw_fd(), events, revents: 0 };
                loop {
                    self.check_live()?;
                    // Only a blocked native wait polls cancellation. The existing
                    // event-loop sleep and its immediate shutdown wake are unchanged.
                    let timeout = self.startup_deadline.get().map(|deadline| {
                        deadline.saturating_duration_since(Instant::now()).as_millis().clamp(1, 50)
                    }).unwrap_or(50) as libc::c_int;
                    let result = unsafe { libc::poll(&mut socket, 1, timeout) };
                    if result > 0 {
                        self.check_live()?;
                        if socket.revents & libc::POLLNVAL != 0 {
                            return Err(io::Error::new(io::ErrorKind::BrokenPipe,
                                "X11 clipboard socket is unavailable"));
                        }
                        return Ok(());
                    }
                    if result < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
                    }
                }
            }

            fn read(&self, buffer: &mut [u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
                self.check_live()?;
                self.stream.read(buffer, fds)
            }

            fn write(&self, buffer: &[u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
                self.check_live()?;
                self.stream.write(buffer, fds)
            }

            fn write_vectored(&self, buffers: &[IoSlice<'_>], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
                self.check_live()?;
                self.stream.write_vectored(buffers, fds)
            }
        }

        fn connect_unix(path: &str, abstract_socket: bool) -> io::Result<UnixStream> {
            let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            let start = usize::from(abstract_socket);
            if path.is_empty() || path.as_bytes().contains(&0) || path.len() + start >= address.sun_path.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid X11 Unix socket path"));
            }
            let descriptor = unsafe {
                libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0)
            };
            if descriptor < 0 { return Err(io::Error::last_os_error()); }
            // Own the descriptor before any fallible operation, including connect.
            let socket = unsafe { UnixStream::from_raw_fd(descriptor) };
            address.sun_family = libc::AF_UNIX as libc::sa_family_t;
            unsafe {
                std::ptr::copy_nonoverlapping(path.as_ptr(),
                    address.sun_path.as_mut_ptr().add(start).cast::<u8>(), path.len());
            }
            let length = (std::mem::size_of::<libc::sa_family_t>() + path.len() + 1) as libc::socklen_t;
            if unsafe { libc::connect(socket.as_raw_fd(), (&address as *const libc::sockaddr_un).cast(), length) } != 0 {
                // AF_UNIX nonblocking admission returns EAGAIN if the peer's
                // backlog is full. Do not wait, retry, or leave a pending socket.
                return Err(io::Error::last_os_error());
            }
            Ok(socket)
        }

        fn authority_bytes<'a>(input: &mut &'a [u8], count: usize) -> io::Result<&'a [u8]> {
            let bytes = *input;
            if bytes.len() < count {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "Malformed X11 clipboard authority"));
            }
            let (value, remaining) = bytes.split_at(count);
            *input = remaining;
            Ok(value)
        }

        fn authority_u16(input: &mut &[u8]) -> io::Result<u16> {
            let bytes = authority_bytes(input, 2)?;
            Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
        }

        fn authority_field<'a>(input: &mut &'a [u8]) -> io::Result<&'a [u8]> {
            let count = usize::from(authority_u16(input)?);
            authority_bytes(input, count)
        }

        fn native_authority(family: xauth::Family, address: &[u8], display: u16,
                            deadline: Instant) -> io::Result<(Vec<u8>, Vec<u8>)> {
            const MAX_BYTES: usize = 1024 * 1024;
            let too_large = || io::Error::new(io::ErrorKind::InvalidData,
                "X11 clipboard authority exceeds 1 MiB");
            let path = std::env::var_os("XAUTHORITY").map(PathBuf::from).or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".Xauthority"))
            });
            let Some(path) = path else { return Ok((Vec::new(), Vec::new())); };
            check_startup_deadline(deadline)?;
            // Pin the object without opening a FIFO/device for I/O. A regular
            // symlink target is valid; the original pathname is never reopened.
            let pinned = match OpenOptions::new().read(true)
                .custom_flags(libc::O_PATH | libc::O_CLOEXEC).open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound =>
                    return Ok((Vec::new(), Vec::new())),
                Err(error) => return Err(error),
            };
            check_startup_deadline(deadline)?;
            let metadata = pinned.metadata()?;
            if !metadata.is_file() {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "X11 clipboard authority is not a regular file"));
            }
            if metadata.len() > MAX_BYTES as u64 { return Err(too_large()); }
            check_startup_deadline(deadline)?;
            let file = OpenOptions::new().read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
                .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
            check_startup_deadline(deadline)?;
            let actual = file.metadata()?;
            if !actual.is_file() || actual.dev() != metadata.dev() || actual.ino() != metadata.ino() {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "X11 clipboard authority object changed"));
            }
            if actual.len() > MAX_BYTES as u64 { return Err(too_large()); }
            drop(pinned);
            // Bound consumption even if the regular file grows after metadata.
            // Kernel filesystem calls themselves are not made deadline-safe by
            // O_NONBLOCK; check the one startup budget between calls and records.
            let mut reader = file.take((MAX_BYTES + 1) as u64);
            let mut contents = Vec::new();
            contents.try_reserve_exact(MAX_BYTES).map_err(native_error)?;
            let mut buffer = [0u8; 8192];
            loop {
                check_startup_deadline(deadline)?;
                let count = match reader.read(&mut buffer) {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                };
                if count == 0 { break; }
                if contents.len() + count > MAX_BYTES { return Err(too_large()); }
                contents.extend_from_slice(&buffer[..count]);
            }
            drop(reader);
            let display = display.to_string();
            let mut input = contents.as_slice();
            let mut selected = None;
            while !input.is_empty() {
                check_startup_deadline(deadline)?;
                let entry_family = xauth::Family::from(authority_u16(&mut input)?);
                let entry_address = authority_field(&mut input)?;
                let number = authority_field(&mut input)?;
                let name = authority_field(&mut input)?;
                let data = authority_field(&mut input)?;
                let address_matches = family == xauth::Family::WILD || entry_family == xauth::Family::WILD
                    || (family == entry_family && address == entry_address);
                if selected.is_none() && address_matches
                    && (number.is_empty() || number == display.as_bytes())
                    && name == b"MIT-MAGIC-COOKIE-1" {
                    selected = Some((name, data));
                }
            }
            check_startup_deadline(deadline)?;
            Ok(selected.map(|(name, data)| (name.to_vec(), data.to_vec())).unwrap_or_default())
        }

        fn native_connection(display: &str) -> io::Result<(RustConnection<NativeStream>, usize)> {
            let deadline = Instant::now() + Duration::from_secs(3);
            let parsed = parse_display::parse_display(Some(display)).map_err(native_error)?;
            let mut addresses = parsed.connect_instruction();
            let path = match (addresses.next(), addresses.next()) {
                (Some(ConnectAddress::Socket(path)), None) => path,
                _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "X11 clipboard requires one Unix address")),
            };
            let socket = match connect_unix(&path, true) {
                Ok(socket) => socket,
                Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused) =>
                    connect_unix(&path, false)?,
                Err(error) => return Err(error),
            };
            let (stream, (family, address)) = DefaultStream::from_unix_stream(socket)?;
            let (auth_name, auth_data) = native_authority(family, &address, parsed.display, deadline)?;
            let stream = NativeStream { stream, startup_deadline: Cell::new(Some(deadline)),
                stopped: Arc::new(AtomicBool::new(false)) };
            stream.check_live()?;
            let screen = usize::from(parsed.screen);
            let connection = RustConnection::connect_to_stream_with_auth_info(stream, screen, auth_name, auth_data)
                .map_err(native_error)?;
            Ok((connection, screen))
        }

        impl<H: ClipboardHandler> Master<H> {
            pub fn new(handler: H) -> io::Result<Self> {
                if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                    return clipboard_master::Master::new(handler).map(Self::Wayland);
                }
                let display = unix_display_name()?;
                let display = display.to_str().map_err(native_error)?;
                let (connection, screen) = native_connection(display)?;
                let root = connection.setup().roots.get(screen).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "X11 clipboard screen is absent")
                })?.root;
                let version = xfixes::query_version(&connection, 5, 0)
                    .map_err(native_error)?.reply().map_err(native_error)?;
                if version.major_version == 0 {
                    return Err(io::Error::new(io::ErrorKind::Unsupported, "XFixes clipboard events are unavailable"));
                }
                let window = connection.generate_id().map_err(native_error)?;
                connection.create_window(0, window, root, 0, 0, 1, 1, 0,
                    WindowClass::INPUT_ONLY, 0, &CreateWindowAux::new())
                    .map_err(native_error)?.check().map_err(native_error)?;
                let selection = connection.intern_atom(false, b"CLIPBOARD")
                    .map_err(native_error)?.reply().map_err(native_error)?.atom;
                xfixes::select_selection_input(&connection, window, selection,
                    xfixes::SelectionEventMask::SET_SELECTION_OWNER
                        | xfixes::SelectionEventMask::SELECTION_CLIENT_CLOSE
                        | xfixes::SelectionEventMask::SELECTION_WINDOW_DESTROY)
                    .map_err(native_error)?.check().map_err(native_error)?;
                connection.stream().check_live()?;
                connection.stream().startup_deadline.set(None);
                let (sender, receiver) = mpsc::sync_channel(0);
                Ok(Self::X11(X11Master { connection, window, selection, handler, sender, receiver }))
            }

            pub fn shutdown_channel(&self) -> Shutdown {
                match self {
                    Self::X11(master) => Shutdown::X11(master.sender.clone(), Arc::clone(&master.connection.stream().stopped)),
                    Self::Wayland(master) => Shutdown::Wayland(master.shutdown_channel()),
                }
            }

            pub fn run(&mut self) -> io::Result<()> {
                match self {
                    Self::X11(master) => master.run(),
                    Self::Wayland(master) => master.run(),
                }
            }
        }

        impl<H: ClipboardHandler> X11Master<H> {
            fn run(&mut self) -> io::Result<()> {
                loop {
                    // Continuous native traffic must not starve exact shutdown.
                    match self.receiver.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                    let event = self.connection.poll_for_event();
                    if self.connection.stream().stopped.load(Ordering::Acquire) { return Ok(()); }
                    match event.map_err(native_error)? {
                        Some(Event::XfixesSelectionNotify(event))
                            if event.window == self.window && event.selection == self.selection =>
                        {
                            match self.handler.on_clipboard_change() {
                                CallbackResult::Next => {},
                                CallbackResult::Stop => return Ok(()),
                                CallbackResult::StopWithError(error) => return Err(error),
                            }
                        }
                        Some(Event::Error(error)) => {
                            return Err(io::Error::new(io::ErrorKind::Other,
                                format!("X11 clipboard protocol error: {error:?}")));
                        }
                        Some(_) => {},
                        None => {
                            match self.receiver.recv_timeout(self.handler.sleep_interval()) {
                                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                                Err(mpsc::RecvTimeoutError::Timeout) => {},
                            }
                        }
                    }
                }
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SubscriptionIdentity {
        name: String,
        generation: u64,
    }

    enum CallbackTerminal {
        Stop,
        Error(String),
    }

    struct CallbackState {
        change_pending: bool,
        terminal: Option<CallbackTerminal>,
        receiver_alive: bool,
    }

    struct CallbackMailbox {
        state: Mutex<CallbackState>,
        ready: Condvar,
    }

    #[derive(Clone)]
    struct CallbackSender {
        mailbox: Arc<CallbackMailbox>,
    }

    impl CallbackSender {
        fn notify_change(&self) -> bool {
            let mut state = self.mailbox.state.lock().unwrap();
            if !state.receiver_alive {
                return false;
            }
            if state.terminal.is_none() {
                state.change_pending = true;
                self.mailbox.ready.notify_one();
            }
            true
        }

        fn notify_terminal(&self, terminal: CallbackTerminal) -> bool {
            let mut state = self.mailbox.state.lock().unwrap();
            if !state.receiver_alive {
                return false;
            }
            if state.terminal.is_none() {
                state.change_pending = false;
                state.terminal = Some(terminal);
                self.mailbox.ready.notify_one();
            }
            true
        }
    }

    pub struct CallbackReceiver {
        mailbox: Arc<CallbackMailbox>,
        identity: Option<Arc<SubscriptionIdentity>>,
    }

    impl CallbackReceiver {
        pub fn recv_timeout(&self, timeout: Duration) -> Option<CallbackResult> {
            let state = self.mailbox.state.lock().unwrap();
            let (mut state, wait_result) = self
                .mailbox
                .ready
                .wait_timeout_while(state, timeout, |state| {
                    state.receiver_alive && !state.change_pending && state.terminal.is_none()
                })
                .unwrap();
            if let Some(terminal) = state.terminal.take() {
                return Some(match terminal {
                    CallbackTerminal::Stop => CallbackResult::Stop,
                    CallbackTerminal::Error(message) => {
                        CallbackResult::StopWithError(io::Error::new(io::ErrorKind::Other, message))
                    }
                });
            }
            if state.change_pending {
                state.change_pending = false;
                return Some(CallbackResult::Next);
            }
            if wait_result.timed_out() {
                return None;
            }
            None
        }
    }

    impl Drop for CallbackReceiver {
        fn drop(&mut self) {
            {
                let mut state = self.mailbox.state.lock().unwrap();
                state.receiver_alive = false;
                state.change_pending = false;
                state.terminal = None;
                self.mailbox.ready.notify_all();
            }
            if let Some(identity) = self.identity.take() {
                unsubscribe_exact(&identity);
            }
        }
    }

    pub struct ClipboardSubscription {
        identity: Arc<SubscriptionIdentity>,
    }

    impl ClipboardSubscription {
        pub fn close(&self) {
            unsubscribe_exact(&self.identity);
        }
    }

    impl Drop for ClipboardSubscription {
        fn drop(&mut self) {
            self.close();
        }
    }

    struct Subscriber {
        generation: u64,
        sender: CallbackSender,
    }

    #[derive(Default)]
    struct SubscriberRegistry {
        subscribers: HashMap<String, Subscriber>,
        terminal: Option<String>,
    }

    type Subscribers = Arc<Mutex<SubscriberRegistry>>;

    struct Handler {
        subscribers: Subscribers,
    }

    impl ClipboardHandler for Handler {
        fn on_clipboard_change(&mut self) -> CallbackResult {
            let mut registry = self.subscribers.lock().unwrap();
            if registry.terminal.is_some() {
                return CallbackResult::Stop;
            }
            registry
                .subscribers
                .retain(|_, subscriber| subscriber.sender.notify_change());
            CallbackResult::Next
        }

        fn on_clipboard_error(&mut self, error: io::Error) -> CallbackResult {
            let msg = format!("Clipboard listener error: {}", error);
            notify_subscribers_terminal(&self.subscribers, &msg);
            CallbackResult::StopWithError(error)
        }
    }

    #[derive(Default)]
    pub struct ClipboardListener {
        subscribers: Subscribers,
        handle: Option<(Shutdown, JoinHandle<()>)>,
        next_generation: u64,
    }

    pub fn subscribe(name: String) -> ResultType<(ClipboardSubscription, CallbackReceiver)> {
        log::info!("Subscribe clipboard listener: {}", &name);
        let mut listener_lock = CLIPBOARD_LISTENER.lock().unwrap();
        let Some(generation) = listener_lock.next_generation.checked_add(1) else {
            bail!("Clipboard listener subscription identity exhausted");
        };
        listener_lock.next_generation = generation;
        let identity;
        let receiver;
        {
            let mut registry = listener_lock.subscribers.lock().unwrap();
            if let Some(error) = registry.terminal.as_ref() {
                bail!(error.clone());
            }
            if registry.subscribers.contains_key(&name) {
                bail!("Clipboard listener subscription already exists: {}", name);
            }
            identity = Arc::new(SubscriptionIdentity { name, generation });
            let (sender, new_receiver) = callback_mailbox(Some(Arc::clone(&identity)));
            receiver = new_receiver;
            registry
                .subscribers
                .insert(identity.name.clone(), Subscriber { generation, sender });
        }

        if listener_lock.handle.is_none() {
            log::info!("Start clipboard listener thread");
            let handler = Handler {
                subscribers: listener_lock.subscribers.clone(),
            };
            let (tx_start_res, rx_start_res) = channel();
            let h = match start_clipboard_master_thread(
                handler,
                listener_lock.subscribers.clone(),
                tx_start_res,
            ) {
                Ok(handle) => handle,
                Err(error) => {
                    remove_exact_subscriber(
                        &mut listener_lock.subscribers.lock().unwrap().subscribers,
                        &identity,
                    );
                    // Receiver retirement reacquires the listener lock.
                    drop(listener_lock);
                    drop(receiver);
                    return Err(error.into());
                }
            };
            let shutdown = match rx_start_res.recv() {
                Ok((Some(s), _)) => s,
                Ok((None, err)) => {
                    remove_exact_subscriber(
                        &mut listener_lock.subscribers.lock().unwrap().subscribers,
                        &identity,
                    );
                    if h.join().is_err() {
                        log::error!("Clipboard listener startup thread terminated by panic");
                    }
                    listener_lock.subscribers.lock().unwrap().terminal = None;
                    drop(listener_lock);
                    drop(receiver);
                    bail!(err);
                }

                Err(e) => {
                    remove_exact_subscriber(
                        &mut listener_lock.subscribers.lock().unwrap().subscribers,
                        &identity,
                    );
                    if h.join().is_err() {
                        log::error!("Clipboard listener startup thread terminated by panic");
                    }
                    listener_lock.subscribers.lock().unwrap().terminal = None;
                    drop(listener_lock);
                    drop(receiver);
                    bail!("Failed to create clipboard listener: {}", e);
                }
            };
            listener_lock.handle = Some((shutdown, h));
            log::info!("Clipboard listener thread started");
        }

        log::info!(
            "Clipboard listener subscribed: {} generation {}",
            identity.name,
            identity.generation
        );
        Ok((ClipboardSubscription { identity }, receiver))
    }

    fn unsubscribe_exact(identity: &SubscriptionIdentity) {
        log::info!(
            "Unsubscribe clipboard listener: {} generation {}",
            identity.name,
            identity.generation
        );
        let mut listener_lock = CLIPBOARD_LISTENER.lock().unwrap();
        let is_empty = {
            let mut registry = listener_lock.subscribers.lock().unwrap();
            if let Some(subscriber) = remove_exact_subscriber(&mut registry.subscribers, identity) {
                subscriber.sender.notify_terminal(CallbackTerminal::Stop);
            }
            registry.subscribers.is_empty()
        };
        if is_empty {
            if let Some((shutdown, h)) = listener_lock.handle.take() {
                log::info!("Stop clipboard listener thread");
                shutdown.signal();
                if h.join().is_err() {
                    log::error!("Clipboard listener thread terminated by panic");
                }
                log::info!("Clipboard listener thread stopped");
            }
            listener_lock.subscribers.lock().unwrap().terminal = None;
        }
        log::info!(
            "Clipboard listener unsubscribed: {} generation {}",
            identity.name,
            identity.generation
        );
    }

    fn callback_mailbox(
        identity: Option<Arc<SubscriptionIdentity>>,
    ) -> (CallbackSender, CallbackReceiver) {
        let mailbox = Arc::new(CallbackMailbox {
            state: Mutex::new(CallbackState {
                change_pending: false,
                terminal: None,
                receiver_alive: true,
            }),
            ready: Condvar::new(),
        });
        (
            CallbackSender {
                mailbox: Arc::clone(&mailbox),
            },
            CallbackReceiver { mailbox, identity },
        )
    }

    fn remove_exact_subscriber(
        subscribers: &mut HashMap<String, Subscriber>,
        identity: &SubscriptionIdentity,
    ) -> Option<Subscriber> {
        let is_current = subscribers
            .get(&identity.name)
            .map(|subscriber| subscriber.generation == identity.generation)
            .unwrap_or(false);
        if is_current {
            subscribers.remove(&identity.name)
        } else {
            None
        }
    }

    fn notify_subscribers_terminal(subscribers: &Subscribers, message: &str) {
        let mut registry = subscribers.lock().unwrap();
        if registry.terminal.is_some() {
            return;
        }
        registry.terminal = Some(message.to_owned());
        registry.subscribers.retain(|_, subscriber| {
            subscriber
                .sender
                .notify_terminal(CallbackTerminal::Error(message.to_owned()))
        });
    }

    struct MasterExit(Subscribers);

    impl Drop for MasterExit {
        fn drop(&mut self) {
            notify_subscribers_terminal(&self.0, "Clipboard listener stopped unexpectedly");
        }
    }

    fn start_clipboard_master_thread(
        handler: impl ClipboardHandler + Send + 'static,
        subscribers: Subscribers,
        tx_start_res: Sender<(Option<Shutdown>, String)>,
    ) -> io::Result<JoinHandle<()>> {
        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessage#:~:text=The%20window%20must%20belong%20to%20the%20current%20thread.
        std::thread::Builder::new().spawn(move || {
            let _exit = MasterExit(Arc::clone(&subscribers));
            match Master::new(handler) {
                Ok(mut master) => {
                    if let Err(retired) = tx_start_res
                        .send((Some(master.shutdown_channel()), "".to_owned()))
                    {
                        // Shutdown's zero-capacity send must not precede receiver destruction.
                        drop(master);
                        drop(retired);
                        log::error!("Clipboard listener startup observer retired");
                        return;
                    }
                    log::debug!("Clipboard listener started");
                    if let Err(err) = master.run() {
                        log::error!("Failed to run clipboard listener: {}", err);
                        notify_subscribers_terminal(
                            &subscribers,
                            &format!("Clipboard listener stopped with error: {}", err),
                        );
                    } else {
                        log::debug!("Clipboard listener stopped");
                    }
                }
                Err(err) => {
                    if tx_start_res
                        .send((
                            None,
                            format!("Failed to create clipboard listener: {}", err),
                        ))
                        .is_err()
                    {
                        log::error!("Clipboard listener startup failure observer retired");
                    }
                }
            }
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn clipboard_native_error_is_terminal() {
            let subscribers = Subscribers::default();
            let (sender, receiver) = callback_mailbox(None);
            subscribers.lock().unwrap().subscribers.insert(
                "clipboard".to_owned(),
                Subscriber {
                    generation: 1,
                    sender,
                },
            );
            let mut handler = Handler {
                subscribers: Arc::clone(&subscribers),
            };
            match handler.on_clipboard_error(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "lost native peer",
            )) {
                CallbackResult::StopWithError(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe)
                }
                _ => panic!("native clipboard failure did not stop the master"),
            }
            assert!(matches!(handler.on_clipboard_change(), CallbackResult::Stop));
            assert!(matches!(
                receiver.recv_timeout(Duration::from_millis(1)),
                Some(CallbackResult::StopWithError(_))
            ));
            notify_subscribers_terminal(&subscribers, "later exit");
            assert!(receiver.recv_timeout(Duration::from_millis(1)).is_none());
            assert_eq!(
                subscribers.lock().unwrap().terminal.as_deref(),
                Some("Clipboard listener error: lost native peer")
            );
        }

        #[test]
        fn clipboard_master_exit_closes_the_registry() {
            let subscribers = Subscribers::default();
            let (sender, receiver) = callback_mailbox(None);
            subscribers.lock().unwrap().subscribers.insert(
                "clipboard".to_owned(),
                Subscriber {
                    generation: 1,
                    sender,
                },
            );
            drop(MasterExit(Arc::clone(&subscribers)));
            assert!(subscribers.lock().unwrap().terminal.is_some());
            assert!(matches!(
                receiver.recv_timeout(Duration::from_millis(1)),
                Some(CallbackResult::StopWithError(_))
            ));
        }

        #[test]
        fn clipboard_change_wakes_are_coalesced() {
            let (sender, receiver) = callback_mailbox(None);
            for _ in 0..1024 {
                assert!(sender.notify_change());
            }
            assert!(matches!(
                receiver.recv_timeout(Duration::from_millis(1)),
                Some(CallbackResult::Next)
            ));
            assert!(receiver.recv_timeout(Duration::from_millis(1)).is_none());
        }

        #[test]
        fn clipboard_terminal_error_supersedes_pending_change() {
            let (sender, receiver) = callback_mailbox(None);
            assert!(sender.notify_change());
            assert!(sender.notify_terminal(CallbackTerminal::Error("listener failed".to_owned())));
            match receiver.recv_timeout(Duration::from_millis(1)) {
                Some(CallbackResult::StopWithError(err)) => {
                    assert_eq!(err.to_string(), "listener failed");
                }
                _ => panic!("terminal clipboard error was not delivered first"),
            }
            assert!(receiver.recv_timeout(Duration::from_millis(1)).is_none());
        }

        #[test]
        fn clipboard_receiver_retirement_closes_admission() {
            let (sender, receiver) = callback_mailbox(None);
            drop(receiver);
            assert!(!sender.notify_change());
            assert!(!sender.notify_terminal(CallbackTerminal::Stop));
        }

        #[test]
        fn stale_clipboard_identity_cannot_remove_replacement() {
            let (sender, _receiver) = callback_mailbox(None);
            let mut subscribers = HashMap::new();
            subscribers.insert(
                "clipboard".to_owned(),
                Subscriber {
                    generation: 2,
                    sender,
                },
            );
            let stale = SubscriptionIdentity {
                name: "clipboard".to_owned(),
                generation: 1,
            };
            let current = SubscriptionIdentity {
                name: "clipboard".to_owned(),
                generation: 2,
            };
            assert!(remove_exact_subscriber(&mut subscribers, &stale).is_none());
            assert!(subscribers.contains_key("clipboard"));
            assert!(remove_exact_subscriber(&mut subscribers, &current).is_some());
            assert!(subscribers.is_empty());
        }
    }
}
