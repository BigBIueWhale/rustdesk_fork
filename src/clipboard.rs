#[cfg(not(target_os = "android"))]
use arboard::{ClipboardData, ClipboardFormat};
// R-X13 (§8): arboard LinuxClipboardKind/SetExtLinux were used only by the removed
// set_with_owner_marker_for_linux (Wayland uinput clipboard-paste SET) — import dropped.
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
#[cfg(not(target_os = "android"))]
const CLIPBOARD_UPDATE_QUEUE_CAPACITY: usize = 1;

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
) -> Option<Vec<u8>> {
    let format = clipboard.format.enum_value().ok()?;
    let data = if clipboard.compress {
        hbb_common::compress::peer_decompress(&clipboard.content)
    } else {
        clipboard.content.to_vec()
    };
    if !native_clipboard_payload_within_limit(format, clipboard.width, clipboard.height, data.len())
    {
        log::warn!(
            "dropping oversized or invalid clipboard payload before native handoff: format={format:?}, width={}, height={}, bytes={}",
            clipboard.width,
            clipboard.height,
            data.len()
        );
        return None;
    }
    Some(data)
}

fn sanitize_clipboard_for_native_proto(
    mut clipboard: hbb_common::message_proto::Clipboard,
) -> Option<hbb_common::message_proto::Clipboard> {
    let data = clipboard_content_for_native(&clipboard)?;
    clipboard.content = data.into();
    clipboard.compress = false;
    Some(clipboard)
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
        let Some(clipboard) = sanitize_clipboard_for_native_proto(clipboard) else {
            log::warn!("dropping unsupported clipboard item before native handoff");
            continue;
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
        MAX_NATIVE_CLIPBOARD_ITEMS, MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES,
        MAX_NATIVE_CLIPBOARD_TOTAL_BYTES,
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
        #[cfg(target_os = "linux")]
        {
            use clipboard::platform::unix;
            if unix::fuse::empty_local_files(_side == ClipboardSide::Client, _conn_id) {
                ctx.try_empty_clipboard_files(_side);
            }
        }
        #[cfg(target_os = "macos")]
        {
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
    if let Err(e) = crate::native_clipboard_worker::update_clipboard(multi_clipboards, side) {
        log::warn!(
            "native clipboard worker failed; refusing in-process desktop clipboard update: {}",
            e
        );
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
    // Appendix C #2b / R-T0: peer clipboard SET is a hostile-peer path. The
    // native conversion/platform SET runs behind `native_clipboard_worker`, but
    // spawning a fresh OS thread for each peer message would be a pre-worker
    // thread-amplification DoS. Use one bounded dispatcher and shed newest
    // excess while a previous clipboard update is still being processed.
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
            if let Err(e) = set_native_clipboard_data(vec![ClipboardData::FileUrl(files)], side) {
                log::debug!("Failed to set file clipboard: {}", e);
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
        let exclude_path =
            clipboard::platform::unix::fuse::get_exclude_paths(side == ClipboardSide::Client);
        data.into_iter()
            .filter_map(|c| match c {
                ClipboardData::FileUrl(urls) => Some(
                    urls.into_iter()
                        .filter(|s| s.starts_with(&*exclude_path))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    #[cfg(feature = "unix-file-copy-paste")]
    fn try_empty_clipboard_files(&mut self, side: ClipboardSide) {
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
        let data = super::clipboard_content_for_native(&clipboard)?;
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
pub fn handle_msg_clipboard(_cb: Clipboard) {
    log::warn!(
        "refusing in-process mobile peer clipboard SET helper until a platform worker/service boundary exists"
    );
}

#[cfg(target_os = "android")]
pub fn handle_msg_multi_clipboards(_mcb: MultiClipboards) {
    log::warn!(
        "refusing in-process mobile peer multi-clipboard SET helper until a platform worker/service boundary exists"
    );
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
// https://github.com/rustdesk-org/clipboard-master/blob/4fb62e5b62fb6350d82b571ec7ba94b3cd466695/src/master/x11.rs#L226
#[cfg(not(target_os = "android"))]
pub mod clipboard_listener {
    use clipboard_master::{CallbackResult, ClipboardHandler, Master, Shutdown};
    use hbb_common::{bail, log, ResultType};
    use std::{
        collections::HashMap,
        io,
        sync::mpsc::{channel, Sender},
        sync::{Arc, Mutex},
        thread::JoinHandle,
    };

    lazy_static::lazy_static! {
        pub static ref CLIPBOARD_LISTENER: Arc<Mutex<ClipboardListener>> = Default::default();
    }

    struct Handler {
        subscribers: Arc<Mutex<HashMap<String, Sender<CallbackResult>>>>,
    }

    impl ClipboardHandler for Handler {
        fn on_clipboard_change(&mut self) -> CallbackResult {
            let sub_lock = self.subscribers.lock().unwrap();
            for tx in sub_lock.values() {
                tx.send(CallbackResult::Next).ok();
            }
            CallbackResult::Next
        }

        fn on_clipboard_error(&mut self, error: io::Error) -> CallbackResult {
            let msg = format!("Clipboard listener error: {}", error);
            let sub_lock = self.subscribers.lock().unwrap();
            for tx in sub_lock.values() {
                tx.send(CallbackResult::StopWithError(io::Error::new(
                    io::ErrorKind::Other,
                    msg.clone(),
                )))
                .ok();
            }
            CallbackResult::Next
        }
    }

    #[derive(Default)]
    pub struct ClipboardListener {
        subscribers: Arc<Mutex<HashMap<String, Sender<CallbackResult>>>>,
        handle: Option<(Shutdown, JoinHandle<()>)>,
    }

    pub fn subscribe(name: String, tx: Sender<CallbackResult>) -> ResultType<()> {
        log::info!("Subscribe clipboard listener: {}", &name);
        let mut listener_lock = CLIPBOARD_LISTENER.lock().unwrap();
        listener_lock
            .subscribers
            .lock()
            .unwrap()
            .insert(name.clone(), tx);

        if listener_lock.handle.is_none() {
            log::info!("Start clipboard listener thread");
            let handler = Handler {
                subscribers: listener_lock.subscribers.clone(),
            };
            let (tx_start_res, rx_start_res) = channel();
            let h = start_clipboard_master_thread(handler, tx_start_res);
            let shutdown = match rx_start_res.recv() {
                Ok((Some(s), _)) => s,
                Ok((None, err)) => {
                    bail!(err);
                }

                Err(e) => {
                    bail!("Failed to create clipboard listener: {}", e);
                }
            };
            listener_lock.handle = Some((shutdown, h));
            log::info!("Clipboard listener thread started");
        }

        log::info!("Clipboard listener subscribed: {}", name);
        Ok(())
    }

    pub fn unsubscribe(name: &str) {
        log::info!("Unsubscribe clipboard listener: {}", name);
        let mut listener_lock = CLIPBOARD_LISTENER.lock().unwrap();
        let is_empty = {
            let mut sub_lock = listener_lock.subscribers.lock().unwrap();
            if let Some(tx) = sub_lock.remove(name) {
                tx.send(CallbackResult::Stop).ok();
            }
            sub_lock.is_empty()
        };
        if is_empty {
            if let Some((shutdown, h)) = listener_lock.handle.take() {
                log::info!("Stop clipboard listener thread");
                shutdown.signal();
                h.join().ok();
                log::info!("Clipboard listener thread stopped");
            }
        }
        log::info!("Clipboard listener unsubscribed: {}", name);
    }

    fn start_clipboard_master_thread(
        handler: impl ClipboardHandler + Send + 'static,
        tx_start_res: Sender<(Option<Shutdown>, String)>,
    ) -> JoinHandle<()> {
        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessage#:~:text=The%20window%20must%20belong%20to%20the%20current%20thread.
        let h = std::thread::spawn(move || match Master::new(handler) {
            Ok(mut master) => {
                tx_start_res
                    .send((Some(master.shutdown_channel()), "".to_owned()))
                    .ok();
                log::debug!("Clipboard listener started");
                if let Err(err) = master.run() {
                    log::error!("Failed to run clipboard listener: {}", err);
                } else {
                    log::debug!("Clipboard listener stopped");
                }
            }
            Err(err) => {
                tx_start_res
                    .send((
                        None,
                        format!("Failed to create clipboard listener: {}", err),
                    ))
                    .ok();
            }
        });
        h
    }
}
