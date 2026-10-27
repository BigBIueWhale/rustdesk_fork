use hbb_common::{bail, log, message_proto::MultiClipboards, ResultType};
use std::{borrow::Cow, io};

/// Clipboard content ceilings apply independently to wire and decoded bytes.
pub(crate) const MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_NATIVE_CLIPBOARD_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_NATIVE_CLIPBOARD_ITEMS: usize = 16;
pub(crate) const MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES: usize = 256;

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

pub(crate) fn clipboard_content_for_native(
    clipboard: &hbb_common::message_proto::Clipboard,
) -> ResultType<Vec<u8>> {
    clipboard_content_for_native_with_limit(clipboard, MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES)
}

fn clipboard_content_for_native_with_limit(
    clipboard: &hbb_common::message_proto::Clipboard,
    max_payload_bytes: usize,
) -> ResultType<Vec<u8>> {
    let max_payload_bytes = max_payload_bytes.min(MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES);
    let format = clipboard
        .format
        .enum_value()
        .map_err(|e| hbb_common::anyhow::anyhow!("invalid clipboard format: {e}"))?;
    let output_limit = if format == hbb_common::message_proto::ClipboardFormat::ImageRgba {
        rgba_clipboard_len(clipboard.width, clipboard.height)
            .filter(|length| *length <= max_payload_bytes)
            .ok_or_else(|| hbb_common::anyhow::anyhow!(
                "invalid clipboard image geometry: width={}, height={}",
                clipboard.width,
                clipboard.height,
            ))?
    } else {
        max_payload_bytes
    };
    let data: Cow<'_, [u8]> = if clipboard.compress {
        Cow::Owned(hbb_common::compress::try_decompress_with_limit(
            &clipboard.content,
            output_limit,
        )?)
    } else {
        Cow::Borrowed(&clipboard.content)
    };
    if data.len() > output_limit
        || !native_clipboard_payload_within_limit(format, clipboard.width, clipboard.height, data.len())
    {
        bail!(
            "oversized or invalid clipboard payload before native handoff: format={format:?}, width={}, height={}, bytes={}",
            clipboard.width,
            clipboard.height,
            data.len()
        );
    }
    match data {
        Cow::Owned(data) => Ok(data),
        Cow::Borrowed(data) => {
            let mut output = Vec::new();
            output.try_reserve_exact(data.len())
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
            output.extend_from_slice(data);
            Ok(output)
        }
    }
}

// Add special format for Excel XML Spreadsheet
pub(crate) const CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET: &'static str = "XML Spreadsheet";

fn sanitize_clipboard_for_native_proto(
    mut clipboard: hbb_common::message_proto::Clipboard,
    remaining_bytes: usize,
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
    let data = clipboard_content_for_native_with_limit(&clipboard, remaining_bytes)?;
    clipboard.content = data.into();
    clipboard.compress = false;
    Ok(Some(clipboard))
}

pub(crate) fn sanitize_multi_clipboards_for_native_proto(
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

    let mut remaining = MAX_NATIVE_CLIPBOARD_TOTAL_BYTES;
    let mut sanitized = Vec::with_capacity(clipboards.len());
    for clipboard in clipboards {
        let clipboard = match sanitize_clipboard_for_native_proto(clipboard, remaining) {
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
        remaining = match remaining.checked_sub(clipboard.content.len()) {
            Some(remaining) => remaining,
            None => {
                log::warn!("clipboard item exceeded its remaining aggregate budget");
                return None;
            }
        };
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
