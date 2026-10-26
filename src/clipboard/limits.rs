use hbb_common::{bail, ResultType};
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
    let format = clipboard
        .format
        .enum_value()
        .map_err(|e| hbb_common::anyhow::anyhow!("invalid clipboard format: {e}"))?;
    let data: Cow<'_, [u8]> = if clipboard.compress {
        Cow::Owned(hbb_common::compress::try_decompress(&clipboard.content)?)
    } else {
        Cow::Borrowed(&clipboard.content)
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
