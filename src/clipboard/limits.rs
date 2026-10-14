/// Clipboard content ceilings apply independently to wire and decoded bytes.
pub(crate) const MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_NATIVE_CLIPBOARD_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_NATIVE_CLIPBOARD_ITEMS: usize = 16;
pub(crate) const MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES: usize = 256;
