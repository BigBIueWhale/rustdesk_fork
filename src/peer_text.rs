use hbb_common::{
    log,
    message_proto::{MessageBox, ScreenshotResponse},
};
use std::time::{Duration, Instant};

pub const MAX_PEER_SCREENSHOT_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PEER_SCREENSHOT_DIMENSION: u32 = 16_384;
pub const MAX_PEER_SCREENSHOT_PIXELS: u64 = 8_192 * 8_192;
pub const MAX_PEER_SCREENSHOT_PNG_CHUNKS: usize = 4_096;
pub const MAX_PEER_SCREENSHOT_SID_BYTES: usize = 128;
pub const MAX_PEER_SCREENSHOT_MSG_BYTES: usize = 1024;
pub const MAX_PEER_CHAT_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_PEER_UI_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_PEER_UI_LABEL_BYTES: usize = 256;
pub const MAX_PEER_UI_TYPE_BYTES: usize = 64;
pub const MAX_PEER_UI_LINK_BYTES: usize = 512;
pub const MAX_PEER_CLOSE_REASON_BYTES: usize = 1024;
pub const MAX_PEER_LOGIN_ERROR_BYTES: usize = 1024;
pub const PEER_CHAT_EVENTS_PER_WINDOW: u32 = 8;
pub const PEER_DIALOG_EVENTS_PER_WINDOW: u32 = 4;
pub const PEER_NOTIFICATION_EVENTS_PER_WINDOW: u32 = 8;
pub const PEER_TEXT_RATE_WINDOW_SECS: u64 = 10;
const PEER_SCREENSHOT_TOO_LARGE_MSG: &str = "Screenshot response too large";
const PEER_SCREENSHOT_INVALID_PNG_MSG: &str = "Screenshot response is not a bounded PNG";
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug)]
struct FixedWindowLimiter {
    started: Instant,
    accepted: u32,
    dropped: u32,
    limit: u32,
    label: &'static str,
}

impl FixedWindowLimiter {
    fn new(limit: u32, label: &'static str) -> Self {
        Self {
            started: Instant::now(),
            accepted: 0,
            dropped: 0,
            limit,
            label,
        }
    }

    fn admit(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.started) >= Duration::from_secs(PEER_TEXT_RATE_WINDOW_SECS) {
            if self.dropped > 0 {
                log::warn!(
                    "dropped {} peer {} events in the previous {}s UI-text window",
                    self.dropped,
                    self.label,
                    PEER_TEXT_RATE_WINDOW_SECS
                );
            }
            self.started = now;
            self.accepted = 0;
            self.dropped = 0;
        }
        if self.accepted < self.limit {
            self.accepted += 1;
            true
        } else {
            self.dropped = self.dropped.saturating_add(1);
            false
        }
    }
}

#[derive(Debug)]
pub struct PeerTextGate {
    chat: FixedWindowLimiter,
    dialog: FixedWindowLimiter,
    notification: FixedWindowLimiter,
}

impl PeerTextGate {
    pub fn new() -> Self {
        Self {
            chat: FixedWindowLimiter::new(PEER_CHAT_EVENTS_PER_WINDOW, "chat"),
            dialog: FixedWindowLimiter::new(PEER_DIALOG_EVENTS_PER_WINDOW, "dialog"),
            notification: FixedWindowLimiter::new(
                PEER_NOTIFICATION_EVENTS_PER_WINDOW,
                "notification",
            ),
        }
    }

    pub fn admit_chat(&mut self, text: String) -> Option<String> {
        if self.chat.admit() {
            Some(bound_peer_text(text, MAX_PEER_CHAT_TEXT_BYTES))
        } else {
            None
        }
    }

    pub fn admit_dialog(&mut self) -> bool {
        self.dialog.admit()
    }

    pub fn admit_notification(&mut self) -> bool {
        self.notification.admit()
    }

    pub fn admit_message_box(&mut self, mut msgbox: MessageBox) -> Option<MessageBox> {
        if !self.admit_dialog() {
            return None;
        }
        msgbox.msgtype = bound_peer_label(msgbox.msgtype, MAX_PEER_UI_TYPE_BYTES);
        msgbox.title = bound_peer_label(msgbox.title, MAX_PEER_UI_LABEL_BYTES);
        msgbox.text = bound_peer_text(msgbox.text, MAX_PEER_UI_TEXT_BYTES);
        msgbox.link = bound_peer_label(msgbox.link, MAX_PEER_UI_LINK_BYTES);
        Some(msgbox)
    }
}

impl Default for PeerTextGate {
    fn default() -> Self {
        Self::new()
    }
}

pub fn bound_peer_close_reason(reason: String) -> String {
    bound_peer_text(reason, MAX_PEER_CLOSE_REASON_BYTES)
}

pub fn bound_peer_login_error(error: String) -> String {
    bound_peer_text(error, MAX_PEER_LOGIN_ERROR_BYTES)
}

pub fn bound_peer_notification_details(details: String) -> String {
    bound_peer_text(details, MAX_PEER_UI_TEXT_BYTES)
}

pub fn admit_peer_screenshot_response(
    mut response: ScreenshotResponse,
) -> Result<ScreenshotResponse, (String, String)> {
    let data_len = response.data.len();
    response.sid = bound_peer_label(response.sid, MAX_PEER_SCREENSHOT_SID_BYTES);
    response.msg = bound_peer_text(response.msg, MAX_PEER_SCREENSHOT_MSG_BYTES);
    if data_len > MAX_PEER_SCREENSHOT_RESPONSE_BYTES {
        log::warn!(
            "dropping oversized peer screenshot response: {} > {} bytes",
            data_len,
            MAX_PEER_SCREENSHOT_RESPONSE_BYTES
        );
        return Err((response.sid, PEER_SCREENSHOT_TOO_LARGE_MSG.to_owned()));
    }
    if data_len == 0 {
        return if response.msg.is_empty() {
            Err((response.sid, PEER_SCREENSHOT_INVALID_PNG_MSG.to_owned()))
        } else {
            Ok(response)
        };
    }
    if !response.msg.is_empty() {
        return Err((response.sid, PEER_SCREENSHOT_INVALID_PNG_MSG.to_owned()));
    }
    if !peer_screenshot_png_within_limit(&response.data) {
        log::warn!("dropping structurally invalid or oversized peer screenshot PNG");
        return Err((response.sid, PEER_SCREENSHOT_INVALID_PNG_MSG.to_owned()));
    }
    Ok(response)
}

fn peer_screenshot_png_within_limit(data: &[u8]) -> bool {
    if data.len() < 33 || !data.starts_with(PNG_SIGNATURE) {
        return false;
    }

    let mut pos = PNG_SIGNATURE.len();
    let mut chunk_count = 0usize;
    let mut saw_ihdr = false;
    let mut saw_idat = false;
    while pos < data.len() {
        chunk_count = match chunk_count.checked_add(1) {
            Some(count) if count <= MAX_PEER_SCREENSHOT_PNG_CHUNKS => count,
            _ => return false,
        };
        let Some(header_end) = pos.checked_add(8) else {
            return false;
        };
        if header_end > data.len() {
            return false;
        }
        let chunk_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let chunk_type = &data[pos + 4..pos + 8];
        let Some(chunk_data_start) = pos.checked_add(8) else {
            return false;
        };
        let Some(chunk_crc_start) = chunk_data_start.checked_add(chunk_len) else {
            return false;
        };
        let Some(next_pos) = chunk_crc_start.checked_add(4) else {
            return false;
        };
        if next_pos > data.len() {
            return false;
        }

        if !saw_ihdr {
            if chunk_type != b"IHDR" || chunk_len != 13 {
                return false;
            }
            let ihdr = &data[chunk_data_start..chunk_crc_start];
            if !valid_png_ihdr(ihdr) {
                return false;
            }
            saw_ihdr = true;
        }

        if chunk_type == b"IDAT" {
            saw_idat = true;
        }
        if chunk_type == b"IEND" {
            return saw_ihdr && saw_idat && chunk_len == 0 && next_pos == data.len();
        }
        pos = next_pos;
    }
    false
}

fn valid_png_ihdr(ihdr: &[u8]) -> bool {
    if ihdr.len() != 13 {
        return false;
    }
    let width = u32::from_be_bytes([ihdr[0], ihdr[1], ihdr[2], ihdr[3]]);
    let height = u32::from_be_bytes([ihdr[4], ihdr[5], ihdr[6], ihdr[7]]);
    if width == 0
        || height == 0
        || width > MAX_PEER_SCREENSHOT_DIMENSION
        || height > MAX_PEER_SCREENSHOT_DIMENSION
    {
        return false;
    }
    let pixels = u64::from(width) * u64::from(height);
    if pixels > MAX_PEER_SCREENSHOT_PIXELS {
        return false;
    }
    valid_png_bit_depth_color(ihdr[8], ihdr[9]) && ihdr[10] == 0 && ihdr[11] == 0 && ihdr[12] <= 1
}

fn valid_png_bit_depth_color(bit_depth: u8, color_type: u8) -> bool {
    match color_type {
        0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
        2 | 4 | 6 => matches!(bit_depth, 8 | 16),
        3 => matches!(bit_depth, 1 | 2 | 4 | 8),
        _ => false,
    }
}

fn bound_peer_label(input: String, max_bytes: usize) -> String {
    bound_peer_text_with_controls(input, max_bytes, false)
}

fn bound_peer_text(input: String, max_bytes: usize) -> String {
    bound_peer_text_with_controls(input, max_bytes, true)
}

fn bound_peer_text_with_controls(input: String, max_bytes: usize, allow_layout: bool) -> String {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    for ch in input.chars() {
        if ch.is_control() {
            let allowed_layout = allow_layout && (ch == '\n' || ch == '\t');
            if !allowed_layout {
                continue;
            }
        }
        let next_len = out.len().saturating_add(ch.len_utf8());
        if next_len > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_png(width: u32, height: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(PNG_SIGNATURE);
        data.extend_from_slice(&13u32.to_be_bytes());
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&[8, 6, 0, 0, 0]);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(b"IDAT");
        data.push(0);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&0u32.to_be_bytes());
        data
    }

    #[test]
    fn peer_text_bound_preserves_utf8_and_strips_controls() {
        let input = format!("ab\u{0000}c\n{}\u{0007}", "é".repeat(3000));
        let out = bound_peer_text(input, 17);
        assert!(out.len() <= 17);
        assert!(out.is_char_boundary(out.len()));
        assert!(out.contains('\n'));
        assert!(!out.contains('\u{0000}'));
        assert!(!out.contains('\u{0007}'));
    }

    #[test]
    fn peer_labels_strip_layout_controls() {
        let out = bound_peer_label("a\nb\tc".to_string(), MAX_PEER_UI_LABEL_BYTES);
        assert_eq!(out, "abc");
    }

    #[test]
    fn chat_rate_limit_sheds_after_window_capacity() {
        let mut gate = PeerTextGate::new();
        for _ in 0..PEER_CHAT_EVENTS_PER_WINDOW {
            assert!(gate.admit_chat("hello".to_string()).is_some());
        }
        assert!(gate.admit_chat("excess".to_string()).is_none());
    }

    #[test]
    fn peer_message_box_fields_are_bounded() {
        let mut gate = PeerTextGate::new();
        let msgbox = MessageBox {
            msgtype: "x".repeat(MAX_PEER_UI_TYPE_BYTES + 8),
            title: "t".repeat(MAX_PEER_UI_LABEL_BYTES + 8),
            text: "m".repeat(MAX_PEER_UI_TEXT_BYTES + 8),
            link: "l".repeat(MAX_PEER_UI_LINK_BYTES + 8),
            ..Default::default()
        };
        let bounded = gate
            .admit_message_box(msgbox)
            .expect("first dialog admitted");
        assert_eq!(bounded.msgtype.len(), MAX_PEER_UI_TYPE_BYTES);
        assert_eq!(bounded.title.len(), MAX_PEER_UI_LABEL_BYTES);
        assert_eq!(bounded.text.len(), MAX_PEER_UI_TEXT_BYTES);
        assert_eq!(bounded.link.len(), MAX_PEER_UI_LINK_BYTES);
    }

    #[test]
    fn screenshot_response_fields_are_bounded() {
        let png = tiny_png(2, 2);
        let response = ScreenshotResponse {
            data: png.clone().into(),
            sid: format!("sid\n{}", "x".repeat(MAX_PEER_SCREENSHOT_SID_BYTES + 8)),
            msg: String::new(),
            ..Default::default()
        };
        let admitted = admit_peer_screenshot_response(response).expect("response admitted");
        assert_eq!(admitted.data.len(), png.len());
        assert!(admitted.sid.len() <= MAX_PEER_SCREENSHOT_SID_BYTES);
        assert!(!admitted.sid.contains('\n'));
        assert!(admitted.msg.is_empty());
    }

    #[test]
    fn oversized_screenshot_response_is_rejected_after_bounding_sid() {
        let response = ScreenshotResponse {
            data: vec![0u8; MAX_PEER_SCREENSHOT_RESPONSE_BYTES + 1].into(),
            sid: format!("sid\t{}", "x".repeat(MAX_PEER_SCREENSHOT_SID_BYTES + 8)),
            msg: "ignored".to_owned(),
            ..Default::default()
        };
        let (sid, msg) = match admit_peer_screenshot_response(response) {
            Ok(_) => panic!("oversized response admitted"),
            Err(err) => err,
        };
        assert!(sid.len() <= MAX_PEER_SCREENSHOT_SID_BYTES);
        assert!(!sid.contains('\t'));
        assert_eq!(msg, PEER_SCREENSHOT_TOO_LARGE_MSG);
    }

    #[test]
    fn screenshot_error_response_without_data_is_admitted() {
        let response = ScreenshotResponse {
            sid: "sid".to_owned(),
            msg: "capture failed".to_owned(),
            ..Default::default()
        };
        let admitted = admit_peer_screenshot_response(response).expect("error response admitted");
        assert!(admitted.data.is_empty());
        assert_eq!(admitted.msg, "capture failed");
    }

    #[test]
    fn arbitrary_screenshot_bytes_are_rejected_before_cache() {
        let response = ScreenshotResponse {
            data: b"not a png".to_vec().into(),
            sid: "sid".to_owned(),
            ..Default::default()
        };
        let (_sid, msg) = admit_peer_screenshot_response(response).expect_err("blob rejected");
        assert_eq!(msg, PEER_SCREENSHOT_INVALID_PNG_MSG);
    }

    #[test]
    fn screenshot_png_dimensions_are_bounded() {
        let response = ScreenshotResponse {
            data: tiny_png(MAX_PEER_SCREENSHOT_DIMENSION + 1, 1).into(),
            sid: "sid".to_owned(),
            ..Default::default()
        };
        let (_sid, msg) = admit_peer_screenshot_response(response).expect_err("wide png rejected");
        assert_eq!(msg, PEER_SCREENSHOT_INVALID_PNG_MSG);

        let response = ScreenshotResponse {
            data: tiny_png(8_193, 8_193).into(),
            sid: "sid".to_owned(),
            ..Default::default()
        };
        let (_sid, msg) =
            admit_peer_screenshot_response(response).expect_err("pixel count rejected");
        assert_eq!(msg, PEER_SCREENSHOT_INVALID_PNG_MSG);
    }
}
