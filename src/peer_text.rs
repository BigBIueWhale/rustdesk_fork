use hbb_common::{log, message_proto::MessageBox};
use std::time::{Duration, Instant};

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
}
