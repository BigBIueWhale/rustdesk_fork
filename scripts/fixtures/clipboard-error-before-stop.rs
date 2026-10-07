        fn on_clipboard_error(&mut self, error: io::Error) -> CallbackResult {
            let msg = format!("Clipboard listener error: {}", error);
            notify_subscribers_terminal(&self.subscribers, &msg);
            CallbackResult::Next
        }
