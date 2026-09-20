pub(crate) struct WhiteboardEventLifecycle<Proxy> {
    pub(crate) proxy: Option<Proxy>,
    ipc_terminated: bool,
}

impl<Proxy> Default for WhiteboardEventLifecycle<Proxy> {
    fn default() -> Self {
        Self {
            proxy: None,
            ipc_terminated: false,
        }
    }
}

impl<Proxy> WhiteboardEventLifecycle<Proxy> {
    pub(crate) fn install(&mut self, proxy: Proxy) -> Option<Proxy> {
        if self.ipc_terminated {
            Some(proxy)
        } else {
            self.proxy = Some(proxy);
            None
        }
    }

    pub(crate) fn terminate(&mut self) -> Option<Proxy> {
        if self.ipc_terminated {
            return None;
        }
        self.ipc_terminated = true;
        self.proxy.take()
    }

    pub(crate) fn clear_proxy(&mut self) {
        self.proxy = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_s11hn_whiteboard_ipc_termination_before_proxy_is_delivered_once() {
        let mut lifecycle = WhiteboardEventLifecycle::default();
        assert_eq!(lifecycle.terminate(), None);
        assert_eq!(lifecycle.install(7), Some(7));
        assert_eq!(lifecycle.terminate(), None);
        assert!(lifecycle.proxy.is_none());
    }

    #[test]
    fn r_s11hn_whiteboard_ipc_termination_takes_exact_installed_proxy_once() {
        let mut lifecycle = WhiteboardEventLifecycle::default();
        assert_eq!(lifecycle.install(11), None);
        assert_eq!(lifecycle.terminate(), Some(11));
        assert_eq!(lifecycle.terminate(), None);
        assert!(lifecycle.proxy.is_none());
    }

    #[test]
    fn r_s11hn_whiteboard_event_loop_retirement_preserves_terminal_latch() {
        let mut lifecycle = WhiteboardEventLifecycle::default();
        assert_eq!(lifecycle.install(13), None);
        lifecycle.clear_proxy();
        assert_eq!(lifecycle.terminate(), None);
        assert_eq!(lifecycle.install(17), Some(17));
        assert!(lifecycle.proxy.is_none());
    }
}
