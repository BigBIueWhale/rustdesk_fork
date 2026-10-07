thread_local! {
    static XDO: RefCell<Option<NativeContext<xdo_t>>> = RefCell::new(match x11_context::open_xdo() {
        Ok(context) => Some(context),
        Err(error) => {
            log::warn!("Failed to create local xdo context: {error}");
            None
        }
    });
    static DISPLAY: RefCell<Option<NativeContext<c_void>>> = RefCell::new(match x11_context::open_display() {
        Ok(context) => Some(context),
        Err(error) => {
            log::warn!("Failed to open local X11 display: {error}");
            None
        }
    });
}
