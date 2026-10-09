//! Dependency re-exports and the production local-display selector used by native components.
//! Each crate is the actual root-lock-pinned source, not a mock implementation.
pub use libc;
pub use libloading;
pub use log;
pub use x11;

pub mod platform {
    #[path = "/work/libs/hbb_common/src/platform/x11_display.rs"]
    pub mod x11_display;
}
