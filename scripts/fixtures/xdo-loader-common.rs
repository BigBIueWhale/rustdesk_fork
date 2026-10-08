//! Dependency re-exports and production display selection used by the native components.
//! Each crate is the actual root-lock-pinned source, not a mock implementation.
pub use libc;
pub use libloading;
pub use log;
pub use x11;

pub mod platform {
    #[path = "/work/libs/hbb_common/src/platform/x11_display.rs"]
    pub mod x11_display;
    pub mod linux {
        // Exact production constants/functions extracted inside the guest build;
        // the rest of hbb_common's Linux module is deliberately not compiled here.
        include!("/loader-build/x11-policy.rs");
    }
}
