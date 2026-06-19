//! This crate intentionally has no library code. It exists only to host the
//! wire-level CPace handshake integration tests in `tests/`, isolated from
//! hbb_common's `webrtc` dev-dependency (whose `sdp` crate does not compile on
//! the pinned 1.75 toolchain). See `tests/handshake.rs`.
