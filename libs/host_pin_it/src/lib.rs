//! Isolated KAT crate for `hbb_common::host_pin` (R-S17). The assertions live in
//! `tests/host_pin.rs`; this lib is intentionally empty so the crate pulls only
//! hbb_common's *library* (no `sdp`/webrtc dev-deps that fail on rust 1.75). See
//! `address_it` for the sibling pattern.
