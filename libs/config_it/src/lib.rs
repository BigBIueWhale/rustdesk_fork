//! No library code — this crate exists only to host the R-S16 PINNED_SETTINGS
//! policy-funnel integration test in `tests/`, built against hbb_common (library
//! only, so the broken `webrtc`/`sdp` dev-dep is excluded). The policy is
//! unconditional now (the lockdown build-split feature was retired, R-R2b).
//! See `tests/lockdown.rs`.
