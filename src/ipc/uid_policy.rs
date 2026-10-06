#[cfg(any(target_os = "macos", target_os = "linux"))]
#[inline]
pub(super) fn is_allowed_service_peer_uid(peer_uid: u32, active_uid: Option<u32>) -> bool {
    // Root is allowed at the UID gate because the service side may run as root.
    // Callers still enforce executable matching before accepting service-scoped peers.
    peer_uid == 0 || active_uid.is_some_and(|uid| uid == peer_uid)
}

#[cfg(target_os = "linux")]
#[inline]
pub(super) fn linux_service_peer_active_uid(
    peer_uid: Option<u32>,
    cached_lookup: impl FnOnce() -> Option<u32>,
    fresh_lookup: impl FnOnce() -> Option<u32>,
) -> Option<u32> {
    if peer_uid == Some(0) {
        return None;
    }
    // The cache may reject a peer, but only a fresh lookup can authorize a non-root peer.
    let cached_active_uid = cached_lookup();
    if matches!(
        (peer_uid, cached_active_uid),
        (Some(peer_uid), Some(active_uid)) if peer_uid == active_uid
    ) {
        fresh_lookup()
    } else {
        cached_active_uid
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn test_service_peer_uid_policy() {
        assert!(super::is_allowed_service_peer_uid(0, None));
        assert!(super::is_allowed_service_peer_uid(501, Some(501)));
        assert!(!super::is_allowed_service_peer_uid(502, Some(501)));
        assert!(!super::is_allowed_service_peer_uid(501, None));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn r_s11e60_linux_service_root_skips_both_uid_lookups() {
        let active_uid = super::linux_service_peer_active_uid(
            Some(0),
            || panic!("root must not consult the cached active UID"),
            || panic!("root must not perform a fresh active UID lookup"),
        );
        assert_eq!(active_uid, None);
        assert!(super::is_allowed_service_peer_uid(0, active_uid));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn r_s11e60_linux_service_cached_negative_skips_fresh_uid_lookup() {
        for (peer_uid, cached_uid) in [
            (Some(502), Some(501)),
            (Some(501), None),
            (None, Some(501)),
        ] {
            let cached_calls = std::cell::Cell::new(0);
            let active_uid = super::linux_service_peer_active_uid(
                peer_uid,
                || {
                    cached_calls.set(cached_calls.get() + 1);
                    cached_uid
                },
                || panic!("a cached negative must not perform a fresh UID lookup"),
            );
            assert_eq!(cached_calls.get(), 1);
            assert_eq!(active_uid, cached_uid);
            assert!(
                !peer_uid.is_some_and(|uid| super::is_allowed_service_peer_uid(uid, active_uid))
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn r_s11e60_linux_service_cache_match_requires_fresh_uid_authority() {
        for fresh_uid in [Some(501), Some(502), None] {
            let cached_calls = std::cell::Cell::new(0);
            let fresh_calls = std::cell::Cell::new(0);
            let active_uid = super::linux_service_peer_active_uid(
                Some(501),
                || {
                    cached_calls.set(cached_calls.get() + 1);
                    Some(501)
                },
                || {
                    fresh_calls.set(fresh_calls.get() + 1);
                    fresh_uid
                },
            );
            assert_eq!(cached_calls.get(), 1);
            assert_eq!(fresh_calls.get(), 1);
            assert_eq!(active_uid, fresh_uid);
            assert_eq!(
                super::is_allowed_service_peer_uid(501, active_uid),
                fresh_uid == Some(501)
            );
        }
    }
}
