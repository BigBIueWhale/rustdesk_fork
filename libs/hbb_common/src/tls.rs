use std::{collections::HashMap, sync::RwLock};

#[derive(Debug, Clone, Copy)]
pub enum TlsType {
    Plain,
    NativeTls,
    Rustls,
}

lazy_static::lazy_static! {
    static ref URL_TLS_TYPE: RwLock<HashMap<String, TlsType>> = RwLock::new(HashMap::new());
}

#[inline]
pub fn is_plain(url: &str) -> bool {
    url.starts_with("ws://") || url.starts_with("http://")
}

// Extract domain from URL.
// e.g., "https://example.com/path" -> "example.com"
//       "https://example.com:8080/path" -> "example.com:8080"
// See the tests for more examples.
#[inline]
fn get_domain_and_port_from_url(url: &str) -> &str {
    // Remove scheme (e.g., http://, https://, ws://, wss://)
    let scheme_end = url.find("://").map(|pos| pos + 3).unwrap_or(0);
    let url2 = &url[scheme_end..];
    // If userinfo is present, domain is after last '@'
    let after_at = match url2.rfind('@') {
        Some(pos) => &url2[pos + 1..],
        None => url2,
    };
    // Find the end of domain (before '/' or '?')
    let domain_end = after_at.find(&['/', '?'][..]).unwrap_or(after_at.len());
    &after_at[..domain_end]
}

#[inline]
pub fn upsert_tls_cache(url: &str, tls_type: TlsType) {
    if is_plain(url) {
        return;
    }

    let domain_port = get_domain_and_port_from_url(url);
    // Use curly braces to ensure the lock is released immediately.
    {
        URL_TLS_TYPE
            .write()
            .unwrap()
            .insert(domain_port.to_string(), tls_type);
    }
}

#[inline]
pub fn reset_tls_cache() {
    // Use curly braces to ensure the lock is released immediately.
    {
        URL_TLS_TYPE.write().unwrap().clear();
    }
}

#[inline]
pub fn get_cached_tls_type(url: &str) -> Option<TlsType> {
    if is_plain(url) {
        return Some(TlsType::Plain);
    }
    let domain_port = get_domain_and_port_from_url(url);
    URL_TLS_TYPE.read().unwrap().get(domain_port).cloned()
}

#[inline]
pub fn get_cached_tls_accept_invalid_cert(_url: &str) -> Option<bool> {
    // R-G4/§8 hardening: insecure-TLS fallback is excised from the fork — outbound TLS NEVER
    // accepts an invalid certificate. This was gated by `allow_insecure_tls_fallback()`, an option
    // the lockdown pins `N`; the guarantee is now STRUCTURAL (no caller can ever obtain a
    // `danger_accept_invalid_certs = true`), not merely config-disabled. The per-host danger cache
    // is now write-only dead (left for a follow-on §8 tidy of the upsert/connector path).
    Some(false)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_domain_and_port_from_url() {
        for (url, expected_domain_port) in vec![
            ("http://example.com", "example.com"),
            ("https://example.com", "example.com"),
            ("ws://example.com/path", "example.com"),
            ("wss://example.com:8080/path", "example.com:8080"),
            ("https://user:pass@example.com", "example.com"),
            ("https://example.com?query=param", "example.com"),
            ("https://example.com:8443?query=param", "example.com:8443"),
            ("ftp://example.com/resource", "example.com"), // ftp scheme
            ("example.com/path", "example.com"),           // no scheme
            ("example.com:8080/path", "example.com:8080"),
        ] {
            let domain_port = get_domain_and_port_from_url(url);
            assert_eq!(domain_port, expected_domain_port);
        }
    }
}
