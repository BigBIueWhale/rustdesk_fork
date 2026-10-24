use crate::config::Config;
use sodiumoxide::{base64, crypto::secretbox};

// R-X7: the rotating one-time (temporary) password is EXCISED — the permanent password is the
// fork's sole credential and sole CPace PRS (R-S9/R-P1). The TEMPORARY_PASSWORD store, its
// generator, update/read, and the per-connection failure-rotation are removed. The
// `OnlyUseTemporaryPassword` resolver variant and the `use-temporary-password` token are removed
// too (R-A6 lists that token grep-zero), leaving `verification_method` as a funnel read (R-S16)
// over only the two surviving, permanent-accepting methods.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationMethod {
    OnlyUsePermanentPassword,
    UseBothPasswords,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveMode {
    Both,
    Password,
    Click,
}

fn verification_method() -> VerificationMethod {
    // Funnel read (R-S16); the R-S16 pin resolves this to `use-permanent-password`. The excised
    // temporary-password branch and its `use-temporary-password` token are gone (R-X7/R-A6).
    let method = Config::get_option("verification-method");
    if method == "use-permanent-password" {
        VerificationMethod::OnlyUsePermanentPassword
    } else {
        VerificationMethod::UseBothPasswords // default
    }
}

pub fn permanent_enabled() -> bool {
    // Every surviving verification method accepts the permanent password (the temporary path is
    // excised, R-X7). Exhaustive match (no wildcard) so re-adding a method is a compile error, not
    // a silent fail-open; retained as a funnel read (R-S16), never a bare constant.
    match verification_method() {
        VerificationMethod::OnlyUsePermanentPassword | VerificationMethod::UseBothPasswords => true,
    }
}

pub fn has_valid_password() -> bool {
    // R-X7: only the permanent password remains (the temporary-password path is excised).
    permanent_enabled() && Config::has_permanent_password()
}

pub fn approve_mode() -> ApproveMode {
    let mode = Config::get_option("approve-mode");
    if mode == "password" {
        ApproveMode::Password
    } else if mode == "click" {
        ApproveMode::Click
    } else {
        ApproveMode::Both
    }
}

pub fn hide_cm() -> bool {
    approve_mode() == ApproveMode::Password
        && verification_method() == VerificationMethod::OnlyUsePermanentPassword
        && crate::config::option2bool("allow-hide-cm", &Config::get_option("allow-hide-cm"))
}

pub(crate) const PASSWORD_ENC_VERSION: &str = "00";
const VERSION_LEN: usize = PASSWORD_ENC_VERSION.len();
const FORMAT_V1: u8 = 1;

// Check if data is already encrypted by verifying:
// 1) version prefix "00"
// 2) valid base64 payload
// 3) decoded payload length >= secretbox::MACBYTES
//
// We intentionally avoid trying to decrypt here because key mismatch would cause
// false negatives.
// The decoded payload may be either legacy ciphertext or FORMAT_V1 || nonce || ciphertext.
// Reference: secretbox::seal returns ciphertext length = plaintext length + MACBYTES
// https://github.com/sodiumoxide/sodiumoxide/blob/3057acb1a030ad86ed8892a223d64036ab5e8523/src/crypto/secretbox/xsalsa20poly1305.rs#L67
fn is_encrypted(v: &[u8]) -> bool {
    if v.len() <= VERSION_LEN || !v.starts_with(b"00") {
        return false;
    }
    match base64::decode(&v[VERSION_LEN..], base64::Variant::Original) {
        Ok(decoded) => decoded.len() >= sodiumoxide::crypto::secretbox::MACBYTES,
        Err(_) => false,
    }
}

pub fn encrypt_str_or_original(s: &str, max_len: usize) -> String {
    if is_encrypted(s.as_bytes()) {
        log::error!("Duplicate encryption!");
        return s.to_owned();
    }
    if s.chars().count() > max_len {
        return String::default();
    }
    if let Ok(s) = encrypt(s.as_bytes()) {
        return PASSWORD_ENC_VERSION.to_owned() + &s;
    }
    log::error!("At-rest string encryption failed");
    String::default()
}

// String: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
// note: s.len() return length in bytes, s.chars().count() return char count
//       &[..2] return the left 2 bytes, s.chars().take(2) return the left 2 chars
pub fn decrypt_str_or_original(s: &str, current_version: &str) -> (String, bool, bool) {
    if s.len() > VERSION_LEN {
        if s.starts_with("00") {
            if let Ok(decrypted) = decrypt(s[VERSION_LEN..].as_bytes()) {
                return (
                    String::from_utf8_lossy(&decrypted.value).to_string(),
                    true,
                    decrypted.should_rewrap || "00" != current_version,
                );
            }
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (
        s.to_owned(),
        false,
        !s.is_empty() && !is_encrypted(s.as_bytes()),
    )
}

pub fn encrypt_vec_or_original(v: &[u8], max_len: usize) -> Vec<u8> {
    if is_encrypted(v) {
        log::error!("Duplicate encryption!");
        return v.to_owned();
    }
    if v.len() > max_len {
        return vec![];
    }
    if let Ok(s) = encrypt(v) {
        let mut wrapped = PASSWORD_ENC_VERSION.as_bytes().to_vec();
        wrapped.extend_from_slice(s.as_bytes());
        return wrapped;
    }
    log::error!("At-rest vector encryption failed");
    Vec::new()
}

// Vec<u8>: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
pub fn decrypt_vec_or_original(v: &[u8], current_version: &str) -> (Vec<u8>, bool, bool) {
    if v.len() > VERSION_LEN {
        let version = String::from_utf8_lossy(&v[..VERSION_LEN]);
        if version == "00" {
            if let Ok(decrypted) = decrypt(&v[VERSION_LEN..]) {
                return (
                    decrypted.value,
                    true,
                    decrypted.should_rewrap || version != current_version,
                );
            }
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (v.to_owned(), false, !v.is_empty() && !is_encrypted(v))
}

fn encrypt(v: &[u8]) -> Result<String, ()> {
    if !v.is_empty() {
        symmetric_crypt(v, true).map(|v| base64::encode(v, base64::Variant::Original))
    } else {
        Err(())
    }
}

struct DecryptedStorage {
    value: Vec<u8>,
    should_rewrap: bool,
}

fn decrypt(v: &[u8]) -> Result<DecryptedStorage, ()> {
    if !v.is_empty() {
        base64::decode(v, base64::Variant::Original)
            .and_then(|decoded| open_at_rest_payload(&decoded))
    } else {
        Err(())
    }
}

pub fn symmetric_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    if encrypt {
        let storage_key = crate::at_rest_storage_key().map_err(|err| {
            log::error!("At-rest storage key unavailable for encryption: {err}");
        })?;
        let key = secretbox_key_from_storage_key(storage_key)?;
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(data, &nonce, &key);
        let mut output = Vec::with_capacity(1 + nonce.0.len() + encrypted.len());
        output.push(FORMAT_V1);
        output.extend(nonce.0);
        output.extend(encrypted);
        Ok(output)
    } else {
        open_at_rest_payload(data).map(|decrypted| decrypted.value)
    }
}

fn open_at_rest_payload(data: &[u8]) -> Result<DecryptedStorage, ()> {
    match crate::at_rest_storage_key() {
        Ok(storage_key) => {
            let key = secretbox_key_from_storage_key(storage_key.clone())?;
            match open_secretbox_payload(data, &key) {
                Ok(value) => Ok(DecryptedStorage {
                    value,
                    should_rewrap: false,
                }),
                Err(_) => open_with_existing_key_pair(data, Some(&storage_key)),
            }
        }
        Err(err) => {
            log::error!("At-rest storage key unavailable for decryption: {err}");
            open_with_existing_key_pair(data, None)
        }
    }
}

fn secretbox_key_from_storage_key(mut storage_key: Vec<u8>) -> Result<secretbox::Key, ()> {
    use std::convert::TryInto;

    if storage_key.is_empty() {
        return Err(());
    }
    storage_key.resize(secretbox::KEYBYTES, 0);
    Ok(secretbox::Key(storage_key.try_into().map_err(|_| ())?))
}

fn legacy_key_pair_fallback_authorized(storage_key_available: bool, mobile: bool) -> bool {
    // On mobile, the config keypair is migration material, not an alternative storage
    // authority. Only try it after the OS-protected key was installed and failed to open
    // old ciphertext. If the OS key is unavailable, encrypted reads must stay fail-closed.
    storage_key_available || !mobile
}

fn open_with_existing_key_pair(
    data: &[u8],
    primary_key: Option<&[u8]>,
) -> Result<DecryptedStorage, ()> {
    let mobile = cfg!(any(target_os = "android", target_os = "ios"));
    if !legacy_key_pair_fallback_authorized(primary_key.is_some(), mobile) {
        return Err(());
    }
    let Some(key_pair) = Config::get_existing_key_pair() else {
        return Err(());
    };
    let pk = key_pair.1;
    if primary_key == Some(pk.as_slice()) {
        return Err(());
    }
    let key = secretbox_key_from_storage_key(pk)?;
    open_secretbox_payload(data, &key).map(|value| DecryptedStorage {
        value,
        should_rewrap: mobile,
    })
}

fn open_secretbox_payload(data: &[u8], key: &secretbox::Key) -> Result<Vec<u8>, ()> {
    if data.first() == Some(&FORMAT_V1)
        && data.len() >= 1 + secretbox::NONCEBYTES + secretbox::MACBYTES
    {
        let mut nonce = [0u8; secretbox::NONCEBYTES];
        nonce.copy_from_slice(&data[1..1 + secretbox::NONCEBYTES]);
        let nonce = secretbox::Nonce(nonce);
        if let Ok(decrypted) = secretbox::open(&data[1 + secretbox::NONCEBYTES..], &nonce, key) {
            return Ok(decrypted);
        }
    }

    let legacy_nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
    secretbox::open(data, &legacy_nonce, key)
}

#[cfg(test)]
mod test {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    static LEGACY_KEY_PAIR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    struct LegacyKeyPairCacheGuard;

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    impl Drop for LegacyKeyPairCacheGuard {
        fn drop(&mut self) {
            crate::config::Config::set_existing_key_pair_cache_for_test(None);
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn install_legacy_key_pair_for_test(primary_key: &[u8]) -> (Vec<u8>, LegacyKeyPairCacheGuard) {
        let mut pk = vec![0x42; sodiumoxide::crypto::secretbox::KEYBYTES];
        if pk.as_slice() == primary_key {
            pk[0] ^= 1;
        }
        crate::config::Config::set_existing_key_pair_cache_for_test(Some((
            vec![0x24; sodiumoxide::crypto::secretbox::KEYBYTES],
            pk.clone(),
        )));
        (pk, LegacyKeyPairCacheGuard)
    }

    #[test]
    fn test_storage_wrappers() {
        use super::*;

        let version = "00";
        let max_len = 128;
        assert!(encrypt_str_or_original("x", 0).is_empty());
        assert!(encrypt_vec_or_original(b"x", 0).is_empty());
        assert!(encrypt_str_or_original(&"ü".repeat(max_len + 1), max_len).is_empty());
        assert!(encrypt_vec_or_original(&vec![b'x'; max_len + 1], max_len).is_empty());
        let unicode = "ü".repeat(max_len);
        let encrypted = encrypt_str_or_original(&unicode, max_len);
        assert_eq!(decrypt_str_or_original(&encrypted, version).0, unicode);

        println!("test str");
        let data = "1ü1111";
        let encrypted = encrypt_str_or_original(data, max_len);
        let (decrypted, succ, store) = decrypt_str_or_original(&encrypted, version);
        println!("data: {data}");
        println!("encrypted: {encrypted}");
        println!("decrypted: {decrypted}");
        assert_eq!(data, decrypted);
        assert_eq!(version, &encrypted[..2]);
        assert!(succ);
        assert!(!store);
        let (_, _, store) = decrypt_str_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_str_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_str_or_original(&encrypted, max_len),
            encrypted
        );

        println!("test vec");
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        let encrypted = encrypt_vec_or_original(&data, max_len);
        let (decrypted, succ, store) = decrypt_vec_or_original(&encrypted, version);
        println!("data: {data:?}");
        println!("encrypted: {encrypted:?}");
        println!("decrypted: {decrypted:?}");
        assert_eq!(data, decrypted);
        assert_eq!(version.as_bytes(), &encrypted[..2]);
        assert!(!store);
        assert!(succ);
        let (_, _, store) = decrypt_vec_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_vec_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_vec_or_original(&encrypted, max_len),
            encrypted
        );

        println!("test original");
        let data = version.to_string() + "Hello World";
        let (decrypted, succ, store) = decrypt_str_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let verbytes = version.as_bytes();
        let data: Vec<u8> = vec![verbytes[0], verbytes[1], 1, 2, 3, 4, 5, 6];
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let (_, succ, store) = decrypt_str_or_original("", version);
        assert!(!store);
        assert!(!succ);
        let (_, succ, store) = decrypt_vec_or_original(&[], version);
        assert!(!store);
        assert!(!succ);
        let data = "1ü1111";
        assert_eq!(decrypt_str_or_original(data, version).0, data);
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        assert_eq!(decrypt_vec_or_original(&data, version).0, data);

        // Base64-shaped "00" prefixed values shorter than MACBYTES are treated
        // as original/plain values and should be stored.
        let data = "00YWJjZA==";
        let (decrypted, succ, store) = decrypt_str_or_original(data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);
        let data = b"00YWJjZA==".to_vec();
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);

        // When decoded length reaches MACBYTES, it is treated as encrypted-like
        // and should not trigger repeated store.
        let exact_mac = vec![0u8; sodiumoxide::crypto::secretbox::MACBYTES];
        let exact_mac_b64 =
            sodiumoxide::base64::encode(&exact_mac, sodiumoxide::base64::Variant::Original);
        let data = format!("00{exact_mac_b64}");
        let (_, succ, store) = decrypt_str_or_original(&data, version);
        assert!(!succ);
        assert!(!store);
        let data = data.into_bytes();
        let (_, succ, store) = decrypt_vec_or_original(&data, version);
        assert!(!succ);
        assert!(!store);
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn test_storage_key_lookup_failure_refuses_wrapping() {
        use crate::libc;
        const CHILD: &str = "RUSTDESK_STORAGE_KEY_FAILURE_CHILD";
        const TEST: &str = "password_security::test::test_storage_key_lookup_failure_refuses_wrapping";
        if std::env::var_os(CHILD).is_none() {
            assert!(crate::at_rest_storage_key().is_ok());
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn().unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.stdout.len() + output.stderr.len() < 8192);
            assert!(output.status.success(), "key failure child failed: {}", String::from_utf8_lossy(&output.stderr));
            let stdout = String::from_utf8(output.stdout).unwrap();
            let observations: Vec<_> = stdout.lines()
                .filter_map(|line| line.find("STORAGE_WRAPPER_KEY_FAILURE=").map(|start| &line[start..]))
                .collect();
            assert_eq!(observations, ["STORAGE_WRAPPER_KEY_FAILURE=pass provider=linux-file errno=13 string=empty vector=empty"]);
            println!("{}", observations[0]);
            return;
        }
        let statement = |code, k| libc::sock_filter { code: code as u16, jt: 0, jf: 0, k };
        let jump = |code, k, jt, jf| libc::sock_filter { code: code as u16, jt, jf, k };
        let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
        let equal = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
        let bits = libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K;
        let ret = libc::BPF_RET | libc::BPF_K;
        let mut filter = [
            statement(load, 4),
            jump(equal, 0xc000003e, 1, 0),
            statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
            statement(load, 0),
            jump(bits, 0x40000000, 0, 1),
            statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
            jump(equal, libc::SYS_open as u32, 3, 0),
            jump(equal, libc::SYS_openat as u32, 2, 0),
            jump(equal, libc::SYS_openat2 as u32, 1, 0),
            statement(ret, libc::SECCOMP_RET_ALLOW),
            statement(ret, libc::SECCOMP_RET_ERRNO | libc::EACCES as u32),
        ];
        let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
        assert_eq!(unsafe {
            libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC, &program)
        }, 0);
        for path in ["/var/lib/dbus/machine-id", "/etc/machine-id"] {
            assert_eq!(std::fs::read(path).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        }
        assert!(crate::at_rest_storage_key().is_err());
        assert!(encrypt_str_or_original("key-unavailable-fixture", 128).is_empty());
        assert!(encrypt_vec_or_original(b"key-unavailable-fixture", 128).is_empty());
        println!("STORAGE_WRAPPER_KEY_FAILURE=pass provider=linux-file errno=13 string=empty vector=empty");
    }

    #[test]
    fn test_is_encrypted() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;

        // Empty data should not be considered encrypted
        assert!(!is_encrypted(b""));
        assert!(!is_encrypted(b"0"));
        assert!(!is_encrypted(b"00"));

        // Data without "00" prefix should not be considered encrypted
        assert!(!is_encrypted(b"01abcd"));
        assert!(!is_encrypted(b"99abcd"));
        assert!(!is_encrypted(b"hello world"));

        // Data with "00" prefix but invalid base64 should not be considered encrypted
        assert!(!is_encrypted(b"00!!!invalid base64!!!"));
        assert!(!is_encrypted(b"00@#$%"));

        // Data with "00" prefix and valid base64 but shorter than MACBYTES is not encrypted
        assert!(!is_encrypted(b"00YWJjZA==")); // "abcd" in base64
        assert!(!is_encrypted(b"00SGVsbG8gV29ybGQ=")); // "Hello World" in base64

        // Data with "00" prefix and valid base64 with decoded len == MACBYTES is considered encrypted
        let exact_mac = vec![0u8; secretbox::MACBYTES];
        let exact_mac_b64 = encode(&exact_mac, Variant::Original);
        let exact_mac_candidate = format!("00{exact_mac_b64}");
        assert!(is_encrypted(exact_mac_candidate.as_bytes()));

        // Real encrypted data should be detected
        let max_len = 128;
        let encrypted_str = encrypt_str_or_original("1", max_len);
        assert!(is_encrypted(encrypted_str.as_bytes()));
        let encrypted_vec = encrypt_vec_or_original(b"1", max_len);
        assert!(is_encrypted(&encrypted_vec));

        // Original unencrypted data should not be detected as encrypted
        assert!(!is_encrypted(b"1"));
        assert!(!is_encrypted("1".as_bytes()));
    }

    #[test]
    fn test_encrypted_payload_min_len_macbytes() {
        use super::*;
        use sodiumoxide::base64::{decode, Variant};
        use sodiumoxide::crypto::secretbox;

        let max_len = 128;

        let encrypted_str = encrypt_str_or_original("1", max_len);
        let decoded = decode(&encrypted_str.as_bytes()[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );

        let encrypted_vec = encrypt_vec_or_original(b"1", max_len);
        let decoded = decode(&encrypted_vec[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );
    }

    #[test]
    fn test_encryption_uses_random_nonce() {
        use super::*;

        let data = b"test password 123";
        let encrypted1 = symmetric_crypt(data, true).unwrap();
        let encrypted2 = symmetric_crypt(data, true).unwrap();

        assert_eq!(encrypted1.first(), Some(&FORMAT_V1));
        assert_eq!(encrypted2.first(), Some(&FORMAT_V1));
        assert_eq!(
            encrypted1.len(),
            1 + secretbox::NONCEBYTES + data.len() + secretbox::MACBYTES
        );
        assert_ne!(encrypted1, encrypted2);
        assert_eq!(symmetric_crypt(&encrypted1, false).unwrap(), data);
        assert_eq!(symmetric_crypt(&encrypted2, false).unwrap(), data);
    }

    #[test]
    fn test_decrypt_legacy_zero_nonce_payload() {
        use super::*;
        use std::convert::TryInto;

        let data = b"test password 123";
        let uuid = crate::at_rest_storage_key().unwrap();
        let mut keybuf = uuid.clone();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let encrypted = secretbox::seal(data, &nonce, &key);

        assert_eq!(symmetric_crypt(&encrypted, false).unwrap(), data);
    }

    #[test]
    fn test_decrypt_legacy_payload_starting_with_v1_marker() {
        use super::*;
        use std::convert::TryInto;

        let mut keybuf = crate::at_rest_storage_key().unwrap();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        for i in 0..=u16::MAX {
            let data = format!("legacy collision payload {i:05}");
            let encrypted = secretbox::seal(data.as_bytes(), &nonce, &key);
            if encrypted.first() == Some(&FORMAT_V1) {
                assert_eq!(symmetric_crypt(&encrypted, false).unwrap(), data.as_bytes());
                return;
            }
        }

        panic!("failed to find legacy payload starting with FORMAT_V1");
    }

    #[test]
    fn test_invalid_short_v1_payload_returns_error() {
        use super::*;

        let encrypted = vec![FORMAT_V1];

        assert!(symmetric_crypt(&encrypted, false).is_err());
    }

    #[test]
    fn test_empty_at_rest_storage_key_is_rejected() {
        use super::*;

        assert!(secretbox_key_from_storage_key(Vec::new()).is_err());
    }

    #[test]
    fn test_mobile_legacy_keypair_fallback_requires_os_storage_key() {
        assert!(!super::legacy_key_pair_fallback_authorized(false, true));
        assert!(super::legacy_key_pair_fallback_authorized(true, true));
        assert!(super::legacy_key_pair_fallback_authorized(false, false));
    }

    #[test]
    fn test_decrypt_legacy_string_does_not_request_store() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use std::convert::TryInto;

        let data = "test password 123";
        let uuid = crate::at_rest_storage_key().unwrap();
        let mut keybuf = uuid.clone();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let encrypted = secretbox::seal(data.as_bytes(), &nonce, &key);
        let encrypted = "00".to_owned() + &encode(encrypted, Variant::Original);

        let (decrypted, success, store) = decrypt_str_or_original(&encrypted, "00");

        assert_eq!(decrypted, data);
        assert!(success);
        assert!(!store);
    }

    #[test]
    fn test_decrypt_legacy_vec_does_not_request_store() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use std::convert::TryInto;

        let data = b"test password 123";
        let uuid = crate::at_rest_storage_key().unwrap();
        let mut keybuf = uuid.clone();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let encrypted = secretbox::seal(data, &nonce, &key);
        let encrypted = ("00".to_owned() + &encode(encrypted, Variant::Original)).into_bytes();

        let (decrypted, success, store) = decrypt_vec_or_original(&encrypted, "00");

        assert_eq!(decrypted, data);
        assert!(success);
        assert!(!store);
    }

    // Test decryption fallback when data was encrypted with key_pair but decryption tries machine_uid first
    #[test]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn test_decrypt_with_pk_fallback() {
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let _lock = LEGACY_KEY_PAIR_TEST_LOCK.lock().unwrap();
        let uuid = crate::at_rest_storage_key().unwrap();
        let (pk, _cache_guard) = install_legacy_key_pair_for_test(&uuid);

        let data = b"test password 123";
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        // Encrypt with pk (simulating machine_uid failure during encryption)
        let mut pk_keybuf = pk;
        pk_keybuf.resize(secretbox::KEYBYTES, 0);
        let pk_key = secretbox::Key(pk_keybuf.try_into().unwrap());
        let encrypted = secretbox::seal(data, &nonce, &pk_key);

        // Decrypt using symmetric_crypt (should fallback to pk since the storage key differs)
        let decrypted = super::symmetric_crypt(&encrypted, false);
        assert!(
            decrypted.is_ok(),
            "Decryption with pk fallback should succeed"
        );
        assert_eq!(decrypted.unwrap(), data);
    }

    #[test]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn test_decrypt_v1_with_pk_fallback() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let _lock = LEGACY_KEY_PAIR_TEST_LOCK.lock().unwrap();
        let uuid = crate::at_rest_storage_key().unwrap();
        let (pk, _cache_guard) = install_legacy_key_pair_for_test(&uuid);

        let data = b"test password 123";
        let nonce = secretbox::gen_nonce();

        let mut pk_keybuf = pk;
        pk_keybuf.resize(secretbox::KEYBYTES, 0);
        let pk_key = secretbox::Key(pk_keybuf.try_into().unwrap());
        let ciphertext = secretbox::seal(data, &nonce, &pk_key);

        let mut encrypted = Vec::with_capacity(1 + secretbox::NONCEBYTES + ciphertext.len());
        encrypted.push(FORMAT_V1);
        encrypted.extend(nonce.0);
        encrypted.extend(ciphertext);

        assert_eq!(super::symmetric_crypt(&encrypted, false).unwrap(), data);

        let encrypted_str = "00".to_owned() + &encode(&encrypted, Variant::Original);
        let (decrypted, success, store) = decrypt_str_or_original(&encrypted_str, "00");
        assert_eq!(decrypted.as_bytes(), data);
        assert!(success);
        assert!(!store);

        let encrypted_vec = encrypted_str.into_bytes();
        let (decrypted, success, store) = decrypt_vec_or_original(&encrypted_vec, "00");
        assert_eq!(decrypted, data);
        assert!(success);
        assert!(!store);
    }
}
