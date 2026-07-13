//! Balanced **CPace** (draft-irtf-cfrg-cpace-21, suite `CPACE-RISTR255-SHA512`)
//! for the hardened RustDesk fork — the single mandatory, mutually-authenticated
//! PAKE run at the choke point before any application message is parsed (§10).
//!
//! Every byte of the construction is pinned by `requirements.html` §10.4 and
//! gated, in this crate's own test module, against:
//!   * the CFRG draft's published ristretto255 vector (`G_Coffee25519`):
//!     g = `222b6b19…`, ISK_SY = `544199d7…` (R-V2);
//!   * the fork KAT **anchor A** — 16-byte draft sid, port 21118 (R-A10); and
//!   * the fork KAT **anchor B** — 32-byte production sid (R-A10), exercised
//!     through the full R-P14a state machine.
//!
//! Zero novel curve math: `curve25519-dalek` supplies the audited, constant-time
//! `from_uniform_bytes` map, scalar×point, decompress and `is_identity`; this
//! crate writes only the encoding (`lv_cat`/`o_cat`), the 64-byte generator
//! string, the ISK transcript, the HKDF labels and the R-P3 confirmation MACs.
//!
//! The crate is deliberately protobuf-agnostic and free of any native/OpenSSL
//! dependency, so it builds and KAT-tests as pure Rust, independent of the
//! OpenSSL-linked workspace crates. The on-wire `Cpace` protobuf message and the
//! `create_tcp_connection` choke-point integration map this crate's plain
//! [`Step1`]–[`Step4`] byte structs to/from the wire (R-P14).

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use unicode_normalization::char::{canonical_combining_class, compose, decompose_canonical};
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

// ── Pinned protocol constants (§10.4 — one suite, one draft version, one DSI
//    set; no negotiation, no downgrade, R-P11) ────────────────────────────────

/// Suite DSI — folded into the generator string.
const SUITE_DSI: &[u8] = b"CPaceRistretto255";
/// ISK-transcript DSI (`SUITE_DSI ‖ b"_ISK"`).
const ISK_DSI: &[u8] = b"CPaceRistretto255_ISK";
/// Key-confirmation DSI (R-P3).
const MAC_DSI: &[u8] = b"CPaceMac";
/// Fixed fork channel-identifier tag (fork · suite · version). The port is
/// appended via [`channel_identifier`]; CI is identical on both sides and is
/// **never sent on the wire** (R-P1/R-P11).
const CI_TAG: &[u8] = b"rustdesk-fork/CPACE-RISTR255-SHA512/v1";
/// Fixed, non-secret HKDF salt for the per-direction secretbox keys (§10.4).
const HKDF_SALT: &[u8] = b"rustdesk-fork/CPACE-RISTR255-SHA512/v1/hkdf";
/// HKDF info label, viewer→controlled key (client-to-server).
const HKDF_INFO_C2S: &[u8] = b"rustdesk-fork/CPace/secretbox/c2s";
/// HKDF info label, controlled→viewer key (server-to-client).
const HKDF_INFO_S2C: &[u8] = b"rustdesk-fork/CPace/secretbox/s2c";

/// Per-side associated data for the initiator (the viewer). Fixed role (R-P5).
pub const AD_INITIATOR: &[u8] = b"viewer";
/// Per-side associated data for the responder (the controlled side). Fixed role.
pub const AD_RESPONDER: &[u8] = b"server";

/// The pinned compile-time direct-access port folded into CI (R-F4). The same
/// constant is compiled into both roles; it is **never** read from the live
/// socket (NAT/forwarding would otherwise desync CI and silently abort).
pub const CI_PORT: u16 = 21118;

/// SHA-512 input block size — the generator-string pad target (§10.4).
const S_IN_BYTES: usize = 128;

// ── Errors ───────────────────────────────────────────────────────────────────

/// A fail-closed abort. Per **R-P14c**, only [`PakeError::Confirmation`] is an
/// online password guess and may feed the per-source limiter (R-S10); every
/// other variant ([`is_password_guess`](PakeError::is_password_guess) ⇒ false)
/// MUST NOT, or a malformed-frame flood would trip the owner's own block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PakeError {
    /// R-P3 key-confirmation tag mismatch — the sole online-guess event.
    Confirmation,
    /// A received element failed ristretto255 `decode()` (R-P7).
    Decode,
    /// The shared point is the group identity (R-P7) — degenerate key. The
    /// all-zeros encoding decodes successfully, so this is tested *after* the
    /// scalar multiply, not by decode alone.
    Identity,
    /// A received AD did not equal the pinned role tag (R-P5). The literal
    /// equality check — not merely folding AD into the transcript — is what
    /// makes each confirmation tag sender-bound and defeats loopback reflection.
    AdMismatch,
    /// PRS was empty after NFC normalization (R-P1/R-S9). CPace has no empty-PRS
    /// guard, so the fork enforces non-emptiness explicitly.
    EmptyPassword,
    /// The system CSPRNG failed (R-P8/R-P12). Fail closed; never proceed with a
    /// non-random scalar or sid.
    Rng,
}

impl PakeError {
    /// True only for [`PakeError::Confirmation`] — the one abort that is an
    /// online password guess and feeds the per-source limiter (R-P14c).
    #[inline]
    pub fn is_password_guess(&self) -> bool {
        matches!(self, PakeError::Confirmation)
    }
}

// ── Wire steps (protobuf-agnostic; the integration layer maps these to the
//    dedicated `Cpace` oneof, R-P14). Two round-trips, four steps. ────────────

/// ① initiator → responder.
#[derive(Clone, Debug)]
pub struct Step1 {
    pub sid_a: [u8; 16],
    pub ada: Vec<u8>,
}
/// ② responder → initiator.
#[derive(Clone, Debug)]
pub struct Step2 {
    pub sid_b: [u8; 16],
    pub adb: Vec<u8>,
    pub yb: [u8; 32],
}
/// ③ initiator → responder.
#[derive(Clone, Debug)]
pub struct Step3 {
    pub ya: [u8; 32],
    pub ta: [u8; 64],
}
/// ④ responder → initiator.
#[derive(Clone, Debug)]
pub struct Step4 {
    pub tb: [u8; 64],
}

/// The two per-direction secretbox keys, oriented for the local role so the
/// caller installs them in mirrored slots (R-P2): a single keying call cannot
/// re-create the catastrophic same-key-both-ways reuse the symmetric `set_key`
/// allowed.
#[derive(Clone)]
pub struct DirectionalKeys {
    /// Key this side seals outbound frames with.
    pub send: [u8; 32],
    /// Key this side opens inbound frames with.
    pub recv: [u8; 32],
}

impl Drop for DirectionalKeys {
    fn drop(&mut self) {
        self.send.zeroize();
        self.recv.zeroize();
    }
}

// ── Encoding primitives (draft §"Notation and conventions") ───────────────────

/// Unsigned LEB128 length encoding (draft `prepend_len`).
fn leb128(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
    }
    out
}

/// `prepend_len(data) = LEB128(len(data)) ‖ data`.
fn prepend_len(data: &[u8]) -> Vec<u8> {
    let mut out = leb128(data.len());
    out.extend_from_slice(data);
    out
}

/// Length-prefixed concatenation: `lv_cat(a, b, …) = prepend_len(a) ‖ prepend_len(b) ‖ …`.
fn lv_cat(args: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in args {
        out.extend_from_slice(&prepend_len(a));
    }
    out
}

/// Draft `lexiographically_larger(b1, b2)` — bytewise, ties broken by length.
fn lexicographically_larger(b1: &[u8], b2: &[u8]) -> bool {
    let min_len = b1.len().min(b2.len());
    for i in 0..min_len {
        if b1[i] > b2[i] {
            return true;
        } else if b1[i] < b2[i] {
            return false;
        }
    }
    b1.len() > b2.len()
}

/// Draft `o_cat` — order-independent concatenation with the `b"oc"` prefix
/// (R-P6 symmetric mode). The larger operand is placed first.
fn o_cat(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let mut out = b"oc".to_vec();
    if lexicographically_larger(b1, b2) {
        out.extend_from_slice(b1);
        out.extend_from_slice(b2);
    } else {
        out.extend_from_slice(b2);
        out.extend_from_slice(b1);
    }
    out
}

/// Draft `generator_string(DSI, PRS, CI, sid, s_in_bytes)` — zero-pads the first
/// hash block after DSI and PRS, and the pad field is itself length-prefixed
/// (§10.4: "lv_cat … prefixes the zero-pad field too").
fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Vec<u8> {
    let len_zpad = (S_IN_BYTES as isize)
        - 1
        - prepend_len(prs).len() as isize
        - prepend_len(SUITE_DSI).len() as isize;
    let len_zpad = if len_zpad > 0 { len_zpad as usize } else { 0 };
    let zpad = vec![0u8; len_zpad];
    lv_cat(&[SUITE_DSI, prs, &zpad, ci, sid])
}

// ── Construction core (each function is KAT-pinned by the test module) ────────

/// CI = `lv_cat(CI_TAG, be16(port))` (§10.4). The port byte-encoding is pinned
/// to fixed 2-byte big-endian so CI is byte-identical on both peers.
pub fn channel_identifier(port: u16) -> Vec<u8> {
    lv_cat(&[CI_TAG, &port.to_be_bytes()])
}

/// `g = RistrettoPoint::from_uniform_bytes(SHA512(generator_string))`.
///
/// R-T15(a)/R-P12: every PRS-laden intermediate of this substep — which §10.4 flags
/// as the most side-channel-critical — is wiped before return. `gs` carries the raw
/// PRS (`lv_cat(SUITE_DSI, prs, zpad, ci, sid)`) and the SHA-512 digest / `wide` copy
/// are PRS-derived; all three are zeroized. The returned point `g` is itself PRS-laden,
/// so callers wrap it in `Zeroizing` to wipe the expanded point on every exit path.
fn derive_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let gs = Zeroizing::new(generator_string(prs, ci, sid));
    let mut digest = Sha512::digest(&gs[..]); // 64 bytes, PRS-derived
    let mut wide = Zeroizing::new([0u8; 64]);
    wide.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// `ISK = SHA512( lv_cat(ISK_DSI, sid, K) ‖ o_cat(lv_cat(Ya,ADa), lv_cat(Yb,ADb)) )`.
///
/// Trap (§10.4 #2): the transcript is appended **raw**, never re-`lv_cat`-wrapped
/// — re-wrapping silently yields a different ISK (`49ddbd…`) and fails the vector.
fn compute_isk(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8], sid: &[u8], k: &[u8]) -> [u8; 64] {
    let m_a = lv_cat(&[ya, ada]);
    let m_b = lv_cat(&[yb, adb]);
    let transcript = o_cat(&m_a, &m_b);
    let mut input = lv_cat(&[ISK_DSI, sid, k]);
    input.extend_from_slice(&transcript);
    let isk = Sha512::digest(&input);
    input.zeroize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&isk);
    out
}

/// Two per-direction secretbox keys via HKDF-SHA-512 with distinct info labels
/// (R-P2/R-P9). Returns `(k_c2s, k_s2c)`, each wrapped in [`Zeroizing`] so the
/// transient copies are wiped on every caller exit path — including the R-P3
/// confirmation-failure abort, where they are never moved into the drop-guarded
/// [`DirectionalKeys`] (R-T15(a)/R-P12).
fn derive_session_keys(isk: &[u8; 64]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT), isk);
    let mut k_c2s = Zeroizing::new([0u8; 32]);
    let mut k_s2c = Zeroizing::new([0u8; 32]);
    // expand() only fails for absurd output lengths; 32 bytes never does.
    hk.expand(HKDF_INFO_C2S, &mut k_c2s[..]).expect("hkdf c2s");
    hk.expand(HKDF_INFO_S2C, &mut k_s2c[..]).expect("hkdf s2c");
    (k_c2s, k_s2c)
}

/// `mac_key = SHA512( MAC_DSI ‖ sid ‖ ISK )` — direct hash, **bare concat**, not
/// `lv_cat`, not HKDF (R-P3, §10.4).
fn derive_mac_key(sid: &[u8], isk: &[u8; 64]) -> Zeroizing<[u8; 64]> {
    let mut input = Zeroizing::new(Vec::with_capacity(MAC_DSI.len() + sid.len() + 64));
    input.extend_from_slice(MAC_DSI);
    input.extend_from_slice(sid);
    input.extend_from_slice(isk);
    let mac = Sha512::digest(&input[..]);
    let mut out = [0u8; 64];
    out.copy_from_slice(&mac);
    Zeroizing::new(out)
}

/// `T = HMAC-SHA512( mac_key, lv_cat(Y, AD) )` (R-P3).
fn compute_tag(mac_key: &[u8; 64], y: &[u8], ad: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(mac_key).expect("hmac key");
    mac.update(&lv_cat(&[y, ad]));
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time verification of a peer's R-P3 tag (R-P12) via HMAC's own
/// `verify_slice`; never a `==` compare.
fn verify_tag(mac_key: &[u8; 64], y: &[u8], ad: &[u8], tag: &[u8; 64]) -> bool {
    let mut mac = HmacSha512::new_from_slice(mac_key).expect("hmac key");
    mac.update(&lv_cat(&[y, ad]));
    mac.verify_slice(tag).is_ok()
}

#[derive(Debug)]
enum NfcNormalizeError {
    Allocation,
    LengthOverflow,
    Invariant,
}

fn canonical_decomposition_len(password: &str) -> Result<usize, NfcNormalizeError> {
    let mut len = Some(0usize);
    for scalar in password.chars() {
        decompose_canonical(scalar, |_| {
            if let Some(current) = len {
                len = current.checked_add(1);
            }
        });
    }
    len.ok_or(NfcNormalizeError::LengthOverflow)
}

fn allocate_zeroed_vec<T: Default>(len: usize) -> Result<Vec<T>, NfcNormalizeError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(len)
        .map_err(|_| NfcNormalizeError::Allocation)?;
    values.resize_with(len, T::default);
    Ok(values)
}

fn allocate_zeroizing_box<T>(len: usize) -> Result<Zeroizing<Box<[T]>>, NfcNormalizeError>
where
    T: Default + Zeroize,
{
    // Any capacity adjustment performed by into_boxed_slice sees only defaults.
    // Once returned, the allocation is fixed and zeroizes its complete contents.
    Ok(Zeroizing::new(allocate_zeroed_vec(len)?.into_boxed_slice()))
}

fn fill_canonical_decomposition(
    password: &str,
    scalars: &mut [u32],
    classes: &mut [u8],
) -> Result<(), NfcNormalizeError> {
    if scalars.len() != classes.len() {
        return Err(NfcNormalizeError::Invariant);
    }

    let mut next = 0usize;
    let mut valid = true;
    for scalar in password.chars() {
        decompose_canonical(scalar, |decomposed| {
            if !valid {
                return;
            }
            match (scalars.get_mut(next), classes.get_mut(next)) {
                (Some(scalar_slot), Some(class_slot)) => {
                    *scalar_slot = decomposed as u32;
                    *class_slot = canonical_combining_class(decomposed);
                    if let Some(index) = next.checked_add(1) {
                        next = index;
                    } else {
                        valid = false;
                    }
                }
                _ => valid = false,
            }
        });
    }

    if valid && next == scalars.len() {
        Ok(())
    } else {
        Err(NfcNormalizeError::Invariant)
    }
}

fn add_order_work(work: &mut usize, amount: usize) -> Result<(), NfcNormalizeError> {
    *work = work
        .checked_add(amount)
        .ok_or(NfcNormalizeError::LengthOverflow)?;
    Ok(())
}

fn copy_ordered_scalar(
    scalars: &[u32],
    classes: &[u8],
    ordered_scalars: &mut [u32],
    ordered_classes: &mut [u8],
    source: usize,
    destination: usize,
) -> Result<(), NfcNormalizeError> {
    let scalar = *scalars.get(source).ok_or(NfcNormalizeError::Invariant)?;
    let class = *classes.get(source).ok_or(NfcNormalizeError::Invariant)?;
    let scalar_slot = ordered_scalars
        .get_mut(destination)
        .ok_or(NfcNormalizeError::Invariant)?;
    let class_slot = ordered_classes
        .get_mut(destination)
        .ok_or(NfcNormalizeError::Invariant)?;
    *scalar_slot = scalar;
    *class_slot = class;
    Ok(())
}

fn canonical_order(
    scalars: &mut [u32],
    classes: &mut [u8],
    ordered_scalars: &mut [u32],
    ordered_classes: &mut [u8],
) -> Result<usize, NfcNormalizeError> {
    let len = scalars.len();
    if classes.len() != len || ordered_scalars.len() != len || ordered_classes.len() != len {
        return Err(NfcNormalizeError::Invariant);
    }

    let mut counts = Zeroizing::new([0usize; 256]);
    let mut positions = Zeroizing::new([0usize; 256]);
    let mut used_classes = Zeroizing::new([0u64; 4]);
    let mut segment_start = 0usize;
    let mut work = 0usize;

    while segment_start < len {
        let first_class = *classes
            .get(segment_start)
            .ok_or(NfcNormalizeError::Invariant)?;
        add_order_work(&mut work, 1)?;
        let marks_start = if first_class == 0 {
            copy_ordered_scalar(
                scalars,
                classes,
                ordered_scalars,
                ordered_classes,
                segment_start,
                segment_start,
            )?;
            add_order_work(&mut work, 1)?;
            segment_start
                .checked_add(1)
                .ok_or(NfcNormalizeError::LengthOverflow)?
        } else {
            segment_start
        };

        let mut segment_end = marks_start;
        while segment_end < len {
            let class = *classes
                .get(segment_end)
                .ok_or(NfcNormalizeError::Invariant)?;
            add_order_work(&mut work, 1)?;
            if class == 0 {
                break;
            }
            segment_end = segment_end
                .checked_add(1)
                .ok_or(NfcNormalizeError::LengthOverflow)?;
        }

        let marks_len = segment_end
            .checked_sub(marks_start)
            .ok_or(NfcNormalizeError::Invariant)?;
        if marks_len <= 1 {
            if marks_len == 1 {
                copy_ordered_scalar(
                    scalars,
                    classes,
                    ordered_scalars,
                    ordered_classes,
                    marks_start,
                    marks_start,
                )?;
                add_order_work(&mut work, 1)?;
            }
        } else {
            for source in marks_start..segment_end {
                let class = *classes.get(source).ok_or(NfcNormalizeError::Invariant)?;
                if class == 0 {
                    return Err(NfcNormalizeError::Invariant);
                }
                let bucket = usize::from(class);
                let count = counts.get_mut(bucket).ok_or(NfcNormalizeError::Invariant)?;
                if *count == 0 {
                    let word_index = bucket / 64;
                    let bit_index = bucket % 64;
                    let word = used_classes
                        .get_mut(word_index)
                        .ok_or(NfcNormalizeError::Invariant)?;
                    *word |= 1u64 << bit_index;
                }
                *count = count
                    .checked_add(1)
                    .ok_or(NfcNormalizeError::LengthOverflow)?;
                add_order_work(&mut work, 1)?;
            }

            let mut next = marks_start;
            for word_index in 0usize..4 {
                let word = used_classes
                    .get_mut(word_index)
                    .ok_or(NfcNormalizeError::Invariant)?;
                let mut bits = *word;
                *word = 0;
                add_order_work(&mut work, 1)?;

                while bits != 0 {
                    let bit_index = bits.trailing_zeros() as usize;
                    let bucket = word_index
                        .checked_mul(64)
                        .and_then(|base| base.checked_add(bit_index))
                        .ok_or(NfcNormalizeError::LengthOverflow)?;
                    let count = counts.get_mut(bucket).ok_or(NfcNormalizeError::Invariant)?;
                    let position = positions
                        .get_mut(bucket)
                        .ok_or(NfcNormalizeError::Invariant)?;
                    *position = next;
                    next = next
                        .checked_add(*count)
                        .ok_or(NfcNormalizeError::LengthOverflow)?;
                    *count = 0;
                    bits &= bits - 1;
                    add_order_work(&mut work, 1)?;
                }
            }
            if next != segment_end {
                return Err(NfcNormalizeError::Invariant);
            }

            // Reading source scalars in their original order makes placement
            // stable for equal canonical combining classes.
            for source in marks_start..segment_end {
                let class = *classes.get(source).ok_or(NfcNormalizeError::Invariant)?;
                let position = positions
                    .get_mut(usize::from(class))
                    .ok_or(NfcNormalizeError::Invariant)?;
                let destination = *position;
                copy_ordered_scalar(
                    scalars,
                    classes,
                    ordered_scalars,
                    ordered_classes,
                    source,
                    destination,
                )?;
                *position = position
                    .checked_add(1)
                    .ok_or(NfcNormalizeError::LengthOverflow)?;
                add_order_work(&mut work, 1)?;
            }
        }

        if segment_end <= segment_start {
            return Err(NfcNormalizeError::Invariant);
        }
        segment_start = segment_end;
    }

    scalars.copy_from_slice(ordered_scalars);
    classes.copy_from_slice(ordered_classes);
    add_order_work(&mut work, len)?;
    Ok(work)
}

fn canonical_compose(scalars: &mut [u32], classes: &mut [u8]) -> Result<usize, NfcNormalizeError> {
    if scalars.len() != classes.len() {
        return Err(NfcNormalizeError::Invariant);
    }

    let mut write = 0usize;
    let mut starter = None;
    let mut last_class = 0u8;

    for read in 0..scalars.len() {
        let scalar = scalars[read];
        let class = classes[read];
        let current = char::from_u32(scalar).ok_or(NfcNormalizeError::Invariant)?;

        if let Some(starter_index) = starter {
            if last_class == 0 || last_class < class {
                let starter_scalar = scalars[starter_index];
                let starter_char =
                    char::from_u32(starter_scalar).ok_or(NfcNormalizeError::Invariant)?;
                if let Some(composite) = compose(starter_char, current) {
                    scalars[starter_index] = composite as u32;
                    continue;
                }
            }
        }

        match (scalars.get_mut(write), classes.get_mut(write)) {
            (Some(scalar_slot), Some(class_slot)) => {
                *scalar_slot = scalar;
                *class_slot = class;
            }
            _ => return Err(NfcNormalizeError::Invariant),
        }
        let destination = write;
        write = write
            .checked_add(1)
            .ok_or(NfcNormalizeError::LengthOverflow)?;

        if class == 0 {
            starter = Some(destination);
            last_class = 0;
        } else if starter.is_some() {
            last_class = class;
        }
    }

    Ok(write)
}

fn normalized_utf8_len(scalars: &[u32], composed_len: usize) -> Result<usize, NfcNormalizeError> {
    let composed = scalars
        .get(..composed_len)
        .ok_or(NfcNormalizeError::Invariant)?;
    let mut utf8_len = 0usize;
    for &scalar in composed {
        let scalar = char::from_u32(scalar).ok_or(NfcNormalizeError::Invariant)?;
        utf8_len = utf8_len
            .checked_add(scalar.len_utf8())
            .ok_or(NfcNormalizeError::LengthOverflow)?;
    }
    Ok(utf8_len)
}

fn encode_normalized_into(
    scalars: &[u32],
    composed_len: usize,
    output: &mut [u8],
) -> Result<(), NfcNormalizeError> {
    let composed = scalars
        .get(..composed_len)
        .ok_or(NfcNormalizeError::Invariant)?;
    let mut offset = 0usize;

    for &scalar in composed {
        let scalar = char::from_u32(scalar).ok_or(NfcNormalizeError::Invariant)?;
        let end = offset
            .checked_add(scalar.len_utf8())
            .ok_or(NfcNormalizeError::LengthOverflow)?;
        let destination = output
            .get_mut(offset..end)
            .ok_or(NfcNormalizeError::Invariant)?;
        scalar.encode_utf8(destination);
        offset = end;
    }

    if offset == output.len() {
        Ok(())
    } else {
        Err(NfcNormalizeError::Invariant)
    }
}

fn encode_normalized(
    scalars: &[u32],
    composed_len: usize,
) -> Result<Zeroizing<Vec<u8>>, NfcNormalizeError> {
    let utf8_len = normalized_utf8_len(scalars, composed_len)?;
    let mut output = Zeroizing::new(allocate_zeroed_vec(utf8_len)?);
    encode_normalized_into(scalars, composed_len, &mut output)?;
    Ok(output)
}

fn try_nfc_normalize(password: &str) -> Result<Zeroizing<Vec<u8>>, NfcNormalizeError> {
    let decomposed_len = canonical_decomposition_len(password)?;
    let mut scalars = allocate_zeroizing_box::<u32>(decomposed_len)?;
    let mut classes = allocate_zeroizing_box::<u8>(decomposed_len)?;
    let mut ordered_scalars = allocate_zeroizing_box::<u32>(decomposed_len)?;
    let mut ordered_classes = allocate_zeroizing_box::<u8>(decomposed_len)?;

    fill_canonical_decomposition(password, &mut scalars, &mut classes)?;
    canonical_order(
        &mut scalars,
        &mut classes,
        &mut ordered_scalars,
        &mut ordered_classes,
    )?;
    let composed_len = canonical_compose(&mut scalars, &mut classes)?;
    encode_normalized(&scalars, composed_len)
}

/// R-P1: the EXACT NFC (no case-fold) password normalization the CPace PRS uses — a
/// deliberate NFC-only subset of RFC 8265 OpaqueString. Exposed (and reused by
/// `normalize_prs` below) so the at-rest memory-hard PRS derivation
/// (`hbb_common::config::derive_cpace_prs`) applies the IDENTICAL normalization to
/// the password BEFORE Argon2id: the bytes fed to the PAKE and the bytes fed to
/// Argon2id MUST be the same, or the controlled side's stored PRS and the viewer's
/// freshly-derived PRS would never agree. Returns the NFC bytes (may be empty after
/// normalization — the caller enforces the non-empty/empty-PRS guard, R-S9). The
/// result self-wipes (`Zeroizing`). Allocation is fixed before plaintext-derived
/// values are written; an allocation or checked-length failure aborts only after
/// every populated zeroizing allocation has been dropped.
pub fn nfc_normalize(password: &str) -> Zeroizing<Vec<u8>> {
    match try_nfc_normalize(password) {
        Ok(normalized) => normalized,
        Err(_) => std::process::abort(),
    }
}

/// PRS = NFC(password), no case-fold — a deliberate NFC-only subset of RFC 8265
/// OpaqueString (R-P1). MUST be non-empty after normalization (R-P1/R-S9).
fn normalize_prs(password: &str) -> Result<Zeroizing<Vec<u8>>, PakeError> {
    let prs = nfc_normalize(password);
    if prs.is_empty() {
        return Err(PakeError::EmptyPassword);
    }
    Ok(prs)
}

fn fill_random(buf: &mut [u8]) -> Result<(), PakeError> {
    getrandom::getrandom(buf).map_err(|_| PakeError::Rng)
}

/// Sample a fresh ephemeral scalar via the wide reduction `Scalar::random` uses
/// (R-P12) — 64 CSPRNG bytes, no bit-masking; never the deprecated, Edwards-only
/// `Scalar::from_bits` (§10.4 trap #1).
fn sample_scalar() -> Result<Scalar, PakeError> {
    let mut wide = [0u8; 64];
    fill_random(&mut wide)?;
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    Ok(s)
}

/// Decompress a received element, mapping a decode failure to [`PakeError::Decode`]
/// (R-P7).
fn decompress(bytes: &[u8; 32]) -> Result<RistrettoPoint, PakeError> {
    CompressedRistretto::from_slice(bytes)
        .map_err(|_| PakeError::Decode)?
        .decompress()
        .ok_or(PakeError::Decode)
}

// ── R-P14a state machine — initiator (viewer) ────────────────────────────────
//
// INIT → WAIT_2 → SEND_3 → WAIT_4 → KEYED, expressed as consuming type-states so
// each step is consumed exactly once and a misordered/duplicate frame is a
// compile-or-abort error, never silently buffered.

/// Initiator state INIT: holds the PRS, CI and its own sid contribution; has
/// emitted [`Step1`].
pub struct Initiator {
    prs: Zeroizing<Vec<u8>>,
    ci: Vec<u8>,
    sid_a: [u8; 16],
}

/// Initiator state WAIT_4: ISK derived, [`Step3`] emitted; awaiting the peer tag.
pub struct InitiatorAwaitConfirm {
    mac_key: Zeroizing<[u8; 64]>,
    yb: [u8; 32],
    k_c2s: [u8; 32],
    k_s2c: [u8; 32],
}

impl Drop for InitiatorAwaitConfirm {
    /// R-T15(a)/R-P12: wipe the derived session keys when this state is dropped — notably
    /// on the R-P14b step-4 timeout (a peer that opens the handshake and stalls), where the
    /// keys would otherwise linger in freed memory. On the success path `recv_step4` copies
    /// them (they are `Copy`) into `DirectionalKeys` (which wipes its own copy on drop) and
    /// this wipes this struct's copy. `mac_key` is `Zeroizing` and self-wipes; `yb` is public.
    fn drop(&mut self) {
        self.k_c2s.zeroize();
        self.k_s2c.zeroize();
    }
}

impl Initiator {
    /// Begin a handshake as the viewer. Samples `sid_a`, pins `ADa = b"viewer"`,
    /// and returns the WAIT_2 state plus [`Step1`] to send.
    pub fn new(password: &str, port: u16) -> Result<(Self, Step1), PakeError> {
        let mut sid_a = [0u8; 16];
        fill_random(&mut sid_a)?;
        Self::from_parts(password, port, sid_a)
    }

    fn from_parts(password: &str, port: u16, sid_a: [u8; 16]) -> Result<(Self, Step1), PakeError> {
        let prs = normalize_prs(password)?;
        let ci = channel_identifier(port);
        let step1 = Step1 {
            sid_a,
            ada: AD_INITIATOR.to_vec(),
        };
        Ok((Initiator { prs, ci, sid_a }, step1))
    }

    /// Consume [`Step2`]: verify `ADb == b"server"` (R-P5), derive `g`, sample
    /// `ya`, compute `Ya`, `K` (abort on identity, R-P7), `ISK`, the directional
    /// keys and `mac_key`, and emit [`Step3`] `{Ya, Ta}`.
    pub fn recv_step2(self, step2: &Step2) -> Result<(InitiatorAwaitConfirm, Step3), PakeError> {
        let ya = sample_scalar()?;
        self.recv_step2_with(step2, ya)
    }

    fn recv_step2_with(
        self,
        step2: &Step2,
        mut ya: Scalar,
    ) -> Result<(InitiatorAwaitConfirm, Step3), PakeError> {
        if step2.adb.as_slice() != AD_RESPONDER {
            ya.zeroize();
            return Err(PakeError::AdMismatch);
        }
        let mut sid = [0u8; 32];
        sid[..16].copy_from_slice(&self.sid_a);
        sid[16..].copy_from_slice(&step2.sid_b);

        // R-T15(a)/R-P12: `g` is PRS-laden — wrap in `Zeroizing` so the expanded point
        // is wiped on every exit path, including the decompress-error early-return below.
        let g = Zeroizing::new(derive_generator(&self.prs, &self.ci, &sid));
        let ya_pt = (ya * *g).compress().to_bytes();

        // R-T15(a)/R-P12: wipe the ephemeral scalar on the decompress-error early-return too
        // (mirrors the responder's recv_step3) — the `?` form would skip the zeroize below,
        // leaking `ya` on an attacker-triggerable malformed-Yb abort.
        let yb_pt = match decompress(&step2.yb) {
            Ok(p) => p,
            Err(e) => {
                ya.zeroize();
                return Err(e);
            }
        };
        // R-T15(a)/R-P12: the DH shared point `K` is as secret as its `k_bytes`
        // serialization — `Zeroizing` wipes the expanded point, not only the bytes.
        let k_pt = Zeroizing::new(ya * yb_pt);
        ya.zeroize();
        if k_pt.is_identity() {
            return Err(PakeError::Identity);
        }
        let mut k_bytes = k_pt.compress().to_bytes();

        // R-T15(a)/R-P12: ISK is the layer's master secret (mac_key + both directional keys
        // derive from it), so wipe it on drop rather than leave it resident on the stack.
        let isk = Zeroizing::new(compute_isk(
            &ya_pt,
            AD_INITIATOR,
            &step2.yb,
            AD_RESPONDER,
            &sid,
            &k_bytes,
        ));
        k_bytes.zeroize();
        let (k_c2s, k_s2c) = derive_session_keys(&isk);
        let mac_key = derive_mac_key(&sid, &isk);
        let ta = compute_tag(&mac_key, &ya_pt, AD_INITIATOR);

        // Copy into the WAIT_4 state (its own Drop wipes them); the Zeroizing locals wipe on return.
        let next = InitiatorAwaitConfirm {
            mac_key,
            yb: step2.yb,
            k_c2s: *k_c2s,
            k_s2c: *k_s2c,
        };
        Ok((next, Step3 { ya: ya_pt, ta }))
    }
}

impl InitiatorAwaitConfirm {
    /// Consume [`Step4`]: verify `Tb` in constant time (R-P3). Only on success
    /// return the role-oriented keys — the viewer seals with `k_c2s`, opens with
    /// `k_s2c` (R-P2). A mismatch is a [`PakeError::Confirmation`] (R-P14c).
    pub fn recv_step4(self, step4: &Step4) -> Result<DirectionalKeys, PakeError> {
        if !verify_tag(&self.mac_key, &self.yb, AD_RESPONDER, &step4.tb) {
            return Err(PakeError::Confirmation);
        }
        Ok(DirectionalKeys {
            send: self.k_c2s,
            recv: self.k_s2c,
        })
    }
}

// ── R-P14a state machine — responder (controlled) ────────────────────────────
//
// WAIT_1 → INIT2 → WAIT_3 → SEND_4 → KEYED.

/// Responder state WAIT_1: holds PRS and CI; awaiting [`Step1`].
pub struct Responder {
    prs: Zeroizing<Vec<u8>>,
    ci: Vec<u8>,
}

/// Responder state WAIT_3: `Yb` emitted via [`Step2`]; holds `yb` and the full
/// sid; awaiting the initiator's element and tag.
pub struct ResponderAwaitConfirm {
    yb_scalar: Scalar,
    yb_pt: [u8; 32],
    sid: [u8; 32],
}

impl Drop for ResponderAwaitConfirm {
    /// R-T15(a)/R-P12: wipe the ephemeral scalar when this state is dropped — notably on the
    /// R-P14b step-3 timeout (a peer that received `Step2` and then stalls), where it would
    /// otherwise linger in freed memory. `recv_step3` also wipes it explicitly on each of its
    /// own paths (belt-and-suspenders); this covers the drop that never reaches `recv_step3`.
    /// `yb_pt`/`sid` are public. `Scalar` is `Copy`, so `recv_step3`'s reads do not move it out.
    fn drop(&mut self) {
        self.yb_scalar.zeroize();
    }
}

impl Responder {
    /// Begin a handshake as the controlled side. CPace is balanced, so this side
    /// must hold the PRS (a password-equivalent value, protect per R-S9).
    pub fn new(password: &str, port: u16) -> Result<Self, PakeError> {
        Ok(Responder {
            prs: normalize_prs(password)?,
            ci: channel_identifier(port),
        })
    }

    /// Consume [`Step1`]: verify `ADa == b"viewer"` (R-P5), sample `sid_b`, form
    /// the full `sid`, derive `g`, sample `yb`, and emit [`Step2`] `{sid_b, ADb, Yb}`.
    pub fn recv_step1(self, step1: &Step1) -> Result<(ResponderAwaitConfirm, Step2), PakeError> {
        let mut sid_b = [0u8; 16];
        fill_random(&mut sid_b)?;
        let yb = sample_scalar()?;
        self.recv_step1_with(step1, sid_b, yb)
    }

    fn recv_step1_with(
        self,
        step1: &Step1,
        sid_b: [u8; 16],
        yb: Scalar,
    ) -> Result<(ResponderAwaitConfirm, Step2), PakeError> {
        if step1.ada.as_slice() != AD_INITIATOR {
            let mut yb = yb;
            yb.zeroize();
            return Err(PakeError::AdMismatch);
        }
        let mut sid = [0u8; 32];
        sid[..16].copy_from_slice(&step1.sid_a);
        sid[16..].copy_from_slice(&sid_b);

        // R-T15(a)/R-P12: `g` is PRS-laden — wipe the expanded point on drop.
        let g = Zeroizing::new(derive_generator(&self.prs, &self.ci, &sid));
        let yb_pt = (yb * *g).compress().to_bytes();

        let next = ResponderAwaitConfirm {
            yb_scalar: yb,
            yb_pt,
            sid,
        };
        let step2 = Step2 {
            sid_b,
            adb: AD_RESPONDER.to_vec(),
            yb: yb_pt,
        };
        Ok((next, step2))
    }
}

impl ResponderAwaitConfirm {
    /// Consume [`Step3`]: compute `K = yb·Ya` (abort on identity, R-P7), derive
    /// `ISK`/keys/`mac_key`, verify the initiator's `Ta` in constant time
    /// **before** authorizing (R-P3/R-A1), then emit `Tb`. Returns the
    /// role-oriented keys — the controlled side seals with `k_s2c`, opens with
    /// `k_c2s` (R-P2).
    pub fn recv_step3(mut self, step3: &Step3) -> Result<(DirectionalKeys, Step4), PakeError> {
        let ya_pt = match decompress(&step3.ya) {
            Ok(p) => p,
            Err(e) => {
                self.yb_scalar.zeroize();
                return Err(e);
            }
        };
        // R-T15(a)/R-P12: wipe the expanded DH point `K`, not only its `k_bytes` form.
        let k_pt = Zeroizing::new(self.yb_scalar * ya_pt);
        if k_pt.is_identity() {
            self.yb_scalar.zeroize();
            return Err(PakeError::Identity);
        }
        let mut k_bytes = k_pt.compress().to_bytes();

        // R-T15(a)/R-P12: ISK is the layer's master secret — wipe it on drop.
        let isk = Zeroizing::new(compute_isk(
            &step3.ya,
            AD_INITIATOR,
            &self.yb_pt,
            AD_RESPONDER,
            &self.sid,
            &k_bytes,
        ));
        k_bytes.zeroize();
        let (k_c2s, k_s2c) = derive_session_keys(&isk);
        let mac_key = derive_mac_key(&self.sid, &isk);

        if !verify_tag(&mac_key, &step3.ya, AD_INITIATOR, &step3.ta) {
            // k_c2s/k_s2c wipe here on scope exit (their `Zeroizing` drop) — they were never
            // moved into the drop-guarded DirectionalKeys on this abort (R-T15(a)/R-P12).
            self.yb_scalar.zeroize();
            return Err(PakeError::Confirmation);
        }
        let tb = compute_tag(&mac_key, &self.yb_pt, AD_RESPONDER);
        self.yb_scalar.zeroize();
        Ok((
            DirectionalKeys {
                send: *k_s2c,
                recv: *k_c2s,
            },
            Step4 { tb },
        ))
    }
}

#[cfg(test)]
mod nfc_normalization_tests {
    use super::*;
    use unicode_normalization::UnicodeNormalization;

    fn reference_nfc(input: &str) -> Vec<u8> {
        input.nfc().collect::<String>().into_bytes()
    }

    fn assert_matches_reference(input: &str) {
        let expected = reference_nfc(input);
        let actual = nfc_normalize(input);
        assert_eq!(&actual[..], expected.as_slice());
    }

    #[test]
    fn nfc_matches_representative_unicode() {
        for input in [
            "",
            "plain ASCII password",
            "\0embedded\0null",
            "\u{e9}",
            "e\u{301}",
            "\u{212b}",
            "\u{2126}",
            "\u{f900}",
            "\u{1f71}",
            "A\u{302}\u{301}",
            "\u{1f469}\u{200d}\u{1f4bb}",
            "\u{315}\u{300}\u{5ae}\u{301}\u{327}",
        ] {
            assert_matches_reference(input);
        }
    }

    #[test]
    fn nfc_orders_stably_and_obeys_composition_blocking() {
        for input in [
            "a\u{315}\u{300}\u{5ae}\u{301}\u{327}",
            "\u{315}\u{300}\u{5ae}\u{301}\u{327}a",
            "A\u{327}\u{30a}",
            "A\u{305}\u{301}",
            "x\u{317}\u{316}",
            "a\u{301}\u{301}\u{300}\u{300}",
        ] {
            assert_matches_reference(input);
        }

        assert_eq!(
            canonical_combining_class('\u{317}'),
            canonical_combining_class('\u{316}')
        );
        assert_eq!(
            &nfc_normalize("x\u{317}\u{316}")[..],
            "x\u{317}\u{316}".as_bytes()
        );
        assert_eq!(
            &nfc_normalize("A\u{305}\u{301}")[..],
            "A\u{305}\u{301}".as_bytes()
        );
    }

    #[test]
    fn nfc_handles_leading_nonstarters_and_cross_scalar_composition() {
        for input in [
            "\u{315}\u{300}A\u{30a}",
            "\u{212b}\u{301}",
            "D\u{307}\u{323}",
            "A\u{30a}\u{301}B\u{327}\u{301}",
            "\u{1100}\u{1161}\u{11a8}\u{1102}\u{1161}",
        ] {
            assert_matches_reference(input);
        }

        assert_eq!(
            &nfc_normalize("\u{315}\u{300}A\u{30a}")[..],
            "\u{300}\u{315}\u{c5}".as_bytes()
        );
        assert_eq!(&nfc_normalize("\u{212b}\u{301}")[..], "\u{1fa}".as_bytes());
    }

    #[test]
    fn nfc_composes_and_decomposes_hangul_exactly() {
        for input in [
            "\u{1100}\u{1161}",
            "\u{1100}\u{1161}\u{11a8}",
            "\u{1100}\u{301}\u{1161}",
            "\u{1112}\u{1175}\u{11c2}",
            "\u{1113}\u{1161}",
            "\u{1100}\u{1176}",
            "\u{ac00}\u{11a7}",
            "\u{d788}\u{11c2}",
            "\u{d788}\u{11c3}",
            "\u{ac00}",
            "\u{ac01}",
            "\u{d7a3}",
            "\u{1102}\u{1161}\u{11ab}\u{1103}\u{1161}",
            "\u{ac00}\u{11a8}",
        ] {
            assert_matches_reference(input);
        }

        assert_eq!(
            &nfc_normalize("\u{1100}\u{1161}")[..],
            "\u{ac00}".as_bytes()
        );
        assert_eq!(
            &nfc_normalize("\u{1100}\u{1161}\u{11a8}")[..],
            "\u{ac01}".as_bytes()
        );
        assert_eq!(
            &nfc_normalize("\u{1100}\u{301}\u{1161}")[..],
            "\u{1100}\u{301}\u{1161}".as_bytes()
        );
        assert_eq!(
            &nfc_normalize("\u{1112}\u{1175}\u{11c2}")[..],
            "\u{d7a3}".as_bytes()
        );
        assert_eq!(
            &nfc_normalize("\u{1113}\u{1161}")[..],
            "\u{1113}\u{1161}".as_bytes()
        );
        assert_eq!(
            &nfc_normalize("\u{1100}\u{1176}")[..],
            "\u{1100}\u{1176}".as_bytes()
        );
        assert_eq!(
            &nfc_normalize("\u{ac00}\u{11a7}")[..],
            "\u{ac00}\u{11a7}".as_bytes()
        );
        assert_eq!(
            &nfc_normalize("\u{d788}\u{11c2}")[..],
            "\u{d7a3}".as_bytes()
        );
        assert_eq!(
            &nfc_normalize("\u{d788}\u{11c3}")[..],
            "\u{d788}\u{11c3}".as_bytes()
        );
    }

    #[test]
    fn nfc_orders_reverse_class_run_with_linear_work_and_fixed_storage() {
        let mut representatives = [None; 256];
        for value in 0u32..=0x10_ffff {
            let Some(scalar) = char::from_u32(value) else {
                continue;
            };
            let class = usize::from(canonical_combining_class(scalar));
            if class == 0 || representatives[class].is_some() {
                continue;
            }
            let mut emitted = 0usize;
            let mut decomposed = None;
            decompose_canonical(scalar, |part| {
                emitted += 1;
                decomposed = Some(part);
            });
            if emitted == 1 && decomposed == Some(scalar) {
                representatives[class] = Some(scalar);
            }
        }

        let mut input = String::from("q");
        let mut distinct_classes = 0usize;
        for class in (1usize..=255).rev() {
            if let Some(mark) = representatives[class] {
                distinct_classes += 1;
                for _ in 0..64 {
                    input.push(mark);
                }
            }
        }
        assert!(distinct_classes > 16);
        let mut previous_class = u8::MAX;
        for mark in input.chars().skip(1) {
            let class = canonical_combining_class(mark);
            assert!(class <= previous_class);
            previous_class = class;
        }
        assert_matches_reference(&input);

        let decomposed_len = canonical_decomposition_len(&input).expect("bounded test input");
        let mut scalars =
            allocate_zeroizing_box::<u32>(decomposed_len).expect("bounded test allocation");
        let mut classes =
            allocate_zeroizing_box::<u8>(decomposed_len).expect("bounded test allocation");
        let mut ordered_scalars =
            allocate_zeroizing_box::<u32>(decomposed_len).expect("bounded test allocation");
        let mut ordered_classes =
            allocate_zeroizing_box::<u8>(decomposed_len).expect("bounded test allocation");
        let scalar_ptr = scalars.as_ptr();
        let class_ptr = classes.as_ptr();
        let ordered_scalar_ptr = ordered_scalars.as_ptr();
        let ordered_class_ptr = ordered_classes.as_ptr();

        fill_canonical_decomposition(&input, &mut scalars, &mut classes)
            .expect("decomposition count is deterministic");
        assert_eq!(scalars.as_ptr(), scalar_ptr);
        assert_eq!(classes.as_ptr(), class_ptr);
        assert_eq!(scalars.len(), decomposed_len);
        assert_eq!(classes.len(), decomposed_len);
        assert_eq!(ordered_scalars.as_ptr(), ordered_scalar_ptr);
        assert_eq!(ordered_classes.as_ptr(), ordered_class_ptr);

        let work = canonical_order(
            &mut scalars,
            &mut classes,
            &mut ordered_scalars,
            &mut ordered_classes,
        )
        .expect("equal fixed scratch lengths");
        let linear_work_bound = decomposed_len
            .checked_mul(8)
            .and_then(|bound| bound.checked_add(1_024))
            .expect("bounded test work");
        assert!(
            work <= linear_work_bound,
            "canonical ordering used {work} operations for {decomposed_len} scalars"
        );
        assert_eq!(scalars.as_ptr(), scalar_ptr);
        assert_eq!(classes.as_ptr(), class_ptr);
        assert_eq!(ordered_scalars.as_ptr(), ordered_scalar_ptr);
        assert_eq!(ordered_classes.as_ptr(), ordered_class_ptr);

        let composed_len =
            canonical_compose(&mut scalars, &mut classes).expect("valid decomposed scalars");
        assert!(composed_len <= decomposed_len);
        assert_eq!(scalars.as_ptr(), scalar_ptr);
        assert_eq!(classes.as_ptr(), class_ptr);
        assert_eq!(scalars.len(), decomposed_len);
        assert_eq!(classes.len(), decomposed_len);

        let utf8_len = normalized_utf8_len(&scalars, composed_len).expect("valid scalars");
        let mut output =
            Zeroizing::new(allocate_zeroed_vec::<u8>(utf8_len).expect("bounded test allocation"));
        let output_ptr = output.as_ptr();
        encode_normalized_into(&scalars, composed_len, &mut output).expect("exact output length");
        assert_eq!(output.as_ptr(), output_ptr);
        assert_eq!(&output[..], reference_nfc(&input).as_slice());
    }

    #[test]
    fn nfc_matches_generated_interacting_sequences() {
        let alphabet = [
            'A',
            'a',
            '\u{300}',
            '\u{301}',
            '\u{302}',
            '\u{305}',
            '\u{315}',
            '\u{316}',
            '\u{323}',
            '\u{327}',
            '\u{345}',
            '\u{5ae}',
            '\u{1100}',
            '\u{1102}',
            '\u{1161}',
            '\u{11a8}',
            '\u{11ab}',
            '\u{ac00}',
            '\u{ac01}',
            '\u{e9}',
            '\u{212b}',
            '\u{f900}',
            '\u{1f600}',
        ];
        let mut state = 0x6a09_e667_f3bc_c909u64;

        for sequence in 0..256usize {
            let mut input = String::new();
            for _ in 0..(32 + sequence % 65) {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                input.push(alphabet[(state as usize) % alphabet.len()]);
            }
            assert_matches_reference(&input);
        }
    }

    #[test]
    fn nfc_matches_every_valid_unicode_scalar_in_bounded_batches() {
        const BATCH_SCALARS: usize = 4096;
        const VALID_SCALARS: usize = 0x11_0000 - 0x800;

        let mut batch = String::with_capacity(BATCH_SCALARS * 5);
        let mut in_batch = 0usize;
        let mut total = 0usize;

        for value in 0u32..=0x10_ffff {
            let Some(scalar) = char::from_u32(value) else {
                continue;
            };
            batch.push(scalar);
            // Bound combining runs while still checking every scalar's canonical
            // decomposition and composition behavior in surrounding text.
            batch.push('\0');
            in_batch += 1;
            total += 1;

            if in_batch == BATCH_SCALARS {
                assert_matches_reference(&batch);
                batch.clear();
                in_batch = 0;
            }
        }

        if !batch.is_empty() {
            assert_matches_reference(&batch);
        }
        assert_eq!(total, VALID_SCALARS);
    }

    #[test]
    fn fixed_allocations_reject_capacity_overflow_before_fill() {
        assert!(allocate_zeroed_vec::<u32>(usize::MAX).is_err());
        let empty = nfc_normalize("");
        assert!(empty.is_empty());
    }
}

#[cfg(test)]
mod tests;
