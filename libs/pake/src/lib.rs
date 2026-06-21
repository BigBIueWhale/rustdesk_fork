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
use unicode_normalization::UnicodeNormalization;
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
fn derive_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let gs = generator_string(prs, ci, sid);
    let hash = Sha512::digest(&gs); // 64 bytes
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    let g = RistrettoPoint::from_uniform_bytes(&wide);
    wide.zeroize();
    g
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
/// (R-P2/R-P9). Returns `(k_c2s, k_s2c)`.
fn derive_session_keys(isk: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT), isk);
    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];
    // expand() only fails for absurd output lengths; 32 bytes never does.
    hk.expand(HKDF_INFO_C2S, &mut k_c2s).expect("hkdf c2s");
    hk.expand(HKDF_INFO_S2C, &mut k_s2c).expect("hkdf s2c");
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

/// PRS = NFC(password), no case-fold — a deliberate NFC-only subset of RFC 8265
/// OpaqueString (R-P1). MUST be non-empty after normalization (R-P1/R-S9).
fn normalize_prs(password: &str) -> Result<Zeroizing<Vec<u8>>, PakeError> {
    let prs: String = password.nfc().collect();
    if prs.is_empty() {
        return Err(PakeError::EmptyPassword);
    }
    Ok(Zeroizing::new(prs.into_bytes()))
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

        let g = derive_generator(&self.prs, &self.ci, &sid);
        let ya_pt = (ya * g).compress().to_bytes();

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
        let k_pt = ya * yb_pt;
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

        let next = InitiatorAwaitConfirm {
            mac_key,
            yb: step2.yb,
            k_c2s,
            k_s2c,
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

        let g = derive_generator(&self.prs, &self.ci, &sid);
        let yb_pt = (yb * g).compress().to_bytes();

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
        let k_pt = self.yb_scalar * ya_pt;
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
            self.yb_scalar.zeroize();
            return Err(PakeError::Confirmation);
        }
        let tb = compute_tag(&mac_key, &self.yb_pt, AD_RESPONDER);
        self.yb_scalar.zeroize();
        Ok((
            DirectionalKeys {
                send: k_s2c,
                recv: k_c2s,
            },
            Step4 { tb },
        ))
    }
}

#[cfg(test)]
mod tests;
