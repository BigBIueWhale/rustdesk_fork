//! CPace handshake driver (R-P14) — runs the [`pake`] state machine over a
//! [`FramedStream`], mapping the dedicated `Cpace` protobuf steps to/from the
//! wire on the still-unkeyed stream, and yields the two per-direction secretbox
//! keys (R-P2). This is the choke-point logic (`create_tcp_connection`), factored
//! here so it is unit-testable against an in-memory connection; `server.rs`
//! (responder) and `client.rs` (initiator) call [`run_responder`] /
//! [`run_initiator`].
//!
//! The pre-key reader parses ONLY `Cpace` (`parse_from_bytes::<Cpace>`), never
//! the `Message` union (R-P14/R-S7), under a small frame cap (R-S7/R-P14b) and a
//! finite per-step timeout (R-P14b). Strict per-role step ordering and
//! no-duplicate handling come from the [`pake`] type-state machine plus the
//! single-variant `match` in each receiving state (R-P14a). Only a key-
//! confirmation failure is reported as an online password guess (R-P14c).

use crate::{
    message_proto::{
        cpace::Union as CpaceUnion, Cpace, CpaceStep1, CpaceStep2, CpaceStep3, CpaceStep4,
        HostIdentity,
    },
    tcp::FramedStream,
};
use bytes::Bytes;
pub use pake::DirectionalKeys;
use pake::{channel_identifier, Initiator, PakeError, Responder, Step1, Step2, Step3, Step4, CI_PORT};
use protobuf::Message as _;
use sodiumoxide::crypto::secretbox::{self, Key, Nonce};
use sodiumoxide::crypto::sign;

/// Per-step bounded-read deadline (R-P14b). Matches the inherited
/// CONNECT_TIMEOUT/READ_TIMEOUT of 18 s; the timeout is the sole bound on a peer
/// that opens the connection and then stalls (the codec returns no error on a
/// dribbled frame).
const HANDSHAKE_STEP_TIMEOUT_MS: u64 = 18_000;
/// The pre-key frame cap (R-S7 / R-P14b). Each CPace step is ≤ ~120 B; this bounds
/// the only attacker-reachable parser before keying.
const MAX_CPACE_PACKET: usize = 4096;
/// The post-key session frame ceiling (R-S7). Once the PAKE completes the cap is
/// raised from the pre-auth 4 KiB to this sane ceiling — far below the variable-
/// length header's 1 GiB max, well above the 128 KiB file block (`fs.rs`) and any
/// realistic video keyframe. Leaving the cap at 4 KiB would reject every legit
/// session frame; not raising it at all (the inherited `usize::MAX`) would
/// re-open the ~1 GiB/connection pre-auth amplification this control closes.
const MAX_SESSION_PACKET: usize = 32 * 1024 * 1024;

/// A fail-closed handshake abort. Per **R-P14c**, only [`HandshakeError::Confirmation`]
/// is an online password guess and may feed the per-source limiter (R-S10); every
/// other variant MUST NOT, or a malformed-frame flood would trip the owner's own
/// block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// R-P3 key-confirmation tag mismatch — the sole online-guess event.
    Confirmation,
    /// Wrong / duplicate / out-of-order oneof variant, an unset union, a
    /// length-invalid field, or a decode failure (R-P14a). Does not feed the limiter.
    Protocol,
    /// A non-confirmation pre-key PAKE abort: ristretto255 decode, identity point,
    /// AD mismatch, or empty PRS (R-P7/R-P5/R-P1). Does not feed the limiter.
    Pake,
    /// Bounded-read failure: per-step timeout, peer EOF, or an oversize frame
    /// (R-P14b). Does not feed the limiter.
    Io,
    /// R-S17 host-key proof failure: the post-keyed `HostIdentity` frame is
    /// malformed, or its Ed25519 signature does not verify against the carried
    /// public key over this session's transcript. Fail-closed; not a guess.
    HostProof,
}

impl HandshakeError {
    /// True only for [`HandshakeError::Confirmation`] (R-P14c).
    #[inline]
    pub fn is_password_guess(&self) -> bool {
        matches!(self, HandshakeError::Confirmation)
    }
}

impl From<PakeError> for HandshakeError {
    fn from(e: PakeError) -> Self {
        // Preserve the limiter taxonomy: only a confirmation failure is a guess.
        if e.is_password_guess() {
            HandshakeError::Confirmation
        } else {
            HandshakeError::Pake
        }
    }
}

type HResult<T> = Result<T, HandshakeError>;

/// The handshake transcript the R-S17 host-proof signature binds: the full
/// 32-byte `sid` (`sid_a ‖ sid_b`) and both ephemeral public elements `Ya`, `Yb`.
/// `CI` is recomputed from the pinned port. Reconstructed from the `Step`
/// messages the driver already exchanged — the pake state machine needs no extra
/// fields, and the 16 KATs are untouched.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transcript {
    pub sid: [u8; 32],
    pub ya: [u8; 32],
    pub yb: [u8; 32],
}

impl Transcript {
    fn from_steps(step1: &Step1, step2: &Step2, step3: &Step3) -> Self {
        let mut sid = [0u8; 32];
        sid[..16].copy_from_slice(&step1.sid_a);
        sid[16..].copy_from_slice(&step2.sid_b);
        Transcript {
            sid,
            ya: step3.ya,
            yb: step2.yb,
        }
    }
}

// ── wire (Cpace protobuf) ⇄ pake step structs ────────────────────────────────

fn exact<const N: usize>(b: &[u8]) -> HResult<[u8; N]> {
    if b.len() != N {
        return Err(HandshakeError::Protocol);
    }
    let mut a = [0u8; N];
    a.copy_from_slice(b);
    Ok(a)
}

fn to_step1(p: &CpaceStep1) -> HResult<Step1> {
    Ok(Step1 {
        sid_a: exact::<16>(&p.sid_a)?,
        ada: p.ad_a.to_vec(),
    })
}
fn to_step2(p: &CpaceStep2) -> HResult<Step2> {
    Ok(Step2 {
        sid_b: exact::<16>(&p.sid_b)?,
        adb: p.ad_b.to_vec(),
        yb: exact::<32>(&p.yb)?,
    })
}
fn to_step3(p: &CpaceStep3) -> HResult<Step3> {
    Ok(Step3 {
        ya: exact::<32>(&p.ya)?,
        ta: exact::<64>(&p.ta)?,
    })
}
fn to_step4(p: &CpaceStep4) -> HResult<Step4> {
    Ok(Step4 {
        tb: exact::<64>(&p.tb)?,
    })
}

fn from_step1(s: &Step1) -> Cpace {
    Cpace {
        union: Some(CpaceUnion::Step1(CpaceStep1 {
            sid_a: Bytes::copy_from_slice(&s.sid_a),
            ad_a: Bytes::copy_from_slice(&s.ada),
            ..Default::default()
        })),
        ..Default::default()
    }
}
fn from_step2(s: &Step2) -> Cpace {
    Cpace {
        union: Some(CpaceUnion::Step2(CpaceStep2 {
            sid_b: Bytes::copy_from_slice(&s.sid_b),
            ad_b: Bytes::copy_from_slice(&s.adb),
            yb: Bytes::copy_from_slice(&s.yb),
            ..Default::default()
        })),
        ..Default::default()
    }
}
fn from_step3(s: &Step3) -> Cpace {
    Cpace {
        union: Some(CpaceUnion::Step3(CpaceStep3 {
            ya: Bytes::copy_from_slice(&s.ya),
            ta: Bytes::copy_from_slice(&s.ta),
            ..Default::default()
        })),
        ..Default::default()
    }
}
fn from_step4(s: &Step4) -> Cpace {
    Cpace {
        union: Some(CpaceUnion::Step4(CpaceStep4 {
            tb: Bytes::copy_from_slice(&s.tb),
            ..Default::default()
        })),
        ..Default::default()
    }
}

// ── framed I/O on the unkeyed stream ─────────────────────────────────────────

async fn send_cpace(stream: &mut FramedStream, msg: Cpace) -> HResult<()> {
    stream.send(&msg).await.map_err(|_| HandshakeError::Io)
}

/// Read exactly one `Cpace` frame under the bounded-read deadline (R-P14b). A
/// timeout, peer EOF, or oversize frame is [`HandshakeError::Io`]; a parse
/// failure is [`HandshakeError::Protocol`] (a decode abort, not a guess, R-P14c).
async fn recv_cpace(stream: &mut FramedStream) -> HResult<Cpace> {
    match stream.next_timeout(HANDSHAKE_STEP_TIMEOUT_MS).await {
        Some(Ok(bytes)) => Cpace::parse_from_bytes(&bytes).map_err(|_| HandshakeError::Protocol),
        Some(Err(_)) => Err(HandshakeError::Io), // oversize / I/O error
        None => Err(HandshakeError::Io),         // timeout / EOF
    }
}

// ── the two drivers ──────────────────────────────────────────────────────────

/// Drive the responder handshake and return only the keys — a convenience over
/// [`run_responder_with_transcript`] for callers that need no host-proof.
pub async fn run_responder(stream: &mut FramedStream, password: &str) -> HResult<DirectionalKeys> {
    run_responder_with_transcript(stream, password)
        .await
        .map(|(keys, _)| keys)
}

/// Drive the responder (controlled side) handshake to completion and return the
/// two role-oriented keys (controlled seals with `k_s2c`, opens with `k_c2s`)
/// PLUS the [`Transcript`] (`sid`/`Ya`/`Yb`) the R-S17 host-proof binds. Caller
/// installs the keys and, on [`HandshakeError::Confirmation`], increments the
/// per-source limiter (R-P14c) — never on any other abort.
pub async fn run_responder_with_transcript(
    stream: &mut FramedStream,
    password: &str,
) -> HResult<(DirectionalKeys, Transcript)> {
    stream.set_max_packet_length(MAX_CPACE_PACKET); // R-S7, before the first byte
    let responder = Responder::new(password, CI_PORT)?;

    // WAIT_1: accept ONLY step ① (R-P14a).
    let step1 = match recv_cpace(stream).await?.union {
        Some(CpaceUnion::Step1(s)) => to_step1(&s)?,
        _ => return Err(HandshakeError::Protocol),
    };
    let (responder, step2) = responder.recv_step1(&step1)?;
    send_cpace(stream, from_step2(&step2)).await?;

    // WAIT_3: accept ONLY step ③.
    let step3 = match recv_cpace(stream).await?.union {
        Some(CpaceUnion::Step3(s)) => to_step3(&s)?,
        _ => return Err(HandshakeError::Protocol),
    };
    // recv_step3 verifies the initiator's tag (R-P3) before producing step ④.
    let (keys, step4) = responder.recv_step3(&step3)?;
    send_cpace(stream, from_step4(&step4)).await?;
    // R-S7: keying done — raise the frame cap from the pre-auth 4 KiB to the
    // session ceiling so legit large frames (file blocks, keyframes) flow.
    stream.set_max_packet_length(MAX_SESSION_PACKET);
    let transcript = Transcript::from_steps(&step1, &step2, &step3);
    Ok((keys, transcript))
}

/// Drive the initiator handshake and return only the keys — a convenience over
/// [`run_initiator_with_transcript`] for callers that need no host-proof.
pub async fn run_initiator(stream: &mut FramedStream, password: &str) -> HResult<DirectionalKeys> {
    run_initiator_with_transcript(stream, password)
        .await
        .map(|(keys, _)| keys)
}

/// Drive the initiator (viewer) handshake to completion and return the two
/// role-oriented keys (viewer seals with `k_c2s`, opens with `k_s2c`) PLUS the
/// [`Transcript`] — the viewer needs it to verify the responder's R-S17
/// `HostIdentity` host-proof against its local pin.
pub async fn run_initiator_with_transcript(
    stream: &mut FramedStream,
    password: &str,
) -> HResult<(DirectionalKeys, Transcript)> {
    stream.set_max_packet_length(MAX_CPACE_PACKET);
    let (initiator, step1) = Initiator::new(password, CI_PORT)?;
    send_cpace(stream, from_step1(&step1)).await?;

    // WAIT_2: accept ONLY step ②.
    let step2 = match recv_cpace(stream).await?.union {
        Some(CpaceUnion::Step2(s)) => to_step2(&s)?,
        _ => return Err(HandshakeError::Protocol),
    };
    let (initiator, step3) = initiator.recv_step2(&step2)?;
    send_cpace(stream, from_step3(&step3)).await?;

    // WAIT_4: accept ONLY step ④; verify the responder's tag (R-P3).
    let step4 = match recv_cpace(stream).await?.union {
        Some(CpaceUnion::Step4(s)) => to_step4(&s)?,
        _ => return Err(HandshakeError::Protocol),
    };
    let keys = initiator.recv_step4(&step4)?;
    // R-S7: keying done — raise the frame cap to the session ceiling (see
    // run_responder); both peers must agree, so the initiator raises too.
    stream.set_max_packet_length(MAX_SESSION_PACKET);
    let transcript = Transcript::from_steps(&step1, &step2, &step3);
    Ok((keys, transcript))
}

// ── R-S17 host-key proof (the HostIdentity frame) ────────────────────────────

/// R-S17 host-proof domain separator — folded into the signed value so this
/// Ed25519 signature can serve no other purpose (it cannot be confused with, or
/// relayed into, any other signing context).
const HOST_PROOF_DSI: &[u8] = b"rustdesk-fork/host-proof/v1";

/// The host-proof signable message: `DSI ‖ sid ‖ CI ‖ Ya ‖ Yb` (R-S17). Folding
/// `sid` and BOTH ephemerals welds the proof to THIS PAKE session — a different
/// session has different `sid`/ephemerals, so a signature cannot be relayed,
/// spliced, or replayed into another (this is what forecloses the
/// tunneled-/compound-authentication MITM class).
fn host_proof_message(t: &Transcript) -> Vec<u8> {
    let ci = channel_identifier(CI_PORT);
    let mut m = Vec::with_capacity(HOST_PROOF_DSI.len() + 32 + ci.len() + 32 + 32);
    m.extend_from_slice(HOST_PROOF_DSI);
    m.extend_from_slice(&t.sid);
    m.extend_from_slice(&ci);
    m.extend_from_slice(&t.ya);
    m.extend_from_slice(&t.yb);
    m
}

/// Build the controlled box's [`HostIdentity`] frame (R-S17): sign the
/// session-bound host-proof message with the box's Ed25519 secret key and
/// package it with the public key. Returns the serialized proto bytes to send
/// (encrypted) as the first post-keyed frame. `pk`/`sk` are passed in (not read
/// from global `Config`) so this is unit-testable; the choke point supplies
/// `Config::get_key_pair()` — `.1` is the public key, `.0` the secret.
pub fn build_host_identity(t: &Transcript, pk: &[u8], sk: &[u8]) -> HResult<Vec<u8>> {
    let sk = sign::SecretKey::from_slice(sk).ok_or(HandshakeError::HostProof)?;
    let sig = sign::sign_detached(&host_proof_message(t), &sk);
    let hi = HostIdentity {
        pk: Bytes::copy_from_slice(pk),
        sig: Bytes::copy_from_slice(sig.as_ref()),
        ..Default::default()
    };
    hi.write_to_bytes().map_err(|_| HandshakeError::HostProof)
}

/// Verify a received [`HostIdentity`] frame against the local transcript (R-S17):
/// parse it, verify the Ed25519 signature over the reconstructed host-proof
/// message against the carried `pk`, and on success return `pk` for the caller's
/// pin compare. A forged signature, a mutated `pk` (a substitute that merely saw
/// the key), or a signature from a different session all fail — the proof is
/// welded to THIS session, so a present-only or MAC-bound check could not catch
/// what this does. (The pin compare itself — `pk` vs the pinned key — is the
/// caller's; this proves the signer holds the matching private key.)
pub fn verify_host_identity(t: &Transcript, bytes: &[u8]) -> HResult<Vec<u8>> {
    let hi = HostIdentity::parse_from_bytes(bytes).map_err(|_| HandshakeError::HostProof)?;
    let pk = sign::PublicKey::from_slice(&hi.pk).ok_or(HandshakeError::HostProof)?;
    let sig = sign::Signature::from_bytes(&hi.sig).map_err(|_| HandshakeError::HostProof)?;
    if sign::verify_detached(&sig, &host_proof_message(t), &pk) {
        Ok(hi.pk.to_vec())
    } else {
        Err(HandshakeError::HostProof)
    }
}

// ── two-key directional cipher (R-P2/R-P10) ──────────────────────────────────

/// XSalsa20-Poly1305 secretbox keyed with **two per-direction keys** — the fix
/// for the inherited single-key reuse (R-P10). Each direction has its own key and
/// its own monotonic counter; the nonce is the pre-incremented counter (first
/// nonce LE64(1)). Because send and recv keys differ, identical counters from 0
/// are safe, and one MUST NOT collapse to a single key. Replaces the inherited
/// `tcp::Encrypt(Key, u64, u64)` at the choke-point cutover.
pub struct DirectionalCipher {
    send_key: Key,
    recv_key: Key,
    write_seq: u64,
    read_seq: u64,
}

impl DirectionalCipher {
    /// Install the role-oriented keys from a completed handshake (R-P2).
    ///
    /// R-A5: the secretbox layer MUST have two **distinct** per-direction keys
    /// engaged — never one shared key both ways (the inherited catastrophic
    /// `(key, nonce)` reuse). HKDF's distinct c2s/s2c labels guarantee this by
    /// construction; the assertion fail-closes on a keying-mis-wire *regression*
    /// — exactly the case the wire-capture test (R-A9) would not catch, since the
    /// keys are derived internally and never attacker-influenced.
    pub fn new(keys: &DirectionalKeys) -> Self {
        assert_ne!(
            keys.send, keys.recv,
            "R-A5: identical send/recv keys — refusing to engage single-key reuse"
        );
        // `[u8; 32]` is Copy, so this copies out of the zeroize-on-drop keys.
        Self {
            send_key: Key(keys.send),
            recv_key: Key(keys.recv),
            write_seq: 0,
            read_seq: 0,
        }
    }

    fn nonce(seq: u64) -> Nonce {
        let mut nonce = Nonce([0u8; secretbox::NONCEBYTES]);
        nonce.0[..std::mem::size_of::<u64>()].copy_from_slice(&seq.to_le_bytes());
        nonce
    }

    /// Seal an outbound frame under the send key (R-P10).
    ///
    /// R-A5: the per-direction nonce IS this monotonic counter, so it MUST NEVER wrap — a wrap
    /// resets to an already-used nonce and reuses `(key, nonce)`, the catastrophic XSalsa20-Poly1305
    /// failure. At `u64::MAX` (2^64 frames) the counter is exhausted; that is physically unreachable
    /// (~5.8e8 yr at 1000 frames/s), but the fork still FAILS CLOSED rather than reset — `+= 1` would
    /// silently wrap in a release build, so use a checked increment. The spec prefers a fresh-key
    /// rekey; aborting is its conservative form (the MUST is "not a counter reset"), and a full
    /// mid-session re-CPace is over-engineering for an unreachable case.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.write_seq = self
            .write_seq
            .checked_add(1)
            .expect("R-A5: send nonce-counter exhausted (2^64 frames) — fail-closed, never reuse a nonce");
        secretbox::seal(plaintext, &Self::nonce(self.write_seq), &self.send_key)
    }

    /// Open an inbound frame under the recv key (R-P10).
    ///
    /// R-A5 (recv side): the recv nonce-counter MUST NOT wrap either (a wrap would accept a frame
    /// under a reused recv nonce). At exhaustion, reject the frame (`Err`) so the connection tears
    /// down fail-closed — never reset the counter.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        self.read_seq = self.read_seq.checked_add(1).ok_or(())?;
        secretbox::open(ciphertext, &Self::nonce(self.read_seq), &self.recv_key)
    }

    /// The recv counter — exposed for the R-T5 cancellation-safety regression test (a dropped
    /// `FramedStream::next` MUST NOT advance it).
    #[inline]
    pub fn read_seq(&self) -> u64 {
        self.read_seq
    }
}

// ── per-source online-guess limiter (R-S10 / R-P14c) ─────────────────────────
//
// The PAKE permits exactly one online password guess per connection, so an
// attacker's only lever is connection volume. This per-IP limiter caps the rate
// of *key-confirmation failures* (the sole online-guess event, R-P14c) — checked
// before the expensive scalar-mult so a blocked source is shed cheaply, and fed
// ONLY by a confirmation mismatch (decode/order/AD/identity/timeout aborts MUST
// NOT increment it, or a malformed-frame flood would trip the owner's own block).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Fixed (tumbling) per-source window for the online-guess limiter — NOT sliding: the window
/// start is not advanced per failure (see `record_guess_failure`), so at most
/// `MAX_GUESSES_PER_WINDOW` confirmation failures per `GUESS_WINDOW` per source IP are allowed
/// (R-S10), with a ~2x worst case straddling a boundary. That is immaterial: the CPace password is
/// the real gate (one online guess per attempt, nothing offline-crackable); this is only DoS-safe
/// rate-limiting, fail-cheap before the scalar-mult (R-P14c) — defence-in-depth, not the auth.
const GUESS_WINDOW: Duration = Duration::from_secs(60);
/// Confirmation failures allowed from one source within a window before it is shed.
const MAX_GUESSES_PER_WINDOW: u32 = 10;

lazy_static::lazy_static! {
    static ref GUESS_FAILURES: Mutex<HashMap<IpAddr, (u32, Instant)>> =
        Mutex::new(HashMap::new());
}

/// True if `source` may attempt a handshake; false if it has exceeded the online-
/// guess rate within the current window (R-S10). MUST be called before the
/// scalar-mult (R-P14c) so a blocked source costs almost nothing.
pub fn guess_limiter_allows(source: IpAddr) -> bool {
    let map = GUESS_FAILURES.lock().unwrap();
    match map.get(&source) {
        Some(&(count, start)) if start.elapsed() < GUESS_WINDOW => count < MAX_GUESSES_PER_WINDOW,
        _ => true, // no record, or the window has expired
    }
}

/// Record one online-guess failure for `source`. Per R-P14c the caller invokes
/// this ONLY on an R-P3 key-confirmation mismatch, never on any other abort.
pub fn record_guess_failure(source: IpAddr) {
    let mut map = GUESS_FAILURES.lock().unwrap();
    let now = Instant::now();
    match map.get_mut(&source) {
        Some(entry) if entry.1.elapsed() < GUESS_WINDOW => entry.0 = entry.0.saturating_add(1),
        _ => {
            map.insert(source, (1, now));
        }
    }
    // Bounded memory: drop entries whose window has long since lapsed.
    map.retain(|_, (_, start)| start.elapsed() < GUESS_WINDOW.saturating_mul(2));
}

// The wire-level round-trip / adversarial tests live in the dedicated `cpace_it`
// crate (libs/cpace_it): hbb_common's own test build links the `webrtc` dev-
// dependency, whose `sdp` crate does not compile on the pinned 1.75 toolchain, so
// an in-crate `#[cfg(test)]` here could not run. `cpace_it` depends only on
// hbb_common's library (no dev-deps ⇒ no webrtc) and exercises the public API
// (`run_initiator`/`run_responder`/`DirectionalCipher`) over a loopback socket.

