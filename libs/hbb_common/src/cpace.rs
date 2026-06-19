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
    message_proto::{cpace::Union as CpaceUnion, Cpace, CpaceStep1, CpaceStep2, CpaceStep3, CpaceStep4},
    tcp::FramedStream,
};
use bytes::Bytes;
use pake::{DirectionalKeys, Initiator, PakeError, Responder, Step1, Step2, Step3, Step4, CI_PORT};
use protobuf::Message as _;
use sodiumoxide::crypto::secretbox::{self, Key, Nonce};

/// Per-step bounded-read deadline (R-P14b). Matches the inherited
/// CONNECT_TIMEOUT/READ_TIMEOUT of 18 s; the timeout is the sole bound on a peer
/// that opens the connection and then stalls (the codec returns no error on a
/// dribbled frame).
const HANDSHAKE_STEP_TIMEOUT_MS: u64 = 18_000;
/// The pre-key frame cap (R-S7 / R-P14b). Each CPace step is ≤ ~120 B; this bounds
/// the only attacker-reachable parser before keying.
const MAX_CPACE_PACKET: usize = 4096;

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

/// Drive the responder (controlled side) handshake to completion and return the
/// two role-oriented keys (controlled seals with `k_s2c`, opens with `k_c2s`).
/// Caller installs them and, on [`HandshakeError::Confirmation`], increments the
/// per-source limiter (R-P14c) — never on any other abort.
pub async fn run_responder(stream: &mut FramedStream, password: &str) -> HResult<DirectionalKeys> {
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
    Ok(keys)
}

/// Drive the initiator (viewer) handshake to completion and return the two
/// role-oriented keys (viewer seals with `k_c2s`, opens with `k_s2c`).
pub async fn run_initiator(stream: &mut FramedStream, password: &str) -> HResult<DirectionalKeys> {
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
    Ok(keys)
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
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.write_seq += 1;
        secretbox::seal(plaintext, &Self::nonce(self.write_seq), &self.send_key)
    }

    /// Open an inbound frame under the recv key (R-P10).
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        self.read_seq += 1;
        secretbox::open(ciphertext, &Self::nonce(self.read_seq), &self.recv_key)
    }
}

// The wire-level round-trip / adversarial tests live in the dedicated `cpace_it`
// crate (libs/cpace_it): hbb_common's own test build links the `webrtc` dev-
// dependency, whose `sdp` crate does not compile on the pinned 1.75 toolchain, so
// an in-crate `#[cfg(test)]` here could not run. `cpace_it` depends only on
// hbb_common's library (no dev-deps ⇒ no webrtc) and exercises the public API
// (`run_initiator`/`run_responder`/`DirectionalCipher`) over a loopback socket.

