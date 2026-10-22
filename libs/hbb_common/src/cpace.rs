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
    },
    tcp::FramedStream,
};
use bytes::Bytes;
pub use pake::DirectionalKeys;
use pake::{Initiator, PakeError, Responder, Step1, Step2, Step3, Step4, CI_PORT};
use protobuf::Message as _;
use sodiumoxide::crypto::secretbox::{self, Key, Nonce};

/// Per-step bounded-read deadline (R-P14b). Matches the inherited
/// CONNECT_TIMEOUT/READ_TIMEOUT of 18 s; the timeout is the sole bound on a peer
/// that opens the connection and then stalls (the codec returns no error on a
/// dribbled frame).
const HANDSHAKE_STEP_TIMEOUT_MS: u64 = 18_000;
/// R1(a) DoS hardening — a SHORTER deadline for the responder's FIRST inbound step
/// (WAIT_1) ONLY. A legitimate viewer prepares its credential before acquiring the socket and
/// sends CPace step ① as the very first frame immediately after TCP connect, so 5 s does not reject
/// a real first step even over a high-latency/lossy link (worst realistic case ~1–3 s incl.
/// TCP retransmits). But it slashes the pre-key silent-hold: an attacker who opens a
/// connection and then sends nothing pins its R-T1 handshake permit for 5 s, not 18 s
/// (~3.6× less capacity consumed per slot → ~3.6× the flood rate to saturate). Every
/// LATER step keeps the full 18 s — post-step-① progress legitimately involves crypto
/// plus a network round-trip, so it must not be rushed. Responder WAIT_1 is the only
/// recv an UNAUTHENTICATED internet attacker drives, so it is the only one shortened.
const HANDSHAKE_FIRST_STEP_TIMEOUT_MS: u64 = 5_000;
/// The pre-key frame cap (R-S7 / R-P14b). Each CPace step is ≤ ~120 B; this bounds
/// the only attacker-reachable parser before keying.
const MAX_CPACE_PACKET: usize = 4096;
/// The post-key session frame ceiling (R-S7). Once the PAKE completes the cap is
/// raised from the pre-auth 4 KiB to this sane ceiling — far below the variable-
/// length header's 1 GiB max, well above the 128 KiB file block (`fs.rs`) and any
/// realistic video keyframe. Leaving the cap at 4 KiB would reject every legit
/// session frame; not raising it at all (the inherited `usize::MAX`) would
/// re-open the ~1 GiB/connection pre-auth amplification this control closes.
pub const MAX_SESSION_PACKET: usize = 32 * 1024 * 1024;

/// A fail-closed handshake abort. Per **R-P14c**, only [`HandshakeError::Confirmation`]
/// is an online password guess and may feed the per-source limiter (R-S10); every
/// other variant MUST NOT, or a malformed-frame flood would trip the owner's own
/// block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// R-P3 key-confirmation tag mismatch — the sole online-guess event.
    Confirmation,
    /// The initiator successfully submitted step ③ but could not obtain step ④.
    /// The responder may have rejected the initiator's confirmation (for example,
    /// because the PRSs differ), or the transport/peer may have failed before its
    /// confirmation arrived. This ambiguity is intentionally preserved: it is a
    /// local credential-replacement opportunity, not proof of a password guess,
    /// and therefore never feeds the responder's per-source limiter.
    PeerConfirmationUnavailable,
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

/// The completed handshake's transcript: the full 32-byte `sid` (`sid_a ‖ sid_b`)
/// and both ephemeral public elements `Ya`, `Yb`. Reconstructed from the `Step`
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
    // R-P14b / R-T1 (active-router threat model): bound the pre-key SEND with the same per-step
    // deadline `recv_cpace` already applies to reads, so the handshake is fully step-bounded in BOTH
    // directions. A passive peer cannot stall a send of a sub-buffer-sized CPace frame — but a
    // MALICIOUS ROUTER manipulating TCP flow control (a forged zero-window advertisement, or dropping
    // the peer's ACKs) can stall ANY send regardless of frame size, leaving `poll_write` Pending
    // forever. Without this deadline the responder/initiator would block inside `send` indefinitely,
    // holding its R-T1 handshake permit (+ task + fd); 256 such stalled connections exhaust the
    // semaphore and deny legitimate handshakes, and keepalive cannot help (the router ACKs probes
    // while holding the window at zero). The bound is therefore the DEADLINE, not the frame size. A
    // timeout aborts the handshake fail-closed (HandshakeError::Io); the stream is then dropped, so
    // the partially-flushed pre-key frame is discarded (no cipher is engaged yet, so no nonce state).
    match crate::timeout(HANDSHAKE_STEP_TIMEOUT_MS, stream.send(&msg)).await {
        Ok(send_result) => send_result.map_err(|_| HandshakeError::Io),
        Err(_) => Err(HandshakeError::Io), // send deadline exceeded — router-stalled flow control
    }
}

/// Read exactly one `Cpace` frame under the bounded-read deadline (R-P14b). A
/// timeout, peer EOF, or oversize frame is [`HandshakeError::Io`]; a parse
/// failure is [`HandshakeError::Protocol`] (a decode abort, not a guess, R-P14c).
async fn recv_cpace(stream: &mut FramedStream, timeout_ms: u64) -> HResult<Cpace> {
    match stream.next_timeout(timeout_ms).await {
        Some(Ok(bytes)) => Cpace::parse_from_bytes(&bytes).map_err(|_| HandshakeError::Protocol),
        Some(Err(_)) => Err(HandshakeError::Io), // oversize / I/O error
        None => Err(HandshakeError::Io),         // timeout / EOF
    }
}

// ── the two drivers ──────────────────────────────────────────────────────────

/// Drive the responder handshake and return only the keys — a convenience over
/// [`run_responder_with_transcript`] for callers that need no transcript.
pub async fn run_responder(stream: &mut FramedStream, password: &str) -> HResult<DirectionalKeys> {
    run_responder_with_transcript(stream, password)
        .await
        .map(|(keys, _)| keys)
}

/// Drive the responder (controlled side) handshake to completion and return the
/// two role-oriented keys (controlled seals with `k_s2c`, opens with `k_c2s`)
/// PLUS the [`Transcript`] (`sid`/`Ya`/`Yb`) that binds this PAKE session. Caller
/// installs the keys and passes any failure to [`record_handshake_failure`],
/// which alone owns the R-P14c limiter taxonomy.
pub async fn run_responder_with_transcript(
    stream: &mut FramedStream,
    password: &str,
) -> HResult<(DirectionalKeys, Transcript)> {
    stream.set_max_packet_length(MAX_CPACE_PACKET); // R-S7, before the first byte
    let responder = Responder::new(password, CI_PORT)?;

    // WAIT_1: accept ONLY step ① (R-P14a). Shorter deadline (R1(a)) — this is the only
    // recv an unauthenticated internet attacker drives; a real viewer's step ① is immediate.
    let step1 = match recv_cpace(stream, HANDSHAKE_FIRST_STEP_TIMEOUT_MS).await?.union {
        Some(CpaceUnion::Step1(s)) => to_step1(&s)?,
        _ => return Err(HandshakeError::Protocol),
    };
    let (responder, step2) = responder.recv_step1(&step1)?;
    send_cpace(stream, from_step2(&step2)).await?;

    // WAIT_3: accept ONLY step ③. Full deadline — the initiator did crypto + a round-trip.
    let step3 = match recv_cpace(stream, HANDSHAKE_STEP_TIMEOUT_MS).await?.union {
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
/// [`run_initiator_with_transcript`] for callers that need no transcript.
pub async fn run_initiator(stream: &mut FramedStream, password: &str) -> HResult<DirectionalKeys> {
    run_initiator_with_transcript(stream, password)
        .await
        .map(|(keys, _)| keys)
}

/// Drive the initiator (viewer) handshake to completion and return the two
/// role-oriented keys (viewer seals with `k_c2s`, opens with `k_s2c`) PLUS the
/// [`Transcript`] (`sid`/`Ya`/`Yb`) that binds this PAKE session.
pub async fn run_initiator_with_transcript(
    stream: &mut FramedStream,
    password: &str,
) -> HResult<(DirectionalKeys, Transcript)> {
    stream.set_max_packet_length(MAX_CPACE_PACKET);
    let (initiator, step1) = Initiator::new(password, CI_PORT)?;
    send_cpace(stream, from_step1(&step1)).await?;

    // WAIT_2: accept ONLY step ②. Initiator side (viewer, not the exposed server) — full 18 s.
    let step2 = match recv_cpace(stream, HANDSHAKE_STEP_TIMEOUT_MS).await?.union {
        Some(CpaceUnion::Step2(s)) => to_step2(&s)?,
        _ => return Err(HandshakeError::Protocol),
    };
    let (initiator, step3) = initiator.recv_step2(&step2)?;
    send_cpace(stream, from_step3(&step3)).await?;

    // WAIT_4: accept ONLY step ④; verify the responder's tag (R-P3). Initiator side — full 18 s.
    // A responder with a different PRS rejects our step ③ and closes without a step ④. Once step ③
    // was successfully submitted, an I/O abort is therefore intrinsically ambiguous: it can be a
    // credential rejection, transport loss, or a hostile peer. Preserve that exact stage instead of
    // collapsing it into the early-handshake `Io` class or claiming that the password was wrong.
    let step4_message = match recv_cpace(stream, HANDSHAKE_STEP_TIMEOUT_MS).await {
        Ok(message) => message,
        Err(HandshakeError::Io) => return Err(HandshakeError::PeerConfirmationUnavailable),
        Err(error) => return Err(error),
    };
    let step4 = match step4_message.union {
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

// ── two-key directional cipher (R-P2/R-P10) ──────────────────────────────────

/// XSalsa20-Poly1305 secretbox keyed with **two per-direction keys** — the fix
/// for the inherited single-key reuse (R-P10). Each direction has its own key and
/// its own monotonic counter; the nonce is the pre-incremented counter (first
/// nonce LE64(1)). Because send and recv keys differ, identical counters from 0
/// are safe, and one MUST NOT collapse to a single key. Replaces the inherited
/// `tcp::Encrypt(Key, u64, u64)` at the choke-point cutover.
///
/// R-T3 (§20): the seal and open halves are split into [`SealCipher`] (the
/// single-producer send side — owned by `FramedStream::send_bytes` so the nonce
/// advances in exact channel-FIFO order) and [`OpenCipher`] (the read-side codec).
/// The halves touch DISJOINT state — send_key/write_seq vs recv_key/read_seq — so
/// the writer-task relocation needs no lock. [`DirectionalCipher`] is retained as a
/// thin wrapper over the two halves for the round-trip self-test (R-A9); the live
/// transport drives the halves directly via [`split_session_keys`].

/// The shared nonce derivation — the pre-incremented per-direction counter, LE64
/// in the low 8 bytes (first nonce LE64(1)). Identical for seal and open.
fn cipher_nonce(seq: u64) -> Nonce {
    let mut nonce = Nonce([0u8; secretbox::NONCEBYTES]);
    nonce.0[..std::mem::size_of::<u64>()].copy_from_slice(&seq.to_le_bytes());
    nonce
}

/// The send half (R-T3 producer side) — owns the send key and the write counter.
/// A single producer (`FramedStream::send_bytes`) owns one of these, so `write_seq`
/// is a plain `u64` (never shared, so no atomic).
pub struct SealCipher {
    send_key: Key,
    write_seq: u64,
}

impl SealCipher {
    /// Seal an outbound frame under the send key (R-P10).
    ///
    /// Reserve the complete tag and payload before consuming the next nonce. Allocation failure
    /// and counter exhaustion return errors without changing the counter; it never wraps (R-A5).
    /// The detached tag is prefixed to preserve the combined secretbox wire format.
    pub fn seal(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let next_seq = self.write_seq
            .checked_add(1)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "send nonce-counter exhausted"))?;
        let length = plaintext.len().checked_add(secretbox::MACBYTES)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "ciphertext length overflow"))?;
        let mut ciphertext = Vec::new();
        ciphertext.try_reserve_exact(length)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        ciphertext.resize(secretbox::MACBYTES, 0);
        ciphertext.extend_from_slice(plaintext);
        let tag = secretbox::seal_detached(
            &mut ciphertext[secretbox::MACBYTES..], &cipher_nonce(next_seq), &self.send_key);
        ciphertext[..secretbox::MACBYTES].copy_from_slice(&tag.0);
        self.write_seq = next_seq;
        Ok(ciphertext)
    }

    /// TEST-SUPPORT (R-A8/R-T7 runtime validation): overwrite the send key with a fixed
    /// non-matching value so the next `seal` yields ciphertext the peer's recv key cannot open —
    /// simulating a forged/injected frame from a party without the matching key. Benign: it
    /// corrupts ONLY this stream's send direction (worst case: the peer drops our own connection);
    /// it cannot leak plaintext, weaken the peer, or bypass auth. Sole caller: the `probe_client`
    /// injection smoke. (Not reachable by a remote peer — it is a local, send-only self-corruption.)
    pub fn corrupt_key_for_test(&mut self) {
        self.send_key = Key([0x42u8; secretbox::KEYBYTES]);
    }
}

/// The recv half (R-T3 codec side) — owns the recv key and the read counter.
///
/// The retained read codec owns this state across pending-read cancellation. Transport status
/// borrows that codec; no observer receives a separate handle that can change its sequence.
pub struct OpenCipher {
    recv_key: Key,
    read_seq: u64,
}

impl OpenCipher {
    /// Authenticate and decrypt the owned frame under the recv key (R-P10).
    ///
    /// Reuse its payload storage and remove the tag only after authentication succeeds. Each
    /// complete frame attempt consumes one nonce; checked advancement refuses exhaustion without
    /// wrapping (R-A5). The transport retires the stream on an authentication error.
    /// Counter advancement and authentication have no intervening await (R-T5).
    pub fn open(&mut self, ciphertext: &mut bytes::BytesMut) -> Result<(), ()> {
        self.read_seq = self.read_seq.checked_add(1).ok_or(())?;
        if ciphertext.len() < secretbox::MACBYTES {
            return Err(());
        }
        let mut tag = secretbox::Tag([0; secretbox::MACBYTES]);
        tag.0.copy_from_slice(&ciphertext[..secretbox::MACBYTES]);
        secretbox::open_detached(&mut ciphertext[secretbox::MACBYTES..], &tag,
            &cipher_nonce(self.read_seq), &self.recv_key)?;
        bytes::Buf::advance(ciphertext, secretbox::MACBYTES);
        Ok(())
    }

    /// The recv counter — exposed for the R-T5 cancellation-safety regression test (a dropped
    /// `FramedStream::next` MUST NOT advance it).
    #[inline]
    pub fn read_seq(&self) -> u64 {
        self.read_seq
    }
}

/// Split a completed handshake's role-oriented keys into the two cipher halves (R-T3).
///
/// R-A5: the secretbox layer MUST have two **distinct** per-direction keys engaged — never one
/// shared key both ways (the inherited catastrophic `(key, nonce)` reuse). HKDF's distinct c2s/s2c
/// labels guarantee this by construction; the assertion fail-closes on a keying-mis-wire *regression*
/// — exactly the case the wire-capture test (R-A9) would not catch, since the keys are derived
/// internally and never attacker-influenced. The check is on the ENGAGED key material: a mis-wire
/// like `recv_key: Key(keys.send)` engages one key both ways while `keys.send != keys.recv` still
/// holds, and reading back the engaged fields fails closed on exactly that.
pub fn split_session_keys(keys: &DirectionalKeys) -> (SealCipher, OpenCipher) {
    // `[u8; 32]` is Copy, so this copies out of the zeroize-on-drop keys.
    let send_key = Key(keys.send);
    let recv_key = Key(keys.recv);
    assert_ne!(
        send_key.0, recv_key.0,
        "R-A5: identical engaged send/recv keys — refusing to engage single-key reuse"
    );
    (
        SealCipher {
            send_key,
            write_seq: 0,
        },
        OpenCipher {
            recv_key,
            read_seq: 0,
        },
    )
}

/// The two-key cipher as a single object — retained as a thin wrapper over the
/// [`SealCipher`] + [`OpenCipher`] halves for the round-trip self-test (R-A9). The
/// live transport uses the halves directly via the R-T3 writer-task split.
pub struct DirectionalCipher {
    seal: SealCipher,
    open: OpenCipher,
}

impl DirectionalCipher {
    /// Install the role-oriented keys from a completed handshake (R-P2).
    pub fn new(keys: &DirectionalKeys) -> Self {
        let (seal, open) = split_session_keys(keys);
        Self { seal, open }
    }

    /// Seal an outbound frame under the send key (R-P10).
    pub fn seal(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        self.seal.seal(plaintext)
    }

    /// Open an inbound frame under the recv key (R-P10).
    pub fn open(&mut self, ciphertext: &mut bytes::BytesMut) -> Result<(), ()> {
        self.open.open(ciphertext)
    }

    /// The recv counter — exposed for the R-T5 cancellation-safety regression test (a dropped
    /// `FramedStream::next` MUST NOT advance it).
    #[inline]
    pub fn read_seq(&self) -> u64 {
        self.open.read_seq()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod open_tests {
    use super::*;
    use bytes::BytesMut;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn owned_frame_opens_with_rust_allocations_refused() {
        const CHILD: &str = "RUSTDESK_CIPHER_OPEN_ALLOCATION_CHILD";
        const TEST: &str = "cpace::open_tests::owned_frame_opens_with_rust_allocations_refused";
        if std::env::var_os(CHILD).is_none() {
            let run = |mode| std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, mode).output().unwrap();
            let probe = run("probe");
            assert_eq!(probe.status.signal(), Some(crate::libc::SIGABRT));
            assert!(String::from_utf8_lossy(&probe.stderr).contains("memory allocation of 31 bytes failed"));
            let output = run("open");
            assert!(output.stdout.len() + output.stderr.len() < 32_768);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "receive cipher child {:?}: {}{}",
                output.status, stdout, String::from_utf8_lossy(&output.stderr));
            assert!(stdout.contains("RECEIVE_CIPHER=pass healthy=6 invalid=6 replay=refused exhaustion=refused rust_allocations=refused alias=exact neighbors=preserved"));
            for line in stdout.lines() {
                if let Some((_, message)) = line.split_once("RECEIVE_CIPHER") {
                    println!("RECEIVE_CIPHER{message}");
                }
            }
            return;
        }
        if std::env::var(CHILD).unwrap() == "probe" {
            crate::fs::with_allocations_refused(|| std::hint::black_box(Vec::<u8>::with_capacity(31)));
            panic!("allocation refusal probe must abort");
        }
        assert_eq!(std::env::var(CHILD).unwrap(), "open");
        let keys = DirectionalKeys { send: [0x2a; 32], recv: [0x19; 32] };
        let mut exact_alias = true;
        for shared in [false, true] {
            for size in [0, 1, 64 * 1_024] {
                let input = (0..size).map(|i| (i as u8).wrapping_mul(37)).collect::<Vec<_>>();
                let ciphertext = secretbox::seal(&input, &cipher_nonce(1), &Key(keys.recv));
                let (mut prefix, mut suffix) = (BytesMut::new(), BytesMut::new());
                let mut frame = if shared {
                    let mut storage = BytesMut::from(&b"prefix!"[..]);
                    storage.extend_from_slice(&ciphertext);
                    storage.extend_from_slice(b"tail!");
                    prefix = storage.split_to(7);
                    suffix = storage.split_off(ciphertext.len());
                    storage
                } else {
                    BytesMut::from(ciphertext.as_slice())
                };
                let pointer = frame.as_ptr() as usize;
                let (_, mut open) = split_session_keys(&keys);
                let result = crate::fs::with_allocations_refused(|| open.open(&mut frame));
                assert_eq!(result, Ok(()));
                assert_eq!(&frame[..], input);
                assert_eq!(open.read_seq(), 1);
                let in_place = frame.as_ptr() as usize == pointer + secretbox::MACBYTES;
                exact_alias &= in_place;
                if shared {
                    assert_eq!(&prefix[..], b"prefix!");
                    assert_eq!(&suffix[..], b"tail!");
                }
                println!("RECEIVE_CIPHER_CASE=pass shared={shared} bytes={size} rust_allocations=refused alias={in_place}");
            }
        }
        assert!(exact_alias);
        let valid = secretbox::seal(b"authenticated", &cipher_nonce(1), &Key(keys.recv));
        for kind in ["empty", "one", "short", "tag", "payload", "wrong-key"] {
            let mut raw = valid.clone();
            match kind {
                "empty" => raw.clear(),
                "one" => raw.truncate(1),
                "short" => raw.truncate(secretbox::MACBYTES - 1),
                "tag" => raw[0] ^= 1,
                "payload" => raw[secretbox::MACBYTES] ^= 1,
                "wrong-key" => {}
                _ => unreachable!(),
            }
            let (_, mut open) = split_session_keys(&keys);
            if kind == "wrong-key" {
                open.recv_key = Key([0x55; 32]);
            }
            let mut frame = BytesMut::from(raw.as_slice());
            let result = crate::fs::with_allocations_refused(|| open.open(&mut frame));
            assert_eq!(result, Err(()));
            assert_eq!(&frame[..], raw);
            assert_eq!(open.read_seq(), 1);
        }
        let (_, mut open) = split_session_keys(&keys);
        let mut first = BytesMut::from(valid.as_slice());
        crate::fs::with_allocations_refused(|| open.open(&mut first)).unwrap();
        let mut replay = BytesMut::from(valid.as_slice());
        assert_eq!(crate::fs::with_allocations_refused(|| open.open(&mut replay)), Err(()));
        assert_eq!(&replay[..], valid);
        assert_eq!(open.read_seq(), 2);
        open.read_seq = u64::MAX;
        for _ in 0..2 {
            assert_eq!(crate::fs::with_allocations_refused(|| open.open(&mut replay)), Err(()));
            assert_eq!(open.read_seq(), u64::MAX);
            assert_eq!(&replay[..], valid);
        }
        println!("RECEIVE_CIPHER=pass healthy=6 invalid=6 replay=refused exhaustion=refused rust_allocations=refused alias=exact neighbors=preserved");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod seal_tests {
    use super::*;

    #[test]
    fn allocation_refusal_preserves_nonce_and_wire() {
        const CHILD: &str = "RUSTDESK_CIPHER_SEAL_ALLOCATION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cpace::seal_tests::allocation_refusal_preserves_nonce_and_wire",
                    "--nocapture", "--test-threads=1"])
                .env(CHILD, "1").output().unwrap();
            assert!(output.stdout.len() + output.stderr.len() < 32_768);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "cipher allocation child {:?}: {}{}",
                output.status, stdout, String::from_utf8_lossy(&output.stderr));
            assert!(stdout.contains("CIPHER_SEAL_ALLOCATION=pass cases=3 refusals=3 nonce=preserved retries=exact wire=unchanged exhaustion=refused"));
            for line in stdout.lines() {
                if let Some((_, message)) = line.split_once("CIPHER_SEAL_") {
                    println!("CIPHER_SEAL_{message}");
                }
            }
            return;
        }
        assert_eq!(std::env::var(CHILD).unwrap(), "1");
        let keys = DirectionalKeys { send: [0x19; 32], recv: [0x2a; 32] };
        let (mut seal, _) = split_session_keys(&keys);
        for size in [0, 1, 64 * 1_024] {
            let input = (0..size).map(|i| (i as u8).wrapping_mul(37)).collect::<Vec<_>>();
            let before = seal.write_seq;
            crate::fs::fail_next_exact_allocation(size + secretbox::MACBYTES);
            let error = seal.seal(&input).expect_err("refused ciphertext allocation must return");
            assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
            assert_eq!(crate::fs::exact_allocation_failure_state(), (0, 1));
            assert_eq!(seal.write_seq, before);
            let ciphertext = seal.seal(&input).unwrap();
            assert_eq!(seal.write_seq, before + 1);
            assert_eq!(ciphertext, secretbox::seal(&input, &cipher_nonce(before + 1), &Key(keys.send)));
            assert_eq!(secretbox::open(&ciphertext, &cipher_nonce(before + 1), &Key(keys.send)).unwrap(), input);
            println!("CIPHER_SEAL_ALLOCATION_CASE=pass bytes={size} nonce=preserved retry=exact wire=unchanged");
        }
        seal.write_seq = u64::MAX;
        for _ in 0..2 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| seal.seal(b"exhausted")));
            assert!(result.is_ok(), "nonce exhaustion must return an error");
            assert_eq!(result.unwrap().unwrap_err().kind(), std::io::ErrorKind::Other);
            assert_eq!(seal.write_seq, u64::MAX);
        }
        println!("CIPHER_SEAL_ALLOCATION=pass cases=3 refusals=3 nonce=preserved retries=exact wire=unchanged exhaustion=refused");
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
/// start is not advanced per failure (see `record_handshake_failure`), so at most
/// `MAX_GUESSES_PER_WINDOW` confirmation failures per `GUESS_WINDOW` per source IP are allowed
/// (R-S10), with a ~2x worst case straddling a boundary. That is immaterial: the CPace password is
/// the real gate (one online guess per attempt, nothing offline-crackable); this is only DoS-safe
/// rate-limiting, fail-cheap before the scalar-mult (R-P14c) — defence-in-depth, not the auth.
const GUESS_WINDOW: Duration = Duration::from_secs(60);
/// Confirmation failures allowed from one source within a window before it is shed.
const MAX_GUESSES_PER_WINDOW: u32 = 10;
/// R-S10(b): a HARD ceiling on the number of distinct source IPs tracked, backstopping the
/// time-eviction in `record_handshake_failure` — so even a flood of distinct sources within one window
/// (each must complete a PAKE and fail R-P3 to be recorded here, and v4-only per R-D5 bounds the
/// keyspace) cannot grow the map without bound. 8192 is ample for any real DMZ; over it, the
/// oldest-window entries are evicted first — those past GUESS_WINDOW are already un-blocked
/// (guess_limiter_allows lets them through), so eviction never weakens the live rate-limit.
const MAX_TRACKED_SOURCES: usize = 8192;

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

/// Account for a failed handshake and report whether it was an online password
/// guess. This is the only public mutation edge for the limiter: accepting the
/// typed [`HandshakeError`] here makes the R-P14c rule structural, so a caller
/// cannot accidentally charge malformed input, timeout, EOF, or any other
/// non-confirmation abort against the owner's source address.
pub fn record_handshake_failure(source: IpAddr, error: HandshakeError) -> bool {
    if !error.is_password_guess() {
        return false;
    }

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
    // R-S10(b): a hard entry-count ceiling backstops the time-eviction — under a distinct-source
    // flood, evict the single oldest-window entry (closest to lapsing; any past GUESS_WINDOW is
    // already un-blocked) whenever an insert pushes the map over the cap. An O(n) min-scan, not a
    // sort, so even at-cap each failure stays cheap (and a failure already cost the attacker a full
    // PAKE). Runs only when over cap, so normal operation is untouched.
    while map.len() > MAX_TRACKED_SOURCES {
        let oldest = map
            .iter()
            .min_by_key(|(_, &(_, start))| start)
            .map(|(ip, _)| *ip);
        match oldest {
            Some(ip) => {
                map.remove(&ip);
            }
            None => break,
        }
    }
    true
}

/// Test-support introspection (R-S10(b)): how many source IPs the online-guess limiter currently
/// tracks. Exposed (not cfg(test) — `cpace_it` is a separate crate) so the cap test can assert the
/// MAX_TRACKED_SOURCES ceiling holds; benign in production (a count, leaks no source identity).
#[doc(hidden)]
pub fn guess_limiter_tracked_count() -> usize {
    GUESS_FAILURES.lock().unwrap().len()
}

// The wire-level round-trip / adversarial tests live in the dedicated `cpace_it`
// crate (libs/cpace_it): hbb_common's own test build links the `webrtc` dev-
// dependency, whose `sdp` crate does not compile on the pinned 1.75 toolchain, so
// an in-crate `#[cfg(test)]` here could not run. `cpace_it` depends only on
// hbb_common's library (no dev-deps ⇒ no webrtc) and exercises the public API
// (`run_initiator`/`run_responder`/`DirectionalCipher`) over a loopback socket.
