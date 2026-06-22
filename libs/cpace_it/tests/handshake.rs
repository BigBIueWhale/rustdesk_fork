//! Wire-level integration tests for the CPace choke-point handshake (R-P14):
//! two real `FramedStream`s over a loopback TCP socket (127.0.0.1 only — never
//! 0.0.0.0) drive [`run_initiator`]/[`run_responder`] to completion, then the
//! two-key [`DirectionalCipher`] is exercised in both directions. Adversarial
//! cases cover the wrong-password (R-P3/R-P14c) and out-of-order (R-P14a) aborts.

use hbb_common::bytes::Bytes;
use hbb_common::cpace::{run_initiator, run_responder, DirectionalCipher, HandshakeError};
use hbb_common::message_proto::{cpace::Union as CpaceUnion, Cpace, CpaceStep1, CpaceStep3};
use hbb_common::tcp::FramedStream;
use tokio::net::{TcpListener, TcpStream};

/// Extract the error without requiring the `Ok` type to be `Debug` (the
/// handshake's success type, `DirectionalKeys`, deliberately is not — it carries
/// secret keys, so `unwrap_err` is unavailable).
fn err_of<T>(r: Result<T, HandshakeError>) -> HandshakeError {
    match r {
        Ok(_) => panic!("expected a handshake error, got Ok"),
        Err(e) => e,
    }
}

/// A connected pair of FramedStreams over loopback TCP (127.0.0.1, ephemeral
/// port). Dropping one end closes the socket, freeing the peer's bounded read.
async fn loopback_pair() -> (FramedStream, FramedStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let client = client.unwrap();
    let (server, _) = accepted.unwrap();
    (
        FramedStream::from(client, addr),
        FramedStream::from(server, addr),
    )
}

#[tokio::test]
async fn handshake_round_trip_and_two_key_cipher() {
    let (mut si, mut sr) = loopback_pair().await;
    let pw = "correct horse battery staple";
    let (ri, rr) = tokio::join!(run_initiator(&mut si, pw), run_responder(&mut sr, pw));
    let ki = ri.expect("initiator derives keys");
    let kr = rr.expect("responder derives keys");

    // Mirrored slots (R-P2): initiator.send == responder.recv, and vice versa.
    assert_eq!(ki.send, kr.recv);
    assert_eq!(ki.recv, kr.send);
    // Per-direction keys actually differ (R-P10) — single-key reuse is impossible.
    assert_ne!(ki.send, ki.recv);

    // The two-key cipher round-trips in both directions.
    let mut ci = DirectionalCipher::new(&ki);
    let mut cr = DirectionalCipher::new(&kr);
    let ct = ci.seal(b"hello from the viewer");
    assert_eq!(cr.open(&ct).unwrap(), b"hello from the viewer");
    let ct2 = cr.seal(b"hello from the controlled host");
    assert_eq!(ci.open(&ct2).unwrap(), b"hello from the controlled host");

    // R-P10: a frame sealed under the send key must NOT open under the same side's
    // recv key. Collapsing to one key (the inherited bug) would make this succeed.
    let mut sealer = DirectionalCipher::new(&ki); // seals under ki.send
    let outbound = sealer.seal(b"probe");
    let mut self_recv = DirectionalCipher::new(&ki); // opens under ki.recv
    assert!(self_recv.open(&outbound).is_err());
}

#[tokio::test]
async fn matching_password_streams_can_exchange_after_keying() {
    let (mut si, mut sr) = loopback_pair().await;
    let pw = "s3cret-äöü"; // non-ASCII PRS exercises the NFC path (R-A10)
    let (ri, rr) = tokio::join!(run_initiator(&mut si, pw), run_responder(&mut sr, pw));
    let mut ci = DirectionalCipher::new(&ri.expect("initiator keys"));
    let mut cr = DirectionalCipher::new(&rr.expect("responder keys"));
    // Several frames each direction: nonces advance independently, no reuse.
    for i in 0..4u8 {
        let msg = vec![i; 100];
        assert_eq!(cr.open(&ci.seal(&msg)).unwrap(), msg);
        let reply = vec![i.wrapping_add(1); 64];
        assert_eq!(ci.open(&cr.seal(&reply)).unwrap(), reply);
    }
}

#[tokio::test]
async fn framed_stream_encrypts_after_session_keys_installed() {
    let (mut si, mut sr) = loopback_pair().await;
    let pw = "stream-key-test";
    let (ri, rr) = tokio::join!(run_initiator(&mut si, pw), run_responder(&mut sr, pw));
    // Engage the two-key cipher on each FramedStream — the choke-point keying call
    // that the cutover will make after a confirmed handshake.
    si.set_session_keys(ri.expect("initiator keys"));
    sr.set_session_keys(rr.expect("responder keys"));
    assert!(si.is_secured() && sr.is_secured());

    // An application frame now travels encrypted and decrypts on the peer, in both
    // directions (each uses the mirrored per-direction key, R-P2/R-P10).
    si.send_raw(b"keyed application payload".to_vec()).await.unwrap();
    let got = sr.next().await.unwrap().unwrap();
    assert_eq!(&got[..], b"keyed application payload");
    sr.send_raw(b"reply from the controlled host".to_vec()).await.unwrap();
    let got2 = si.next().await.unwrap().unwrap();
    assert_eq!(&got2[..], b"reply from the controlled host");
}

#[tokio::test]
async fn responder_many_frames_decrypt_in_strict_fifo_order() {
    // R-T8 / R-P2 / R-P10 — and the regression harness the §20 R-T3 writer-task refactor MUST keep
    // green: on the keyed responder->initiator stream every frame is sealed with k_s2c, advancing
    // write_seq by one; the initiator opens with k_s2c, advancing read_seq. Send N distinct frames
    // back-to-back and assert each arrives in the EXACT order sent and decrypts. A nonce-sequencing
    // regression — or a future writer-task that reorders, drops, or double-seals a frame — desyncs
    // write_seq/read_seq and fails the AEAD here.
    let (mut si, mut sr) = loopback_pair().await;
    let pw = "fifo-order-pw";
    let (ri, rr) = tokio::join!(run_initiator(&mut si, pw), run_responder(&mut sr, pw));
    si.set_session_keys(ri.expect("initiator keys"));
    sr.set_session_keys(rr.expect("responder keys"));
    const N: usize = 100; // ~3 KB framed: fits the loopback socket buffer, so no reader is needed mid-send
    for i in 0..N {
        sr.send_raw(format!("frame-{i:05}").into_bytes()).await.unwrap();
    }
    for i in 0..N {
        let got = si.next().await.expect("frame present").expect("frame decrypts");
        assert_eq!(
            &got[..],
            format!("frame-{i:05}").as_bytes(),
            "frame {i} arrived out of order or corrupt — a write_seq/read_seq desync"
        );
    }
}

/// R-T5 (§20): a `FramedStream::next()` that LOSES a `select!` race (a competing always-ready
/// branch wins, so the read branch is not taken) MUST NOT advance the recv counter or consume
/// bytes — the cancellation-safety the decrypt-in-codec (`SecretboxCodec`) makes structural by
/// advancing `read_seq` only inside `decode`, atomically with reassembly. We put a complete keyed
/// frame on the wire (so data genuinely IS available at the receiver), then repeatedly drive
/// `next()` under a `biased` select whose first branch is always ready, asserting `recv_counter()`
/// is unchanged each round; finally a real read still delivers the frame intact and advances the
/// counter EXACTLY once — proving the dropped reads neither consumed the bytes nor desynced the
/// recv nonce. A regression that advanced `read_seq` outside the delivered-frame path (or consumed
/// the buffer on a dropped poll) fails here: the final frame would be lost or decrypt-fail.
#[tokio::test]
async fn r_t5_dropped_next_does_not_advance_read_seq() {
    let (mut si, mut sr) = loopback_pair().await;
    let pw = "cancel-safety-test";
    let (ri, rr) = tokio::join!(run_initiator(&mut si, pw), run_responder(&mut sr, pw));
    si.set_session_keys(ri.expect("initiator keys"));
    sr.set_session_keys(rr.expect("responder keys"));

    // Put a complete keyed frame on the wire toward `sr`, and let it arrive so the read branch
    // genuinely COULD complete were it ever polled to completion.
    si.send_raw(b"frame-that-must-survive-a-dropped-read".to_vec())
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert_eq!(sr.recv_counter(), 0, "no frame consumed before any read");
    for _ in 0..8 {
        let before = sr.recv_counter();
        tokio::select! {
            biased;
            _ = std::future::ready(()) => {}
            _ = sr.next() => panic!("R-T5: the read branch must not be taken"),
        }
        assert_eq!(
            sr.recv_counter(),
            before,
            "R-T5: a dropped next() advanced read_seq — cancellation-safety violated"
        );
    }

    // A real read still delivers the frame intact and advances the counter exactly once.
    let got = sr.next().await.unwrap().unwrap();
    assert_eq!(&got[..], b"frame-that-must-survive-a-dropped-read");
    assert_eq!(sr.recv_counter(), 1, "exactly one frame consumed after the dropped reads");
}

/// R-S7: the handshake caps frames at 4 KiB pre-PAKE (the only attacker-reachable
/// parser before keying), then RAISES the cap to the session ceiling on success.
/// A 100 KiB frame — far over the pre-auth cap — therefore flows only because
/// keying raised it; if the reset were missing the receiver's decode would reject
/// it as "Too big packet". This pins the post-key half of the frame-cap control.
#[tokio::test]
async fn r_s7_large_frame_flows_only_after_keying_raises_the_cap() {
    let (mut si, mut sr) = loopback_pair().await;
    let pw = "frame-cap-test";
    let (ri, rr) = tokio::join!(run_initiator(&mut si, pw), run_responder(&mut sr, pw));
    si.set_session_keys(ri.expect("initiator keys"));
    sr.set_session_keys(rr.expect("responder keys"));

    let big = vec![0xABu8; 100 * 1024]; // 100 KiB ≫ the 4 KiB pre-auth cap
    si.send_raw(big.clone()).await.unwrap();
    let got = sr.next().await.unwrap().unwrap();
    assert_eq!(got.len(), big.len());
    assert_eq!(&got[..], &big[..]);
}

#[tokio::test]
async fn responder_rejects_oversize_pre_pake_frame() {
    // R-S7 / R-P14b (R-A10 wire-choreography negative): BEFORE keying the frame cap is
    // 4 KiB (MAX_CPACE_PACKET=4096). An unauthenticated peer that sends a LARGER first
    // frame is rejected at the cap (HandshakeError::Io) — the box refuses to allocate or
    // buffer an oversize pre-auth frame, a memory-exhaustion guard against a peer that has
    // not yet proven the password. This is the pre-key twin of
    // `r_s7_large_frame_flows_only_after_keying_raises_the_cap` (which proves the post-key
    // raise to 32 MiB for real video keyframes); together they pin BOTH sides of the cap.
    let (mut si, sr) = loopback_pair().await;
    let jr = tokio::spawn(async move {
        let mut sr = sr;
        run_responder(&mut sr, "frame-cap-pw").await
    });
    // The attacker raises ITS OWN cap (a hostile client emits whatever size it likes) and
    // blasts a 5 KiB raw frame on the still-UNKEYED stream — not even a valid CPace step.
    // Encode is uncapped on the wire; the responder's 4 KiB DECODE cap is what must reject,
    // at the length prefix, before any body allocation.
    si.set_max_packet_length(64 * 1024);
    si.send_raw(vec![0x5au8; 5 * 1024]).await.ok(); // 5 KiB > the 4 KiB pre-PAKE cap
    assert_eq!(
        err_of(jr.await.unwrap()),
        HandshakeError::Io,
        "R-S7/R-P14b: an oversize (>4 KiB) pre-PAKE frame must abort at the cap, never buffer"
    );
}

#[tokio::test]
async fn wrong_password_aborts_at_confirmation() {
    let (si, sr) = loopback_pair().await;
    // Spawn so the responder's abort drops its stream and frees the initiator
    // (EOF) without waiting out the 18 s per-step timeout.
    let jr = tokio::spawn(async move {
        let mut sr = sr;
        run_responder(&mut sr, "the-right-password").await
    });
    let ji = tokio::spawn(async move {
        let mut si = si;
        run_initiator(&mut si, "a-different-password").await
    });
    // The responder verifies Ta first → the sole online-guess event (R-P14c).
    assert_eq!(err_of(jr.await.unwrap()), HandshakeError::Confirmation);
    assert!(ji.await.unwrap().is_err(), "initiator also fails closed");
}

#[test]
fn guess_limiter_blocks_after_threshold() {
    // R-S10 / R-P14c: a source is shed after too many online-guess (confirmation)
    // failures within the window; other sources are unaffected (a per-IP block,
    // not a global one — so a flood from one IP can't lock everyone out).
    use hbb_common::cpace::{guess_limiter_allows, record_guess_failure};
    use std::net::IpAddr;
    let ip: IpAddr = "198.51.100.7".parse().unwrap(); // TEST-NET-2, unique to this test
    let other: IpAddr = "198.51.100.8".parse().unwrap();
    assert!(guess_limiter_allows(ip), "a fresh source is allowed");
    for _ in 0..10 {
        record_guess_failure(ip);
    }
    assert!(!guess_limiter_allows(ip), "blocked after 10 online-guess failures");
    assert!(
        guess_limiter_allows(other),
        "a different source is independent (R-P14c)"
    );
}

#[test]
fn directional_cipher_refuses_identical_keys() {
    // R-A5: the secretbox layer must refuse to engage a single shared key in
    // both directions (the inherited catastrophic reuse). A real handshake never
    // produces this — HKDF's c2s/s2c labels differ — but a keying-mis-wire
    // regression must fail closed.
    let same = pake::DirectionalKeys {
        send: [0x42; 32],
        recv: [0x42; 32],
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = DirectionalCipher::new(&same);
    }));
    assert!(result.is_err(), "R-A5: identical send/recv keys must abort");
}

#[tokio::test]
async fn responder_rejects_out_of_order_first_frame() {
    let (si, sr) = loopback_pair().await;
    let jr = tokio::spawn(async move {
        let mut sr = sr;
        run_responder(&mut sr, "pw").await
    });
    let mut si = si;
    // Send step ③ as the very first frame, skipping ① (R-P14a violation). Built
    // directly from the public proto types.
    let bogus = Cpace {
        union: Some(CpaceUnion::Step3(CpaceStep3 {
            ya: Bytes::copy_from_slice(&[7u8; 32]),
            ta: Bytes::copy_from_slice(&[9u8; 64]),
            ..Default::default()
        })),
        ..Default::default()
    };
    si.send(&bogus).await.unwrap();
    assert_eq!(err_of(jr.await.unwrap()), HandshakeError::Protocol);
    drop(si);
}

/// R-P14a / R-A10: each handshake step is consumed EXACTLY ONCE. After the responder consumes step ①
/// (deriving sid_b/g/yb and moving to WAIT_3, having replied step ②), a SECOND ① MUST abort as a
/// wrong variant for the state — never be re-processed (which would re-derive sid_b / reset the
/// machine and re-open the half-open/duplicate surface). This is the R-A10 "duplicated step (two ①
/// frames)" negative, DISTINCT from the out-of-order case above (a future step before its prerequisite).
#[tokio::test]
async fn responder_rejects_duplicate_first_frame() {
    let (si, sr) = loopback_pair().await;
    let jr = tokio::spawn(async move {
        let mut sr = sr;
        run_responder(&mut sr, "pw").await
    });
    let mut si = si;
    let step1 = Cpace {
        union: Some(CpaceUnion::Step1(CpaceStep1 {
            sid_a: Bytes::copy_from_slice(&[1u8; 16]),
            ad_a: Bytes::copy_from_slice(b"viewer"),
            ..Default::default()
        })),
        ..Default::default()
    };
    // The first ① is valid: the responder consumes it, replies step ② (which sits unread in si's
    // buffer), and waits for step ③. The second ① arrives in WAIT_3 — a duplicate/wrong variant.
    si.send(&step1).await.unwrap();
    si.send(&step1).await.unwrap();
    assert_eq!(err_of(jr.await.unwrap()), HandshakeError::Protocol);
    drop(si);
}

/// DoS-robustness (unauthenticated, pre-key): every fixed-size handshake field is length-validated via
/// cpace.rs's `exact::<N>` (which returns HandshakeError::Protocol on a length mismatch) BEFORE any
/// `copy_from_slice` into the fixed `sid`/`ya`/`yb`/`ta`/`tb` arrays — so a malformed-LENGTH field on
/// the UNAUTHENTICATED wire is REFUSED, never panicking the responder task. Without `exact::<N>`, a
/// `sid[..16].copy_from_slice(&sid_a)` with `sid_a.len() != 16` would PANIC (Transcript::from_steps) —
/// an unauthenticated panic-DoS any peer could trigger pre-key. The other rejection tests all send
/// VALID-length fields, so this is the only guard on the length-validator itself. The no-panic property
/// is asserted by `jr.await.unwrap()` succeeding (a panic would surface as a JoinError, failing it).
#[tokio::test]
async fn responder_rejects_malformed_length_field() {
    let (si, sr) = loopback_pair().await;
    let jr = tokio::spawn(async move {
        let mut sr = sr;
        run_responder(&mut sr, "pw").await
    });
    let mut si = si;
    // step ① with a 15-byte sid_a (NOT the required 16): exact::<16> MUST reject it before the
    // copy_from_slice into sid[..16] that would otherwise panic the task.
    let step1 = Cpace {
        union: Some(CpaceUnion::Step1(CpaceStep1 {
            sid_a: Bytes::copy_from_slice(&[1u8; 15]),
            ad_a: Bytes::copy_from_slice(b"viewer"),
            ..Default::default()
        })),
        ..Default::default()
    };
    si.send(&step1).await.unwrap();
    assert_eq!(err_of(jr.await.unwrap()), HandshakeError::Protocol);
    drop(si);
}

/// R-S17: the responder's HostIdentity host-proof binds the box's Ed25519 public
/// key to THIS PAKE session. Both sides reconstruct the same transcript; the box
/// signs `DSI ‖ sid ‖ CI ‖ Ya ‖ Yb`; the viewer verifies it and recovers pk for
/// its pin compare. A different-session signature, a tampered frame, and garbage
/// all fail closed — so the proof cannot be relayed/replayed and a substitute
/// that knows the password but not the private key is caught.
#[tokio::test]
async fn r_s17_host_proof_binds_pk_to_the_session() {
    use hbb_common::cpace::{
        build_host_identity, run_initiator_with_transcript, run_responder_with_transcript,
        verify_host_identity, Transcript,
    };
    let (mut si, mut sr) = loopback_pair().await;
    let pw = "host-proof-pw";
    let (ri, rr) = tokio::join!(
        run_initiator_with_transcript(&mut si, pw),
        run_responder_with_transcript(&mut sr, pw)
    );
    let (_ki, ti) = ri.expect("initiator keys+transcript");
    let (_kr, tr) = rr.expect("responder keys+transcript");
    // Both sides reconstruct the SAME transcript (sid/Ya/Yb).
    assert_eq!(ti, tr);

    // The box (responder) signs with its Ed25519 keypair; the viewer (initiator)
    // verifies against its own transcript and recovers pk.
    let (pk, sk) = hbb_common::sodiumoxide::crypto::sign::gen_keypair();
    let frame = build_host_identity(&tr, &pk.0, &sk.0).expect("build host-proof");
    let recovered = verify_host_identity(&ti, &frame).expect("verify host-proof");
    assert_eq!(recovered, pk.0.to_vec());

    // Negative — a signature welded to a DIFFERENT session (mutated sid) fails.
    let other = Transcript {
        sid: [0x5a; 32],
        ya: ti.ya,
        yb: ti.yb,
    };
    assert!(verify_host_identity(&other, &frame).is_err());

    // Negative — a tampered frame (flip a byte in the trailing signature) fails.
    let mut bad = frame.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(verify_host_identity(&ti, &bad).is_err());

    // Negative — garbage fails closed rather than panicking.
    assert!(verify_host_identity(&ti, b"not a HostIdentity frame").is_err());
}

/// R-S17 WIRE PATH: the responder emits its HostIdentity host-proof as the FIRST
/// frame AFTER keying, so it travels ENCRYPTED under the session key; the viewer
/// reads it with the same key and verifies. This exercises the exact transit
/// `Client::key_initiator` (client.rs) and the responder choke point (server.rs)
/// use — `set_session_keys` then `send_raw` on the box, `next` on the viewer —
/// proving `send_raw`/`next` round-trip the frame encrypted end-to-end, not just
/// the in-memory build/verify of the test above. A keyed viewer that could not
/// decrypt the box's proof would fail closed on EVERY legit connect (a silent
/// correctness break that the in-memory test cannot catch).
#[tokio::test]
async fn r_s17_host_proof_travels_encrypted_over_the_keyed_channel() {
    use hbb_common::cpace::{
        build_host_identity, run_initiator_with_transcript, run_responder_with_transcript,
        verify_host_identity,
    };
    let (mut si, mut sr) = loopback_pair().await;
    let pw = "wire-path-pw";
    let (ri, rr) = tokio::join!(
        run_initiator_with_transcript(&mut si, pw),
        run_responder_with_transcript(&mut sr, pw)
    );
    let (ki, ti) = ri.expect("initiator keys+transcript");
    let (kr, tr) = rr.expect("responder keys+transcript");

    // Engage the session keys on BOTH ends, exactly as the choke points do.
    si.set_session_keys(ki);
    sr.set_session_keys(kr);

    // The box signs with its Ed25519 keypair and sends the proof as the first
    // post-key frame (encrypted by the session key via send_raw).
    let (pk, sk) = hbb_common::sodiumoxide::crypto::sign::gen_keypair();
    let frame = build_host_identity(&tr, &pk.0, &sk.0).expect("build host-proof");
    sr.send_raw(frame).await.expect("responder sends host-proof");

    // The viewer reads + DECRYPTS it with the same key and recovers pk for its pin.
    let bytes = si
        .next()
        .await
        .expect("a frame arrives")
        .expect("it decrypts cleanly under the session key");
    let recovered = verify_host_identity(&ti, &bytes).expect("verify host-proof");
    assert_eq!(recovered, pk.0.to_vec());
}
