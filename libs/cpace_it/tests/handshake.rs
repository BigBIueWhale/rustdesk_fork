//! Wire-level integration tests for the CPace choke-point handshake (R-P14):
//! two real `FramedStream`s over a loopback TCP socket (127.0.0.1 only — never
//! 0.0.0.0) drive [`run_initiator`]/[`run_responder`] to completion, then the
//! two-key [`DirectionalCipher`] is exercised in both directions. Adversarial
//! cases cover the wrong-password (R-P3/R-P14c) and out-of-order (R-P14a) aborts.

use hbb_common::bytes::Bytes;
use hbb_common::cpace::{run_initiator, run_responder, DirectionalCipher, HandshakeError};
use hbb_common::message_proto::{cpace::Union as CpaceUnion, Cpace, CpaceStep3};
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
