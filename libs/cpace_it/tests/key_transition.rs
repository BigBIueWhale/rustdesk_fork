//! Transport key-transition coverage. Keys and the final unkeyed payload are controlled;
//! this does not execute the CPace handshake or an application message dispatcher.
use hbb_common::{
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    cpace::{split_session_keys, DirectionalKeys},
    tcp::FramedStream,
    tokio_util::codec::Encoder,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{atomic::{AtomicUsize, Ordering}, Arc},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(2), future).await.unwrap()
}

// Read an exact prefix from the real socket before exposing it to Framed. This makes
// read-ahead deterministic, independent of TCP segmentation and scheduler timing.
#[derive(Default)]
struct Observation {
    supplied: AtomicUsize,
    pending_reads: AtomicUsize,
    drops: AtomicUsize,
}

struct PrefetchedTcp {
    socket: TcpStream,
    prefix: Vec<u8>,
    observation: Arc<Observation>,
}

impl AsyncRead for PrefetchedTcp {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>)
        -> Poll<io::Result<()>>
    {
        let offset = self.observation.supplied.load(Ordering::Relaxed);
        if offset < self.prefix.len() {
            let count = (self.prefix.len() - offset).min(buf.remaining());
            buf.put_slice(&self.prefix[offset..offset + count]);
            self.observation.supplied.store(offset + count, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        } else {
            let result = Pin::new(&mut self.socket).poll_read(cx, buf);
            if result.is_pending() {
                self.observation.pending_reads.fetch_add(1, Ordering::Relaxed);
            }
            result
        }
    }
}

impl AsyncWrite for PrefetchedTcp {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8])
        -> Poll<io::Result<usize>>
    {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

impl Drop for PrefetchedTcp {
    fn drop(&mut self) {
        self.observation.drops.fetch_add(1, Ordering::Relaxed);
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut wire = BytesMut::new();
    BytesCodec::new().encode(Bytes::copy_from_slice(payload), &mut wire).unwrap();
    wire.to_vec()
}

fn encrypted_frames(payloads: &[&[u8]], reflected: bool) -> Vec<Vec<u8>> {
    let (mut seal, _) = split_session_keys(&DirectionalKeys {
        send: [if reflected { 0x21 } else { 0x32 }; 32],
        recv: [if reflected { 0x32 } else { 0x21 }; 32],
    });
    payloads.iter().map(|payload| frame(&seal.seal(payload).unwrap())).collect()
}

async fn transition(buffered: &[u8]) -> (TcpStream, FramedStream, Arc<Observation>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (mut peer, (mut socket, _)) = bounded(async {
        tokio::try_join!(TcpStream::connect(address), listener.accept())
    }).await.unwrap();
    drop(listener);
    let mut wire = frame(b"final unkeyed payload");
    wire.extend_from_slice(buffered);
    bounded(peer.write_all(&wire)).await.unwrap();
    let mut prefix = vec![0; wire.len()];
    bounded(socket.read_exact(&mut prefix)).await.unwrap();
    assert_eq!(prefix, wire);
    let observation = Arc::new(Observation::default());
    let io = PrefetchedTcp { socket, prefix, observation: observation.clone() };
    let mut stream = FramedStream::from(io, address);
    stream.set_max_packet_length(4_096);
    assert_eq!(&bounded(stream.next()).await.unwrap().unwrap()[..], b"final unkeyed payload");
    assert_eq!(observation.supplied.load(Ordering::Relaxed), wire.len(), "suffix must already be in Framed's buffer");
    assert_eq!(observation.pending_reads.load(Ordering::Relaxed), 0);
    assert_eq!(stream.recv_counter(), 0);
    stream.set_max_packet_length(256);
    stream.set_session_keys(DirectionalKeys { send: [0x21; 32], recv: [0x32; 32] });
    assert!(stream.is_secured());
    (peer, stream, observation)
}

async fn retire(mut peer: TcpStream, mut stream: FramedStream, observation: Arc<Observation>) {
    // A local oversize refusal joins the production writer on positive cases too.
    assert!(bounded(stream.send_bytes(Bytes::from(vec![0; 256]))).await.is_err());
    assert!(bounded(stream.next()).await.is_none());
    assert!(bounded(stream.send_bytes(Bytes::new())).await.is_err());
    drop(stream);
    assert_eq!(observation.drops.load(Ordering::Relaxed), 1, "both split I/O owners must already be gone");
    assert_eq!(bounded(peer.read(&mut [0; 1])).await.unwrap(), 0);
}

#[tokio::test]
async fn buffered_ciphertext_survives_key_transition_in_order() {
    let payloads = [b"".as_slice(), b"first authenticated payload", b"second authenticated payload"];
    let frames = encrypted_frames(&payloads, false);
    let (peer, mut stream, observation) = transition(&frames.concat()).await;
    for (index, payload) in payloads.iter().enumerate() {
        assert_eq!(&bounded(stream.next()).await.unwrap().unwrap()[..], *payload);
        assert_eq!(stream.recv_counter(), index as u64 + 1);
    }
    retire(peer, stream, observation).await;
}

#[tokio::test]
async fn partial_ciphertext_survives_key_transition_and_cancelled_read() {
    let payload = [0x6a; 80];
    let frames = encrypted_frames(&[&payload, b"following frame"], false);
    for split in [1, 2, 3, frames[0].len() / 2, frames[0].len() - 1] {
        let (mut peer, mut stream, observation) = transition(&frames[0][..split]).await;
        assert!(tokio::time::timeout(Duration::from_millis(20), stream.next()).await.is_err());
        assert!(observation.pending_reads.load(Ordering::Relaxed) > 0, "the native read must be polled before cancellation");
        assert_eq!(stream.recv_counter(), 0);
        bounded(peer.write_all(&frames[0][split..])).await.unwrap();
        bounded(peer.write_all(&frames[1])).await.unwrap();
        assert_eq!(&bounded(stream.next()).await.unwrap().unwrap()[..], &payload);
        assert_eq!(&bounded(stream.next()).await.unwrap().unwrap()[..], b"following frame");
        assert_eq!(stream.recv_counter(), 2);
        retire(peer, stream, observation).await;
    }
}

#[tokio::test]
async fn buffered_plaintext_is_refused_after_key_transition() {
    for length in [0, 1, 15, 16, 80] {
        let (peer, mut stream, observation) = transition(&frame(&vec![0x51; length])).await;
        let error = bounded(stream.next()).await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "decryption error");
        assert_eq!(stream.recv_counter(), 1);
        retire(peer, stream, observation).await;
    }
}

#[tokio::test]
async fn buffered_reflection_and_tampering_are_refused_after_key_transition() {
    let reflected = encrypted_frames(&[b"reflected"], true).remove(0);
    let mut tampered = encrypted_frames(&[b"tampered"], false).remove(0);
    *tampered.last_mut().unwrap() ^= 0x80;
    for frame in [reflected, tampered] {
        let (peer, mut stream, observation) = transition(&frame).await;
        let error = bounded(stream.next()).await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "decryption error");
        assert_eq!(stream.recv_counter(), 1);
        retire(peer, stream, observation).await;
    }
}

#[tokio::test]
async fn buffered_replay_cannot_release_a_later_valid_frame() {
    let frames = encrypted_frames(&[b"accepted", b"must not escape"], false);
    let (peer, mut stream, observation) = transition(&[frames[0].clone(), frames[0].clone(), frames[1].clone()].concat()).await;
    assert_eq!(&bounded(stream.next()).await.unwrap().unwrap()[..], b"accepted");
    assert_eq!(stream.recv_counter(), 1);
    assert_eq!(bounded(stream.next()).await.unwrap().unwrap_err().to_string(), "decryption error");
    assert_eq!(stream.recv_counter(), 2);
    assert!(bounded(stream.next()).await.is_none());
    retire(peer, stream, observation).await;
}

#[tokio::test]
async fn buffered_truncation_at_key_transition_is_terminal() {
    let frame = encrypted_frames(&[&[0x6a; 80]], false).remove(0);
    for split in [1, 2, 3, frame.len() / 2, frame.len() - 1] {
        let (mut peer, mut stream, observation) = transition(&frame[..split]).await;
        bounded(peer.shutdown()).await.unwrap();
        assert_eq!(bounded(stream.next()).await.unwrap().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(stream.recv_counter(), 0);
        retire(peer, stream, observation).await;
    }
}
