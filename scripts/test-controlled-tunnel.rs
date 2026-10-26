//! Exact controlled relay and CM mailbox, with a native TCP target and observed socket writes.
//! The authenticated peer is a bounded frame-channel double; this does not exercise CPace.
use crate::{bail, ipc, log, ResultType};
use bytes::{Bytes, BytesMut};
use futures::{future::poll_fn, SinkExt, StreamExt};
use std::{io, pin::Pin, sync::Arc, task::{Context, Poll}};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{mpsc, Notify},
    time::{self, Duration, Instant, Interval},
};
use tokio_util::{codec::{BytesCodec, Framed}, sync::CancellationToken};

include!(env!("TUNNEL_INTERVAL_SOURCE"));

async fn timeout<F: std::future::Future>(ms: u64, future: F) -> Result<F::Output, time::error::Elapsed> {
    time::timeout(Duration::from_millis(ms), future).await
}

struct ObservedSocket {
    socket: TcpStream,
    blocked: Arc<Notify>,
}
impl AsyncRead for ObservedSocket {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}
impl AsyncWrite for ObservedSocket {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.socket).poll_write(cx, buf);
        if result.is_pending() { self.blocked.notify_one(); }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}
struct PeerStream {
    inbound: mpsc::Receiver<io::Result<BytesMut>>,
    outbound: mpsc::Sender<Bytes>,
}
impl PeerStream {
    async fn next(&mut self) -> Option<io::Result<BytesMut>> { self.inbound.recv().await }
    async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        self.outbound.try_send(bytes)?;
        Ok(())
    }
}
struct Connection {
    port_forward_socket: Option<Framed<ObservedSocket, BytesCodec>>,
    stream: PeerStream,
}
include!(env!("CONTROLLED_TUNNEL_SOURCE"));

struct Fixture {
    target: TcpStream,
    inbound: mpsc::Sender<io::Result<BytesMut>>,
    outbound: mpsc::Receiver<Bytes>,
    control: Option<crate::CmEgressSender>,
    cancellation: CancellationToken,
    blocked: Arc<Notify>,
    task: tokio::task::JoinHandle<ResultType<()>>,
}
impl Fixture {
    async fn new() -> Self {
        let listener = TcpSocket::new_v4().unwrap();
        listener.set_recv_buffer_size(64 * 1024).unwrap();
        listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = listener.listen(1).unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(4096).unwrap();
        let socket = socket.connect(listener.local_addr().unwrap()).await.unwrap();
        let (target, _) = listener.accept().await.unwrap();
        drop(listener);
        let blocked = Arc::new(Notify::new());
        let (inbound, input) = mpsc::channel(1);
        let (output, outbound) = mpsc::channel(32);
        let (control, mut receiver) = crate::cm_egress_channel();
        let mut connection = Connection {
            port_forward_socket: Some(Framed::new(ObservedSocket { socket, blocked: blocked.clone() }, BytesCodec::new())),
            stream: PeerStream { inbound: input, outbound: output },
        };
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        let task = tokio::spawn(async move { connection.try_port_forward_loop(&mut receiver, &cancel).await });
        Self { target, inbound, outbound, control: Some(control), cancellation, blocked, task }
    }
    async fn block_target(&mut self) -> Vec<u8> {
        let payload: Vec<u8> = (0..1024 * 1024).map(|n| (n % 251) as u8).collect();
        self.inbound.send(Ok(BytesMut::from(payload.as_slice()))).await.unwrap();
        timeout(5000, self.blocked.notified()).await.expect("native socket must report Pending");
        assert!(!self.task.is_finished());
        payload
    }
    async fn stop(mut self) -> (bool, String) {
        let completed = timeout(500, &mut self.task).await;
        let (timely, reason) = match completed {
            Ok(result) => (true, result.unwrap().unwrap_err().to_string()),
            Err(_) => {
                self.task.abort();
                assert!(self.task.await.unwrap_err().is_cancelled());
                (false, "deadline".to_owned())
            }
        };
        // The exact relay task has joined, including on a deliberately failing baseline.
        let mut remaining = Vec::new();
        timeout(5000, self.target.read_to_end(&mut remaining)).await.unwrap().unwrap();
        assert!(remaining.len() <= 1024 * 1024);
        assert!(self.inbound.is_closed());
        assert!(self.outbound.recv().await.is_none());
        (timely, reason)
    }
}

#[tokio::test]
async fn controlled_tunnel_close_interrupts_backpressured_target() {
    let mut passed = 0;
    for cause in ["shutdown", "close", "cm-error", "cm-eof", "cm-failure"] {
        let mut fixture = Fixture::new().await;
        fixture.block_target().await;
        let expected = match cause {
            "shutdown" => { fixture.cancellation.cancel(); "Server is shutting down" },
            "close" => { fixture.control.as_ref().unwrap().send(ipc::Data::Close).unwrap(); "Close requested from connection manager" },
            "cm-error" => { fixture.control.as_ref().unwrap().send(ipc::Data::CmErr("test CM error".into())).unwrap(); "test CM error" },
            "cm-eof" => { drop(fixture.control.take()); "Connection manager channel closed" },
            "cm-failure" => { fixture.control.as_ref().unwrap().fail(crate::CmEgressFailure::MessageCapacity).unwrap_err(); "connection-manager egress message-count capacity reached" },
            _ => unreachable!(),
        };
        let (timely, reason) = fixture.stop().await;
        let correct = timely && reason == expected;
        passed += usize::from(correct);
        println!("CONTROLLED_TUNNEL_STOP_CASE=observed cause={cause} blocked=native deadline_ms=500 timely={timely} joined=true correct={correct}");
    }
    assert_eq!(passed, 5);
    println!("CONTROLLED_TUNNEL_STOP=pass cases=5 blocked=native control=production deadline_ms=500 cleanup=joined peer=double");
}

#[tokio::test]
async fn controlled_tunnel_preserves_pending_write_and_healthy_relay() {
    let mut fixture = Fixture::new().await;
    let payload = fixture.block_target().await;
    fixture.control.as_ref().unwrap().send(ipc::Data::ChatMessage { text: "irrelevant to tunnel".into() }).unwrap();
    // Observe actual mailbox consumption before allowing the target to drain the pending write.
    let consumed = timeout(500, async {
        loop {
            if fixture.control.as_ref().unwrap().state.lock().unwrap().queue.is_empty() { break; }
            tokio::task::yield_now().await;
        }
    }).await.is_ok();
    let mut received = vec![0; payload.len()];
    timeout(5000, fixture.target.read_exact(&mut received)).await.unwrap().unwrap();
    assert_eq!(received, payload);
    fixture.target.write_all(b"target response").await.unwrap();
    let mut response = Vec::new();
    while response.len() < b"target response".len() {
        response.extend_from_slice(&timeout(5000, fixture.outbound.recv()).await.unwrap().unwrap());
    }
    assert_eq!(response, b"target response");
    fixture.inbound.send(Ok(BytesMut::from(&b"second request"[..]))).await.unwrap();
    let mut second = [0; 14];
    timeout(5000, fixture.target.read_exact(&mut second)).await.unwrap().unwrap();
    assert_eq!(&second, b"second request");
    fixture.cancellation.cancel();
    let (timely, reason) = fixture.stop().await;
    assert!(timely && reason == "Server is shutting down");
    assert!(consumed, "nonterminal CM event must be consumed during the blocked write");
    println!("CONTROLLED_TUNNEL_CONTINUE=pass pending_bytes=1048576 exact=true nonterminal=consumed directions=2 subsequent=usable cleanup=joined peer=double");
}
