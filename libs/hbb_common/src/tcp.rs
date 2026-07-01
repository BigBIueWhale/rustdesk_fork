use crate::{
    bail,
    bytes_codec::BytesCodec,
    config::Socks5Server,
    cpace::{split_session_keys, DirectionalKeys, OpenCipher, SealCipher},
    proxy::Proxy,
    ResultType,
};
use anyhow::Context as AnyhowCtx;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use protobuf::Message;
use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{lookup_host, TcpListener, TcpSocket, ToSocketAddrs},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_socks::IntoTargetAddr;
use tokio_util::codec::{Decoder, Encoder, Framed};

pub trait TcpStreamTrait: AsyncRead + AsyncWrite + Unpin {}
pub struct DynTcpStream(pub Box<dyn TcpStreamTrait + Send + Sync>);

/// R-T5/R-T7 (§20): the length codec with the recv-side AEAD FOLDED IN — the structural form of the
/// reassemble → authenticate → parse order on the read half.
///
/// `decode` reassembles exactly ONE complete frame (the stateful `Head`/`Data(n)` machine of the
/// inner [`BytesCodec`]) and THEN, in the same synchronous call with **no `.await` between**,
/// authenticates + decrypts it under the recv key (advancing `read_seq` inside the [`OpenCipher`]).
/// Because the counter lives in this `Framed`-owned codec and the decrypt is part of the value
/// `StreamExt::next` atomically yields, a dropped `next()` (a `select!`/`timeout` losing the race)
/// consumes zero bytes and never advances `read_seq` — inheriting tokio-util's documented
/// cancel-safety verbatim, *structurally* rather than by the incidental ordering of an external
/// decrypt step. A partial frame returns `Ok(None)` (buffered, no counter advance), so a dropped
/// poll never half-consumes.
///
/// R-T3 (§20): `encode` is the inverse-asymmetric half — it ONLY length-frames, it does NOT seal.
/// The send-side seal (advancing `write_seq`) happens on the single-producer enqueue side
/// ([`FramedStream::send_bytes`]) so the nonce advances in exact channel-FIFO order, and the
/// dedicated writer task (the sole sink consumer, R-T8) feeds already-sealed frames here to be
/// length-framed only. Seal order == channel order == wire order.
pub struct SecretboxCodec {
    inner: BytesCodec,
    /// The recv-direction cipher (R-T3): present once keyed, used by `decode` only. The send
    /// direction's [`SealCipher`] lives on the producer side ([`FramedStream`]), never in the codec.
    open_cipher: Option<OpenCipher>,
}

impl SecretboxCodec {
    pub(crate) fn new() -> Self {
        Self {
            inner: BytesCodec::new(),
            open_cipher: None,
        }
    }
    #[inline]
    fn set_raw(&mut self) {
        self.inner.set_raw();
    }
    #[inline]
    fn set_max_packet_length(&mut self, n: usize) {
        self.inner.set_max_packet_length(n);
    }

    fn max_packet_length(&self) -> usize {
        self.inner.max_packet_length()
    }
}

impl Decoder for SecretboxCodec {
    type Item = BytesMut;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, Error> {
        // (1) reassemble exactly ONE complete frame; a partial frame buffers as Ok(None) with no
        // counter advance, so a dropped poll never half-consumes.
        match self.inner.decode(src)? {
            Some(mut frame) => {
                // (2) authenticate + decrypt the WHOLE frame, advancing read_seq INSIDE decode.
                // R-T7 (§20): authenticate EVERY frame on the keyed stream — there is no ≤1-byte
                // passthrough. A genuine sealed frame is always >= MACBYTES (16 bytes: seal appends
                // a 16-byte tag even to a 0-byte plaintext), so any shorter frame cannot be a valid
                // ciphertext and MUST fail closed at the AEAD — closing the one path by which a byte
                // could reach the application parser unauthenticated (also the worst-case carryover
                // channel for R-T6). `secretbox::open` rejects len < MACBYTES, so a tiny injected
                // frame is a clean decryption error.
                if let Some(open) = self.open_cipher.as_mut() {
                    match open.open(&frame) {
                        Ok(plain) => {
                            frame.clear();
                            frame.put_slice(&plain);
                        }
                        Err(()) => return Err(Error::new(ErrorKind::Other, "decryption error")),
                    }
                }
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<Bytes> for SecretboxCodec {
    type Error = Error;

    fn encode(&mut self, data: Bytes, dst: &mut BytesMut) -> Result<(), Error> {
        // R-T3: length-frame ONLY — the producer (`FramedStream::send_bytes`) already sealed the
        // bytes under the send key before enqueuing them to the writer task. Pre-key, `data` is a
        // raw handshake frame; post-key, it is sealed ciphertext. Either way the codec just frames.
        self.inner.encode(data, dst)
    }
}

/// A length-delimited, optionally-keyed TCP message stream.
///
/// # Single-writer contract (R-T8 / R-T3, §20)
///
/// **Each `FramedStream` has exactly one writer.** Two concurrent writers would
/// byte-interleave their encoded frames on the wire — a permanent framing desync,
/// and on a keyed stream garbage ciphertext that fails every subsequent Poly1305
/// tag. The invariant is kept *structural*, not conventional, so a refactor cannot
/// silently break it:
///
/// * every write method (`send`/`send_raw`/`send_bytes`) takes `&mut self`, so the
///   borrow checker alone forbids two simultaneous writers;
/// * the type owns its socket through a `Box<dyn>` (`DynTcpStream`) and is
///   deliberately **not** `Clone` — there is no way to obtain a second owner;
/// * the ONLY `.split()` is the R-T3 keying transition (`set_session_keys`): it
///   splits the `Framed` into the read half (kept here) and a write half moved into
///   a SINGLE dedicated writer task — the sole sink consumer — so the split yields
///   one reader + one writer, never two writers; the stream is **never** wrapped in
///   `Arc<Mutex<_>>` for writing.
///
/// The fork's many output producers (video / audio / clipboard / camera / the
/// connection-manager) therefore do **not** hold the stream; each holds a *clone of
/// an `mpsc` sender*, and the single run-loop task that owns the `FramedStream`
/// enqueues into the writer channel (non-blocking). `seal` advances the write
/// counter on that single-producer enqueue side (R-T3), and the lone writer task
/// drains the channel in FIFO order, so seal order = channel order = wire order (the
/// nonce never races). A second writable handle must remain a compile-visible error,
/// never a silent wire corruption — `scripts/verify.sh` gates that the only
/// `.split()` is the R-T3 writer-task one and that no `Arc<Mutex<FramedStream>>`
/// write-wrapper exists.
///
/// # Framing + processing-order contract (R-T16 / R-T5 / R-T7, §20)
///
/// TCP is a boundary-less byte stream, so message delimitation is a property of
/// *this framing*, never of TCP segmentation or any "accidental packetization":
/// every message carries an explicit self-describing length prefix (a variable
/// 1–4 byte header — low 2 bits select the width, the remaining 30 bits carry the
/// payload length; see `bytes_codec.rs`) decoded by a **stateful `Head`/`Data(n)`
/// `Decoder`** driven across reads by tokio-util's `Framed` loop. A partial frame
/// returns `Ok(None)` and is buffered; coalesced frames are each emitted; a frame
/// split across arbitrarily many segments — even one byte at a time, even with the
/// header split — is reassembled correctly. The `Framed` (with its partial-frame
/// buffer) is **retained across reads, never reconstructed**.
///
/// The processing order in [`FramedStream::next`] is **normative and exactly**:
/// (1) *reassemble* — `self.0.next()` yields exactly ONE complete frame; (2)
/// *authenticate + decrypt* — `key.dec` (R-T7) opens the WHOLE frame's AEAD,
/// advancing the recv counter only on a frame actually delivered (R-T5); (3)
/// *parse* — the protobuf decoder (`connection.rs`) sees ONLY the decrypted,
/// authenticated plaintext. No validation, decryption, or application parse ever
/// runs on a partial frame or a raw TCP segment, and no `.await` sits between a
/// frame leaving the read buffer and the secretbox `open`. The frame-length cap
/// (`max_packet_length`, R-S7) and the speculative-allocation cap
/// (`MAX_PREALLOCATED_PAYLOAD_LEN`, decoupled from the declared length) are
/// enforced at the framing layer *before* reassembly completes, so an
/// attacker-advertised huge length is rejected — and its allocation bounded —
/// before any payload is buffered.
///
/// The drop-safety this relies on — that dropping a `next()` read future (a `select!`/`timeout`
/// losing the race) consumes zero bytes and so cannot desync the recv nonce — is a documented
/// cross-backend property of the pinned reactor (mio 1.0.3 / tokio 1.44.2), not folklore; the
/// citation and the "never hand-roll an overlapped read" rule live at the read site in
/// [`FramedStream::next`] (R-T14).
///
/// # Field layout
/// `state` the keying-state machine — pre-key holds the whole [`Framed`]; post-key (R-T3) holds the
/// read half ([`SplitStream`]) plus the send-side [`SealCipher`] and the bounded channel to the
/// dedicated writer task · `local_addr` peer addr · `poison` flag (R-T2).
pub struct FramedStream {
    state: StreamState,
    local_addr: SocketAddr,
    // R-T2 (§20): the poison flag. Set on ANY send/recv error so the stream can never be
    // reused after a failure. On a keyed stream `seal` pre-increments the write nonce before
    // the bytes are flushed; if a future edit kept looping after a send error and reused the
    // stream, the next send would re-flush stale buffered ciphertext under an already-advanced
    // nonce, permanently desyncing the c2s direction. Poisoning makes "a send/recv error is
    // fatal-to-the-connection" a structural invariant rather than a per-call-site convention —
    // `send_bytes`/`next` short-circuit to an error / EOF once it is set.
    poison: bool,
}

/// The keying-state machine of a [`FramedStream`] (R-T3, §20).
enum StreamState {
    /// Pre-key: the whole [`Framed`] on one task — the CPace handshake reads and writes it
    /// sequentially (request/response), so no split is needed yet.
    Unkeyed(Framed<DynTcpStream, SecretboxCodec>),
    /// Post-key: the read half stays on the owning task (decode + recv-AEAD, R-T5-cancel-safe); the
    /// write half is owned by a dedicated writer task fed already-sealed frames over a bounded
    /// channel (R-T3/R-T8 single-writer).
    Keyed(KeyedStream),
    /// A transient placeholder held ONLY across the synchronous body of
    /// [`FramedStream::set_session_keys`] while the [`Framed`] is moved out to be split.
    /// `set_session_keys` is not `async`, so no other method can ever observe this — they treat it
    /// as `unreachable!()`.
    Keying,
}

/// The post-key half of a [`FramedStream`] (R-T3).
struct KeyedStream {
    /// The read half — decode + recv-AEAD happen here (R-T5 cancel-safe).
    read: SplitStream<Framed<DynTcpStream, SecretboxCodec>>,
    /// The send-side cipher (R-T3): `send_bytes` seals on this single-producer enqueue side so the
    /// nonce advances in exact channel-FIFO order.
    seal: SealCipher,
    /// Bounded channel of ALREADY-SEALED frames to the sole writer task (R-T8). A full channel is
    /// the back-pressure liveness signal — `send_bytes` drops the connection rather than block.
    writer_tx: mpsc::Sender<WriterCommand>,
    /// A handle to the codec's recv counter, so `recv_counter` can read `read_seq` after the codec
    /// is moved into `read` (the `SplitStream` exposes no codec accessor).
    read_seq: Arc<AtomicU64>,
    /// The dedicated writer task — aborted on drop so a write blocked on a dead socket cannot leak.
    writer: JoinHandle<()>,
}

/// Commands consumed by the sole R-T3 writer task.
///
/// `Frame` carries an already-sealed frame. `Drain` is the R-T9 close-path
/// acknowledgement: once the writer observes it, every prior frame in channel
/// FIFO order has been handed to the sink and flushed, so the caller knows a
/// queued `CloseReason` was not immediately lost to `FramedStream::Drop`.
enum WriterCommand {
    Frame(Bytes),
    Drain(oneshot::Sender<io::Result<()>>),
}

impl Deref for DynTcpStream {
    type Target = Box<dyn TcpStreamTrait + Send + Sync>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DynTcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub(crate) fn new_socket(
    addr: std::net::SocketAddr,
    reuse: bool,
) -> Result<TcpSocket, std::io::Error> {
    let socket = match addr {
        std::net::SocketAddr::V4(..) => TcpSocket::new_v4()?,
        std::net::SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };
    if reuse {
        // windows has no reuse_port, but its reuse_address
        // almost equals to unix's reuse_port + reuse_address,
        // though may introduce nondeterministic behavior
        // illumos has no support for SO_REUSEPORT
        #[cfg(all(unix, not(target_os = "illumos")))]
        socket.set_reuseport(true).ok();
        socket.set_reuseaddr(true).ok();
    }
    socket.bind(addr)?;
    Ok(socket)
}

/// R-T11 (§20): the socket for the PUBLIC inbound listener (the direct-server port). Unlike
/// `new_socket`, it does NOT set `SO_REUSEPORT`: a single-instance service needs no kernel
/// load-balance group, and `SO_REUSEPORT` would let another same-uid (root) process silently
/// bind the same port and join the group, stealing a fraction of inbound connections — a local
/// connection-hijack invisible to R-A4's own-process `/proc/self/net` self-check, violating
/// R-D3's "no second listener of any kind". On Unix it keeps `SO_REUSEADDR` for a clean
/// restart; on Windows it OMITS `SO_REUSEADDR` (whose Windows semantics are "steal the port"),
/// so the listener bind is exclusive and cannot be hijacked. (A listening socket does not enter
/// TIME_WAIT — that is the active-close side of an established connection, on an ephemeral port —
/// so omitting `SO_REUSEADDR` on Windows does not impede rebinding the listener port on restart.)
pub(crate) fn new_listener_socket(addr: std::net::SocketAddr) -> Result<TcpSocket, std::io::Error> {
    let socket = match addr {
        std::net::SocketAddr::V4(..) => TcpSocket::new_v4()?,
        std::net::SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };
    // NEVER SO_REUSEPORT (no load-balance group). SO_REUSEADDR for clean restart on non-Windows
    // only — on Windows it is the bind-hijack enabler, so leave the listener bind exclusive there.
    #[cfg(not(windows))]
    socket.set_reuseaddr(true).ok();
    socket.bind(addr)?;
    Ok(socket)
}

impl FramedStream {
    pub async fn new<T: ToSocketAddrs + std::fmt::Display>(
        remote_addr: T,
        local_addr: Option<SocketAddr>,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        for remote_addr in lookup_host(&remote_addr).await? {
            let local = if let Some(addr) = local_addr {
                addr
            } else {
                crate::config::Config::get_any_listen_addr(remote_addr.is_ipv4())
            };
            if let Ok(socket) = new_socket(local, true) {
                if let Ok(Ok(stream)) =
                    super::timeout(ms_timeout, socket.connect(remote_addr)).await
                {
                    stream.set_nodelay(true).ok();
                    let addr = stream.local_addr()?;
                    return Ok(Self::from_parts(
                        Framed::new(DynTcpStream(Box::new(stream)), SecretboxCodec::new()),
                        addr,
                    ));
                }
            }
        }
        bail!(format!("Failed to connect to {remote_addr}"));
    }

    pub async fn connect<'t, T>(
        target: T,
        local_addr: Option<SocketAddr>,
        proxy_conf: &Socks5Server,
        ms_timeout: u64,
    ) -> ResultType<Self>
    where
        T: IntoTargetAddr<'t>,
    {
        let proxy = Proxy::from_conf(proxy_conf, Some(ms_timeout))?;
        proxy.connect::<T>(target, local_addr).await
    }

    /// Build an unkeyed stream from a framed socket (R-T2: fresh = not poisoned; the per-send
    /// timeout starts at 0/none). The single tuple-free constructor — `new`/`from` and the proxy
    /// connectors all funnel through here so the keying-state machine has one entry point.
    pub(crate) fn from_parts(
        framed: Framed<DynTcpStream, SecretboxCodec>,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            state: StreamState::Unkeyed(framed),
            local_addr,
            poison: false,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn from(stream: impl TcpStreamTrait + Send + Sync + 'static, addr: SocketAddr) -> Self {
        Self::from_parts(
            Framed::new(DynTcpStream(Box::new(stream)), SecretboxCodec::new()),
            addr,
        )
    }

    pub fn set_raw(&mut self) {
        // R-A3 / R-S5: a keyed session stream MUST NOT be downgraded to raw — stripping the engaged
        // secretbox would leak plaintext, and keeping it would break framing (raw mode cannot
        // delimit framed secretbox output). set_raw()'s historical caller was the port-forward/tunnel;
        // in this fork no live caller invokes it on a session stream (there is no `.set_raw()` call in
        // src/). This is a fail-closed guard (R-A3/R-R2b): even under full access (enable-tunnel=Y,
        // R-S16), a keyed stream reaching here is a bug — panic rather than downgrade.
        match &mut self.state {
            StreamState::Unkeyed(framed) => framed.codec_mut().set_raw(),
            StreamState::Keyed(_) => {
                panic!("R-A3: set_raw on a keyed session stream — refusing to downgrade")
            }
            StreamState::Keying => unreachable!("set_raw observed a mid-keying stream"),
        }
    }

    /// Cap the inbound frame length before the first byte is read. Used to bound the
    /// attacker-reachable pre-key parser to the small CPace handshake frames (R-S7 / R-P14b): an
    /// oversize frame then aborts fail-closed at the codec. Pre-key only — the cap is fixed at keying.
    pub fn set_max_packet_length(&mut self, n: usize) {
        match &mut self.state {
            StreamState::Unkeyed(framed) => framed.codec_mut().set_max_packet_length(n),
            StreamState::Keyed(_) => {
                panic!("R-S7: set_max_packet_length after keying — the cap is fixed at set_session_keys")
            }
            StreamState::Keying => {
                unreachable!("set_max_packet_length observed a mid-keying stream")
            }
        }
    }

    pub fn is_secured(&self) -> bool {
        matches!(self.state, StreamState::Keyed(_))
    }

    /// The recv counter (`read_seq`) of the engaged cipher, or 0 if unkeyed — exposed for the
    /// R-T5 cancellation-safety regression test (a dropped `next()` MUST NOT advance it).
    pub fn recv_counter(&self) -> u64 {
        match &self.state {
            StreamState::Keyed(k) => k.read_seq.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    #[inline]
    pub async fn send(&mut self, msg: &impl Message) -> ResultType<()> {
        self.send_raw(msg.write_to_bytes()?).await
    }

    #[inline]
    pub async fn send_raw(&mut self, msg: Vec<u8>) -> ResultType<()> {
        // The keyed path seals the plaintext on this single-producer side (R-T3) then enqueues it to
        // the writer task; the unkeyed (handshake) path frames it raw. `send_bytes` is the one choke.
        self.send_bytes(bytes::Bytes::from(msg)).await
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        // R-T2: a poisoned stream is never reused (a prior send/recv error was fatal).
        if self.poison {
            bail!("R-T2: refusing to send on a poisoned stream (a prior send/recv error)");
        }
        let r = self.send_bytes_raw(bytes).await;
        if r.is_err() {
            // R-T2: a send error (a write failure, or the R-T3 writer channel full/closed) is fatal
            // — poison so a later edit cannot reuse the stream and re-flush under an advanced nonce.
            self.poison = true;
        }
        r
    }

    #[inline]
    async fn send_bytes_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        match &mut self.state {
            StreamState::Unkeyed(framed) => {
                // Pre-key handshake: a direct framed send (raw — the codec only length-frames). The
                // handshake is request/response on one task and its steps are tiny, so a send never
                // blocks; once keyed, R-T3's bounded writer channel is what bounds back-pressure.
                framed.send(bytes).await?;
            }
            StreamState::Keyed(k) => {
                // R-T3 (§20): seal on THIS single-producer enqueue side so the nonce advances in
                // exact channel-FIFO order (R-T8: the writer task is the sole consumer, so flush
                // order == seal order == wire order), then enqueue NON-BLOCKING. A full bounded
                // channel is the back-pressure liveness signal (replacing R-T2's per-write timeout):
                // the peer can't drain, so the connection is dropped here (`try_send` Err →
                // `send_bytes` poisons) rather than the run-loop blocking inside a `select!` branch.
                let sealed = Bytes::from(k.seal.seal(&bytes));
                k.writer_tx
                    .try_send(WriterCommand::Frame(sealed))
                    .map_err(|e| match e {
                        mpsc::error::TrySendError::Full(_) => {
                            anyhow::anyhow!("R-T3: writer channel full — dropping the back-pressured connection")
                        }
                        mpsc::error::TrySendError::Closed(_) => {
                            anyhow::anyhow!("R-T3: writer task gone — connection is dead")
                        }
                    })?;
            }
            StreamState::Keying => unreachable!("send_bytes observed a mid-keying stream"),
        }
        Ok(())
    }

    /// R-T9 (§20): wait until the dedicated writer task has flushed all frames
    /// already queued before this call. The graceful-close path uses this
    /// immediately after sending `CloseReason`; without the acknowledgement,
    /// dropping `FramedStream` may abort the writer task before it ever writes the
    /// close frame.
    ///
    /// This is deliberately bounded. Normal traffic keeps using non-blocking
    /// `try_send` for frames; only shutdown/close asks the writer for an explicit
    /// drain acknowledgement, and a peer that is already back-pressured or dead is
    /// failed closed instead of stalling the session indefinitely.
    pub async fn flush_writer(&mut self) -> ResultType<()> {
        if self.poison {
            bail!("R-T2/R-T9: refusing to flush a poisoned stream");
        }
        let result = match &mut self.state {
            StreamState::Unkeyed(framed) => framed.flush().await.map_err(anyhow::Error::from),
            StreamState::Keyed(k) => {
                let (ack_tx, ack_rx) = oneshot::channel();
                let writer_tx = k.writer_tx.clone();
                let enqueue = tokio::time::timeout(
                    WRITER_DRAIN_TIMEOUT,
                    writer_tx.send(WriterCommand::Drain(ack_tx)),
                )
                .await
                .map_err(|_| anyhow::anyhow!("R-T9: timed out enqueueing writer drain"))?;
                enqueue.map_err(|_| anyhow::anyhow!("R-T9: writer task gone before drain"))?;

                tokio::time::timeout(WRITER_DRAIN_TIMEOUT, ack_rx)
                    .await
                    .map_err(|_| anyhow::anyhow!("R-T9: timed out waiting for writer drain"))?
                    .map_err(|_| anyhow::anyhow!("R-T9: writer task dropped drain ack"))?
                    .map_err(anyhow::Error::from)
            }
            StreamState::Keying => unreachable!("flush_writer observed a mid-keying stream"),
        };
        if result.is_err() {
            self.poison = true;
        }
        result
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        // R-T2: a poisoned stream behaves as EOF — never read again after a fatal error.
        if self.poison {
            return None;
        }
        // R-T5 (§20): reassembly AND decryption+`read_seq` advance happen atomically INSIDE the
        // codec's `decode` (see `SecretboxCodec`) — there is no `.await` between a frame leaving the
        // buffer and the AEAD `open`, so the recv counter advances only on a frame actually
        // delivered, and a decrypt/auth failure (R-T7) surfaces here as `Some(Err(_))`. Post-key the
        // read half is a `SplitStream` (R-T3) that forwards the same `Framed`-owned codec `decode`,
        // so this property is unchanged by the writer-task split.
        //
        // R-T14 (§20) — cross-backend cancellation-safety basis (the foundation R-T5 relies on):
        // dropping THIS read future (because `select!`/`timeout` chose another branch) consumes
        // ZERO bytes on epoll, kqueue, AND Windows IOCP alike, so a dropped read can never desync
        // the recv nonce. By construction of the pinned reactor (mio 1.0.3 / tokio 1.44.2): mio is
        // edge-triggered on every backend (epoll EPOLLET / kqueue EV_CLEAR / IOCP+AFD emulated),
        // but the actual byte transfer is a SYNCHRONOUS non-blocking std `recv` inside mio's
        // `do_io` on all of them — NO kernel-owned overlapped data buffer is ever in flight (the
        // Windows AFD path carries only an `AfdPollInfo` handle+mask; there is no `WSARecv` in
        // mio's TcpStream path), so dropping the future only unlinks a readiness waiter. This MUST
        // NOT be "fixed" with a hand-rolled overlapped / `WSARecv` read: that would reintroduce the
        // very per-OS hazard (a kernel buffer consuming bytes into a dropped future) this avoids.
        let res = match &mut self.state {
            StreamState::Unkeyed(framed) => framed.next().await,
            StreamState::Keyed(k) => k.read.next().await,
            StreamState::Keying => unreachable!("next observed a mid-keying stream"),
        };
        if matches!(res, Some(Err(_))) {
            // R-T2: a read / framing / decrypt-auth failure is fatal — poison the stream so it is
            // never reused (the decrypt now lives in the codec, so this one check covers both).
            self.poison = true;
        }
        res
    }

    #[inline]
    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<BytesMut, Error>> {
        if let Ok(res) = super::timeout(ms, self.next()).await {
            res
        } else {
            None
        }
    }

    /// Engage the CPace two-key per-direction cipher after a confirmed handshake (R-P2/R-P10), and
    /// restructure to the R-T3 writer-task transport. The keys are role-oriented (the caller's
    /// send/recv slots), so a single key can never end up engaged in both directions.
    ///
    /// This splits the `Framed`: the read half stays here (decode + recv-AEAD), and the write half
    /// is moved into a dedicated writer task (R-T3) that is the SOLE sink consumer (R-T8). It is a
    /// synchronous one-shot Unkeyed → Keyed transition; the transient `Keying` state it swaps in is
    /// never observed because no `.await` sits between the take and the re-set.
    pub fn set_session_keys(&mut self, keys: DirectionalKeys) {
        let mut framed = match std::mem::replace(&mut self.state, StreamState::Keying) {
            StreamState::Unkeyed(framed) => framed,
            _ => panic!("R-P2: set_session_keys on an already-keyed (or keying) stream"),
        };
        // R-A5: a keyed session stream MUST carry a BOUNDED frame cap before any keyed byte flows.
        // The handshake (cpace.rs) sets MAX_SESSION_PACKET before handing the keys here, so the cap
        // is never the BytesCodec `usize::MAX` default at this choke-point. Assert it fail-closed —
        // an unbounded keyed read would be a speculative-allocation DoS (R-S7), and the assertion is
        // what R-A5 mandates ("max_packet_length is set, not usize::MAX, on every connection").
        assert!(
            framed.codec().max_packet_length() != usize::MAX,
            "R-A5: keyed stream has an unbounded frame cap (usize::MAX) — the handshake must set MAX_SESSION_PACKET first"
        );
        // Split the keys into the producer's SealCipher + the read-codec's OpenCipher (R-T3); R-A5
        // distinctness is asserted inside split_session_keys.
        let (seal, open) = split_session_keys(&keys);
        let read_seq = open.read_seq_handle();
        // Engage the recv cipher in the codec for DECODE (the encode side stays raw — the producer
        // pre-seals), then split: the read half stays here, the write half feeds the writer task.
        framed.codec_mut().open_cipher = Some(open);
        let (sink, read) = framed.split();
        let (writer_tx, writer_rx) = mpsc::channel::<WriterCommand>(WRITER_CHANNEL_CAP);
        let writer = tokio::spawn(writer_task(sink, writer_rx));
        self.state = StreamState::Keyed(KeyedStream {
            read,
            seal,
            writer_tx,
            read_seq,
            writer,
        });
    }

    /// TEST-SUPPORT (R-A8/R-T7 runtime validation): garble the engaged SEND key so the next
    /// `send_bytes` produces a frame the peer's recv-AEAD MUST reject — simulating a forged/injected
    /// frame from a party without the matching key. Benign (corrupts only THIS stream's send
    /// direction; cannot leak plaintext or bypass auth). No-op pre-key. Sole caller: probe_client.
    pub fn corrupt_send_key_for_test(&mut self) {
        if let StreamState::Keyed(k) = &mut self.state {
            k.seal.corrupt_key_for_test();
        }
    }
}

/// R-T3 (§20): the bounded writer-channel capacity. The channel buffers already-sealed outbound
/// frames between the run-loop (producer, non-blocking enqueue) and the dedicated writer task (sole
/// consumer). It is sized for headroom against normal bursts while keeping a stuck/back-pressured
/// peer detectable: when it fills, `send_bytes` drops the connection rather than block the loop
/// (replacing R-T2's per-write timeout). Outbound frames are server-generated (their size bounded by
/// the encoder, not attacker-controlled), so the buffer is not an attacker-driven memory lever.
const WRITER_CHANNEL_CAP: usize = 512;
const WRITER_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// R-T3/R-T8 (§20): the dedicated writer task — the SOLE consumer of the split sink. It drains
/// already-sealed frames in channel-FIFO order (so flush order == seal order == wire order) and
/// writes each. A socket write error ends the task (the connection is dead); `send_bytes` then
/// observes the closed channel on its next enqueue and poisons the stream (R-T2).
async fn writer_task(
    mut sink: SplitSink<Framed<DynTcpStream, SecretboxCodec>, Bytes>,
    mut writer_rx: mpsc::Receiver<WriterCommand>,
) {
    while let Some(cmd) = writer_rx.recv().await {
        match cmd {
            WriterCommand::Frame(frame) => {
                if sink.send(frame).await.is_err() {
                    break;
                }
            }
            WriterCommand::Drain(done) => {
                let res = sink.flush().await;
                let failed = res.is_err();
                let _ = done.send(res);
                if failed {
                    break;
                }
            }
        }
    }
    // The channel closed (the FramedStream dropped) or a write failed — close the sink to flush and
    // shut the write half down cleanly (R-T9).
    let _ = sink.close().await;
}

impl Drop for FramedStream {
    fn drop(&mut self) {
        // R-T3: tear down the writer task so a write blocked on a dead/back-pressured socket cannot
        // leak the task (and its half of the split `Framed`, holding the socket open) past the
        // connection's lifetime. Dropping `writer_tx` also closes the channel, but an abort is
        // immediate even if the task is parked inside `sink.send`.
        if let StreamState::Keyed(k) = &self.state {
            k.writer.abort();
        }
    }
}

const DEFAULT_BACKLOG: u32 = 128;

pub async fn new_listener<T: ToSocketAddrs>(addr: T, reuse: bool) -> ResultType<TcpListener> {
    if !reuse {
        Ok(TcpListener::bind(addr).await?)
    } else {
        let addr = lookup_host(&addr)
            .await?
            .next()
            .context("could not resolve to any address")?;
        new_socket(addr, true)?
            .listen(DEFAULT_BACKLOG)
            .map_err(anyhow::Error::msg)
    }
}

pub async fn listen_any(port: u16) -> ResultType<TcpListener> {
    if let Ok(mut socket) = TcpSocket::new_v6() {
        #[cfg(unix)]
        {
            // illumos has no support for SO_REUSEPORT
            #[cfg(not(target_os = "illumos"))]
            socket.set_reuseport(true).ok();
            socket.set_reuseaddr(true).ok();
            use std::os::unix::io::{FromRawFd, IntoRawFd};
            let raw_fd = socket.into_raw_fd();
            let sock2 = unsafe { socket2::Socket::from_raw_fd(raw_fd) };
            sock2.set_only_v6(false).ok();
            socket = unsafe { TcpSocket::from_raw_fd(sock2.into_raw_fd()) };
        }
        #[cfg(windows)]
        {
            use std::os::windows::prelude::{FromRawSocket, IntoRawSocket};
            let raw_socket = socket.into_raw_socket();
            let sock2 = unsafe { socket2::Socket::from_raw_socket(raw_socket) };
            sock2.set_only_v6(false).ok();
            socket = unsafe { TcpSocket::from_raw_socket(sock2.into_raw_socket()) };
        }
        if socket
            .bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))
            .is_ok()
        {
            if let Ok(l) = socket.listen(DEFAULT_BACKLOG) {
                return Ok(l);
            }
        }
    }
    Ok(new_socket(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        true,
    )?
    .listen(DEFAULT_BACKLOG)?)
}

/// R-D5: bind the direct listener **v4-only**. This is exactly the v4 body of
/// `listen_any` (above) used unconditionally — `0.0.0.0:port`, no dual-stack v6
/// face — so IPv6 unreachability is a *property of the binary*, not of a host
/// sysctl or an `ip6tables` rule that can drift ("structural > config" applied
/// to address families). The fork's only inbound listener (the lifted
/// `direct_server`, R-D4) calls this; a v4-only box also retires the
/// connection.rs IPv6-prefix limiter (R-S10) as dead code by construction.
pub async fn listen_any_v4(port: u16) -> ResultType<TcpListener> {
    // R-T11: the public listener uses the REUSEPORT-free, hijack-resistant constructor.
    Ok(new_listener_socket(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port,
    ))?
    .listen(DEFAULT_BACKLOG)?)
}

impl Unpin for DynTcpStream {}

impl AsyncRead for DynTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

impl AsyncWrite for DynTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

impl<R: AsyncRead + AsyncWrite + Unpin> TcpStreamTrait for R {}
