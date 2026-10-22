use crate::{
    bail,
    bytes_codec::BytesCodec,
    cpace::{split_session_keys, DirectionalKeys, OpenCipher, SealCipher},
    ResultType,
};
use anyhow::Context as AnyhowCtx;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use protobuf::Message;
use std::{
    convert::TryFrom,
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf},
    net::{lookup_host, TcpListener, TcpSocket, ToSocketAddrs},
    sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore, TryAcquireError},
    task::JoinHandle,
};
use tokio_util::codec::{Decoder, Encoder, Framed, FramedParts, FramedWrite};

pub trait TcpStreamTrait: AsyncRead + AsyncWrite + Unpin {}
pub struct DynTcpStream(pub Box<dyn TcpStreamTrait + Send + Sync>);

/// R-T5/R-T7 (§20): the length codec with the recv-side AEAD FOLDED IN — the structural form of the
/// reassemble → authenticate → parse order on the read half.
///
/// `decode` reassembles exactly ONE complete frame (the stateful `Head`/`Data(n)` machine of the
/// inner [`BytesCodec`]) and THEN, in the same synchronous call with **no `.await` between**,
/// authenticates + decrypts it under the recv key (advancing `read_seq` inside the [`OpenCipher`]).
/// Because the counter lives in this `Framed`-owned codec and the decrypt is part of the value
/// `StreamExt::next` atomically yields, cancelling a pending `next()` preserves the partial frame
/// and never advances `read_seq`. Socket bytes may already have entered the retained buffer or
/// length-decoder state; dropping the borrowed future does not discard that state. A partial frame
/// returns `Ok(None)` without calling the cipher. A complete authentication failure is terminal.
///
/// `encode` length-frames the unkeyed handshake. After keying, the sole writer owns a separate
/// `BytesCodec` and output buffer; the producer seals before that writer length-frames its FIFO.
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
    fn set_max_packet_length(&mut self, n: usize) {
        self.inner.set_max_packet_length(n);
    }

    fn max_packet_length(&self) -> usize {
        self.inner.max_packet_length()
    }

    fn open_frame(&mut self, frame: Option<BytesMut>) -> Result<Option<BytesMut>, Error> {
        match frame {
            Some(mut frame) => {
                // Authenticate the whole frame before either decoder path can yield it.
                // R-T7 (§20): authenticate EVERY frame on the keyed stream — there is no ≤1-byte
                // passthrough. A genuine sealed frame is always >= MACBYTES (16 bytes: seal appends
                // a 16-byte tag even to a 0-byte plaintext), so any shorter frame cannot be a valid
                // ciphertext and MUST fail closed at the AEAD — closing the one path by which a byte
                // could reach the application parser unauthenticated (also the worst-case carryover
                // channel for R-T6). `secretbox::open` rejects len < MACBYTES, so a tiny injected
                // frame is a clean decryption error.
                if let Some(open) = self.open_cipher.as_mut() {
                    match open.open(&mut frame) {
                        Ok(()) => {}
                        Err(()) => return Err(Error::new(ErrorKind::Other, "decryption error")),
                    }
                }
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }
}

impl Decoder for SecretboxCodec {
    type Item = BytesMut;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, Error> {
        let frame = self.inner.decode(src)?;
        self.open_frame(frame)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, Error> {
        let frame = self.inner.decode_eof(src)?;
        self.open_frame(frame)
    }
}

impl Encoder<Bytes> for SecretboxCodec {
    type Error = Error;

    fn encode(&mut self, data: Bytes, dst: &mut BytesMut) -> Result<(), Error> {
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
/// * key installation splits the I/O into one `ReadHalf` and one `WriteHalf`. The retained
///   receive `Framed` cannot implement `Sink` because its I/O is read-only. A single dedicated
///   writer exclusively owns its `FramedWrite`, active reservation, FIFO and completion.
///
/// The fork's many output producers (video / audio / clipboard / camera / the
/// connection-manager) therefore do **not** hold the stream; each holds a *clone of
/// an `mpsc` sender*, and the single run-loop task that owns the `FramedStream`
/// enqueues into the writer channel (non-blocking). `seal` advances the write
/// counter on that single-producer enqueue side (R-T3), and the lone writer task
/// drains the channel in FIFO order, so seal order = channel order = wire order (the
/// nonce never races). No second writable stream handle is exposed.
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
/// The codec reassembles one complete ciphertext and synchronously authenticates/decrypts it
/// before `next` yields plaintext. The protobuf decoder (`connection.rs`) parses only that
/// authenticated plaintext. A partial frame does not invoke the cipher; a complete authentication
/// failure poisons the stream. No application parse runs on a partial frame, and no `.await` sits
/// between a frame leaving the read buffer and the secretbox `open`. The frame-length cap
/// (`max_packet_length`, R-S7) and the speculative-allocation cap
/// (`MAX_PREALLOCATED_PAYLOAD_LEN`, decoupled from the declared length) are
/// enforced at the framing layer *before* reassembly completes, so an
/// attacker-advertised huge length is rejected — and its allocation bounded —
/// before any payload is buffered.
///
/// The same `Framed` owner preserves partial input across cancelled pending reads; cancellation
/// does not imply that no socket bytes were read. The documented frame-preservation contract and
/// backend acceptance obligation are referenced at [`FramedStream::next`] (R-T14).
///
/// # Field layout
/// `state` the keying-state machine — pre-key holds the whole [`Framed`]; post-key (R-T3) holds the
/// read-only `Framed` plus the send-side [`SealCipher`], exact writer admission, and the
/// bounded channel to the dedicated writer task · `local_addr` peer addr · `poison` flag (R-T2).
///
/// Framing is the only transport mode. The public types and bounded setup remain available:
/// ```rust
/// use hbb_common::{bytes_codec::BytesCodec, stream::Stream, tcp::FramedStream};
/// fn setup(stream: &mut FramedStream, codec: &mut BytesCodec, wrapper: &Stream) {
///     stream.set_max_packet_length(4096);
///     codec.set_max_packet_length(4096);
///     let _ = wrapper.is_secured();
/// }
/// ```
/// A stream cannot select an unframed mode:
/// ```compile_fail
/// fn bypass(stream: &mut hbb_common::tcp::FramedStream) { stream.set_raw(); }
/// ```
/// Its wrapper cannot select one either:
/// ```compile_fail
/// fn bypass(stream: &mut hbb_common::stream::Stream) { stream.set_raw(); }
/// ```
/// The framing codec exposes no raw-mode switch:
/// ```compile_fail
/// fn bypass(codec: &mut hbb_common::bytes_codec::BytesCodec) { codec.set_raw(); }
/// ```
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
    read: Framed<ReadHalf<DynTcpStream>, SecretboxCodec>,
    /// The send-side cipher (R-T3): `send_bytes` seals on this single-producer enqueue side so the
    /// nonce advances in exact channel-FIFO order.
    seal: SealCipher,
    /// Bounded FIFO of already-sealed frames to the sole writer task (R-T8). R-T18's separate
    /// admission remains held after dequeue; either admission or channel refusal is fatal.
    writer_tx: mpsc::Sender<WriterCommand>,
    /// Nonblocking count-and-ciphertext admission held through the exact sink send (R-T18).
    writer_admission: WriterAdmission,
    /// A read-only handle to the counter owned by the retained receive codec.
    read_seq: Arc<AtomicU64>,
    /// The sole writer, retained until joined. Hard drop can only request cancellation.
    writer: Option<JoinHandle<()>>,
}

/// The sole writer's complete lifetime, including an in-flight command.
///
/// Fields drop in declaration order: encoded sink storage retires before active admission,
/// queued commands drop their bytes before their permits, and current completion retires last.
struct KeyedWriter {
    sink: FramedWrite<WriteHalf<DynTcpStream>, BytesCodec>,
    active: Option<WriterFrameReservation>,
    commands: mpsc::Receiver<WriterCommand>,
    completion: Option<oneshot::Sender<io::Result<()>>>,
}

/// Commands consumed by the sole R-T3 writer task.
///
/// `Frame` carries an already-sealed frame. `Drain` is the R-T9 close-path
/// acknowledgement: once the writer observes it, every prior frame in channel
/// FIFO order has been handed to the sink and flushed, so the caller knows a
/// queued `CloseReason` was not immediately lost to `FramedStream::Drop`.
enum WriterCommand {
    Frame {
        bytes: Bytes,
        reservation: WriterFrameReservation,
        completion: Option<oneshot::Sender<io::Result<()>>>,
    },
    Drain(oneshot::Sender<io::Result<()>>),
}

/// Exact retained-frame and ciphertext-byte ownership for one keyed writer command (R-T18).
///
/// Tokio's channel capacity is returned when the receiver dequeues a command, before the sink send
/// completes. These owned permits therefore travel with the command and remain held while the sole
/// writer is blocked in `sink.send`, so active plus queued retention has one exact finite owner.
struct WriterFrameReservation {
    _frame: OwnedSemaphorePermit,
    _ciphertext_bytes: OwnedSemaphorePermit,
    ciphertext_bytes: usize,
}

/// Shared nonblocking admission for the sole keyed writer producer and consumer (R-T18).
#[derive(Clone)]
struct WriterAdmission {
    frames: Arc<Semaphore>,
    ciphertext_bytes: Arc<Semaphore>,
    max_ciphertext_bytes: usize,
    max_retained_ciphertext_bytes: usize,
}

impl WriterAdmission {
    fn new(max_ciphertext_bytes: usize) -> Self {
        let mac_bytes = sodiumoxide::crypto::secretbox::MACBYTES;
        assert!(
            max_ciphertext_bytes >= mac_bytes,
            "R-T18: keyed packet ceiling cannot hold the secretbox authenticator"
        );
        assert!(
            max_ciphertext_bytes <= u32::MAX as usize,
            "R-T18: keyed packet ceiling is not representable by Tokio byte admission"
        );
        assert!(
            max_ciphertext_bytes
                <= Semaphore::MAX_PERMITS / WRITER_RETAINED_CIPHERTEXT_PACKETS,
            "R-T18: keyed writer retained-byte ceiling exceeds Tokio semaphore capacity"
        );
        let max_retained_ciphertext_bytes =
            max_ciphertext_bytes * WRITER_RETAINED_CIPHERTEXT_PACKETS;
        Self {
            frames: Arc::new(Semaphore::new(WRITER_CHANNEL_CAP)),
            ciphertext_bytes: Arc::new(Semaphore::new(max_retained_ciphertext_bytes)),
            max_ciphertext_bytes,
            max_retained_ciphertext_bytes,
        }
    }

    fn reserve_plaintext(&self, plaintext_bytes: usize) -> ResultType<WriterFrameReservation> {
        let ciphertext_bytes = plaintext_bytes
            .checked_add(sodiumoxide::crypto::secretbox::MACBYTES)
            .ok_or_else(|| anyhow::anyhow!("R-T18: outbound keyed frame size overflow"))?;
        self.reserve_ciphertext(ciphertext_bytes)
    }

    fn reserve_ciphertext(
        &self,
        ciphertext_bytes: usize,
    ) -> ResultType<WriterFrameReservation> {
        if ciphertext_bytes > self.max_ciphertext_bytes {
            bail!(
                "R-T18: outbound keyed frame exceeds the engaged packet ceiling ({} bytes; limit {})",
                ciphertext_bytes,
                self.max_ciphertext_bytes
            );
        }
        let permit_count = u32::try_from(ciphertext_bytes)
            .map_err(|_| anyhow::anyhow!("R-T18: outbound keyed frame size is not representable"))?;
        let frame = match Arc::clone(&self.frames).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                bail!(
                    "R-T18: keyed writer retained-frame capacity reached (limit {})",
                    WRITER_CHANNEL_CAP
                );
            }
            Err(TryAcquireError::Closed) => {
                bail!("R-T18: keyed writer admission is closed");
            }
        };
        let ciphertext = match Arc::clone(&self.ciphertext_bytes)
            .try_acquire_many_owned(permit_count)
        {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                bail!(
                    "R-T18: keyed writer retained-byte capacity reached (limit {} bytes)",
                    self.max_retained_ciphertext_bytes
                );
            }
            Err(TryAcquireError::Closed) => {
                bail!("R-T18: keyed writer admission is closed");
            }
        };
        Ok(WriterFrameReservation {
            _frame: frame,
            _ciphertext_bytes: ciphertext,
            ciphertext_bytes,
        })
    }

    fn close(&self) {
        self.frames.close();
        self.ciphertext_bytes.close();
    }
}

/// Exact completion of one frame handed to the sole post-key transport sink.
///
/// This is intentionally a one-shot receipt rather than a cloneable status channel: one caller
/// owns the decision that depends on this exact write. Cancellation means the writer retired
/// before it could report a result and must be treated as a failed connection, never as success.
pub type WriterReceipt = oneshot::Receiver<io::Result<()>>;

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
/// restart; on Windows it leaves `SO_REUSEADDR` unset and sets `SO_EXCLUSIVEADDRUSE` before bind,
/// so the listener bind is exclusive and cannot be hijacked. (A listening socket does not enter
/// TIME_WAIT — that is the active-close side of an established connection, on an ephemeral port —
/// so omitting `SO_REUSEADDR` on Windows does not impede rebinding the listener port on restart.)
pub(crate) fn new_listener_socket(addr: std::net::SocketAddr) -> Result<TcpSocket, std::io::Error> {
    let socket = match addr {
        std::net::SocketAddr::V4(..) => TcpSocket::new_v4()?,
        std::net::SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    #[cfg(windows)]
    set_exclusive_addr_use(&socket)?;
    socket.bind(addr)?;
    Ok(socket)
}

#[cfg(windows)]
fn set_exclusive_addr_use(socket: &TcpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use winapi::shared::ws2def::{SOL_SOCKET, SO_EXCLUSIVEADDRUSE};

    #[link(name = "Ws2_32")]
    extern "system" {
        fn setsockopt(
            socket: usize,
            level: i32,
            option_name: i32,
            option_value: *const i8,
            option_length: i32,
        ) -> i32;
    }

    let enabled: i32 = 1;
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl FramedStream {
    /// Connect one concrete socket address; name resolution belongs to the connector.
    pub async fn new(
        remote_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        let local = local_addr.unwrap_or_else(|| {
            crate::config::Config::get_any_listen_addr(remote_addr.is_ipv4())
        });
        let socket = new_socket(local, true)?;
        let stream = super::timeout(ms_timeout, socket.connect(remote_addr)).await??;
        stream.set_nodelay(true)?;
        let addr = stream.local_addr()?;
        Ok(Self::from_parts(
            Framed::new(DynTcpStream(Box::new(stream)), SecretboxCodec::new()),
            addr,
        ))
    }

    /// Build an unkeyed stream from a framed socket (R-T2: fresh = not poisoned; the per-send
    /// timeout starts at 0/none). Direct connects and accepted sockets both funnel through this
    /// single constructor, so the keying-state machine has one entry point.
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
        self.send_payload(
            || {
                usize::try_from(msg.compute_size())
                    .map_err(|_| anyhow::anyhow!("outbound protobuf size does not fit usize"))
            },
            || Ok(Bytes::from(msg.write_to_bytes()?)),
            None,
        )
        .await
    }

    #[inline]
    pub async fn send_raw(&mut self, msg: Vec<u8>) -> ResultType<()> {
        self.send_bytes(bytes::Bytes::from(msg)).await
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        let plaintext_bytes = bytes.len();
        self.send_payload(|| Ok(plaintext_bytes), || Ok(bytes), None)
            .await
    }

    /// Enqueue one frame and return exact writer completion ownership.
    ///
    /// Normal traffic needs only fail-fast bounded enqueue and uses [`Self::send_bytes`]. A
    /// real-time producer additionally needs to know when its exact frame has left the bounded
    /// writer queue so it does not mistake enqueue for downstream progress. The frame is still
    /// sealed on this single-producer side and remains in the same FIFO as every other frame; the
    /// receipt changes no nonce or ordering rule.
    #[inline]
    pub async fn send_with_receipt(&mut self, msg: &impl Message) -> ResultType<WriterReceipt> {
        let (completion, receipt) = oneshot::channel();
        self.send_payload(
            || {
                usize::try_from(msg.compute_size())
                    .map_err(|_| anyhow::anyhow!("outbound protobuf size does not fit usize"))
            },
            || Ok(Bytes::from(msg.write_to_bytes()?)),
            Some(completion),
        )
        .await?;
        Ok(receipt)
    }

    async fn send_payload(
        &mut self,
        measure: impl FnOnce() -> ResultType<usize>,
        encode: impl FnOnce() -> ResultType<Bytes>,
        completion: Option<oneshot::Sender<io::Result<()>>>,
    ) -> ResultType<()> {
        if self.poison {
            self.poison_and_retire_writer().await;
            bail!("R-T2: refusing to send on a poisoned stream (a prior send/recv error)");
        }

        let result: ResultType<()> = async {
            match &mut self.state {
                StreamState::Unkeyed(framed) => {
                    if completion.is_some() {
                        bail!("tracked writer completion requires a keyed stream");
                    }
                    framed.send(encode()?).await?;
                }
                StreamState::Keyed(k) => {
                    // Own channel capacity and retained bytes before encoding or advancing the nonce.
                    let slot = k.writer_tx.try_reserve().map_err(|e| match e {
                        mpsc::error::TrySendError::Full(_) => {
                            anyhow::anyhow!("R-T3: writer channel full — dropping the back-pressured connection")
                        }
                        mpsc::error::TrySendError::Closed(_) => {
                            anyhow::anyhow!("R-T3: writer task gone — connection is dead")
                        }
                    })?;
                    let plaintext_bytes = measure()?;
                    let reservation = k.writer_admission.reserve_plaintext(plaintext_bytes)?;
                    let bytes = encode()?;
                    if bytes.len() != plaintext_bytes {
                        bail!("R-T18: encoded plaintext length disagrees with declared size");
                    }
                    let sealed = Bytes::from(k.seal.seal(&bytes)?);
                    if sealed.len() != reservation.ciphertext_bytes {
                        bail!("R-T18: secretbox ciphertext length disagrees with reserved bytes");
                    }
                    slot.send(WriterCommand::Frame {
                        bytes: sealed,
                        reservation,
                        completion,
                    });
                }
                StreamState::Keying => unreachable!("send_payload observed a mid-keying stream"),
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            self.poison_and_retire_writer().await;
        }
        result
    }

    /// R-T9 (§20): wait until the dedicated writer task has flushed all frames
    /// already queued before this call. The graceful-close path uses this
    /// immediately after sending `CloseReason`; without the acknowledgement,
    /// dropping `FramedStream` may abort the writer task before it ever writes the
    /// close frame.
    ///
    /// Drain acknowledgement has a deadline. Failure closes admission and initiates cancellation;
    /// the exact writer remains owned until joined. Normal traffic reserves capacity without waiting.
    pub async fn flush_writer(&mut self) -> ResultType<()> {
        if self.poison {
            self.poison_and_retire_writer().await;
            bail!("R-T2/R-T9: refusing to flush a poisoned stream");
        }
        let result = match &mut self.state {
            StreamState::Unkeyed(framed) => framed.flush().await.map_err(anyhow::Error::from),
            StreamState::Keyed(k) => {
                // Contain `?` inside this local result so every keyed drain failure reaches the
                // common close-admission-before-abort transition below. Returning directly from
                // `flush_writer` here would leave the failed writer and its reservations alive.
                let keyed_result: ResultType<()> = async {
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
                .await;
                keyed_result
            }
            StreamState::Keying => unreachable!("flush_writer observed a mid-keying stream"),
        };
        if result.is_err() {
            self.poison_and_retire_writer().await;
        }
        result
    }

    /// Close admission and join the sole writer before reporting a fatal transport outcome.
    async fn poison_and_retire_writer(&mut self) {
        self.poison = true;
        if let StreamState::Keyed(k) = &mut self.state {
            k.writer_admission.close();
            if let Some(writer) = &mut k.writer {
                writer.abort();
                // Await the borrowed handle so cancellation retains exact join ownership here.
                let result = writer.await;
                k.writer = None;
                if let Err(error) = result {
                    if !error.is_cancelled() {
                        crate::log::error!("TCP writer retirement failed: {}", error);
                    }
                }
            }
        }
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        // R-T2: a poisoned stream behaves as EOF — never read again after a fatal error.
        if self.poison {
            self.poison_and_retire_writer().await;
            return None;
        }
        // R-T5 (§20): reassembly AND decryption+`read_seq` advance happen atomically INSIDE the
        // codec's `decode` (see `SecretboxCodec`) — there is no `.await` between a frame leaving the
        // buffer and the AEAD `open`. Partial frames and cancelled pending reads cannot advance
        // the counter; a complete decrypt/auth failure (R-T7) surfaces as `Some(Err(_))`. Post-key the
        // read-only Framed retains that exact decoder and input buffer, independently of output.
        //
        // R-T14: tokio-util's Framed documents next() as borrowing the stream and never losing a
        // value on cancellation. Its persistent owner may already hold partial socket input:
        // https://github.com/tokio-rs/tokio/blob/tokio-util-0.7.15/tokio-util/src/codec/framed.rs
        // Keep that owner and codec across reads. Backend changes, including a custom overlapped
        // read implementation, require renewed native cancellation/buffer-lifetime evidence.
        let res = match &mut self.state {
            StreamState::Unkeyed(framed) => framed.next().await,
            StreamState::Keyed(k) => {
                let result = tokio::select! {
                    biased;
                    _ = k.writer_tx.closed() => None,
                    result = k.read.next() => result,
                };
                // Closure is permanent and wins over a frame or EOF that became ready together.
                if k.writer_tx.is_closed() {
                    Some(Err(Error::new(ErrorKind::BrokenPipe, "TCP writer terminated")))
                } else {
                    result
                }
            }
            StreamState::Keying => unreachable!("next observed a mid-keying stream"),
        };
        if matches!(res, Some(Err(_))) {
            // R-T2: a read / framing / decrypt-auth failure is fatal — poison the stream so it is
            // never reused (the decrypt now lives in the codec, so this one check covers both).
            self.poison_and_retire_writer().await;
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
    /// The receive codec and buffered input stay here; the write I/O, framing codec and encoded
    /// buffer move to the sole writer task (R-T3/R-T8). It is a
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
        let writer_admission = WriterAdmission::new(framed.codec().max_packet_length());
        // Split the keys into the producer's SealCipher + the read-codec's OpenCipher (R-T3); R-A5
        // distinctness is asserted inside split_session_keys.
        let (seal, open) = split_session_keys(&keys);
        let read_seq = open.read_seq_handle();
        // Keep the exact receive codec and buffered input, but give encoded output its own owner.
        framed.codec_mut().open_cipher = Some(open);
        let backpressure_boundary = framed.backpressure_boundary();
        let parts = framed.into_parts();
        let writer_codec = parts.codec.inner;
        let (read_io, write_io) = tokio::io::split(parts.io);
        let mut read_parts = FramedParts::new(read_io, parts.codec);
        read_parts.read_buf = parts.read_buf;
        let read = Framed::from_parts(read_parts);
        let mut sink = FramedWrite::new(write_io, writer_codec);
        *sink.write_buffer_mut() = parts.write_buf;
        sink.set_backpressure_boundary(backpressure_boundary);
        let (writer_tx, writer_rx) = mpsc::channel::<WriterCommand>(WRITER_CHANNEL_CAP);
        let writer = tokio::spawn(writer_task(sink, writer_rx));
        self.state = StreamState::Keyed(KeyedStream {
            read,
            seal,
            writer_tx,
            writer_admission,
            read_seq,
            writer: Some(writer),
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

/// R-T3/R-T18 (§20): finite writer admission. The Tokio channel is the FIFO handoff, while the
/// separate frame permits remain held after dequeue so the active sink frame still counts toward
/// this 512-frame limit. Exact ciphertext permits cap active plus queued payload at two engaged
/// keyed packets. All admission is nonblocking; refusal retires the exact connection.
const WRITER_CHANNEL_CAP: usize = 512;
const WRITER_RETAINED_CIPHERTEXT_PACKETS: usize = 2;
const WRITER_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// R-T3/R-T8 (§20): the dedicated writer owns its framed output and is the SOLE sink consumer. It drains
/// already-sealed frames in channel-FIFO order (so flush order == seal order == wire order) and
/// writes each. A socket write error ends the task; the read owner and subsequent enqueues
/// observe its closed channel and poison the stream (R-T2).
async fn writer_task(
    sink: FramedWrite<WriteHalf<DynTcpStream>, BytesCodec>,
    writer_rx: mpsc::Receiver<WriterCommand>,
) {
    let mut writer = KeyedWriter {
        sink,
        active: None,
        commands: writer_rx,
        completion: None,
    };
    while let Some(cmd) = writer.commands.recv().await {
        let result = match cmd {
            WriterCommand::Frame {
                bytes,
                reservation,
                completion,
            } => {
                writer.active = Some(reservation);
                writer.completion = completion;
                writer.sink.send(bytes).await
            }
            WriterCommand::Drain(done) => {
                writer.completion = Some(done);
                writer.sink.flush().await
            }
        };
        let completion = writer.completion.take();
        if result.is_err() {
            // Retire encoded storage and every reservation before reporting the exact failure.
            drop(writer);
            if let Some(completion) = completion {
                let _ = completion.send(result);
            }
            return;
        }
        // SinkExt::send includes flush; its encoded payload is gone before admission returns.
        drop(writer.active.take());
        if let Some(completion) = completion {
            let _ = completion.send(result);
        }
    }
    // The channel closed after the last command; flush and shut down the write half (R-T9).
    if let Err(error) = writer.sink.close().await {
        crate::log::debug!("TCP writer shutdown failed: {}", error);
    }
}

impl Drop for FramedStream {
    fn drop(&mut self) {
        // Close admission before requesting cancellation. The task owns its encoded storage and
        // reservations together until cancellation is observed and its future is dropped.
        if let StreamState::Keyed(k) = &self.state {
            k.writer_admission.close();
            if let Some(writer) = &k.writer {
                writer.abort();
            }
        }
    }
}

const DEFAULT_BACKLOG: u32 = 128;

pub async fn new_exclusive_listener<T: ToSocketAddrs>(addr: T) -> ResultType<TcpListener> {
    let addr = lookup_host(&addr)
        .await?
        .next()
        .context("could not resolve exclusive listener address")?;
    Ok(new_listener_socket(addr)?.listen(DEFAULT_BACKLOG)?)
}

/// R-D5: bind the direct listener **v4-only** to `0.0.0.0:port`, with no dual-stack
/// face — so IPv6 unreachability is a *property of the binary*, not of a host
/// sysctl or an `ip6tables` rule that can drift ("structural > config" applied
/// to address families). The fork's only inbound listener (the lifted
/// `direct_server`, R-D4) calls this; a v4-only box also retires the
/// connection.rs IPv6-prefix limiter (R-S10) as dead code by construction.
pub async fn listen_any_v4(port: u16) -> ResultType<TcpListener> {
    // R-T11: the public listener uses the REUSEPORT-free, hijack-resistant constructor.
    Ok(
        new_listener_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))?
            .listen(DEFAULT_BACKLOG)?,
    )
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

#[cfg(test)]
async fn join_test_writer(
    stream: &mut FramedStream,
    abort: bool,
) -> Option<Result<(), tokio::task::JoinError>> {
    if let StreamState::Keyed(keyed) = &mut stream.state {
        if let Some(writer) = &mut keyed.writer {
            if abort {
                writer.abort();
            }
            let result = tokio::time::timeout(std::time::Duration::from_secs(2), writer)
                .await
                .unwrap();
            keyed.writer = None;
            return Some(result);
        }
    }
    None
}

#[cfg(test)]
mod eof_tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    async fn tcp_pair(keyed: bool) -> (tokio::net::TcpStream, FramedStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (peer, (incoming, _)) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept())
        })
        .await
        .unwrap()
        .unwrap();
        let mut stream = FramedStream::from(incoming, addr);
        stream.set_max_packet_length(1_024);
        if keyed {
            stream.set_session_keys(DirectionalKeys {
                send: [0x21; 32],
                recv: [0x32; 32],
            });
        }
        (peer, stream)
    }

    async fn join_writer(stream: &mut FramedStream, abort: bool) {
        if let Some(result) = join_test_writer(stream, abort).await {
            assert!(result.unwrap_err().is_cancelled());
        }
    }

    async fn assert_truncated_tcp_frames(keyed: bool) {
        for prefix in [b"\x04".as_slice(), b"\x10x", b"\x01"] {
            let (mut peer, mut stream) = tcp_pair(keyed).await;
            peer.write_all(prefix).await.unwrap();
            peer.shutdown().await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(2), stream.next())
                .await
                .unwrap();
            // Join the exact writer even when the pre-fix result is a clean EOF.
            join_writer(&mut stream, !matches!(result, Some(Err(_)))).await;
            let error = result
                .expect("a truncated TCP frame must report an error")
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
            assert_eq!(stream.recv_counter(), 0);
            assert!(stream.poison);
            if let StreamState::Keyed(keyed) = &stream.state {
                assert!(keyed.writer_admission.frames.is_closed());
                assert!(keyed.writer_admission.ciphertext_bytes.is_closed());
            }
            assert!(stream.next().await.is_none());
            assert!(stream.send_bytes(Bytes::new()).await.is_err());
        }
    }

    #[tokio::test]
    async fn unkeyed_tcp_truncation_is_fatal() {
        assert_truncated_tcp_frames(false).await;
    }

    #[tokio::test]
    async fn keyed_tcp_truncation_is_fatal() {
        assert_truncated_tcp_frames(true).await;
    }

    #[tokio::test]
    async fn tcp_complete_frames_finish_cleanly() {
        for keyed in [false, true] {
            let (mut peer, mut stream) = tcp_pair(keyed).await;
            let (mut seal, _) = split_session_keys(&DirectionalKeys {
                send: [0x32; 32],
                recv: [0x21; 32],
            });
            let mut wire = BytesMut::new();
            let mut codec = BytesCodec::new();
            for payload in [b"".as_slice(), b"complete", b""] {
                let data = if keyed {
                    seal.seal(payload).unwrap()
                } else {
                    payload.to_vec()
                };
                codec.encode(data.into(), &mut wire).unwrap();
            }
            peer.write_all(&wire).await.unwrap();
            peer.shutdown().await.unwrap();
            for payload in [b"".as_slice(), b"complete", b""] {
                let frame = tokio::time::timeout(Duration::from_secs(2), stream.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(&frame[..], payload);
            }
            assert!(stream.next().await.is_none());
            assert!(!stream.poison);
            assert_eq!(stream.recv_counter(), if keyed { 3 } else { 0 });
            join_writer(&mut stream, true).await;
        }
    }

    #[test]
    fn buffered_eof_frames_require_authentication() {
        let (mut seal, _) = split_session_keys(&DirectionalKeys {
            send: [0x32; 32],
            recv: [0x21; 32],
        });
        let (_, open) = split_session_keys(&DirectionalKeys {
            send: [0x21; 32],
            recv: [0x32; 32],
        });
        let mut codec = SecretboxCodec::new();
        codec.open_cipher = Some(open);
        let mut wire = BytesMut::new();
        for payload in [b"".as_slice(), b"authenticated"] {
            codec
                .inner
                .encode(seal.seal(payload).unwrap().into(), &mut wire)
                .unwrap();
        }
        for payload in [b"".as_slice(), b"authenticated"] {
            assert_eq!(&codec.decode_eof(&mut wire).unwrap().unwrap()[..], payload);
        }
        assert!(codec.decode_eof(&mut wire).unwrap().is_none());
        assert_eq!(codec.open_cipher.as_ref().unwrap().read_seq(), 2);

        codec
            .inner
            .encode(Bytes::from_static(b"forged"), &mut wire)
            .unwrap();
        let error = codec.decode_eof(&mut wire).unwrap_err();
        assert_eq!(error.to_string(), "decryption error");
    }
}

#[cfg(test)]
mod writer_lifetime_tests {
    use super::*;
    use std::{sync::atomic::{AtomicBool, AtomicUsize}, time::Duration};
    use tokio::io::AsyncWriteExt;

    #[derive(Default)]
    struct WriteObservation {
        written: AtomicUsize,
        pending_ptr: AtomicUsize,
        pending_len: AtomicUsize,
        failures: AtomicUsize,
        fail_writes: AtomicBool,
        reads_after_failure: AtomicUsize,
    }

    struct ObservedTcp {
        io: tokio::net::TcpStream,
        observation: Arc<WriteObservation>,
    }

    #[derive(Default)]
    struct ReadWake(AtomicUsize);

    impl std::task::Wake for ReadWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl AsyncRead for ObservedTcp {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.observation.failures.load(Ordering::Relaxed) != 0 {
                self.observation.reads_after_failure.fetch_add(1, Ordering::Relaxed);
            }
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ObservedTcp {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.observation.fail_writes.load(Ordering::Relaxed) {
                self.observation.failures.fetch_add(1, Ordering::Relaxed);
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionReset,
                    "injected TCP write failure",
                )));
            }
            let result = Pin::new(&mut self.io).poll_write(cx, buf);
            match &result {
                Poll::Pending => {
                    self.observation.pending_ptr.store(buf.as_ptr() as usize, Ordering::Relaxed);
                    self.observation.pending_len.store(buf.len(), Ordering::Relaxed);
                }
                Poll::Ready(Ok(n)) => {
                    self.observation.written.fetch_add(*n, Ordering::Relaxed);
                }
                Poll::Ready(Err(_)) => {
                    self.observation.failures.fetch_add(1, Ordering::Relaxed);
                }
            }
            result
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    struct BlockedWriter {
        stream: FramedStream,
        peer: tokio::net::TcpStream,
        observation: Arc<WriteObservation>,
        witness: Bytes,
        admission: WriterAdmission,
        receipt: WriterReceipt,
    }

    async fn blocked_writer() -> BlockedWriter {
        let listener = TcpSocket::new_v4().unwrap();
        listener.set_recv_buffer_size(4_096).unwrap();
        listener.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let listener = listener.listen(1).unwrap();
        let addr = listener.local_addr().unwrap();
        let outgoing = TcpSocket::new_v4().unwrap();
        outgoing.set_send_buffer_size(4_096).unwrap();
        let (outgoing, (mut peer, _)) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::try_join!(outgoing.connect(addr), listener.accept())
        })
        .await
        .unwrap()
        .unwrap();
        drop(listener);
        let observation = Arc::new(WriteObservation::default());
        let io = ObservedTcp { io: outgoing, observation: Arc::clone(&observation) };
        let mut framed = Framed::new(DynTcpStream(Box::new(io)), SecretboxCodec::new());
        let mut buffer = BytesMut::with_capacity(128 * 1_024);
        buffer.extend_from_slice(&[0, 0]);
        let witness = buffer.split_to(1).freeze();
        buffer.clear();
        let buffer_start = buffer.as_ptr() as usize;
        let buffer_end = buffer_start + buffer.capacity();
        assert!(!witness.is_unique());
        *framed.write_buffer_mut() = buffer;
        let mut stream = FramedStream::from_parts(framed, addr);
        stream.set_max_packet_length(128 * 1_024);
        stream.set_session_keys(DirectionalKeys { send: [0x19; 32], recv: [0x2a; 32] });
        assert!(!witness.is_unique(), "keying must preserve the seeded write buffer");
        let admission = match &stream.state {
            StreamState::Keyed(keyed) => keyed.writer_admission.clone(),
            _ => panic!("stream must be keyed"),
        };
        let mut screenshot = crate::message_proto::ScreenshotResponse::new();
        screenshot.data = vec![0x5a; 64 * 1_024].into();
        let mut message = crate::message_proto::Message::new();
        message.set_screenshot_response(screenshot);
        let receipt = stream.send_with_receipt(&message).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while observation.pending_len.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let pending_ptr = observation.pending_ptr.load(Ordering::Relaxed);
        let pending_len = observation.pending_len.load(Ordering::Relaxed);
        assert!(observation.written.load(Ordering::Relaxed) > 0);
        assert!(pending_ptr >= buffer_start && pending_ptr + pending_len <= buffer_end);
        assert_eq!(admission.frames.available_permits(), WRITER_CHANNEL_CAP - 1);
        assert!(!witness.is_unique());

        // A real incoming control frame must remain readable while the outgoing socket is blocked.
        let (mut seal, _) = split_session_keys(&DirectionalKeys {
            send: [0x2a; 32], recv: [0x19; 32],
        });
        let mut wire = BytesMut::new();
        BytesCodec::new().encode(seal.seal(b"control").unwrap().into(), &mut wire).unwrap();
        peer.write_all(&wire).await.unwrap();
        let control = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await.unwrap().unwrap().unwrap();
        assert_eq!(&control[..], b"control");
        assert_eq!(stream.recv_counter(), 1);
        BlockedWriter { stream, peer, observation, witness, admission, receipt }
    }

    async fn assert_encoded_storage_retires(reset: bool) {
        let BlockedWriter {
            mut stream, mut peer, observation, witness, admission, receipt,
        } = blocked_writer().await;
        if reset {
            peer.set_linger(Some(Duration::ZERO)).unwrap();
            drop(peer);
            assert!(tokio::time::timeout(Duration::from_secs(2), receipt)
                .await.unwrap().unwrap().is_err());
            if let Some(result) = join_test_writer(&mut stream, false).await {
                result.unwrap();
            }
            assert!(observation.failures.load(Ordering::Relaxed) > 0);
        } else {
            peer.write_all(&[4 << 2, 1, 2, 3, 4]).await.unwrap();
            assert!(tokio::time::timeout(Duration::from_secs(2), stream.next())
                .await.unwrap().unwrap().is_err());
            assert!(stream.poison);
            if let Some(result) = join_test_writer(&mut stream, false).await {
                assert!(result.unwrap_err().is_cancelled());
            }
            assert!(receipt.await.is_err());
            drop(peer);
        }
        let retired_after_join = witness.is_unique();
        assert_eq!(admission.frames.available_permits(), WRITER_CHANNEL_CAP);
        assert_eq!(admission.ciphertext_bytes.available_permits(), 256 * 1_024);
        drop(stream);
        assert!(witness.is_unique(), "dropping the stream must retire every buffer alias");
        println!(
            "WRITER_BUFFER_LIFETIME=observed case={} partial_write=true blocked=true control_read=true writer_joined=true permits_returned=true stream_buffer_retired={} owner_drop_control=true",
            if reset { "reset" } else { "cancel" }, retired_after_join,
        );
        assert!(retired_after_join, "the read owner retained the retired writer's encoded storage");
    }

    #[tokio::test]
    async fn tcp_failed_writer_retires_encoded_storage() {
        assert_encoded_storage_retires(true).await;
        let mut all_terminal = true;
        for pending in [false, true] {
            all_terminal &= assert_failed_writer_terminates_read(pending).await;
        }
        assert!(all_terminal, "a failed writer must terminate its retained read owner");
    }

    async fn assert_failed_writer_terminates_read(pending: bool) -> bool {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (outgoing, (mut peer, _)) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept())
        }).await.unwrap().unwrap();
        drop(listener);
        let observation = Arc::new(WriteObservation::default());
        let io = ObservedTcp { io: outgoing, observation: Arc::clone(&observation) };
        let mut stream = FramedStream::from(io, addr);
        stream.set_max_packet_length(1_024);
        stream.set_session_keys(DirectionalKeys { send: [0x19; 32], recv: [0x2a; 32] });
        let admission = match &stream.state {
            StreamState::Keyed(keyed) => keyed.writer_admission.clone(),
            _ => panic!("stream must be keyed"),
        };
        let (mut seal, _) = split_session_keys(&DirectionalKeys {
            send: [0x2a; 32], recv: [0x19; 32],
        });
        let mut wire = BytesMut::new();
        BytesCodec::new().encode(seal.seal(b"healthy").unwrap().into(), &mut wire).unwrap();
        peer.write_all(&wire).await.unwrap();
        let healthy = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await.unwrap().unwrap().unwrap();
        assert_eq!(&healthy[..], b"healthy");
        assert_eq!(stream.recv_counter(), 1);
        if !pending {
            wire.clear();
            BytesCodec::new().encode(seal.seal(b"after failure").unwrap().into(), &mut wire).unwrap();
            peer.write_all(&wire).await.unwrap();
        }
        observation.fail_writes.store(true, Ordering::Relaxed);
        let mut receipt = Some(stream.send_with_receipt(&crate::message_proto::Message::new())
            .await.unwrap());
        if !pending {
            let error = tokio::time::timeout(Duration::from_secs(2), receipt.take().unwrap())
                .await.unwrap().unwrap().unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ConnectionReset);
            assert!(matches!(&stream.state,
                StreamState::Keyed(keyed) if keyed.writer_tx.is_closed()));
        }
        let mut pending_woken = false;
        let result = {
            let mut read = Box::pin(stream.next());
            if pending {
                let wake = Arc::new(ReadWake::default());
                let waker = std::task::Waker::from(Arc::clone(&wake));
                {
                    let mut context = Context::from_waker(&waker);
                    assert!(std::future::Future::poll(read.as_mut(), &mut context).is_pending());
                }
                assert_eq!(observation.failures.load(Ordering::Relaxed), 0);
                assert_eq!(wake.0.load(Ordering::Relaxed), 0);
                let error = tokio::time::timeout(Duration::from_secs(2), receipt.take().unwrap())
                    .await.unwrap().unwrap().unwrap_err();
                assert_eq!(error.kind(), ErrorKind::ConnectionReset);
                pending_woken = wake.0.load(Ordering::Relaxed) != 0;
                // Observe the registered wake before a timer or another read poll can mask it.
                tokio::time::timeout(Duration::ZERO, read).await
            } else {
                tokio::time::timeout(Duration::from_millis(250), read).await
            }
        };
        if let Some(receipt) = receipt {
            let error = tokio::time::timeout(Duration::from_secs(2), receipt)
                .await.unwrap().unwrap().unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ConnectionReset);
        }
        assert_eq!(observation.failures.load(Ordering::Relaxed), 1);
        let terminal_error = matches!(&result,
            Ok(Some(Err(error))) if error.kind() == ErrorKind::BrokenPipe);
        let yielded = matches!(&result, Ok(Some(Ok(_))));
        let timed_out = result.is_err();
        let poisoned = stream.poison;
        let counter = stream.recv_counter();
        let reads_after_failure = observation.reads_after_failure.load(Ordering::Relaxed);
        let joined_at_return = matches!(&stream.state,
            StreamState::Keyed(keyed) if keyed.writer.is_none());
        if let Some(result) = join_test_writer(&mut stream, false).await {
            result.unwrap();
        }
        assert_eq!(admission.frames.available_permits(), WRITER_CHANNEL_CAP);
        assert_eq!(admission.ciphertext_bytes.available_permits(), 2_048);
        println!(
            "WRITER_FAILURE_READ=observed case={} healthy_control=true injected_write_failures=1 terminal_error={} yielded={} timed_out={} poisoned={} recv_counter={} reads_after_failure={} joined_at_return={} pending_woken={}",
            if pending { "pending" } else { "peer-frame" }, terminal_error, yielded,
            timed_out, poisoned, counter, reads_after_failure, joined_at_return, pending_woken,
        );
        let passed = terminal_error && !yielded && !timed_out && poisoned
            && counter == 1 && reads_after_failure == 0 && joined_at_return
            && (!pending || pending_woken);
        if passed {
            assert!(stream.next().await.is_none());
            assert!(stream.send_bytes(Bytes::new()).await.is_err());
            assert!(stream.flush_writer().await.is_err());
            assert!(admission.frames.is_closed() && admission.ciphertext_bytes.is_closed());
        }
        drop((stream, peer));
        passed
    }

    #[tokio::test]
    async fn tcp_cancelled_writer_retires_encoded_storage() {
        assert_encoded_storage_retires(false).await;
    }

    async fn observe_then_join(fixture: &mut BlockedWriter, kind: &str) -> bool {
        // Capture the public-return boundary before any test-side yield or cleanup.
        let writer_joined = matches!(&fixture.stream.state,
            StreamState::Keyed(keyed) if keyed.writer.is_none());
        let storage_retired = fixture.witness.is_unique();
        let permits_returned = fixture.admission.frames.available_permits() == WRITER_CHANNEL_CAP
            && fixture.admission.ciphertext_bytes.available_permits() == 256 * 1_024;
        let completion_retired = matches!(fixture.receipt.try_recv(),
            Err(oneshot::error::TryRecvError::Closed));
        println!(
            "WRITER_FATAL_RETURN=observed kind={} storage_retired={} permits_returned={} completion_retired={} writer_joined={}",
            kind, storage_retired, permits_returned, completion_retired, writer_joined,
        );
        if let Some(result) = join_test_writer(&mut fixture.stream, true).await {
            assert!(result.unwrap_err().is_cancelled());
        }
        assert!(fixture.witness.is_unique());
        assert_eq!(fixture.admission.frames.available_permits(), WRITER_CHANNEL_CAP);
        assert_eq!(fixture.admission.ciphertext_bytes.available_permits(), 256 * 1_024);
        if !completion_retired {
            assert!(tokio::time::timeout(Duration::from_secs(2), &mut fixture.receipt)
                .await.unwrap().is_err());
        }
        writer_joined && storage_retired && permits_returned && completion_retired
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_fatal_send_returns_after_writer_retirement() {
        let mut fixture = blocked_writer().await;
        assert!(fixture.stream.send_bytes(Bytes::from(vec![0; 128 * 1_024])).await.is_err());
        assert!(fixture.stream.poison);
        assert!(observe_then_join(&mut fixture, "send").await);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn read_jobs_retire_before_native_writer_pressure_errors() {
        use crate::fs::{handle_read_jobs, JobType, TransferJob};
        use std::os::unix::fs::DirBuilderExt;

        for (case, start, full_channel) in [
            ("read_error", 0, false),
            ("open_error", 0, false),
            ("complete", 1, false),
            ("full_channel", 1, true),
        ] {
            let root = std::env::temp_dir().join(format!(
                "rustdesk-read-job-pressure-{}-{:x}", std::process::id(), rand::random::<u64>(),
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let paused_source = root.join("paused.zip");
            let active_source = root.join("active.zip");
            std::fs::write(&paused_source, b"source").unwrap();
            std::fs::write(&active_source, b"source").unwrap();
            let mut paused = TransferJob::new_read(
                241, JobType::Generic, "paused".to_owned(), paused_source.clone(), 0, false, false, false,
            ).unwrap();
            paused.init_data_stream_for_cm().await.unwrap();
            paused.is_last_job = true;
            let active = TransferJob::new_read(
                241, JobType::Generic, "active".to_owned(), active_source.clone(), start, false, false, false,
            ).unwrap();
            match case {
                "read_error" => std::fs::write(&active_source, b"src").unwrap(),
                "open_error" => std::fs::remove_file(&active_source).unwrap(),
                _ => {}
            }
            let mut jobs = vec![paused, active];
            let BlockedWriter {
                mut stream, peer, observation, witness, admission, mut receipt,
            } = blocked_writer().await;

            let budget = admission.max_retained_ciphertext_bytes;
            let mut queued = 0;
            if full_channel {
                for _ in 0..WRITER_CHANNEL_CAP - 1 {
                    stream.send_bytes(Bytes::new()).await.unwrap();
                    queued += 1;
                }
                tokio::task::yield_now().await;
                assert_eq!(admission.frames.available_permits(), 0);
                assert!(admission.ciphertext_bytes.available_permits() > 0);
                assert!(matches!(&stream.state,
                    StreamState::Keyed(keyed) if keyed.writer_tx.capacity() == 1));
                let mut drain = Box::pin(stream.flush_writer());
                assert!(matches!(futures::poll!(drain.as_mut()), Poll::Pending));
                drop(drain);
                assert!(!stream.poison);
                assert!(matches!(&stream.state,
                    StreamState::Keyed(keyed) if keyed.writer.is_some() && keyed.writer_tx.capacity() == 0));
            } else {
                while admission.ciphertext_bytes.available_permits() > 0 {
                    let wire_size = admission.ciphertext_bytes.available_permits()
                        .min(admission.max_ciphertext_bytes);
                    assert!(wire_size > sodiumoxide::crypto::secretbox::MACBYTES);
                    stream.send_bytes(Bytes::from(vec![
                        0x6d; wire_size - sodiumoxide::crypto::secretbox::MACBYTES
                    ])).await.unwrap();
                    queued += 1;
                }
                assert_eq!(queued, 2);
                assert_eq!(admission.frames.available_permits(), WRITER_CHANNEL_CAP - 3);
                assert!(matches!(&stream.state,
                    StreamState::Keyed(keyed) if keyed.writer_tx.capacity() > 0));
            }
            assert_eq!(budget, 256 * 1024);
            assert!(observation.pending_len.load(Ordering::Relaxed) > 0);

            let mut stream = crate::Stream::Tcp(stream);
            let error = tokio::time::timeout(Duration::from_secs(2), handle_read_jobs(&mut jobs, &mut stream))
                .await.unwrap().expect_err("the live writer admission is exhausted");
            let expected_error = if full_channel {
                "R-T3: writer channel full"
            } else {
                "R-T18: keyed writer retained-byte capacity reached"
            };
            assert!(error.to_string().starts_with(expected_error));
            let crate::Stream::Tcp(stream) = stream else { panic!("retain the TCP stream"); };
            // Observe the public error boundary before any test-side yield or cleanup.
            assert!(stream.poison);
            assert!(matches!(&stream.state,
                StreamState::Keyed(keyed) if keyed.writer.is_none() && keyed.writer_tx.is_closed()));
            assert_eq!(admission.frames.available_permits(), WRITER_CHANNEL_CAP);
            assert_eq!(admission.ciphertext_bytes.available_permits(), budget);
            assert!(witness.is_unique());
            assert!(matches!(receipt.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
            assert_eq!(jobs.len(), 1);
            assert_eq!(jobs[0].remote, "paused");
            assert!(jobs[0].is_last_job);
            assert_eq!((jobs[0].file_num(), jobs[0].finished_size(), jobs[0].transferred()), (0, 0, 0));
            jobs[0].is_last_job = false;
            let block = jobs[0].read().await.unwrap().unwrap();
            assert!(!block.compressed);
            assert_eq!(block.data.as_ref(), b"source");
            assert!(jobs[0].read().await.unwrap().unwrap().data.is_empty());
            assert!(jobs[0].read().await.unwrap().is_none());
            assert!(jobs[0].job_completed());
            assert_eq!(std::fs::read(&paused_source).unwrap(), b"source");
            drop(jobs);
            drop(stream);
            drop(peer);
            std::fs::remove_file(paused_source).unwrap();
            if case != "open_error" {
                std::fs::remove_file(active_source).unwrap();
            }
            std::fs::remove_dir(root).unwrap();
            println!("READ_JOB_BACKPRESSURE_CASE=pass case={case} partial_write=true kernel_blocked=true queued_frames={queued} cancelled_drain={full_channel} byte_budget={budget} selected=retired survivor=exact writer=joined permits=returned receipt=closed storage=retired");
        }
        println!("READ_JOB_BACKPRESSURE=pass cases=4 byte_refusals=3 channel_refusals=1 selected=retired survivors=exact writer=joined permits=returned receipt=closed storage=retired");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_fatal_receive_returns_after_writer_retirement() {
        let mut fixture = blocked_writer().await;
        fixture.peer.write_all(&[4 << 2, 1, 2, 3, 4]).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), fixture.stream.next())
            .await.unwrap().unwrap().is_err());
        assert!(fixture.stream.poison);
        assert!(observe_then_join(&mut fixture, "receive").await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_fatal_drain_returns_after_writer_retirement() {
        let mut fixture = blocked_writer().await;
        let error = tokio::time::timeout(Duration::from_secs(4), fixture.stream.flush_writer())
            .await.unwrap().unwrap_err();
        assert!(error.to_string().contains("timed out waiting for writer drain"));
        assert!(fixture.stream.poison);
        assert!(observe_then_join(&mut fixture, "drain").await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_cancelled_retirement_keeps_writer_owned_until_retry() {
        let mut all_retired = true;
        for retry in ["send", "receive", "drain"] {
            let mut fixture = blocked_writer().await;
            let mut operation = Box::pin(fixture.stream.send_bytes(Bytes::from(vec![0; 128 * 1_024])));
            let pending_before_cancel = matches!(futures::poll!(operation.as_mut()), Poll::Pending);
            drop(operation);
            let ownership_retained = matches!(&fixture.stream.state,
                StreamState::Keyed(keyed) if keyed.writer.is_some());
            let resumed_error = match retry {
                "send" => fixture.stream.send_bytes(Bytes::new()).await.is_err(),
                "receive" => fixture.stream.next().await.is_none(),
                "drain" => fixture.stream.flush_writer().await.is_err(),
                _ => unreachable!(),
            };
            println!(
                "WRITER_RETIRE_CANCEL=observed retry={} pending_before_cancel={} ownership_retained={} resumed_error={}",
                retry, pending_before_cancel, ownership_retained, resumed_error,
            );
            let retired = observe_then_join(&mut fixture, retry).await;
            all_retired &= pending_before_cancel && ownership_retained && resumed_error && retired;
        }
        assert!(all_retired);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod open_tests {
    use super::*;

    #[test]
    fn decoder_reuses_the_authenticated_frame_storage() {
        const CHILD: &str = "RUSTDESK_RECEIVE_CODEC_ALLOCATION_CHILD";
        const TEST: &str = "tcp::open_tests::decoder_reuses_the_authenticated_frame_storage";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, "1").output().unwrap();
            assert!(output.stdout.len() + output.stderr.len() < 32_768);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "receive codec child {:?}: {}{}",
                output.status, stdout, String::from_utf8_lossy(&output.stderr));
            assert!(stdout.contains("RECEIVE_CODEC=pass cases=6 frames=12 normal=exact eof=exact rust_allocations=refused alias=exact prefetch=preserved"));
            for line in stdout.lines() {
                if let Some((_, message)) = line.split_once("RECEIVE_CODEC") {
                    println!("RECEIVE_CODEC{message}");
                }
            }
            return;
        }
        assert_eq!(std::env::var(CHILD).unwrap(), "1");
        for eof in [false, true] {
            for size in [0, 1, 64 * 1_024] {
                let input = vec![0x5a; size];
                let (mut seal, _) = split_session_keys(&DirectionalKeys {
                    send: [0x19; 32], recv: [0x2a; 32],
                });
                let (_, open) = split_session_keys(&DirectionalKeys {
                    send: [0x2a; 32], recv: [0x19; 32],
                });
                let mut codec = SecretboxCodec::new();
                codec.set_max_packet_length(128 * 1_024);
                codec.open_cipher = Some(open);
                let mut wire = BytesMut::from(&b"prefix!"[..]);
                let mut next_wire = BytesMut::new();
                BytesCodec::new().encode(seal.seal(&input).unwrap().into(), &mut wire).unwrap();
                BytesCodec::new().encode(seal.seal(b"next").unwrap().into(), &mut next_wire).unwrap();
                wire.extend_from_slice(&next_wire);
                wire.extend_from_slice(b"tail!");
                let prefix = wire.split_to(7);
                let suffix = wire.split_off(wire.len() - 5);
                for (index, payload) in [input.as_slice(), b"next"].iter().copied().enumerate() {
                    let pointer = wire.as_ptr() as usize + ((wire[0] & 3) + 1) as usize
                        + sodiumoxide::crypto::secretbox::MACBYTES;
                    let frame = crate::fs::with_allocations_refused(|| {
                        if eof { codec.decode_eof(&mut wire) } else { codec.decode(&mut wire) }
                    }).unwrap().unwrap();
                    assert_eq!(&frame[..], payload);
                    assert_eq!(frame.as_ptr() as usize, pointer);
                    assert_eq!(codec.open_cipher.as_ref().unwrap().read_seq(), index as u64 + 1);
                    assert_eq!(&prefix[..], b"prefix!");
                    assert_eq!(&suffix[..], b"tail!");
                    if index == 0 {
                        assert_eq!(&wire[..], &next_wire[..]);
                    } else {
                        assert!(wire.is_empty());
                    }
                }
                let result = crate::fs::with_allocations_refused(|| {
                    if eof { codec.decode_eof(&mut wire) } else { codec.decode(&mut wire) }
                }).unwrap();
                assert!(result.is_none());
                assert_eq!(codec.open_cipher.as_ref().unwrap().read_seq(), 2);
                println!("RECEIVE_CODEC_CASE=pass eof={eof} bytes={size} frames=2 rust_allocations=refused alias=exact prefetch=preserved");
            }
        }
        println!("RECEIVE_CODEC=pass cases=6 frames=12 normal=exact eof=exact rust_allocations=refused alias=exact prefetch=preserved");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod seal_tests {
    use super::*;

    #[test]
    fn allocation_refusal_retires_the_native_writer() {
        const CHILD: &str = "RUSTDESK_TCP_SEAL_ALLOCATION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tcp::seal_tests::allocation_refusal_retires_the_native_writer",
                    "--nocapture", "--test-threads=1"])
                .env(CHILD, "1").output().unwrap();
            assert!(output.stdout.len() + output.stderr.len() < 32_768);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "TCP seal allocation child {:?}: {}{}",
                output.status, stdout, String::from_utf8_lossy(&output.stderr));
            assert!(stdout.contains("TCP_SEAL_ALLOCATION=pass cases=9 refusals=9 healthy=exact writer=joined permits=returned peer=no-failed-frame"));
            for line in stdout.lines() {
                if let Some((_, message)) = line.split_once("TCP_SEAL_ALLOCATION") {
                    println!("TCP_SEAL_ALLOCATION{message}");
                }
            }
            return;
        }
        assert_eq!(std::env::var(CHILD).unwrap(), "1");
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for api in ["bytes", "message", "receipt"] {
                for size in [0, 1, 64 * 1_024] {
                    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let (socket, (peer, _)) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                        tokio::try_join!(tokio::net::TcpStream::connect(address), listener.accept())
                    }).await.unwrap().unwrap();
                    drop(listener);
                    let mut stream = FramedStream::from(socket, address);
                    stream.set_max_packet_length(128 * 1_024);
                    stream.set_session_keys(DirectionalKeys { send: [0x19; 32], recv: [0x2a; 32] });
                    let mut peer = Framed::new(peer, BytesCodec::new());
                    peer.codec_mut().set_max_packet_length(128 * 1_024);
                    stream.send_bytes(Bytes::from_static(b"healthy")).await.unwrap();
                    stream.flush_writer().await.unwrap();
                    let healthy = tokio::time::timeout(std::time::Duration::from_secs(2), peer.next())
                        .await.unwrap().unwrap().unwrap();
                    let mut nonce = sodiumoxide::crypto::secretbox::Nonce([0; 24]);
                    nonce.0[..8].copy_from_slice(&1u64.to_le_bytes());
                    assert_eq!(&healthy[..], sodiumoxide::crypto::secretbox::seal(
                        b"healthy", &nonce, &sodiumoxide::crypto::secretbox::Key([0x19; 32])));

                    let input = vec![0x5a; size];
                    let raw = Bytes::from(input.clone());
                    let mut response = crate::message_proto::ScreenshotResponse::new();
                    response.data = input.into();
                    let mut message = crate::message_proto::Message::new();
                    message.set_screenshot_response(response);
                    let encoded = message.write_to_bytes().unwrap();
                    let length = if api == "bytes" { raw.len() } else { encoded.len() };
                    crate::fs::fail_next_exact_allocation(length + sodiumoxide::crypto::secretbox::MACBYTES);
                    let error = match api {
                        "bytes" => stream.send_bytes(raw).await.unwrap_err(),
                        "message" => stream.send(&message).await.unwrap_err(),
                        "receipt" => stream.send_with_receipt(&message).await.unwrap_err(),
                        _ => unreachable!(),
                    };
                    // Observe exact retirement at return, before any test-side yield or cleanup.
                    assert_eq!(error.downcast_ref::<io::Error>().unwrap().kind(), ErrorKind::OutOfMemory);
                    assert_eq!(crate::fs::exact_allocation_failure_state(), (0, 1));
                    assert!(stream.poison);
                    if let StreamState::Keyed(keyed) = &stream.state {
                        assert!(keyed.writer.is_none());
                        assert!(keyed.writer_tx.is_closed());
                        assert!(keyed.writer_admission.frames.is_closed());
                        assert!(keyed.writer_admission.ciphertext_bytes.is_closed());
                        assert_eq!(keyed.writer_admission.frames.available_permits(), WRITER_CHANNEL_CAP);
                        assert_eq!(keyed.writer_admission.ciphertext_bytes.available_permits(), 256 * 1_024);
                    } else {
                        panic!("stream must remain keyed");
                    }
                    assert!(stream.send_bytes(Bytes::new()).await.is_err());
                    assert!(stream.flush_writer().await.is_err());
                    assert!(stream.next().await.is_none());
                    drop(stream);
                    assert!(tokio::time::timeout(std::time::Duration::from_secs(2), peer.next())
                        .await.unwrap().is_none(), "failed ciphertext must never reach the peer");
                    println!("TCP_SEAL_ALLOCATION_CASE=pass api={api} bytes={size} writer=joined permits=returned peer=no-failed-frame");
                }
            }
        });
        println!("TCP_SEAL_ALLOCATION=pass cases=9 refusals=9 healthy=exact writer=joined permits=returned peer=no-failed-frame");
    }
}

#[cfg(test)]
mod writer_receipt_tests {
    use super::*;
    use tokio::io::duplex;

    #[derive(Clone, Default)]
    struct ObservedMessage {
        inner: crate::message_proto::Message,
        encodes: Arc<std::sync::atomic::AtomicUsize>,
        fail_encoding: bool,
    }

    impl PartialEq for ObservedMessage {
        fn eq(&self, other: &Self) -> bool {
            self.inner == other.inner && self.fail_encoding == other.fail_encoding
        }
    }

    impl Message for ObservedMessage {
        const NAME: &'static str = "ObservedMessage";

        fn is_initialized(&self) -> bool {
            self.inner.is_initialized()
        }

        fn merge_from(&mut self, input: &mut protobuf::CodedInputStream) -> protobuf::Result<()> {
            self.inner.merge_from(input)
        }

        fn compute_size(&self) -> u64 {
            self.inner.compute_size()
        }

        fn write_to_with_cached_sizes(
            &self,
            output: &mut protobuf::CodedOutputStream,
        ) -> protobuf::Result<()> {
            self.encodes.fetch_add(1, Ordering::Relaxed);
            if self.fail_encoding {
                return Err(io::Error::new(ErrorKind::Other, "injected encoding failure").into());
            }
            self.inner.write_to_with_cached_sizes(output)
        }

        fn special_fields(&self) -> &protobuf::SpecialFields {
            self.inner.special_fields()
        }

        fn mut_special_fields(&mut self) -> &mut protobuf::SpecialFields {
            self.inner.mut_special_fields()
        }

        fn new() -> Self {
            Self::default()
        }

        fn default_instance() -> &'static Self {
            static INSTANCE: std::sync::OnceLock<ObservedMessage> = std::sync::OnceLock::new();
            INSTANCE.get_or_init(Self::default)
        }
    }

    fn observed_message() -> ObservedMessage {
        let mut response = crate::message_proto::ScreenshotResponse::new();
        response.data = vec![0x5a; 1_024].into();
        let mut inner = crate::message_proto::Message::new();
        inner.set_screenshot_response(response);
        ObservedMessage {
            inner,
            ..Default::default()
        }
    }

    async fn join_aborted_writer(stream: &mut FramedStream) {
        if let Some(result) = join_test_writer(stream, false).await {
            assert!(result.unwrap_err().is_cancelled());
        }
    }

    async fn assert_protobuf_refusal_before_encoding(with_receipt: bool) {
        use tokio::io::AsyncReadExt;

        for reason in ["oversize", "frames", "bytes", "closed", "poisoned", "unkeyed"] {
            if reason == "unkeyed" && !with_receipt {
                continue;
            }
            let (sender_side, mut peer) = duplex(8_192);
            let mut stream = FramedStream::from(sender_side, SocketAddr::from(([127, 0, 0, 1], 0)));
            stream.set_max_packet_length(if reason == "oversize" { 64 } else { 4_096 });
            if reason != "unkeyed" {
                stream.set_session_keys(DirectionalKeys {
                    send: [0x13; 32],
                    recv: [0x24; 32],
                });
            }
            let admission = match &stream.state {
                StreamState::Keyed(keyed) => Some(keyed.writer_admission.clone()),
                _ => None,
            };
            let held = match (reason, admission.as_ref()) {
                ("frames", Some(admission)) => Some(
                    Arc::clone(&admission.frames)
                        .try_acquire_many_owned(WRITER_CHANNEL_CAP as u32)
                        .unwrap(),
                ),
                ("bytes", Some(admission)) => Some(
                    Arc::clone(&admission.ciphertext_bytes)
                        .try_acquire_many_owned(admission.max_retained_ciphertext_bytes as u32)
                        .unwrap(),
                ),
                ("closed", Some(admission)) => {
                    admission.close();
                    None
                }
                _ => None,
            };
            if reason == "poisoned" {
                stream.poison_and_retire_writer().await;
            }
            let message = observed_message();
            let result = if with_receipt {
                stream.send_with_receipt(&message).await.map(|_| ())
            } else {
                stream.send(&message).await
            };
            assert!(result.is_err(), "refusal must be terminal: {}", reason);
            assert!(stream.poison);
            join_aborted_writer(&mut stream).await;
            drop(held);
            if let Some(admission) = admission {
                assert!(admission.frames.is_closed() && admission.ciphertext_bytes.is_closed());
                assert_eq!(admission.frames.available_permits(), WRITER_CHANNEL_CAP);
                assert_eq!(
                    admission.ciphertext_bytes.available_permits(),
                    admission.max_retained_ciphertext_bytes
                );
            }
            drop(stream);
            let mut received = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                peer.read_to_end(&mut received),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(received.is_empty());
            assert_eq!(
                message.encodes.load(Ordering::Relaxed),
                0,
                "encoded before refusal: {}",
                reason
            );
        }
    }

    #[tokio::test]
    async fn protobuf_send_refuses_before_encoding() {
        assert_protobuf_refusal_before_encoding(false).await;
    }

    #[tokio::test]
    async fn protobuf_receipt_refuses_before_encoding() {
        assert_protobuf_refusal_before_encoding(true).await;
    }

    async fn assert_writer_channel_refusal_before_encoding(closed: bool) {
        use tokio::io::AsyncReadExt;

        let keys = DirectionalKeys {
            send: [0x57; 32],
            recv: [0x68; 32],
        };
        let mut observations = Vec::new();
        for with_receipt in [false, true] {
            let (sender_side, peer) = duplex(8_192);
            let mut peer = Some(peer);
            let mut stream = FramedStream::from(sender_side, SocketAddr::from(([127, 0, 0, 1], 0)));
            stream.set_max_packet_length(4_096);
            stream.set_session_keys(keys.clone());
            let (mut expected_seal, _) = split_session_keys(&keys);
            if closed {
                drop(peer.take());
                let receipt = stream
                    .send_with_receipt(&crate::message_proto::Message::new())
                    .await
                    .unwrap();
                assert!(
                    tokio::time::timeout(std::time::Duration::from_secs(1), receipt)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_err()
                );
                if let Some(result) = join_test_writer(&mut stream, false).await {
                    result.unwrap();
                }
                if let StreamState::Keyed(keyed) = &stream.state {
                    assert!(keyed.writer_tx.is_closed());
                }
                expected_seal.seal(&[]).unwrap();
            } else if let StreamState::Keyed(keyed) = &stream.state {
                // The current-thread test has not yielded since spawning the writer. Fill its
                // channel with drain commands, which do not consume frame or byte admission.
                for _ in 0..WRITER_CHANNEL_CAP {
                    let (ack, _) = oneshot::channel();
                    assert!(keyed.writer_tx.try_send(WriterCommand::Drain(ack)).is_ok());
                }
                assert_eq!(keyed.writer_tx.capacity(), 0);
            }

            let message = observed_message();
            let result = if with_receipt {
                stream.send_with_receipt(&message).await.map(|_| ())
            } else {
                stream.send(&message).await
            };
            assert!(result.is_err());
            assert!(stream.poison);
            if !closed {
                join_aborted_writer(&mut stream).await;
            }
            if let StreamState::Keyed(keyed) = &mut stream.state {
                observations.push((
                    message.encodes.load(Ordering::Relaxed),
                    keyed.seal.seal(b"next nonce").unwrap() == expected_seal.seal(b"next nonce").unwrap(),
                ));
                assert!(keyed.writer_admission.frames.is_closed());
                assert!(keyed.writer_admission.ciphertext_bytes.is_closed());
                assert_eq!(
                    keyed.writer_admission.frames.available_permits(),
                    WRITER_CHANNEL_CAP
                );
                assert_eq!(
                    keyed.writer_admission.ciphertext_bytes.available_permits(),
                    8_192
                );
            }
            drop(stream);
            if let Some(mut peer) = peer {
                let mut received = Vec::new();
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    peer.read_to_end(&mut received),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(received.is_empty());
            }
        }
        assert_eq!(observations, [(0, true), (0, true)]);
    }

    #[tokio::test]
    async fn protobuf_refuses_failed_writer_before_encoding_and_sealing() {
        assert_writer_channel_refusal_before_encoding(true).await;
    }

    #[tokio::test]
    async fn protobuf_refuses_full_channel_before_encoding_and_sealing() {
        assert_writer_channel_refusal_before_encoding(false).await;
    }

    #[tokio::test]
    async fn protobuf_encoding_failure_retires_admission() {
        for with_receipt in [false, true] {
            let (sender_side, _peer) = duplex(8_192);
            let mut stream = FramedStream::from(sender_side, SocketAddr::from(([127, 0, 0, 1], 0)));
            stream.set_max_packet_length(4_096);
            stream.set_session_keys(DirectionalKeys {
                send: [0x35; 32],
                recv: [0x46; 32],
            });
            let mut message = observed_message();
            message.fail_encoding = true;
            let result = if with_receipt {
                stream.send_with_receipt(&message).await.map(|_| ())
            } else {
                stream.send(&message).await
            };
            assert!(result.is_err());
            let poisoned = stream.poison;
            // Join the old implementation's still-live writer before reporting its failed oracle.
            if !poisoned {
                if let StreamState::Keyed(keyed) = &stream.state {
                    if let Some(writer) = &keyed.writer {
                        writer.abort();
                    }
                }
            }
            join_aborted_writer(&mut stream).await;
            assert_eq!(message.encodes.load(Ordering::Relaxed), 1);
            assert!(poisoned, "encoding failure must retire the exact stream");
            if let StreamState::Keyed(keyed) = &stream.state {
                assert!(keyed.writer_admission.frames.is_closed());
                assert!(keyed.writer_admission.ciphertext_bytes.is_closed());
                assert_eq!(
                    keyed.writer_admission.frames.available_permits(),
                    WRITER_CHANNEL_CAP
                );
                assert_eq!(keyed.writer_admission.ciphertext_bytes.available_permits(), 8_192);
            }
        }
    }

    fn framed<T>(stream: T) -> Framed<DynTcpStream, SecretboxCodec>
    where
        T: TcpStreamTrait + Send + Sync + 'static,
    {
        Framed::new(DynTcpStream(Box::new(stream)), SecretboxCodec::new())
    }

    fn writer_frame(
        admission: &WriterAdmission,
        bytes: Bytes,
        completion: Option<oneshot::Sender<io::Result<()>>>,
    ) -> WriterCommand {
        let reservation = admission
            .reserve_ciphertext(bytes.len())
            .expect("test writer frame must fit exact admission");
        WriterCommand::Frame {
            bytes,
            reservation,
            completion,
        }
    }

    fn writer_sink<T>(stream: T) -> FramedWrite<WriteHalf<DynTcpStream>, BytesCodec>
    where
        T: TcpStreamTrait + Send + Sync + 'static,
    {
        let (_, write) = tokio::io::split(DynTcpStream(Box::new(stream)));
        FramedWrite::new(write, BytesCodec::new())
    }

    #[test]
    fn r_s11gx_writer_admission_checks_size_count_and_bytes_before_ownership() {
        let count_admission = WriterAdmission::new(4_096);
        let frame_permits = count_admission.frames.available_permits();
        let byte_permits = count_admission.ciphertext_bytes.available_permits();
        assert!(count_admission.reserve_plaintext(usize::MAX).is_err());
        assert!(count_admission.reserve_plaintext(4_081).is_err());
        assert_eq!(count_admission.frames.available_permits(), frame_permits);
        assert_eq!(
            count_admission.ciphertext_bytes.available_permits(),
            byte_permits
        );

        let mut retained = Vec::with_capacity(WRITER_CHANNEL_CAP);
        for _ in 0..WRITER_CHANNEL_CAP {
            retained.push(
                count_admission
                    .reserve_plaintext(0)
                    .expect("all exact frame slots must be usable"),
            );
        }
        let count_error = match count_admission.reserve_plaintext(0) {
            Err(error) => error,
            Ok(_) => panic!("the active-plus-queued frame ceiling must be exact"),
        };
        assert!(count_error.to_string().contains("retained-frame capacity"));
        drop(retained.pop());
        retained.push(
            count_admission
                .reserve_plaintext(0)
                .expect("dropping one frame owner must return its exact slot"),
        );
        drop(retained);
        assert_eq!(
            count_admission.frames.available_permits(),
            WRITER_CHANNEL_CAP
        );
        assert_eq!(
            count_admission.ciphertext_bytes.available_permits(),
            byte_permits
        );

        let byte_admission = WriterAdmission::new(64);
        let first = byte_admission
            .reserve_plaintext(48)
            .expect("one ceiling-sized ciphertext must fit");
        let second = byte_admission
            .reserve_plaintext(48)
            .expect("the second ceiling-sized ciphertext must fit");
        let byte_error = match byte_admission.reserve_plaintext(0) {
            Err(error) => error,
            Ok(_) => panic!("two exact packets must exhaust the retained-byte budget"),
        };
        assert!(byte_error.to_string().contains("retained-byte capacity"));
        drop(first);
        byte_admission
            .reserve_plaintext(0)
            .expect("dropping one byte owner must return exact byte capacity");
        drop(second);
    }

    #[tokio::test]
    async fn r_s11fb_receipt_waits_for_the_exact_sink_send() {
        let (writer_side, reader_side) = duplex(64);
        let sink = writer_sink(writer_side);
        let mut peer = framed(reader_side);
        let (writer_tx, writer_rx) = mpsc::channel(1);
        let writer = tokio::spawn(writer_task(sink, writer_rx));
        let (completion, mut receipt) = oneshot::channel();
        let expected = Bytes::from(vec![0x5a; 4_096]);
        let admission = WriterAdmission::new(4_096);

        writer_tx
            .send(writer_frame(
                &admission,
                expected.clone(),
                Some(completion),
            ))
            .await
            .expect("writer command must be admitted");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut receipt)
                .await
                .is_err(),
            "bounded enqueue alone must not complete a tracked frame"
        );

        let actual = peer
            .next()
            .await
            .expect("peer frame must arrive")
            .expect("peer frame must decode");
        assert_eq!(actual.as_ref(), expected.as_ref());
        receipt
            .await
            .expect("the exact writer must retain completion ownership")
            .expect("the exact sink send must succeed");
        assert_eq!(admission.frames.available_permits(), WRITER_CHANNEL_CAP);
        assert_eq!(admission.ciphertext_bytes.available_permits(), 8_192);

        drop(writer_tx);
        writer.await.expect("writer task must retire cleanly");
    }

    #[tokio::test]
    async fn r_s11fb_receipt_reports_the_exact_sink_failure() {
        let (writer_side, reader_side) = duplex(64);
        drop(reader_side);
        let sink = writer_sink(writer_side);
        let (writer_tx, writer_rx) = mpsc::channel(1);
        let writer = tokio::spawn(writer_task(sink, writer_rx));
        let (completion, receipt) = oneshot::channel();
        let admission = WriterAdmission::new(64);

        writer_tx
            .send(writer_frame(
                &admission,
                Bytes::from_static(b"failure"),
                Some(completion),
            ))
            .await
            .expect("writer command must be admitted");
        assert!(
            receipt
                .await
                .expect("writer must report its exact result")
                .is_err(),
            "a sink failure must never be reported as completion"
        );

        drop(writer_tx);
        writer.await.expect("writer task must retire after failure");
        assert_eq!(admission.frames.available_permits(), WRITER_CHANNEL_CAP);
        assert_eq!(admission.ciphertext_bytes.available_permits(), 128);
    }

    #[tokio::test]
    async fn r_s11gx_active_and_queued_frames_share_one_exact_budget_until_abort() {
        let (sender_side, _receiver_side) = duplex(1);
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut sender = FramedStream::from(sender_side, local_addr);
        sender.set_max_packet_length(64);
        sender.set_session_keys(DirectionalKeys {
            send: [0x51; 32],
            recv: [0x62; 32],
        });
        let admission = match &sender.state {
            StreamState::Keyed(keyed) => keyed.writer_admission.clone(),
            _ => panic!("test stream must be keyed"),
        };

        sender
            .send_bytes(Bytes::from(vec![0x71; 48]))
            .await
            .expect("first ceiling-sized frame must be admitted");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let active = match &sender.state {
                    StreamState::Keyed(keyed) => {
                        keyed.writer_tx.capacity() == WRITER_CHANNEL_CAP
                            && admission.frames.available_permits() == WRITER_CHANNEL_CAP - 1
                            && admission.ciphertext_bytes.available_permits() == 64
                    }
                    _ => false,
                };
                if active {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the writer must dequeue and retain the active sink frame");

        sender
            .send_bytes(Bytes::from(vec![0x72; 48]))
            .await
            .expect("one queued ceiling-sized frame must share the two-packet budget");
        assert_eq!(admission.frames.available_permits(), WRITER_CHANNEL_CAP - 2);
        assert_eq!(admission.ciphertext_bytes.available_permits(), 0);
        let error = sender
            .send_bytes(Bytes::new())
            .await
            .expect_err("a third ciphertext must retire the back-pressured writer");
        assert!(error.to_string().contains("retained-byte capacity"));

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while admission.frames.available_permits() != WRITER_CHANNEL_CAP
                || admission.ciphertext_bytes.available_permits() != 128
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer abort must release the active and queued exact reservations");
    }

    #[tokio::test]
    async fn r_s11gx_failed_drain_retires_writer_admission() {
        let (sender_side, _receiver_side) = duplex(64);
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut sender = FramedStream::from(sender_side, local_addr);
        sender.set_max_packet_length(64);
        sender.set_session_keys(DirectionalKeys {
            send: [0xa6; 32],
            recv: [0xb7; 32],
        });
        let admission = match &mut sender.state {
            StreamState::Keyed(keyed) => {
                let admission = keyed.writer_admission.clone();
                let writer = keyed.writer.as_mut().unwrap();
                writer.abort();
                let error = writer
                    .await
                    .expect_err("the deliberately aborted writer must not complete normally");
                assert!(error.is_cancelled());
                keyed.writer = None;
                admission
            }
            _ => panic!("test stream must be keyed"),
        };

        let error = sender
            .flush_writer()
            .await
            .expect_err("a missing exact writer must make drain terminal");
        assert!(error.to_string().contains("writer task gone before drain"));
        assert!(sender.poison);
        assert!(admission.frames.is_closed());
        assert!(admission.ciphertext_bytes.is_closed());
        assert!(
            sender.send_bytes(Bytes::new()).await.is_err(),
            "a failed drain must leave the exact stream terminal"
        );
    }

    #[tokio::test]
    async fn r_s11gx_oversized_plaintext_is_rejected_before_peer_delivery() {
        let (sender_side, receiver_side) = duplex(64);
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut sender = FramedStream::from(sender_side, local_addr);
        let mut receiver = FramedStream::from(receiver_side, local_addr);
        sender.set_max_packet_length(64);
        receiver.set_max_packet_length(64);
        sender.set_session_keys(DirectionalKeys {
            send: [0x73; 32],
            recv: [0x84; 32],
        });
        receiver.set_session_keys(DirectionalKeys {
            send: [0x84; 32],
            recv: [0x73; 32],
        });

        let error = sender
            .send_bytes(Bytes::from(vec![0x95; 49]))
            .await
            .expect_err("plaintext beyond the post-secretbox ceiling must fail locally");
        assert!(error.to_string().contains("engaged packet ceiling"));
        assert!(
            sender.send_bytes(Bytes::new()).await.is_err(),
            "the failed stream must remain poisoned"
        );
        assert_eq!(receiver.recv_counter(), 0);
        match tokio::time::timeout(std::time::Duration::from_millis(20), receiver.next()).await {
            Err(_) | Ok(None) => {}
            Ok(Some(result)) => {
                panic!("oversized ciphertext reached the peer unexpectedly: {result:?}")
            }
        }
    }

    #[tokio::test]
    async fn r_s11fb_tracked_keyed_send_round_trips_the_exact_frame() {
        let (sender_side, receiver_side) = duplex(64);
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut sender = FramedStream::from(sender_side, local_addr);
        let mut receiver = FramedStream::from(receiver_side, local_addr);
        sender.set_max_packet_length(8 * 1024);
        receiver.set_max_packet_length(8 * 1024);
        sender.set_session_keys(DirectionalKeys {
            send: [0x11; 32],
            recv: [0x22; 32],
        });
        receiver.set_session_keys(DirectionalKeys {
            send: [0x22; 32],
            recv: [0x11; 32],
        });

        let mut response = crate::message_proto::ScreenshotResponse::new();
        response.sid = "writer-receipt".to_owned();
        response.data = vec![0x6b; 4_096].into();
        let mut message = crate::message_proto::Message::new();
        message.set_screenshot_response(response);
        let expected = message
            .write_to_bytes()
            .expect("test message must serialize");

        let mut receipt = sender
            .send_with_receipt(&message)
            .await
            .expect("tracked keyed send must be admitted");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut receipt)
                .await
                .is_err(),
            "tracked keyed enqueue must not report completion while its sink is back-pressured"
        );

        let actual = receiver
            .next()
            .await
            .expect("the exact keyed frame must arrive")
            .expect("the exact keyed frame must authenticate");
        assert_eq!(actual.as_ref(), expected.as_slice());
        receipt
            .await
            .expect("the keyed writer must retain exact completion ownership")
            .expect("the exact keyed sink send must succeed");
    }

    #[tokio::test]
    async fn r_s11fk_real_tcp_receipt_can_precede_peer_read() {
        // Characterize the exact boundary of WriterReceipt on a real kernel TCP socket. Unlike
        // `duplex(64)` above, successful `SinkExt::send` may hand the complete frame to the local
        // TCP stack before the peer polls its read half. This is intentionally not accepted as
        // controlled-video progress: an exact peer receipt is required above this transport layer.
        let listener = new_exclusive_listener("127.0.0.1:0")
            .await
            .expect("loopback listener must bind");
        let addr = listener
            .local_addr()
            .expect("loopback listener must have an address");
        let (connected, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let receiver_side = connected.expect("loopback peer must connect");
        let (sender_side, peer_addr) = accepted.expect("loopback sender must accept the peer");

        let mut sender = FramedStream::from(sender_side, peer_addr);
        let mut receiver = FramedStream::from(receiver_side, addr);
        sender.set_max_packet_length(8 * 1024);
        receiver.set_max_packet_length(8 * 1024);
        sender.set_session_keys(DirectionalKeys {
            send: [0x31; 32],
            recv: [0x42; 32],
        });
        receiver.set_session_keys(DirectionalKeys {
            send: [0x42; 32],
            recv: [0x31; 32],
        });

        let mut response = crate::message_proto::ScreenshotResponse::new();
        response.sid = "real-tcp-local-receipt".to_owned();
        response.data = vec![0x7c; 4_096].into();
        let mut message = crate::message_proto::Message::new();
        message.set_screenshot_response(response);
        let expected = message
            .write_to_bytes()
            .expect("test message must serialize");

        let observed = ObservedMessage {
            inner: message,
            ..Default::default()
        };
        sender
            .send(&observed)
            .await
            .expect("ordinary real-TCP protobuf send must be admitted");
        let receipt = sender
            .send_with_receipt(&observed)
            .await
            .expect("tracked real-TCP send must be admitted");
        assert_eq!(observed.encodes.load(Ordering::Relaxed), 2);
        tokio::time::timeout(std::time::Duration::from_secs(1), receipt)
            .await
            .expect("local TCP writer receipt must complete without a peer read")
            .expect("the exact writer must retain completion ownership")
            .expect("the local TCP sink send must succeed");
        assert_eq!(
            receiver.recv_counter(),
            0,
            "writer completion must be observable before the peer authenticates or reads the frame"
        );

        for _ in 0..2 {
            let actual = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.next())
                .await
                .expect("the peer read must complete after it is explicitly polled")
                .expect("the exact keyed frame must arrive")
                .expect("the exact keyed frame must authenticate");
            assert_eq!(actual.as_ref(), expected.as_slice());
        }
    }
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod exclusive_listener_tests {
    use super::new_exclusive_listener;

    #[cfg(not(windows))]
    #[tokio::test]
    async fn second_exclusive_listener_bind_is_refused() {
        let listener = new_exclusive_listener("127.0.0.1:0")
            .await
            .expect("first exclusive bind must succeed");
        let addr = listener
            .local_addr()
            .expect("exclusive listener must have a local address");
        let err = new_exclusive_listener(addr)
            .await
            .expect_err("second exclusive bind must be refused");
        let io_error = err
            .downcast_ref::<std::io::Error>()
            .expect("bind failure must retain its io::Error");
        assert_eq!(io_error.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn hostile_reuseaddr_socket_cannot_bind_exclusive_listener_port() {
        let listener = new_exclusive_listener("127.0.0.1:0")
            .await
            .expect("first exclusive bind must succeed");
        let addr = listener
            .local_addr()
            .expect("exclusive listener must have a local address");
        let hostile = tokio::net::TcpSocket::new_v4().expect("hostile socket creation");
        hostile
            .set_reuseaddr(true)
            .expect("hostile socket must explicitly set SO_REUSEADDR");
        hostile
            .bind(addr)
            .expect_err("SO_REUSEADDR socket must not steal an exclusive listener port");
    }
}
