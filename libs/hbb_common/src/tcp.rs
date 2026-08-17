use crate::{
    bail,
    bytes_codec::BytesCodec,
    cpace::{split_session_keys, DirectionalKeys, OpenCipher, SealCipher},
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
    sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore, TryAcquireError},
    task::JoinHandle,
};
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
/// read half ([`SplitStream`]) plus the send-side [`SealCipher`], exact writer admission, and the
/// bounded channel to the dedicated writer task · `local_addr` peer addr · `poison` flag (R-T2).
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
    /// Bounded FIFO of already-sealed frames to the sole writer task (R-T8). R-T18's separate
    /// admission remains held after dequeue; either admission or channel refusal is fatal.
    writer_tx: mpsc::Sender<WriterCommand>,
    /// Nonblocking count-and-ciphertext admission held through the exact sink send (R-T18).
    writer_admission: WriterAdmission,
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
            self.poison_and_retire_writer();
        }
        r
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
        let bytes = Bytes::from(msg.write_to_bytes()?);
        if self.poison {
            bail!("R-T2: refusing to send on a poisoned stream (a prior send/recv error)");
        }
        let result = self.send_bytes_raw_with_receipt(bytes).await;
        if result.is_err() {
            self.poison_and_retire_writer();
        }
        result
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
                // R-T18 validates and reserves count plus exact ciphertext bytes BEFORE sealing, so
                // refusal allocates no ciphertext and advances no nonce. The owned reservation then
                // follows the frame through the sole sink send; active and queued frames share one
                // finite budget even though Tokio returns channel capacity at dequeue.
                let reservation = k.writer_admission.reserve_plaintext(bytes.len())?;
                // R-T3 (§20): seal on THIS single-producer enqueue side so nonce order remains exact
                // channel-FIFO order, then enqueue NON-BLOCKING. Full/closed remains fatal rather
                // than blocking the connection run-loop inside a `select!` branch.
                let sealed = Bytes::from(k.seal.seal(&bytes));
                if sealed.len() != reservation.ciphertext_bytes {
                    bail!("R-T18: secretbox ciphertext length disagrees with reserved bytes");
                }
                k.writer_tx
                    .try_send(WriterCommand::Frame {
                        bytes: sealed,
                        reservation,
                        completion: None,
                    })
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

    async fn send_bytes_raw_with_receipt(&mut self, bytes: Bytes) -> ResultType<WriterReceipt> {
        let (completion, receipt) = oneshot::channel();
        match &mut self.state {
            StreamState::Unkeyed(_) => {
                bail!("tracked writer completion requires a keyed stream");
            }
            StreamState::Keyed(k) => {
                let reservation = k.writer_admission.reserve_plaintext(bytes.len())?;
                let sealed = Bytes::from(k.seal.seal(&bytes));
                if sealed.len() != reservation.ciphertext_bytes {
                    bail!("R-T18: secretbox ciphertext length disagrees with reserved bytes");
                }
                k.writer_tx
                    .try_send(WriterCommand::Frame {
                        bytes: sealed,
                        reservation,
                        completion: Some(completion),
                    })
                    .map_err(|e| match e {
                        mpsc::error::TrySendError::Full(_) => {
                            anyhow::anyhow!("R-T3: writer channel full — dropping the back-pressured connection")
                        }
                        mpsc::error::TrySendError::Closed(_) => {
                            anyhow::anyhow!("R-T3: writer task gone — connection is dead")
                        }
                    })?;
            }
            StreamState::Keying => {
                unreachable!("send_bytes_raw_with_receipt observed a mid-keying stream")
            }
        }
        Ok(receipt)
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
            self.poison_and_retire_writer();
        }
        result
    }

    /// Retire keyed admission and its sole writer immediately after a fatal transport outcome.
    /// Closing admission prevents future internal use; aborting drops the active command and the
    /// receiver's queued commands, which returns every owned R-T18 permit without waiting for the
    /// outer connection future to reach `Drop`.
    fn poison_and_retire_writer(&mut self) {
        self.poison = true;
        if let StreamState::Keyed(k) = &self.state {
            k.writer_admission.close();
            k.writer.abort();
        }
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
            self.poison_and_retire_writer();
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
        let writer_admission = WriterAdmission::new(framed.codec().max_packet_length());
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
            writer_admission,
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

/// R-T3/R-T18 (§20): finite writer admission. The Tokio channel is the FIFO handoff, while the
/// separate frame permits remain held after dequeue so the active sink frame still counts toward
/// this 512-frame limit. Exact ciphertext permits cap active plus queued payload at two engaged
/// keyed packets. All admission is nonblocking; refusal retires the exact connection.
const WRITER_CHANNEL_CAP: usize = 512;
const WRITER_RETAINED_CIPHERTEXT_PACKETS: usize = 2;
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
            WriterCommand::Frame {
                bytes,
                reservation,
                completion,
            } => {
                let result = sink.send(bytes).await;
                let failed = result.is_err();
                if failed {
                    // A failed Framed sink may retain encoded bytes. Drop that sink before releasing
                    // their exact reservation, then report the failure and retire this writer.
                    drop(sink);
                    drop(reservation);
                    if let Some(completion) = completion {
                        let _ = completion.send(result);
                    }
                    return;
                }
                // Successful `SinkExt::send` includes flush completion. Keep the reservation alive
                // across that await, then release it before publishing exact completion.
                drop(reservation);
                if let Some(completion) = completion {
                    let _ = completion.send(result);
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
            k.writer_admission.close();
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

pub async fn new_exclusive_listener<T: ToSocketAddrs>(addr: T) -> ResultType<TcpListener> {
    let addr = lookup_host(&addr)
        .await?
        .next()
        .context("could not resolve exclusive listener address")?;
    Ok(new_listener_socket(addr)?.listen(DEFAULT_BACKLOG)?)
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
mod writer_receipt_tests {
    use super::*;
    use tokio::io::duplex;

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
        let (sink, _) = framed(writer_side).split();
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
        let (sink, _) = framed(writer_side).split();
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
                keyed.writer.abort();
                let error = (&mut keyed.writer)
                    .await
                    .expect_err("the deliberately aborted writer must not complete normally");
                assert!(error.is_cancelled());
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

        let receipt = sender
            .send_with_receipt(&message)
            .await
            .expect("tracked real-TCP send must be admitted");
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

        let actual = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.next())
            .await
            .expect("the peer read must complete after it is explicitly polled")
            .expect("the exact keyed frame must arrive")
            .expect("the exact keyed frame must authenticate");
        assert_eq!(actual.as_ref(), expected.as_slice());
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
