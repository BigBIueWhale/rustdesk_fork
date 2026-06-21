use crate::{
    bail, bytes_codec::BytesCodec, config::Socks5Server,
    cpace::{DirectionalCipher, DirectionalKeys},
    proxy::Proxy, ResultType,
};
use anyhow::Context as AnyhowCtx;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use protobuf::Message;
use sodiumoxide::crypto::{
    box_,
    secretbox::{self, Key, Nonce},
};
use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{lookup_host, TcpListener, TcpSocket, ToSocketAddrs},
};
use tokio_socks::IntoTargetAddr;
use tokio_util::codec::{Decoder, Encoder, Framed};

pub trait TcpStreamTrait: AsyncRead + AsyncWrite + Unpin {}
pub struct DynTcpStream(pub Box<dyn TcpStreamTrait + Send + Sync>);

#[derive(Clone)]
pub struct Encrypt(pub Key, pub u64, pub u64);

/// The cipher engaged on a stream after keying. Either the inherited single-key
/// secretbox ([`Encrypt`], from the legacy `SignedId`/`box_` bootstrap) or the
/// CPace two-key per-direction cipher ([`DirectionalCipher`], R-P2/R-P10). The
/// single-key form is retained only until the choke-point cutover moves every
/// caller to [`FramedStream::set_session_keys`]; R-A6 then removes it.
pub enum StreamCipher {
    Single(Encrypt),
    Dual(DirectionalCipher),
}

impl StreamCipher {
    #[inline]
    pub fn enc(&mut self, data: &[u8]) -> Vec<u8> {
        match self {
            StreamCipher::Single(e) => e.enc(data),
            StreamCipher::Dual(d) => d.seal(data),
        }
    }

    #[inline]
    pub fn dec(&mut self, bytes: &mut BytesMut) -> Result<(), Error> {
        match self {
            StreamCipher::Single(e) => e.dec(bytes),
            StreamCipher::Dual(d) => {
                // R-T7 (§20): authenticate EVERY frame on the keyed stream — there is no
                // ≤1-byte passthrough. A genuine sealed frame is always >= MACBYTES (16 bytes:
                // seal appends a 16-byte tag even to a 0-byte plaintext), so any shorter frame
                // cannot be a valid ciphertext and MUST fail closed at the AEAD — closing the
                // one path by which a byte could reach the application parser unauthenticated
                // (also the worst-case carryover channel for R-T6). secretbox::open rejects
                // len < MACBYTES, so a tiny injected frame is a clean decryption error.
                match d.open(bytes) {
                    Ok(res) => {
                        bytes.clear();
                        bytes.put_slice(&res);
                        Ok(())
                    }
                    Err(()) => Err(Error::new(ErrorKind::Other, "decryption error")),
                }
            }
        }
    }

    /// The recv counter (`read_seq`) — exposed for the R-T5 cancellation-safety regression test
    /// (a dropped `next()` MUST NOT advance it). Single: the `Encrypt` recv field; Dual: the
    /// `DirectionalCipher`'s `read_seq`.
    #[inline]
    pub fn read_seq(&self) -> u64 {
        match self {
            StreamCipher::Single(e) => e.2,
            StreamCipher::Dual(d) => d.read_seq(),
        }
    }
}

/// R-T5 (§20): the length codec with decryption FOLDED IN — the structural form of the
/// reassemble → authenticate → parse order.
///
/// `decode` reassembles exactly ONE complete frame (the stateful `Head`/`Data(n)` machine of the
/// inner [`BytesCodec`]) and THEN, in the same synchronous call with **no `.await` between**,
/// authenticates + decrypts it and advances the recv counter (`read_seq`). Because the counter
/// lives in this `Framed`-owned codec and the decrypt is part of the value `StreamExt::next`
/// atomically yields, a dropped `next()` (a `select!`/`timeout` losing the race) consumes zero
/// bytes and never advances `read_seq` — inheriting tokio-util's documented cancel-safety verbatim,
/// *structurally* rather than by the incidental ordering of an external decrypt step. A partial
/// frame returns `Ok(None)` (buffered, no counter advance), so a dropped poll never half-consumes.
/// `encode` symmetrically seals the plaintext under the send key (advancing `write_seq`) THEN
/// length-frames it, so on the single-writer side (R-T8) seal order == wire order.
pub struct SecretboxCodec {
    inner: BytesCodec,
    cipher: Option<StreamCipher>,
}

impl SecretboxCodec {
    pub(crate) fn new() -> Self {
        Self {
            inner: BytesCodec::new(),
            cipher: None,
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
                // (2) authenticate + decrypt the WHOLE frame, advancing read_seq INSIDE decode —
                // R-T7 (every keyed frame AEAD-authenticated) lives in StreamCipher::dec.
                if let Some(cipher) = self.cipher.as_mut() {
                    cipher.dec(&mut frame)?;
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
        // seal under the send key (advancing write_seq) THEN length-frame.
        let framed_input = match self.cipher.as_mut() {
            Some(cipher) => Bytes::from(cipher.enc(&data)),
            None => data,
        };
        self.inner.encode(framed_input, dst)
    }
}

/// A length-delimited, optionally-keyed TCP message stream.
///
/// # Single-writer contract (R-T8, §20)
///
/// **Each `FramedStream` has exactly one writer.** Two concurrent writers would
/// byte-interleave their encoded frames on the wire — a permanent framing desync,
/// and on a keyed stream (field `.2 = Some`) garbage ciphertext that fails every
/// subsequent Poly1305 tag. The invariant is kept *structural*, not conventional,
/// so a refactor cannot silently break it:
///
/// * every write method (`send`/`send_raw`/`send_bytes`) takes `&mut self`, so the
///   borrow checker alone forbids two simultaneous writers;
/// * the type owns its socket through a `Box<dyn>` (`DynTcpStream`) and is
///   deliberately **not** `Clone` — there is no way to obtain a second owner;
/// * the stream is **never** `.split()` into independent read/write halves, and
///   **never** wrapped in `Arc<Mutex<_>>` for writing.
///
/// The fork's many output producers (video / audio / clipboard / camera / the
/// connection-manager) therefore do **not** hold the stream; each holds a *clone of
/// an `mpsc` sender*, and the single task that owns the `FramedStream` is the sole
/// drainer of that channel and the sole writer of the socket. `seal` advances the
/// write counter on that single-producer drain side, so flush order = seal order =
/// wire order (the nonce never races). A second writable handle must remain a
/// compile-visible error, never a silent wire corruption — `scripts/verify.sh`
/// gates against `.split()` / `Arc<Mutex<FramedStream>>` as a backstop.
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
/// `.0` framed socket whose codec ([`SecretboxCodec`]) OWNS the engaged cipher (R-T5: the recv
/// counter lives in the `Framed`-owned codec, so a dropped `next()` cannot desync it) · `.1` peer
/// addr · `.2` per-send write timeout (ms; 0 = none) · `.3` poison flag (R-T2).
pub struct FramedStream(
    pub Framed<DynTcpStream, SecretboxCodec>,
    pub SocketAddr,
    pub u64,
    // R-T2 (§20): the poison flag. Set on ANY send/recv error so the stream can never be
    // reused after a failure. On a keyed stream `seal` pre-increments the write nonce before
    // the bytes are flushed; if a future edit kept looping after a send error and reused the
    // stream, the next send would re-flush stale buffered ciphertext under an already-advanced
    // nonce, permanently desyncing the c2s direction. Poisoning makes "a send/recv error is
    // fatal-to-the-connection" a structural invariant rather than a per-call-site convention —
    // `send_bytes`/`next` short-circuit to an error / EOF once it is set.
    pub bool,
);

impl Deref for FramedStream {
    type Target = Framed<DynTcpStream, SecretboxCodec>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FramedStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
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

pub(crate) fn new_socket(addr: std::net::SocketAddr, reuse: bool) -> Result<TcpSocket, std::io::Error> {
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
                    return Ok(Self(
                        Framed::new(DynTcpStream(Box::new(stream)), SecretboxCodec::new()),
                        addr,
                        0,
                        false, // R-T2: a fresh stream is not poisoned
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

    pub fn local_addr(&self) -> SocketAddr {
        self.1
    }

    pub fn set_send_timeout(&mut self, ms: u64) {
        self.2 = ms;
    }

    pub fn from(stream: impl TcpStreamTrait + Send + Sync + 'static, addr: SocketAddr) -> Self {
        Self(
            Framed::new(DynTcpStream(Box::new(stream)), SecretboxCodec::new()),
            addr,
            0,
            false, // R-T2: a fresh stream is not poisoned
        )
    }

    pub fn set_raw(&mut self) {
        // R-A3 / R-S5: a keyed session stream MUST NOT be downgraded to raw — stripping
        // the engaged secretbox would leak plaintext, and keeping it would break framing
        // (raw mode cannot delimit framed secretbox output). The only caller is the
        // port-forward/tunnel, which is policy-disabled on the box (enable-tunnel=N,
        // R-S16, now unconditional), so a keyed stream must never reach here; assert it
        // fail-closed on every build (R-A3/R-R2b) rather than silently downgrade.
        assert!(
            self.0.codec().cipher.is_none(),
            "R-A3: set_raw on a keyed session stream — refusing to downgrade"
        );
        self.0.codec_mut().set_raw();
    }

    /// Cap the inbound frame length before the first byte is read. Used to bound
    /// the attacker-reachable pre-key parser to the small CPace handshake frames
    /// (R-S7 / R-P14b): an oversize frame then aborts fail-closed at the codec.
    pub fn set_max_packet_length(&mut self, n: usize) {
        self.0.codec_mut().set_max_packet_length(n);
    }

    pub fn is_secured(&self) -> bool {
        self.0.codec().cipher.is_some()
    }

    /// The recv counter (`read_seq`) of the engaged cipher, or 0 if unkeyed — exposed for the
    /// R-T5 cancellation-safety regression test (a dropped `next()` MUST NOT advance it).
    pub fn recv_counter(&self) -> u64 {
        self.0.codec().cipher.as_ref().map_or(0, |c| c.read_seq())
    }

    #[inline]
    pub async fn send(&mut self, msg: &impl Message) -> ResultType<()> {
        self.send_raw(msg.write_to_bytes()?).await
    }

    #[inline]
    pub async fn send_raw(&mut self, msg: Vec<u8>) -> ResultType<()> {
        // R-T5: encryption (and the write_seq advance) is folded into the codec's `encode`; this
        // just enqueues the plaintext frame, which the SecretboxCodec seals then length-frames.
        self.send_bytes(bytes::Bytes::from(msg)).await
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        // R-T2: a poisoned stream is never reused (a prior send/recv error was fatal).
        if self.3 {
            bail!("R-T2: refusing to send on a poisoned stream (a prior send/recv error)");
        }
        let r = self.send_bytes_raw(bytes).await;
        if r.is_err() {
            // R-T2: a send error (incl. a write timeout) is fatal — poison so a later edit
            // cannot reuse the stream and re-flush stale ciphertext under an advanced nonce.
            self.3 = true;
        }
        r
    }

    #[inline]
    async fn send_bytes_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        if self.2 > 0 {
            super::timeout(self.2, self.0.send(bytes)).await??;
        } else {
            self.0.send(bytes).await?;
        }
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        // R-T2: a poisoned stream behaves as EOF — never read again after a fatal error.
        if self.3 {
            return None;
        }
        // R-T5 (§20): reassembly AND decryption+`read_seq` advance happen atomically INSIDE the
        // codec's `decode` (see `SecretboxCodec`) — there is no `.await` between a frame leaving the
        // buffer and the AEAD `open`, so the recv counter advances only on a frame actually
        // delivered, and a decrypt/auth failure (R-T7) surfaces here as `Some(Err(_))`.
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
        let res = self.0.next().await;
        if matches!(res, Some(Err(_))) {
            // R-T2: a read / framing / decrypt-auth failure is fatal — poison the stream so it is
            // never reused (the decrypt now lives in the codec, so this one check covers both).
            self.3 = true;
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

    pub fn set_key(&mut self, key: Key) {
        // R-T5: the cipher lives in the Framed-owned codec.
        self.0.codec_mut().cipher = Some(StreamCipher::Single(Encrypt::new(key)));
    }

    /// Engage the CPace two-key per-direction cipher after a confirmed handshake
    /// (R-P2/R-P10). The keys are role-oriented (the caller's send/recv slots),
    /// so a single key can never end up engaged in both directions.
    pub fn set_session_keys(&mut self, keys: DirectionalKeys) {
        // R-A5: a keyed session stream MUST carry a BOUNDED frame cap before any keyed byte flows.
        // The handshake (cpace.rs) sets MAX_SESSION_PACKET before handing the keys here, so the cap
        // is never the BytesCodec `usize::MAX` default at this choke-point. Assert it fail-closed —
        // an unbounded keyed read would be a speculative-allocation DoS (R-S7), and the assertion
        // is what R-A5 mandates ("max_packet_length is set, not usize::MAX, on every connection").
        assert!(
            self.0.codec().max_packet_length() != usize::MAX,
            "R-A5: keyed stream has an unbounded frame cap (usize::MAX) — the handshake must set MAX_SESSION_PACKET first"
        );
        // R-T5: the cipher lives in the Framed-owned codec.
        self.0.codec_mut().cipher = Some(StreamCipher::Dual(DirectionalCipher::new(&keys)));
    }

    fn get_nonce(seqnum: u64) -> Nonce {
        let mut nonce = Nonce([0u8; secretbox::NONCEBYTES]);
        nonce.0[..std::mem::size_of_val(&seqnum)].copy_from_slice(&seqnum.to_le_bytes());
        nonce
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
    // RUSTDESK_BIND_LOOPBACK (TEST-ONLY): bind 127.0.0.1 instead of 0.0.0.0 so the docker-loopback
    // runtime tests (scripts/smoke-server.sh) never listen on 0.0.0.0. Unset (the production
    // default) = the all-interfaces bind the §17 DMZ box needs. A single env read, no normal-path
    // cost, and the bound port/listener-count the R-A4 socket-surface check asserts is unchanged.
    let bind_addr = if std::env::var("RUSTDESK_BIND_LOOPBACK").is_ok() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    Ok(new_listener_socket(SocketAddr::new(bind_addr, port))?.listen(DEFAULT_BACKLOG)?)
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

impl Encrypt {
    pub fn new(key: Key) -> Self {
        Self(key, 0, 0)
    }

    pub fn dec(&mut self, bytes: &mut BytesMut) -> Result<(), Error> {
        if bytes.len() <= 1 {
            return Ok(());
        }
        self.2 += 1;
        let nonce = FramedStream::get_nonce(self.2);
        match secretbox::open(bytes, &nonce, &self.0) {
            Ok(res) => {
                bytes.clear();
                bytes.put_slice(&res);
                Ok(())
            }
            Err(()) => Err(Error::new(ErrorKind::Other, "decryption error")),
        }
    }

    pub fn enc(&mut self, data: &[u8]) -> Vec<u8> {
        self.1 += 1;
        let nonce = FramedStream::get_nonce(self.1);
        secretbox::seal(&data, &nonce, &self.0)
    }

    pub fn decode(
        symmetric_data: &[u8],
        their_pk_b: &[u8],
        our_sk_b: &box_::SecretKey,
    ) -> ResultType<Key> {
        if their_pk_b.len() != box_::PUBLICKEYBYTES {
            anyhow::bail!("Handshake failed: pk length {}", their_pk_b.len());
        }
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let mut pk_ = [0u8; box_::PUBLICKEYBYTES];
        pk_[..].copy_from_slice(their_pk_b);
        let their_pk_b = box_::PublicKey(pk_);
        let symmetric_key = box_::open(symmetric_data, &nonce, &their_pk_b, &our_sk_b)
            .map_err(|_| anyhow::anyhow!("Handshake failed: box decryption failure"))?;
        if symmetric_key.len() != secretbox::KEYBYTES {
            anyhow::bail!("Handshake failed: invalid secret key length from peer");
        }
        let mut key = [0u8; secretbox::KEYBYTES];
        key[..].copy_from_slice(&symmetric_key);
        Ok(Key(key))
    }
}
