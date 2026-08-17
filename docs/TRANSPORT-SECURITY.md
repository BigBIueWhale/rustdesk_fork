# Transport security — the AEAD frame layer

Companion to [`libs/pake/README.md`](../libs/pake/README.md). The authoritative
external-review handoff is
[`docs/CRYPTO-AUDIT-SCOPE.md`](CRYPTO-AUDIT-SCOPE.md). The PAKE produces two
per-direction keys; **this** layer is what encrypts every byte after the
handshake and is the second half of the R-V3 audit surface (the "secretbox
parameters" R-V3 names). It is the §20 transport: `libs/hbb_common/src/cpace.rs`
(the cipher halves) and `libs/hbb_common/src/tcp.rs` (the framing, the stream
state machine, and the dedicated writer task). **R-V3 remains outstanding**;
this project-authored claim map is not independent sign-off.

The security claim: once keyed, **every** frame in **both** directions is
sealed under a distinct key with a never-reused nonce, authenticated before it
can reach any parser, with no plaintext escape and no path by which a write
error, cancellation, or back-pressure can replay, reorder, skip, or leak.

Pointers below use file and symbol names rather than source line numbers.

---

## 1. Cipher and parameters

* **AEAD:** XSalsa20-Poly1305 via `sodiumoxide::crypto::secretbox`
  (`libs/hbb_common/src/cpace.rs`; `sodiumoxide = "0.2"`, a libsodium binding).
  `KEYBYTES = 32`,
  `NONCEBYTES = 24`, `MACBYTES = 16`.
* **Keys:** the two role-oriented 32-byte keys from the PAKE
  (`DirectionalKeys.send` / `.recv`, HKDF-SHA512 `c2s`/`s2c` — see the PAKE
  doc §1). Each direction uses its own key.
* **Nonce (`cpace::cipher_nonce`):** a 24-byte nonce whose low 8 bytes
  are a little-endian `u64` monotonic counter and whose high 16 bytes are zero;
  the first frame uses `LE64(1)`. Uniqueness does **not** rely on the high bytes
  — it is guaranteed by the counter being monotonic and non-wrapping (§2) within
  a direction, and each direction having a *distinct key*. So a given
  `(key, nonce)` pair is never produced twice.

---

## 2. Nonce discipline — never reuse `(key, nonce)` (R-A5)

A repeated `(key, nonce)` is the catastrophic XSalsa20-Poly1305 failure
(keystream reuse + Poly1305 forgery). Three independent guarantees:

1. **Distinct keys both ways.** `cpace::split_session_keys` engages
   `send_key`/`recv_key` and **asserts they differ** — a keying-mis-wire
   regression that engaged one key both ways (the inherited symmetric-`set_key`
   bug) fails closed here, the one case the wire-capture test can't catch since
   the keys are never attacker-influenced.
2. **Monotonic, non-wrapping counter — send.** `cpace::SealCipher::seal`
   pre-increments `write_seq` with `checked_add(1)` and
   `expect`s — at the physically-unreachable 2^64-frame exhaustion it
   **fail-closes** (panics) rather than wrap to a used nonce. The MUST is "not a
   counter reset"; aborting is its conservative form.
3. **Monotonic, non-wrapping counter — recv.** `cpace::OpenCipher::open`
   `fetch_add(1)`s, returns the new value as the nonce, and if
   the previous value was `u64::MAX` returns `Err(())` so the connection tears
   down — the wrapped-to-0 counter is never used to open.

**Ordering invariant.** The send seal happens on the *single-producer enqueue
side* (`FramedStream::send_bytes`, not the codec), and a single writer task
drains the channel in FIFO order, so **seal order == channel order == wire
order** (`tcp::writer_task`). The counter therefore matches the peer's receive
order exactly — no gaps, no reordering of the nonce sequence.

---

## 3. Authenticate every frame — no plaintext escape (R-T7)

`tcp::SecretboxCodec::decode`:

1. Reassemble exactly **one** complete frame via the length-delimited inner
   codec.
2. If a recv cipher is engaged, `open()` the **whole** frame; on `Err` return a
   decryption error (drops the connection). There is **no ≤1-byte passthrough**
   and no "small frames skip the AEAD" branch. A genuine sealed frame is always
   ≥ `MACBYTES` (seal appends a 16-byte tag even to a 0-byte plaintext), so any
   shorter injected frame cannot be valid ciphertext and `secretbox::open`
   rejects it.

This closes the only path by which an unauthenticated byte could reach the
application parser (and the worst-case carry-over channel for R-T6). The encode
side is length-framing only — the producer pre-seals in
`FramedStream::send_bytes` before `SecretboxCodec::encode` frames it.

---

## 4. Cancellation safety (R-T5)

A `select!`-dropped `FramedStream::next` must neither replay nor skip a frame:

* `decode` reassembles one frame; a partial frame returns `Ok(None)` with **no
  counter advance** — a dropped poll never half-consumes.
* `OpenCipher::open` is the **sole** writer of `read_seq` and advances it with
  **no `.await` between** reading the count and advancing it
  — so a cancellation point cannot interleave to replay or skip the counter.

The `read_seq` lives behind an `Arc<AtomicU64>` only so `recv_counter` can
observe it after the codec is moved into the split read half; the producer never
touches it, `open` is the only writer, so `Relaxed` ordering suffices
(`OpenCipher::read_seq_handle` / `FramedStream::recv_counter`). An R-T5
regression test asserts a dropped `next` does not
advance the counter.

---

## 5. Single writer, poison, and bounded back-pressure (R-T2 / R-T3 / R-T8)

* **One writer, ever (R-T8).** After keying, the `Framed` is `split()` once: the
  read half stays on the run-loop; the write half (`SplitSink`) is owned by a
  single dedicated `writer_task` — the **sole** sink consumer
  (`FramedStream::set_session_keys` / `writer_task`). The stream is never
  wrapped in `Arc<Mutex<…>>`; two concurrent
  writers (which would interleave nonces) are structurally impossible.
* **Non-blocking exact admission + refusal ⇒ drop (R-T3 / R-T18).**
  `FramedStream::send_bytes` computes the checked secretbox ciphertext length
  and validates it against the exact packet ceiling engaged at keying.
  Admission is reserved before secretbox sealing, so an oversized or back-pressured frame
  allocates no ciphertext and advances no nonce. One owned frame permit and the
  exact ciphertext-byte permits then travel in `WriterCommand::Frame` and remain
  held through `sink.send`: even after Tokio returns channel capacity at dequeue,
  the active sink frame still owns its permits. Active plus queued retention is
  therefore at most 512 frames and two engaged maximum ciphertext packets. Both
  acquisitions and the FIFO handoff use non-blocking `try_*` operations; any
  size, count, byte, closed-admission, or channel refusal poisons the stream,
  closes admission, and aborts the exact writer rather than blocking the run-loop
  inside a `select!`. On sink failure the encoded sink is dropped before its
  reservation is released. This replaces the old count-only channel assumption;
  the shared writer carries peer-influenced media, file, clipboard, tunnel, and
  control traffic and is not trusted as an encoder-bounded server-only source.
* **Poison (R-T2).** Any send/recv error calls the single
  `poison_and_retire_writer` transition. A poisoned stream refuses all further
  sends, keyed admission closes, and the exact writer is aborted — so a later
  code path cannot reuse the stream and re-flush under an advanced nonce or
  retain active/queued ciphertext until outer teardown happens to run.
* **Drop aborts the writer (`FramedStream::drop`).** Dropping the `FramedStream`
  aborts the writer task immediately, so a write parked on a dead/back-pressured
  socket cannot leak the task (and its half of the split socket) past the
  connection's lifetime.

---

## 6. Frame cap (R-S7 / R-T11)

The keyed stream's `max_packet_length` is **fixed at keying** and asserted to be
non-`usize::MAX` before the keys are engaged
(`FramedStream::set_session_keys`, `MAX_SESSION_PACKET`); setting it after
keying panics (`FramedStream::set_max_packet_length`). So an
attacker-advertised huge frame length is rejected and its speculative allocation
bounded — a partial read cannot drive unbounded memory.

---

## 7. Threat model — an active network attacker is reduced to denial of service (§2 / §20 / R-V1)

The transport assumes the *strongest* network adversary: an active attacker on
the path — up to and including a **fully compromised router** — that can inject,
drop, modify, replay, reorder, reset, segment, coalesce, and **manipulate TCP
flow control** at will, on both the controlled (responder) and viewer (initiator)
sides. Against this attacker the construction guarantees the worst achievable
outcome is a **denial of service**; confidentiality, integrity, and
authentication never degrade:

| Active manipulation | Outcome |
|---|---|
| Inject / modify a **post-key** frame | Fails the Poly1305 tag (§3, R-T7 — no ≤1-byte bypass) → stream poisoned → fail-closed |
| Reorder / replay / drop frames | Desyncs the per-direction monotonic nonce (§2, R-A5) → tag fails → abort |
| MITM first contact | Cannot complete the mutual CPace PAKE without the password (R-S1) |
| Substitute its own endpoint | Without the password, cannot complete the mutual CPace PAKE (same as first-contact MITM). A substitute that *knows* the password is out of scope by §2 (password secrecy is assumed) — the balanced PAKE authenticates whoever holds the shared secret, with no separate long-term device identity to forge |
| Replay a whole captured session | A fresh responder `sid_b`/`Yb` diverges the ISK → key-confirmation fails (R-P14c) |
| Inject malformed **pre-key** bytes | The only pre-key parsers — the frame codec, `protobuf` 3.7.2 (recursion/alloc/varint bounded, R-A7), and the CPace fixed-length fields (`exact::<N>`) — are panic-free, so injected garbage is a clean error, never a `panic='abort'` process crash |
| RST / SYN flood / drop the connection | A pure availability attack, inherent to TCP and unpreventable at this layer; no confidentiality/integrity impact |

**Bounding the pre-key handshake against flow-control manipulation.** The one
place an active router reaches *un-authenticated* code is the CPace handshake
(before keys are engaged). Both directions are deadline-bounded so a router
cannot hold resources open indefinitely: `recv_cpace` reads under
`HANDSHAKE_STEP_TIMEOUT_MS` and `send_cpace` wraps its send in the *same*
deadline (`cpace.rs`). The send bound is load-bearing under this model — a router
that forges a zero-window advertisement or drops ACKs can stall a send of even a
sub-buffer-sized frame forever, and without the deadline the responder would
block holding its R-T1 connection-flood permit (exhausting the semaphore to deny
legitimate handshakes; keepalive cannot help — the router ACKs probes while
pinning the window at zero). The permit is also acquired *before* any per-socket
setup, so a shed connection under a flood costs accept+close, not
accept+setsockopt+close (`direct_service.rs`, §20.0 "shed cheaply, early").

**Residuals (bounded, accepted).** A slowloris router can hold a handshake permit
up to ~4 × `HANDSHAKE_STEP_TIMEOUT_MS` before it recycles — bounded by the
per-step deadlines and the generous semaphore budget; the systemd cgroup ceilings
(`MemoryMax`/`TasksMax`/`LimitNOFILE`) bound the blast radius to the service, not
the host. RST/SYN-level denial is inherent to TCP. Neither affects
confidentiality, integrity, or authentication.

---

## Audit pointers and test basis

| R-V3 / §20 concern | Where |
|---|---|
| AEAD choice + key install | `cpace::split_session_keys`, `tcp::FramedStream::set_session_keys` |
| Nonce never-reuse | `cpace::cipher_nonce`, `SealCipher::seal`, `OpenCipher::open` |
| Distinct-keys assert | `cpace::split_session_keys` |
| Authenticate-all / no bypass | `tcp::SecretboxCodec::decode` |
| Cancellation safety | `cpace::OpenCipher::open`, `tcp::SecretboxCodec::decode` / `FramedStream::next` |
| Single writer / poison / back-pressure | `tcp::FramedStream::send_bytes`, `writer_task`, `FramedStream::drop` |
| Frame cap | `tcp::FramedStream::set_max_packet_length` / `set_session_keys` |
| Pre-key handshake deadlines (both directions) | `cpace::recv_cpace` / `send_cpace` (`HANDSHAKE_STEP_TIMEOUT_MS`) |
| Connection-flood shed (permit before socket setup) | `direct_service.rs` accept loop, `server.rs` `PREKEY_HANDSHAKE_SLOTS` |

**Runtime test basis.** The integration `cpace_it` suite drives two real
`FramedStream`s through keying and asserts: replay/reorder/duplicate-first-frame
rejection, oversize-pre-PAKE rejection, FIFO ordering, the writer-channel-full
drop, and R-T5 cancellation non-advance. `scripts/smoke-server.sh` exercises the
live binary: forged-frame AEAD rejection (R-A8, via `corrupt_send_key_for_test`,
in `cpace.rs`), the owner-safe per-IP limiter (R-S10), and a `tcpdump`
wire-capture asserting no plaintext on the wire (R-A9). Both are gated by
`scripts/verify.sh`.

Findings file against `requirements.html` §20 / §11 and resolve or risk-accept
in writing before the "not independently audited" disclosure is removed.
