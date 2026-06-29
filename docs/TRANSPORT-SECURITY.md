# Transport security — the AEAD frame layer

Companion to [`libs/pake/README.md`](../libs/pake/README.md). The PAKE produces
two per-direction keys; **this** layer is what encrypts every byte after the
handshake and is the second half of the R-V3 audit surface (the "secretbox
parameters" R-V3 names). It is the §20 transport: `libs/hbb_common/src/cpace.rs`
(the cipher halves) and `libs/hbb_common/src/tcp.rs` (the framing, the stream
state machine, and the dedicated writer task).

The security claim: once keyed, **every** frame in **both** directions is
sealed under a distinct key with a never-reused nonce, authenticated before it
can reach any parser, with no plaintext escape and no path by which a write
error, cancellation, or back-pressure can replay, reorder, skip, or leak.

Line references are to `cpace.rs`/`tcp.rs` as noted.

---

## 1. Cipher and parameters

* **AEAD:** XSalsa20-Poly1305 via `sodiumoxide::crypto::secretbox`
  (`cpace.rs:27`; `sodiumoxide = "0.2"`, a libsodium binding). `KEYBYTES = 32`,
  `NONCEBYTES = 24`, `MACBYTES = 16`.
* **Keys:** the two role-oriented 32-byte keys from the PAKE
  (`DirectionalKeys.send` / `.recv`, HKDF-SHA512 `c2s`/`s2c` — see the PAKE
  doc §1). Each direction uses its own key.
* **Nonce (`cipher_nonce`, `cpace.rs:377`):** a 24-byte nonce whose low 8 bytes
  are a little-endian `u64` monotonic counter and whose high 16 bytes are zero;
  the first frame uses `LE64(1)`. Uniqueness does **not** rely on the high bytes
  — it is guaranteed by the counter being monotonic and non-wrapping (§2) within
  a direction, and each direction having a *distinct key*. So a given
  `(key, nonce)` pair is never produced twice.

---

## 2. Nonce discipline — never reuse `(key, nonce)` (R-A5)

A repeated `(key, nonce)` is the catastrophic XSalsa20-Poly1305 failure
(keystream reuse + Poly1305 forgery). Three independent guarantees:

1. **Distinct keys both ways.** `split_session_keys` (`cpace.rs:476`) engages
   `send_key`/`recv_key` and **asserts they differ** (l.480) — a keying-mis-wire
   regression that engaged one key both ways (the inherited symmetric-`set_key`
   bug) fails closed here, the one case the wire-capture test can't catch since
   the keys are never attacker-influenced.
2. **Monotonic, non-wrapping counter — send.** `SealCipher::seal`
   (`cpace.rs:401`) pre-increments `write_seq` with `checked_add(1)` and
   `expect`s — at the physically-unreachable 2^64-frame exhaustion it
   **fail-closes** (panics) rather than wrap to a used nonce. The MUST is "not a
   counter reset"; aborting is its conservative form.
3. **Monotonic, non-wrapping counter — recv.** `OpenCipher::open`
   (`cpace.rs:444`) `fetch_add(1)`s, returns the new value as the nonce, and if
   the previous value was `u64::MAX` returns `Err(())` so the connection tears
   down — the wrapped-to-0 counter is never used to open.

**Ordering invariant.** The send seal happens on the *single-producer enqueue
side* (`FramedStream::send_bytes`, not the codec), and a single writer task
drains the channel in FIFO order, so **seal order == channel order == wire
order** (`tcp.rs:50-53`, `cpace.rs:368`). The counter therefore matches the
peer's receive order exactly — no gaps, no reordering of the nonce sequence.

---

## 3. Authenticate every frame — no plaintext escape (R-T7)

`SecretboxCodec::decode` (`tcp.rs:86`):

1. Reassemble exactly **one** complete frame via the length-delimited inner
   codec.
2. If a recv cipher is engaged, `open()` the **whole** frame; on `Err` return a
   decryption error (drops the connection). There is **no ≤1-byte passthrough**
   and no "small frames skip the AEAD" branch. A genuine sealed frame is always
   ≥ `MACBYTES` (seal appends a 16-byte tag even to a 0-byte plaintext), so any
   shorter injected frame cannot be valid ciphertext and `secretbox::open`
   rejects it (`tcp.rs:92-98`).

This closes the only path by which an unauthenticated byte could reach the
application parser (and the worst-case carry-over channel for R-T6). The encode
side is length-framing only — the producer pre-seals (`encode`, `tcp.rs:118`).

---

## 4. Cancellation safety (R-T5)

A `select!`-dropped `FramedStream::next` must neither replay nor skip a frame:

* `decode` reassembles one frame; a partial frame returns `Ok(None)` with **no
  counter advance** — a dropped poll never half-consumes (`tcp.rs:87-88`).
* `OpenCipher::open` is the **sole** writer of `read_seq` and advances it with
  **no `.await` between** reading the count and advancing it (`cpace.rs:442-449`)
  — so a cancellation point cannot interleave to replay or skip the counter.

The `read_seq` lives behind an `Arc<AtomicU64>` only so `recv_counter` can
observe it after the codec is moved into the split read half; the producer never
touches it, `open` is the only writer, so `Relaxed` ordering suffices
(`cpace.rs:420-426`). An R-T5 regression test asserts a dropped `next` does not
advance the counter.

---

## 5. Single writer, poison, and bounded back-pressure (R-T2 / R-T3 / R-T8)

* **One writer, ever (R-T8).** After keying, the `Framed` is `split()` once: the
  read half stays on the run-loop; the write half (`SplitSink`) is owned by a
  single dedicated `writer_task` — the **sole** sink consumer (`tcp.rs:539-548`,
  `570-586`). The stream is never wrapped in `Arc<Mutex<…>>`; two concurrent
  writers (which would interleave nonces) are structurally impossible.
* **Non-blocking enqueue + full ⇒ drop (R-T3).** `send_bytes` (`tcp.rs:417`)
  seals, then `try_send`s into a **bounded** channel (`WRITER_CHANNEL_CAP = 512`,
  `tcp.rs:568`). A full channel means the peer can't drain — the connection is
  dropped (`tcp.rs:448-456`) rather than blocking the run-loop inside a
  `select!`. This bounded channel *replaces* the old per-write timeout as the
  back-pressure liveness signal. Outbound frame sizes are server-generated
  (encoder-bounded, not attacker-controlled), so the buffer is not an
  attacker-driven memory lever.
* **Poison (R-T2).** Any send/recv error sets `poison` (`tcp.rs:204, 419-426`);
  a poisoned stream refuses all further sends — so a later code path cannot
  reuse the stream and re-flush under an advanced nonce.
* **Drop aborts the writer (`tcp.rs:588-595`).** Dropping the `FramedStream`
  aborts the writer task immediately, so a write parked on a dead/back-pressured
  socket cannot leak the task (and its half of the split socket) past the
  connection's lifetime.

---

## 6. Frame cap (R-S7 / R-T11)

The keyed stream's `max_packet_length` is **fixed at keying** and asserted to be
non-`usize::MAX` before the keys are engaged (`tcp.rs:528-531`,
`MAX_SESSION_PACKET`); setting it after keying panics (`tcp.rs:383`). So an
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
| Substitute its own endpoint (even one that knows the password) | Fails the R-S17 Ed25519 host-proof signed over this session's transcript (`sid‖CI‖Ya‖Yb`) — a substitute lacks the pinned private key |
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
| AEAD choice + key install | `cpace.rs:476` `split_session_keys`, `tcp.rs:516-549` `set_session_keys` |
| Nonce never-reuse | `cpace.rs:377` (`cipher_nonce`), `:401` (`seal`), `:444` (`open`) |
| Distinct-keys assert | `cpace.rs:480` |
| Authenticate-all / no bypass | `tcp.rs:86` (`decode`) |
| Cancellation safety | `cpace.rs:444-449`, `tcp.rs:86-89` |
| Single writer / poison / back-pressure | `tcp.rs:417` (`send_bytes`), `:574` (`writer_task`), `:588` (`Drop`) |
| Frame cap | `tcp.rs:528`, `:379-386` |
| Pre-key handshake deadlines (both directions) | `cpace.rs` `recv_cpace` / `send_cpace` (`HANDSHAKE_STEP_TIMEOUT_MS`) |
| Connection-flood shed (permit before socket setup) | `direct_service.rs` accept loop, `server.rs` `PREKEY_HANDSHAKE_SLOTS` |

**Runtime test basis.** The integration `cpace_it` suite drives two real
`FramedStream`s through keying and asserts: replay/reorder/duplicate-first-frame
rejection, oversize-pre-PAKE rejection, FIFO ordering, the writer-channel-full
drop, and R-T5 cancellation non-advance. `scripts/smoke-server.sh` exercises the
live binary: forged-frame AEAD rejection (R-A8, via `corrupt_send_key_for_test`,
`cpace.rs:415`), the owner-safe per-IP limiter (R-S10), and a `tcpdump`
wire-capture asserting no plaintext on the wire (R-A9). Both are gated by
`scripts/verify.sh`.

Findings file against `requirements.html` §20 / §11 and resolve or risk-accept
in writing before the "not independently audited" disclosure is removed.
