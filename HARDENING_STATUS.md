# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Superseded work-log material (intermediate `PARTIAL`/`TODO`/deferred
notes, and — as of 2026-06-28 — the reverted native-worker-sandbox slices) is
removed from this live ledger because it is misleading as current status. Git
history remains the traceability record for that intermediate work.

## Current Verdict

**Status: the cryptographic/transport core and the direct-IP-only posture are in
place and gated.** The single mandatory CPace PAKE runs at the `create_tcp_connection`
choke point before any application message, on every transport, with the `secure`
parameter deleted (R-S1/R-P14); authorization collapses onto the lone CPace
`KEYED` edge (R-S2/R-A2, one `self.authorized = true` site); the session cipher
uses two distinct per-direction keys split into a producer `SealCipher` and a
codec `OpenCipher` (R-P2/R-P10/R-T3), every keyed frame is AEAD-authenticated
with no short-frame bypass (R-T7), and the `set_raw` plaintext-tunnel escape is
sealed to a backstop with no app caller (R-S5/R-A3). The rendezvous mediator,
relay, KCP, `udp_nat_connect`, and LAN discovery are compiled out so the exposed
`--server` binds exactly one v4-only TCP port and zero UDP (R-D3/R-D4/R-D5,
asserted at startup by R-A4); egress is silent by construction (R-D6/§18); the
§8 excisions (auto-updater, plugin loader, `ConfigureUpdate`, trust-anchor
overrides, `os_login`→PAM, terminal root-PTY policy-lock, the OTP/2FA cluster)
are done and CI-grepped absent (R-A6); the R-S16 compile-time policy funnel pins
the controlled-side security options; the §19 Flutter GUI conformance and the
§20 TCP transport-correctness/cancellation-safety/DMZ-flood requirements are
implemented. The §4.2/§20 post-key DoS bounds are in place: bounded peer video
display/decode queues, Opus/zstd input caps and the R-S7 decompressed-output
ceiling, bounded peer screenshot/PeerInfo/UI-text/file-transfer admission,
display-control validation, FUSE mount-point no-follow setup and bounded
FileContents response queue, and the FILEDESCRIPTOR path-traversal sanitizer
(`sanitize_relative_names`) with its count cap (`MAX_FILE_DESCRIPTORS`). The
file-clipboard serve/confirm paths are additionally arithmetic/index-safe — the
peer-supplied `file_num` is bounded before indexing in `set_stream_offset`, the
CLIPRDR file-read clamps `length` to the remaining bytes with no `offset+length`
wrap, and the descriptor serializer truncates an over-long name with no
`520 - name_len` underflow (each overflow-safe, unit-tested). The
build is reproducible for Debian/Android/Windows (R-B2), and the Apple
SDK-free source-conformance gate covers the macOS/iOS code paths (R-R2).

**§20 TCP active-router audit (2026-06-29).** The full TCP transport — both the
controlled (responder) and viewer (initiator) sides — was audited under the
*strongest* network-adversary model: both peers connected through a fully
malicious router that can inject / drop / modify / replay / reorder / reset /
segment / coalesce / flow-control-manipulate the connection at will. The
cryptographic construction reduces this attacker to (at most) a DoS: post-key
manipulation fails the Poly1305 tag (R-T7, no ≤1-byte bypass) → poison →
fail-closed; reorder/replay/drop desync the per-direction monotonic nonce
(R-A5); first-contact MITM fails the mutual PAKE; substitution fails the R-S17
Ed25519 host-proof bound to the session transcript; and the pre-key parsers
(frame codec, protobuf 3.7.2, CPace fixed-length fields) are panic-free, so
injected garbage cannot crash the `panic='abort'` process. One genuine DoS lever
the model surfaced was **fixed** (`f1ecfb0`): the pre-key handshake *sends* had
no deadline (only reads did), so a router stalling flow control (forged
zero-window / dropped ACKs) could block a send forever and hold an R-T1
handshake permit indefinitely — `send_cpace` now carries the same per-step
deadline as `recv_cpace` (handshake fully step-bounded both directions; new
verify.sh R-T1 gate). The accept-path bound (R-T1 semaphore + host-relative
cgroup ceilings), cancellation safety (R-T2–T5 writer-task / poison / Drop
cleanup), socket options (R-T10 keepalive / R-T11 no-`SO_REUSEPORT`), accept
observability (R-T12), and graceful shutdown (R-T9) were each confirmed
conformant on both sides.

**Validation (2026-06-28/29):** `scripts/verify.sh` is **all-gates-green**
(PAKE KATs + wire handshake + two-key cipher + R-S16 policy funnel + main-crate
compile under `linux-pkg-config,unix-file-copy-paste` + the R-A6 done-set
greps). The full server binary builds and the loopback runtime smoke
(`scripts/smoke-server.sh`) exercises the one-TCP/zero-UDP surface, fail-closed
startup, graceful shutdown, and the no-plaintext wire-capture. The reproducible
release builds hold: the Debian `.deb` (Flutter) R-B2 double-build is
byte-identical (A==B) and was **re-proven at the post-audit HEAD `5cd5907` →
`c2d9aa04…`** — this session's transport/parser hardening (cpace send-deadline,
accept-shed reorder, fs/clipboard arithmetic fixes) does **not** regress
reproducibility — and the Windows `.exe`/`.msi` R-B2 double-build is
byte-identical (A==B: exe `b87a9b6b…`, msi `5d023302…`, at `b1ed623`; a Windows
rebuild at this HEAD needs the §12.2 KVM VM + the build-host-network sudo, so
`dist/SHA256SUMS-HEAD.txt` remains the last full three-platform snapshot at
`b1ed623`). The Windows VM build — the only path that
compiles the `cfg(windows)` code — caught a worker-revert base-restore residual
(a dropped `as Box<_>` trait-object coercion in the CLIPRDR clipboard dispatch,
`libs/clipboard/src/platform/mod.rs`) that the Linux gates structurally cannot
see; it is fixed (008e2ba) and the in-VM honesty gate prevented any stale
artifact from shipping.

## Appendix C #2b (native-decode RCE surface) — ACCEPTED residual

Per the spec, Appendix C #2b — a full viewer decoding a hostile-but-password-correct
peer's media through in-process C codecs (libvpx/aom/libyuv/opus/zstd + Windows
CLIPRDR) — is dispositioned **`ACCEPT` + SHOULD-sandbox**: "a *universal residual*
... bounded operationally (connect only to peers you trust) ... recorded as a
**documented residual** not closable by keying — the fork SHOULD sandbox the
decode path." It is **not** a MUST.

A prior session (2026-06-26→28) built a large worker-subprocess sandbox for #2b —
hidden same-artifact `--native-*-worker` roles, a `native_worker_sandbox` helper
(seccomp-BPF / Seatbelt / Windows Job-Object / token confinement), and Android
`isolatedProcess` services for video/Opus/zstd/clipboard. On **2026-06-28** that
subsystem was **reverted** in full, by maintainer decision and per the spec's
`ACCEPT` disposition: it was the project's single largest net addition for a
SHOULD-level residual, it fought the spec's defend-by-deletion philosophy, it
re-introduced the hidden-argv multi-tool pattern §8 excises, and its fail-closed
no-fallback design risked the MUST content channels (R-S4/R-F1) when a worker was
unavailable. Video, Opus, zstd, clipboard, CLIPRDR, Unix file-copy, and the
Windows printer path are restored to **in-process** decode/decompress/handoff
(upstream behaviour), and the worker modules/sandbox/Android services are deleted.
**#2b therefore stands as the documented accepted residual the spec prescribes**,
to be closed later — if at all — by sandboxing the decode path, bounded
operationally in the meantime.

On the same date a separate beyond-spec change (f0b9966) that had disabled the
desktop viewer's GPU texture-upload display path — routing decoded peer RGBA
through the native `texture_rgba_renderer` plugin — was also **reverted** by
maintainer decision, restoring upstream GPU rendering. That plugin is
**#2b-adjacent native viewer surface**, but distinct from and smaller than the
decode residual itself: it receives already-decoded, shape/length-validated RGBA
(no compressed-codec or container parser), and the soft `CustomPaint` fallback it
replaced hands the same validated pixels to Skia's native image decode — so no
decoder/parser surface is removed either way. With hwcodec compiled out, the
texture upload was the desktop pipeline's only GPU acceleration; disabling it made
every desktop viewer fully CPU-bound for display at no real security gain. It is
accepted alongside #2b (viewer-side only; desktop Windows/Debian/macOS — Android
and iOS already software-render).

The genuinely-good companion work from that session is **kept**: the post-key
DoS bounds above (R-T0/R-S7/R-S10), the `sanitize_relative_names` path-traversal
defense, the bounded in-process clipboard-SET dispatcher (anti thread-amplification),
the FUSE mount/queue hardening, the insecure-TLS-fallback excision, the native
codec advisory-watch (`docs/NATIVE-CODEC-WATCH.md`), the `rustdesk-org` Dart
git-fork SHA pins (R-B12), and the upstream-doc-link removal.

## Open residuals (tracked, not regressions)

- **Appendix C #2b decode sandbox** — accepted residual (above); SHOULD, not MUST.
- **Desktop GPU texture-upload display** — #2b-adjacent native viewer surface
  (`texture_rgba_renderer`), restored 2026-06-28 (f0b9966 revert); accepted
  alongside #2b — already-validated pixels, no parser, viewer/desktop-only.
- **R-V3 independent CPace audit** — the in-tree CPace implementation is
  vector/KAT-conformant and adversarially tested but **not yet independently
  audited**; the §11 "not independently audited" disclosure stands.
- **Protobuf parser attack-surface audit — ✅ PERFORMED 2026-06-29; parser
  SOUND for our threat model.** The `protobuf` crate (rust-protobuf) **v3.7.2**
  (crates.io, `Cargo.lock` checksum
  `d65a1d4ddae7d8b5de68153b48f6aa3bba8cb002b243dbdbc55a5afbc98f99f4`) is the
  **first code that touches attacker bytes** — the unauthenticated pre-key
  `parse_from_bytes::<Cpace>` (sole pre-auth parser, R-S7/R-P14) and the post-key
  full `Message`-union parse (connection.rs / io_loop.rs) — and with
  `panic = 'abort'` any decoder panic/OOM/hang is a whole-process DoS, so this
  assumption was load-bearing. Audited the exact pinned source (cloned
  `rust-protobuf` tag `v3.7.2` → `/tmp`, runtime crate version confirmed 3.7.2).
  Findings — every relevant DoS vector is **defended**: (a) **stack overflow** —
  `CodedInputStream` enforces `DEFAULT_RECURSION_LIMIT = 100` via
  `incr_recursion()?`/`decr_recursion()` around every nested-message and
  group/unknown-field read on the **static** path; the incr/decr are balanced
  (decr only after a successful incr, so no underflow panic). (b) **OOM** —
  `read_exact_to_vec` validates the claimed length against `bytes_until_limit()`
  **before any allocation** (so a length prefix can't exceed the actual bounded
  input), and the speculative reserve is capped at `READ_RAW_BYTES_MAX_ALLOC =
  10 MB` (growing incrementally past that). (c) **varint** non-termination /
  overflow — capped at `MAX_VARINT_ENCODED_LEN = 10` bytes with a 10th-byte
  overflow guard, error-not-panic. (d) Both relevant advisories are fixed in
  **exactly this pin**: RUSTSEC-2024-0437 (uncontrolled-recursion crash via
  unknown-field parsing, `patched >= 3.7.2`) and RUSTSEC-2019-0003
  (`Vec::reserve` on user input, `patched >= 2.6.0`); no advisory requires
  `> 3.7.2`. RustDesk parses **only via the static, recursion-checked path**
  (`T::parse_from_bytes`; no `merge_message_dyn`/reflection of untrusted bytes).
  Our own frame cap (4 KiB pre-key / 32 MiB post-key) is defense-in-depth on top.
  A new `verify.sh` gate pins the parser-safety floor (`protobuf >= 3.7.2` in
  `Cargo.lock`, the RUSTSEC-2024-0437 fix). **Forward-looking residual (not
  currently reachable):** `merge_message_dyn` lacks the recursion incr/decr — if
  reflection-based dynamic parsing of untrusted input is ever added, it would
  bypass the depth limit; the gate + this note flag it.
- **Apple artifacts** — macOS/iOS are source-conformed (R-R2 retain-and-check),
  not built; full artifacts need the Apple SDK/toolchain path.
- **R-R3 dependency-advisory gates** — `cargo audit`/`cargo deny` (`scripts/audit.sh`)
  and `osv-scanner` (`scripts/dart-audit.sh`) are wired; the documented-accept
  ledger is maintained there.

The requirements snapshot reviewed in this pass was:

```text
d34aad84c44e8b919e72130eecb78e3f06e3f19a8d667a2219402e8225c90dc1  requirements.html
```

`requirements.html` is intentionally not edited by implementation work.
