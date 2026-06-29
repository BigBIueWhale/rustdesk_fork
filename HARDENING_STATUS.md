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

**Validation (2026-06-28/29):** `scripts/verify.sh` is **all-gates-green**
(PAKE KATs + wire handshake + two-key cipher + R-S16 policy funnel + main-crate
compile under `linux-pkg-config,unix-file-copy-paste` + the R-A6 done-set
greps). The full server binary builds and the loopback runtime smoke
(`scripts/smoke-server.sh`) exercises the one-TCP/zero-UDP surface, fail-closed
startup, graceful shutdown, and the no-plaintext wire-capture. The reproducible
release builds are re-proven at HEAD: the Debian `.deb` (Flutter) builds offline,
and the Windows `.exe`/`.msi` R-B2 double-build is byte-identical (A==B: exe
`b87a9b6b…`, msi `5d023302…`). The Windows VM build — the only path that
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
- **Protobuf parser attack-surface audit (TODO — not yet performed; high
  priority).** The `protobuf` crate (rust-protobuf) **v3.7.2** (crates.io,
  `Cargo.lock` checksum `d65a1d4ddae7d8b5de68153b48f6aa3bba8cb002b243dbdbc55a5afbc98f99f4`)
  is the **first code that touches attacker bytes** on both surfaces: the
  *unauthenticated, pre-key* `parse_from_bytes::<Cpace>` (the sole pre-auth
  parser, R-S7/R-P14) and the post-key full `Message`-union `parse_from_bytes`
  (connection.rs / io_loop.rs). Every hardening above *assumes* this decoder is
  memory-safe and panic-free on malformed input — and with `panic = 'abort'`
  (release, Cargo.toml) **any decoder panic is a whole-process DoS**, so the
  assumption is load-bearing and unverified. **Task:** clone the exact pinned
  source into `/tmp` (`rust-protobuf` at tag `v3.7.2`, or fetch the crates.io
  `.crate` and verify it matches the lockfile checksum above), then audit its
  **runtime** decode path — `CodedInputStream`, varint/tag/length-delimited
  decoding, nested-message and group recursion, `UnknownFields`, string/bytes
  length handling — for attacker-reachable: (a) panics (index-OOB, unwrap,
  slice, debug-assert), (b) **unbounded recursion → stack overflow** via deeply
  nested submessages (the 4 KiB pre-key / 32 MiB post-key frame cap bounds total
  *input size* but **not nesting depth** — a few KB can nest thousands deep),
  (c) unbounded allocation / `reserve` from an attacker length prefix, (d)
  integer-overflow/truncation in length/varint math, and (e) non-termination /
  quadratic blowup. Cross-check RUSTSEC + the crate's changelog for known parse
  CVEs/fixes after 3.7.2. **The load-bearing question: can a malformed pre-auth
  `Cpace` frame crash, hang, or OOM the responder before keying?** If a real
  defect is found, the fix is a bounded/recursion-limited decode wrapper or a
  crate bump (re-pinned per R-B5a/`--locked`). (Build-time `protobuf-codegen`/
  `protobuf-parse` are out of scope — not attacker-reachable.)
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
