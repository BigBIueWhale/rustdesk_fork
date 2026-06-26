# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Older work-log material was removed from this live ledger on
2026-06-26 because it contained superseded `PARTIAL`, `TODO`, and deferred-work
claims that were useful historically but misleading as current status. Git
history remains the traceability record for those intermediate notes.

## Current Verdict

**Status: file-transfer parent-walk, Windows/Android socket-surface,
native-codec advisory-watch, native media/clipboard handoff-bound follow-ups,
and Apple SDK-free source-conformance are closed in source and gates;
responder-side port-forward latent-connect and file write-response forwarding
follow-ups remain closed. The native decoder sandbox itself remains open.**

On 2026-06-26, final reviewer `Maxwell` (`gpt-5.5`, `xhigh`) reviewed the
then-current dirty worktree, read the full `requirements.html`, checked the previous
blocker classes, and returned **PASS** with no blocking findings.
That review predates the current Apple source-conformance fix and artifact
refresh, so it is retained as historical evidence, not a current final-completion
claim.

After commit `f90f197`, three additional read-only route/security audits were
run against the exposed TCP paths. The server/responder audit passed, and the
whole-route bypass audit did not find a CPace/AEAD/authorization bypass. The
client/initiator audit found one in-repository conformance gap: stale relay
suffix syntax (`/r`, `/r@...`) could still pass through a desktop URI/CLI route,
be normalized into a direct address, and persist stale relay state. That finding
did not revive relay/KCP or bypass CPace, but it violated the direct-IP-only
fail-closed philosophy.

That relay-route gap was closed by commit `465be6a` and remains gated. A later
read-only TCP/security sweep also identified a defense-in-depth issue in the
responder-side port-forward path: even though tunnel use was pinned/refused, dead
code still held a latent tunnel socket opener. The current worktree deletes that
responder-side `TcpStream::connect` path, removes the per-connection
`port_forward_socket`/`port_forward_address` state, and makes
`LoginRequest::PortForward` fail closed immediately with the direct-IP hardened
build refusal. `scripts/verify.sh` now fails if the responder tunnel opener or
viewer tunnel socket opener regrows.

The latest DoS-focused TCP/path review separated two classes. The unauthenticated
connection-flood class remains covered by the R-T1/R-T12 semaphore, cgroup, fd,
accept-backoff, and rate-limited log gates. The password-correct hostile-peer
native-content class is now bounded in-process: encoded video batches are capped
before decode queueing and again before libvpx/aom decode, decoded RGB output has
checked arithmetic plus a hard byte ceiling, Opus packet and format fields are
validated before audio queueing and decoder setup, text/image clipboard payloads
are capped before native handoff, CLIPRDR format/data/file-content payloads are
capped, and the Windows CLIPRDR mapping table grows before append with zeroed new
slots. This is a DoS/resource-bound closure, not the Appendix C #2b sandbox.

The requirements snapshot reviewed in this pass was:

```text
d34aad84c44e8b919e72130eecb78e3f06e3f19a8d667a2219402e8225c90dc1  requirements.html
```

`requirements.html` is intentionally not edited by implementation work.

## Recent Closures

- **Apple SDK-free source-conformance reaches the intended SDK boundary.**
  `scripts/apple-conform-check.sh` caught a real Rust 1.81 Apple-target
  coherence break in the Unix file-transfer receive path: `openat(..., mode)` was
  passing `mode_t` directly through a C variadic call. `libs/hbb_common/src/fs.rs`
  now applies the C default-promotion cast (`mode as c_uint`) before the varargs
  call. The Apple gate now passes through the Rust-only graph and stops only at
  the expected SDK framework boundary (`coreaudio-sys`/`AudioUnit.h`) on this
  Linux host.
- **Windows artifact production is offline through helper containers.**
  `scripts/online-fetch.sh` builds the pinned
  `rustdesk-fork-harness-win-helper` image during the one networked phase.
  Artifact-producing Windows scripts (`build-windows-vm.sh`,
  `provision-windows-vm.sh`, `verify-windows-golden.sh`) use that image with
  `--network=none` for UDF media creation, libguestfs inspection/extraction,
  and MSI canonicalization. They no longer run networked `apt-get` helper
  containers.
- **Windows golden qcow2 reuse is pinned and fail-closed.** The golden image
  SHA-256 is pinned in `scripts/pins.env`:
  `18ca6c4d80490af308d66cbc2d68465d305fe39005c1f005f6eaeb95702f6dba`.
  Build, provision, and verification paths check that exact SHA before reuse.
  A stale or markerless golden now fails loud rather than being silently reused
  or mutated.
- **R-S5/R-A3 port-forward and RDP raw tunnels refuse before raw mode.**
  `src/port_forward.rs` is a fail-closed tunnel-refusal shim. On the responder,
  `LoginRequest::PortForward` now fails closed before authorization, and the
  latent tunnel opener/state (`connect_port_forward_if_needed`,
  `normalize_port_forward_target`, `port_forward_socket`,
  `port_forward_address`, responder-side `TcpStream::connect`) is deleted. App
  code has no `.set_raw(` caller, no tunnel socket opener, and no responder-side
  latent connect path left. The remaining `hbb_common::Stream::set_raw`
  implementation is only a defensive backstop.
- **FileResponse write forwarding is same-session/job gated.**
  `Connection` now tracks write job ids that this connection created through
  `FileAction::Receive`. Incoming `FileResponse::{Block,Digest,Done,Error}` is
  dropped unless the connection is a file-transfer session and the write job id
  is outstanding for that connection. The write-side FS IPC messages carry
  `conn_id`, and the CM/FS worker matches write jobs by `(id, conn_id)` before
  writing, digest-checking, completing, or erroring a job. This closes the
  defense-in-depth cross-session/id-collision concern without changing the
  intended full-filesystem file-transfer model.
- **File-transfer receive writes no-follow the parent walk and finalization.**
  On Unix, receive-side `*.download` and `*.digest` writes now create/open every
  parent directory through `mkdirat`/`openat(O_DIRECTORY|O_NOFOLLOW)`, open the
  target as a regular file through `openat(O_NOFOLLOW)`, read resume digest
  sidecars through a bounded no-follow regular-file open, and finalize the
  transfer with `renameat` plus handle-based mtime setting. This closes the
  intermediate-directory symlink race that remained after the earlier
  final-component `O_NOFOLLOW` fix. Non-Unix keeps the platform no-follow
  fallback.
- **Windows and Android socket-surface assertions are process-owned.**
  `socket_surface.rs` keeps the Linux confined-namespace `/proc/self/net`
  assertion, adds Android filtering from `/proc/self/fd` `socket:[inode]` links
  into `/proc/self/net/*` rows, and adds Windows IP Helper owner-PID TCP/UDP
  table reads. All three checked targets feed the same R-A4 policy: exactly one
  IPv4 TCP listener on the pinned direct port and zero UDP sockets. The
  implementation is source-gated by `scripts/verify.sh` and the Android proc
  parser/filtering path is covered by `surface_it`; native runtime execution is
  still part of the platform artifact validation path, not implied by this
  source gate alone.
- **Native codec advisory watch is separate and source-gated.**
  `docs/NATIVE-CODEC-WATCH.md` enumerates the exact vcpkg native C/C++ package
  set (`aom`, `libvpx`, `libyuv`, `opus`, `libjpeg-turbo`, `oboe`,
  `cpu-features`) and ties the overlay pins to `scripts/pins.env`.
  `scripts/native-codec-watch.sh` and `scripts/verify.sh` now fail if
  `vcpkg.json`, the overlay versions, or the manual watch ledger drift. This is
  a Cargo/Dart-advisory coverage closure only; it is not a "no current CVEs"
  assertion and does not close the Appendix C #2b decoder-sandbox residual.
- **Windows validation builds the tracked worktree when requested.**
  `WINDOWS_BUILD_SOURCE=worktree scripts/build-windows-vm.sh` snapshots tracked
  dirty edits and tracked deletions into the BUILD CD. The release default stays
  `head`, and `scripts/verify.sh` gates the worktree-validation mode so local
  completion proofs cannot accidentally compile stale committed source.
- **Validation-blocker cleanup is reflected in source and gates.**
  The Windows helper Dockerfile is tracked source and `scripts/verify.sh`
  gates that fact. Flutter/Dart lockfiles are treated as authoritative in
  verification and artifact build paths, with fail-closed drift checks instead
  of restore-after-resolution behavior. Rust `users` advisories are resolved by
  dependency-renaming to `uzers` 0.12.x; the stale advisory ignores were removed
  from `deny.toml`.
- **Relay route syntax and force-relay state fail closed.** Authored Dart now
  detects and rejects `/r`, `\r`, and `/r@...` route syntax in connect/deep-link
  paths instead of stripping it into a direct address. The Rust core treats
  relay suffixes as ordinary invalid direct-address input, rejects `--relay`
  instead of forwarding it into a connection parameter, and ignores the old
  `forceRelay` ABI positions by pinning them false where generated bindings
  still require a shape. Live `force-always-relay` behavior is gone; remaining
  mentions are limited to verification/tests or inert generated/API-compatibility
  shapes.
- **Malformed post-key `Message` frames fail closed.** A keyed frame that
  decrypts but does not parse as a protobuf `Message` now closes the responder
  session or viewer session instead of being ignored. `scripts/verify.sh` gates
  both post-key dispatch roots so the old silent `if let Ok(parse)` pattern
  cannot return.

## Artifact State

The artifacts below were produced from disposable build environments after the
current file-transfer parent-walk, responder-side tunnel refusal, socket-surface,
native handoff-bound, and Apple source-conformance follow-ups. They are current
evidence for this patched worktree; a later source change requires rebuilding
them again before making a release/tag artifact claim.

```text
0f3a5dae9f07fbfbc0571c31ec29e67119e58a5b483d81465a0592d3d4b91e5d  dist/rustdesk-x86_64.deb
c8d75e1fb6307778548c656090b9513d725296eac958423dac4733874e11cadf  dist/rustdesk-arm64.apk
9e799bb8e90d31ed76e2ccfd6d4afa4c9584da0160054ce606f27ba7a8250dd8  dist/rustdesk-setup.exe
bcd0628d87d27ded873f124c68eb6845b1b6ef1d80a5baa286e2552f392ee47e  dist/rustdesk.msi
```

Build evidence:

- Debian `scripts/build-debian.sh` passed its offline double-build A==B gate
  after the Apple varargs source fix.
- Android `scripts/build-android.sh` produced the signed arm64 APK and
  `apksigner` verified one signer after the same source fix.
- Windows `WINDOWS_BUILD_SOURCE=worktree scripts/build-windows-vm.sh` passed the
  transient KVM VM double-build A==B gate from the pinned golden, using the
  tracked dirty worktree snapshot so the source fix was present on the BUILD CD.
  The VM ran with `--network=none`; the only graphics listener was VNC on
  `127.0.0.1`, and all host-side helper containers in the artifact path also ran
  with `--network=none`.

## Validation Matrix

The following gates passed after the current source fix and full artifact
rebuilds:

```text
bash scripts/verify.sh                 # GREEN: VERIFY: all gates green
bash scripts/dart-verify.sh            # GREEN: flutter analyze lib/ + Dart gates
bash scripts/flutter-verify.sh         # GREEN: cargo check --features flutter,linux-pkg-config
bash scripts/audit.sh                  # GREEN: no unignored Rust advisories
bash scripts/dart-audit.sh             # GREEN: no unignored Pub advisories
bash scripts/apple-conform-check.sh    # GREEN: SDK-free Apple source conformance
bash scripts/smoke-server.sh           # GREEN: loopback runtime smoke
git diff --check                       # GREEN
```

Coverage highlights:

- `scripts/verify.sh` passed KATs, handshake tests, policy-funnel checks,
  main-crate compile checks, forbidden-token/excision checks, Windows
  offline-helper and golden-hash structural gates, R-S5 raw-mode refusal gates,
  build reproducibility gates, TCP/socket correctness gates, Windows/Android
  R-A4 socket-surface source-structure gates, and the R-R3 native-codec
  advisory-watch source gate.
- `scripts/dart-verify.sh` passed `flutter analyze lib/`, address-validator
  tests, and Section 19 Dart-layer absence checks.
- `scripts/flutter-verify.sh` passed
  `cargo check --features flutter,linux-pkg-config`; its Dart-side `ffigen`
  refresh warning is nonfatal and independently covered by `dart-verify.sh`.
- `scripts/audit.sh` passed against the pinned Rust advisory snapshot with no
  unignored advisories.
- `scripts/dart-audit.sh` passed against the pinned OSV Pub snapshot with no
  unignored advisories.
- `scripts/apple-conform-check.sh` passed the SDK-free Apple source-conformance
  boundary check.
- `scripts/smoke-server.sh` runtime-validated one loopback-only IPv4 TCP
  listener on `127.0.0.1:21118`, zero UDP sockets, fail-closed startup without a
  password, correct and wrong CPace outcomes, R-T1 connection-flood shedding,
  empty-whitelist denial, full keyed session authorization with `0.0.0.0/0`,
  R-S17 host-proof verification, forged-frame AEAD rejection, owner-safe online
  guess limiting, and absence of a plaintext canary on the captured wire.

## Open Audit Follow-Ups

These items were added after the post-commit read-only TCP route audits. They
are current tracking items, not historical work-log notes.

### Closed in Current Follow-Up

- **Client relay-suffix routes fail closed.** Desktop URI/CLI and deep-link
  initiation now reject stale relay syntax such as `rustdesk://host:21118/r`,
  `host:21118/r`, and `/r@...` instead of stripping the suffix and continuing.
  `urlLinkToCmdArgs`, `handleUriLink`, direct-address formatting/validation, and
  the Rust `LoginConfigHandler::initialize` path now preserve the direct-only
  invariant by refusing relay-route syntax.

- **Relay state plumbing is removed or pinned inert.** Authored Flutter session
  and multi-window creation paths no longer serialize or propagate `forceRelay`.
  Rust rejects `--relay`, stops consulting `force-always-relay` for live route
  decisions, and keeps only ABI-compatible ignored parameters where generated
  bridge shapes still require them.

- **Relay regression gates are live.** `scripts/verify.sh` rejects any re-growth
  of CLI relay forwarding, live `force-always-relay` Rust behavior, client-side
  relay suffix stripping, or a non-identity `handle_relay_id`.
  `scripts/dart-verify.sh` rejects authored Dart callers of
  `mainHandleRelayId`, live `forceRelay` plumbing, serialized `"forceRelay"`
  fields, and missing `/r` rejection coverage. The latest Docker/Dart
  validation evidence is:

```text
bash scripts/verify.sh        # GREEN: VERIFY: all gates green
bash scripts/dart-verify.sh   # GREEN: flutter analyze lib/ + address-validator tests + R-G6/R-X6 gates
git diff --check              # GREEN after this ledger update
```

- **Malformed post-key `Message` parse closes the session.** Both keyed dispatch
  roots now treat protobuf parse failure as a protocol violation: the responder
  calls `on_close` and breaks, while the viewer reports an error and returns
  `false` from `handle_msg_from_peer`. `scripts/verify.sh` requires both markers
  and fails on the old silent parse-ignore pattern.

### Larger Assurance / Hardening Items

- **Native viewer decoder sandbox.** The biggest remaining code hardening target
  beyond route security is the documented viewer residual: a deliberately
  connected, password-correct hostile peer can still feed media/content bytes
  into in-process native decoders. The current source now length-bounds and
  allocation-bounds those handoffs before native calls/queues, but that is not a
  process boundary. Design an out-of-process, killable decode boundary for
  video/audio/clipboard/file-compression surfaces. The separate native codec
  CVE/advisory watch is now wired and source-gated, but it is only a
  tracking/coverage mechanism for vcpkg C/C++ libraries, not a substitute for the
  sandbox.

- **R-V3 independent CPace/transport audit.** Keep the audit disclosure until an
  outside expert reviews the CPace construction, transcript binding, KDF,
  confirmation MACs, constant-time behavior, zeroization, AEAD nonce/key
  separation, and HostIdentity session binding. The existing docs and tests are
  audit inputs, not a substitute.

- **Apple artifact builds.** Source conformance is checked here, but actual
  macOS/iOS artifact builds still need the pinned Apple toolchain path. The
  ledger should not claim Apple artifact parity until those builds run.

- **Real two-host demonstrations.** The Docker loopback harness validates local
  executable properties. Separate operational evidence should demonstrate
  wrong-password failure, no plaintext canary, host-key mismatch failure before
  application decode, relay-syntax rejection, and RDP/tunnel refusal on a real
  two-host topology.

## Known Residuals

The current known residuals are the open follow-ups above. The remaining
in-repository hardening work is the larger native viewer decoder sandbox
design/implementation; the native-codec advisory watch and the in-process
handoff bounds are now present and source-gated, but deliberately do not claim
sandboxing or current CVE freedom.
Windows and Android platform-native socket-surface logic is now present and
source-gated, with refreshed platform artifacts recorded above. Any later source
change must rebuild those artifacts before a new release/tag claim.

The remaining external or pre-exposure evidence items are:

- **R-V3 independent expert audit.** The in-tree CPace construction is not yet
  independently audited. That disclosure is intentional and must remain until an
  outside audit is performed and published.
- **Apple artifact builds.** Apple source conformance is checked here, but full
  macOS/iOS artifact builds require the Apple SDK/toolchain path outside this
  Linux host.
- **Real two-host demonstrations.** The Docker loopback harness validates the
  executable security properties available on this machine. Real two-host MITM
  and RDP/tunnel wire demonstrations remain operational evidence, not required
  in-repo build outputs for this host.
