# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Older work-log material was removed from this live ledger on
2026-06-26 because it contained superseded `PARTIAL`, `TODO`, and deferred-work
claims that were useful historically but misleading as current status. Git
history remains the traceability record for those intermediate notes.

## Current Verdict

**Status: responder-side port-forward latent-connect follow-up closed; file
write-response forwarding is now same-session/job gated in source and gates.**

On 2026-06-26, final reviewer `Maxwell` (`gpt-5.5`, `xhigh`) reviewed the
then-current dirty worktree, read the full `requirements.html`, checked the previous
blocker classes, and returned **PASS** with no blocking findings.

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

The requirements snapshot reviewed in this pass was:

```text
d34aad84c44e8b919e72130eecb78e3f06e3f19a8d667a2219402e8225c90dc1  requirements.html
```

`requirements.html` is intentionally not edited by implementation work.

## Recent Closures

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
Windows-helper, golden-hash, first R-S5 raw-mode refusal, Flutter/Dart lockfile,
and `uzers` advisory fixes. They are now **previous-build evidence only**: the
current source contains the later responder-side port-forward latent-connect
deletion described above, so these exact hashes are stale for any new release or
tag until the artifacts are rebuilt from the current commit.

```text
7a42dfac65ed5cfd8a060f8dbe15a9f377b460f3f6376392fe23cd8246a4afbf  dist/rustdesk-x86_64.deb
1a4f54573845e0706a6cc6bc70fa92debdd0684cebc1786a73082e89fd2d79d3  dist/rustdesk-arm64.apk
2532d08957fc8dfec7e068f188fd2ee55c2217923deb999465ae0a5ef56743f1  dist/rustdesk-setup.exe
1da411a876b962251f486d87d78ff6813680851192dcfa737893a13eb7e5a868  dist/rustdesk.msi
```

Build evidence:

- Debian `scripts/build-debian.sh` passed its offline double-build A==B gate.
- Android `scripts/build-android.sh` produced the signed arm64 APK and
  `apksigner` verified one signer.
- Windows `WINDOWS_BUILD_SOURCE=worktree scripts/build-windows-vm.sh` passed the
  transient KVM VM double-build A==B gate from the pinned golden. The VM ran with
  `--network=none`; the only graphics listener was VNC on `127.0.0.1`, and all
  host-side helper containers in the artifact path also ran with `--network=none`.

## Validation Matrix

The following full source gate passed after the current responder-side
port-forward follow-up:

```text
bash scripts/verify.sh        # GREEN: VERIFY: all gates green
```

The following gates passed after the previous full artifact builds and must be
re-run after the next artifact rebuild before making a final artifact claim:

```text
bash scripts/verify.sh
bash scripts/dart-verify.sh
bash scripts/flutter-verify.sh
bash scripts/audit.sh
bash scripts/dart-audit.sh
bash scripts/apple-conform-check.sh
bash scripts/smoke-server.sh
git diff --check
```

Coverage highlights:

- `scripts/verify.sh` passed KATs, handshake tests, policy-funnel checks,
  main-crate compile checks, forbidden-token/excision checks, Windows
  offline-helper and golden-hash structural gates, R-S5 raw-mode refusal gates,
  build reproducibility gates, and TCP/socket correctness gates.
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

### Defense-In-Depth Items

- **Windows and Android socket-surface assertions.** Linux has a live
  process-table assertion for exactly one IPv4 TCP listener on `127.0.0.1` in
  smoke tests / `21118` in service mode and zero UDP sockets. Windows and Android
  currently rely more on code-path proof. Add platform-native checks in their
  validation paths so every shipped target proves one direct TCP listener, zero
  UDP, and no relay/rendezvous/KCP listener.

- **Delete or cfg-fence inert UDP/KCP/rendezvous helpers.** Remaining UDP helper
  code in `hbb_common` appears inert by call graph, not by physical absence.
  Prefer deleting or target-cfg-fencing transport-capable helper functions so
  "no UDP/KCP/rendezvous" is enforced by absence, with grep/call-graph gates
  preventing future reintroduction.

- **Strengthen file-transfer parent traversal.** Final-component writes use
  no-follow opens; intermediate path validation remains path-based. A full
  handle/openat-style parent walk would better match the no-TOCTOU philosophy
  and should be tracked as local filesystem hardening.

### Larger Assurance / Hardening Items

- **Native viewer decoder sandbox.** The biggest remaining code hardening target
  beyond route security is the documented viewer residual: a deliberately
  connected, password-correct hostile peer can feed media/content bytes into
  in-process native decoders. Design an out-of-process, length-bounded,
  killable decode boundary for video/audio/clipboard/file-compression surfaces,
  and maintain a native codec CVE watch separate from Cargo/Dart advisories.

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

No known in-repository implementation or build-harness gap remains from the
post-`f90f197` TCP route audits after the relay-suffix closure and the
responder-side port-forward latent-connect deletion above. The artifact hashes
in this ledger predate the latter source follow-up and must be rebuilt before a
new release/tag claim.

The remaining items are explicitly external or pre-exposure evidence, not source
tree TODOs:

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
