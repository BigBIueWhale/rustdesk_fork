# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Older work-log material was removed from this live ledger on
2026-06-26 because it contained superseded `PARTIAL`, `TODO`, and deferred-work
claims that were useful historically but misleading as current status. Git
history remains the traceability record for those intermediate notes.

## Current Verdict

**Status: complete for the in-repository implementation and reproducible local
build harness.**

On 2026-06-26, final reviewer `Maxwell` (`gpt-5.5`, `xhigh`) reviewed the
current dirty worktree, read the full `requirements.html`, checked the previous
blocker classes, and returned **PASS** with no blocking findings.

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
  `src/port_forward.rs` is a fail-closed tunnel-refusal shim, and
  `Connection::try_port_forward_loop` returns an error if a forwarding socket is
  present. App code has no `.set_raw(` caller left. The remaining
  `hbb_common::Stream::set_raw` implementation is only a defensive backstop.
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

## Final Artifacts

All artifacts below were produced from disposable build environments after the
latest Windows-helper, golden-hash, R-S5, Flutter/Dart lockfile, and `uzers`
advisory fixes.

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

## Final Gate Matrix

The following gates passed after the final artifact builds:

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

## Known Residuals

No known in-repository implementation or build-harness gaps remain under the
reviewed requirements snapshot.

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
