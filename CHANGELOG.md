# Changelog — RustDesk Hardened Fork

Source changes recorded under each fork version, newest first. The version headings
follow [the fork versioning rules](docs/VERSIONING.md). These historical entries do
not establish publication or release acceptance. The exact source commit identifies
a build; current verification evidence and unresolved obligations belong in
[HARDENING_STATUS.md](HARDENING_STATUS.md).

## 1.4.7-hardened.6 - 2026-07-14

### Credentials and privileged operations

- Moved installed unattended credentials to the enforcing Linux root, macOS
  LaunchDaemon or Windows LocalSystem service. Ordinary configuration IPC cannot
  replace those credentials or supply a user-profile fallback.
- Moved desktop password changes to dedicated bounded raw protocols, with endpoint
  authorization before secret transfer, operation-bound status, secret wiping,
  generation checks and explicit handling of uncertain durable/runtime outcomes.
- Bound service children, session switching, SAS, connection-manager operations and
  privileged helpers to their receiver, process generation and session authority.
- Made Windows Installer the machine-installation authority and moved Windows
  service credentials to protected ProgramData storage. Service-owned child jobs
  retain and drain their exact process trees before reporting shutdown.

### Remote sessions and desktop behavior

- Made remote input queues, physical key/button ownership, native execution and
  teardown belong to the authenticated Remote connection. Native failures are
  reported and unfinished cleanup is retained.
- Removed the macOS privacy-blackout event tap; display obscuring does not
  implicitly block local physical input.
- Bound each desktop tunnel mapping to one validated target and owned setup,
  authentication, relay and teardown work, with exclusive loopback listeners and
  process-wide admission limits.
- Removed RDP credentials from the dialog, peer configuration and tunnel path.
  The Windows client receives the loopback endpoint and prompts for credentials.
- Removed desktop main IPC from mobile builds, narrowed mobile configuration
  crossing to connection-manager visibility, and rejected unsupported mobile
  tunnel/RDP construction and dispatch.

### Codecs and packaging

- Backported the libvpx VP9 encoder `write_superframe_index` fix tracked as
  CVE-2026-1861/CVE-2026-2447, and removed the libaom/AV1 runtime and build scaffold.
  In-process decoder risk remains explicit in the
  [native-codec watch](docs/NATIVE-CODEC-WATCH.md).
- Made Debian payload contents, ownership, modes and loader policies independent
  of checkout metadata and generated staging inventories.
- Tightened native-library inputs, Android signing checks, Apple helper provenance,
  installer authority and final artifact manifests.

### Build, verification and publication

- Added offline Android Rust/Flutter-bridge compilation and made Gradle use an
  explicit offline execution policy.
- Isolated build passes in independent exact-commit source copies and separated
  target outputs, mutable harness state and authenticated input snapshots.
- Strengthened runtime-smoke process ownership, readiness, bounded waits, failure
  reporting and joined cleanup. Current execution and storage boundaries are in
  [the build harness guide](scripts/README.md); historical harness descriptions
  are not operating instructions.
- Bound release publication and cleanup to retained filesystem authority and a
  durable recovery journal. Ambiguous state is preserved for reconciliation;
  process-restart fixtures do not establish physical power-loss recovery.
- Required clean source identity throughout verification and independent cold
  Debian, Android and Windows builds, with commit/version-bound manifests.
- Required independent manifest authentication before artifact verification.
  Documented Android signing-key loss and compromise handling without replacing
  or bypassing the committed signing identity.

### Assurance scope

These are source-change summaries. Component checks, source gates and compilation
do not establish installed-service behavior or complete artifact acceptance.
Current native, reproducibility and release obligations remain in the hardening
ledger. This work used AI assistance and single-maintainer review; it is not an
independent professional cryptographic or product-security audit.

## 1.4.7-hardened.5 — 2026-07-11

### Service-owned unattended passwords
- Made the macOS root LaunchDaemon the durable owner of installed-service unattended password storage.
- Removed the old macOS main-IPC commit fallback: the service-owned LaunchAgent now receives only a typed
  runtime password snapshot, never authority to write the credential.
- Bound macOS runtime snapshots to the installed LaunchAgent job: the root service checks the live peer
  process, launchd `gui/<uid>/<label>` pid/path, root:wheel plist file and parent trust, ACL absence, and
  parsed LaunchAgent `Label`, `ProgramArguments`, `RunAtLoad`, and `KeepAlive` shape before returning a
  snapshot.
- Kept the snapshot runtime-only: it rebuilds only the in-memory PRS overlay used by listener parking,
  CPace, and password status, and it is never serialized into user config. Empty root storage returns an
  empty snapshot.
- Fixed explicit password changes that match a preset value so they still persist as local durable storage.

### Verification
- Kept Windows release packaging compiling under the offline VM harness when staging installer shortcut
  command files.
- Added behavior tests for macOS LaunchAgent plist proof, runtime snapshot non-persistence, and the
  preset-match persistence case.
- Tightened `verify.sh` and `apple-conform-check.sh` to gate the macOS snapshot proof in the specific
  implementation blocks, including live argv, exactly owned proof work, launchctl pid/path, parsed plist
  shape, empty snapshots, and runtime overlay behavior.

## 1.4.7-hardened.4 — 2026-07-08

### Remote control of RustDesk itself
- Removed the remote-configuration UI blocker completely: no `allow-remote-config-modification` option,
  Flutter click-absorbing wrapper, mouse-time/video-count probe, or remote-modify IPC override remains.
- Removed the obsolete setting text from all localization files.

### Verification
- Regenerated the Flutter Rust Bridge bindings from the reduced FFI surface.
- Added a verifier gate that rejects the removed option, UI helpers, IPC variants, FFI methods, and
  server mouse-move timestamp if they return.

## 1.4.7-hardened.3 — 2026-07-08

### Remote control of RustDesk itself
- Removed the separate connection-manager local gate that could still block remote interaction with
  RustDesk's own CM window.
- Kept `allow-remote-config-modification=Y` as the single policy: the authenticated owner can manage
  RustDesk itself during a session, and the controlled-side config remains funnel-pinned rather than
  operator-toggleable.

### Verification
- Added a gate that rejects any return of the hidden `allow-remote-cm-modification` path.

## 1.4.7-hardened.2 — 2026-07-08

### Linux service sandbox
- Restored the shipped Linux CLIPRDR/FUSE file-clipboard path under the systemd sandbox by admitting only
  the legacy FUSE mount syscalls the current implementation uses: `mount`, `umount`, and `umount2`.
- Kept the broader `@mount` group out of the service policy. The new mount API and root-changing calls
  (`chroot`, `pivot_root`, `open_tree`, `move_mount`, `fsconfig`, `fsopen`, `fsmount`, `fspick`,
  `mount_setattr`) remain denied.
- Kept denied syscalls fail-closed: the unit does not install a `SystemCallErrorNumber=` fallback.

### Verification
- Updated the R-D3a gate to require the exact FUSE-only syscall allowlist and to reject broad mount-group
  reintroduction or an errno fallback.
- Corrected the dependency-audit disposition for `fuser`: Linux file clipboard is a shipped reachable path,
  so the accepted residual is now tied to the service-unit syscall boundary and existing FUSE mount-point /
  queue bounds.

## 1.4.7-hardened.1 — 2026-07-07

A hardened, **direct-IP-only** RustDesk, built on upstream RustDesk 1.4.7.

### Connectivity
- **Direct-IP only** — no rendezvous server, relay, UDP, or auto-updater. The box is reachable by one
  deliberate, CPace-PAKE-gated TCP connection on `0.0.0.0:21118`.
- The listener binds **only while a permanent password is set** (fail-closed, R-S9) and re-checks that at
  runtime; a transient bind failure backs off and retries.

### Authentication
- **The permanent password is the sole authenticator.** A balanced CPace PAKE over the password keys a
  sealed two-key AEAD channel and defeats an active MITM by construction. There is no host-key or
  fingerprint to pin — a viewer connects with just an address and the password — and no `rustdesk://` link
  or CLI argument can carry an embedded credential (R-X6).
- The password derives a memory-hard Argon2id PRS; it is machine-bound at rest and durable across restarts.

### Surface & sovereignty
- The box asserts its own reachable surface is **exactly one v4 listener and zero UDP sockets**, scoped to
  its own process — so it coexists with SSH / `systemd-resolved` on the same host (R-A4).
- The rendezvous / relay / KCP / LAN-discovery / auto-updater / plugin-loader / host-key subsystems are
  compiled out — as are the cloud account / address-book / group panels (no OIDC login, no shared address
  book) and the remote-printer capability — and CI greps assert their tokens stay absent (R-A6). Egress is
  silent by construction (§18): the box phones home to nobody.

### Sessions & UI
- **All five session types are preserved for the authenticated owner** — remote desktop, file transfer,
  terminal, TCP tunnel / RDP, and view-camera, plus the clipboard and audio channels — each riding the
  single sealed session stream (R-S5) and confined to the session's authenticated type (R-S19).
- **No GUI footguns (R-G1):** a control whose backend is compiled out or pinned is removed, not greyed; a
  pinned capability that must still be shown is read-only, "set by policy", never a toggle that reverts.
- Settings are usable and honest — the password is settable from the GUI, and services / listeners report
  their **real** reachability (a down or wedged daemon never shows a false "Listening").

### Android (controlled side)
- An Android device can be the controlled host, **owned by the foreground service**: reachable only while
  the service runs and a password is set, and a "Stop" (or an OS kill) genuinely closes the listener by
  construction. Boot starts only the password-gated listener, never an unprompted screen-capture consent.
- **The sideloaded-install flow is spelled out in-app** — on Android 13+ the accessibility toggle is a
  "Restricted setting", and the app walks you through App info → ⋮ → "Allow restricted settings" →
  authenticate → enable.
- Honest scope: screen view is attainable (per-session consent; `FLAG_SECURE` windows capture black);
  remote input is best-effort within Android's limits — the phone is viewer-dominant in practice.

### Build + release
- **Reproducible (R-B2).** A release set is accepted only after Debian, Android, Windows EXE, and Windows
  MSI each cold double-build byte-for-byte identically with the pinned `SOURCE_DATE_EPOCH`. Cargo generates
  version metadata only under `OUT_DIR`, and compilation-only verification mounts source read-only.
  `dist/SHA256SUMS` records the exact commit. Apple targets are source-conformance-checked (not built here).
- **The commit is the source of truth.** A release is identified by its build commit; the fork version is
  the human-readable name. `rustdesk --version` reports the app version (`1.4.7`); `rustdesk --fork-version`
  reports the fork release.
