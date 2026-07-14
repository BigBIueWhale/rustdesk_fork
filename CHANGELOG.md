# Changelog — RustDesk Hardened Fork

All notable changes to the hardened fork, newest first. Each entry's heading is the fork release name
(`<upstream-base>-hardened.<N>` — see [`docs/VERSIONING.md`](docs/VERSIONING.md)). The single source of
truth for the exact code a release contains is the **commit** it was built from, linked in the GitHub
release notes.

## 1.4.7-hardened.6 - 2026-07-14

### Privileged authority and unattended credentials
- Made installed-service credential changes explicit privileged transactions rather than generic
  configuration writes. Linux uses administrator-authorized service ownership, macOS uses the root
  LaunchDaemon with exact LaunchAgent proof, and Windows uses the stable SCM service as the sole durable
  authority.
- Made credential changes generation-bound and fail-closed through derivation, durable replacement,
  runtime publication, and authentication finality. A credential generation cannot be reused, an
  authentication attempt cannot complete across a generation change, and ambiguous post-replacement
  persistence terminates rather than reporting a false failure or success.
- Replaced Windows profile-derived credential storage with an MSI-provisioned `ProgramData` root whose
  protected ACL grants only SYSTEM and Administrators full control. Runtime access is handle-relative and
  reparse-rejecting; only the LocalSystem SCM supervisor has write and durability authority.
- Bound privileged IPC actions, service children, terminal helpers, clipboard helpers, URL forwarding,
  SAS, and connection-manager operations to their actual receiver and session authority. Removed
  password-valued CLI provisioning and remaining whole-configuration authority crossings.

### Credential IPC and finality
- Moved every desktop password body to dedicated raw `_password` or `_service_password` transport. The
  protocol is outside serde, JSON, `Bytes`, and `Framed`, with one canonical fixed header, exactly bounded
  body, operation-bound status, and a Windows operation-bound status acknowledgement before disconnect.
- Proved both connected endpoints before secret-body transfer. Fixed wiping body/stack allocations feed
  redacted `SensitivePassword` and `SensitiveAuthorization` ownership without plaintext retry copies; macOS
  also explicitly wipes native Authorization Services external-form stack copies.
- Bound operation UUIDs to owner class and process-random-keyed HMAC-SHA256 value fingerprints. Each 64-entry
  process-lifetime replay ledger reclaims only its oldest terminal result, never evicts admitted work, and keeps
  retained results value-bound. Uncertain clients reuse one operation for at most 600 seconds; authoritative
  rejection, internal failure, and shutdown are terminal. Restart remains explicitly non-durable exactly-once.
- Bound Linux service mutation to the raw root endpoint, socket-derived PID/UID/start-time polkit subject,
  bounded killed-and-reaped `pkcheck`, single-claimant authorization/commit recovery, and exact root-parent
  plus service-owned-replica identity. Ordinary main IPC has no password write fallback.
- Gave macOS generic and password proofs separate capacities and exactly owned, synchronously joined OS
  threads that abort on timeout, cancellation, lost result, panic, or lost ownership. The user-paced admin
  prompt sits between bounded right readiness and a fresh raw transport deadline; exact helper, installed-app,
  LaunchAgent argv/launchd/plist, and runtime-only snapshot proofs remain required.
- Made the Windows LocalSystem password listener one process-lifetime first-instance, local-only,
  max-instances-one message pipe. Exact role/generation/process-token and last-message impersonation-token
  proof, stable active-principal sampling around two token reads, live kernel-DACL reread, exact overlapped
  cancellation/drain, and retained listener/client supervisors precede admission and operation-ACK-bound
  disconnect. Arbitrary Interactive Users are rejected before header wait; an authorized active-principal
  process in an exact RustDesk role can consume only bounded local work and receives no password or admin authority.

### Windows machine authority
- Made Windows Installer the sole machine-installation authority. Removed application-owned install,
  uninstall, service, firewall, and elevated command-program paths; the setup bootstrapper admits only
  its embedded MSI and invokes fixed System32 `msiexec.exe` through a closed command grammar.
- Bound the LocalSystem child tree to an SCM-owned kill-on-close job assigned at process creation. Session
  handoff and stop retain exact child identity, account for descendants, preserve active tunnel state,
  drain admitted service work, and report `SERVICE_STOPPED` only after the owned tree is absent.
- Bound runtime broker refresh, terminal launch, clipboard access, privacy-session handling, post-install
  relaunch, MSI cleanup, and deferred installer actions to fixed files, exact tokens, package state, or
  served-session authority as applicable.

### Remote input ownership
- Made desktop input execution an owned resource of one authenticated Remote connection from admission
  through joined teardown. Bounded queues, cancellation, physical key and mouse-button ownership,
  aggregate `BlockInput` leases, backend-canonical identities, and process-wide native dispatch prevent
  one session from releasing or inheriting another session's input state.
- Kept Windows input and `BlockInput` calls on a stable native executor, kept required macOS work on its
  owned queue, and made Linux, macOS, and Windows injection failures explicit. Temporary modifiers and
  teardown retry releases or fail closed instead of silently abandoning uncertain native state.
- Removed the macOS privacy-blackout event tap. Display obscuring cannot implicitly block local physical
  input; explicit `BlockInput` remains a separate Remote-only, connection-owned capability.
- Bounded wheel and gesture magnitudes and retained Remote-only authorization at every controlled-side
  input sink, including rewritten Android events and Windows service-owned SAS.

### TCP tunnels and RDP
- Made every desktop tunnel mapping carry an immutable validated target and own its listener,
  cancellation, setup, login, relay tasks, and teardown. Removal, replacement, command-channel closure,
  and outer-session cancellation stop acceptance and join all owned work.
- Made loopback listeners exclusive on each desktop platform, including Windows
  `SO_EXCLUSIVEADDRUSE`. Added nonblocking limits of 32 mappings process-wide, 32 accepted connections
  per mapping, and 128 accepted connections process-wide, with permits held through setup and relay.
- Removed pre-login application reads and shared mutable target selection. Tunnel bytes enter relay only
  after the remote authorizes the exact `PortForward` session.
- Removed RDP usernames and passwords from the dialog, peer configuration, tunnel transport, process state,
  and Windows Credential Manager. Legacy options are scrubbed on load/store; trusted System32 `mstsc.exe`
  receives only the ephemeral loopback endpoint and `/prompt`.

### Native codecs and supply chain
- Backported the exact upstream libvpx VP9 encoder `write_superframe_index` bounds fix tracked as
  CVE-2026-1861/CVE-2026-2447 and pinned the source archive, patch, and Windows build tools by SHA-512.
  Native codec staging remains offline and platform-specific; in-process decoder risk remains an explicit
  accepted residual.
- Removed the libaom/AV1 runtime and build scaffold instead of retaining another unreviewed in-process
  decoder. Rust, Dart, native, workflow, build-script, and lexical unsafe-site inventories are
  machine-derived and verifier-gated.
- Hardened dependency and build inputs, including bundled native libraries, runner libraries, Android
  signing and final-manifest checks, Debian payload ownership and ELF search paths, and Apple
  service/helper provenance.

### Verification and release discipline
- Confined verifier scratch state to private workspaces and made mutation self-tests prove that source,
  lockfile, release-ordering, and workspace-authority failures are detected.
- Bound verifier fixture allocation and cleanup to retained no-follow scratch descriptors. Random descriptor-relative
  creation, mount/identity-checked cleanup, acquisition-failure fixtures, exact descriptor inheritance, and a real
  consumer pathname-replacement fixture reject redirection and preserve ambiguous edges.
- Routed lifecycle-capable verifier commands through authenticated transient cgroup scopes with gated execution,
  post-authentication `SCM_RIGHTS` descriptor handoff, pidfd target identity, exact unit/cgroup authentication,
  `cgroup.kill`, recursive emptiness proof, and unit collection. Fixtures cover signals, `setsid`, lingering
  descendants, and double-fork daemonization.
- Moved canonical publication snapshots to a fresh pidfd-supervised worker and included ctime, `statx` mount and
  attribute state, mount flags, visible xattrs, explicit ACL/capability probes, inode flags, two inventories,
  exact content/EOF, final edges, and independent resource/deadline mutation gates.
- Closed source-gate text scanning to fixed, root-owned GNU `grep`, with explicit match/no-match/error
  status handling and a release preflight that runs before the online closure is copied.
- Made the non-root portable password smoke stage execute from an immutable owner-scoped fixture, prove
  its portable role and exact process ownership, and leave the mode-0700 release source bind unchanged.
- Made each release pass an independent `--no-hardlinks --reject-shallow` private repository with its own object database, detached exact
  commit, no remotes, strict object validation, mount closure, and complete inode-link closure. The release transaction
  creates no Git worktree registration and never inspects or mutates the invoking repository's worktree registry.
- Made generated-state normalization one retained-authority operation. It requires kernel hardlink protection and a
  524,288-entry, depth-128 authority with exact descriptor accounting, retains every directory and unique non-directory
  inode, records and re-proves complete type/owner/group/mode/link metadata, rejects external links, mounts, special
  objects, and changed inventories, strips dangerous mode bits, and re-proves the exact private source before
  fail-closed Git cleanup. Release preflight proves the 524,544-descriptor host and pinned-container budgets before
  building. Every closure and normalization invocation re-authenticates bounded bytes read from one retained committed
  helper descriptor; no release operation executes or mounts its mutable pathname.
- Made production workspace cleanup a terminal privileged deletion instead of whole-workspace ownership normalization.
  An exact hash-verified helper descriptor acquires complete mount, type, depth, inventory, and hardlink authority; a
  no-network container receives bounded helper source directly from that descriptor and, with only filesystem
  `DAC_OVERRIDE` and `FOWNER`, consumes authenticated edges without changing the online snapshot's ownership or
  modes. Every use hashes the bounded descriptor bytes in memory against the committed digest; preflight exercises the
  exact capability path against hostile metadata, and the host refuses late content before removing only the exact
  empty root through retained parent authority. Missing production image authority preserves the workspace; recursive
  host cleanup is fixture-only.
- Isolated the production dirty-source proof in a private complete-history no-hardlink clone attached as `master` to the
  expected commit. Its exclusive probe is the sole invalid source state, and its mount-closed, inode-link-closed fixture
  is descriptor-removed and proved absent.
- Made managed verifier finalization preserve the complete forced-kill, launcher-reap, descriptor-close,
  unit-collection, and cgroup-path failure set instead of allowing one cleanup failure to hide another.
- Made final `dist` installation an ext4-only same-parent transaction bound to the complete descriptor-retrieved ext4 UUID and
  opaque object handles. Nonblocking retained-descriptor opens reject special-file substitution before reads; public
  verification rejects unresolved journal state without repair.
- Made the durable v3 journal advance through `initializing`, handle-bound `staging`, manifest-bound `prepared`, and
  explicit `rollback` or `cleanup`. Unbound payloads are preserved as ambiguous, partial staging is removed only under
  its recorded handle, first installation is kernel no-clobber, and replacement uses one atomic exchange.
- Expanded restart and corruption fixtures across first and replacement publication, partial cleanup, no-clobber,
  wrong-token canonical state, malformed reserved state, object substitution, modes, hardlinks, xattrs, root metadata,
  and special-file types.
  These are process-restart proofs; they do not claim physical power-loss simulation.
- Deferred release success until signal-excluded final cleanup has reconciled publication, removed the exact private
  workspace through retained descriptors, and proved its deletion boundary.
- Made the complete release build require one clean committed `HEAD` before verification, after
  verification, and after all cold reproducible target builds. Windows artifacts must be archived from
  that same commit; generated checksums record the exact source commit and fork version.
- Made release verification authenticate the manifest digest, full commit, and fork version through an
  independent channel before checking artifacts. Documented fail-closed Android signing-key loss and
  compromise handling: no pin bypass, and a suspected compromise retires the package identity.
- Added focused behavioral and structural gates for credential transaction finality, service authority,
  exact-child supervision, desktop input ownership, tunnel lifecycle and admission, installer authority,
  and the native codec backport.

### Assurance scope
- Linux behavior and compile gates, Apple source-conformance checks, and native Windows pre-build suites
  cover platform-specific source contracts. Only the repository's complete clean committed cold release
  build is artifact-level proof for Debian, Android, Windows EXE, and Windows MSI outputs.
- These source notes establish no native Windows or artifact reproducibility evidence; only a complete clean
  committed `.6` release transaction and its generated exact-commit manifest can establish that evidence.
- This hardening was developed and reviewed with AI assistance and remains single-maintainer security
  engineering, not an independent professional cryptographic or product-security audit.

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
- **Reproducible (R-B2).** Debian, Android, and Windows each cold double-build byte-for-byte identically
  (`SOURCE_DATE_EPOCH` pinned); `dist/SHA256SUMS` records the exact commit. Apple targets are
  source-conformance-checked (not built here).
- **The commit is the source of truth.** A release is identified by its build commit; the fork version is
  the human-readable name. `rustdesk --version` reports the app version (`1.4.7`); `rustdesk --fork-version`
  reports the fork release.
