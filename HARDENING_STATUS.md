# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Superseded work-log material (intermediate `PARTIAL`/`TODO`/deferred
notes, and — as of 2026-06-28 — the reverted native-worker-sandbox slices) is
removed from this live ledger because it is misleading as current status. Git
history remains the traceability record for that intermediate work.

## Current Verdict

> ⚠️ **Qualified by live QA (2026-07-06) and service-boundary audit (2026-07-08) — see the _Live acceptance-testing regressions_ and _R-S11b/R-S11c service-owned IPC authority_ sections below.** Hands-on acceptance testing of the deployed `v1.4.7-hardened.1` prerelease surfaced connection-lifecycle, settings-control, desktop-shutdown, and UI↔excision-coherence regressions this verdict does not yet reflect. The follow-on IPC audit reclassified service-owned unattended credentials and privileged service actions as a blocking authority-boundary item. The cryptographic / transport core and the direct-IP posture hold; the build is **not release-ready**, and the prerelease is not to be promoted. Investigation in progress — damage-control, not implementation.

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
asserted at startup by R-A4); inbound has no in-app source ACL — CPace is the sole gate (like SSH); source-IP scoping,
if wanted, is a firewall rule (R-S9/R-D2); egress is silent by construction (R-D6/§18); the
§8 excisions (auto-updater, plugin loader, `ConfigureUpdate`, trust-anchor
overrides, `os_login`→PAM, terminal root-PTY policy-lock, the OTP/2FA cluster)
are done and CI-grepped absent (R-A6); the R-S16 compile-time policy funnel pins
the controlled-side security options; the §19 Flutter GUI conformance and the
§20 TCP transport-correctness/cancellation-safety/DMZ-flood requirements are
implemented. The §4.2/§20 post-key DoS bounds are in place: bounded peer video
display/decode queues, Opus/zstd input caps and the R-S7 decompressed-output
ceiling, bounded peer screenshot/PeerInfo/UI-text/file-transfer admission,
display-control validation, FUSE mount-point no-follow setup, the service
unit's FUSE-only `mount`/`umount` syscall exception, bounded FileContents
response queue, and the FILEDESCRIPTOR path-traversal sanitizer
(`sanitize_relative_names`) with its count cap (`MAX_FILE_DESCRIPTORS`). The
file-clipboard serve/confirm paths are additionally arithmetic/index-safe — the
peer-supplied `file_num` is bounded before indexing in `set_stream_offset`, the
CLIPRDR file-read clamps `length` to the remaining bytes with no `offset+length`
wrap, and the descriptor serializer truncates an over-long name with no
`520 - name_len` underflow (each overflow-safe, unit-tested). The
build is reproducible for Debian/Android/Windows (R-B2), and the Apple
SDK-free source-conformance gate covers the macOS/iOS code paths (R-R2).

**RESOLVED (2026-07-04) — the GUI/coherence backlog is CLOSED.** The six-audit sweep found the
cryptographic/transport core clean (0 security hazards) and enumerated the surrounding
structural-coherence debt (~80 orphaned-scaffolding sites, 7 user-visible correctness defects, 1 live
latent race). That backlog is now IMPLEMENTED in full (36 files, +441/−1790, reviewed to standard):
the re-key "Password Required" loop is fixed, and the whole dead-scaffolding stratum
(2FA/trusted-devices, the attended-accept + permission-widener IPC pipelines, the rendezvous
online-status cluster, socks/change_id/relay/`IdPk` residue) is excised. **Superseded (host-key
retirement):** the R-S17 fingerprint/first-contact-pin/`--get-fingerprint` GUI items in that sweep
were subsequently RETIRED with the whole host-key subsystem — the CPace PRS is now derived from the
password alone (fixed salt, R-P1) and there is no host identity, host-proof, or local pin (R-P5), so
the fingerprint boards, the pin/known-hosts dialogs, and the `--get-fingerprint`/`--pin-host` CLI are
removed, not fixed. All source gates green (the
`verify-release` bundle + `flutter-verify`), zero dangling references across all five platforms, and
R-B2 reproducibility re-proven per release (build-release.sh → dist/SHA256SUMS, double-build A==B per
target). Detail is retained as the implementation record in the
`## ✅ CLOSED — the excision-vestige backlog` section below.

**§20 TCP active-router audit (2026-06-29).** The full TCP transport — both the
controlled (responder) and viewer (initiator) sides — was audited under the
*strongest* network-adversary model: both peers connected through a fully
malicious router that can inject / drop / modify / replay / reorder / reset /
segment / coalesce / flow-control-manipulate the connection at will. The
cryptographic construction reduces this attacker to (at most) a DoS: post-key
manipulation fails the Poly1305 tag (R-T7, no ≤1-byte bypass) → poison →
fail-closed; reorder/replay/drop desync the per-direction monotonic nonce
(R-A5); first-contact MITM fails the mutual PAKE; a substitute that does not know
the password fails the PAKE (one that does is out of scope per §2 — peer identity
rests on the shared password alone, with no host-key pin, R-P5); and the pre-key parsers
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
release builds hold.

**R-S19 — capability-confinement class (CWE-863) — status.** requirements.html §7 R-S19 pins
the class: every peer-triggerable capability MUST key on the session's `AuthConnType`, not on the
upstream decoupled per-capability booleans / broad `self.authorized`. **The named instance
CVE-2026-58056 (a FileTransfer session injecting input + capturing the screen — Appendix C #24) is
FIXED and gated** (`0150cde`): an `AuthConnType` allowlist in `on_message` (input=Remote-only,
desktop-capture=Remote|ViewCamera) + a FileTransfer capability-flag clear. **The full structural
closure is DONE and gated** (`3afc51b`, after a four-agent all-platform research pass): a
`confine_capabilities_to_conn_type` derivation keys every capability boolean off the `AuthConnType`
at authorization time — *before* any peer login-option is applied, closing a real login-time ordering
window (a FileTransfer peer's `LoginRequest.option{block_input:Yes}` fired a Windows console-freeze
once before the old in-branch clear landed); the `on_message` guard is a 3-way allowlist (input +
remote-*control* reboot/privacy/virtual-display = Remote-only; desktop *capture* = Remote|ViewCamera);
and the flag-gated sinks the guard's message set misses now key on `AuthConnType`/`voice_calling` —
host clipboard-*text* write (Remote-only; the FileTransfer *file*-clipboard stays), peer→host audio
(voice-call only), cursor/window capture + whiteboard spawn + the Windows RDP session-switch
(Remote-only). The research surfaced **two instances beyond the known set**, both closed: a **HIGH**
outbound host-audio-*capture* by FileTransfer/Terminal (the audio analog of the CVE's screen capture —
closed by deriving `self.audio` from `AuthConnType`, since the `audio_service` subscribe reads
`audio_enabled()`), and cursor-position/window-focus capture. Validated: docker `cargo check` (both
feature sets), `verify.sh` all-green incl. the generalized R-S19 gate (asserts derivation-before-options
+ the 3-way guard + the sink gates), `apple-conform-check` PASS (iOS/macOS source-conformant). The
Windows-cfg `SelectedSid` edit is type-trivial (the R-B2 Windows build re-prove confirms it). `MessageQuery`
(which answers `make_display_changed_msg` — monitor geometry/resolution) is now confined to the
Remote-or-ViewCamera `is_desktop_capture` allowlist too, so a FileTransfer/Terminal/PortForward peer can no
longer read display metadata (verify.sh R-S19 asserts it). Not a §2 exposure
(all instances moot for the trusted password-holder); least-privilege coherence the actually-secure fork
carries as a MUST. **The final dedicated all-platform Opus sweep is DONE** (`60f8904`): PART 1 confirmed
the connection.rs fix is sound / not bypassable (cross-confirmed by multiple independent passes — SAS is
Remote-gated, peer-elevation is proto-excised, the headless `--service` trust model holds); PART 2 found
**four more edge instances of the same shape** the on_message dispatch didn't reach, all now closed with a
`verify.sh` "R-S19 edge residuals" gate: (1) a **screenshot** cross-source leak — SCREENSHOTS was keyed by
display index alone, so a concurrent Remote monitor loop could serve a ViewCamera peer a desktop frame
(now keyed by `(VideoSource, idx)`); (2) the **viewer-side clipboard reciprocal** — a hostile peer in a
non-default session the viewer opened could write the viewer's OS clipboard (now `is_default()`-gated,
the viewer analog of `AuthConnType::Remote`); (3) the **Windows CLIPRDR→CM** forward was unconditional
(now gated on the confined `self.clipboard && self.file`, removing a latent approve-mode-pin dependence);
(4) **Android MediaProjection** fired for view-camera/terminal (now excluded in both the Dart and Kotlin
gates). All moot under §2; validated via docker cargo check + verify.sh + apple-conform + dart-verify.
Accepted low-severity residual (no host action/capability): the video-QoS metadata arms
(`ClientRecordStatus`/`AutoAdjustFps`). Remaining: R-B2 all-3-platform build
re-prove at this HEAD (a background build loop is handling it; the connection.rs/video_service.rs changes
are in all builds, and the Windows/Kotlin edges are validated by the win-exe/apk builds).

**R-S11b/R-S11c — service-owned IPC authority — status: OPEN / RELEASE-BLOCKING.**
The 2026-07-08 service-boundary audit supersedes the earlier narrow "IPC transport is local and
write-allowlisted" conclusion for installed-service mode. The issue is not socket locality; it is authority
ownership. In installed mode the unattended password/PRS and machine remote-access policy are owned by the
root/SYSTEM/LaunchDaemon service because that service will honor them later over the network. Therefore a
normal user-session IPC config write is the wrong primitive even if it is same-session, same-UID, or
executable-path matched. The old R-S11 allowlist and R-S11a transport/parent-dir hardening remain useful
prerequisites; they do not close the service-owned credential/action class.

Tracking rule for this block: every remediation item must name the platform(s), endpoint/message/action,
privilege boundary, exact attack surface, and closure condition. A fix is not complete until the old path is
unreachable and a source/test/AST gate prevents reintroduction.

**Completed slices:**
- **R-S11b-1 — Linux/macOS `_service` whole-config boundary — CLOSED 2026-07-08.** Platforms: Linux installed
  service and macOS LaunchDaemon/source-conformance path. Endpoint: AF_UNIX `_service` formerly carrying
  `Data::SyncConfig(None)` and `Data::SyncConfig(Some(_))`, including stale-socket probes that read config.
  Boundary: active user ↔ root/LaunchDaemon service. Attack surface closed: a local active-user process no
  longer receives or replaces whole service `Config`/`Config2` over `_service`. Source closure:
  `src/ipc.rs` admits only `Data::Test` on Linux/macOS `_service` via `service_channel_admits_message`;
  `src/ipc.rs` deletes the `Data::SyncConfig(Some(_))` receiver write arm; `src/ipc/fs.rs` probes `_service`
  liveness with `Data::Test`, not config reads; `src/server.rs` deletes
  `wait_initial_config_sync`/`sync_and_watch_config_dir` and the root↔user service-config watch loop.
  Verification closure: `scripts/verify.sh` runs `ipc::test::service_channel_rejects_config_bus` and asserts
  the service loop, stale-socket probe, server startup, and handler do not reintroduce the whole-config bus;
  `scripts/apple-conform-check.sh` mirrors the source assertions for the macOS conformance path.
- **R-S11b-2a/R-S11c-1a — service-marked server rejects ordinary password IPC — CLOSED 2026-07-08.**
  Platforms: Windows installed service-launched `--server`, Linux root-service-launched root or active-user
  `--server`, and macOS LaunchAgent `--server` source path. Endpoint/action: main IPC
  `Data::Config(("permanent-password", Some(_)))` and `Data::Config(("permanent-password-storage-and-salt",
  None))`. Boundary: user-owned IPC caller ↔ service-owned unattended credential. Attack surface closed:
  the service-launched server is marked with `--service-owned-server`; `src/ipc.rs` classifies that receiver
  as `MainIpcAuthority::ServiceOwned` (with a Windows LocalSystem fallback); main-channel allowlisting rejects
  ordinary password writes and returns an explicit NACK; the handler also rejects password writes and refuses
  whole-config, standalone salt, and storage/salt sync snapshots if reached directly. Linux `--password` is no
  longer routed through `UserMainIpcScope`, so root does not cross-write a service-owned user server through the
  legacy CLI path.
  Verification closure: `scripts/verify.sh` asserts user-owned vs service-owned IPC policy, service launch
  markers on Linux/Windows/macOS, no `--password` root-to-user routing, and handler-level whole-config,
  standalone salt, and storage-sync denial; `scripts/apple-conform-check.sh` asserts the macOS LaunchAgent marker and
  source policy.
- **R-S11b-3a — service-marked server rejects ordinary options IPC — CLOSED 2026-07-08.** Platforms:
  Windows installed service-launched `--server`, Linux root-service-launched root or active-user `--server`,
  and macOS LaunchAgent `--server` source path. Endpoint/action: main IPC `Data::Options(Some(_))`.
  Boundary: user-owned IPC caller ↔ service-owned remote-access policy. Attack surface closed: service-owned
  receivers reject whole-options writes in the main-channel allowlist and in the handler before
  `privacy_mode::switch` or `Config::set_options`; the daemon returns `Data::OptionsSetResult(false)` rather
  than the old overloaded `Data::Options(None)` sentinel; IPC callers persist/cache option writes only after
  `Data::OptionsSetResult(true)` and do not locally persist options when the daemon is unreachable. User-owned
  `--server` option writes remain user-owned through the same typed ACK path. Verification
  closure: `scripts/verify.sh` tests the user-owned vs service-owned allowlist and asserts the typed ACK/NACK,
  no-local-fallback rule, receiver gate, and UI cache ordering; `scripts/apple-conform-check.sh` mirrors
  the macOS source assertions.

**Release-blocking items:**
- **R-S11b-2 — installed-service unattended password ownership.** Platforms: Windows installed service,
  Linux installed service, macOS LaunchDaemon/source path. Android is app-UID/service-owned rather than
  root/SYSTEM, and non-installed/portable user-mode remains user-owned. Endpoints: `Data::Config` for
  `permanent-password`, CLI/FFI/UI password setters that reach ordinary IPC, and any `SyncConfig` path that
  carries password storage/salt. Boundary: user-session process ↔ privileged unattended host. Attack
  surface: an unprivileged local caller can mint or replace the credential the privileged host later accepts
  remotely. Current state: the ordinary IPC password write, whole-config sync, standalone salt read, and
  storage/salt sync paths are closed for service-marked servers by R-S11b-2a/R-S11c-1a; user-owned `--server` paths remain
  user-owned. Remaining closure: add a typed `SetUnattendedPassword` service operation; commit only inside
  the privileged service after OS admin authorization (Linux polkit; Windows UAC/service-admin proof; macOS
  Authorization Services/privileged helper); the service derives/stores the PRS itself; tests cover
  installed service-owned provisioning vs user-mode behavior.
- **R-S11b-3 — service-owned remote-access policy, identity, and trust material.** Platforms: all desktop
  installed-service paths. Linux/macOS no longer have the `_service` whole-config bus after R-S11b-1, but
  ordinary config writers, whole-config reads/responses, and any reintroduced whole-config import remain in
  scope; Windows remains high risk because main IPC is same-session. Endpoints: `Data::Config`,
  `Data::Options`, `Data::Socks`, `Data::SyncConfig`, trusted-device removals,
  server/direct-listener/RDP/session-sharing policy writers, and any hidden UI/CLI/FFI path that persists
  controlled-side policy. Boundary: user-session process ↔ privileged host policy. Attack surface: a local
  caller can alter who can reach the service, how it binds, which trust/identity state it uses, or which
  hardened policy pins are effective. Current state: ordinary whole-options IPC writes are closed for
  service-marked servers by R-S11b-3a, including typed daemon ACK/NACK and no local persistence fallback inside
  the IPC helper; user-owned `--server` option writes remain user-owned. Remaining closure: privileged service
  policy writes are typed service actions with receiver-side validation; whole user config is never imported;
  `Config::set*`, `set_socks`, trust-store writes, identity/salt/key writes, and service-policy writes are not
  reachable from ordinary IPC except through named approved operations with gates.
- **R-S11c-1 — Windows main IPC credential write into a SYSTEM/winlogon-launched server.** Platform:
  Windows installed service. Endpoint: main named pipe `\\.\pipe\<APP>\query` accepting same-session genuine
  executable peers; action: `Data::Config(("permanent-password", value))`. Boundary: same-session desktop
  process ↔ service-launched server process. Attack surface: same-session is not machine-admin authority,
  yet it can change the service-hosted remote credential. Current state: the same-session/same-exe main
  pipe no longer authorizes ordinary service credential mutation after R-S11b-2a/R-S11c-1a. Remaining
  closure: the typed service operation still needs receiver-side admin authority validation before any PRS
  write.
- **R-S11c-2 — Windows `_service` caller-supplied session switching.** Platform: Windows multi-session,
  RDP, fast-user-switching, installed service. Endpoint: `_service` named pipe carrying `Data::UserSid`.
  Boundary: local caller ↔ SYSTEM service session broker. Attack surface: the legitimate remote path checks
  policy before sending, but a direct local IPC caller can supply a target session and make the service launch
  or move the server there. Closure: `_service` rejects raw caller-supplied session IDs; the service itself
  validates target existence, current session, `share_rdp`/policy, caller authority, and a service-minted
  capability tied to an authenticated Remote connection; tests cover invalid target, no policy, stale
  capability, and direct local IPC bypass attempts.
- **R-S11c-3 — Windows `_service` privileged SAS/HKLM action.** Platform: Windows installed service.
  Endpoint: `_service` message `Data::SAS` and the handler that may temporarily write HKLM
  `SoftwareSASGeneration` before sending SAS. Boundary: same-session caller ↔ SYSTEM service. Attack
  surface: a privileged OS action is exposed as a generic local service command. Closure: remove generic SAS
  from `_service` or require a service-minted capability tied to an authenticated Remote session and a
  current control context; direct same-session IPC alone is rejected; tests assert unauthorized local callers
  cannot reach the HKLM/SAS path.
- **R-S11c-4 — `_cm` pre-login file authority.** Platforms: Linux, Windows, macOS desktop CM paths; highest
  severity where CM can run as root/headless/no-console, lower but still wrong as same-user ambient trust.
  Endpoint: `_cm` IPC accepts `Data::FS` before `Data::Login`. Boundary: local helper client ↔ file-transfer
  authority. Attack surface: local read/write/delete/rename/digest/file-transfer operations are reachable
  before connection ownership is proven; if privileged, this becomes local privileged filesystem authority.
  Closure: reject all `Data::FS` before authenticated connection login/capability; bind CM to a
  per-connection nonce minted by the owning `Connection`; key file authority to `AuthConnType::FileTransfer`
  or `Remote` as designed; tests cover pre-login FS rejection and stale/wrong nonce rejection.
- **R-S11c-5 — macOS privileged service packaging.** Platform: macOS source-conformance and any future macOS
  artifact. Surfaces: `update.scpt` chowning `/Applications/RustDesk.app` to the active user while
  `daemon.plist` runs a binary from that bundle as root; daemon `ProgramArguments` using `/bin/sh -c`;
  daemon logs under predictable `/tmp` paths; privileged install/update shell quoting. Boundary:
  user-writable app/update flow ↔ root LaunchDaemon. Attack surface: user-writable root-run code path or
  privileged file/log clobbering. Closure: root-run binaries, plists, support dirs, and logs are root-owned
  and non-user-writable; update flow never makes the service path user-owned; LaunchDaemon uses direct
  arguments, not shell; privileged scripts avoid unquoted shell construction; Apple conformance gate checks
  ownership/mode/path/log invariants.

**Contained hardening items from the same audit:**
- **R-S11c-6 — Windows named-pipe endpoint hardening.** Platform: Windows desktop. Endpoint:
  predictable `\\.\pipe\<APP>\query{postfix}` names and broad create permissions for main/`_service`.
  Boundary: local process ↔ IPC endpoint identity. Attack surface: pipe squatting, spoofing/confusion, or
  denial of service even where message auth blocks higher impact. Closure: privileged endpoints are created
  by the service with tight DACLs; clients authenticate/verify the server endpoint where practical; broad
  `allow_everyone_create` is not used for privileged channels; tests cover pre-creation/squatting.
- **R-S11c-7 — Linux `_pa` audio helper ambient same-UID trust.** Platform: Linux desktop while `_pa` is
  running. Endpoint: `_pa` IPC streams PulseAudio/default-monitor frames. Boundary: same-UID local process ↔
  active audio capture helper. Attack surface: same-UID local audio capture/spoofing outside the owning
  connection. Closure: require a per-connection capability/nonce tied to the active authorized session; reject
  arbitrary same-UID clients; test wrong/missing/stale capability.
- **R-S11c-8 — `_whiteboard` helper ambient same-UID trust.** Platforms: desktop whiteboard helper paths.
  Endpoint: `_whiteboard` IPC accepts drawing/input events and `Exit`. Boundary: same-UID local process ↔
  active overlay helper. Attack surface: local spoof/DoS of whiteboard overlay. Closure: require an owning
  connection capability/nonce; reject arbitrary same-UID clients and stale `Exit`.
- **R-S11c-9 — Windows URL forwarding via unauthenticated window messages.** Platform: Windows desktop.
  Endpoint: `WM_COPYDATA` / `WM_USER+2` URL forwarding to an existing UI window. Boundary: local process ↔
  URL/deep-link dispatcher. Current impact: prompt/DoS only because password/config/import deep-link writes
  are excised. Closure: keep credential/config authorities rejected; if URL handling ever becomes sensitive,
  move forwarding to authenticated local IPC or add sender validation; gate to prevent credential/config
  writes from reappearing behind window messages.
- **R-S11c-10 — Linux root-context shell interpolation.** Platform: Linux service/helper discovery.
  Surfaces: root-side env/home/session discovery commands that interpolate UID/process/user fields into shell
  strings. Boundary: discovered local names/metadata ↔ root shell. Current impact: lower probability than the
  primary IPC findings because the main spawn path is argv-based and inputs are mostly OS-discovered, but root
  shell strings are not acceptable. Closure: replace with direct `/proc`, `getpwnam`/`getpwuid`, or argv-only
  commands; no shell pipeline/string interpolation in root-context helpers.
- **R-S11b-4 — config secrecy statement after IPC closure.** Platforms: all. Surface: at-rest password/PRS
  wrapper keyed by machine UUID. Boundary: local endpoint read ↔ connect-equivalent credential. Status:
  accepted residual only when endpoint compromise/local config read is in scope-out; not a permission boundary
  and not a substitute for IPC secrecy. Closure condition for this block: no service IPC leaks PRS/key/salt,
  config files remain owner/root-only, and docs/tests continue to treat PRS/config as remote credentials. Any
  future stronger storage (TPM/OS keychain) is defense-in-depth, not the cure for the IPC class.

**Checked during this audit and not opened under R-S11b/R-S11c:** Android exported components/service
surfaces remain contained by manifest/exported-permission shape; iOS has no controlled-side/root IPC surface
in scope; Unix IPC parent/socket hardening remains a prerequisite and is not the failing layer; FileTransfer
authorization, file-transfer symlink TOCTOU, port-forward plaintext, decompression amplification,
OS-login/PAM/LogonUser, deep-link password/config/import, and Windows terminal-helper SYSTEM-shell concerns
are tracked by their existing requirements/fixes, not reopened here. Dependency advisories remain the
separate R-R3/Appendix D open item.

Current implementation is **not yet compliant** with this stronger requirement. No release or prerelease
should be promoted until the release-blocking items above are implemented and gated.

**R-B2 — the reproducible release is produced + published by DEFAULT script runs, no manual step.** The
whole flow is opinionated + self-validating end to end, so an operator (not an AI agent) produces AND
uploads an official GitHub release with bare commands and NO env vars:

```
scripts/online-fetch.sh            # once: fetch + stage the digest-pinned toolchains / caches / VM helper
scripts/gen-android-keystore.sh    # once: mint the stable R-B2 signing key at its default location
scripts/provision-windows-vm.sh    # once: build the §12.2 Windows golden VM
scripts/build-release.sh           # each release: cold, all 3 platforms, double-build A==B -> dist/ + SHA256SUMS
scripts/publish-github-release.sh  # each release: upload dist/ as a GitHub release (draft; --publish to go live)
```

`build-release.sh` cleans from scratch and builds Debian/Android/Windows each **byte-identical
double-build A==B**, pins the release commit so the set is **coherent** (it rejects itself if HEAD moves
mid-build), and writes the authoritative manifest `dist/SHA256SUMS` (HEAD + `SOURCE_DATE_EPOCH` + the
four SHAs) — so the per-release SHAs live THERE and in the published GitHub release, never hand-copied
into this ledger. `publish-github-release.sh` refuses to publish anything not matching a clean
committed+pushed HEAD and its recorded SHAs. Three build-integrity fixes make that trust sound (each
was caught fail-loud during development, not shipped):
- **`.msi` cross-day reproducibility (`c47bca8`)** — `res/msi/preprocess.py` had stamped the wall-clock
  build date into an ARP `InstallDate` (DATE-granular: it passed a same-day double-build but differed
  across calendar days). Now `SOURCE_DATE_EPOCH`-derived (UTC, timezone-independent); verify.sh §(6) gates it.
- **clean-worktree assertion (`99fcadd`)** — deb/apk refuse a dirty/stale tree (`ALLOW_DIRTY_TREE=1` for a
  deliberate local build); the keystore + every other input default correctly, so no env var is required.
- **concurrent-commit coherence (`1405369`)** — Windows pins the commit for both double-build passes, and
  build-release.sh rejects the set if HEAD moves mid-build, so the manifest can never mislabel a
  mixed-commit set.
`verify-release.sh` (8 source gates: compile + PAKE KATs + runtime smoke + flutter analyze + Rust/Dart
advisories + the R-B2 determinism guards + the build-harness fail-loud suite) is the source-side
confirmation. The reproducible set folds in the R-S19 structural closure of CWE-863 / CVE-2026-58056
(every peer-triggerable capability derived from `AuthConnType` by construction).

Prior re-prove (superseded; its `.msi` `2d8b8aed` was later found NOT cross-day reproducible — fixed
`c47bca8` above; exe/deb/apk WERE reproducible): **R-B2 at HEAD `5e03011` (2026-07-02)** after the R-V3
crypto-audit publication (`docs/CRYPTO-AUDIT-2026-07-02.md`, VERDICT **SOUND**): deb `d15c6ed5…` / apk
`6d06a547…` / exe `beed598c…` / msi `2d8b8aed…`.

Prior re-prove (superseded): **R-B2 re-proven on all three platforms at HEAD `a5bd577` (2026-07-02)**, after the
autonomous-session change batch: the mobile **QR-scanner excision** (R-G1/R-G2 — page + button +
the `qr_code_scanner`/`zxing2`/`image_picker` deps), the **encrypted port-forward/RDP tunnel
RESTORATION** (R-S5 option 1 / R-F1 / R-D6 / R-A9 — the relay was wrongly refused; it now rides the
sealed session stream, proven ciphertext by the R-A9 wire-capture test), and the **AppCompat-theme
build fix** (R-B2 — the QR-plugin excision dropped the transitive `androidx.appcompat` the
permission activity's theme referenced; reparented to the platform translucent theme). The binaries
change; **A==B at this HEAD is the proof, not a match to older hashes.** New byte-identical (A==B)
double-build SHA-256s:

```
ad70b491597a5dbd59c8bdbbd3596999bfe95c6fe156da7954ea3d88df03d30e  rustdesk-x86_64.deb
eee3cad7f4837ce2537facd29409c11cd831e2f16ed83bf22be66a114dc71db1  rustdesk-arm64.apk
c68fb11ea3d25945a014c15ced26f534ba9f8ceb2f871b02a6623ba8d4a46932  rustdesk-setup.exe
8795007d56006038448026b35bf3d08b85c30e2bd04b77f64a74b136bde3b739  rustdesk.msi
```

Debian = offline `DOUBLE_BUILD` `dist` vs `dist/_rebuild`; Android = two independent offline CLEAN
builds proven byte-identical (signed apksigner v2, RSA-4096, cert `10:91:32:2B:A0:42:5A:FA:…`);
Windows = §12.2 KVM golden-VM `DOUBLE_BUILD` A==B (exe + msi). `verify-release.sh` ALL 7 source gates
GREEN at this HEAD (incl. the port-forward runtime smoke + the R-A9 wire-ciphertext test).

Prior re-prove (superseded): **R-B2 re-proven on all three platforms at HEAD `ede091e` (2026-07-01), after the
completion-review fix batch (R-G6 additive error copy + R-X7/R-G3/R-S18 letter-of-spec
closures).** That batch changed app source (client.rs error surfaces, en.rs keys, the
flutter `_secure`/`_direct` badge-state removal, the `use-temporary-password`/os-cred
dead-code excision), so the binaries change; **A==B at this HEAD is the proof, not a
match to older hashes**. A latent **R-B9 idempotency** bug surfaced during the re-prove
and was fixed in `build-debian.sh`: it now `rm`s the stale ephemeral plugin symlinks
(`flutter/linux/flutter/ephemeral/.plugin_symlinks` + `.flutter-plugins{,-dependencies}`)
before the flutter plugin re-injection — a prior build leaves them dangling at its own
PUB_CACHE and `flutter pub get` does NOT overwrite them, so `flutter build linux`
CMake-aborted on a non-pristine tree ("re-running is safe" now holds). It is a
build-harness fix only — no artifact payload changes. New byte-identical (A==B)
double-build SHA-256s:

```
4187b8e196047c1c1ab96610562806da396512282bcb8790f32918e49a3a396a  rustdesk-x86_64.deb
4a9d7fad89547fdd58ef98eddbcfae8af0a1a9653d14b561e6348f578155c77e  rustdesk-arm64.apk
d8a4417010d1a22a94826b9d3bde59e308aa08dd9911a650385abf5b85a7d15d  rustdesk-setup.exe
dff1205c76308a6999e9e5a57790a29876d1e859be660cf487804211abb6cb65  rustdesk.msi
```

Debian = offline DOUBLE_BUILD `dist` vs `dist/_rebuild`; Android = two independent
offline builds proven byte-identical (signed apksigner v2+v3, RSA-4096); Windows =
§12.2 KVM golden-VM DOUBLE_BUILD A==B. This confirms the completion-review source
changes compile cleanly end-to-end on **all three** targets — the full `flutter build`
validation beyond `flutter analyze`.

Prior re-prove (superseded): **R-B2 was re-proven on all three platforms at HEAD
`6fbae50`** — after this session's two *source-changing* commits: the full-access
pin reversal (`9a83b50`, one controlled-side mode for the authenticated owner)
and the at-rest credential change (`6fbae50`, the CPace PRS now stored as a
memory-hard Argon2id hash, never the plaintext — R-P1).
Those genuinely change the binaries, so the new hashes differ from the prior
doc-only-stable `313f776` set — **A==B at this HEAD is the proof, not a match to
the old hashes**. The new byte-identical (A==B) double-build SHA-256s:

```
7cadaaab23788b73417ebd6348290dd1e5831ff088bee9826ded834c32a22472  rustdesk-x86_64.deb
9468236ab2f2eff7ad71b63339e21705cd7fabc650ca871fa906ec10f6254d2d  rustdesk-setup.exe
bc5135c5c738908ba5a454a70331103dab44bb10405bf7fff20384d70dea23d8  rustdesk.msi
54e26d37e46bdc3a788972df57fd1848b4df0403b10c0bd01d555b9083f6c593  rustdesk-arm64.apk
```

The Debian `.deb` is an offline `DOUBLE_BUILD` A==B (`build-debian.sh`, `dist`
vs `dist/_rebuild`); the Windows `.exe`/`.msi` are a §12.2 KVM golden-VM
`DOUBLE_BUILD` A==B (a fresh CoW overlay cloned from the byte-identical golden
*per cycle*, the in-VM `build-windows.ps1 exit=0` honesty gate confirming a real
compile rather than a stale artifact); the Android `.apk` is two independent
offline builds proven byte-identical, signed (apksigner v2+v3, RSA-4096). So
**all three platforms are byte-reproducible (A==B) at HEAD `6fbae50`**, and the
full-access + Argon2id-PRS changes compile cleanly on every target — including
the `cfg(windows)` path that only an actual build can validate.
`dist/SHA256SUMS-HEAD.txt` is regenerated as the consistent full **3/3** manifest
at `6fbae50`, superseding the `313f776` set (deb `c2d9aa04…` / exe `5f280a07…` /
msi `48a301bb…` / apk `b49c4f20…`). The Windows VM build — the only path that
compiles the `cfg(windows)` code — remains the sole validator there (it earlier
caught a dropped `as Box<_>` trait-object coercion in the CLIPRDR clipboard
dispatch, `libs/clipboard/src/platform/mod.rs`, that the Linux gates structurally
cannot see; fixed 008e2ba), and the in-VM honesty gate prevents any stale
artifact from shipping.

## Live acceptance-testing regressions — damage-control investigation (2026-07-06, IN PROGRESS)

The deployed `v1.4.7-hardened.1` prerelease (`commit-7c16d75…`) was put through hands-on acceptance
testing across three real hosts — the **haggai_computer** Debian/Docker box (controlled side), a
**Windows 11** machine (both roles), and an **Android** phone (both roles). The operator, acting as QA,
surfaced a set of correctness and coherence defects that the `## Current Verdict` above does not reflect.

**What this means for the verdict:** the cryptographic / transport core and the direct-IP-only posture
hold (CPace auth, fail-closed, the excisions, reproducible builds — all confirmed working in the field).
But the **connection lifecycle**, the **settings / security-settings controls**, the **desktop process &
shutdown model**, and **UI ↔ excision coherence** are not release-ready. The 2026-07-04 "GUI/coherence
backlog CLOSED / RESOLVED" claim is **qualified**: it closed the *dead-scaffolding* stratum, not the
*behavioral* correctness of the surfaces a real user exercises. The prerelease is **not to be promoted**.

**Mode (operator directive):** investigation and damage-control, **not implementation**. One Opus 1M
subagent at a time; each **begins by reading `requirements.html` in full**; first-principles against the
upstream 1.4.7 baseline; **read-only**. Each cavity is drilled to its true depth before any treatment is
named; findings are appended here per item; nothing is called fixed until proven end-to-end. No verdict unearned.

**Every audit carries two mandatory sweeps** — the reported symptom is a starting point, never the whole finding:
1. **Anything-else-wrong sweep.** Beyond confirming the report, hunt the surrounding code for other defects
   of the same class or nearby — the sibling bug the operator hasn't hit yet. Damage-control, not symptom-confirmation.
2. **Cross-platform sweep.** Determine whether the defect is that-platform-only or also present on the others —
   never stop at the platform where it was observed. **For any server / controlled-side question, actively
   research ALL FOUR server-capable platforms — Windows, Debian/Linux, macOS, AND Android** (iOS is viewer-only) —
   reading each one's platform-specific source (`cfg(windows)` / `cfg(target_os="linux")` / `cfg(target_os="macos")` /
   `cfg(target_os="android")`), client AND server. Deliver the full per-platform matrix, not a spot check.

### The operator's bug reports — verbatim (cleaned of typos, as reported)

**BR-1 · File transfer to the Linux box (haggai) is broken.**
> File transfer works perfectly between Windows and Android, and so does copy-paste. However, file transfer to haggai_computer shows no files on the remote end, and creating a folder doesn't actually create a folder, and the home folder is essentially… no path? Going "back" doesn't help either. It's almost like something is very broken with file transfer on a system without systemd, possibly.

> (earlier, related) Connect works great for screen control, and terminal control works great. But "transfer file" says: *error no active console user logged on, please connect and log on first* — on the same currently-served haggai computer that works for screen control just fine, where I see the desktop and am able to control perfectly.

**BR-2 · Windows: "Enable changing settings" is a one-way trap.**
> On Windows, initially there's an option to "Enable changing settings". I pressed the button, then the button disappeared, the contents of the screen rearranged themselves, and now I can't press that button again ever, and I can't change settings.

**BR-3 · Windows: can't use or control RustDesk itself while a session is connected.**
> On Windows there's no default to enable remote control of RustDesk itself. It's kind of annoying that I can't control or use RustDesk itself, or its settings, for as long as somebody is connected via RustDesk.

**BR-4 · Windows: the app says "Listening on :21118" before any password is set.**
> When I open the Windows app it seems to immediately say "Listening on :21118", which is a bit weird — but whatever; then when I set a password it's actually possible to connect and control / transfer files.

**BR-5 · Connections never close / don't clean up (bidirectional).**
> The Windows app, at a certain point: "Unlock security settings" just doesn't work — it becomes corrupted or something. It started with a connection from the Android phone to the Windows machine never closing. Even after force-shutting-down the Android app on the phone side, the Windows side still showed a connected file transfer, or a different type of connection or something. The same type of issue existed when controlling the Android phone from the Windows computer. Something with the connection closing doesn't quite work or clean up.

**BR-6 · Windows: the security-settings corruption worsens — can't unlock, can't set the password, can't toggle remote-config.**
> Then it became so much worse. The "Unlock Security Settings" button on Windows is now not disappeared, but clicking it does nothing — and I can't unlock security settings, and I can't change or set the RustDesk password either. And of course I can't "Enable remote configuration modification" (I was never able to toggle any of those, for some reason).

**BR-7 · The dead "Unlock security settings" control is identical on both platforms.**
> To be clear: in both the Windows 11 machine and in the Debian haggai_computer, the "Unlock security settings" blue button is visually clickable, and I click it, but it does nothing.

**BR-8 · Windows: no clear way to shut RustDesk down; no tray; the process persists.**
> I don't know how to shut down RustDesk on the Windows client. I made sure to not only launch RustDesk but also install it on the system using the built-in capability I was suggested — and that worked — but when I close the RustDesk window on Windows 11 I don't see any tray menu, so it's very unclear whether I truly shut it down. It seems not, because it's still visible in Task Manager.

**BR-9 · Windows: the listener wedges — killing the process and relaunching doesn't recover it.**
> Even closing RustDesk, killing it from Task Manager, then relaunching on Windows, was not enough to get RustDesk connections into the Windows machine to work again. So obviously something there is very broken.

**BR-10 · Windows: after disconnecting, the box can't accept connections again (intermittent).**
> After the whole issue with the Windows connection staying open, I obviously shut it off by clicking "disconnect client" or something — then even restarting RustDesk on the Windows machine didn't help, and nobody can connect to the Windows machine at all. This doesn't happen always; often disconnecting does actually disconnect.

**BR-11 · The Android side cleans up, but the Windows listener stays wedged; clearing the Android side doesn't help.**
> I just pressed X on the connection to the Android phone (on Windows), and RustDesk on Android does show disconnected — that's actually good, it doesn't show anyone connected to me. But I still can't connect from Android to Windows now. It worked perfectly before. Forgetting the password on the Android didn't help at all, and neither did pressing "Delete" on the saved profile (or whatever the list of known addresses is) in the Android app.

**BR-12 · Debian stays stable and reachable; Windows corrupts to the point of being unreachable — possibly because the Debian settings couldn't be touched.**
> The Debian I'm still able to connect to. The Windows is corrupted to a point where I'm not even able to connect to it. The Debian seems pretty stable — maybe because I wasn't able to freely touch the Debian's info. (Think about it: if I turned off RustDesk's ability to accept a connection, or touched another important setting, I wouldn't be able to get back to control inside that Docker image.)

**BR-13 · Completely irrelevant menus that shouldn't be there.**
> There are completely irrelevant menus that don't work and shouldn't be there — such as "Install RustDesk printer", which I'm glad doesn't work, but of course it shouldn't be there.

**BR-14 · Many settings, on both Windows and Debian, make no sense given the fork's excisions.**
> Many of the actual settings displayed — both in the Windows and in the Debian RustDesk GUI — don't make any sense given our fork's excisions and goals, almost like nobody even took a second look to determine what works in the settings controls.

**BR-15 · Android: "Start service" is mislabeled; the port is open whenever a password is set.**
> The Android screen sharing works perfectly — but only when clicking "Start service" before actually connecting from the Windows computer. When doing the opposite, it still allows me to connect. So it shouldn't be called "Start service"; it should be called "start listening for screen control" or something, on the Android phone. Because file transfer works as long as there's a password set, without needing "Start service" at all. If there's no "Start service", however, the remote-control screen to control the Android phone never actually loads. I actually like that suite of behaviours on Android, but it has to be renamed — and it should be explicit, in general, that as long as there's a password, the port is open for connections.

**BR-16 · Android: the Terminal (Beta) is whitewashed / too transparent.**
> The Terminal (Beta) on Android has opacity such that it feels white-washed — kind of like an American flag on the moon after half a year.

**BR-17 · Android: the screen-capture consent popup appears unprompted on boot/unlock.**
> I just ran out of battery on my Android phone and booted it back up after charging a lot. Then when I unlocked my phone screen, I got a pop-up — without consent, really — "Share your screen with RustDesk?", "Share one app" or entire screen, with Cancel and Next buttons. That's part of a series of conceptual issues I described earlier. Our RustDesk fork is so secure that I'd *love* for it to be open to connections to the Android phone all the time, believe me — I'm the first to say the Android security model is idiotic; but the fact is it's there, so we have to deal with it and design things that actually make sense. Getting that popup on startup is very problematic.
>
> _(Design direction the operator is drawing — CONFIRMED as desired, to be validated & designed in cavity #4, not yet implemented: **(1)** the password-gated **listener / foreground-service staying active in the background is GOOD and wanted** — file transfer over it (with a password) needs no screen-capture consent at all and works today; **(2)** what must NEVER happen is auto-requesting the **MediaProjection capture** consent on boot / unprompted; **(3) preferred design — fire the capture-consent popup lazily, specifically WHEN a connecting peer initiates a screen-view/control session**, so consent is requested exactly when it is actually needed, tied to a real incoming session — never on boot, never speculatively. Net: listener/file-transfer = always-on-with-password in the background; capture consent = on-demand at peer-connect. **Feasibility caveat for cavity #4 to PROVE from the Android API, not assume:** MediaProjection consent has foreground-context constraints — cavity #4 must establish whether raising the dialog at connect-time is permissible (e.g. via a full-screen-intent notification that surfaces consent when a session arrives) and design the best achievable version.)_

### Confirmed WORKING in the same QA pass (context, not defects)
- Android phone remote control (controlled from Windows): *"works perfectly … the instructions about sideloaded apps and the entire flow are literally perfect."*
- Audio, including Android → Windows while controlling the phone: *"audio does work … which is pretty impressive."*
- CPace/password auth + direct-IP connect on all three hosts; screen control; clipboard/copy-paste; terminal control; Windows↔Android file transfer.

### Investigation plan — drilled ONE Opus 1M subagent at a time; findings appended per cavity
1. **Session & connection lifecycle** (BR-5, BR-9, BR-10, BR-11, BR-12; root of BR-6's corruption) — teardown on graceful close / abrupt kill / net-drop; the reaper mechanics (removed send-timeout, keepalive, `test_delay`, the `MAX_AUTHED_SESSIONS` cap) vs upstream; CM / `AUTHED_CONNS` lingering; the Windows `--service`-vs-GUI process model.
2. **Settings write-path & the dead security controls** (BR-2, BR-6, BR-7; part of BR-3) — the GUI→FFI/IPC→config option-write path, and whether the R-S16 lockdown reject-set / `is_option_can_save` is swallowing the unlock / password / remote-config writes on both desktops.
3. **UI ↔ excision coherence** (BR-4, BR-13, BR-14; the "Start service" label in BR-15) — the full extent of inert / misleading / incoherent controls, menus, labels, and status text across desktop + mobile (settings, tray, peer/context menus, home/connection).
4. **Android controlled-side model** (BR-15, BR-16, **BR-17**) — service / listener / capture lifecycle from first principles, the honest "port-open-when-password-set" model, R-D7a reconciliation, **and the boot/unlock behavior: what auto-starts on boot (BootReceiver? a persisted "was-serving" re-arm? `MainService.onCreate` requesting MediaProjection?) such that the capture-consent popup fires unprompted — the app must NOT auto-request screen-capture on boot; capture consent must be tied to an explicit user action / an actual incoming session, while the password-gated listener may stay open.**
5. **File-transfer host session/user context** (BR-1) — the "no files / no path / no active console user" breakage on the headless, systemd-less Linux host.

### Cavity 1 — Session & connection lifecycle: FINDINGS (Opus 1M, read-only, 2026-07-07) ✅ EXHAUSTIVE — every claim proven from source

**Headline.** The Rust transport/connection core is **SOUND** — no permanent leak or wedge lives in it; a dead peer reaps in **≤~31 s** on every controlled platform (an improvement over upstream's removed 12–120 s per-write timeout). The permanent Windows unreachability is a **service-supervision** defect *outside* the connection loop; there is also a second, **reboot-proof silent-park** path. Two operator hypotheses are refuted from source. Exactly one honest NEEDS-RUNTIME remains (which trigger the operator's box hit).

**DRILL A — Windows process model & every wedge trigger (CONFIRMED from source).** Only a `--server` (SYSTEM, winlogon-token) binds :21118 (`server.rs:761,784`→`direct_service::start_direct_only`); the GUI's `start_server(false)` (`core_main.rs:185`→`server.rs:748,808-816`) **never binds** — the fork deleted upstream's in-GUI self-heal (R-X10). A `--server` is spawned **only** by the installed `--service` monitor (`windows.rs:667,682,720,753`), which **SELF-HEALS a dead `--server`** (`GetExitCodeProcess`→relaunch within `SERVICE_INTERVAL=300ms`, `:748-761`; `--server` exits cleanly on IPC `Data::Close` via `process::exit(-1)`, releasing the port; `panic='abort'` → respawn in 300 ms). **So a `--server` crash/panic/kill self-heals — the wedge requires the `--SERVICE` itself to die**, and the SCM has **no recovery** (`sc create … start=auto`, no `SetServiceFailureActions`, `:2963-2967` → restarts only at BOOT).

Every `--service`-death trigger, ranked (from source):
| # | Trigger | Reachability | Recovery |
|---|---|---|---|
| 1 | **Elevated kill of BOTH `--service`+`--server`** (Task Manager) | needs elevation; killing `--server` alone → respawn 300 ms; killing `--service` alone → the winlogon-token `--server` is independent → keeps serving until it dies | :21118 unbound, no respawn → **wedge until REBOOT** (`start=auto`) / manual `sc start` |
| 2 | **Tray "Stop service"** → `sc stop`+**`sc delete`**+`taskkill` (`windows.rs:2823-2843`, `tray.rs:184`) | UI (BR-8: operator saw no tray) | **wedge until REINSTALL** (service deleted) |
| 3 | **`--service` panic** (`panic='abort'`) in `run_service` | reachable | abort → no SCM recovery → **wedge until REBOOT** |
| 4 | **SCM / `services.msc` stop** | admin tool | **wedge until REBOOT / `sc start`** |
| — | session change / logoff | relaunch `close_first=true` (`windows.rs:677-684`) | **transient, self-heals** |
| — | machine shutdown | clean stop | **restarts next boot (`start=auto`)** |

**Amplifier:** the Windows public bind is exclusive (no `SO_REUSEADDR`, `tcp.rs:299-310`) and `direct_server` retries the identical bind **forever** on `EADDRINUSE` (`direct_service.rs:516-552`) — a lingering :21118 holder is a permanent bind-lock. **Net (from source, not runtime):** the wedge survives an *app* restart (R-X10), but a machine **REBOOT recovers triggers 1/3/4** (`start=auto`); only the tray `sc delete` (2) needs reinstall. **BR-11 fully resolved:** client (GUI) and listener (`--server`) share no in-memory state → a client "X" cannot wedge the server. The one genuine **NEEDS-RUNTIME**: *which* trigger the operator's box hit (a user action absent from the tree; the code constrains it to exactly this table).

**DRILL B — no AUTHED_CONNS slot leak (CONFIRMED, exhaustive).** The slot exists only from `connection.rs:1087` (`AuthedConnID::new`) to `Connection::Drop` (`:5204`→`:5502-5514`). Before `:1087` no slot is held (every pre-auth bail/`break`/cap-reject/login-fail/`wait_desktop_cm_ready`-timeout enumerated). After `:1087` the slot is a `Connection` field owned by the `start()` future → Rust runs `Drop` on **every** completion/`break`/`return`/`?`-unwind/cancellation; the **only** skip is `process::exit`/`abort` (incl. `panic='abort'`), which kills the process → OS reaps everything + the `--service` respawns a fresh `--server`. No `mem::forget`/`Box::leak`. **`panic='abort'` corollary: a poisoned-mutex wedge is impossible.** The `MAX_AUTHED_SESSIONS=16` cap (fork addition) can only **transiently** saturate (16 reaping sessions → "Too many active sessions" `:1034`; BR-10 contributor) and is a **soft** cap (pre-slot check → K racing connections can over-shoot by K; benign, not a leak).

**DRILL C — exact worst-case reap per session type (from constants).** Remote/view-camera/file-transfer/terminal/pre-auth: **≤~31 s** (`test_delay` `SEC30`+`ThrottledInterval`, `connection.rs:357-358,867-871`); pre-key handshake stall ≤~23 s (CPace steps `cpace.rs:36,47`); **port-forward ≤~60 s** (no `test_delay` → TCP keepalive `direct_service.rs:604-608` kills the idle socket; the 3600 s idle-timer is a rarely-reached fallback). FIN/RST → immediate. Improvement over upstream's removed 12–120 s `SEND_TIMEOUT`.

**DRILL D — machine-UUID PRS decrypt-fail → empty → silent park (CONFIRMED trigger; reboot-proof).** `get_permanent_password_prs()` = `decrypt(...).unwrap_or_default()` (`config.rs:1437-1440`) → **any** decrypt failure silently yields empty → `direct_server` **parks, binds nothing** (`direct_service.rs:492-508`) while the GUI shows green "Listening." Park triggers: (1) machine GUID changed (MachineGuid / `/etc/machine-id` / IOPlatformUUID differs from set-time); (2) `machine_uid::get()` fails at read-time → `get_uuid()` caches the pk fallback for the whole `--server` (`lib.rs:330-388`) → the GUID-sealed PRS can't open **and** the `pk!=uuid` fallback is also skipped → empty for that process lifetime; (3) corrupted `password_prs` bytes. **Survives a restart** (stored bytes unchanged). Windows/Linux/macOS only (Android/iOS use the stable persisted pk, `machine_uid` cfg-excluded). NEEDS-RUNTIME (justified): whether the GUID changed / `machine_uid` failed on the operator's box — the code fully determines the *consequence*.

**DRILL E — platform supervision matrix (each cell from its own cfg-gated source) — this IS BR-12.**
| | Listener owner | Respawns `--server` | Supervises the service tier | Permanent wedge on service death |
|---|---|---|---|---|
| **Windows** | `--server` (SYSTEM) | monitor 300 ms (`windows.rs:748-761`) | **NO** — `start=auto`, no failure actions (`:2963-2967`) | **YES** — until reboot (reinstall if `sc delete`d) |
| **Linux** | `--server` (session user) | monitor `try_wait` (`linux.rs:758-768`) | **YES** — systemd `Restart=on-failure`/`RestartSec=2` (`res/rustdesk.service`) | **NO** — self-heals ~2 s (a deliberate `systemctl stop` stays stopped) |
| **macOS** | `--server` (LaunchAgent) | **launchd** `KeepAlive{SuccessfulExit=false}` (`agent.plist`); in-proc monitor commented out (`macos.rs:737-793`) | **YES** — daemon `KeepAlive=true` (`daemon.plist`); `--server`'s `exit(-1)` is *designed* to trigger restart (`ipc.rs:766`) | **NO** |
| **Android** | foreground `MainService` (R-D7a) via JNI (`flutter_ffi.rs:2502-2537`) | n/a | user-controlled FGS lifecycle; `stopServer`→generation bump→accept loop unwinds→socket closes; `START_NOT_STICKY` | **NO** — dies with the process; re-created on next `onCreate` (R-T13 Doze caveat → cavity #4) |
| **iOS** | — viewer only (`connection.rs:282` `cfg(not(ios))`) | — | — | n/a |

Shared un-cfg'd reap loop (`connection.rs`) + writer task (`tcp.rs`) → the ≤~31 s reap holds identically on all four servers. **BR-12 = the SCM-vs-systemd/launchd supervision asymmetry, proven from all four sources.**

**DRILL F — sweep (other leak/linger paths).**
- **`--cm` orphan on Windows-root (CONFIRMED):** `run_as_user`→`run_exe_in_session` returns `Ok(None)` (`windows.rs:894`) → the `if let Some(task)` push is skipped (`connection.rs:4892`) → the `--cm` handle is untracked, never reaped by `check_zombie` (`server.rs:707-722`). Ghost CM window if it fails to self-exit. Not a listener wedge. (Linux/non-root path IS tracked, `:4904`.)
- **Windows clean-stop skips the R-T9 drain (CONFIRMED):** the SIGTERM drain is Unix-only (`direct_service.rs:355-377`); a Windows `--server` stop is IPC `Data::Close`→`exit(-1)` → an in-flight file block truncates on a Windows service stop/upgrade (cleanliness, not a wedge). Conversely macOS `exit(0)` would NOT restart the agent (`SuccessfulExit=false`) → the `exit(-1)` design is load-bearing there.
- Persistent terminal holds a root PTY but is bounded (`MAX_SERVICES=100` + `cleanup_inactive_services`, `terminal_service.rs`); port-forward 3600 s idle-timer (bounded to ~60 s by keepalive); `terminal_generic_service.join()` in `Drop` (~30–60 ms) — all LOW/by-design. No pre-auth connection leak.

**Blast radius (all CONFIRMED-from-source).** BR-9/10/11/12 + persistent root of BR-6 = the Windows `--service`-death wedge (Drill A/E); BR-10 intermittency also from the 16-cap transient (B) + the session-change sub-second gap. BR-5 = the CM `Data::Disconnected` lingering row (`connection.rs:4059-4066`, `ui_cm_interface.rs:302-311`). BR-4 = cosmetic `stop-service` label + the empty-PRS park (D) both show green "Listening" while unable to accept. **BR-6 connection→settings link REFUTED** (the `videoConnCount>0` gate is dead — `canBeBlocked()` always false under pinned `access-mode=full` + no direct `control_permissions`) → real cause is cavity #2.

**Options (NOT-YET-DECIDED).** Windows service resilience is load-bearing: SCM failure/recovery actions (`SetServiceFailureActions`), a rebinding watchdog, or a controlled GUI/in-process re-arm — each trading against R-X9/R-X10. Secondary: replace the cosmetic "Listening" with an honest-reachability signal + make the empty-PRS case fail loud (or repair the PRS) instead of silently parking; the Windows-stop R-T9-drain gap. Treatment chosen later.

### Cavity 2 — Settings write-path & the dead security controls: FINDINGS (Opus 1M, read-only, 2026-07-07) ✅ EXHAUSTIVE — every claim proven from source

**Headline (CONFIRMED).** The desktop "Unlock Security Settings" button gates the whole Safety tab — including the sole-authenticator **"Set permanent password"** — on `check_super_user_permission()`. The fork excised the *active* elevation ceremonies (R-X9 `run_uac`/`elevate` Windows; R-X11 `gtk_sudo` Linux) and rewired that check into a **passive "am I already elevated/root?" probe**, leaving the unlock button + the essential password control behind it. The desktop GUI is **proven never-elevated**, so the probe always returns false, `onUnlock()` never fires, the click is silently swallowed — identically on Windows and Linux (BR-7). macOS diverges (genuine interactive admin dialog → works); Android has no such gate (password works). One mechanism → BR-7, password-half of BR-6, BR-2, settings-half of BR-3.

**The exact break — full chain (cfg-gated source).** `desktop_setting_page.dart:749-752` `locked=mainIsInstalled()`; `:766-778` `preventMouseKeyBuilder = ExcludeFocus+AbsorbPointer(absorbing:locked)`; `:1979-2020` `_lock.onPressed`: `unlockPin` empty → `callMainCheckSuperUserPermission()` **false** → `if(checked) onUnlock()` never runs, **no else** → silent no-op. → `flutter_ffi.rs:1918` → `ui_interface.rs:917` → `platform::check_super_user_permission()`: **Windows** `is_elevated(None)` (passive `TokenElevation`, `windows.rs:2335-2370`; `run_uac`/`elevate` excised) → false; **Linux** `Ok(is_root())`=`username()=="root"` (`linux.rs:1400,1052`) → false; **macOS** `MacCheckAdminAuthorization()` (`macos.mm:84`) → true; **Android/iOS** returns true but mobile UI has **no `_lock` at all**.

**GUI PROVEN never-elevated on Win/Linux.** Windows exe manifest is **asInvoker** — `res/manifest.xml` (via `build.rs:35`) + `runner.exe.manifest` have **no `<requestedExecutionLevel>`** → medium-integrity, no auto-UAC; install elevates only the *batch* (`runas`, `windows.rs:1853`), post-install GUI spawns with the caller's medium token (`windows.rs:2974-2980`); the service is a separate LocalSystem process. Linux GUI runs as the desktop user; root is the separate systemd `--service`. → `is_elevated`/`is_root`=false every ordinary launch → permanent silent no-op (matches BR-7).

**macOS unlock PROVEN WORKS from the framework contract (NOT NEEDS-RUNTIME).** `macos.mm:84-101`: fresh `AuthorizationCreate`+`AuthorizationCopyRights(kAuthorizationRightExecute, flags=InteractionAllowed|PreAuthorize|ExtendRights)`, returns `status==errAuthorizationSuccess`. Apple's Authorization Services contract: InteractionAllowed → the Security Server presents the admin dialog; the `kAuthorizationRightExecute` rule requires admin auth; returns success **only when the user authenticates as admin** (else Denied/Canceled). Fresh authRef per call → dialog every click. → macOS unlock **WORKS**; inert only on cancel/non-admin.

**Platform matrix (each cell from its own cfg-gated source).**
| Control | Windows | Linux/Debian | macOS | Android | iOS |
|---|---|---|---|---|---|
| Unlock Security Settings | **DEAD** (passive `is_elevated`, asInvoker) | **DEAD** (passive `is_root`, non-root) | **WORKS** (interactive admin dialog) | N/A (no `_lock`) | viewer-only |
| Set permanent password (GUI) | **BLOCKED** by lock; CLI `--password` works | **BLOCKED**; CLI works | works after unlock | **WORKS** (menu+auto-prompt, no lock) | no controlled service |
| Pinned security toggles | greyed + locked | greyed + locked | greyed (pinned) even after unlock | greyed | n/a |
| Non-pinned Safety prefs | locked out | locked out | editable after unlock | editable | n/a |

**BR-6 consequences (CONFIRMED).** *Set password*: button (`:889`, inside locked card) `enabled=!locked=false`→`onPressed:null`+AbsorbPointer; home pencil (`desktop_home_page.dart:259`) only navigates into the locked tab; desktop auto-prompt guarded `isAndroid||isIOS` (`server_model.dart:393`). The dialog + its IPC write are sound and are the **exact path CLI `--password` uses** (`ipc.rs:837-848` `Config::set_permanent_password`) — why CLI works, GUI doesn't. *"Enable remote config modification"*: pinned `Y` (`config.rs:3265`), quadruple-inert (AbsorbPointer + `enabled=false` + `fakeValue=true` checked + `isOptionFixed→onChanged:null`) — already ON by policy, shown greyed.

**Complete R-S16 pinned set — 28 keys classified (CONFIRMED).**
- **(A) Correctly pinned AND UI-conformant, removed/hidden per R-G1 (13):** `verification-method`, `approve-mode` (R-X7a), `2fa`, `bot` (R-X7), `api-server`, `custom-rendezvous-server`, `relay-server`, `proxy-url` (Network/SOCKS removed R-G4), `enable-virtual-display`, `allow-websocket`, `allow-insecure-tls-fallback`, `allow-linux-headless`, `stop-service` (Stop button correctly **hidden**, `:430-454`).
- **(B) Correctly pinned BUT shown as greyed live-looking toggle — R-G1 VIOLATION (15):** `access-mode`=full, `enable-{keyboard,clipboard,file-transfer,audio,camera,terminal,tunnel,remote-restart,record-session,block-input(Win),privacy-mode,remote-printer(Win)}`, `allow-remote-config-modification`, `allow-only-conn-window-open` (greyed+fakeValue checkboxes `:813-905`); `enable-record-session` also greyed on Android. **This 15-toggle set is the concrete backbone of BR-14.**
- **Verdict:** the reject-set is **correctly scoped**; the defect is UI honesty — 15/28 rendered as greyed *actuating* toggles instead of read-only/removed (§19 live-looking-dead), compounded by the dead lock.

**Password PROVEN structurally excluded from the reject-set (CONFIRMED).** `is_option_can_save` operates only on the options HashMap; the password is `config.password`/`password_prs` — **struct fields** (`config.rs:236,1425`) written via `Config::set_permanent_password`, and the IPC path (`ipc.rs:837-848`) calls it **directly, bypassing `set_options`/`purify_options`** → the reject-set **structurally cannot swallow the password.** BUILTIN/HARD funnels empty on a fork build (R-A4) → `is_disable_change_permanent_password`/`isUnlockPinDisabled`/`is_disable_settings` all false. The lockout is entirely the Dart `locked` gate. (Corrects the pre-audit hypothesis.)

**Every control trapped behind `locked` (exhaustive) — 5 non-pinned victims beyond the password:** `share-rdp` (Win), `allow-auto-disconnect`+timeout+Apply, `keep-awake-during-incoming-sessions`, the `unlock-pin` setter — all non-pinned/writable but locked out on Win/Linux. The **unlock-PIN is chicken-and-egg dead** (its only setter lives inside the card it would unlock).

**BR-2 one-way trap — fully source-determined; installer-elevation REFUTED.** `locked` is a non-persisted `_SafetyState` field; success `Offstage`-hides the button + releases AbsorbPointer ("disappeared"/"rearranged"), re-inits `true` on next tab build. The button can only vanish via a successful unlock (needs `is_elevated=true`), and the app **never produces an elevated GUI** → the "installer→elevated GUI" theory is **REFUTED**; the one success could only be a manual **"Run as administrator"** launch. Every ordinary launch → inert.

**BR-3 reconciliation (re-proven).** The connection-gated block is dead (`canBeBlocked()` always false — `IS_REMOTE_MODIFY_…` None for direct + `access-mode` pinned full). A live connection does NOT block settings; BR-3's "while connected" is a **misattribution** of the always-on `locked` gate; "no default to enable remote control" is moot (pinned ON, shown greyed).

**Sweep 1 — siblings.** (1) 5 non-pinned controls trapped by the lock; (2) unlock-PIN chicken-and-egg; (3) home "Change Password" pencil dead-end; (4) **`hide_cm()` orphaned dead code** — defined `desktop_setting_page.dart:937-975`, **never called** (§19); (5) the 15 greyed pinned toggles (R-G1). Verified-CLEAN (don't re-flag): Network/Account + SOCKS/ID-Relay removed (R-G4); Android verification/approve/OTP removed (R-X7a); `service()` hides "Stop" when pinned; password IPC arm + dialog sound.

**Sweep 2 — platform (per cfg).** Win/Linux: unlock DEAD, password GUI BLOCKED, 15 greyed toggles, 5 non-pinned locked out. macOS: unlock WORKS then password+non-pinned editable, pinned stay greyed. Android: no lock, password works (`server_page.dart:60`+auto-prompt), pinned greyed. iOS: viewer-only. Shared `_Safety`/`_lock` on Win/Linux/macOS — only `check_super_user_permission` diverges.

**NEEDS-RUNTIME: none** source/framework-derivable. Sole residual is a *user-action* fact (whether the operator's one BR-2 success was a manual Run-as-admin launch — the only source-consistent path).

**Superseded by R-S11b/R-S11c for installed-service password setting.** User-owned mode may keep the
ordinary GUI/CLI password setter; installed service-owned mode requires a typed, admin-authorized service
operation and must not use the old ordinary IPC write. The remaining UI work here is R-G1 honesty for the
pinned/non-pinned controls, not a relaxation of the service-owned credential boundary.

### Cavity 3 — UI ↔ excision coherence: FINDINGS (Opus 1M, read-only, 2026-07-07) ✅ EXHAUSTIVE — every claim proven from source

**Headline.** The Flutter front-end already has **substantial** §19 work done (far more than "nobody looked"): R-G2 (ID board/status/connect-box → direct-address), R-G3 (security badge), R-G4 (account-login/server/proxy/update/elevation editors, OTP board), R-G5 (fingerprint), R-G6 (relay/WOL actions), most of R-G7 (CM click-to-accept + read-only chips) are **done + verified absent from source**. The surviving iceberg = **five clusters** (below). No live security-egress UI found.

**BR-13 Printer (CONFIRMED broken + self-contradictory).** The Printer tab is Windows-only (`desktop_setting_page.dart:68`) → absent on Debian/macOS/Android (operator saw it on Windows). "Install {App} Printer" (`:1465`→`mainSetCommon('install-printer')`→`remote_printer::install_update_printer`, `flutter_ffi.rs:2400`) loads `drivers/RustDeskPrinterDriver/RustDeskPrinterDriver.inf` — **payload exists NOWHERE in the tree** (no `.inf`/`drivers/`/WiX ref) → the click errors (the operator's "glad it doesn't work"). **Novel contradiction:** `enable-remote-printer` pinned **ON** (`config.rs:3262`), but `enable-virtual-display` pinned **OFF** with the rationale it "drives a native display-DRIVER API … the native-code surface the fork minimizes" (`config.rs:3257-3261`) — a print driver is the *same* class, so pinning printer ON (no driver shipped) contradicts the fork's own logic. Class C. Option: ship driver+WiX, OR excise the tab + `enable-remote-printer=Y` pin + `remote_printer` capability (reconcile R-G7).

**Tray (CONFIRMED — `src/tray.rs` read in full).** Two items: "Open" (A) + "Stop service" (C). Neither `OPTION_HIDE_TRAY=Y` nor `OPTION_HIDE_STOP_SERVICE=Y` is set anywhere in `res/`/`build.py` → both render by default. **"Stop service" is a mislabel on all 3 desktops — it UNINSTALLS, not pauses:** Windows `sc stop`+`sc delete` (the cavity-1 self-DoS wedge); Linux `systemctl disable`+`stop`+`exit(0)` (kills boot-autostart, `linux.rs:2065-2084`); macOS osascript-admin uninstall + `launchctl remove` (`macos.rs:315`). **Inconsistency (novel):** the in-app Service card IS hidden under the `stop-service` pin (`desktop_setting_page.dart:430-440`) but the tray keys on the DIFFERENT, unset `hide-stop-service` buildin → hid the in-app button, left the destructive tray item live (BR-8). **No non-destructive quit** in the tray. (I own the label; cav 1 owns the Windows wedge.)

**BR-4 desktop honest-status (CONFIRMED — own the *should-reflect*).** `connection_page.dart:110-120` renders "Listening on :21118" whenever `_svcStopped==false`, and `_svcStopped` is the pinned `stop-service` RxBool (always false) → **green/"Listening" unconditionally** — reflects neither the real socket, the R-S9 empty-PRS park (`direct_service.rs:492`), nor a Windows wedge. **The GUI CAN cheaply observe the truth** — `is_permanent_password_set()` (`ui_interface.rs:522`; FFI `permanent-password-set`) → the lie is derivable-away. **The mobile side already solved it:** `ServerInfo` shows two honest facts — "Reachable on :21118 while this app is open" + "Screen capture ready/not ready" (`server_page.dart:358-386`) — a ready-made desktop template.

**BR-15 "Start service" label (CONFIRMED — own wording; capture model = cavity #4).** Three Android mislabels keying the *listener* to the *capture* toggle: "Start service" (`mobile/server_page.dart:144`), "Service is not running" (`:123`), "Stop service" (`:434`) — frame the listener as off when the port is reachable whenever a password is set. The honest 2-fact `ServerInfo` card already exists but is contradicted by the "service" wording. Option: relabel to "Start screen sharing" + explicit "port open whenever a password is set."

**(E) Pinned-but-shown-as-greyed-live-toggle — R-G1 violations.**
- **NOVEL: "Allow linux headless" checkbox** (`desktop_setting_page.dart:536-538` + `flutter_ffi.rs:930-936` `main_show_option→true` on Linux + pin `config.rs:3278`) — pinned `N` (R-X14/R-S16) yet SHOWN → greyed-unchecked, **DIRECTLY VISIBLE on the Debian box (NOT behind the Safety lock)** — the clearest live R-G1 violation. Linux desktop only.
- Cavity 2's Safety-tab set (access-mode combo + 13 capability checkboxes) — greyed + `fakeValue`-checked + behind the dead `_lock`.

**(B) Dead — backend excised, present-but-inert (hygiene removals, not security hazards).**
- **Account + address-book/my-group subsystem** (~1,200 lines): tab off (`peer_tab_model.dart:37-52` `isEnabled=[T,T,F,F]`), `isLogin` permanently false, `loginDialog` shim (`login.dart:25`); `address_book.dart` (898 ln) + `my_group.dart` (309 ln); `AddressBookPeerCard`/`MyGroupPeerCard` (`peer_card.dart:1030-1222`) never instantiated. Triple-locked dead; **explicitly deferred** (`login.dart:19-22`).
- **WaylandCard** (General tab, `desktop_setting_page.dart:392,1768-1925`): Wayland/pipewire excised (R-X12) → restore-token always empty → whole card `Offstage`. The "hidden ≠ removed" trap the fork's own hwcodec comment (`:387`) calls out.
- Linux home Wayland help cards (`desktop_home_page.dart:397-407`); `formatID` numeric-ID grouping vestige; `Peer.sameServer` relay-hint field; **`hide_cm()` orphan** (`:937-975`); `bind.isDisableAccount()` FFI (zero call sites).

**(C, minor).** Android scam-warning dialog on Start (userName always empty; sovereign fork has no rustdesk.com scam context, `mobile/server_page.dart:136-139`). Legacy numeric-ID recent card renders "connectable" but fails closed (SUSPECTED/NEEDS-RUNTIME — needs a pre-fork on-disk config; fork-native peers unaffected).

**R-G8 branding residuals (SHOULD, minor).** "Powered by RustDesk" (`desktop_home_page.dart:85`, `mobile/settings_page.dart:149`); About "About RustDesk"/"Purslane Ltd."/`Slogan_tip` (`desktop_setting_page.dart:1572-1604`). rustdesk.com links already removed.

**(A) Keep — coherent (representative).** General (theme/lang/audio-input/recording-dir/bitrate/render/DirectX-capture(Win)/keep-awake/wallpaper/new-tab), Display (view-style/scroll/quality/codec/trackpad/privacy), the full in-session toolbar (all act on an already-authed peer), connect box (direct address), peer context menus (funnel through `connect()`→`isDirectAddress` fail-closed; Forget-Password clears password + CPace PRS), CM read-only chips, the Android permission ceremony, About.

**Options (NOT-YET-DECIDED).** Printer: ship-driver vs excise (reconcile R-G7 + the native-driver-minimization precedent — leans excise). Tray: relabel/suppress/non-destructive-exit (interlock with cav 1's Windows resilience). BR-4: mirror the mobile 2-fact model via `permanent-password-set` (+ optional real bind probe). BR-15: relabel to "Start screen sharing" + port-open messaging. (E): remove or render read-only "set by policy" (the Linux "Allow linux headless" most urgent). (B): the deferred ~1,200-line account/AB compile-out.

**Confidence.** All CONFIRMED-from-source except: legacy-numeric-ID card (NEEDS-RUNTIME — migrated config), the exact Install-Printer error *string* (that it fails is CONFIRMED via absent payload), and ruling out an out-of-tree CI injection of the INF / `hide-stop-service=Y` (none in-tree).

### Cavity 4 — Android controlled-side model: FINDINGS (Opus 1M, read-only, 2026-07-07) ✅ EXHAUSTIVE — every claim proven from source / API contract

**BR-17 — exact boot-consent mechanism (CONFIRMED).** Chain: `BootReceiver.onReceive` (`BootReceiver.kt:18-44`, `ACTION_BOOT_COMPLETED` if battery-opt exempt) → `startForegroundService(MainService, action=ACT_INIT_MEDIA_PROJECTION_AND_SERVICE, EXT_INIT_FROM_BOOT=true)` → `MainService.onCreate` starts the **listener only** (`FFI.startServer`, `:312`, no projection) → `onStartCommand` (`:402-424`): the projection-result extra is **null** on boot → the `?: let { requestMediaProjection() }` branch fires (`:420`) → `PermissionRequestTransparentActivity` → `createScreenCaptureIntent()`+`startActivityForResult` = the system dialog. Surfaces on **unlock** (can't draw over the keyguard at boot). **Two root causes:** (1) **`EXT_INIT_FROM_BOOT` is SET but NEVER READ** (`common.kt:32`) → boot is indistinguishable from a deliberate "Start service"; both request projection — a plumbed-but-unwired boot/start split. (2) Neither boot nor `onStartCommand` gates on the password → the consent fires **even with no password set** (listener would just park, R-S9).

**Listener-vs-capture model (CONFIRMED) — three distinct states.** (a) **Listener** (:21118 → file-transfer/clipboard/terminal): binds iff a permanent password is set (R-S9 park, `direct_service.rs:492-529`); owned by the FGS (R-D7a); persists from boot/Start until an explicit Stop or process kill (`START_NOT_STICKY` + generation teardown → "service stopped ⇒ socket closed"). (b) **MediaProjection consent** (`_isReady`): from Start-service, boot, or a stale-token retry. (c) **Capture** (`_isStart`): needs the token; fires from `add_connection` for **screen sessions only** (`MainService.kt:130-134`). **File transfer needs only the listener** (no capture) — exactly the operator's observation; it works "without Start service" because the FGS was already running (boot autostart / a prior start); a *fresh* app-open with no prior FGS does NOT auto-start the listener (`runMobileApp` doesn't call `startService`).

**Consent-on-connect FEASIBILITY — VERDICT: FEASIBLE (key deliverable).** Feasible as a **notification-launched** consent at connect-time; not as a silent background auto-prompt — but that isn't wanted (attended; the human approves). **Controlling constraint (API contract):** a foreground service does NOT grant background-activity-launch (BAL); the consent dialog is a system Activity. `SYSTEM_ALERT_WINDOW` dropped (R-X6) → unavailable. **BAL-exempt paths that ARE available:** an Activity from a **notification-tap `PendingIntent`** (all versions, no permission) or a **full-screen-intent** notification (auto-surfaces even over the keyguard). FSI on Android 14+ is restricted **by the Play Store at install, not AOSP** — the fork is **sideloaded** → ≤13 auto-grants and 14+ likely retains it (NEEDS-RUNTIME per OEM; runtime-detectable via `canUseFullScreenIntent()`), degrading to tap-to-consent where unavailable. **So the operator's design is correct + achievable** (may present as tap-to-consent vs auto-surface on some 14+ OEMs); strictly better than the boot-time speculative prompt.

**Best-achievable design (direction, NOT-YET-DECIDED).** (1) **Decouple boot from capture (BR-17 core fix):** boot starts the listener/FGS ONLY — honor the already-plumbed `EXT_INIT_FROM_BOOT` in `onStartCommand` to skip `requestMediaProjection()`. Preserves the always-on password-gated listener the operator *wants*; kills the boot popup. (2) **Lazy consent at connect:** when an authorized **screen** session arrives (`add_connection`) with no token, post a HIGH-importance notification (channel already `IMPORTANCE_HIGH`) with a content `PendingIntent`→`PermissionRequestTransparentActivity` (tap) **and** `setFullScreenIntent`+`CATEGORY_CALL` (auto-surface where granted). (3) **New edge required:** wire "consent-granted ⇒ `startCapture()` for the waiting session" — today `add_connection` starts capture only if the token is *already* present, no retry when consent lands after. (4) **Keep** the foreground "Start screen sharing" tap as the direct path. **Hard constraints (CONFIRMED from API contract):** C1 no zero-touch background prompt (must ride a notification); C2 device unlocked + human present (Android 15 auto-stops capture on lock + per-session re-consent — *helps* this design); C3 targetSdk 33 → token reusable within the FGS lifetime → consent only on the **first** screen session after start (if bumped ≥34, add `FOREGROUND_SERVICE_MEDIA_PROJECTION`+ordering, per R-X6); C4 the session must be **held** during "waiting for consent," not failed (today `startCapture` returns false and gives up).

**BR-16 Terminal (Beta) whitewash — ALREADY FIXED AT HEAD (CONFIRMED).** Upstream `backgroundOpacity: 0.7` on the mobile `TerminalView` → `theme.background.withOpacity(0.7)` over the light `scaffoldBackgroundColor` bled through. Fixed to `1.0` (solid dark) at `terminal_page.dart:172` (+ desktop twin `:198`) in commit `8c0180d` (2026-07-05), **after** the tested release `ab084e3` (2026-07-04, carried `0.7`). **Ship-forward: no code change; lands in the next build.**

**Sweep 1 — other Android-model defects.**
- **Scam-warning dialog on every "Start service" (CONFIRMED).** `ScamWarningDialog` (`mobile/server_page.dart:136-144,150-340`) shows when `userName.isEmpty && show-scam-warning!="N"` — accounts excised → `userName` **always empty** → the 12-second-countdown "I Agree" dialog fires on the first Start-service + the Screen-Capture permission tap. Upstream's public-relay social-engineering warning — incoherent for the sovereign direct-IP+password fork (mobile BR-14 sibling). Treatment: excise or pin `show-scam-warning=N`.
- **`ServerInfo` fact (1) is an unconditional green lie (CONFIRMED — mobile BR-4 analog).** `server_page.dart:367-373` hardcodes a green check + "Reachable on :21118 while this app is open" reading **no runtime state** — wrong both ways (up while the app is *closed* since the FGS persists; down while *open* if no FGS/no password). Fact (2) "capture ready" (reads `mediaOk`) is honest. Direction: gate fact (1) on `permanent-password-set` + service-running.
- Fresh-install no-password crash **FIXED** (`process::exit` removed; Dart gate + R-S9 park). R-D7a SHOULD residuals DONE (keep-screen-on pinned, dead `useVP9` excised). No other unprompted boot permission. Minor: BootReceiver shows a `Toast "RustDesk is Open"` on every boot.

**Sweep 2 — cross-platform contrast.** iOS: no controlled side (viewer-only). **Desktop capture has NO per-session OS consent** (Linux X11/`scrap` + Windows DXGI capture with no dialog; macOS = persistent app-wide TCC) — **Android is the sole outlier** (mandatory per-session, human-tapped, un-persistable `MediaProjection`), which is *why* consent-on-connect is an Android-only design problem. Shared invariant (already correct on Android): capture begins only inside a confirmed PAKE session (R-S14/R-A1; `startCapture` only via authorized `add_connection`).

**NEEDS-RUNTIME (minimal).** FSI auto-surface retention on the operator's specific 14+ OEM (doesn't block the design — the tap path works everywhere); whether consent auto-surfaced over the keyguard (cosmetic); BR-16's APK-provenance link (the tested prerelease carried `0.7`, git-confirmed).

### Cavity 5 — File-transfer host session/user context (BR-1): FINDINGS (Opus 1M, read-only, 2026-07-07) ✅ EXHAUSTIVE — every claim proven from source

**BOTTOM LINE.** BR-1 is **only HALF-FIXED at HEAD.** The sole BR-1 commit (`8ec46d3`, in HEAD + the deployed prerelease `7c16d75`) removed the **"No active console user logged on"** refusal — but the **actual breakage ("no files / no path / create-folder does nothing") REMAINS**. Root cause (CONFIRMED): on a systemd-less/logind-less host, every file-transfer dir/create op is delegated to a separate **`--cm` process that NEVER STARTS**, because `start_ipc` hangs forever in `loop { if !is_prelogin() break }` and `is_prelogin()` is permanently **true** with no logind seat0. The commit's own premise ("file I/O runs in the CM process … independent of it") is exactly the bug: that CM process doesn't run. The operator's instinct ("broken on a system without systemd") is precisely correct.

**"No active console user" origin (CONFIRMED — 4 sites; operator saw the VIEWER one).** Server-side sites are terminal-only + `cfg(windows)` (`connection.rs:1932-1940,3036-3040`). The one hit on Linux is the **viewer** gate (`ui_session_interface.rs:1711-1722,1521-1539`), which upstream fired whenever `pi.username.is_empty()` regardless of peer OS. **`8ec46d3` fixed it** (all at HEAD): server falls back to `whoami::username()` (the `--server` owner) when `get_active_username()` is empty (`connection.rs:1102-1110`, `cfg(linux,macos)`); the viewer gates now require `peer_is_windows` (`:1717,1525`). So the refusal is genuinely closed for a Linux peer — **but that is the ONLY thing 8ec46d3 changed; it did not touch the CM spawn.**

**Where it breaks (CONFIRMED).** Dir-list/create flow: viewer → wire `ReadDir`/`CreateDir` → controlled `--server` (`connection.rs:4358,2605`) → `send_fs`→`tx_to_cm` → drained **only inside `start_ipc`** (`:4970`) → the **`--cm` process** (`ui_cm_interface.rs:918→1600/1659`, home = `Config::get_home()` for an empty path). **`start_ipc` never passes its first statement:** `connection.rs:4783-4788` `loop { if !is_prelogin() break; sleep(1) }` — `is_prelogin()==true` on headless → spins forever → the `--cm` is **never spawned**, `rx_to_cm` never drained → every `ReadDir`/`CreateDir` sits unread. Matches BR-1 exactly: "no files" (`FileResponse` never returns), "home = no path / back doesn't help" (Flutter remote home is `""`, `file_model.dart:495-502,380-419`; every remote `fetchDirectory` goes over the wire into the dead CM), "create-folder does nothing" (`CreateDir` never reaches `fs::create_dir`). The viewer's **local** pane works (in-process); only the **remote** pane depends on the dead CM. **Secondary blocker even if the loop passed:** with `is_headless_allowed()` pinned `N` (`config.rs:3278`), a **root** `--server` spawns the CM via `run_as_user(["--cm"], None)` → `get_active_user_id_name()` empty → `bail!("No valid uid")` (`linux.rs:1075-1082`); a **non-root** `--server` would `run_me(["--cm"])` and could start — but the `is_prelogin()` hang fires **first and regardless of root-ness**.

**systemd/logind dependency (CONFIRMED — the fork's own smoke test asserts it).** `get_active_username()` → `get_values_of_seat0` → **`run_loginctl`** (the `loginctl` CLI). No systemd-logind → `loginctl` absent/errors → empty. `is_prelogin()`: empty name → `run_cmds("getent passwd ")` → the empty arg collapses to `getent passwd` (no arg) → lists **every** passwd entry → contains `/usr/sbin/nologin` → **true** (`smoke-server.sh:288-289` states this outright). Nothing consumes that fact to fix the CM-spawn hang.

**Why screen-control + terminal work but file-transfer doesn't (differentiator, CONFIRMED).** Screen-control captures via X11 `DISPLAY` (no CM). Terminal runs **in the `--server` process** (`init_terminal_service`/`handle_terminal_action`, `connection.rs:4715-4735`; token `SelfUser`) — no CM, no `start_ipc`, no `is_prelogin`. **File transfer is the ONLY session type that delegates to the separate `--cm` process** — the one wedged behind the hang. The fork's smoke comment **mis-attributes** the missing dir response to "the CM needs a display this container lacks" (`smoke-server.sh:294-296`) — wrong twice: the CM's `read_dir` is pure filesystem (no display), and haggai HAS a display yet file-transfer is still broken. The fork validated the symptom it fixed, not the one that remained.

**Correct-by-construction options (NOT-YET-DECIDED).** Consistent with §2/R-S8 (file transfer serves at the `--server`/service privilege for the CPace-authed owner) + R-F1 (the `SelfUser` the terminal reports): (1) **Mirror the terminal** — run the file-transfer CM as the `--server` owner unconditionally on a headless box (skip the `is_prelogin()` wait; take `run_me(["--cm"])` same-user when no console user, not `run_as_user(None)`). (2) **Short-circuit the `is_prelogin()` gate** in `start_ipc` for the direct `--server`/headless deployment. (3) **Resolve the browsing root from the process owner** (`getpwuid` of the `--server` uid / process `$HOME`) rather than `Config::get_home()`'s seat0 assumptions. Any makes the context the *service user's* — as terminal + capture already do.

**Sweep 1 — siblings.** **`try_start_desktop` over-broad headless gate (latent):** `connection.rs:1949-1957` calls it for **all** session types (no `is_remote()` guard); on a box with **no Xorg / no `/usr/share/xsessions`**, `detect_headless` returns `DESKTOP_XORG_NOT_FOUND`/`NO_DESKTOP` (not tolerated) → the file-transfer/terminal **login is refused** even though neither needs a desktop. Doesn't bite haggai (XFCE → tolerated `SESSION_NOT_READY`); flag for a truly GUI-less server. `Config::get_home()` `$HOME`/`/root`-patch reliance (secondary). O_NOFOLLOW/symlink write path (R-S8/R-A5) orthogonal + clean; FUSE not in this path; `sanitize_relative_names` as named doesn't exist (validation inline in `fs.rs`).

**Sweep 2 — platform matrix.** Linux headless (haggai): **BROKEN** (is_prelogin hang; root also bails `run_as_user(None)`). Linux desktop / Windows logged-in / macOS console-user: **work** (Windows pre-logon SYSTEM correctly refused by design). **macOS headless: SAME breakage class** (is_prelogin → hang). **Android: WORKS** — **in-process CM** (`start_channel`→`start_listen` thread, `connection.rs:490`, `flutter.rs:1610`; home = `APP_HOME_DIR`), no `--cm` subprocess, no `is_prelogin` — matching BR-1's "works between Windows and Android." **Decisive fact: Android does file ops IN-PROCESS; every desktop platform delegates to a `--cm` subprocess whose spawn depends on a console/logind session** → Android immune, headless Linux/macOS not.

**Confidence.** All CONFIRMED-from-source. NEEDS-RUNTIME (narrow, moot): which downstream blocker fires *if* the is_prelogin loop were passed (root-dependent) — doesn't change the conclusion (the hang fires first, deployment-independent).

### Adversarial-verification + completeness pass: FINDINGS (Opus 1M, read-only, 2026-07-07) ✅ — investigation confidence HIGH

**Verdict: all five cavities' core claims remain CONFIRMED** (independently re-traced). Net = two corrections, a materially larger cavity-5 scope, three cross-cavity misses, and one spec-violating treatment flag.

**Cavity 5 UNDER-COUNTED — the headless CM-spawn hang breaks a CLUSTER, not just file-transfer (CONFIRMED).** The `is_prelogin()`-gated `--cm` dependency also kills, on a logind-less Linux box:
- **F2 — Host audio** (`audio_service.rs:98-99` → `ipc::connect("_pa")`; the `_pa` server is CM-spawned only, `flutter.rs:1588`) → host→viewer audio breaks on headless Linux via the SAME hang. (Clipboard-text stays clean — in-process `arboard`.)
- **F3 — Whiteboard carries a SECOND, INDEPENDENT copy of the hang:** `whiteboard/client.rs:144-149` `loop { if !is_prelogin() break; sleep(1) }` before `ipc::connect("_whiteboard")`. **Any headless-CM fix (T5) must patch BOTH sites** (this + `connection.rs:4783-4788`).
- **F4 — Chat + voice-call** are CM-hosted (`connection.rs:2782` `send_to_cm(ChatMessage)`; voice-accept via `rx_from_cm`) → non-functional with no CM.
So T5 fixes more than BR-1 (file-transfer + audio + whiteboard + chat/voice) and must patch both hang sites.

**Cavity 4 consent-on-connect DOWNGRADED to TAP-TO-CONSENT-ONLY (CONFIRMED).** A foreground service does not grant background-activity-launch; `SYSTEM_ALERT_WINDOW` is dropped; `USE_FULL_SCREEN_INTENT` is **absent from the manifest** and FSI is restricted to calling/alarm apps on 14+; the hold+resume edge doesn't exist. **Net: consent-on-connect is achievable only as a notification the user must TAP** — not the auto-surfacing full-screen-intent the cavity floated (it hedged, so this sharpens). T4 scopes to tap-to-consent (or accept adding `USE_FULL_SCREEN_INTENT` + its 14+ limits). BR-17 nuance: on API≥29 the boot-path speculative dialog is itself BAL-restricted (may not surface on modern devices; operator's device = API 22–28 or an OEM allowance) — either way the fix (honor `EXT_INIT_FROM_BOOT`) is robust.

**New completeness findings (cross-cavity misses).**
- **N1/F1 — Android orphaned-listener race (CONFIRMED; reopens "Stop doesn't stop"):** the R-D7a generation-snapshot has a race where the listener can survive a "Stop" — reopening the very issue R-D7a was meant to close. HIGH; T4 must close it (exact mechanism to pin during implementation).
- **N3 — Linux fast-crash-loop start-limit lockout (CONFIRMED) defeats R-T1(a):** a fast `--server`/service crash loop trips the systemd start-limit and locks out restart. Interacts with the T1 Windows-resilience decision (both are "supervisor recovery" questions).
- **F5 — Android MediaProjection release asymmetry (SUSPECTED→CONFIRMED):** `MainService.onDestroy()` (`MainService.kt:319-331`) tears down the listener but NOT `mediaProjection` (null'd only in the app-driven `destroy()` `:549`; `.stop()` never called) → a system-initiated `onDestroy` leaks the projection until process death (R-S14 SHOULD "release when not running"). Bounded (start-capture stays auth-gated; new instance = null token) → hygiene gap, not a live capture-after-stop hole. Inherited from upstream.

**Reconciliation (verifier more precise).** Cavity 5's `try_start_desktop` "latent over-broad headless gate" is **neutralized on the shipped build**: `allow-linux-headless` pinned `N` → `is_headless_allowed()==false` → `try_start_desktop` returns `""` with no refusal (`config.rs:3278`; `connection.rs:1950`). Moot for haggai.

**⚠️ SPEC-VIOLATING TREATMENT FLAG — HELD FOR OPERATOR RECONCILIATION (NOT decided autonomously).** **Excising the `enable-remote-printer=Y` pin (the leaning T3 printer fix) CONTRADICTS R-S16/R-D8/R-G7** (which retain remote-printer as a Y capability). The printer must NOT be autonomously excised. Options for the operator: (a) ship the `RustDeskPrinterDriver.inf` payload + WiX (make it work, per the spec's retention); (b) keep the capability but hide/relabel the broken Install button honestly when no driver is present (spec-consistent honest-status); (c) reconcile the spec to drop it. **Held for operator decision.**

**Verified-CLEAN (corroborating).** Android manifest R-X6-conformant (SYSTEM_ALERT_WINDOW / legacy-storage / DEBUG_BOOT_COMPLETED absent, `allowBackup=false`, cleartext denied, BootReceiver `exported=false`, targetSdk 33); no auto-restart surface (START_NOT_STICKY; no WorkManager/AlarmManager/JobScheduler); `startService` hard-gated on a complexity-validated password; on headless Linux screen/cursor/keyboard-mouse/clipboard-text/CLIPRDR/port-forward/RDP/terminal all work; BR-16 confirmed HEAD-only.

**Overall confidence: HIGH.** All five cavity cores confirmed; the corrections make T5 larger (both hang sites + the audio/whiteboard/chat-voice cluster) and T4 tighter (tap-to-consent); the strongest added issues are N1/F1 (Android orphaned-listener race), N3 (crash-loop lockout), F5 (projection leak); the one spec-violating lean (printer excision) is held for operator reconciliation.

### Implementation plan — treatments (sequential Opus 1M; each: implement → find-the-flaw review → my review → commit ONLY if it verifies clean; decisions per requirements.html principles)

Order = highest real-world value + spec-clear first; each verified (verify.sh / smoke-server.sh / dart-verify / apk / Win-VM as applicable) before commit:
- **T5 — Headless CM cluster (cavity 5 + F2/F3/F4):** spawn the file-transfer `--cm` as the `--server` owner on a logind-less host (per R-S8/R-F1), patching BOTH `is_prelogin()` hang sites (`connection.rs:4783`, `whiteboard/client.rs:144`). Restores file-transfer + audio + whiteboard + chat/voice on the haggai deployment. ✅ **DONE `98fc028`** — new `platform::is_headless_no_console_user()` helper drives one factored decision at both sites; verify.sh + smoke-server.sh 9/9 + cargo-check(both) green; find-the-flaw review APPROVE (no Crit/High/Med; 1 Low comment-accuracy fixed, 1 Low pre-existing noted). Runtime dir round-trip to confirm on a rebuilt flutter `.deb` on haggai (docker smoke is a CM-less compile-proxy).
- **T2 — Settings unlock/password (cavity 2):** drop the dead elevation `_lock` gate → Set-Password settable on Win/Linux; free the 5 trapped non-pinned prefs; R-G1-render the 15 pinned toggles read-only "set by policy"; delete `hide_cm()`; fix the home pencil. ✅ **DONE `b1c243c`** — + excised the now-dead unlock-PIN subsystem end-to-end (Dart/FFI/IPC/config/CLI — its consumer the lock was gone → inert R-G1 control; the find-the-flaw review drove it); flutter-verify + dart-verify + verify.sh green, unlock-pin tokens grep-zero. Runtime desktop render to confirm on the rebuild.
- **T4 — Android (cavity 4 + N1/F1/F5):** honor `EXT_INIT_FROM_BOOT` (decouple boot from capture — the BR-17 core fix); close the N1/F1 orphaned-listener race; F5 projection release on `onDestroy`; excise the scam-dialog; honest ServerInfo status; relabel "Start service"→"Start screen sharing" (BR-15). ✅ **DONE `66ec419`** (fixes only) — BR-17 boot-decouple; N1/F1 fixed by capturing the R-D7a generation **by value** (the thread was re-reading it late → a Stop was adopted not obeyed); F5 onDestroy release; scam-dialog excised end-to-end (3 keys × 51 locales + 642KB `scam.png`); a **real `DIRECT_LISTENER_BOUND` RAII signal** (set at bind, cleared on every teardown incl. the tokio runtime-abort) now drives honest mobile status (replaced the optimistic `isStart` lie). Two find-the-flaw passes drove the isStart→real-signal fix + the RAII abort-safe teardown; apk + dart-verify + flutter-verify + verify.sh + smoke ALL green. **Consent-on-connect SPLIT OUT** → flagged for operator UX review (feasibility = tap-to-consent, design in cavity 4).
- **T1 — Windows resilience + honest status (cavity 1 + N3):** ✅ **DONE `741d3b1`** — Windows `sc failure` crash/kill auto-restart (OS-supervisor parity with systemd/launchd, R-X9/R-X10-clean, clean-stop-stays-stopped verified from the SCM handler); non-destructive tray "Exit" (cfg'd OUT on macOS, where the tray shares the `--server` process → `process::exit(0)` would self-DoS the listener with no launchd restart — a find-the-flaw catch) replacing the destructive `sc delete` "Stop service"; honest desktop status bridged **cross-process** (the real `DIRECT_LISTENER_BOUND` lives in the `--server`, read via a new read-only IPC GET arm — a wedged/down daemon reads not-reachable, BR-4); N3 `StartLimitIntervalSec=0`. verify.sh + dart-verify + flutter-verify + apple-conform green; Windows compile/runtime deferred to the `.msi` rebuild / a real Windows box. (empty-PRS auto-repair deliberately NOT done — honestly surfaced instead; re-setting the password rebuilds the PRS.)
- **T3 — UI coherence remainder (cavity 3):** ✅ **DONE `79078c0`** — removed the directly-visible Linux "Allow linux headless" R-G1 toggle (it gates the compiled-out R-X14 subsystem → R-G1 *delete*, not read-only) + the dead WaylandCard (R-X12, verified-Offstage, −159 ln) + the §19 no-leftovers sweep of the orphaned Wayland/headless backends (`main_show_option`; the Wayland restore-token FFI/IPC chain + its `Data` variant + web stubs; 3 lang keys × 51 locales); kept the conditionally-live home-page Wayland cards + their keys. R-G8 branding flagged for operator (NOT rebranded; "Powered by RustDesk" already de-branded); ~1,200-line account/AB compile-out deferred. dart-verify + flutter-verify + verify.sh green; find-the-flaw APPROVE + reviewed the §19 sweep.
- **HELD for operator reconciliation:** the Printer (excising `enable-remote-printer` contradicts R-S16/R-D8/R-G7). BR-16 = already fixed at HEAD (ship-forward, no code).

### Deferred (post-treatment) audits — run AFTER the cavity decisions are made and the changes implemented
- **Android background battery-drain audit.** Once the Android controlled-side model (cavity #4) is finalized and built, specifically audit the battery cost of keeping the listener / foreground-service active in the background — Doze / App-Standby behavior, any wakelock / the R-T13 CPU-keepalive, the persistent FGS notification, and network-wake — to confirm that treating the phone as an always-reachable host does not hurt background battery life too much. The operator is pro-"Android-as-a-computer" but wants this validated. By nature partly a real-device measurement (NEEDS-RUNTIME), paired with a from-source review of what stays awake.

_Status (2026-07-07): **cavities 1 & 2 re-drills = EXHAUSTIVE / done** (all proven from source). Cav 1 = the Windows `--service`-death wedge (no SCM recovery; reboot recovers most triggers) + reboot-proof empty-PRS silent park + no slot leak possible. Cav 2 = the dead elevation-gated unlock on Win/Linux (macOS works, Android has no lock), the 28-key pinned set with **15 greyed R-G1 toggles = BR-14's backbone**, the password proven structurally un-swallowable, `hide_cm()` dead. **Cavity 3 = EXHAUSTIVE / done** (§19 largely already done R-G2..G7; surviving iceberg = 5 clusters: the unshipped-driver Printer BR-13 self-contradictory vs the native-driver-minimization pin; the tray "Stop service" mislabel+self-DoS shown-by-default with no non-destructive quit; the NOVEL directly-visible Linux "Allow linux headless" greyed R-G1 toggle; the desktop "Listening" config-lie [mobile has the honest 2-fact template]; the Android "Start service" mislabels; + ~1,200 ln deferred account/AB scaffolding + dead WaylandCard). **Cavity 4 = EXHAUSTIVE / done** (BR-17 boot-consent = `onStartCommand` requesting MediaProjection because the plumbed-but-unread `EXT_INIT_FROM_BOOT` never splits boot from Start; consent-on-connect PROVEN FEASIBLE via a notification / full-screen-intent [BAL constraint; sideloaded FSI]; BR-16 Terminal-opacity ALREADY FIXED at HEAD `8c0180d`, ship-forward; scam-dialog + ServerInfo-green-lie siblings). **ALL 5 CAVITIES = EXHAUSTIVE / done.** Cav 5 = BR-1 is only HALF-fixed: `8ec46d3` closed the "No active console user" refusal but NOT the real breakage — the file-transfer `--cm` process never spawns on a logind-less host because `start_ipc` hangs in `loop{if !is_prelogin() break}` and `is_prelogin()==true` with no seat0 (the fork's own smoke test asserts it); terminal/screen work in-process/X11; Android works because its CM is in-process. **The adversarial-verification pass = done; investigation confidence HIGH.** It confirmed every cavity core, EXTENDED cav 5 (the headless CM-hang breaks a cluster — file-transfer + audio + whiteboard [2nd hang site] + chat/voice), TIGHTENED cav 4 (consent-on-connect = tap-to-consent only), and found 3 cross-cavity misses (N1/F1 Android orphaned-listener race reopening "Stop-doesn't-stop"; N3 Linux crash-loop start-limit lockout; F5 MediaProjection release leak). One spec-tension HELD for operator reconciliation: excising `enable-remote-printer` contradicts R-S16/R-D8/R-G7. **Ledger `f0f4037` + T5 `98fc028` + T2 `b1c243c` pushed.** SEQUENTIAL IMPLEMENTATION (each: Opus 1M → find-the-flaw → my review → commit only if clean). **T5 DONE** (`98fc028`, headless CM cluster). **T2 DONE** (`b1c243c`, settings unlock/password + unlock-PIN excision). **T4 DONE** (`66ec419`). **T1 DONE** (`741d3b1`). **T3 DONE** (`79078c0`). ✅ **ALL 5 TREATMENTS COMPLETE** (T5 `98fc028`, T2 `b1c243c`, T4 `66ec419`, T1 `741d3b1`, T3 `79078c0` — each verified + adversarially reviewed + pushed to origin/master). **NEXT: Phase 4 — the full R-B2 rebuild** (cold double-build Debian/Android/Windows via `build-release.sh` + the gate suite) to byte-reproducibly confirm the whole implementation. **HELD for operator:** the Printer (R-S16/R-D8/R-G7 tension); consent-on-connect (UX, tap-to-consent design in cavity 4); the ~1,200-line account/AB compile-out (deferred); the R-G8 About-page branding (SHOULD). **Runtime confirmations that need real hardware:** the Windows `windows.rs` compile + SCM-restart (VM `.msi` build / a Windows box); the T5 file-transfer round-trip + the honest status (a rebuilt haggai `.deb`). Plus the deferred Android battery audit._

## Upstream-CVE coverage — the 2026 RustDesk client CVE inventory

Cross-checked (2026-06-29) the fork's hardening against the **complete public 2026
RustDesk client CVE set** (the spec's batch `CVE-2026-30783..30798`/`3598`/`2490`
plus the post-spec **`CVE-2026-58056`**). **Every one is covered** — the
spec's PAKE-plus-excisions design attacks exactly the root-cause classes the CVE
researchers later found:
- **signaling / strategy-sync / heartbeat / address-book** (`30783`/`30792`/
  `30798`/`30795`/`30796`) → the rendezvous mediator, `hbbs_http::sync`, and the
  account/address-book module are **excised** (R-D4/R-X3/R-SV6).
- **URI-scheme CSRF / missing-authz config-import** (`30793`/`30797`/`30791`) →
  the deep-link config/password/key write authorities are **excised** (R-X6/R-X4).
- **offline password brute-force / weak hashing** (`30789`/`30785`) → the PAKE
  replaces the unstretched hash; no offline-crackable material (R-S6); the
  at-rest store is the #14 HARDEN+ACCEPT residual.
- **client AiTM (cert-validation on retry)** (`30794`) → insecure-TLS-fallback
  excised, pinned `N`.
- **`CVE-2026-58056` session-type-confusion** (a FileTransfer-authorized peer
  injecting keyboard/mouse + reaching screenshot/display handlers) → **non-issue
  by design**: all those handlers sit behind the lone post-PAKE `self.authorized`
  edge (connection.rs, set only on the CPace `KEYED` success, R-S2/R-A2), so
  reaching them requires the PAKE password = the §2-trusted owner; and R-S2/R-S18
  make conn-type an intentional capability *tag* (capabilities gated by the pinned
  `Permission` flags, not conn-type). The single-PAKE-credential model dissolves
  the upstream confusion — a "FileTransfer peer" here is a password-knower
  exercising access it already has, no escalation.
- The **server / Server Pro** CVEs (`30784`/`3598`/`30796`-Pro) are N/A — the
  rendezvous/relay server is excised entirely.

## Appendix C #2b (native-decode RCE surface) — ACCEPTED residual

Per the spec, Appendix C #2b — a full viewer decoding a hostile-but-password-correct
peer's media through in-process C codecs (libvpx/aom/libyuv/opus/zstd + Windows
CLIPRDR) — is dispositioned **`ACCEPT` + SHOULD-sandbox**: "a *universal residual*
... bounded operationally (connect only to peers you trust) ... recorded as a
**documented residual** not closable by keying — the fork SHOULD sandbox the
decode path." It is **not** a MUST.

**The residual is armed, not latent (recorded 2026-07-05 under the universal-deployment re-rating).**
The pinned in-process decoders on the peer-reachable **viewer** path carry **open, unfixed, RCE-class
CVEs right now** (see `docs/NATIVE-CODEC-WATCH.md`, recorded 2026-06-29 against the Debian security tracker):
- **libaom 3.12.1** — the AV1 decoder (`aomdec`), reached when a hostile peer sends an `Av1s` frame:
  **CVE-2026-56211** (remote code execution), **CVE-2026-56209** (arbitrary address write),
  **CVE-2026-56210** (heap-buffer-overflow read), **CVE-2026-56208** (heap buffer overflow). No-DSA /
  unfixed across every Debian release — **no fixed aom release exists**.
- **libvpx 1.15.2** — the VP8/VP9 decoder: **CVE-2026-1861**, a decoder heap buffer overflow (malformed
  video → OOB heap write; fixed in Chrome 144.0.7559.132 via "enhanced bounds checking in the libvpx
  decoder"). The pinned 1.15.2 (a 2025 release) predates the fix; the fixed libvpx commit is not yet pinned.
All lie in the **decoder**, not the encoder (the fork encodes its own screen, so encoder-only advisories
are N/A). So the spec's "pinned ≠ CVE-free" caveat is **not hypothetical**: there are live, unfixed
memory-corruption / RCE bugs on the exact bytes an in-process viewer decodes when connected to a
hostile-but-password-correct box — in **every** binary (every build ships the full viewer, R-R2b). This
does not change the `ACCEPT`/SHOULD disposition, but it makes the SHOULD-sandbox the **highest-value open
hardening item** for a universal-deployment posture (where a viewer routinely connects to boxes it does
not control), and the strongest argument to reconsider a *narrow* decoder sandbox (a maintainer call — do
**not** unilaterally re-add the reverted subsystem). The controlled/`--server` role is **unaffected**: it
decodes no peer video (it encodes its own screen); its only inbound native decode is Opus, gated behind an
operator-accepted voice call (R-S19), plus 64 MiB-bounded zstd.

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

A follow-on fix (2026-07-01) closed the **one stale expectation the revert missed**:
`scripts/apple-conform-check.sh` still listed the deleted
`libs/hbb_common/src/native_worker_sandbox.rs` in its R-R2 retain-and-check set and
ran a macOS-worker Seatbelt assertion over that absent file, so the Apple R-R2
source-conformance gate had been **failing on a deliberately-absent file** since the
revert. The gate now reflects the accepted residual (`apple-conform-check` **PASS** at
HEAD); re-closing #2b later restores the worker subsystem on *all* platforms, so the
removal is deliberately not a presence-of-absence pin.

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
- **Mobile (iOS + Android) at-rest config wrapper keyed by `get_uuid()`** — the mobile face of Appendix
  C #14. On BOTH iOS and Android the
  `password_prs` at-rest wrapper is keyed by the config keypair PK (`get_uuid()` — the off-file
  `machine_uid` block is cfg-compiled out on both mobile platforms, `lib.rs:331`), which is itself
  stored in plaintext in the same TOML, so the `symmetric_crypt` wrapper adds no confidentiality over
  a plain config read. Scoped out, not fixed: §2 explicitly excludes endpoint at-rest reads, and the
  stored value is already the Argon2id PRS (a memory-hard salted hash, R-P1/R-S9) — not the plaintext
  password and not the OS/sudo credential even when those are reused — so a cold read yields only the
  connect-equivalent hash. A proper fix rebinds the **mobile** at-rest key to the iOS Keychain
  (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecUseDataProtectionKeychain`) / Android Keystore
  (AES-256-GCM, StrongBox + TEE fallback, non-auth-bound, `setUnlockedDeviceRequired(false)`) — a
  device-bound, hardware-wrapped, this-device-only random storage key — sourced ONLY by `symmetric_crypt`
  via a new `at_rest_storage_key()` seam (NOT `get_uuid()`, a separate device-id function also exported as
  the `main_get_uuid` FFI), and it MUST NOT change `derive_cpace_prs` output bytes (only the wrapper's key
  SOURCE changes). A full fail-safe design + no-data-loss proof was worked out (2026-07-06): encrypt under
  the hardware key; on decrypt try it, else **fall back to the legacy PK key and re-wrap** (the exact
  desktop pattern at `password_security.rs:203-215`/`:546`, generalized to mobile); adopt the hardware key
  only after an in-process encrypt→decrypt **self-test** passes, else degrade to today's behavior — so a
  broken Keystore/Keychain/JNI integration cannot lose data; and the ultimate backstop is that the stored
  value is `Argon2id(password)`, re-derivable by re-entering the password. It is NOT landed now: it is
  LOW-severity (both local-exfil channels below are already closed), it lives in the single
  highest-blast-radius at-rest chokepoint (`symmetric_crypt` keys EVERY at-rest secret — `config.password`
  / `password_prs`, per-peer creds, socks pw, `unlock_pin`, `enc_id`, address book), and its
  Keystore/Keychain round-trip is unverifiable on this Linux host (no device/emulator; iOS unbuildable; a
  JNI marshaling error under `panic='abort'` can hard-abort rather than surface catchably). The fail-safe
  design is ready to land after ONE on-device validation pass (Android emulator first; iOS as
  source-conformance like the fork's other Apple-gated items) — recorded as a documented residual, not a
  partial, unverifiable change. The Documents directory this wrapper
  sits in had **two** local-exfiltration channels, now closed by two separate fixes: (a) the **Files-app /
  iTunes file-sharing BROWSE** channel was closed by the APPLE-6 plist fix (dropping
  `UIFileSharingEnabled`/`UISupportsDocumentBrowser`, so the directory is no longer user-browsable); and
  (b) the **device-BACKUP** channel — iCloud and unencrypted local iTunes/Finder backups copy the
  Documents directory *regardless* of the file-sharing keys — is closed by setting
  `NSURLIsExcludedFromBackupKey` on the config directory at startup
  (`flutter/ios/Runner/AppDelegate.swift`), the iOS twin of Android's `allowBackup="false"` (R-X6).
  APPLE-6 alone did **not** close the backup vector — dropping the file-sharing keys stops browsing, not
  backup. (Source-layer fix, presence-asserted by `apple-conform-check.sh` `(2e)`; the Swift is not
  runtime-built on this Linux host, like the fork's other Apple source-conformance items. Raising the
  config's iOS data-protection class to `NSFileProtectionComplete` was assessed and declined: the default
  `CompleteUntilFirstUserAuthentication` already protects a not-yet-unlocked device, `Complete` makes the
  file unreadable whenever the device is locked — breaking backgrounded/locked config writes and
  reconnect — and it addresses only physical seizure of an unlocked-since-boot device, which §2 scopes
  out as endpoint compromise.)
- **R-V3 independent CPace audit — ✅ PERFORMED 2026-07-02; VERDICT SOUND (findings
  resolved @4eb6912).** An independent expert review (docs/CRYPTO-AUDIT-2026-07-02.md):
  the §10.4 construction reproduced byte-for-byte by an INDEPENDENT implementation
  (libsodium ristretto255 + from-scratch encoding/HKDF) against the published CFRG
  draft-21 vector AND both fork anchors; first-principles analysis of the state machine,
  two-key secretbox, constant-time paths, R-P3 MAC composition, R-S17 host-proof, and
  Argon2id PRS. Three findings raised and RESOLVED: F-1 (viewer stored plaintext → now
  the derived Argon2id PRS), F-2 (constant-time gate added to verify.sh + ignored dudect
  probe), F-3 (deps already resolved in-tree). **HONEST CAVEAT:** this was an AI-conducted
  (Claude Opus) SINGLE-reviewer review — rigorous, but not the multi-party/decades
  third-party scrutiny SSH has (the honest boundary of this audit; scope + limitations in
  the report).
- **Crypto protocol-logic audit — ✅ PERFORMED 2026-07-01; VERDICT SOUND.** A
  dedicated adversarial pass over the STATE-MACHINE / KEY-DISCIPLINE that KATs do
  not cover (both endpoints' keying paths traced in source): confirm-before-key
  fail-closed (`pake/lib.rs:486,612`; keys installed only after `Ok`, `is_secured()`
  guard `server.rs:498`/`client.rs:306`); host-proof binding + no-TOFU pin
  (`cpace.rs:361-370`, `client.rs:339-343,383-390`; PRS Argon2id-salted by the pinned
  key); two-key nonce/key discipline (distinct c2s/s2c, mirrored+cross-checked,
  `split_session_keys` asserts send≠recv `cpace.rs:494-497`, counters `checked_add`
  can't-wrap `cpace.rs:416-420,459-463`, single-writer-per-direction); ristretto
  canonical-decode + identity-reject; no-downgrade (`set_raw` panics on keyed);
  replay/desync (monotonic recv counter, atomic decode, cross-session abort);
  framing caps both sides; CT confirm/at-rest compares. **No exploitable flaw.**
  Three DEFENSE-IN-DEPTH observations (all NON-exploitable, severity none): (DiD-1)
  the no-TOFU-on-mismatch friction is caller-enforced (Dart re-pin dialog + `--pin-host`
  CLI), not core-structural — now backstopped by a new `verify.sh` R-S17 gate that
  confines `host_pin::set_pinned_pk` to those two friction callers so a future
  non-Flutter UI can't silently add a no-friction adopt; (DiD-2) the online-guess
  limiter is a tumbling (not sliding) window → ~2× guesses possible straddling a
  boundary — DoS-defense only, each connection is still exactly one guess vs the
  memory-hard PRS; (DiD-3) the host-proof signs `DSI‖sid‖CI‖Ya‖Yb` (not the literal
  ISK) but is key-bound because it travels encrypted as the first post-key frame with
  session-unique CPace-authenticated `sid/Ya/Yb` (test `r_s17_host_proof_binds_pk_to_the_session`).
  The R-V3 independent expert review (above) is now DONE (2026-07-02, docs/CRYPTO-AUDIT-2026-07-02.md).
  **Superseded (2026-07-04, host-key retirement):** the host-proof / no-TOFU host-key-pin elements
  these two audits reviewed (the `HostIdentity` Ed25519 proof, the viewer pin-compare, the DiD-1
  `set_pinned_pk` confinement gate, DiD-3's host-proof signing, and the host-key-derived PRS salt) are
  now RETIRED — the CPace PRS is derived from the password alone (fixed salt, R-P1) with no host
  identity, host-proof, or local pin (R-P5), so those specific items are moot. The audits' core
  findings on the PAKE state machine, two-key cipher, constant-time paths, R-P3 MAC, and Argon2id
  memory-hardness are UNAFFECTED and stand.
- **Local IPC/CM authorization audit — ⚠️ SUPERSEDED 2026-07-08 by R-S11b/R-S11c.** The
  2026-07-01 pass remains useful only for its transport facts: owner-only channels are
  0600 socket + 0700 per-uid parent; the service parent-dir hardening uses
  `O_NOFOLLOW|O_DIRECTORY`, rejects symlinked/foreign-owned parents, and recreates
  rather than adopts; pid files are 0600; foreign uid access to owner-only sockets is
  kernel-blocked. Its conclusion that the local IPC boundary was "sound" is retired.
  The missed model was authority ownership in installed-service mode: "same UID",
  "same session", "active uid + executable path", and "only `SyncConfig`" are not
  sufficient when the receiver is the root/SYSTEM/LaunchDaemon service and the message
  can read/write connect-equivalent credentials, rewrite service policy, select a
  privileged target session, invoke SAS/HKLM behavior, or drive pre-login helper file
  operations. The service-owned credential/action class is now tracked as OPEN under
  R-S11b/R-S11c above. Any future IPC audit must distinguish transport admission from
  message authority and must treat the process that enforces a credential/action as
  the owner of that credential/action.
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
- **Apple R-R2 gate runs outside `verify.sh`** — `scripts/apple-conform-check.sh`
  needs the `rd-apple-check` image + cargo cross-checks, so it is **not in the default
  verify loop**; its `0c54912` #2b leftover (above) therefore went unnoticed through the
  "complete"/"proven" milestones. GREEN again at HEAD (2026-07-01). **To wire in:** add
  it to the release-verification path so future Apple-source drift fails fast rather than
  silently.
- **R-R3 dependency-advisory gates** — `cargo audit`/`cargo deny` (`scripts/audit.sh`)
  and `osv-scanner` (`scripts/dart-audit.sh`) are wired; the documented-accept
  ledger is maintained there.
- **Peer-avatar remote-image egress — ✅ CLOSED 2026-07-01.** The 2026-07-01
  completion review found the sole open gap: a CPace-authenticated peer's
  `LoginRequest.avatar` (`connection.rs:1447` → CM `Client`) was rendered by
  `buildAvatarWidget`, whose http(s) branch issued an unconditioned Flutter
  `NetworkImage` GET to a peer-**named** host — a first-party, attacker-influenceable
  outbound fetch at odds with "dial nobody / defensible with no firewall"
  (deanonymization / SSRF-lite). Fixed at the sink (`common.dart:3941`): the network
  branch is removed; only an inline `data:image/` (base64, no egress) renders,
  non-inline avatars fall through to the initials fallback. New `verify.sh` gate pins
  `NetworkImage` to **zero** across the whole flutter UI (R-SV1) plus a positive check
  that inline-`data:` rendering is retained.
- **Peer msgbox-text → tappable `launchUrl` egress — ✅ CLOSED 2026-07-01.** A
  follow-up taint audit (looking for *siblings* of the avatar bug — any peer-controlled
  wire field reaching a dangerous sink) found one: a peer's `MessageBox.text` /
  `LoginResponse.error` (`src/client/io_loop.rs` → `src/flutter.rs`) reached
  `createDialogContent` (`common.dart`), whose `RegExp(r'(https?://[^\s]+)')` linkifier
  wrapped any URL in a `TapGestureRecognizer` → `launchUrl(peer_url)`. A malicious peer
  (e.g. a server this box views — the fork is bidirectional) sends
  `MessageBox{text:"…http://evil/leak", link:""}`; one operator tap opens the box's
  browser to an attacker-named host (deanonymization / phishing). Same "dial nobody"
  class as the avatar, and a **bypass of the fork's own defense** — it deliberately
  blanks `MessageBox.link` unless it is in the (empty, gated) `HELPER_URL` allowlist, but
  the text linkifier was an unguarded parallel path to the same `launchUrl` sink. Fixed:
  `createDialogContent` renders plain `SelectableText` (URLs stay visible + copyable,
  never one-tap navigable). New `verify.sh` gate pins the dialog-text URL-linkifier regex
  to **zero** across flutter/lib (launchUrl is NOT globally gated — it has legit local
  uses: `Uri.file` folder-opens + the HELPER_URL-gated JumpLink). The audit's broad
  CHECKED-SAFE list (filesystem-receive traversal/symlink guards, alloc/deser/index
  bounds, PortForward disabled, no live Rust HTTP client, chat renders plain `Text`,
  pre-auth CPace bounded) confirmed this was the **only** sibling.
- **Inert dead-code leftovers (optional hygiene, no reachable path).** The same
  review enumerated confirmed-inert residue retained for now to avoid multi-file
  regression risk at the completion boundary: orphaned uncompiled
  `libs/scrap/src/wayland.rs` + `libs/scrap/src/common/wayland.rs` (the `mod` is
  excised, the files linger beside cfg-gated `common/linux.rs` WAYLAND arms);
  the neutered `--assign` arm in `core_main.rs` (assembles then discards a body —
  dials nobody); dead `--quick_support` plumbing in `libs/portable`;
  `enable_trusted_devices` viewer plumbing (wired login-response→handler but unused)
  and the `Dialog2FaField`/`kUseTemporaryPassword` Dart stubs; dead
  `"Click to upgrade"`/`"Auto update"` translation entries in `src/lang/*.rs`.
  None affects behavior or opens a security path (reviewer + local re-confirm);
  each is a candidate for a later focused excision carrying its own build re-prove.
  **⤷ NOTE: this bullet sampled ~5 items; it is SUPERSEDED by the `## Incomplete`
  section immediately below (2026-07-03 full sweep = ~80 sites, incl. 7 user-visible
  defects + 1 live race this earlier note missed).**
- **File-transfer receive write-path no-follow (R-S8/R-A5) — POSIX handle walk confirmed
  correct-by-design.** The Unix receive-write path (`libs/hbb_common/src/fs.rs`:
  `open_parent_dir_no_follow` ~828, `open_recv_write_no_follow_std` ~979) opens **every** parent
  component with `openat(O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW)` walking down from `/` (or cwd),
  then the target with `openat(O_NOFOLLOW)` (rejecting non-regular targets), and finalizes with
  `renameat`/`unlinkat`/`fstatat` under that same parent handle — a full-path **handle walk**, not a
  final-component check. This is **correct-by-design and deliberately not narrowed**: it is a
  *per-write TOCTOU* guarantee (R-A5) defending the authenticated peer's **own** privileged write
  (root on the §17 box) against a **local unprivileged** attacker racing a symlink into an
  intermediate directory or the target between validation and write. It is **not** scope-confinement —
  per §2/R-S8 the password-holding peer is trusted with full-filesystem reach as a single unconfined
  mode, and a confinement toggle is forbidden (R-S12). Two intended design consequences: (1) a receive
  destination that legitimately *traverses* a symlinked prefix (a relocated `~/Downloads` on a
  symlinked volume, a macOS firmlink, an Android `/sdcard` bind) is **refused** — the walk cannot tell
  a trusted admin-made prefix symlink from an attacker-raced one without canonicalizing, and
  canonicalizing the peer-chosen base then reopening by path would reintroduce the exact race; on the
  deployed Ubuntu box (`/home/user`, `/root` — no symlink components) it never triggers. (2) The
  proposed **narrowing** to "no-follow only the peer-relative segments, trust the base prefix" was
  **considered and rejected as a TOCTOU regression**: the peer-chosen base is uncanonicalized, so
  following base-prefix symlinks reopens the escape. The one airtight way to support symlinked-prefix
  destinations without reopening the race is a *trusted-symlink resolver* (a `chase_symlinks`/
  CHASE_SAFE walk that follows a link component only when its immediate parent is root/euid-owned and
  non-group/other-writable, else refuses) — **deferred** until a deployment concretely needs it (this
  one does not). **Both roles** ride the same shared path — server-receive (upload into the box,
  `src/ui_cm_interface.rs:1002 handle_fs` → `TransferJob::new_write`) and client/viewer-receive
  (download from a peer, `src/client/io_loop.rs:797,869`) — so R-A5's per-write assertion binds the
  viewer path too, per R-S8. Behavior-tested (`fs.rs`
  `recv_write_no_follow_refuses_symlink_{target,parent_component}` +
  `recv_finish_renameat_replaces_symlink_final_...`, `#[cfg(unix)]`) and gated by `verify.sh` (3c) /
  the R-S8/R-A5 grep gate.
- **Windows file-transfer parent-junction TOCTOU — ✅ CLOSED (applied 2026-07-05, Windows-VM-validated).**
  The Windows receive-write path now performs the same reparse-safe, handle-relative walk as the POSIX
  side — the "Windows equivalent" of `openat(O_NOFOLLOW)` that R-S8 mandates. Previously the Windows
  branch opened only the **final** component reparse-safe and let the OS resolve every intermediate
  directory *by path*, so a junction / mount-point / symlink planted on a parent between validation and
  write was followed (the intermediate-directory TOCTOU the Unix walk closes). That path-based resolve
  is replaced by the NT layer (`fs.rs` module `nt_nofollow`, `#[cfg(windows)]`): open the volume root
  once via Win32 (`FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` — the analogue of the Unix
  `/` anchor), then walk each `Normal` component with `NtCreateFile` +
  `OBJECT_ATTRIBUTES{ RootDirectory = parent_handle, ObjectName = <bare component> }` +
  `FILE_OPEN_REPARSE_POINT | FILE_DIRECTORY_FILE` (the real `openat` equivalent — resolves relative to
  the parent HANDLE and opens the reparse point itself instead of traversing it), fail-closed
  **rejecting** any component whose handle reports `FILE_ATTRIBUTE_REPARSE_POINT` (catches NTFS
  **junctions**, `IO_REPARSE_TAG_MOUNT_POINT`, *and* symlinks — the junctions `is_symlink()` misses).
  The final target is opened relative to the walked handle, and the finalize/cleanup steps that also
  shared the old gap are now handle-relative too: rename via
  `NtSetInformationFile(FileRenameInformation, RootDirectory=parent)`, and digest/sidecar read+delete
  relative to the walked parent — so no step re-resolves a parent by path.
  `validate_no_symlink_components` is made junction-inclusive on Windows
  (`file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT (0x400)` — the primitive
  `src/platform/windows/acl.rs::is_reparse_point` uses) as defense-in-depth atop the walk (being a
  separate syscall from the open, that stat is TOCTOU-prone on its own, so it complements rather than
  replaces the handle walk). **Both roles** on Windows — server-receive (upload; the `--cm` process's
  `ui_cm_interface.rs handle_fs` → `TransferJob::new_write`) and viewer-download (`io_loop.rs`) — ride
  the same `fs.rs` path, so R-A5's per-write no-follow guarantee now binds the viewer path on Windows too.
  **Severity was LOW, Windows-only** (the deployed box is Ubuntu/Xorg — unaffected). **Privilege reality
  (corrected — the earlier "SYSTEM / service account" wording overstated it):** the redirected write
  would have run at the **interactive logged-in user's** privilege, **not** SYSTEM. On Windows the
  SYSTEM `--server` does not write received files itself — it forwards the file bytes over IPC to the
  `--cm` connection-manager, which runs in the *active user's* session (an explorer /
  `CreateProcessAsUserW` token via `run_as_user`) and performs the actual `open_recv_write`; the
  viewer/download side likewise writes as the user running the client. So the (now-closed) exposure was
  a **local cross-user write-redirection**, capped at the interactive user's privilege, not a
  SYSTEM-LPE. Exploitation still needed a co-located **local** principal able to plant/swap a reparse
  point on an intermediate directory **on** the receive path *and* writable by them: creating an NTFS
  **junction** needs **no** privilege (`mklink /J` / `FSCTL_SET_REPARSE_POINT`), a **symlink** needs
  `SeCreateSymbolicLinkPrivilege`/Developer-Mode — but either way write access to that specific dir,
  which the default per-user download dir (ACL'd to the owner) denies a lower-privileged user; the
  practical exposure was a **non-default** receive path traversing a directory writable by a
  lower-privileged principal. Hence LOW — and now closed regardless.
  **Validated in the §12.2 Windows VM (2026-07-05).** The fork's rule is *never ship a raw-NT-syscall
  Windows security change that cannot be run here* (a mis-shaped
  `OBJECT_ATTRIBUTES`/`UNICODE_STRING`/`FILE_RENAME_INFORMATION` = memory corruption), so the walk was
  built correct-by-construction from primary sources (the `cap-std` Windows resolver, the `ntapi 0.4.1`
  + `winapi 0.3.9` struct/fn shapes, and the ntifs docs) **and then type-checked + run on real Windows**:
  `cargo test -p hbb_common --target x86_64-pc-windows-msvc --lib fs::tests` under the pinned Rust 1.75
  (MSVC) **compiled and passed 25/25** (1 privileged-symlink e2e `ignore`d), including the new
  `#[cfg(windows)]` junction tests that plant an NTFS junction (`mklink /J`, unprivileged) as the
  intermediate/final component and assert: a junction **parent** is REFUSED and does not redirect the
  write out of tree (`recv_write_no_follow_refuses_junction_parent_component`); a junction **final**
  component is REFUSED and its target directory is untouched (`..._refuses_junction_final_component`);
  a legit nested non-junction path SUCCEEDS (`..._allows_regular_nested_target_windows`); the
  junction-inclusive validate rejects (`validate_no_symlink_components_rejects_junction_windows`); and
  the handle-relative finalize renames on a clean path yet refuses a junction parent
  (`recv_finish_rename_windows_happy_path` / `recv_finish_refuses_junction_parent_windows`).
  (The earlier boundary — `cargo check --target x86_64-pc-windows-msvc` fails on *this Linux host* at the
  native-C-dep build, `zstd-sys`/`sodiumoxide`/`ring` needing MSVC `lib.exe` — is why the change is
  validated in the VM, not on the host; the VM has Rust 1.75-msvc + VS Build Tools + the Win11 SDK.)
  **Gated:** `verify.sh` now asserts the Windows walk tokens (`mod nt_nofollow`, `NtCreateFile`,
  `OBJECT_ATTRIBUTES`, `oa.RootDirectory = parent`, `FILE_OPEN_REPARSE_POINT`, `FILE_DIRECTORY_FILE`,
  `FILE_ATTRIBUTE_REPARSE_POINT`, `FileRenameInformation`, the `nt_nofollow::*` wiring, the
  junction-inclusive `is_symlink_or_reparse_point`, the junction tests, and the `ntapi` dep) alongside
  the Unix `openat`/`O_NOFOLLOW` tokens — closing the gate's prior **Windows false-green** (it grepped
  only the always-present `#[cfg(unix)]` tokens, so the `cfg(not(unix))` receive-write branch went
  entirely unasserted on a Windows build). **New dependency:** `ntapi = "0.4"` (already resolved in the
  lock, built on the same `winapi 0.3` hbb_common already uses — no new external crate lineage) plus the
  winapi `ntdef`/`fileapi` features. (The `fs.rs` module doc-comment describes the walk in full; the
  code + the VM-run tests are the record.)

## ✅ CLOSED — the excision-vestige backlog + the R-S17 pin-GUI defects (implemented 2026-07-04)

> **⤷ SUPERSEDED (2026-07-04, host-key retirement).** The R-S17 pin-GUI items in this record — I-1
> (fingerprint boards render), I-2 (first-contact fingerprint-entry pin dialog), I-3 (host-key-mismatch
> re-key loop), and I-8 (`--get-fingerprint` phantom-key race) — described fixes to the host-key /
> fingerprint / known-hosts subsystem, which has since been **RETIRED in full** (spec `16b67a2`). The
> CPace PRS is now derived from the password alone (fixed salt, R-P1); there is no host identity,
> host-proof, or local pin (R-P5). So the fingerprint boards, the pin/known-hosts dialogs, the
> `HostIdentity` frame, and the `--get-fingerprint`/`--pin-host`/`--forget-host` CLI are **removed, not
> fixed** — those I-items are retained below only as the historical record. The non-pin items in this
> backlog (the dead-scaffolding excisions) stand.

**✅ STATUS: ALL CLOSED — 2026-07-04.** The backlog enumerated below was IMPLEMENTED in full by a
single coherent excision pass (36 files, **+441 / −1790**) and reviewed to standard: all source gates
green (the `verify-release` bundle — verify.sh / smoke-server / dart-verify / native-codec-watch /
apple-conform / audit / dart-audit / test-build-faillo — plus `flutter-verify` for the flutter-feature
Rust), **zero dangling references across all five platforms** (Rust / Dart / Kotlin / Swift / proto /
tests), and R-B2 reproducibility re-proven per release (build-release.sh → dist/SHA256SUMS, double-build
A==B per target). The four tiers below are **retained as the implementation record** — each item's
problem statement and the fix that closed it.

**The original finding (2026-07-03).** Six independent Opus-1M code audits swept the entire auth /
identity / online-status / connection-manager / server-config / viewer-peer-list surface, every
load-bearing claim re-verified against source by hand. The verdict was **behaviorally sound but
structurally incomplete** — every user-visible control and every security path was correctly
neutralized and failed closed (**zero security hazards, zero peer-reachable bugs**), but the excisions
had left a large stratum of **orphaned plumbing**: dialogs that could never open, FFI shims with no
caller, IPC enum variants nothing sent, state flags stuck forever in one branch, and helpers that
returned the semantic opposite of their name — **~80 distinct dead-or-wrong sites, ~15 root excisions**
(rendezvous/`register_pk`, relay, 2FA/OTP, TOFU→R-P1 salt-is-the-pin, account/address-book, QR,
numeric-ID→direct-address, socks/proxy, attended-accept, permission-widener).

**Why it was non-negotiable.** "Excise, don't disable," **R-G1 "remove, don't grey,"** and **R-S12 "no
defaulted-off-but-present"** are the whole point of this project — and they apply one level down, to
plumbing, exactly as they apply to visible toggles. A codebase that advertises itself as
secure-by-assertion and "correct as if written correctly from the first place" could not carry a
rendezvous signed-id verifier nothing calls, a two-factor-auth pipe wired end-to-end behind a trigger
that never fires, or a "Password Required" dialog whose OK button authenticates nothing. Dead code that
*looks alive* is worse than a stale comment: it makes the next auditor reason about a data flow that
does not exist. That entire stratum is now gone — the tiers below record each site and its fix.

### Tier 1 — user-visible correctness defects ✅ DONE (a user SAW these)

- **[I-1] The box's own R-S17 fingerprint renders BLANK on every GUI screen — the worst item in
  this document.** `ui_interface::get_fingerprint` gates the value on `Config::get_key_confirmed()`
  (desktop via `src/ipc.rs:847`, mobile via `src/ui_interface.rs:1090`), but
  `Config::set_key_confirmed(true)` is called **nowhere in the entire tree** — the only thing that
  ever flipped it true was the *excised* rendezvous `register_pk` acknowledgement (only
  `set_key_confirmed(false)` survives: `ipc.rs:870`, `ipc.rs:1519`, `ui_interface.rs:1299`; `= true`
  appears solely in a config-parser unit test). The flag is therefore permanently false and the
  fingerprint shows **empty** on the desktop home board
  (`flutter/lib/desktop/pages/desktop_home_page.dart:214`), the mobile server page
  (`flutter/lib/mobile/pages/server_page.dart:357`), and mobile settings
  (`flutter/lib/mobile/pages/settings_page.dart:459`). This guts the trust model in the one place it
  matters most: R-S17 is "the operator reads the box's fingerprint out-of-band and the viewer pins
  it," and the screen meant to *show* that fingerprint shows nothing. Only the headless
  `--get-fingerprint` still works (it computes the fp directly, ungated) — which is exactly why the
  deployed `--server` box appears fine while every GUI is broken. **FIX (opinionated):** DELETE the
  gate; do NOT "set the flag true." A direct-IP fork with no rendezvous has nothing to confirm, and
  the self-generated Ed25519 key is *always* present (`Config::get_key_pair()` generates it on first
  read). Return `pk_to_fingerprint(get_key_pair().1)` unconditionally at both sites, and excise the
  whole `key_confirmed`/`keys_confirmed` concept (also `OnlineStatus.confirmed`/`ConfirmedKey`, Tier 4).

- **[I-2] The first-contact pin dialog HANGS; on mobile it means the app connects to NOTHING, ever.**
  Because the CPace password (PRS) is Argon2id-salted with the pinned host key (R-P1), the viewer
  bails *before keying* when there is no pin (`src/client.rs:347`) — the host key is never received,
  so `pending_host_pk` stays `None`. The shared Flutter first-contact dialog `hostNotPinnedDialog`
  (`flutter/lib/common/widgets/dialog.dart:586`, desktop+mobile) then shows a **"Trust"** button
  whose `bind.sessionPinHost` → `set_pin_host_and_reconnect` (`src/ui_session_interface.rs:1319`)
  finds `pending_host_pk == None`, logs "refusing," and returns **without reconnecting** — while the
  dialog has already thrown up a `showLoading("Connecting…")` spinner. Net: the spinner hangs forever,
  no fingerprint is shown, and there is no field to type one into. The dialog is a vestige of the
  pre-R-P1 trust-on-first-use design; its own comment ("the box keyed… show the fingerprint")
  describes a flow that can no longer happen. Desktop users can escape via the `--pin-host` CLI;
  **Android/iOS have no CLI and no deep-link/QR/import pin channel, so a fresh mobile install
  literally cannot connect to any host.** **FIX:** replace the dead "Trust" with a fingerprint-ENTRY
  dialog (paste the out-of-band fingerprint → a new FFI `session_pin_host_by_fingerprint(session_id,
  hex)` → `host_pin::set_pinned_pk` → reconnect), mirroring the working `hostMismatchDialog`
  text-field pattern (`dialog.dart:641`). That is the only honest UI for a no-TOFU design.

- **[I-3] A legitimately re-keyed host dead-ends the viewer in an eternal "Password Required" loop.**
  If the box is wiped and re-provisioned (new Ed25519 key, password re-set → `password_prs`
  re-derived under the new key, read at `src/server.rs:426`), a viewer still pinned to the OLD key
  derives a PRS under the old key → the salts differ → **CPace fails first** (`src/client.rs:370`),
  and that failure is routed to the pre-keying password prompt (`src/client.rs:3074`, "Password
  Required"). Re-typing the correct password re-derives the same non-matching PRS → identical failure
  → infinite loop, with **no hint** the real cause is a changed host key. The elaborate
  `hostMismatchDialog` re-pin UI is **unreachable** here (it requires CPace to *succeed* yet the proof
  key to differ — a contrived stale-PRS corruption, never a normal re-key), and even when reached it
  does **not** restore connectivity (re-pinning rewrites known_hosts but does not re-derive the host's
  PRS — only a host-side `--password` heals it). **FIX:** route "CPace handshake failed" to a message
  naming BOTH causes ("wrong password OR the box's host key changed — re-verify the fingerprint
  out-of-band and re-pin"), and delete the near-dead mismatch machinery (`client.rs:400` branch +
  `hostMismatchDialog`) or make a key change genuinely distinguishable.

- **[I-4] A dead "Sort by → Status" option in the peer menu.** `PeerSortType.status = 'Status'`
  (`flutter/lib/common/widgets/peers_view.dart:28`) is offered in the Favorites sort menu; its
  comparator `peers.sort((p1, p2) => p1.online ? -1 : 1)` (`peers_view.dart:389`) reads `peer.online`,
  which is **always false** (the rendezvous online query is a no-egress stub, Tier 4), so the sort is
  a visible no-op. **FIX:** remove `status` from `PeerSortType.values`.

- **[I-5] Stale numeric-ID-era labels "Remote ID" / "Search ID" render literally.**
  `PeerSortType.remoteId = 'Remote ID'` (`peers_view.dart:25`) and the "Search ID" hint
  (`flutter/lib/desktop/pages/peer_tab_page.dart:727`) are absent from `src/lang/en.rs`, so they
  display verbatim — numeric-rendezvous-ID wording in a fork whose identity is a direct address.
  **FIX:** relabel to "Remote address" / "Search address."

- **[I-6] There is NO saved-credential indicator anywhere, and the one that exists is misdesigned.**
  The peer-card key/lock badge `_shouldBuildPasswordIcon` (`flutter/lib/common/widgets/peer_card.dart:163`)
  is gated on `currentTab == PeerTabIndex.ab.index` — the address-book tab, structurally disabled
  (`isEnabled = [true,true,false,false]`) — so it **never renders**, and it reads the old shared-AB
  `peer.password` field rather than the per-address PRS the fork actually stores. **FIX:** re-gate on
  `mainPeerHasPassword(peer.id)` for the recent/favorite tabs so the lock reflects the real PRS.

- **[I-7] iOS advertises camera + photo-library access "to scan QR codes" for a scanner that was
  excised.** `flutter/ios/Runner/Info.plist:73-76` still declares `NSCameraUsageDescription`
  ("…to scan QR codes") and `NSPhotoLibraryUsageDescription` ("…to get QR codes from image"), but the
  QR scanner (`scan_page.dart`) and its `rustdesk://config` import backend are gone. A straight R-G1
  "defaulted-off-but-present" trap and an **App-Store-review privacy red flag** — permissions
  requested for a capability that does not exist. **FIX:** delete both plist keys.

### Tier 2 — a LIVE latent bug ✅ DONE (not merely dead code)

- **[I-8] `--get-fingerprint` on a keyless box can make the operator pin a PHANTOM key.**
  `Config::get_key_pair()` persists a freshly-generated key via a **detached** background thread
  (`libs/hbb_common/src/config.rs:1160`); `--get-fingerprint` (`src/core_main.rs:390`) prints the
  fingerprint and immediately exits — potentially **before** that store commits. The next process then
  generates a *different* key and the box uses it, while the operator has pinned the printed
  (never-persisted) key → CPace fails forever. `set_permanent_password` is immune (it force-commits
  the key synchronously, `config.rs:1357-1370`); `--get-fingerprint` is not. The window is narrow
  (only on a brand-new box, before `--service`/a password exists — the deployed haggai box is
  unaffected because the server comes up first), but the documented onboarding order is exactly "read
  the fingerprint, then pin it," so this is a real footgun. **FIX:** have `--get-fingerprint`
  synchronously commit the key if it just generated one (or refuse on a keyless box with an actionable
  "set the password / start the service first" error).

### Tier 3 — "live-looking dead" code ✅ DONE (deleted — it had lied to the next auditor)

- **[I-9] `enterPasswordDialog` is a normal-looking "Password Required" dialog that authenticates
  NOTHING.** Its submit calls `gFFI.login()`, which sends a passwordless `LoginRequest` the host
  authorizes purely by CPace (`src/server/connection.rs:2000`). It is unreachable — the host never
  sends `LOGIN_MSG_PASSWORD_EMPTY`, and the only `LOGIN_MSG_PASSWORD_WRONG` send sits behind
  `if !self.stream.is_secured()` (`connection.rs:2007`), a branch that cannot execute because login is
  only reached on a keyed stream (R-A1). But it *looks* completely live
  (`flutter/lib/common/widgets/dialog.dart:556`) — that is the danger. Do NOT confuse it with the LIVE
  pre-keying `enterConnectPasswordDialog`. **FIX:** delete `enterPasswordDialog` and the non-`preKeying`
  branch of `_connectDialog`; delete the dead `input-password`/`re-input-password` msgbox arms
  (`client.rs:2923-2929`) and their `src/cli.rs` handlers.

- **[I-10] A connection-manager `SwitchPermission` receiver whose comment asserts a data flow that
  does not exist.** `src/ui_cm_interface.rs:591` handles a "privacy-mode rollback"
  `Data::SwitchPermission` from the connection, and its comment states "the backend currently sends
  SwitchPermission back to CM…" — but **nothing in `connection.rs`/`libs` ever constructs that
  message**; the only senders are the CM→connection direction, and `connection.rs` has no
  `SwitchPermission` arm (it falls to `_ => {}`). **FIX:** delete the receiver arm and the false comment.

- **[I-11] The `enable_trusted_devices` two-factor pipe is wired end-to-end behind a trigger that
  never fires.** Wire field (`libs/hbb_common/protos/message.proto:152`) → `REQUIRE_2FA` reader
  (`src/client/io_loop.rs:1590`) → `LoginConfigHandler` field (`src/client.rs:1362`) → getter
  (`src/ui_session_interface.rs:1382`, **zero native callers**): a fully intact, fully disconnected
  pipe — the host never sets the flag and never sends `REQUIRE_2FA` (the responder 2FA gate is
  excised, `connection.rs:1073`). Same cluster: `LOGIN_MSG_2FA_WRONG`/`REQUIRE_2FA` consts
  (`client.rs:114`); the `input-2fa` msgbox emitter that **survives on the Rust side though Dart has
  no handler** (`client.rs:2938` — a half-excision); `trust-this-device` (read `client.rs:2932`, never
  set to "Y"); and the never-instantiated Dart widgets `Dialog2FaField`/`DialogEmailCodeField`/
  `DialogVerificationCodeField` (`dialog.dart:204/278/342`). **FIX:** excise the whole
  2FA/trusted-devices cluster on both sides and drop the proto field.

- **[I-12] `IdPk` + `decode_id_pk` — dead rendezvous crypto.** `message IdPk { id; pk }`
  (`libs/hbb_common/protos/message.proto:38`) and `decode_id_pk` (`src/common.rs:1121`), which verified
  a rendezvous server's signature over an id→public-key binding, have **zero callers** and `IdPk` is
  never constructed (the one `server.rs` reference is a comment). **FIX:** delete both.

### Tier 4 — inert dead scaffolding ✅ DONE (~65 sites excised by root cause)

Safe at runtime, but each is R-G1 debt a from-scratch direct-IP fork would never contain:

- **Rendezvous online-status cluster (always-0 / always-offline):** the `ONLINE` latency map +
  `get_online_state()` are permanently 0 because `update_latency`/`reset_online` are never called
  (`config.rs:995/999`); `status_num` and the mobile `_connectStatus` getter feed off it and are dead;
  the whole viewer peer-online pipeline — `peer.online`, `_updateOnlineState`, `_cbQueryOnlines`, and a
  **300 ms poll loop with a deleted payload** (`peers_view.dart:312`, `peer_model.dart`) — spins
  forever behind an already-invisible dot (`getOnline()` → `SizedBox.shrink()`). Excise the map, the
  loop, and the pipeline.
- **`using_public_server()` returns the semantic OPPOSITE of its name** —
  `get_custom_rendezvous_server(...).is_empty()` (`src/common.rs:1133`) is always `true` in a fork
  with no rendezvous, so it reports "using the public server" when there is no server at all; its
  callers (a quality cap, a peer-loop cadence) are inert. Delete the function + FFI.
- **Viewer `direct`/relay residue:** `direct` is hardcoded `Some(true)` and
  `direct_failures`/`set_direct_failure` are dead (`client.rs:314`); the `allow_more` quality cap, the
  `retry_for_relay` misnomer, and the `getConnectionText` "Relay"→"TCP" branch are unreachable;
  `set_connection_type`'s `is_secured`/`direct` args are sent always-true and ignored by Dart.
  Simplify to unconditionally-direct.
- **Dead FFI exports (zero Dart callers):** `main_test_if_valid_server`, `main_get_proxy_status`,
  `main_handle_relay_id`, `main_resolve_avatar_url` (`src/flutter_ffi.rs`). Drop the exports.
- **Dead Rust backends:** the socks/proxy module (`set_socks`/`get_socks`/`get_proxy_status`, not
  flutter-exported, no actuator), `change_id`/`change_id_shared`, the ipc `rendezvous_server(s)` query
  answer (`ipc.rs:838`), and the `resolve_avatar_url`/`get_api_server` builder (resolves empty). Excise.
- **Dead Dart option constants:** `kOptionHideServerSetting`, `kOptionHideProxySetting`,
  `kOptionDisableChangeId`, `kOptionAllowDeepLinkServerSettings` (`flutter/lib/consts.dart:171-187`) —
  zero consumers. Delete.
- **The attended-accept IPC pipeline (8 sites, A1–A8):** because `approve-mode` is pinned to
  `"password"` (`config.rs:3176`), every connection is authorized before the CM sees it, so
  `buildUnAuthorized`, `showLoginDialog`, the `cmLoginRes`/`authorize()` accept path, and the
  `Data::Authorize` IPC variant are all dead. Excise the pipeline.
- **The runtime permission-widener IPC pipeline (5 sites, B1–B5):** the CM permission chips are
  read-only (`canModifyPermission=false`) and `connection.rs` has no `SwitchPermission` handler (dead
  sink), so `cm_switch_permission`/`switch_permission`/`switch_permission_all` and the
  `Data::SwitchPermission` variant are dead. Excise.
- **Misc:** the unshown my-numeric-ID machinery (`server_model.dart` `_serverId`/`fetchID`, fetched
  and never rendered); the serialized-but-unread `forceAlwaysRelay`/`sameServer`/`recording`/
  `block_input`/`restart` fields; `reconnect(_forceRelay)`; the `formatID` numeric-grouping
  passthrough; the `switch_sides()` empty stub; `logOut(apiServer)`; and the `--get-id` CLI (a
  meaningless numeric ID in the direct-IP model). Delete.

### Verified CLEAN — do NOT re-open these (keeps the backlog honest)

The security-critical excisions were done correctly and must not be re-litigated: the `LoginRequest`
proto is stripped to session metadata (password/os_login/hwid fields reserved+deleted,
`connection.rs:2000`); the top-level auth message types (`SignedId`, `PublicKey`, `Auth2FA`,
`SwitchSides`, `OSLogin`, `Hash`) are absent; **elevation/OS-login proto fields are retired, nothing
dangles on the wire** (`elevation_request`/`_response`/`portable_service_running`, `message.proto:839-842`
— this closes the old "R-X9 Windows-deferred" worry: there is no dangling handler); `get_key` is
pinned to `RS_PUB_KEY` ignoring any `option("key")` override (regression-tested, `common.rs:1500`);
the deep-link `config`/`password` write authorities return `null` (`common.dart:2352`); the settings
surface carries no id/relay/key/proxy/whitelist row; voice-call accept gates host audio (R-S19); the
status dot was correctly rewired to a service-listening indicator ("Listening on :21118"); and
"Remember/Forget password" are PRS-coherent (both check/clear `password` and `password_prs`).
(Corrected stale note: `maxTabCount` is **4**, not the "5→3" in an earlier record; all parallel tab
arrays are consistent at 4, no out-of-bounds risk.)

### Discipline for closing this

Excise by root cause, not by scattered line; each removal carries its own **R-B2 reproducible-build
re-prove** (Debian/Android/Windows double-build A==B) and re-runs `verify.sh` plus the out-of-loop
gates (`audit.sh`, `dart-audit.sh`, `apple-conform-check.sh`, the smoke harness). Any code-audit help
uses **Opus-1M subagents told to research extensively** — the recurring failure mode in this very
sweep was agents trusting a stale comment (e.g. "the dialog shows the fingerprint" — it does not), so
every claim must be verified against source. Tiers 1–2 are the priority (a user sees them / a box can
mis-pin); Tiers 3–4 are the coherence work that lets this tree finally read as
correct-from-the-first-place. This section supersedes the "Inert dead-code leftovers" sample above.

The requirements snapshot reviewed in prior passes (2026-07-01 completion review at
HEAD 358a4b9) was `67dbbba4…`. On 2026-07-02 the spec was updated to reflect the R-V3
independent expert review: the §11 caveat, the SSH-bar maturity row, acceptance #6, and
the R-V3 body were flipped from "not independently audited" to "reviewed 2026-07-02,
findings resolved — docs/CRYPTO-AUDIT-2026-07-02.md." Two 2026-07-03 follow-ups: the
recommendation-of-further-audit hedge was removed (maintainer decision — a funded firm is not
a reachable gate for a solo fork; the factual limitations were kept), and Appendix C gained
rows #23–#24 for the two RustDesk items in the June-2026 "Exploitarium" public zero-day dump
(#23 relay-downgrade = already REPLACED by construction; #24 CVE-2026-58056 FileTransfer
scope-bypass = inherited but moot under §2, now **FIXED** in connection.rs — an AuthConnType
allowlist in on_message (input=Remote-only, desktop-capture=Remote|ViewCamera) + a FileTransfer
capability-flag clear (keyboard/block_input/privacy_mode), verify.sh-gated). A further 2026-07-03
edit **added a normative requirement** — §7 **R-S19** (capability confinement by `AuthConnType`:
the CWE-863 class of which CVE-2026-58056 is one instance; see the R-S19 status note above) — the
first spec change in this run that is not disclosure-only; its structural closure is in progress.
The other requirements.html edits are disclosure/inventory updates (no normative requirement
changed) — the #24 confinement itself is a source change landed alongside — and the
native-codec-watch ledger is re-confirmed valid against each.
The current snapshot (matching the `scripts/native-codec-watch.sh` pin) is:

```text
77168170a0e6abbc9f7acfcb2ffe773f1efb583f4db0b8b286d7c48856a3c751  requirements.html
```

`requirements.html` is not edited by routine implementation work; the only deliberate
exception is an audit-status disclosure update like this one, which re-pins the hash here,
in `scripts/native-codec-watch.sh`, and in `docs/NATIVE-CODEC-WATCH.md`.
