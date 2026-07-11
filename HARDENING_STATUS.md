# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Superseded work-log material (intermediate `PARTIAL`/`TODO`/deferred
notes, and — as of 2026-06-28 — the reverted native-worker-sandbox slices) is
removed from this live ledger because it is misleading as current status. Git
history remains the traceability record for that intermediate work.

## Current Verdict

> ⚠️ **Qualified by live QA (2026-07-06), with the service-boundary audit now closed and gated (2026-07-09) — see the _Live acceptance-testing regressions_ and _R-S11b/R-S11c service-owned IPC authority_ sections below.** Hands-on acceptance testing of the deployed `v1.4.7-hardened.1` prerelease surfaced connection-lifecycle, settings-control, desktop-shutdown, and UI↔excision-coherence regressions this verdict does not yet reflect. The follow-on IPC audit reclassified service-owned unattended credentials and privileged service actions as a blocking authority-boundary item; those R-S11b/R-S11c items are now implemented and verifier-gated. The cryptographic / transport core and the direct-IP posture hold; the build is **not release-ready**, and the prerelease is not to be promoted until the separate live-QA/build/release items below are closed.

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
display-control validation, FUSE mount-point no-follow setup, Linux euid-0
FUSE refusal, fixed-helper clipboard FUSE fd passing, bounded FileContents
response queue, and the FILEDESCRIPTOR path-traversal sanitizer
(`sanitize_relative_names`) with its count cap (`MAX_FILE_DESCRIPTORS`). The
macOS clipboard-file paste worker additionally anchors peer-requested file
creation, progress xattrs, cancellation cleanup, and final rename to an opened
target-directory handle with no-follow/exclusive fd-relative operations
(R-S11e-12), and its pasteboard placeholder URLs live in a private per-context
temporary directory with fd-relative exclusive create/unlink instead of global
`/tmp/.rustdesk_*` state (R-S11e-13).
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

**R-S19 voice-call close/reset authority — CLOSED / GATED (2026-07-11).**
Platforms: all connection.rs targets. Endpoint/action: peer `VoiceCallRequest(false)`,
CM `Data::CloseVoiceCall`, voice-call accept/refuse, and connection teardown global
voice-call input reset. Boundary: authenticated narrow session type
(`FileTransfer`/`Terminal`) or its CM helper ↔ Remote/ViewCamera-only voice-call
state. Attack surface closed: `can_drive_voice_call()` admits only Remote/ViewCamera;
`handle_voice_call()` rejects non-voice session types before accepting/refusing;
`close_voice_call()` is result-bearing and returns false unless the connection is
Remote/ViewCamera and owns pending or active voice-call state; CM close sends a peer
close notification only after that state closes; and `on_close` resets the global
voice-call input device only for an active voice-call owner. Verification closure:
`scripts/verify.sh` now asserts the helper, Remote/ViewCamera predicate, accept
guard, result-bearing close, state-owned close condition, CM result gate, and teardown
reset guard. This is not a root/LPE path; it closes the remaining voice-call state
member of the R-S19 capability-confinement class.

**R-S19 Linux FUSE file-content response provenance — CLOSED / GATED (2026-07-11).**
Platform: Linux `unix-file-copy-paste`. Endpoint/action: CLIPRDR
`FileContentsResponse` delivery into the local FUSE file-clipboard read path.
Boundary: one authenticated file-clipboard-capable connection ↔ another concurrent
file-clipboard-capable connection sharing the process-wide FUSE context for the same
side. Attack surface closed: `FuseServer::read_node` generates a fresh stream id
for each read, registers a bounded active response route keyed by `(conn_id,
stream_id)` before sending `FileContentsRequest`, and `src/clipboard_file.rs`
passes the response-supplying connection id into
`handle_file_content_response`. The handler dispatches `FuseFileContentResponse { conn_id, clip }`
only to the matching active route; responses that do not match the fresh active key
are dropped before they can occupy another read path. Verification
closure: `libs/clipboard` has regression tests for bounded route admission, wrong
connection/stream rejection, stale route removal, duplicate-route rejection, and a
real `read_node` request/response path where wrong-connection and wrong-stream replies
are ignored before the correct response supplies the bytes. `scripts/verify.sh` asserts
the keyed router type, caller wiring, active-route registration, bounded nonblocking
admission, fresh per-read stream ids, stale global-queue absence, and regression tests.
This is not a root/LPE path; it closes a Linux file-clipboard cross-session
capability/provenance member of R-S19.

**R-S15 — viewer PeerConfig write authority — status: CLOSED / GATED (2026-07-10).**
Platforms: all viewer-capable targets. Endpoint/action: post-PAKE peer messages that reach the viewer's
per-peer config store. Boundary: password-correct but hostile peer ↔ operator-owned persisted viewer
preferences. Attack surface closed: peer identity strings are bounded, `TerminalResponse.service_id` is
bounded, `privacy-mode-impl-key` is accepted only from the compile-time supported implementation set, and
peer `BackNotification::PrivacyModeState` no longer owns the saved privacy-mode policy. A privacy-mode status
response can persist only when it matches a receiver-owned pending local outbound `TogglePrivacyMode` or legacy
`OptionMessage.privacy_mode` request for a default remote-control session; unsolicited, expired, wrong-impl, or
wrong-direction status remains notification-only. `PeerInfo.version`/`platform` may still determine the effective
runtime keyboard-mode compatibility fallback, but neither `LoginConfigHandler::handle_peer_info` nor the Flutter
peer-info flow persists a keyboard-mode value chosen from peer metadata. The saved `PeerConfig.keyboard_mode` is
changed only by an explicit operator session setting, while Flutter input-source compatibility is applied as a
runtime input-model fallback. Verification closure: `src/client.rs` regression tests assert peer info neither
chooses an empty saved keyboard mode nor rewrites an existing saved keyboard mode; `src/client/io_loop.rs`
regression tests assert privacy-mode responses require a matching pending request, expire, and are recorded only
from local remote-session toggles; and `scripts/verify.sh` asserts the Rust peer-info body, Dart peer-info path,
removed auto-persist helper, runtime fallback, bounded peer writes, and pending-request privacy-mode gate.

**R-S9 permanent-password PRS read-state authority — CLOSED / GATED (2026-07-11).**
Platforms: all controlled-side direct-listener/CPace targets; desktop machine-UUID storage and mobile persisted-key
wrappers feed the same live PRS reader. Endpoint/action: permanent-password PRS reads that decide CPace auth,
direct-listener binding, and "password set" status. Boundary: durable credential envelope or service-owned runtime
snapshot ↔ network reachability/auth state. Attack surface closed: unavailable PRS states are now typed as
`PermanentPasswordPrsRead::Available`, `Empty`, or `UndecryptableStorage` instead of being silently collapsed
inside the live reader. `get_permanent_password_prs()` only string-adapts the typed result at the legacy CPace
call boundary, where empty still means fail closed before keying; `has_permanent_password()` keys on the PRS the
auth boundary can actually use, not stale `config.password`. The macOS service-owned runtime snapshot helper
preserves the typed status, and `direct_server` logs undecryptable stored PRS distinctly while dropping/parking
the listener until a valid password is provisioned. No fallback is admitted from stale runtime memory,
`config.password`, preset/hard settings, or prior service snapshots. Verification closure: the config regression
test covers fully provisioned, PRS-empty half-state, and undecryptable current-format storage; `scripts/verify.sh`
gates the typed enum, the undecryptable branch, the server status helper, the direct-listener diagnostic, the
requirements/status disposition, and absence of a silent `unwrap_or_default()` collapse in the PRS string accessor.

**R-S11b/R-S11c — service-owned IPC authority — status: CLOSED / GATED (2026-07-09).**
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
  `src/ipc.rs` admits only narrow typed messages on `_service` via `service_channel_admits_message`
  (`Data::Test`, Linux's R-S11b-2c service-owned unattended-password request, and macOS's
  authorized request/runtime-snapshot service-owned unattended-password messages);
  `src/ipc.rs` deletes the `Data::SyncConfig` IPC variant; `src/ipc/fs.rs` probes `_service`
  liveness with `Data::Test`, not config reads; `src/server.rs` deletes
  `wait_initial_config_sync`/`sync_and_watch_config_dir` and the root↔user service-config watch loop.
  Verification closure: `scripts/verify.sh` runs `ipc::test::service_channel_rejects_config_bus` and asserts
  the service loop, stale-socket probe, server startup, handler, and `Data` enum do not reintroduce the
  whole-config bus;
  `scripts/apple-conform-check.sh` mirrors the source assertions for the macOS conformance path.
- **R-S11b-2a/R-S11c-1a — service-marked server rejects ordinary password IPC — CLOSED 2026-07-08.**
  Platforms: Windows installed service-launched `--server`, Linux root-service-launched root or active-user
  `--server`, and macOS LaunchAgent `--server` source path. Endpoint/action: historical main IPC
  generic config credential writes and password storage/salt read snapshots. Boundary: user-owned IPC caller ↔
  service-owned unattended credential. Attack surface closed:
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
- **R-S11b-2b/R-S11c-1b — user-owned password mutation is typed, not a config write — CLOSED 2026-07-08.**
  Platforms: Linux, Windows, and macOS desktop main IPC; Android/iOS remain app-owned in-process paths rather
  than installed desktop service boundaries. Endpoint/action: `Data::SetUserOwnedPermanentPassword(String)` and
  `Data::SetUserOwnedPermanentPasswordResult(bool)` replace the old in-tree
  generic permanent-password config writer; `permanent-password-user-owned-writable` is a
  read-only receiver capability query. Boundary: user-owned daemon credential state vs installed-service
  unattended credential state. Attack surface closed: CLI, FFI, and Flutter desktop password setters no longer
  send the permanent password as a generic config-key mutation; the generic config write shape is absent;
  service-owned receivers reject and NACK the typed user-owned operation; desktop UI exposes the password setter only when the
  receiver advertises user-owned writability. Changing or removing a password does not prove knowledge of the
  old RustDesk password; authority is daemon ownership now, and OS-admin authorization for future service-owned
  provisioning. Verification closure: `scripts/verify.sh` runs
  `ipc::test::main_channel_rejects_untyped_state_mutations` and
  `ipc::test::service_channel_rejects_config_bus`, asserts the typed operation/result, asserts absence of the
  old generic password config-key send/gate, and checks the desktop writability query;
  `scripts/apple-conform-check.sh` mirrors the macOS source assertions; `scripts/smoke-server.sh` exercises
  the typed user-owned CLI path.
- **R-S11b-2c/R-S11c-1d — Linux service-owned unattended password provisioning — CLOSED 2026-07-09.**
  Platform: Linux installed service. Endpoint/action:
  `Data::RequestServiceOwnedUnattendedPasswordChange(String)` over `_service`, followed by
  `Data::CommitServiceOwnedUnattendedPasswordChange(String)` from the root service into the service-owned
  main server. Boundary: active user process ↔ root `_service` ↔ service-owned `--server` process that honors
  the unattended credential. Attack surface closed: the desktop UI, FFI, and `--password` CLI no longer need the
  old RustDesk password and do not write a service-owned credential over ordinary main IPC. In installed Linux
  mode they request the narrow `_service` operation; the root service authorizes the caller with polkit action
  `com.carriez.RustDesk.set-unattended-password`, deriving the subject from SO_PEERCRED
  `(pid, uid)` plus `/proc/<pid>/stat` start time and invoking `pkcheck --process pid,start-time,uid
  --allow-user-interaction`; only after that does it forward a separate commit message. The service-owned main
  server accepts that commit only when the receiver is `MainIpcAuthority::ServiceOwned` and the committing peer
  is root. Main-channel service-owned password requests are denied, ordinary user-owned password writes remain
  denied for service-owned receivers, and rejection ACKs fail closed. Packaging closure: the `.deb` build paths
  install `res/com.carriez.RustDesk.policy` under `/usr/share/polkit-1/actions/` with `auth_admin` defaults.
  Verification closure: `scripts/verify.sh` asserts the request/commit/result variants, service-channel
  allowlist, main-channel denial/commit gates, peer pid/uid/start-time subject construction, `pkcheck` arguments,
  polkit policy packaging, owner-aware UI/FFI/CLI routing, and the updated two-write handler reachability count;
  `ipc::test::main_channel_rejects_untyped_state_mutations`,
  `ipc::test::service_channel_rejects_config_bus`, and Linux `/proc` parser tests cover the source policy.
- **R-S11b-2d/R-S11c-1e — Windows service-owned unattended password provisioning — CLOSED 2026-07-09; tightened 2026-07-11.**
  Platform: Windows installed service. Endpoint/action:
  `Data::RequestServiceOwnedUnattendedPasswordChange(String)` over `_service`, followed by
  `Data::CommitServiceOwnedUnattendedPasswordChange(String)` from the LocalSystem service into the
  service-owned main server. Boundary: active desktop process ↔ LocalSystem `_service` ↔ service-owned
  `--server` process that honors the unattended credential. Attack surface closed: a medium-integrity
  same-session process cannot mint the privileged unattended password through ordinary main IPC or by forging
  the service request. The desktop/CLI service-owned setter is exposed on Windows only when the caller process
  is already elevated; the service receiver still performs the load-bearing check itself by impersonating the
  connected named-pipe client and requiring an elevated client token before forwarding the commit. Before
  serializing the password-bearing main-IPC commit, the LocalSystem service now authenticates the connected
  main-pipe receiver as the current executable, running as LocalSystem, with the exact
  `--server --service-owned-server` argv shape. The main server accepts the final commit only when the receiver
  is service-owned and the committing pipe client token is LocalSystem. The service loop handles only `Close`,
  `Test`, and the typed password request; it does not
  forward arbitrary `_service` traffic into the main IPC handler. Main-channel service-owned password requests
  remain denied, ordinary user-owned password writes remain denied for service-owned receivers, and rejection
  ACKs fail closed. Verification closure: `scripts/verify.sh` asserts the Windows typed request dispatch,
  pipe-client token impersonation, `RevertToSelf`, elevated-token request gate, sender-side service-owned
  main-receiver proof before the password-bearing send, LocalSystem-token commit gate, already-elevated UI/CLI
  exposure, and absence of PID-based elevation proof for this operation; the Windows source tests cover the
  exact service-owned server argv shape and main-channel policy.
- **R-S11b-2e/R-S11c-1f — macOS service-owned unattended password provisioning — CLOSED 2026-07-09; tightened 2026-07-11.**
  Platform: macOS LaunchDaemon/LaunchAgent installed service. Endpoint/action:
  `Data::RequestMacosServiceOwnedUnattendedPasswordChange { password, authorization }` over `_service`,
  followed by root LaunchDaemon storage and a typed `Data::MacosServiceOwnedPermanentPasswordSnapshotRequest`
  runtime refresh from the service-owned LaunchAgent. Boundary: active desktop/CLI process ↔ root LaunchDaemon `_service`
  ↔ service-owned `--server` process that honors the unattended credential. The `_service` executable identity gate models the deployed
  installation: the peer is the installed app executable under `/Applications/<App>.app/Contents/MacOS/<App>`,
  with root-owned, non-symlink, non-group/world-writable bundle/executable components and the pinned Developer ID
  Team ID plus app identifier requirement, and the receiver is the root-owned, non-symlink,
  non-group/world-writable, ACL-free executable at
  `/Library/PrivilegedHelperTools/com.carriez.rustdesk_service`; the old same-directory app-bundle `service`
  exception is absent. Attack surface closed: service-owned password provisioning no
  longer fails closed on macOS for lack of a privileged path, and it does not fall back to ordinary main IPC,
  generic config writes, or the Authorization Services generic rule. The UI connects to `_service` through the
  authenticated trusted-helper client path, obtains an Authorization Services external form for the RustDesk-specific
  `com.carriez.RustDesk.set-unattended-password` right, and only then sends the proposed password and external
  form in one typed request. The LaunchDaemon creates/updates that right as admin-only, non-shared, and timeout
  zero, internalizes the external form, verifies the right without interaction, destroys the rights, enforces the
  password-size bound, and writes the authorized password directly into the root LaunchDaemon credential store;
  no request-id state machine or pending plaintext secret cache exists. An explicit set is persisted as local
  durable storage even when the value equals a preset. The old macOS main-server
  `Data::CommitServiceOwnedUnattendedPasswordChange` path rejects and cannot write. The service-owned
  LaunchAgent receives the root credential only as a runtime snapshot after the LaunchDaemon proves that the
  `_service` peer is the installed app/trusted-helper pair, has the exact live `--server --service-owned-server`
  command vector, is the pid launchd reports for the expected root-owned
  `/Library/LaunchAgents/..._server.plist` label in `gui/<uid>/<label>`, and is bound to a parsed plist
  whose parent and file are root:wheel, non-symlink, non-group/world-writable, ACL-free, and whose
  `Label`, `ProgramArguments`, `RunAtLoad`, and `KeepAlive` shape exactly describe the service-owned
  LaunchAgent. Empty root local storage returns an empty snapshot; preset/hard-settings
  fallback is absent. The LaunchAgent applies the snapshot to an in-memory PRS overlay that is read by listener
  parking, CPace, and password-set status, and that overlay is never written into user config. Main-channel
  macOS service-owned password flow messages are denied, ordinary user-owned password writes remain denied for
  service-owned receivers, and rejection ACKs fail closed. Verification closure:
  `scripts/verify.sh` and `scripts/apple-conform-check.sh`
  assert the macOS single authorized request shape, `_service` allowlist, main-channel denial, absence of the old
  begin/challenge/finish and pending-cache machinery, authorization-before-send ordering, password-size bound,
  explicit non-shared timeout-zero Authorization Services right, no
  request-digest prompt/verification API, no `kAuthorizationRightExecute` fallback in the service password
  functions, non-interactive `AuthorizationCreateFromExternalForm` verification, signed/root-owned installed-app
  peer identity, trusted PrivilegedHelperTools `_service` current-helper identity, absence of the old same-directory
  `service` binary exception, budgeted macOS `_service` blocking-proof offload, root-store write,
  launchd-owned runtime snapshot with exact live argv plus parsed
  root-owned plist command-shape proof, runtime overlay non-persistence,
  installed-daemon exposure gate, and service handler wiring; the Unix source tests cover main-channel commit
  rejection and `_service` request admission.
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
- **R-S11b-3b/R-S11c-1c — whole-config main IPC and GUI import deleted — CLOSED 2026-07-09.** Platforms:
  Linux, Windows, and macOS desktop main IPC. Endpoint/action: historical `Data::SyncConfig(None)` request,
  `Data::SyncConfig(Some(Box<(Config, Config2)>))` response/write shape, and the GUI/client startup import in
  `src/server.rs` that called `Config::set`/`Config2::set` on the received whole structs. Boundary:
  user-session process ↔ daemon-owned credential, identity, trust, and remote-access policy state. Attack
  surface closed: no local IPC peer can request, receive, or import whole `Config`/`Config2` snapshots through
  the main IPC channel; the enum variant is absent rather than conditionally allowed for user-owned receivers.
  Source closure: `src/ipc.rs` has no `SyncConfig` data variant, no whole-config handler arm, and no
  whole-config authority policy; `src/server.rs` no longer syncs whole config at GUI/client startup.
  Verification closure: `scripts/verify.sh` and `scripts/apple-conform-check.sh` assert `SyncConfig` remains
  absent from `src/ipc.rs`, absent from `src/server.rs`, and absent from `_service` stale-socket probing; the
  main-channel unit test now covers the remaining untyped state mutations instead of accepting a whole-config
  read path.
- **R-S11b-3c — generic config/proxy IPC write shape deleted — CLOSED 2026-07-09.** Platforms: Linux,
  Windows, and macOS desktop main IPC; Linux `_pa` helper bootstrap. Endpoint/action: historical generic
  config write tuple, proxy IPC variant, generic `send_config`/`set_config` helpers, and the `_pa` audio-source
  bootstrap that reused the generic config write payload. Boundary: same-session IPC caller ↔ daemon identity,
  salt, proxy, and local operator preference state. Attack surface closed: config IPC is request/value only
  (`ConfigRequest`/`ConfigValue`); the handler has no `Config::set_id`, `Config::set_salt`, or
  `Config::set_socks` reach; voice-call input is the typed `SetVoiceCallInput` operation; `_pa` no longer
  reuses any generic config write payload; and the proxy IPC variant is absent rather than denied. Verification closure:
  `scripts/verify.sh` runs the main-channel mutation test, asserts absence of the legacy generic config write
  shape, generic config helpers, and proxy IPC variant, and pins the handler's
  `is_option_can_save`-bypassing config-write count to the two typed password operations (user-owned direct
  commit and Linux/Windows service-owned service commit);
  `scripts/apple-conform-check.sh` mirrors the source absence assertions for macOS.
- **R-S11b-3d — Windows service-owned RDP session-sharing policy — CLOSED 2026-07-09.** Platform:
  Windows installed service. Endpoint/action: the desktop Security page's "Enable RDP session sharing" toggle,
  Flutter `mainSetShareRdp`, `ui_interface::set_share_rdp`, and the historical direct `reg add ... share_rdp`
  writer in `src/platform/windows.rs`. Boundary: active user-session UI ↔ LocalSystem service policy that
  selects which Windows session the service-owned host serves. Attack surface closed: the UI/FFI path no
  longer commits HKLM state directly or shells out to `cmd.exe`/`reg.exe`; it sends the typed
  `Data::RequestServiceOwnedShareRdp(bool)` request to the protected Windows `_service` pipe. The service
  validates the connected pipe client's elevated token at the receiver, writes the install registry value
  directly as LocalSystem, and returns `Data::ServiceOwnedShareRdpResult(bool)`. The main IPC channel rejects
  the same request with a negative typed ACK, and the settings toggle is writable only from an elevated
  RustDesk process. Verification closure: `scripts/verify.sh` asserts the typed request/result, main-channel
  denial, `_service` dispatch, receiver-side elevated-token gate, direct registry commit, absence of the
  direct shell writer, UI service request, and UI elevation gate.
- **R-S11b-3e — service identity/salt reads are side-effect-free — CLOSED 2026-07-09.** Platforms: all
  desktop installed-service paths. Endpoint/action: `Config::get_id()`, `Data::ConfigRequest("id")`,
  `Data::ConfigRequest("salt")`, `ipc::get_id()`, login username validation, local recording metadata, and
  startup ID logging. Boundary: read-shaped local/server metadata paths ↔ service-owned identity/salt
  material. Attack surface closed:
  `Config::get_id()` is a pure read; new direct-IP configs no longer auto-generate a numeric RustDesk ID
  at load time; the old MAC-derived generator, Change-ID writer, and `mac_address` dependency are gone;
  config load/store no longer migrates or rewrites legacy ID storage; whole-config `Config::set` preserves
  existing ID fields instead of importing new ones; `Config::get_salt()` is a pure read and no longer
  creates/persists a salt;
  startup logging no longer reads the ID; and the server login gate no longer accepts a non-address
  username by matching the local numeric ID. Existing stored `enc_id` values remain readable for
  compatibility, but an empty ID is valid and stored as absent. The UI helper no longer copies daemon `id`
  into local config and no longer fetches/copies `salt` as a side effect of asking for the ID.
  Verification closure: `scripts/verify.sh` and config unit tests assert the getter body has no
  generation/write/store path, fresh config load does not mint an ID, salt reads do not mint a salt,
  empty IDs are stored absent, legacy IDs are not migrated or rewritten by load/store, whole-config set
  does not import ID fields, the old ID generator/writer/key/dependency symbols are absent, the server
  login fallback is absent, and the IPC helper cannot reintroduce id/salt copy-back.
- **R-S11b-3f — desktop at-rest wrapper no longer creates service identity/key material — CLOSED 2026-07-09.**
  Platforms: Windows/Linux/macOS desktop installed-service and user-owned desktop paths. Endpoint/action:
  `hbb_common::get_uuid()`, `password_security::symmetric_crypt`, and legacy `Config.key_pair` access.
  Boundary: read-shaped metadata / at-rest-secret wrapping ↔ service-owned identity/trust material. Attack
  surface closed: desktop reads and at-rest encryption no longer fall back to generating or storing a
  signing key when `machine_uid` is unavailable; `get_uuid()` is now a UI/device-metadata read that returns
  the machine UID or empty on failure, while `at_rest_storage_key()` is the explicit fallible secret-wrapper
  key source. `symmetric_crypt` fails closed on an unavailable or empty desktop wrapper key instead of
  zero-padding it into an all-zero secretbox key or storing current-version secrets as plaintext. Existing
  legacy desktop blobs encrypted under a previously stored keypair public key remain decryptable through
  `Config::get_existing_key_pair()`, which is read-only and never generates. Mobile `key_pair` generation is
  cfg-isolated to Android/iOS because that remains the documented mobile at-rest wrapper residual pending the
  Keychain/Keystore replacement. Verification closure: `scripts/verify.sh` runs the pk-fallback tests and
  asserts desktop `get_uuid()` does not call the keypair generator, the generator is mobile-cfg-only,
  `get_cached_pk` is absent, `symmetric_crypt` uses the fallible at-rest key API rather than `get_uuid()`,
  empty wrapper keys are rejected, and current-version encryption failures return empty values rather than
  plaintext.
- **R-S11b-3g — trust-anchor/proxy-shaped option writes are pinned empty — CLOSED 2026-07-09.**
  Platforms: all desktop main IPC and every shared `Config` option write path. Endpoint/action:
  `Config::set_option`, `Config::set_options`, `Data::Options(Some(_))`, and callers that sync or cache
  the shared options map. Boundary: local option writers ↔ trust-anchor and proxy credential material.
  Attack surface closed: the legacy `key` option cannot persist a rendezvous trust-anchor override, and
  `proxy-username`/`proxy-password` cannot persist proxy credential material through ordinary options IPC,
  UI/FFI setters, or server-pushed option maps. The existing `proxy-url` pin and the direct `set_socks` /
  `get_socks` / `get_network_type` accessor checks keep the structured SOCKS store inert; this closure adds
  the missing string-map pins for the credential-shaped companions and the trust-anchor override. `get_key`
  continues to return the baked `RS_PUB_KEY`, now with no stored override to ignore. Verification closure:
  `config_it` asserts the pins read empty and reject both single-key and whole-map writes; the `get_key`
  unit test asserts rejected persistence plus constant anchor reads; `scripts/verify.sh` and
  `scripts/apple-conform-check.sh` assert the source pins and the absence of trusted-device/key-confirmation
  writer symbols.
- **R-S11b-3h — main IPC mutation policy has no permissive fallback — CLOSED 2026-07-09.**
  Platforms: Linux, Windows, and macOS desktop main IPC. Endpoint/action:
  `main_channel_admits_state_mutation` over every `Data` variant. Boundary: local IPC caller ↔ daemon-owned
  credential, identity, proxy, trust-anchor, and machine-policy state. Attack surface closed: adding a future
  IPC message can no longer inherit ordinary main-channel authority through `_ => true`; the policy match is
  exhaustive and classifies every current message as a named typed mutation, a denied service-owned request,
  an authority-gated options/password write, or a non-mutating message. Any new `Data` variant now fails
  compilation until it is classified, and `scripts/verify.sh` fails if a wildcard arm is reintroduced. The
  existing handle-level config-write count remains pinned to the two typed permanent-password writers, so a
  newly classified identity/salt/key/proxy/trust-store writer must be introduced as an explicit
  receiver-authorized operation with its own gate rather than as an ordinary IPC write.
- **R-S11b-3i — hardware-codec probe IPC write surface deleted — CLOSED 2026-07-10.**
  Platforms: desktop main IPC source surface. Endpoint/action: the feature-gated `CheckHwcodec` /
  `HwCodecConfig` hardware-codec probe and `_hwcodec` config propagation path. Boundary: ordinary local
  main-IPC peer ↔ service-owned receiver runtime codec state. Attack surface closed: the fork's R-R2b
  software-codec policy already forbids selecting `hwcodec`/`vram`/`mediacodec` in any build path, so the
  remaining feature-gated main-IPC probe write had no valid authority model. `Data::CheckHwcodec`,
  `Data::HwCodecConfig`, their receiver handler, `--check-hwcodec-config`, the client/server IPC sync helpers,
  and the startup callers are deleted instead of being wrapped in a helper-token protocol for a forbidden
  feature. The generated Flutter `main_check_hwcodec` wrapper remains ABI-compatible but reaches a no-op.
  Verification closure: `scripts/verify.sh` rejects any reintroduced hardware-codec IPC message, handler helper,
  client/server sync helper, core `--check-hwcodec-config` entry, or direct helper-process/probe caller anywhere
  in the application source.
- **R-S11c-13 — service-owned IPC close is receiver-authorized — CLOSED 2026-07-09.**
  Platforms: Windows installed service-owned main server and `_service`; Linux/macOS main-channel policy covered
  by the same source rule. Endpoint/action: `Data::Close` on desktop main IPC and Windows `_service`.
  Boundary: same-session/same-executable IPC peer ↔ service-owned process-control action. Attack surface
  closed: `Data::Close` is no longer classified as an unconditional main-channel message. User-owned receivers
  still accept user-owned close, but service-owned receivers accept main-channel close only from the owning
  root/LocalSystem service peer. On Windows the main IPC loop resolves the named-pipe client token for
  `Data::Close` before calling `main_channel_admits_state_mutation`, so a normal same-session installed
  executable cannot trigger service-owned server exit/restart through transport identity alone. The Windows
  `_service` receiver also checks the pipe client token and stops the service loop only for LocalSystem.
  Verification closure: `scripts/verify.sh` runs the main-channel mutation policy test, asserts the close
  authority helper, the `Data::Close => authority.allows_main_channel_close(peer_authority)` policy arm, the
  Windows main-pipe token resolution path, the Windows `_service` LocalSystem close gate, absence of an
  unconditional close bucket, and the Appendix C #31 disposition.
- **R-S11c-14 — service-owned voice-call input IPC mutation gate — CLOSED 2026-07-10.**
  Platforms: Linux, Windows, and macOS desktop main IPC. Endpoint/action:
  `Data::SetVoiceCallInput`. Boundary: ordinary local main-IPC peer ↔ service-owned runtime audio-selection
  state. Attack surface closed: the last unconditional typed main-channel state mutation is no longer admitted
  for service-owned receivers. User-owned receivers keep the operation; service-owned receivers reject it
  regardless of ordinary/same-service peer identity because there is no service-owned voice-input control path
  that should ride the ordinary main IPC channel. Verification closure: `scripts/verify.sh` asserts the
  `allows_main_channel_voice_call_input_write` receiver-authority helper, the gated
  `Data::SetVoiceCallInput` policy arm, and absence of the old unconditional
  `Data::SetVoiceCallInput(_) => true` arm.
- **R-S11c-15 — Windows helper launch environment authority — CLOSED 2026-07-10.**
  Platform: Windows token-switched helper launches. Endpoint/action: `LaunchProcessWin` environment construction
  for helper processes that carry CM/whiteboard launch-token and launch-parent proof variables. Boundary:
  LocalSystem/session-token launcher ↔ helper IPC endpoint proof. Attack surface closed: a token-switched child
  no longer receives an ambiguous environment block when the target user's profile already contains a same-name
  RustDesk launch-proof variable. The C++ launch path now removes inherited same-name variables using
  case-insensitive environment-key comparison, appends the launcher-owned variables, and sorts the final block
  before `CreateProcessAsUserW`, matching the Win32 environment-block contract. The practical impact of the old
  shape was helper launch ambiguity/denial rather than a proven SYSTEM shell, but the authority model is now
  explicit: helper proof material belongs to the launcher, not to ambient user environment state. Verification
  closure: `scripts/verify.sh` asserts the Windows helper environment key parser, case-insensitive key comparison,
  base-entry removal for extra variables, final environment-block sorting, and that the merge helper remains
  outside C linkage.
- **R-S11b-4d — local credential-bearing store file hardening — CLOSED 2026-07-10.**
  Platforms: desktop local config stores. Endpoint/action: per-peer config load, address-book store/load,
  and group store/load. Boundary: local filesystem readers/writers ↔ connect-relevant saved peer credentials
  and address-book/group access tokens. Attack surface closed: `PeerConfig::load` no longer bypasses the
  hardened config loader; it carries typed load status so Windows ACL preparation and corrupt-config
  preservation apply to per-peer config loads, and peer enumeration removes peer files only after a successful
  load of that exact enumerated path as a semantically default `PeerConfig`, never after loading a different
  canonicalized peer path, never after transient unreadable/corrupt/default status, and never when saved options
  or connect-equivalent credentials are present. Address-book and group files keep
  their existing encrypted compressed raw-byte format, but writes now go through a
  temp-and-replace raw helper that prepares the Windows config ACL, writes owner-only `0600` files on Unix,
  uses `MoveFileExW` replace-existing/write-through semantics on Windows, hardens the final Windows file, and
  logs store/load/remove failures. Present-but-unreadable or corrupt raw encrypted payloads are preserved as
  sibling recovery files instead of being deleted. Verification closure: `scripts/verify.sh` asserts the typed
  peer-config load status, exact-path loaded-and-semantically-default empty-peer cleanup, the raw helper shape,
  Windows ACL preparation, Unix owner-only permissions, Windows replace-existing/write-through replacement,
  corrupt-payload preservation, absence of direct `File::create(Self::path())` / ignored `write_all` in those
  stores, and the raw-store permission, replacement, recovery, transient-load, RDP-password, and alias-path
  cleanup-policy regression tests.
- **R-S11c-2a/R-S11c-3a — Windows `_service` raw session/SAS commands removed — CLOSED 2026-07-08.**
  Platform: Windows installed service. Endpoint/action: `_service` named pipe messages formerly carrying
  `Data::UserSid(Some(_))` for service-owned session switching and `Data::SAS` for SYSTEM-mediated
  Ctrl+Alt+Del / temporary HKLM `SoftwareSASGeneration` changes. Boundary: local same-session process or
  user-launched `--server` ↔ SYSTEM service. Attack surface closed: `src/ipc.rs` no longer defines
  `Data::UserSid`, `Data::SAS`, or `connect_to_user_session`; `src/platform/windows.rs` no longer dispatches
  either raw command in the service loop; selected-session requests in `src/server/connection.rs` fail closed
  instead of asking `_service` to launch a target session; physical-console SAS in `src/server/input_service.rs`
  fails closed instead of sending a generic service command. Service-owned session switching and service-mediated
  SAS may be reintroduced only as a typed receiver-authorized capability tied to an authenticated Remote
  connection and current policy state. Verification closure: `scripts/verify.sh` asserts the raw message/API
  symbols and receiver dispatch are absent and the caller paths fail closed.
- **R-S11c-4a/R-S11c-4b — `_cm` file authority bound to a server-validated connection — CLOSED 2026-07-08.**
  Platforms: Linux, Windows, and macOS desktop CM paths; Android in-process CM. Endpoint/action:
  `_cm` / CM file read/write/delete/rename/digest operations. Boundary: helper client ↔ file-transfer
  authority. Attack surface closed: desktop CM no longer trusts a local helper's self-asserted
  `Data::Login`. Each authenticated `Connection` mints a random `cm_auth_token`, records it in
  `AUTHED_CONNS` with the authenticated `AuthConnType` and server-side file capability, and sends it to
  CM. CM validates `(conn_id, AuthConnType, token)` through the main server IPC before calling
  `add_connection`; stale, missing, wrong-type, wrong-token, and forged local logins fail before any CM
  client state is created. Desktop file operations are accepted only as `Data::AuthorizedFS` carrying
  the same token on the already validated CM stream; legacy desktop `Data::FS` is reject-only and is
  closed before `WriteBlock` raw bytes or `handle_fs`. File authority is additionally limited to
  server-validated Remote/FileTransfer sessions with server-validated file capability, so ViewCamera,
  Terminal, PortForward, unauthorized, id-zero, and no-file-capability sessions do not create CM file
  authority. Android remains an in-process channel and keeps the same receiver-side `CmFileAuthority`
  derivation before `handle_fs`. Verification closure: `scripts/verify.sh` runs `cm_file_authority_*`
  tests and source-gates the server token registry, the `ValidateCmConnection` callback, validation
  before `add_connection`, desktop `AuthorizedFS` token matching, desktop legacy `Data::FS` rejection,
  and Android pre-`handle_fs` gating; `scripts/apple-conform-check.sh` mirrors the desktop source
  assertion for macOS.
- **R-S11c-5 — macOS privileged service packaging — CLOSED 2026-07-09; tightened 2026-07-11.** Platform: macOS
  source-conformance and any future macOS artifact. Surfaces: `src/platform/privileges_scripts/daemon.plist`,
  `install.scpt`, deleted `update.scpt`, `uninstall.scpt`, and their `osascript` call sites in
  `src/platform/macos.rs`. Boundary: active-user install/update flow ↔ root LaunchDaemon. Attack surface
  closed: the LaunchDaemon no longer uses `/bin/sh -c`, its stdout/stderr paths no longer point under
  predictable `/tmp`, and its root service executable is no longer inside `/Applications/RustDesk.app`.
  `daemon.plist` runs `/Library/PrivilegedHelperTools/com.carriez.rustdesk_service` directly with
  `/Library/Application Support/RustDesk` as the root-owned working directory. `install.scpt` creates the
  root-owned helper/log/support/root-preference directories and quoted root-owned launchd plists; it no longer
  chowns a mutable app bundle into a root service path, no longer accepts an active-user home argument, no longer
  copies active-user `RustDesk.toml`/`RustDesk2.toml` into root preferences, and no longer trusts a preexisting
  PrivilegedHelperTools executable as the service authority. Instead the Rust install context resolves the bundled
  `Contents/MacOS/service` helper beside the running app, passes that path to the privileged script, and the script
  verifies that bundled helper as a non-symlink executable signed by the pinned Developer ID Team ID with the
  expected helper identifier. It then installs that exact bundled helper through a root-owned temporary file into
  `/Library/PrivilegedHelperTools/com.carriez.rustdesk_service` as `root:wheel` mode `0755`, clears ACLs, verifies
  the temp and final helper signatures, byte-compares the final helper to the bundled source, requires the deployed
  helper directory and helper executable to be non-symlinks, `root:wheel`, non-group/world-writable, ACL-free,
  executable, and signed by the same requirement, and re-verifies the helper after plist writes and immediately
  before `launchctl load`. `uninstall.scpt` unloads the daemon and removes the deployed helper plus any install-temp
  helper before verifying absence. The dormant privileged updater is deleted rather than retained: `update.scpt`,
  `update_daemon_agent`, `.rustdeskupdate-*` helpers, and the macOS startup cleanup for the old update temp
  tree are absent. The Rust-side launcher path remains closed against caller-controlled `PATH`: local
  install/uninstall/asuser/reopen helpers invoke fixed system paths for `osascript`, `launchctl`, `open`,
  and `ioreg`, and active-console identity no longer parses `ls /dev/console`; it reads `/dev/console`
  ownership and resolves the username through `getpwuid_r`, with `launchctl asuser` failing closed on an
  unresolved console UID. The `_service` IPC executable identity exception now requires the peer to be the installed
  app executable under a root-owned, non-symlink, non-group/world-writable bundle path that satisfies the pinned
  Developer ID Team ID plus `com.carriez.rustdesk` app identifier requirement before the helper is inspected. It
  also requires the same deployed helper path, helper-directory ownership/mode/ACL invariants, helper-file
  ownership/mode/ACL invariants, and the same helper code-signing requirement. The old sibling `service` binary
  exception inside the app bundle is absent. Verification closure: `scripts/verify.sh` and
  `scripts/apple-conform-check.sh` assert the PrivilegedHelperTools daemon target and root-owned working
  directory, absence of `update.scpt`/`update_daemon_agent`/`.rustdeskupdate-*`, absence of app-bundle root
  service execution, absence of active-user config import, bundled-helper resolution and osascript argument
  passing, bundled-helper signature checks, root-owned temporary helper install, byte comparison against the
  bundled source, installed-app root ownership/mode and designated-requirement checks, deployed-helper root
  ownership/mode/ACL checks, helper designated-requirement checks in the install script and `_service` IPC receiver,
  helper re-verification before load, uninstall removal of helper leftovers, `/Library/Logs/RustDesk` daemon logs,
  root-owned directory setup, quoted plist writes, quoted privileged plist paths, trusted signed-app plus
  PrivilegedHelperTools `_service` IPC identity, absence of the old same-directory `service` binary exception,
  absolute local helper tool paths, and the `/dev/console`/`getpwuid_r` active-user lookup.
- **R-S11c-17 — macOS runtime service ACL inspection provenance — CLOSED 2026-07-11.**
  Platform: macOS runtime service IPC and service-owned LaunchAgent credential snapshot proof. Surfaces:
  `src/ipc/auth.rs` installed-app/helper trust checks and `src/ipc.rs` LaunchAgent plist trust checks. Boundary:
  root/helper-side runtime trust decision ↔ local filesystem ACL state. Attack surface closed: the Rust runtime
  path no longer spawns `/bin/ls -lde` or parses `ls` output to decide whether a root-owned service path has
  extended ACL entries. This was not a confirmed command-injection primitive because the old command path was
  absolute and the checked path was argv-passed, but root-side authorization must not depend on a formatter
  subprocess for authority-bearing ACL state. Closure: `macos_path_has_no_extended_acl` is a single shared
  `ipc_auth` helper that builds a checked C path, retrieves the exact no-follow extended ACL with
  `acl_get_link_np(..., ACL_TYPE_EXTENDED)`, validates the ACL with `acl_valid_link_np`, rejects any first entry
  returned by `acl_get_entry`, frees the ACL through a drop guard, and fails closed on NUL paths, ACL retrieval
  failure, or validation failure. `src/ipc.rs` now calls that shared helper for LaunchAgent plist parent/file
  trust instead of carrying a second parser. Verification closure: `scripts/verify.sh` and
  `scripts/apple-conform-check.sh` assert the native ACL API shape, the shared free guard, and absence of
  `MACOS_LS` / `Command::new(MACOS_LS)` from the Rust runtime trust path. The privileged installer shell surface is
  closed separately by R-S11c-18.
- **R-S11c-18 — macOS privileged installer ACL enforcement provenance — CLOSED 2026-07-11.**
  Platform: macOS admin-authorized service install. Surfaces: `src/platform/privileges_scripts/install.scpt`,
  `scripts/verify.sh`, and `scripts/apple-conform-check.sh`. Boundary: root installer service-helper authority ↔
  filesystem ACL state. Attack surface closed: the privileged installer no longer proves ACL-free helper state by
  spawning absolute `/bin/ls -lde` and parsing the formatter output with `awk`. The bundled helper source remains
  verified as a non-symlink executable signed by the pinned helper requirement; after copying, the deployed
  `/Library/PrivilegedHelperTools` directory and `com.carriez.rustdesk_service` helper are made ACL-free through
  checked `/bin/chmod -N` postconditions before the script verifies root:wheel ownership, non-group/world-writable
  mode, executable state, byte identity with the bundled helper, and the helper code-signing requirement. This is a
  correctness hardening closure rather than a confirmed command-injection primitive: the old command paths were
  absolute and dynamic paths were quoted, but authority-bearing ACL state is no longer derived from a
  human-readable listing format. Verification closure: `scripts/verify.sh` and `scripts/apple-conform-check.sh`
  require the deployed-helper ACL postcondition, require the requirements/ledger disposition, and reject any
  reintroduced `/bin/ls -lde` / `NR > 1 {exit 1}` installer ACL parser.
- **R-S11c-19 — macOS LaunchAgent live argv authority — CLOSED 2026-07-11.**
  Platform: macOS LaunchDaemon/LaunchAgent installed service. Surfaces: `src/ipc.rs`, `scripts/verify.sh`, and
  `scripts/apple-conform-check.sh`. Boundary: root LaunchDaemon credential snapshot delivery ↔ service-owned
  LaunchAgent process identity. Attack surface closed: the live peer-process proof for
  `Data::MacosServiceOwnedPermanentPasswordSnapshotRequest` no longer accepts a prefix-shaped command vector.
  The LaunchDaemon still requires the `_service` peer to be the installed app talking to the trusted privileged
  helper, requires launchd to report the peer pid under the expected `gui/<uid>/<label>` job and root-owned plist,
  and parses that plist for the exact `ProgramArguments`/`RunAtLoad`/`KeepAlive` shape; this slice makes the live
  process proof match that exact job shape by rejecting any command vector other than the three-entry
  `argv[0]`, `--server`, `--service-owned-server` form. This is correctness hardening rather than a confirmed
  local-to-root path because installed-app code identity and root-owned launchd plist proof were already load-bearing;
  R-S11e-9 subsequently binds that installed-app proof to the socket audit token rather than a PID/path re-observation. Verification
  closure: the Rust tests reject extra live argv, a wrong live service marker, and extra plist
  `ProgramArguments`; both source gates require the exact live argv helper, its snapshot-peer wiring, the
  exact-length check, the wrong-marker test, the extra-argument tests, and absence of the old raw indexed proof
  shape in the blocking peer check.
- **R-S11c-20 — Unix terminal default-shell command provenance — CLOSED 2026-07-11.**
  Platforms: Linux, macOS, Android source path, and other non-Windows Unix terminal service builds. Surfaces:
  `src/server/terminal_service.rs`, `scripts/verify.sh`, and `scripts/apple-conform-check.sh`. Boundary:
  authenticated Terminal session launch ↔ privileged-capable service process environment. Attack surface closed:
  Unix terminal shell selection no longer reads the process `SHELL` environment variable and no longer returns
  `/bin/sh` as an unconditional success fallback. The terminal capability remains the intentional full-control
  shell for the PAKE-authenticated owner; this slice only fixes the executable provenance of the shell used to
  provide that capability. Closure: the Unix resolver selects only fixed absolute shell candidates, rejects
  relative or parent-traversal paths, canonicalizes the selected path, requires both the candidate/canonical parent
  directory and executable to be root-owned and not group/world-writable, requires executable mode bits, and fails
  terminal open when no trusted candidate is present. This is correctness hardening rather than a confirmed local
  privilege escalation in the shipped Linux systemd unit because the unit does not pass `SHELL`. Verification
  closure: Rust tests cover absolute candidate shape, relative/parent-path rejection, and a trusted candidate in
  the Linux verifier environment; both source gates require the trusted Unix shell resolver, root/mode/executable
  checks, tests, requirements/ledger disposition, and absence of `SHELL`, bare shell, or unconditional `/bin/sh`
  success fallback in the Unix terminal shell block.
- **R-S11c-21 — macOS privileged service template identity input — CLOSED 2026-07-11.**
  Platform: macOS admin-authorized service install/uninstall source path. Surfaces:
  `src/platform/macos.rs`, `src/platform/privileges_scripts/install.scpt`, `uninstall.scpt`,
  `daemon.plist`, `agent.plist`, `scripts/verify.sh`, and `scripts/apple-conform-check.sh`. Boundary:
  active-user app metadata and signed custom-client app-name state ↔ root-executed AppleScript/plist service
  authority. Attack surface closed: privileged script/plist rendering no longer reads the live
  `NSBundle.bundleIdentifier` / `CFBundleIdentifier` and no longer performs broad `rustdesk`/`RustDesk`
  source replacement that can rewrite fixed helper/app identifiers. The old path was
  `get_bundle_id()` → `correct_app_name()` → substituted AppleScript/plist source →
  `/usr/bin/osascript -e` → `do shell script ... with administrator privileges`. It is deleted, not
  authority-wrapped. The renderer now substitutes only explicit app-name-derived data: launchd service/server
  labels, app executable and working-directory paths, support/log/root-preference paths, and user-facing prompt
  text. The helper executable path, helper designated requirement, LaunchDaemon/LaunchAgent associated bundle
  identifier, and runtime app designated requirement stay fixed to `com.carriez.rustdesk` /
  `com.carriez.rustdesk_service`, matching the `_service` IPC trust constants. Verification closure:
  `scripts/verify.sh` and `scripts/apple-conform-check.sh` reject `get_bundle_id`, `bundleIdentifier`, the old
  `correct_app_name` renderer, any lowercase fixed-identifier rewrite in the renderer, missing explicit app-path
  and label substitutions, non-fixed associated bundle identifiers in the plists, and missing
  requirements/ledger disposition.
- **R-S11c-16 — Desktop service lifecycle completion authority — CLOSED 2026-07-10.**
  Platforms: Linux and macOS desktop service wrappers, plus the shared desktop service CLI dispatcher. Surfaces:
  `core_main` `--install-service` / `--uninstall-service`, Linux `systemctl` service lifecycle helpers, macOS
  `install_service()` / `is_installed_daemon(prompt=true)` / `uninstall_service(sync=true)`, and
  `install.scpt` / `uninstall.scpt`. Boundary: local caller/UI/CLI ↔ privileged service lifecycle state.
  Attack surface closed: service install/uninstall can no longer hide failure behind a started helper process,
  ignored status, partial plist state, or a discarded wrapper return. The CLI exits nonzero when service lifecycle
  wrappers report failure. Linux service install no longer imports active-user `Config`/`Config2` files into
  root service state; service-owned unattended password provisioning remains the typed `_service` + polkit path.
  `systemctl enable`, `start`, `disable`, and `stop` failures are fatal wrapper failures with logged status.
  macOS checks AppleScript exit status, verifies both daemon and agent plist
  postconditions, propagates synchronous uninstall result, verifies current-session
  LaunchAgent label removal/reload, and the privileged scripts verify daemon unload/load state plus final plist
  removal instead of masking `launchctl unload` with `|| true`. The Flutter daemon install card keeps its
  prompt-and-return-immediately shape: the prompt path starts the checked install worker and the UI's next state
  observation is still the ordinary installed-state query. Verification closure: `scripts/verify.sh` asserts the
  cross-desktop CLI, Linux, and macOS invariants; `scripts/apple-conform-check.sh` mirrors the macOS source
  assertions.
- **R-S11c-10a — Linux root-context desktop discovery shell interpolation — CLOSED 2026-07-09.**
  Platform: Linux installed service/helper discovery. Surfaces: active-user prelogin shell lookup,
  process-environment discovery for `DISPLAY`/`XAUTHORITY`/Wayland/DBus variables, direct PID environment
  lookup, Xorg `-auth` discovery, active-user home lookup, and RustDesk Xorg-subprocess detection.
  Boundary: local seat/user/process metadata ↔ root-context discovery helpers. Attack surface closed:
  these paths no longer build `getent passwd`, `ps|grep|awk`, or `/proc/<pid>/environ|grep|sed`
  pipelines. Prelogin state uses the `users` passwd API and path-based non-login-shell detection; home lookup
  uses `get_user_home_by_name`; process selection reads `/proc/<pid>/cmdline` and filters by UID in Rust; and
  environment lookup reads `/proc/<pid>/environ` with exact key matching. Verification closure:
  `scripts/verify.sh` runs the `r_s11c10_` Linux unit tests and asserts that the touched discovery function
  bodies contain no shell-shaped passwd/proc/process pipeline.
- **R-S11c-10b — Linux service lifecycle process cleanup shell pipelines — CLOSED 2026-07-09.**
  Platform: Linux installed service lifecycle cleanup. Surfaces: `stop_rustdesk_servers()` and
  `stop_subprocess()` in `src/platform/linux.rs`. Boundary: root service lifecycle management ↔ local
  process table. Attack surface closed: root-context cleanup no longer interpolates the app name into
  `ps | grep | awk | xargs kill -9` shell pipelines. It enumerates `/proc/<pid>/cmdline` directly, matches
  RustDesk `--server` and `--cm-no-ui` processes by `/proc/<pid>/exe` equality to the current executable
  plus exact argv, matches Xorg cleanup by basename `Xorg` plus the exact `/etc/<app>/xorg.conf` argv, and sends `SIGKILL` with
  `kill(2)` only to positive, non-current pids. Verification closure: `scripts/verify.sh` runs the
  `r_s11c10_process_kill_*` unit test and asserts the lifecycle cleanup block uses the `/proc` argv helpers
  and `hbb_common::libc::kill`, with no `run_cmds`, `ps`, `grep`, `awk`, `sed`, `xargs`, or `kill -9`
  shell-shaped cleanup path.
- **R-S11c-10c — Linux xrandr resolution discovery shell pipeline — CLOSED 2026-07-09.**
  Platform: Linux installed service/display helper path. Surfaces: supported-resolution discovery and current
  resolution lookup in `src/platform/linux.rs`. Boundary: display metadata lookup ↔ root-context process
  execution. Attack surface closed: resolution discovery no longer invokes `sh -c "xrandr --query | tr -s ' '"`
  from a service/helper process. The fixed query is now `Command::new("xrandr").arg("--query")`, and the old
  `tr -s ' '` behavior is implemented by a Rust-side whitespace normalizer before the existing parser runs.
  Verification closure: `scripts/verify.sh` runs the `r_s11c10_xrandr_*` unit test and asserts both resolution
  query call sites use the argv-only helper, no shell/pipeline tokens remain in the xrandr query block, and
  Rust-side normalization preserves the parser's expected shape.
- **R-S11c-10d — Linux process-discovery `pgrep` shell probes — CLOSED 2026-07-09.**
  Platform: Linux service/helper process discovery. Surfaces: Xwayland presence detection in
  `src/platform/linux.rs`, whiteboard Xwayland display discovery in `src/whiteboard/linux.rs`, and KDE session
  detection in `libs/hbb_common/src/platform/linux.rs`. Boundary: local process-table metadata ↔
  root/service/helper process decisions. Attack surface closed: these paths no longer invoke `pgrep` or
  `sh -c "pgrep ..."`. Xwayland discovery enumerates `/proc/<pid>/cmdline`, matches argv[0] basename
  `Xwayland`, and extracts only local display arguments such as `:0`/`:1.0`; whiteboard uses that same typed
  helper instead of parsing whitespace output; KDE detection matches only process basenames of the form
  `kded` plus digits, not arbitrary command-line text containing `kded5`. Empty, unreadable, or disappearing
  `/proc` entries are skipped. Verification closure: `scripts/verify.sh` runs the
  `r_s11c10_process_discovery_*` and `r_s11c10_kde_session_*` unit tests and asserts the touched discovery
  blocks contain no `run_cmds`, `CMD_SH`, `sh -c`, `pgrep`, or grep-shaped process probe.
- **R-S11c-10g — Linux SELinux status shell probes — CLOSED 2026-07-09.**
  Platform: Linux service/display helper status path. Surface: `is_selinux_enforcing()` in
  `src/platform/linux.rs`. Boundary: root/service helper status lookup ↔ local shell command execution.
  Attack surface closed: SELinux status no longer invokes `getenforce` or parses `sestatus` through
  `run_cmds`. The helper reads the fixed selinuxfs runtime enforcement files `/sys/fs/selinux/enforce` and
  legacy `/selinux/enforce` as ordered data, uses the first readable valid state, treats only the kernel
  boolean value `1` as enforcing, and treats
  missing, unreadable, malformed, disabled, or permissive state as not enforcing for the UI status check.
  Verification closure: `scripts/verify.sh` runs the `r_s11c10_selinux_*` unit tests and asserts the fixed
  selinuxfs paths, parser, file reader, absence of `getenforce`/`sestatus`, and absence of shell-shaped
  SELinux status probing in the touched block.
- **R-S11c-10h — Linux config-home correction shell probes — CLOSED 2026-07-09.**
  Platform: Linux config path resolution when `ProjectDirs` resolves through `/root`. Surface:
  `libs/hbb_common/src/config.rs` `patch(PathBuf)`, which formerly invoked `whoami` and then interpolated the
  discovered user into `getent passwd ... | awk` to recover a non-root home. Boundary: current process identity
  / account database lookup ↔ service/root-context config filesystem decision. Attack surface closed: config
  home correction now calls the existing `getpwuid`-backed `crate::platform::linux::get_home_dir_trusted()`
  helper and falls back to the original path if the typed lookup cannot resolve a directory; it no longer
  executes shell commands or derives a fallback home from shell output. Verification closure:
  `scripts/verify.sh` runs `config_patch_root_home_uses_passwd_home` and asserts the `patch`
  block contains no `run_cmds`, `whoami`, `getent`, `awk`, or shell-shaped probe tokens.
- **R-S11c-10i — Linux service lifecycle `systemctl` command construction — CLOSED 2026-07-09.**
  Platform: Linux installed-service lifecycle commands from `src/platform/linux.rs`. Surface:
  `install_service()` / `uninstall_service()`. Boundary: local service lifecycle action ↔ root-context
  process execution and service-owned credential state. Attack surface closed: lifecycle commands no longer build a single `sh -c`
  string containing `cp -f ...; systemctl enable/disable/start/stop ...`, and they no longer discover
  `systemctl` through `which`/`PATH`. The service helper selects only fixed root-owned non-group/world-writable
  `/usr/bin/systemctl` or `/bin/systemctl` candidates and invokes `enable`, `disable`, `start`, and `stop`
  as direct argv. Linux service install no longer imports active-user `Config`/`Config2` files into root service
  state; service-owned unattended password provisioning remains the typed `_service` + polkit path. Verification
  closure: `scripts/verify.sh` runs the `r_s11c10_service_*` unit tests and asserts the lifecycle block uses fixed
  `systemctl` paths, the argv helper, no user-config import into root service state, and no stale
  `run_cmds_status`, `has_cmd`, `which`, `cp -f`, shell, or inline `systemctl ...` command text.
- **R-S11c-10j — Debian package lifecycle and systemd stop semantics — CLOSED 2026-07-09; tightened 2026-07-11.**
  Platform: Debian/Linux `.deb` install, upgrade, remove, and purge lifecycle. Surfaces:
  `res/DEBIAN/preinst`, `postinst`, `prerm`, `postrm`, `res/rustdesk.service`, generated `.deb`
  dependencies and Debian packaging paths in `build.py`, `scripts/build-debian.sh`, and the Linux service parent
  that supervises the managed `--server` child.
  Boundary: privileged package-maintainer scripts and systemd stop semantics ↔ local process table and
  service-owned listener process. Attack surface closed: package scripts no longer parse `/proc/1/exe` with
  `ls|awk`, call `service` or arbitrary `systemctl` unit actions directly, sed-patch the installed unit, discover old user services with
  `ps|grep|awk`, or interpolate a discovered user into `systemctl --machine=...`. Maintainer scripts use
  `deb-systemd-helper` for enable/disable/purge state, `deb-systemd-invoke` only for unit stop/start, and the
  fixed manager command `/bin/systemctl --system daemon-reload` for daemon reloads, with `init-system-helpers`
  declared in the generated Debian control file; helper and manager failures are no longer converted to
  maintainer-script success. Fresh install does not stop a nonexistent old unit; upgrade stops an existing old
  system unit before package transition; configure checks enable, manager reload, and start; remove and
  deconfigure check stop/disable/manager-reload before deleting entry points and unit files; purge checks
  helper-state cleanup and removes the stock root service config tree at `/root/.config/RustDesk`, plus the
  historical lowercase `/root/.config/rustdesk` residue. `build.py` starts Debian package staging from a clean
  `tmpdeb`, uses checked control-script copy operations, and separates `dpkg-deb` from cleanup so package-build
  failure cannot be hidden by `rm -rf`. `scripts/build-debian.sh` extracts each emitted `.deb`, compares
  `preinst`/`postinst`/`prerm`/`postrm` byte-for-byte with `res/DEBIAN`, runs the same maintainer-script
  lifecycle validator over the built control scripts, and rejects any built maintainer script that masks
  lifecycle helper failure or reintroduces invalid helper actions. The unit no longer carries
  `ExecStop=pkill -f "rustdesk --"` or `KillMode=mixed`; shutdown is cgroup-scoped `SIGTERM` with
  `TimeoutStopSec=30`/SIGKILL as the fixed backstop. The Linux service parent no longer uses
  `Child::kill()` as the first stop action for the managed `--server` child; it sends `SIGTERM`, waits a bounded
  eight seconds for the existing R-T9 drain, and only then forces the child. Verification closure:
  `scripts/verify.sh` asserts the helper-layer package scripts, checked helper/manager results, stock root config
  purge path, checked Debian packaging operations, the `.deb` dependency, absence of legacy raw process/systemctl/pkill stop shapes, the
  cgroup-scoped unit stop mode, and the SIGTERM-first managed-child supervisor path; `scripts/build-debian.sh`
  enforces the built-control-script proof before hashing artifacts.
- **R-S11c-7 — Linux `_pa` audio helper capability — CLOSED 2026-07-09.** Platform: Linux desktop while the
  `_pa` helper is running for local audio capture. Endpoint/action: `_pa` IPC stream formerly accepted a
  bare PulseAudio source request and then streamed raw monitor/input frames. Boundary: same-UID local process
  ↔ active audio capture helper. Attack surface closed: `_pa` now requires the first frame to be
  `Data::PulseAudioStart { owner, token, source }`; the audio service mints a 32-byte in-memory capture
  lease from its active subscriber-id set immediately before connecting to `_pa`; controlled-side `--server`
  leases are bound to the authenticated live process identity of the server's connected `_cm` stream for those
  subscriber ids (`pid`, `uid`, Linux `/proc` start time, current executable, expected `--cm`/`--cm-no-ui`
  mode, server-scoped CM launch token, and server-parent ancestry), while viewer-side `CLIENT_SERVER` voice-call capture is bound to
  the current process identity. The server accepts a Linux `_cm` endpoint only after that identity check, stores
  it only for the lifetime of the CM IPC bridge, and rejects stale/reused, launch-tokenless, or non-descendant identities before
  minting a downstream audio lease. The audio service verifies the connected `_pa` endpoint identity before
  disclosing the token; `_pa` validates locally only when the serialized owner identity is its own process and
  otherwise connects to the owner's UID-scoped main IPC, authenticates that endpoint against the serialized owner
  identity, and sends `ValidatePulseAudioStart`. The owner server then checks both token and validation peer
  identity before any source resolution, default-monitor lookup, PulseAudio open, or raw audio frame streaming.
  The token is cleared when the audio service run exits, and missing, wrong, wrong-peer, and stale tokens fail
  closed. The old
  `PulseAudioSource(String)` message is absent, so a local same-UID process can no longer connect directly to
  `_pa` and start audio capture by naming a source, nor can a fixed-path `_cm`/`_pa` squatter feed the Linux
  audio authority unless it is the authenticated live token-launched CM process identity selected for that server.
  Linux stale-socket probing for `_cm` and `_pa` is identity-bound, so arbitrary same-UID listeners are not kept
  as valid incumbents. Verification closure:
  `scripts/verify.sh` runs the Linux `pa_capture_authority_*` unit tests and asserts the owner-identity start
  message, owner-UID-routed and owner-identity-authenticated helper validation, endpoint identity check before
  token send, subscriber-bound authority installation, authenticated live CM identity registration/cleanup,
  CM launch-token and launch-parent ancestry checks, stale `_cm`/`_pa` socket probe checks, old message absence, and the service-layer
  subscriber-id snapshot. The fixed-path CM endpoint-selection class is closed separately below for macOS and
  non-audio helper consumers.
- **R-S11c-11 — Desktop `_cm` endpoint-selection identity — CLOSED 2026-07-09; Windows extended 2026-07-11.** Platforms: Linux,
  macOS, and Windows desktop CM paths before any non-audio helper authority is disclosed. Endpoint/action:
  server-side selection of the fixed `_cm` listener that receives `Data::Login`, `cm_auth_token`,
  file-authority messages, chat, voice-call state, and future downstream helper leases. Boundary: same-UID
  local process ↔ connection-manager endpoint. Attack surface closed: macOS and Windows no longer accept a raw
  fixed-path `_cm` connect as endpoint identity. The server authenticates the selected CM process shape
  (`--cm`, current executable; on Windows through the named-pipe server PID), proves the server launch token
  to the CM over a server-proof HMAC context, and then sends a fresh endpoint challenge; the CM listener only
  answers after accepting a current-executable `--server` peer and verifying that peer's launch-token proof,
  and answers with an endpoint-proof HMAC keyed by the server-minted launch token inherited through the CM
  launch environment. Windows CM launch paths now pass that token environment through both the active-session
  launcher and same-user launcher, and the Windows server-side secondary `_cm` clients for clipboard-file sync
  and privacy-mode state perform the same authenticated connect before sending data. The old Flutter
  theme/language notification side-channel is no longer a `_cm` IPC client.
  Linux keeps its stronger live process identity check (UID, current executable, expected CM mode, proc
  start time, launch token, launch parent ancestry) and now also performs the same mutual pre-disclosure
  proof. Stale, preexisting, launch-tokenless, wrong-mode, wrong-token, fixed-path squatting listeners, and
  same-binary `--server` signing-oracle attempts fail before `Data::Login` or the per-connection CM token is
  sent. Verification closure: `scripts/verify.sh` runs the `cm_endpoint_proof_*` unit test and asserts the
  server/endpoint challenge/proof variants, directional HMAC proof/verify helpers, server-side proof before
  CM stream use, CM listener server-proof verification before endpoint proof and before spawning the normal
  IPC loop, macOS and Windows process-shape checks, macOS and Windows launch-token environment propagation,
  authenticated Windows clipboard/privacy `_cm` clients, absence of the old generic theme/language `_cm`
  notification channel, and absence of raw Linux/macOS/Windows `_cm` connects;
  `scripts/apple-conform-check.sh` mirrors the macOS source assertions.
- **R-S11c-8 — `_whiteboard` helper ambient same-UID trust — CLOSED 2026-07-09.** Platforms: Windows,
  Linux, and macOS desktop whiteboard helper paths. Endpoint/action: `_whiteboard` overlay helper IPC formerly
  accepted `Data::Whiteboard((String, CustomEvent))` drawing events and `Exit` on a fixed endpoint.
  Boundary: local same-UID/same-session process ↔ active whiteboard overlay helper. Attack surface closed:
  `src/ipc.rs` deletes the bare tuple message and replaces it with typed
  `WhiteboardBind`, tokenized `WhiteboardEvent`, tokenized `WhiteboardClose`, and authenticated-stream
  `WhiteboardShutdown` messages plus whiteboard-specific server/endpoint HMAC proof variants. The server-side
  producer in `src/whiteboard/client.rs` now creates a fresh 32-byte launch token per helper start, derives a
  launch-scoped `_whiteboard_<hmac>` endpoint from that token, passes the token and parent pid through the
  helper environment, authenticates the endpoint proof before binding any connection, and sends only
  per-connection tokens minted when a Remote-authenticated `Connection` registers `show_my_cursor`.
  `src/whiteboard/server.rs` reads the launch-scoped endpoint, admits only the recorded parent pid through
  `ipc::authorize_whiteboard_ipc_connection`, completes the whiteboard launch proof before spawning the stream
  loop, derives the render key from the validated `conn_id`, rejects unbound/wrong-token/`Exit` events, and no
  longer sends a global overlay `Exit` on arbitrary stream close. Windows service-session whiteboard launch is
  covered by `src/platform/windows.rs`/`src/platform/windows.cc`, which now pass caller-specified child
  environment entries through `CreateProcessAsUserW` without putting the token on the command line.
  Verification closure: `scripts/verify.sh` runs `whiteboard_endpoint_proof_*` and `whiteboard_authority_*`
  tests, asserts the typed protocol, launch-token/parent environment, launch-scoped endpoint, endpoint proof,
  parent-pid admission, per-connection token state machine, Remote-only registration by `conn_id`, Windows
  environment launcher, absence of the legacy tuple message/sends, absence of raw fixed `_whiteboard`
  connect/listen, absence of caller-derived render keys outside the helper, and absence of unconditional
  global `Exit`; `scripts/apple-conform-check.sh` mirrors the macOS source assertions.
- **R-S11c-12 — Windows terminal helper pipe binding — CLOSED 2026-07-09.** Platform: Windows desktop
  installed-service terminal helper path. Endpoint/action: the SYSTEM service launches a logged-in-user
  terminal helper with `CreateProcessAsUserW`, then exchanges terminal input/output over per-terminal named
  pipes. Boundary: local target-user process ↔ helper pipe endpoint selected by the privileged service.
  Attack surface closed: a same-user local process that learns or races the UUID pipe names is not accepted
  as the helper. The service creates each pipe as a first-instance, local-only named pipe with the existing
  SYSTEM-plus-target-user DACL, launches the helper, and after `ConnectNamedPipe` accepts only a client PID
  returned by `GetNamedPipeClientProcessId` that exactly matches the PID returned by `CreateProcessAsUserW`.
  Service/helper debug logs no longer print the pipe names. Verification closure: `scripts/verify.sh` asserts
  the client-PID query/gate, expected helper PID parameter, both service-side pipe waits passing the launched
  helper PID, first-instance and remote-client rejection flags, absence of the old pipe-name logging strings,
  and this ledger/requirements disposition.
- **R-S11d — Windows installer service-root authority — CLOSED 2026-07-09.** Platform: Windows EXE and MSI
  install/update service creation paths. Endpoint/action: choosing or carrying the installed service binary
  directory, staging elevated EXE command files, and MSI service/registry privileged custom actions. Boundary:
  local unelevated install UI/CLI/MSI properties and caller-writable staging ↔ elevated installer/LocalSystem
  service binary authority. Attack surface closed: a caller-selected or registry-restored install folder no
  longer becomes the LocalSystem service root. The EXE installer resolves Program Files with
  `SHGetKnownFolderPath`, rejects non-default paths, removes Flutter path selection, resolves elevated `cmd.exe`
  with `GetSystemDirectoryW`, keeps generated command files open read-only with `FILE_SHARE_READ` only while the
  elevated child consumes them, uses the same fixed-root helper from `install_me`, `install_service`, and
  `run_after_install`, and makes `sc` service-creation failures leave the elevated command marker intact so the
  caller sees failure. MSI uses private `App.InstallFolder` under `ProgramFiles6432Folder`, has no public
  `INSTALLFOLDER`/`INSTALLFOLDER_INNER`/`WIXUI_INSTALLDIR`/browse surface, and has no service shell
  fallback; service creation/start/stop/delete use checked native APIs and fail closed on native API failure or
  stale service deletion. Verification closure: `scripts/verify.sh`
  asserts known-folder Program Files resolution, custom-path rejection, trusted system `cmd.exe` resolution,
  write/delete sharing denial on EXE command staging, fixed Flutter install entry, fixed-root EXE service entry
  points, fatal EXE `sc` errors, MSI private install root, absence of MSI browse/public install-folder routing,
  checked MSI privileged custom-action returns, native service-delete verification, absence of MSI
  `sc`/`cmd.exe`/`reg` shell fallbacks, post-elevated relaunch executable authority via R-S11d-30,
  privacy broker served-session authority via R-S11d-31, and this ledger/requirements disposition.
- **R-S11d-1 — Windows Amyuni IDD helper launch provenance — CLOSED 2026-07-10.** Platform:
  Windows MSI deferred custom action and runtime virtual-display helper path. Endpoint/action:
  `deviceinstaller64.exe` under `usbmmidd_v2`, launched to install/remove the Amyuni virtual-display driver.
  Boundary: installed Program Files helper payload ↔ privileged MSI/custom-action or service/runtime helper
  execution. Attack surface closed: both launch paths now execute the checked absolute helper executable path.
  The MSI action checks that `usbmmidd_v2` is a directory, checks that the helper path is a
  file, and passes `exePath` as the `CreateProcessW` application path rather than the bare helper name. The runtime helper carries both the working
  directory and absolute executable path as wide strings and executes `paths.exe_path`, with the old ANSI
  bare-name `ShellExecuteA` surface removed. Verification closure: `scripts/verify.sh` asserts the MSI
  `exePath` CreateProcess call, rejects the old bare-name call, asserts the runtime absolute-path helper and
  `paths.exe_path` launch, rejects `ShellExecuteA`/bare `INSTALLER_EXE_FILE` launch, and checks this
  ledger/requirements disposition.
- **R-S11d-2 — Windows Amyuni IDD cleanup completion authority — CLOSED 2026-07-10.** Platform:
  Windows MSI deferred non-impersonated uninstall/update custom action. Endpoint/action:
  `RemoveAmyuniIdd` removing the `usbmmidd` Amyuni virtual-display device through SetupAPI and, on AMD64, the
  installed `usbmmidd_v2\deviceinstaller64.exe remove usbmmidd` fallback. Boundary: installed privileged driver
  state/helper payload ↔ privileged MSI cleanup state. Attack surface closed: cleanup no longer hides native
  SetupAPI failure or helper failure from MSI. The native path returns a `DriverUninstallStatus` plus `HRESULT`:
  complete enumeration proving no present matching hardware ID is a successful no-op, successful removal of all
  matching present devices is success, and enumeration/property/class-installer/remove failures are fatal unless
  the AMD64 helper fallback succeeds. The helper fallback is attempted only after native failure; if native
  removal failed, a missing helper directory or helper executable is fatal rather than a silent skip. The action
  launches the already checked absolute helper with `CreateProcessW`, waits with a bounded timeout, reads the
  exit code, accepts `ERROR_SUCCESS_REBOOT_REQUIRED` as success-with-reboot, treats other nonzero exits as
  failure, signals reboot-required state through WiX, and the WiX action is `Return="check"`. The action is
  scheduled only for uninstall/upgrade. Stale bare-`netsh` `ShellExecuteW` firewall helper examples and their
  commented reactivation path are deleted. Verification closure: `scripts/verify.sh` asserts the native status
  contract, HRESULT propagation, complete-enumeration/not-present branch, MultiSZ hardware-ID scan, checked
  helper fallback, reboot signaling, uninstall/upgrade scheduling, `RemoveAmyuniIdd` `Return="check"`, absence
  of the old ignored-return/native-result-discard shapes, and this ledger/requirements disposition.
- **R-S11d-3 — Windows runtime process command provenance — CLOSED 2026-07-10.** Platform:
  Windows runtime service-adjacent process probes in `src/platform/windows.rs`. Endpoint/action:
  non-installed UAC `consent.exe` detection used by capture/privacy-mode decisions, and startup cleanup for the
  topmost-window `RuntimeBroker_rustdesk.exe` helper. Boundary: service/runtime control flow ↔ ambient shell and
  executable lookup. Attack surface closed: these paths no longer launch bare `cmd`, `tasklist | findstr`, or
  shell `taskkill`; they enumerate exact image names with a ToolHelp process snapshot, close snapshot/process
  handles through a local RAII guard, and terminate stale broker processes through `OpenProcess(PROCESS_TERMINATE)`
  plus `TerminateProcess`. Cleanup remains best-effort for service startup, but enumeration and per-process
  failures are logged instead of hidden behind a spawned shell. The service-start IPC bind-failure path no longer
  tries to close an unknown IPC occupant or terminate a basename/argv-matched "main window" process through
  `NtTerminateProcess` / `PROCESS_ALL_ACCESS`; it reports the occupied IPC endpoint and exits fail-closed.
  Verification closure: `scripts/verify.sh` asserts the exact-name ToolHelp enumerator, RAII handle guard, native
  termination helper, the `consent.exe` and broker call sites, absence of shell probes in the runtime blocks,
  absence of `Command::new("cmd")` in `src/platform/windows.rs`, absence of the main-window process-kill fallback,
  and this ledger/requirements disposition.
- **R-S11d-4 — Windows MSI runtime-generated executable cleanup completion authority — CLOSED 2026-07-10.**
  Platform: Windows MSI deferred non-impersonated uninstall/update custom action. Endpoint/action:
  `RemoveRuntimeGeneratedFiles` removing `RuntimeBroker_rustdesk.exe` from the installed Program Files
  directory. Boundary: installed runtime-generated executable payload ↔ privileged MSI cleanup state. Attack
  surface closed: the cleanup no longer silently continues after malformed empty install-folder data, root-folder
  targets, or a failed broker deletion. The action treats empty/root install folders as fatal packaging errors,
  requires the existing handle-based no-follow `DeleteRuntimeGeneratedFile` path to report success for the broker
  payload, keeps absent files as a successful no-op, and declares the WiX action `Return="check"`. The scheduled
  no-op `CustomActionHello` sample action is deleted from the custom-action DLL exports, WiX declaration, and
  execute sequence. Verification closure: `scripts/verify.sh` asserts the checked broker-delete branch, fatal
  cleanup message, checked WiX return, absence of the old ignored return, absence of the sample custom action,
  and this ledger/requirements disposition.
- **R-S11d-5 — Windows EXE elevated batch command provenance — CLOSED 2026-07-10.** Platform:
  Windows EXE install/uninstall/service-install elevated command path. Endpoint/action: generated `.bat`
  files launched through UAC-elevated `System32\cmd.exe` by `run_cmds`. Boundary: unelevated installer process
  and its current directory/environment ↔ elevated registry, firewall, service, process-termination, shortcut,
  and file-copy actions. Attack surface closed: the batch body no longer resolves external tools by bare command
  name. Before any elevated EXE batch is formatted, `src/platform/windows.rs` resolves `chcp.com`,
  `cscript.exe`, `msiexec.exe`, `netsh.exe`, `reg.exe`, `sc.exe`, `taskkill.exe`, `timeout.exe`, and
  `xcopy.exe` from `GetSystemDirectoryW`, requires each file to exist, quotes the resulting absolute path, and
  threads that tool set through broker update, install, uninstall, service install/uninstall, prior-MSI uninstall
  handoff, service creation, shortcut-script execution, registry/firewall/SAS setup, and bulk-copy fragments.
  Missing or malformed tool paths fail closed before elevation; the existing `.undone` marker still makes batch
  failure visible to the caller. Prior MSI uninstall strings are not replayed as command text: R-S11d-35 parses
  only the MSI product-code grammar, proves `ProductName` through Windows Installer, and rebuilds the command with
  the trusted `msiexec.exe`. Verification closure: `scripts/verify.sh` asserts the System32 tool resolver, the
  required tool set, prior-MSI product-code reconstruction/proof, and absence of bare `chcp`, `reg`, `netsh`, `sc`,
  `taskkill`, `cscript`, `XCOPY`, `xcopy`, or `timeout` command lines in the elevated batch surface.
- **R-S11d-6 — Windows EXE shortcut finalization provenance — CLOSED 2026-07-10.** Platform:
  Windows EXE install/service-install elevated shortcut creation. Endpoint/action: Public Desktop shortcut,
  Common Programs Start Menu shortcuts, Common Startup tray shortcut, and Program Files uninstall shortcut.
  Boundary: unelevated caller-owned temporary staging ↔ all-users/protected shortcut destinations. Attack
  surface closed: the installer no longer creates predictable `.lnk` files under the user temp directory and
  then elevated-copies them into public/ProgramData/Program Files locations. `src/platform/windows.rs` resolves
  final shortcut roots with `SHGetKnownFolderPath` (`FOLDERID_PublicDesktop`, `FOLDERID_CommonPrograms`,
  `FOLDERID_CommonStartup`), creates VBS command files that call `WScript.Shell.CreateShortcut` on the final
  protected shortcut path directly under the elevated batch, rejects quote/CR/LF in installer script literals,
  fails the batch immediately on `cscript.exe` error, and deletes the old temp-output tray shortcut helper.
  Verification closure: `scripts/verify.sh` asserts the known-folder roots, final-destination shortcut command
  helper, checked `cscript.exe` runner, final path call sites, absence of temp `.lnk` staging/copy patterns, and
  this ledger/requirements disposition.
- **R-S11d-7 — Windows MSI firewall custom-action completion authority — CLOSED 2026-07-10.** Platform:
  Windows MSI deferred non-impersonated install/uninstall custom actions. Endpoint/action:
  `AddFirewallRules` and `RemoveFirewallRules` modifying Windows Firewall policy for the installed RustDesk
  executable. Boundary: privileged firewall policy ↔ MSI install/uninstall completion state. Attack surface
  closed: the actions no longer continue after firewall COM/policy/add/remove failure and no longer discard
  helper results. WiX declares both actions `Return="check"`; the custom-action entry validates the mode byte and
  non-empty executable path, derives the rule name with string-copy rather than format-string copy, propagates
  the helper `HRESULT`, and fails MSI on helper failure. The helper returns `HRESULT`, removes existing same-name
  rules before add, requires both inbound and outbound rule creation to succeed, best-effort removes partial state
  before returning an add failure, and removes rules by bounded `Item`/`Remove` loops until absence is proven.
  Already-absent rules are successful no-ops; COM/policy/query/remove failures are fatal. Verification closure:
  `scripts/verify.sh` asserts checked WiX returns, HRESULT helper signatures and propagation, invalid
  CustomActionData rejection, absence of format-string copies and discarded helper results, bounded
  remove-until-absent semantics, absent-rule no-op HRESULTs, and this ledger/requirements disposition.
- **R-S11d-8 — Windows RDP viewer credential command provenance — CLOSED 2026-07-10.** Platform: Windows
  viewer-side RDP tunnel convenience. Endpoint/action: launching `mstsc.exe` to connect to the loopback tunnel
  and temporarily seeding the current user's Windows Credential Manager entry for `TERMSRV/localhost`. Boundary:
  same-user viewer credential handling and local command provenance, not a service/SYSTEM escalation path. Attack
  surface closed: the RDP helper no longer resolves `cmdkey` or `mstsc` through the caller's current directory or
  PATH, no longer passes the saved RDP password through `cmdkey /pass:` argv, and no longer moves RDP credentials
  through process-global environment variables. It binds `mstsc.exe` through the checked `GetSystemDirectoryW`
  resolver, writes the temporary credential with native `CredWriteW` only when both username and password are
  present, snapshots any pre-existing `TERMSRV/localhost` generic credential with `CredReadW`, serializes
  in-process seeded launches with a credential lease, prompts `mstsc` when no complete credential was seeded, and
  restores the previous credential state or deletes the temporary credential after `mstsc` exits or if launch
  fails. Verification closure: `scripts/verify.sh` asserts trusted `mstsc` resolution, absence of `cmdkey` and
  bare RDP command launch, absence of password argv/env plumbing, native `CredReadW`/`CredWriteW`/`CredDeleteW`
  use, session-scoped generic credential policy, lease/drop restoration, prompt fallback, and this
  ledger/requirements disposition.
- **R-S11d-9 — Windows terminal default-shell command provenance — CLOSED 2026-07-10.** Platform:
  Windows terminal helper and direct terminal service. Endpoint/action: opening the default shell for an
  authenticated terminal session. Boundary: remote-triggered only after Terminal authorization; installed-service
  mode launches the helper and shell as the current logon user rather than SYSTEM, and direct mode uses the
  process owner. Attack surface closed: default shell selection no longer accepts a current-directory
  `pwsh.exe`, no longer reads `COMSPEC`, and no longer falls back to a bare `cmd.exe`. Windows shell selection is
  fallible, resolves `%SystemRoot%\System32` with `GetSystemDirectoryW`, tries only absolute PowerShell Core
  locations and `System32` Windows PowerShell / `cmd.exe`, and fails the terminal-open path if no trusted shell is
  present. Verification closure: `scripts/verify.sh` asserts fallible shell selection, `GetSystemDirectoryW`
  use, the absolute trusted candidate set, fail-closed propagation in both helper and direct terminal paths,
  absence of `COMSPEC`/bare `pwsh.exe`/bare `cmd.exe` fallback, and this ledger/requirements disposition.
- **R-S11d-10 — Windows portable RuntimeBroker cleanup command provenance — CLOSED 2026-07-10.**
  Platform: Windows portable launcher/installer. Endpoint/action: best-effort termination of stale
  `RuntimeBroker_rustdesk.exe` before copying the runtime broker payload. Boundary: local same-user portable
  launch/install flow; if a user deliberately starts the portable installer elevated, the launched cleanup tool
  inherits that approved local elevation, but the action is not remote-triggered and not service-owned. Attack
  surface closed: the portable launcher no longer starts `taskkill` through current-directory/PATH search.
  `taskkill.exe` is resolved from `GetSystemDirectoryW`, checked as a file, and used without any ambient fallback.
  Cleanup remains best-effort because an absent stale broker process is an acceptable state; spawn-resolution
  errors are reported rather than hidden. Verification closure: `scripts/verify.sh` asserts trusted
  `taskkill.exe` resolution, `GetSystemDirectoryW` use, absence of bare taskkill launch, reported spawn errors,
  and this ledger/requirements disposition.
- **R-S11d-11 — Windows unsupported 32-bit WMIC process-probe deletion — CLOSED 2026-07-10.**
  Platform: unsupported Windows non-x64 source branches. Endpoint/action: process command-line probes used by
  `check_process` and the shared platform process helpers. Boundary: release matrix is Windows x86_64; the
  32-bit Windows branch was inherited dead compatibility code, not a shipped artifact path. Attack surface
  closed: the fork no longer retains a WMIC fallback that launches `wmic.exe`, parses command-line output, or
  keeps a non-x64 process-probe detour for Windows. Non-mobile process probes use the existing structured
  `sysinfo` enumeration path only. Verification closure: `scripts/verify.sh` rejects any reintroduced WMIC
  helper, `by_wmic` helper, `get_pids_with_first_arg_check_session` helper, or Windows non-64-bit process-probe
  cfg detour in `src/common.rs` / `src/platform`, and asserts this ledger/requirements disposition.
- **R-S11d-12 — Windows privacy broker and user shortcut process provenance — CLOSED 2026-07-10.**
  Platform: Windows desktop. Endpoint/action: privacy-mode broker launch and user-created Desktop connection
  shortcuts. Boundary: authenticated privacy-mode request / local same-user UI action ↔ process creation and
  shortcut persistence. Attack surface closed: privacy mode no longer asks `CreateProcessAsUserW` to infer the
  executable from a command-line string; the broker path is verified as a file, passed as explicit
  `lpApplicationName`, launched with a null command line, and given the broker directory as current directory.
  The user shortcut path no longer writes per-shortcut VBScript or launches `cscript`; it validates the direct
  connect id and creates the shell link through native COM `IShellLinkW` / `IPersistFile` under the current
  user's Desktop known folder. Verification closure: `scripts/verify.sh` asserts explicit broker
  application-name launch, broker file checks, absence of `cmd_utf16`, native ShellLink shortcut creation,
  direct-id validation, Desktop known-folder use, absence of script-backed shortcut code in `create_shortcut`,
  and this ledger/requirements disposition.
- **R-S11d-13 — Windows service and session-token process launch provenance — CLOSED 2026-07-10.**
  Platform: Windows installed service and desktop session handoff. Endpoint/action: service-owned `--server`
  launch plus token-switched `--tray`, connection-manager, whiteboard, and `run_exe_in_session` launches.
  Boundary: LocalSystem/root Windows service or elevated process ↔ target session process creation through
  `CreateProcessAsUserW`. Attack surface closed: the launcher no longer passes only a mutable command-line
  string while leaving `lpApplicationName` null. The Rust FFI now passes an explicit application path and a
  separately quoted command line; the C++ side requires both, copies the command line into a dynamically sized
  mutable buffer, and calls `CreateProcessAsUserW` with the explicit application path. Token-switched Rust
  launches require an absolute existing executable file, reject NUL-bearing application, argv, and environment
  data, use Windows command-line quoting for argv, and reuse the same provenance helper for service-owned
  `--server` and user-session helper launches. The old preformatted command-string wrapper is deleted.
  Verification closure: `scripts/verify.sh` asserts the explicit application-name FFI shape, absence of
  null-application `CreateProcessAsUserW` and fixed `MAX_PATH` command buffers, absolute-file validation,
  quoted argv construction, service-owned `--server` launch through the helper, user-session launch reuse of
  the helper, removal of the obsolete wrapper, and this ledger/requirements disposition.
- **R-S11d-14 — Windows service/session token source provenance — CLOSED 2026-07-10.**
  Platform: Windows installed service and desktop session handoff. Endpoint/action: resolving the token used
  by `CreateProcessAsUserW` for service-owned `--server` and user-session helper launches. Boundary:
  LocalSystem service ↔ session token authority. Attack surface closed: the service no longer turns the first
  same-session process whose basename is `explorer.exe`, `sihost.exe`, or `winlogon.exe` into launch authority.
  User-session launches use `WTSQueryUserToken` for the target session's logged-on user token. Service-owned
  SYSTEM launches accept only a same-session `winlogon.exe` whose full image path is the trusted
  `%SystemRoot%\System32\winlogon.exe`, whose token belongs to LocalSystem, and whose token session matches the
  target session. This path now requests only the documented token/process rights needed for query and
  `CreateProcessAsUserW` instead of `PROCESS_ALL_ACCESS` / `TOKEN_ALL_ACCESS`. The obsolete user-process
  fallback and Explorer-name error suppression are deleted. Verification closure: `scripts/verify.sh` asserts
  `WTSQueryUserToken`, trusted System32 `winlogon.exe` image validation, LocalSystem SID validation,
  token-session validation, minimum handle rights, absence of Explorer/sihost token fallbacks, absence of the
  old all-access token source, and this ledger/requirements disposition.
- **R-S11d-15 — Windows EXE elevated batch completion accounting — CLOSED 2026-07-10.**
  Platform: Windows EXE install/uninstall/service-install elevated command path. Endpoint/action:
  `run_cmds` launching generated `.bat` files through UAC-elevated `System32\cmd.exe`, plus the
  `install_service` / `uninstall_service` wrappers that report service-lifecycle result status. Boundary:
  unelevated caller ↔ elevated installer command completion. Attack surface closed: the elevated wrapper no
  longer treats a successfully spawned `cmd.exe` as proof of successful privileged state change. The `.undone`
  completion marker is now created as a mandatory precondition; after the elevated command exits, `run_cmds`
  requires both `ExitStatus::success()` and removal of the completion marker. A leftover marker is deleted
  before returning failure. `install_service` and `uninstall_service` now return `false` when the elevated
  command fails instead of logging the error and reporting success. Verification closure: `scripts/verify.sh`
  asserts mandatory marker creation, elevated exit-status success checking, marker-state checking, absence of
  the old ignored-status shape, service install/uninstall failure reporting, and this ledger/requirements
  disposition.
- **R-S11d-18 — Windows EXE elevated batch cmd-state hardening — CLOSED 2026-07-10.**
  Platform: Windows EXE install/uninstall/service-install/service-uninstall elevated command runner.
  Endpoint/action: `run_cmds` writing generated `.bat` and completion-marker files, then executing the batch
  through elevated `System32\cmd.exe`. Boundary: medium-integrity caller environment, temp path, and HKCU
  Command Processor state ↔ elevated installer command execution. Attack surface closed: the runner no longer
  lets HKCU Command Processor `AutoRun` participate in elevated command startup, and generated batch/marker
  path text no longer enters `cmd.exe` with expansion-sensitive characters. `run_cmds` invokes trusted
  `cmd.exe` with `/D /V:OFF /S /C`; generated batch and marker paths are accepted only after rejecting quotes,
  `%`, `!`, shell metacharacters, CR/LF, and control characters; command-file creation tries only validated
  candidate directories, in order: caller temp, the ProgramData known folder, and the existing user-accessible
  folder, continuing to the next safe candidate when creation fails. Completion-marker deletion is quoted
  through the same safe path guard.
  Verification closure: `scripts/verify.sh` asserts the ProgramData fallback, fallible installer command
  directory candidate list, literal/path guards, rejected expansion/metacharacter set, safe temp/ProgramData/
  user-accessible checks, create-error tracking, marker quoting, `/D /V:OFF /S /C` command invocation on both
  already-elevated and UAC `runas` paths, absence of the old bare `/C` invocation shape, and this
  ledger/requirements disposition. Separate Windows findings not closed by this item were tracked separately:
  R-S11d-19 closes env-expanded uninstall cleanup roots, R-S11d-20 closes elevated batch command
  postconditions, and R-S11d-21 closes the MSI `CC_CONNECTION_TYPE` public-property service-mode gate.
- **R-S11d-19 — Windows EXE uninstall cleanup known-folder authority — CLOSED 2026-07-10.**
  Platform: Windows EXE uninstall and service-uninstall elevated command paths. Endpoint/action: cleanup of
  all-users Start Menu, Public Desktop, and Common Startup shortcuts/directories after uninstall or service
  removal. Boundary: caller/elevated process environment ↔ protected all-users shell folders. Attack surface
  closed: elevated cleanup no longer expands `%ProgramData%`, `%PROGRAMDATA%`, or `%PUBLIC%` inside the batch
  body to decide which protected shell-folder paths to delete. The stale start-menu field was removed from
  `get_install_info`; install, uninstall, service install, and service uninstall now share fallible
  `SHGetKnownFolderPath` helpers for Public Desktop, Common Programs, and Common Startup. `get_uninstall` is
  fallible, guards the installed path as batch-literal text, quotes known-folder cleanup targets through the
  same elevated batch path guard, and propagates known-folder/quoting failures to callers. `uninstall_service`
  resolves and quotes the Common Startup tray shortcut before composing the elevated command and returns
  `false` on failure. Verification closure: `scripts/verify.sh` asserts the narrowed `get_install_info` tuple,
  fallible uninstall builder/callers, installed-path literal guard, known-folder quoted cleanup paths, service
  uninstall known-folder cleanup, absence of `%ProgramData%` / `%PROGRAMDATA%` / `%PUBLIC%` roots in
  `src/platform/windows.rs`, and this ledger/requirements disposition. Separate Windows findings not closed by
  this item are tracked separately: R-S11d-20 closes elevated batch command postconditions, and R-S11d-21 closes
  the MSI `CC_CONNECTION_TYPE` public-property service-mode gate.
- **R-S11d-20 — Windows EXE elevated batch command postconditions — CLOSED 2026-07-10.**
  Platform: Windows EXE install, update-broker, uninstall, service-install, and service-uninstall elevated
  batch bodies. Endpoint/action: generated `.bat` fragments that copy binaries, create install directories,
  write HKLM/HKCR registry state, add/remove firewall rules, create/delete the service, create/delete all-users
  shortcuts, and delegate to a prior MSI uninstall. Boundary: approved elevated installer command stream ↔
  privileged persistent Windows state. Attack surface closed: required elevated operations no longer fall
  through to marker deletion after an ignored command failure, and cleanup operations that are allowed to be
  absent now verify the target is absent before reporting success. Required install/update operations are routed
  through fail-fast helpers: broker and install payload copies verify their destination files, `xcopy` no longer
  carries `/C`, install-directory creation verifies the directory exists, registry and firewall additions are
  checked for command failure, shortcut scripts verify the final `.lnk` exists, and service creation/failure/start
  retains checked `sc` exit handling. Uninstall cleanup now uses absence-driven helpers for service deletion,
  HKCR/HKLM key deletion, firewall rule deletion, install-directory removal, Start Menu removal, Public Desktop
  shortcut removal, and Common Startup tray-shortcut removal. Prior MSI uninstall delegation is reconstructed by
  R-S11d-35 before it enters the batch, then observes `msiexec` exit status, accepting only success,
  reboot-required `3010`, and product-absent `1605`. R-S11d-21 separately closes the MSI `CC_CONNECTION_TYPE`
  public-property service-mode gate, R-S11d-22 separately closes EXE certificate-cleanup completion, and R-S11d-23
  separately closes EXE Amyuni IDD cleanup completion. The MSI Amyuni cleanup authority is R-S11d-2/R-S11d-7.
  Verification closure: `scripts/verify.sh` asserts the fail-fast and absence-postcondition helpers, checked
  copy/update/install call sites, removal of `xcopy /C`, install directory and shortcut existence postconditions,
  service/registry/firewall absence checks, reconstructed MSI uninstall exit handling, absence of the raw
  uninstall-string fallback and raw install-dir create/service-delete/uninstall-registry-delete leftovers, and this
  ledger/requirements disposition.
- **R-S11d-21 — Windows MSI service-mode package authority — CLOSED 2026-07-10.**
  Platform: Windows MSI install/repair/upgrade. Endpoint/action: package-time service creation/start, tray launch,
  and startup tray shortcut installation. Boundary: MSI public properties and transforms ↔ per-machine LocalSystem
  service presence. Attack surface closed: `CC_CONNECTION_TYPE` can no longer be generated by the custom-client
  preprocessor and can no longer suppress service/tray installation state. The MSI no longer has a public
  connection-type service-mode switch: the `--conn-type` preprocessor argument and `gen_conn_type` property writer
  are deleted, all `CC_CONNECTION_TYPE` package conditions are deleted, and the service/tray conditions now follow
  the package's pinned service policy. Verification closure: `scripts/verify.sh` rejects `CC_CONNECTION_TYPE`,
  `--conn-type`, `conn_type`, and `gen_conn_type` under `res/msi`, asserts the service/tray/startup shortcut
  conditions without a connection-type branch, and pins this ledger/requirements disposition.
- **R-S11d-22 — Windows EXE certificate cleanup completion authority — CLOSED 2026-07-10.**
  Platform: Windows EXE uninstall. Endpoint/action: elevated uninstall batch invoking `--uninstall-cert`, the
  Rust `uninstall_cert()` FFI wrapper, and `windows_delete_test_cert.cc` deleting the fixed WDK test-certificate
  thumbprint plus the historical malformed ROOT store. Boundary: elevated uninstall completion ↔ persistent
  Windows certificate trust state. Attack surface closed: certificate cleanup can no longer fail or be skipped
  while EXE uninstall reports success. `get_uninstall` now fails if the current executable cannot be resolved and
  wraps `--uninstall-cert` with the fail-fast batch helper; the CLI arm logs cleanup errors and exits nonzero; the
  Rust FFI wrapper treats a false native result as an error; and the native helper returns `BOOL` after checking
  every registry operation it owns. The native helper also removes the stale `readResult` branch that prevented the
  certificate Blob read from authorizing deletion, deletes only the fixed thumbprint after a bounded WDK-test-cert
  suffix match, preserves malformed-ROOT-store cleanup through an explicit wide prefix, and opens store keys with
  read-scoped access rather than `KEY_ALL_ACCESS`. Verification closure: `scripts/verify.sh` asserts the native
  `BOOL` contract, Rust status propagation, nonzero CLI exit on failure, checked uninstall batch command, fatal
  current-exe resolution, checked Blob read, bounded Blob match, explicit malformed-store prefix, absence of the
  old void-return/read-result/ignored-error/all-access shapes, and this ledger/requirements disposition.
- **R-S11d-23 — Windows EXE Amyuni IDD cleanup completion authority — CLOSED 2026-07-10.**
  Platform: Windows EXE uninstall and runtime AMD64 Amyuni helper launch. Endpoint/action: elevated uninstall batch
  invoking `--uninstall-amyuni-idd`, the top-level `--uninstall` dispatcher, the Rust
  `amyuni_idd::uninstall_driver()` CLI arm, and runtime `deviceinstaller64.exe` install/remove fallback. Boundary:
  elevated uninstall/install completion ↔ persistent Amyuni virtual-display driver state and helper execution.
  Attack surface closed: EXE uninstall can no longer skip or hide Amyuni cleanup failure while reporting success.
  `get_uninstall` resolves the current executable once for EXE uninstall helpers, treats that failure as fatal, quotes
  the helper command through the elevated-batch path guard, and wraps `--uninstall-amyuni-idd` in the fail-fast
  command helper. The top-level `--uninstall` dispatcher exits nonzero when `uninstall_me()` fails, and the
  `--uninstall-amyuni-idd` CLI arm logs cleanup errors and exits nonzero. The AMD64 runtime helper no longer uses
  `ShellExecuteW` fire-and-forget; it builds a quoted mutable command line, starts the checked absolute
  `deviceinstaller64.exe` path with `CreateProcessW`, waits with the same two-minute bound used by MSI, reads the
  child exit code, accepts `ERROR_SUCCESS_REBOOT_REQUIRED` only for remove/cleanup, rejects reboot-required on
  install/update before trying to use the driver, and propagates launch/wait/exit-code failures. Optional helper
  payload absence before selecting the helper remains a no-op; selected native/helper cleanup failure does not.
  Verification closure: `scripts/verify.sh` asserts checked elevated-batch command construction, fatal shared
  `current_exe` resolution, top-level and helper CLI nonzero exits, explicit helper command-line ownership,
  `CreateProcessW` application-path binding, bounded wait, exit-code read, remove-vs-install reboot policy, absence
  of the old skipped-command helper, absence of `ShellExecuteW` in the runtime helper, and this ledger/requirements
  disposition.
- **R-S11d-24 — Windows stale RustDesk IDD install helper completion — CLOSED 2026-07-10.**
  Platform: Windows raw CLI. Endpoint/action: `--install-idd`, the RustDesk IDD
  `rustdesk_idd::install_update_driver()` helper, and the active virtual-display implementation selector. Boundary:
  local CLI exit status ↔ persistent display-driver install/update state. Attack surface closed: a stale public CLI
  can no longer invoke the inactive RustDesk IDD installer, mask install/update failure with `allow_err!`, and report
  success in a build whose active virtual-display implementation is Amyuni. The fork's supported virtual-display
  driver install/update path remains the Amyuni runtime path, which is checked by R-S11d-23: helper launch is bound to
  the checked executable path, waited, exit-code checked, and rejects reboot-required install before the driver is
  used. The raw `--install-idd` arm is now reject-only: it logs that the command is unsupported in this build and
  exits nonzero without touching driver state. Verification closure: `scripts/verify.sh` asserts the reject-only
  `--install-idd` arm, nonzero exit, absence of `allow_err!` and `rustdesk_idd::install_update_driver()` from that
  arm, the active `IDD_IMPL_AMYUNI` selector, and this ledger/requirements disposition.
- **R-S11d-25 — Windows Amyuni SetupAPI install reboot-required completion — CLOSED 2026-07-10.**
  Platform: Windows runtime Amyuni virtual-display driver install fallback. Endpoint/action: direct SetupAPI
  `win_device::install_driver()` path used when the AMD64 `deviceinstaller64.exe` helper is unavailable. Boundary:
  driver install/update completion ↔ immediate virtual-display use. Attack surface closed: direct SetupAPI install
  can no longer report success when `UpdateDriverForPlugAndPlayDevicesW` sets `reboot_required`, because that state
  means the driver cannot be treated as immediately usable. The fallback now follows the same install/update policy
  as the checked helper path from R-S11d-23: reboot-required install fails closed before `check_install_driver()`
  returns and before monitor plug-in proceeds. Remove/cleanup reboot-required remains accepted under the cleanup
  policy; this entry is only the install/update fallback. Verification closure: `scripts/verify.sh` asserts the
  direct SetupAPI install call, the `reboot_required` branch, fatal install reboot-required error, absence of the old
  discarded install result shape, and this ledger/requirements disposition.
- **R-S11d-26 — Windows app-name identity contract — CLOSED 2026-07-11.** Platform: Windows
  signed custom-client runtime config and MSI packaging. Endpoint/action: custom `app-name` reaching executable
  names, install paths, URI scheme, service name, HKCR/HKLM registry keys, firewall rule labels, shortcuts, and
  elevated EXE batch text. Boundary: signed/build-time branding input ↔ privileged Windows system identifiers.
  Attack surface closed: `app-name` is no longer accepted as arbitrary display text. Signed custom-client parsing
  now rejects non-string or invalid `app-name` before applying any payload settings, and MSI preprocessing rejects
  invalid `--app-name` before generating package resources. The contract is a 1-64 byte ASCII identifier: first
  character letter, last character letter or digit, and only letters/digits/hyphen in between. Verification
  closure: `scripts/verify.sh` asserts the Rust validator and unit test, the guarded signed-config `APP_NAME`
  assignment, the MSI regex/front-door check, and this ledger/requirements disposition.
- **R-S11d-27 — Windows custom-client public staging deletion — CLOSED 2026-07-11.** Platform:
  Windows custom-client update residue. Endpoint/action: dormant `custom.txt` staging from a public-style
  `RustDeskCustomClientStaging` directory into the current executable directory, followed by runtime custom-client
  loading. Boundary: mutable public filesystem mailbox ↔ installed executable directory and signed custom-client
  identity/policy. Attack surface closed: the public staging bridge is deleted rather than hardened or retained as
  compatibility code. The cluster had no live caller in current source, generated bindings, scripts, packaging,
  tests, or docs; normal custom-client loading remains the signed runtime/build input path from `load_custom_client`
  and `read_custom_client`. `get_public_base_dir`, `get_custom_client_staging_dir`,
  `remove_custom_client_staging_dir`, `prepare_custom_client_update`, the `RustDeskCustomClientStaging` literal, and
  the executable-directory `custom.txt` copy/load sink are absent from `src/platform/windows.rs`. Verification
  closure: `scripts/verify.sh` rejects reintroduced staging symbols, the staging directory name, the executable-dir
  copy sink, and requires this ledger/requirements disposition.
- **R-S11d-28 — Windows dormant diagnostic message-box deletion — CLOSED 2026-07-11.** Platform:
  Windows runtime diagnostic residue. Endpoint/action: unused Rust `my_println!` macro and its Windows-only
  `message_box` helper. Boundary: dormant diagnostic text path ↔ environment-selected file/clipboard/UI side
  effects in privileged-capable Windows processes. Attack surface closed: the unused macro and helper are deleted
  rather than retained with environment switches. The helper had no live caller and was not an exported FFI,
  generated Flutter bridge, or cross-platform platform-trait requirement, but it still read `NO_DIALOG`,
  `PRINT_OUT`, and `WRITE_TO_FILE`, could write diagnostic text to an environment-selected path, could suppress the
  dialog, and wrote to the clipboard while discarding errors. The peer protocol/UI `MessageBox` flow is unrelated
  and remains intact. Verification closure: `scripts/verify.sh` rejects `my_println!`, `macro_rules! my_println`,
  the Windows `message_box` helper, the diagnostic environment knobs, and the old diagnostic strings, and requires
  this ledger/requirements disposition.
- **R-S11d-29 — Windows service-adjacent path known-folder authority — CLOSED 2026-07-11.** Platform:
  Windows runtime/service-adjacent path selection. Endpoint/action: active-user home fallback, root recording
  directory selection, and installer command-file user-accessible fallback directory. Boundary: Windows system/profile
  root authority ↔ process environment text. Attack surface closed: profile, ProgramData, and Windows Temp roots no
  longer derive from `SystemDrive`. This was not a proven current unprivileged-to-SYSTEM primitive: recording is local
  session-recording state, active-user home is a UI fallback, and installer command files were already literal-guarded
  before creation. The corrected authority model is still stricter: privileged-capable code resolves these roots
  through `SHGetKnownFolderPath`. Active-user home now uses `FOLDERID_UserProfiles` plus a single-component username
  guard before joining; root recording uses the shared `FOLDERID_ProgramData` helper and fails closed with a logged
  error if resolution fails; installer command fallback uses `FOLDERID_ProgramData` and `FOLDERID_Windows\\Temp`,
  not `SystemDrive` strings. Verification closure: `scripts/verify.sh` rejects `SystemDrive` in the affected Windows
  sources, asserts the `FOLDERID_UserProfiles` and `FOLDERID_Windows` helpers, the username component/control guard,
  the root-recording ProgramData known-folder path, the Windows Temp known-folder fallback, and this
  ledger/requirements disposition.
- **R-S11d-30 — Windows elevated post-install relaunch executable authority — CLOSED 2026-07-11.** Platform:
  Windows EXE install, service install, and service uninstall paths. Endpoint/action: post-elevated GUI/tray
  relaunch after privileged batch completion. Boundary: elevated installer/service-management process ↔ child
  executable authority. Attack surface closed: the post-elevated relaunch helper no longer chooses its executable
  by calling `get_install_info()`, whose compatibility behavior prefers legacy uninstall registry keys before
  the current app key. Normal install passes the fixed Program Files executable already chosen by `install_me`;
  service install and service uninstall resolve the same `fixed_service_install_dir_and_exe()` executable before
  running their elevated batches. The helper revalidates that the passed executable exactly matches the fixed
  Program Files service executable, requires it to exist as a file, and propagates GUI/tray spawn errors instead
  of hiding them behind `allow_err!`. Legacy uninstall registry metadata may remain compatibility/read-only
  install state, but it no longer selects any elevated post-install child process. Verification closure:
  `scripts/verify.sh` asserts the new helper shape, all three fixed-executable call sites, the fixed-root recheck,
  file-existence check, absence of `get_install_info()` in the helper body, absence of the old
  `run_after_run_cmds` helper, and this requirements/ledger disposition.
- **R-S11d-31 — Windows privacy broker served-session authority — CLOSED 2026-07-11.** Platform:
  Windows installed service with privacy mode, especially RDP/ICA session-sharing hosts. Endpoint/action:
  topmost-window privacy broker launch of `RuntimeBroker_rustdesk.exe` and `WindowInjection.dll` injection.
  Boundary: service-owned `--server` process serving an authenticated Remote session ↔ per-session user-token
  broker process. Attack surface closed: the broker launch no longer uses `WTSGetActiveConsoleSessionId()`,
  which selects the physical console session and can differ from the session currently served by the installed
  service when `share_rdp` allows RDP/ICA sessions. The broker now resolves the current process session id of
  the service-owned server that is handling the Remote session, rejects unavailable or invalid session ids,
  obtains the user token for that served session, and launches the checked broker executable there with the
  existing explicit `lpApplicationName`, null command line, checked current directory, and checked broker/DLL
  files. Verification closure: `scripts/verify.sh` asserts the served-session helper, current-process-session
  lookup, launch-site use of that helper, session-specific token error, absence of `WTSGetActiveConsoleSessionId`
  from the privacy broker source, and this requirements/ledger disposition.
- **R-S11d-32 — Windows elevated command-file reopen identity — CLOSED 2026-07-11.** Platform:
  Windows EXE install, uninstall, service install, and service uninstall elevated command files. Endpoint/action:
  generated `.bat` and `.vbs` command files handed to elevated `System32\cmd.exe` / `cscript.exe`. Boundary:
  medium-integrity same-owner command-file directory state ↔ elevated installer command execution. Attack surface
  closed: the command-file read lock is no longer trusted after a naked pathname reopen. Before the write handle is
  dropped, `src/platform/windows.rs` now records `GetFileInformationByHandle` volume/file-index identity and a
  SHA-256 digest of the exact bytes written. The path is then reopened read-only with `FILE_SHARE_READ`, and the
  reopened handle must match both the original identity and the original byte length/digest before elevation
  proceeds. Replacement or in-place modification during the close/reopen gap fails closed; after verification, the
  existing read handle remains live for the command lifetime and continues to deny write/delete sharing. Verification
  closure: `scripts/verify.sh` asserts the identity query helper, digest helper, verified reopen helper, write-handle
  identity capture, reopened read-lock wiring, identity/content drift failures, regression tests, and this
  requirements/ledger disposition.
- **R-S11d-33 — Windows MSI deferred install-root provenance — CLOSED 2026-07-11.** Platform:
  Windows MSI deferred no-impersonation custom actions. Endpoint/action: LocalSystem service creation,
  runtime-generated broker cleanup, and Amyuni IDD fallback helper execution. Boundary: MSI execution script
  `CustomActionData` and directory resolution ↔ LocalSystem service/helper authority. Attack surface closed: the
  package-level private `App.InstallFolder` proof is no longer the only check before the deferred DLL consumes
  privileged install-root state. `res/msi/CustomActions/CustomActions.cpp` now normalizes deferred install folders,
  rejects empty/relative/root/path-too-long values, requires the install directory to be an immediate child of
  `FOLDERID_ProgramFiles` or `FOLDERID_ProgramFilesX86`, requires the Program Files parent and any existing install
  directory to be non-reparse directories, and uses the normalized install folder for runtime broker cleanup and
  Amyuni fallback path construction. The Amyuni fallback now builds `usbmmidd_v2` with an explicit separator and
  requires both the helper directory and `deviceinstaller64.exe` to exist as non-reparse objects before
  `CreateProcessW`. `CreateStartService` now fails malformed service `CustomActionData` instead of reporting
  success, requires a constrained service identifier, parses only the exact quoted executable plus `--service`
  command shape, validates the executable as the matching service binary under the trusted MSI install folder,
  requires the service executable to exist and not be a reparse point, and passes a normalized command to
  `CreateServiceW`. This is privileged-state correctness hardening, not a newly proven low-privilege LPE in the
  current MSI: the package already keeps `App.InstallFolder` private under `ProgramFiles6432Folder` with no browse
  surface. Verification closure: `scripts/verify.sh` gates the Program Files directory declaration, absence of
  directory-setter UI/actions, native install-root validator, malformed service-data fatal path, service identifier
  and command validators, normalized service creation command, normalized runtime cleanup root, non-reparse Amyuni
  helper proof, and this ledger/requirements disposition.
- **R-S11d-34 — Windows MSI deferred firewall/service target provenance — CLOSED 2026-07-11.** Platform:
  Windows MSI deferred no-impersonation custom actions. Endpoint/action: LocalSystem firewall policy updates,
  service stop/delete, and post-delete process cleanup. Boundary: MSI execution-script `CustomActionData` ↔
  firewall/service/process-control authority. Attack surface closed: the remaining deferred custom-action targets
  are no longer accepted as raw path/name authority after R-S11d-33. `AddFirewallRules` and `RemoveFirewallRules`
  now normalize their executable path, require the path to sit under the trusted Program Files MSI install-folder
  shape, require a constrained `.exe` rule identity, require the executable to exist for add, and pass the
  normalized path into the firewall COM helper. `TryStopDeleteService.SetParam` now carries the same quoted
  `<exe> --service` command shape used by service creation. The native action validates the service identifier,
  normalizes the package executable under the trusted install folder, opens the service with query/stop/delete
  rights, proves the installed service `ImagePath` normalizes to the same trusted command before any stop/delete,
  performs stop/delete through that validated handle, verifies deletion by service absence, and only then runs
  leftover process cleanup by exact normalized image path instead of executable name alone. This remains
  privileged-state correctness hardening rather than a newly proven ordinary-user LPE in the current package: the
  MSI authoring already derives these values from private package state, but the LocalSystem DLL now rejects
  malformed or target-shifted execution-script data itself. Verification closure: `scripts/verify.sh` gates the
  product-executable validator, firewall normalized-path call, service-delete binary proof in WiX, live
  service-config proof, handle-bound trusted delete helper, image-path-bound process cleanup, absence of the old
  raw firewall helper path, absence of name-only service-delete cleanup, and this ledger/requirements disposition.
- **R-S11d-35 — Windows EXE prior-MSI uninstall command reconstruction — CLOSED 2026-07-11.** Platform:
  Windows EXE install/upgrade over an existing MSI install. Endpoint/action: `get_uninstall` delegating the prior
  MSI removal before the elevated EXE install batch writes new Program Files/HKLM/service state. Boundary: HKLM
  uninstall metadata from the previous install ↔ approved elevated batch command text. Attack surface closed:
  prior `UninstallString` values containing `msiexec.exe` are no longer spliced into the elevated batch after a
  prefix bind, and there is no raw fallback when binding fails. `src/platform/windows.rs` now accepts only a
  `msiexec.exe /X {PRODUCT-CODE}`-class command shape, validates the braced GUID grammar, rejects unsupported
  arguments and duplicate product codes, proves the product name with `MsiGetProductInfoW(...,
  INSTALLPROPERTY_PRODUCTNAME, ...)`, requires it to match `crate::get_app_name()`, and reconstructs
  `"<System32>\\msiexec.exe" /X {PRODUCT-CODE}` from the trusted tool path. The prior registry string contributes
  only the product code after validation; it contributes no shell metacharacters, extra argv, alternate executable,
  or command tail. Verification closure: `scripts/verify.sh` gates the Windows Installer API feature, product-code
  parser, GUID validator, product-name proof, command reconstruction, absence of the prefix-only binder, absence of
  the raw `checked_msi_uninstall_command(reg_uninstall_string)` fallback, and this requirements/ledger disposition.
- **R-S11d-16 — Windows MSI service-state and SAS policy persistence — CLOSED 2026-07-10.**
  Platform: Windows MSI install/upgrade/uninstall and runtime Ctrl+Alt+Del. Endpoint/action: per-machine
  LocalSystem service creation/start and HKLM `SoftwareSASGeneration` handling. Boundary: installing user's
  profile/config and installer UI properties ↔ per-machine service presence and machine policy. Attack surface
  closed: MSI no longer reads `[AppDataFolder]...\config\...\toml` or any `stop-service` property to decide
  whether to create/start the service. The MSI service path now follows the fork's pinned runtime policy:
  create/start the per-machine service on install/repair/upgrade, and scope stop/delete to uninstall or upgrade
  cleanup. The obsolete `STOP_SERVICE`, `SetPropertyServiceStop`,
  `SetPropertyFromConfig`, `SetPropertyIsServiceRunning`, `TryDeleteStartupShortcut`, and `ReadConfig` custom
  action surfaces are deleted. Persistent installer writes to `SoftwareSASGeneration` are deleted from both MSI
  and EXE installer paths; no uninstall-time blind delete is added because prior installers did not record
  ownership or the original machine-policy value. Runtime SAS is the sole remaining `SoftwareSASGeneration`
  mutation path: it serializes local policy mutation, accepts only the documented policy values, distinguishes
  absent from present values, fails before `SendSAS` on open/read/set failure, preserves administrator value
  `0` as `0`, preserves the Ease of Access allowance by temporarily changing value `2` to `3`, restores or
  deletes after `SendSAS`, and returns an error if restoration fails. Verification closure:
  `scripts/verify.sh` asserts the MSI service conditions, scoped service stop/delete, absence of the deleted
  MSI service/SAS custom actions and config reader, absence of persistent installer SAS writes, the runtime
  original-policy state machine, serialized known-value-only temporary policy mutation, fail-closed
  read/set/restore handling, caller error propagation, and this ledger/requirements disposition.
- **R-S11d-17 — Windows portable installer source-staging authority — CLOSED 2026-07-10.**
  Platform: Windows self-extracting EXE installer. Endpoint/action: double-click `rustdesk-*install.exe`
  extraction and handoff into the installed-service EXE installer. Boundary: medium-integrity caller-writable
  portable staging vs elevated Program Files install source. Attack surface closed: the double-click and silent
  installer entry points no longer extract to `%LOCALAPPDATA%\rustdesk` and then let an elevated install copy
  that mutable same-user tree into Program Files. The packer relaunches itself with `ShellExecuteExW`/`runas`,
  waits for and checks the elevated child exit code, requires the internal install leg to be elevated, creates a
  private per-run staging directory under the width-correct Program Files root,
  rejects staging paths equal to or below the final install root, rejects reparse-point staging roots, validates
  embedded payload paths as relative Windows-safe components, treats decompression/create/write/sync failures as
  fatal, treats generated RuntimeBroker copy failure as fatal, and launches interactive and silent install
  operations only from the protected staging tree. The protected install UI is marked with
  `RUSTDESK_PROTECTED_INSTALL`, which hides and blocks the run-without-install escape; the app-side `install_me`
  sink requires that exact marker, an already elevated child process, a regular current executable, and a regular
  non-reparse `Program Files\RustDesk-staging-*` source directory whose parent is the width-correct Program Files
  root and whose path is outside the final install root before composing the privileged copy command. The copy
  command receives that verified source directory directly rather than deriving authority from an arbitrary
  `current_exe().parent()`, and interactive/silent child install failures exit nonzero for the waiting protected
  packer. `run_cmds` executes through trusted `cmd.exe` directly when the process is already elevated instead of
  prompting for a second elevation. Cleanup removes only manifest-known payload files plus the generated broker
  copy after verifying parent directories and targets are not reparse points, then removes empty payload directories
  and the staging root; post-extraction failures still attempt that manifest cleanup before returning.
  Verification closure: `scripts/verify.sh` asserts the protected relaunch, elevated child exit-code check,
  Program Files staging root, final-root overlap rejection, payload path validation, create-new/synced payload
  writes, protected install marker, app-side exact marker/elevation/source-directory proof at `install_me`,
  verified-source-directory copy construction, interactive and silent install routing, child install nonzero failure
  exits, run-without-install block, already-elevated command execution path, fatal RuntimeBroker source copy,
  manifest cleanup on success and failure paths, and this ledger/requirements disposition.

**Release-blocking items — closed:**
- **R-S11b-2 — installed-service unattended password ownership.** Platforms: Windows installed service,
  Linux installed service, macOS LaunchDaemon/source path. Android is app-UID/service-owned rather than
  root/SYSTEM, and non-installed/portable user-mode remains user-owned. Endpoints: any service-owned password
  provisioning operation, historical generic config permanent-password writes, CLI/FFI/UI password setters, and
  any whole-config IPC path that carries password storage/salt. Boundary: user-session process ↔ privileged
  unattended host. Attack surface: any unprivileged local caller path that can mint or replace the credential
  the privileged host later accepts remotely. Current state: the ordinary IPC password config-key write is absent
  from the data model and in-tree setters after R-S11b-2b/R-S11c-1b and R-S11b-3c; typed user-owned password writes
  are accepted only by user-owned receivers; service-marked receivers reject typed user-owned writes, the
  whole-config IPC variant is absent, and standalone salt read/storage-salt sync are denied by
  R-S11b-2a/R-S11c-1a. User-owned `--server` paths remain
  user-owned; R-S11e-7 binds their password capability query and password-bearing write to an authenticated
  same-UID current-executable `--server` receiver before any user-owned password value is sent. Linux
  installed-service provisioning is closed by R-S11b-2c/R-S11c-1d plus R-S11e-6:
  clients authenticate the connected root `--service` receiver before sending the service-owned password
  request, that request is the only enabled service-owned password path, polkit authorizes it, and the final
  commit is accepted only by a service-owned server from a root peer. Windows installed-service provisioning is closed by
  R-S11b-2d/R-S11c-1e: the `_service` request requires an elevated connected pipe-client token, and the final
  main-server commit is accepted only from a LocalSystem service peer. macOS installed-service provisioning is
  closed by R-S11b-2e/R-S11c-1f: the `_service` path authenticates the connected root helper, asks that helper to
  normalize the explicit non-shared timeout-zero RustDesk Authorization Services right before the UI obtains an
  external form, verifies that exact-definition external form noninteractively in the LaunchDaemon, writes the
  authorized value directly into the root LaunchDaemon credential
  store without a pending plaintext cache, rejects the old
  macOS main-server commit fallback, and serves that root credential to the service-owned LaunchAgent only as a
  launchd-owned runtime snapshot after socket audit-token installed-app code proof, exact live argv, and parsed
  root-owned plist command-shape proof; macOS `_service` clients also authenticate the connected server as the root
  trusted privileged helper with audit-token code identity before sending password-change or runtime-snapshot messages,
  and the snapshot cannot be persisted into user config.
- **R-S11e — Linux polkit policy/package assurance — CLOSED 2026-07-10.**
  Platform: Linux `.deb` installed-service mode. Endpoint/action: the single local admin-authorized
  service-owned unattended-password change. Boundary: user-session process and distro-local polkit policy
  state ↔ root service credential commit. Attack surface closed: no new credential mutation path is added;
  the existing R-S11b-2c `_service` request remains the only Linux service-owned password path, still using
  the SO_PEERCRED-derived peer process subject, `/usr/bin/pkcheck --action-id ... --process ... --allow-user-interaction`,
  and a root-service final commit into the service-owned main server. This slice closes the residual assurance
  gap around what the repo ships: `res/com.carriez.RustDesk.policy` is now structurally verified as exactly
  one action, `com.carriez.RustDesk.set-unattended-password`, with `allow_any`, `allow_inactive`, and
  `allow_active` all set to `auth_admin`, with no `yes`, `auth_self`, or keep-style authorizations. The
  repository is checked for matching shipped `.rules` overrides, `build.py` is checked to stage that policy
  in all Debian packaging paths, and the obsolete executable `usr/share/rustdesk/files/polkit` stub is rejected
  at both source and package-validation time. `scripts/build-debian.sh` validates every emitted `.deb` before
  hashing it by inspecting the packaged path, file type, root ownership, non-writable group/world mode, XML
  policy semantics, byte identity with the source policy, and absence of the legacy executable polkit stub.
  Distro-local administrator policy/rules overrides remain an environment fact outside app-side LPE; the package
  now proves the fork itself does not ship one.
  Verification closure: `scripts/verify-polkit-policy.py`, called from `scripts/verify.sh` and
  `scripts/build-debian.sh`, enforces the source and package invariants above, and `scripts/verify.sh`
  requires this ledger/requirements disposition.
- **R-S11e-1 — Linux pkcheck executable provenance — CLOSED 2026-07-11.**
  Platform: Linux `.deb` installed-service mode. Endpoint/action: the same local admin-authorized service-owned
  unattended-password change covered by R-S11e. Boundary: root service credential authority ↔ local polkit
  authorization checker executable. Attack surface closed: the root service no longer launches a raw
  `/usr/bin/pkcheck` string as the authority-bearing authorization helper. It resolves only the fixed absolute
  `PKCHECK_PATH`, rejects relative or parent-traversal path shapes, canonicalizes the selected path, requires both
  candidate and canonical parent directories to be root-owned and not group/world-writable, requires the canonical
  executable to be a root-owned regular file, not group/world-writable, and executable, and fails the service-owned
  password change closed if no trusted helper is present. This is correctness hardening rather than a confirmed LPE:
  replacing `/usr/bin/pkcheck` or its parent already implies root-equivalent local compromise on normal Debian/Ubuntu
  systems. Verification closure: `scripts/verify.sh` requires the trusted resolver, root/mode/executable checks, pure
  metadata/path regression tests, the requirements/ledger disposition, and absence of the old direct
  `Command::new("/usr/bin/pkcheck")` launch shape.
- **R-S11e-2 — macOS _service client-side server authentication — CLOSED 2026-07-11.**
  Platform: macOS installed-service mode. Endpoint/action: clients of the shared `_service` IPC socket, including
  the service-owned unattended-password authorized request and the LaunchAgent runtime password snapshot request. Boundary:
  installed app / service-owned LaunchAgent ↔ root privileged helper credential authority. Attack surface closed:
  `_service` clients no longer trust the socket path alone. A local same-user fake server that wins the
  `/tmp/<app>-service/ipc_service` race cannot receive the plaintext candidate password before authorization, and
  cannot feed attacker-chosen runtime password storage/salt to the service-owned LaunchAgent. `connect_with_path()`
  authenticates the macOS `POSTFIX_SERVICE` peer before any service protocol message is sent or read: peer uid must
  be root, the socket-bound `LOCAL_PEERTOKEN` must resolve through Security.framework to live peer code satisfying
  the pinned helper requirement with strict validation, and the resulting code path must be the trusted
  `/Library/PrivilegedHelperTools/com.carriez.rustdesk_service` helper with root:wheel ownership, non-writable
  helper directory/file, executable bit, no symlinks, and no extended ACLs. The effective peer pid is logged metadata,
  not the code authority. There is no unauthenticated compatibility fallback. Verification closure: `scripts/verify.sh`
  and `scripts/apple-conform-check.sh` require the client-side helper proof, root uid gate, audit-token code proof,
  connect-path wiring, and requirements/ledger disposition.
- **R-S11e-3 — Linux helper canonical target provenance — CLOSED 2026-07-11.**
  Platform: Linux `.deb` installed-service mode and shared Linux helper paths when invoked by privileged processes.
  Endpoint/action: fixed helper launches such as the root-to-user `sudo`/`env` server launch, `w`/`xrandr`/
  `xdg-screensaver`/`systemctl` app-side helpers, and shared `loginctl`/notification helpers. Boundary: privileged
  RustDesk process execution authority ↔ local filesystem helper resolution. Attack surface closed: fixed helper
  resolution no longer verifies metadata through one path and executes the original candidate string. Resolvers reject
  relative and parent-traversal candidates, require the candidate parent directory to be root-owned and not
  group/world-writable, canonicalize the helper, require the canonical path and canonical parent to remain clean
  absolute trusted state, require the canonical executable to be a root-owned regular executable with no group/world
  write bits, and return the canonical `PathBuf` that is passed to `Command::new`. This closes the symlink-chain
  target-swap class for privileged helper launches without changing helper command semantics. Verification closure:
  `scripts/verify.sh` runs app-side and shared helper resolver tests and requires canonicalization, candidate/canonical
  parent trust, executable-bit checks, canonical return wiring, and requirements/ledger disposition.
- **R-S11e-4 — macOS _service accept-loop blocking-proof offload — CLOSED 2026-07-11.**
  Platform: macOS installed-service mode. Endpoint/action: receiver-side admission for the world-connectable
  `_service` IPC listener. Boundary: local IPC connect attempts ↔ root LaunchDaemon service availability and
  credential-authority admission. Attack surface closed: the current-thread `_service` listener no longer performs
  filesystem metadata, ACL, peer executable, and code-signing proof inline before spawning the per-connection task.
  The accepted socket's uid and `MacosPeerProcessIdentity` are captured as a typed `ServiceScopedIpcAuthorization`
  snapshot; the accept path obtains a nonblocking bounded authorization slot and passes it to the macOS connection
  task, which runs the fail-closed audit-token executable/code-signing proof in `tokio::task::spawn_blocking` and
  returns before the first `stream.next().await` if authorization fails. If the
  authorization budget is exhausted, the listener drops the connection before spawning a task. No `_service` message is read before that
  proof succeeds, Linux keeps its existing synchronous service admission path, and the `_url` sender proof remains
  separate. Verification closure: `scripts/verify.sh` and `scripts/apple-conform-check.sh` require the snapshot type,
  snapshot verifier, macOS authorization-slot budget, `spawn_blocking` task authorizer, start-loop ordering
  (nonblocking slot before `tokio::spawn`, blocking proof inside the task, and authorization before first read), absence of the old combined
  Linux/macOS pre-spawn service gate, and requirements/ledger disposition.
- **R-S11e-5 — Linux service-owned main-server commit receiver proof — CLOSED 2026-07-11.**
  Platform: Linux `.deb` installed-service mode. Endpoint/action: the root service's final
  `Data::CommitServiceOwnedUnattendedPasswordChange` send into the uid-scoped main IPC server after polkit
  authorizes a local service-owned unattended-password request. Boundary: root `_service` credential authority ↔
  service-owned `--server` receiver identity. Attack surface closed: requester authorization and receiver
  authentication are now separate proofs. The root service launches both active-user and headless/root
  service-owned servers with a service-parent environment claim, and
  `commit_service_owned_unattended_password_change` calls
  `authenticate_linux_service_owned_main_server` before sending the password. That receiver proof derives pid/uid
  from SO_PEERCRED, rechecks the peer as the current executable, requires the exact three-entry
  `--server --service-owned-server` argv shape, requires the service-parent environment value to name the
  current root service process, and requires the live `/proc` parent chain to include that service process.
  Missing, stale, wrong-argv, wrong-parent, or non-descendant receivers fail closed before the password leaves the
  root service. Verification closure: `scripts/verify.sh` gates launch-parent propagation in both Linux
  service-server launch paths, the receiver authenticator, exact argv helper, live ancestor proof, structural
  commit-path ordering from scoped connect to receiver proof to password-bearing send, the argv regression test,
  and this requirements/ledger disposition.
- **R-S11e-6 — Linux _service client-side server authentication — CLOSED 2026-07-11.**
  Platform: Linux `.deb` installed-service mode. Endpoint/action: GUI/CLI service-owned unattended-password
  requests over the shared `_service` Unix socket. Boundary: user-session password setter ↔ root service credential
  authority. Attack surface closed: the client no longer sends `Data::RequestServiceOwnedUnattendedPasswordChange`
  to a socket-path peer before proving that the connected receiver is the root RustDesk service. A local fake
  `_service` listener that wins the shared socket path while the legitimate root-owned service socket/parent is
  absent cannot receive the proposed plaintext password. `connect_with_path` authenticates Linux
  `POSTFIX_SERVICE` peers before returning the connection: SO_PEERCRED-derived pid/uid must prove uid 0, the peer
  executable must match the current executable, live argv must be exactly the service command shape
  `argv[1] == "--service"`, and the peer executable plus parent directory must be root-owned, executable where
  applicable, and not group/world-writable. Missing, non-root, wrong-executable, wrong-argv, or writable-path
  receivers fail closed before any `_service` frame carrying the password leaves the client. Verification closure:
  `scripts/verify.sh` gates the Linux `_service` client authenticator, root uid gate, exact service argv helper,
  root-owned executable/parent trust predicates and tests, `connect_with_path` wiring, request-before-send ordering
  through authenticated `connect_service`, and this requirements/ledger disposition.
- **R-S11e-7 — user-owned permanent-password main IPC receiver authentication — CLOSED 2026-07-11.**
  Platforms: Linux and macOS desktop user-owned main IPC, with the same password-route ordering applied across
  Windows/Linux/macOS desktop setters. Endpoint/action: `permanent-password-user-owned-writable` capability query and
  `Data::SetUserOwnedPermanentPassword(String)` write. Boundary: local GUI/CLI password entry ↔ same-UID main IPC
  receiver. Attack surface closed: a same-UID fake main IPC listener that wins the per-user socket path while the real
  user-owned daemon is absent or stale can no longer answer "user-owned password writable" and then receive the
  proposed plaintext password. The user-owned password connector proves the connected receiver before either the
  capability query or the password-bearing write: the peer uid must equal the caller's effective uid, the peer pid must
  resolve to the current executable, and the live argv must be the exact user-owned `argv[1] == "--server"` shape,
  rejecting service-owned markers and extra mode args. The generic desktop password setter also prefers the
  service-owned path whenever that path is available, so an installed-service password change does not consult
  user-owned main IPC to choose where the service-owned credential should go. This is local credential-secrecy and
  route-correctness hardening, not a root/SYSTEM privilege-escalation bypass. Verification closure: `scripts/verify.sh`
  gates the receiver authenticator, exact argv helper and test, same-uid/executable/argv checks, authenticated
  password query/write connector, service-owned-first routing in both capability and setter functions, and this
  requirements/ledger disposition.
- **R-S11e-8 — macOS service-owned password right normalization before authorization — CLOSED 2026-07-11.**
  Platform: macOS installed-service mode. Endpoint/action: service-owned unattended-password authorization through
  Authorization Services and the root `_service` helper. Boundary: UI/CLI password entry and Authorization Services
  policy database ↔ root LaunchDaemon credential authority. Attack surface closed: the UI no longer calls
  `AuthorizationCopyRights` against a merely existing or stale `com.carriez.RustDesk.set-unattended-password` right.
  After authenticating the connected `_service` peer as the trusted privileged helper, the client sends a no-secret
  `MacosServiceOwnedPasswordRightReadyRequest`; the helper runs the existing exact right setup and returns
  `MacosServiceOwnedPasswordRightReadyResult(bool)`. Only then does the UI create the external authorization form.
  The native creator no longer accepts existence-only state: `MacCreateServiceOwnedUnattendedPasswordAuthorizationExternalForm`
  requires `RustDeskSetUnattendedPasswordRightMatchesExpected`, which reads the right definition and checks
  `class=user`, `group=admin`, `shared=false`, `allow-root=false`, `authenticate-user=true`,
  `session-owner=false`, `extract-password=false`, and `timeout=0` before prompting. Fresh authdb first use is
  therefore seeded by the trusted helper before the prompt, and stale/weaker definitions fail closed instead of being used for
  the authorization grant. Verification closure: `scripts/verify.sh` and `scripts/apple-conform-check.sh` gate the
  readiness request/result, service-channel allowlist, client ordering from authenticated `_service` connect to
  readiness to `AuthorizationCopyRights` to password send, exact native dictionary validation, absence of the old
  existence-only helper, and this requirements/ledger disposition.
- **R-S11e-9 — macOS _service audit-token peer code identity — CLOSED 2026-07-11.**
  Platform: macOS installed-service mode. Endpoint/action: `_service` client-side server authentication,
  receiver-side service-scoped admission, and the service-owned password runtime snapshot requester. Boundary:
  local Unix-domain socket peers ↔ root privileged helper/app credential authority. Attack surface closed: macOS
  `_service` code identity no longer depends on re-observing an effective pid/path or shelling out to filesystem
  `codesign` after accept. The connected socket's uid, `LOCAL_PEEREPID` metadata, and `LOCAL_PEERTOKEN` are captured
  as `MacosPeerProcessIdentity`; Security.framework resolves live peer code from the audit token through
  `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)`; app/helper requirements are validated with
  `SecCodeCheckValidity(..., STRICT_VALIDATE)`; and the path from `SecCodeCopyPath` is used only for secondary
  installed-location, owner, mode, symlink, and ACL checks. `_service` client auth now requires a root peer whose
  audit-token code is the trusted privileged helper; receiver admission snapshots carry the audit token into the
  blocking verifier before any `_service` frame is read; and the password runtime snapshot requester must be the
  audit-token trusted installed app before launchd argv/plist proof is considered. There is no unauthenticated,
  PID-only, path-only, or subprocess-code-signing fallback. Verification closure: `scripts/verify.sh` and
  `scripts/apple-conform-check.sh` gate the direct `security-framework` dependency, `LOCAL_PEERTOKEN`,
  `LOCAL_PEEREPID`, legacy `LOCAL_PEERPID` absence, audit-token identity capture, native strict validation, Rust
  `MACOS_CODESIGN` absence, service-client/server/snapshot wiring, and this requirements/ledger disposition.
- **R-S11e-10 — macOS residual process launch provenance — CLOSED 2026-07-11.**
  Platform: macOS desktop/server source. Endpoint/action: post-keying wake/user-activity notification and
  root-capable `launchctl asuser` helper launch for CM/whiteboard bootstrap. Boundary: authenticated Remote
  connection or service-owned server helper launch ↔ local process creation/provenance. Attack surface closed:
  the connected-session wake path no longer spawns `/usr/bin/caffeinate -u -t 5`; it calls the native
  `MacDeclareRemoteUserActivity` bridge, which invokes
  `IOPMAssertionDeclareUserActivity(..., kIOPMUserActiveRemote, ...)` through IOKit. The macOS bootstrap launcher
  no longer inserts `/usr/bin/env KEY=VALUE ...` as an argv bridge. `run_as_user_with_env` now executes
  `/bin/launchctl asuser <uid> <current_exe> ...`, applies the launcher-owned token variables through
  `Command::env`, and rejects every environment key except the CM and whiteboard launch-token/parent keys. This was
  not a newly proven ordinary-user-to-root path: the installed macOS service-owned server is the LaunchAgent user
  process, and the old helper paths did not accept peer-chosen executable text. It closes residual subprocess and
  future-call-site authority ambiguity so the macOS helper surfaces remain typed and source-gated. Verification
  closure: `scripts/verify.sh` and `scripts/apple-conform-check.sh` gate the explicit IOKit link, native
  user-activity helper, remote-user activity type, server wiring, absence of `caffeinate`, absence of the
  `/usr/bin/env` bridge, the environment-key allowlist, and this requirements/ledger disposition.
- **R-S11e-11 — Windows service-owned password commit receiver proof — CLOSED 2026-07-11.**
  Platform: Windows installed service. Endpoint/action:
  `Data::CommitServiceOwnedUnattendedPasswordChange(String)` from LocalSystem `_service` into main IPC.
  Boundary: authorized elevated local password-change request ↔ the main-pipe receiver that will receive the
  plaintext service-owned credential. Attack surface closed: the receiver-side main-channel policy already
  rejected a user-owned server before writing the password, but the LocalSystem sender still connected to the
  generic main pipe and serialized the password before proving that receiver was the service-owned server. The
  sender now calls `authenticate_windows_service_owned_main_server` immediately after connecting and before
  sending the password-bearing frame. That authenticator resolves the named-pipe server pid, requires the exact
  current executable path, requires the process token to be LocalSystem, and requires the exact
  `--server --service-owned-server` process shape through the exact-argv process lookup. If any proof is missing,
  the service fails closed and returns the existing typed rejection ACK. Verification closure: `scripts/verify.sh`
  gates the authenticator, exact-argv helper, LocalSystem receiver proof, source ordering before
  `Data::CommitServiceOwnedUnattendedPasswordChange(value)`, the retained receiver-side LocalSystem commit gate,
  and this requirements/ledger disposition.
- **R-S11e-12 — macOS clipboard-file paste no-follow finalize — CLOSED 2026-07-11.**
  Platform: macOS desktop with `unix-file-copy-paste`. Endpoint/action: CLIPRDR file paste after a local
  Finder/pasteboard paste operation asks the authenticated peer for `FILEDESCRIPTOR` metadata and file contents.
  Boundary: hostile-peer descriptor/content names ↔ local filesystem writes under the user's paste destination.
  Attack surface closed: the paste worker no longer re-resolves peer-influenced paths with `File::create`,
  `create_dir_all`, `std::fs::rename`, path xattrs, path metadata reopen, or path removal. This was not a hidden
  remote-to-root path in the normal installed macOS model because the controlled server is a user LaunchAgent, but
  it was still the wrong primitive for a peer-controlled filesystem write surface adjacent to R-S8/R-A5. The worker
  now opens the paste target directory through a component walk using `openat(O_DIRECTORY|O_NOFOLLOW)`, keeps that
  handle as the authority anchor, creates any peer-requested parent directories with `mkdirat` plus no-follow
  re-open, reserves zero-size and `.rddownload` files with `openat(O_CREAT|O_EXCL|O_NOFOLLOW)`, records relative
  download paths for cleanup, updates and removes Finder progress xattrs through `fsetxattr`/`fremovexattr` on the
  open file descriptor, removes cancelled temp files with `unlinkat`, and finalizes downloads with
  `renameatx_np(..., RENAME_EXCL)` while retrying numbered destination names on actual collisions. Initial
  filesystem setup errors are propagated instead of masked by `update_next(0).ok()`, and a zero-byte write from the
  file sink is treated as `WriteZero`. Verification closure: `scripts/verify.sh` and
  `scripts/apple-conform-check.sh` gate the target-dir no-follow open, relative parent walk, exclusive file open,
  exclusive final rename, fd-bound xattr operations, relative cleanup state, unmasked initialization, requirements
  disposition, and absence of the deleted path-based write/finalize fallback.
- **R-S11e-13 — macOS clipboard-file paste placeholder temp authority — CLOSED 2026-07-11.**
  Platform: macOS desktop with `unix-file-copy-paste`. Endpoint/action: pasteboard placeholder file URLs used to
  trigger Finder's file-paste flow before CLIPRDR file contents are requested. Boundary: local pasteboard/temp
  namespace state ↔ the RustDesk-owned placeholder that authorizes the later paste observation. Attack surface
  closed: placeholder files are no longer global `/tmp/.rustdesk_*` names created with path-based `File::create`,
  counted across all of `/tmp`, or source-cleaned by path. This was not a newly proven remote-to-root path because
  the normal installed macOS controlled side is a user LaunchAgent, but the old namespace was the wrong authority
  primitive for a pasteboard file URL that other same-user processes can observe or race. `pasteboard_context.rs`
  now creates a unique `rustdesk-clipboard-<euid>-<uuid>` directory under the current user's temporary directory with
  `mkdir(0700)`, opens it with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, normalizes/verifies owner-only mode and euid
  ownership through `fchmod`/`fstat`, and keeps that directory handle as the placeholder authority. The provider
  creates placeholders only through `openat(O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC)` mode `0600`; temp counting is
  scoped to the private directory and fails closed on read errors; source cleanup uses `unlinkat` through the same
  handle; and the paste observer accepts a captured callback so paste-result cleanup carries the private authority.
  Verification closure: `scripts/verify.sh` and `scripts/apple-conform-check.sh` retain the touched Apple clipboard
  sources and gate the private directory, fd-relative create/unlink, scoped counting, README/requirements
  disposition, and absence of global `/tmp` placeholder creation/counting or source-placeholder path cleanup.
- **R-S11e-14 — Linux root/headless FileTransfer owner authority — CLOSED / ACCEPTED / GATED 2026-07-11.**
  Platform: Linux installed service and root/headless service-owned `--server` modes. Endpoint/action:
  `LoginRequest.FileTransfer`, `Data::AuthorizedFS`, and FileTransfer read/write/list/delete/rename jobs. Boundary:
  authenticated owner session ↔ serving `--server`/CM process filesystem authority. Finding disposition: the
  follow-up audit found no unprivileged local-to-root IPC mutation path and no unauthenticated remote path. It found
  an intentional R-S8 policy fact: where the serving process is root/service-owned, FileTransfer executes at that
  process credential. This is accepted rather than denied or demoted because the CPace-authenticated peer is the
  trusted owner, FileTransfer is the single full-filesystem owner mode, and a runtime confinement/demotion knob would
  contradict R-S8/R-S12 unless the project philosophy changes. Closure condition: FileTransfer must remain post-CPace,
  file-only, CM-token-bound, and budgeted/path-hardened. The Linux FileTransfer login arm admits the session only
  through the local file-transfer permission gate and has no root/headless special denial or demotion branch;
  `AuthConnType::FileTransfer` receives CM file authority only with the server-validated connection token; legacy
  desktop `Data::FS` is reject-only; FileTransfer capability confinement clears desktop input, block-input, privacy,
  restart, recording, and host-audio; Unix headless FileTransfer reports the process owner while the "no active console
  user" refusal remains Windows-peer-only; and the R-S8 no-follow/budget/job-provenance gates continue to cover the
  actual filesystem operations. Verification closure: `scripts/verify.sh` gates this requirements/ledger disposition,
  the FileTransfer login shape, CM `Remote`/`FileTransfer` file-authority binding, Unix headless username/refusal
  guards, and the FileTransfer capability confinement set. No runtime behavior changed in this slice.
- **R-X6/R-S11c-9b — desktop URL IPC handoff canonicalization — CLOSED 2026-07-11.**
  Platforms: Windows/macOS desktop URL forwarding. Endpoint/action: `listenUniLinks(handleByFlutter: false)`
  to `bind.sendUrlScheme` to Rust `_url` IPC. Boundary: OS-delivered deep-link material ↔ local IPC handoff
  and main-process parser. Attack surface closed: the non-main/connection-manager forwarding branch no longer
  serializes raw `uri.toString()` into `_url` IPC before stripping. It calls `urlLinkToForwardUrl`, reuses
  `urlLinkToCmdArgs`, rejects config/password write authorities and relay syntax, accepts only connect
  authorities, and forwards a freshly rendered address-only `rustdesk://<authority>/<id>` URL. This closes a
  local same-user IPC disclosure and authority-hygiene gap, not a remote or root escalation path. Verification
  closure: `scripts/verify.sh` gates the canonicalizing helper, listener wiring, address-only renderer, absence
  of raw URI forwarding, and this requirements/ledger disposition.
- **R-S11b-3 — service-owned remote-access policy, identity, and trust material.** Platforms: all desktop
  installed-service paths. Linux/macOS no longer have the `_service` whole-config bus after R-S11b-1, and
  the desktop main IPC no longer has a whole-config request/response/import path after R-S11b-3b; Windows
  remains high risk because main IPC is same-session. Endpoints: `Data::Options`, trusted-device removals,
  remaining server/direct-listener policy writers, and any hidden UI/CLI/FFI path that persists
  controlled-side policy. Boundary: user-session process ↔ privileged host policy. Attack surface: a local
  caller can alter who can reach the service, how it binds, which trust/identity state it uses, or which
  hardened policy pins are effective. Current state: ordinary whole-options IPC writes are closed for
  service-marked servers by R-S11b-3a, including typed daemon ACK/NACK and no local persistence fallback inside
  the IPC helper; user-owned `--server` option writes remain user-owned; whole user config is never imported
  over IPC after R-S11b-3b; generic config writes, generic config helpers, and the proxy IPC variant are absent
  after R-S11b-3c; Windows `share_rdp` is no longer a UI-side shell/registry write after R-S11b-3d and is
  committed only by the LocalSystem service through a typed elevated `_service` request; service identity/salt
  reads are side-effect-free after R-S11b-3e; desktop at-rest wrapper reads no longer mint key material after
  R-S11b-3f; trust-anchor/proxy-shaped option keys are pinned empty after R-S11b-3g; whole-map option reads
  (`Config::get_options`, the UI cache, CLI `--option`, and IPC `Data::Options(None)`) now overlay
  `PINNED_SETTINGS` last after R-S11b-3i, so broad reads cannot surface stale default/stored/signed-custom
  values for pinned policy keys; and the main IPC mutation
  policy is exhaustive after R-S11b-3h, with no wildcard arm that could admit a future
  identity/salt/key/proxy/trust-store write without an explicit receiver-authorized gate.
**Contained hardening items from the same audit:**
- **R-S11c-6 — Windows named-pipe endpoint hardening.** Platform: Windows desktop. Endpoint:
  predictable `\\.\pipe\<APP>\query{postfix}` names and broad create permissions for main/`_service`.
  Boundary: local process ↔ IPC endpoint identity. Attack surface: pipe squatting, spoofing/confusion, or
  denial of service even where message auth blocks higher impact. Current state: Windows main and `_service`
  listeners no longer use the broad `allow_everyone_create` descriptor. Privileged listener creation builds
  an explicit SDDL DACL: LocalSystem can create/own service-side pipe instances; a non-System user-owned
  server gets its own logon/user SID for server-instance creation; the active session identity gets only the
  client read/write/synchronize mask and not `FILE_CREATE_PIPE_INSTANCE`; `Everyone` and the Administrators
  group are absent from the base DACL. Windows clients open the pipe with that explicit non-generic mask and
  verify the connected server PID/executable, with `_service` additionally requiring a LocalSystem server.
  The long-lived `_service` listener is recreated on active-session changes so its DACL and the runtime
  expected-session check do not drift. Status: closed for the named-pipe endpoint boundary.
- **R-S11c-12 — Windows terminal helper pipe binding.** Status: closed by the completed R-S11c-12 slice above.
  The Windows terminal helper pipes are transport only: they are first-instance, local-only, DACL-restricted,
  and post-connect bound to the exact helper PID returned by `CreateProcessAsUserW`; same-user pipe-name
  knowledge, log scraping, or first-client racing cannot select the terminal helper endpoint.
- **R-S11c-7 — Linux `_pa` audio helper ambient same-UID trust.** Status: closed by the completed
  R-S11c-7 slice above. `_pa` capture requires an owner-identity/token lease minted from the active audio
  subscriber set and bound to the authenticated live `_cm`/`_pa` process identity plus the server-scoped CM
  launch token and server-parent ancestry; missing, wrong, wrong-peer, launch-tokenless, non-descendant, and stale capabilities are rejected before
  PulseAudio capture starts.
- **R-S11c-11 — Unix `_cm` endpoint-selection identity.** Status: closed by the completed
  R-S11c-11 slice above. Fixed-path `_cm` selection is now authority-bearing before the server discloses
  `cm_auth_token`, file/chat/voice-call state, or future downstream helper leases: macOS requires mutual
  server/endpoint launch-token proof via separate HMAC-SHA256 contexts after process-shape checks, and Linux
  keeps its live process identity checks plus the same mutual pre-disclosure proof.
- **R-S11c-8 — `_whiteboard` helper ambient same-UID trust.** Status: closed by the completed R-S11c-8
  slice above. Whiteboard helper IPC now uses a launch-scoped endpoint, mutual whiteboard-specific launch
  proof, parent-pid admission, and per-connection event tokens; arbitrary same-UID clients, fixed-path
  squatters, caller-supplied render keys, wrong-token events, and stale `Exit` are rejected before overlay
  state changes.
- **R-S11c-9 — Windows URL forwarding via unauthenticated window messages — CLOSED 2026-07-09.**
  Platform: Windows desktop. Endpoint: `WM_COPYDATA` / `WM_USER+2` URL forwarding to an existing UI
  window. Boundary: local process ↔ URL/deep-link dispatcher. Closure: the Rust helper
  `send_message_to_hnwd` is deleted, `core_main` forwards Windows URL handoff through
  `ipc::send_url_scheme`, and the Flutter Windows runner no longer calls
  `DispatchToUniLinksDesktop(hwnd)`. Raw Windows URL launches are handed to the same path through the
  `rustdesk_send_url_scheme` C ABI bridge. The main Windows Flutter process starts the `_url` IPC
  listener; `_url` uses a restricted named-pipe DACL and receiver-side same-session/current-executable
  peer authorization before delivering `Data::UrlLink`. If IPC is unavailable, the process launched by
  the OS/CLI handles its own arguments instead of sending them by public window message.
  Credential/config authorities remain ignored and embedded password/key/relay material remains
  stripped/rejected.
- **R-S11c-10 — Linux root-context shell interpolation.** Platform: Linux service/helper discovery.
  Surfaces: root-side env/home/session discovery commands that interpolate UID/process/user fields into shell
  strings. Boundary: discovered local names/metadata ↔ root shell. Current impact: lower probability than the
  primary IPC findings because the main spawn path is argv-based and inputs are mostly OS-discovered, but root
  shell strings are not acceptable. Current state: R-S11c-10a closes the prelogin/home/env/Xorg/subprocess
  desktop-discovery cluster with `users` + direct `/proc` reads and a source gate; R-S11c-10b closes the
  service lifecycle process-kill pipelines with `/proc/<pid>/exe` identity, direct `/proc/<pid>/cmdline`
  argv matching, and `kill(2)`.
  R-S11c-10e closes Linux distro metadata parsing: `Distro::new()` now reads `/etc/os-release` or
  `/usr/lib/os-release` directly and parses shell-compatible assignments as data; the dormant OpenSUSE
  elevation helper that used `cat /etc/os-release | grep opensuse` is deleted with the commented elevation
  scaffold. `scripts/verify.sh` runs the parser tests and source gate for this closure.
  R-S11c-10f closes `linux_desktop_manager` headless detection: the remaining existing-session discovery path
  now checks a fixed set of absolute Xorg paths and reads `/usr/share/xsessions` directly for `.desktop`
  entries; it no longer shells through `which` or `ls`, and the bare `Xorg` PATH fallback is gone.
  `scripts/verify.sh` runs the focused desktop-manager tests and source gate.
  R-S11c-10g closes Linux SELinux status probing: `is_selinux_enforcing()` reads selinuxfs `enforce` files
  directly, treats only `1` as enforcing, and no longer shells through `getenforce` or parses `sestatus`.
  `scripts/verify.sh` runs the focused parser tests and source gate. R-S11c-10h closes config-home correction
  in `libs/hbb_common/src/config.rs`: `patch(PathBuf)` uses the `getpwuid`-backed trusted home helper instead
  of `whoami` plus `getent|awk`. R-S11c-10i closes Linux runtime service lifecycle command construction:
  service start/stop/enable/disable now invoke fixed trusted `systemctl` paths with direct argv, and service install
  does not import active-user config into root service state. R-S11c-10j closes the
  Debian package lifecycle and unit stop layer: maintainer scripts use checked
  `deb-systemd-helper`/`deb-systemd-invoke` operations for unit state/actions plus a fixed checked system manager
  reload instead of raw init/process-table probes or invalid helper actions, `build.py` cannot mask Debian
  control-script/package-build failures, the release build compares emitted `.deb` maintainer scripts to source
  and validates their lifecycle semantics before hashing artifacts, and the unit/supervisor stop path is
  cgroup/SIGTERM-first with a bounded forced-stop backstop. R-S11c-10k closes Linux root/service helper command provenance:
  the root-to-user `sudo` transition, `env` fallback, `w`, `xrandr`, `xdg-screensaver`, and `systemctl`
  resolve only trusted fixed `/usr/bin`/`/bin` candidates and now execute the trusted canonical target after
  candidate-parent, canonical-parent, root-owned, non-writable, and executable-bit checks; `--cm` detection is
  `/proc`/current-exe/argv-backed instead of `ps`; and the X11
  socket fallback reads `/tmp/.X11-unix` socket metadata plus passwd ownership instead of parsing `ls`.
  R-S11c-10l closes the Linux `--server` tray cleanup: `src/core_main.rs` no longer launches PATH-selected
  `pkill -f`; it calls `platform::stop_tray_processes()`, which selects only current-executable processes
  with an exact `--tray` argv through `/proc` and sends SIGTERM.
  R-S11c-10m closes the shared Linux helper command-provenance residue in
  `libs/hbb_common/src/platform/linux.rs` plus the delayed service-reopen path: shared `loginctl` and
  crash-notification helpers no longer use `which`, bare command names, or Flatpak host spawning; they select
  fixed absolute candidates only when the candidate parent, canonical parent, and canonical executable are trusted,
  and they execute the returned canonical path.
  The unused public `run_cmds`/`run_cmds_trim_newline` shell API and `shell_quote` helper are deleted.
  Linux service uninstall no longer sequences delayed reopen through `sh -c "sleep ...; exec ..."`; it spawns
  the current executable in an internal argv-only `--reopen-after-service-stop <seconds>` mode, whose receiver
  fails closed on malformed or out-of-range delay values before reopening the GUI.
  R-S11c-10n closes the Linux headless CM uid lookup in `src/server/connection.rs`: the headless
  `--cm-no-ui` branch no longer runs a PATH-selected `id -u <username>` subprocess to derive the
  uid for the discovered seat user. It resolves the user through `hbb_common::users::get_user_by_name`
  on a blocking worker and carries the returned uid into the existing CM launcher shape.
  R-S11c-10o closes the Linux clipboard FUSE stale-unmount provenance path in
  `libs/clipboard/src/platform/unix/fuse/mod.rs`: the `unix-file-copy-paste` mount setup no longer runs a
  PATH-selected `umount` program before mounting. After the existing no-follow, current-euid-owned
  `/tmp/<app>/cliprdr-*` directory setup, stale cleanup uses a checked mount-path C string and direct
  `umount2(..., UMOUNT_NOFOLLOW)` syscall plus the fixed trusted `fusermount -u -q -z --` fallback used by
  normal teardown; "not mounted" remains best-effort cleanup, and the following fixed-helper mount fails
  closed if a stale mount still blocks the mount point.
  R-S11c-10p closes the Linux self-relaunch AppImage fallback in `src/common.rs`: the shared
  `run_me_with_env` helper no longer honors ambient `APPDIR` or launches `AppRun` for Linux child-process
  relaunch. CM, whiteboard, tray, and same-user service-owned child launches now use the current executable
  only while preserving the explicit authority-token environment supplied by their callers.
  R-S11c-10q closes the Linux clipboard FUSE root-process path in
  `libs/clipboard/src/platform/unix/fuse/mod.rs`: before mountpoint setup or fixed-helper mounting, Linux
  clipboard FUSE initialization checks the process euid and fails closed for euid 0. The normal installed
  desktop path remains the non-root user `--server` child launched by the root `--service`; headless/root
  `--server` and root-launched viewer/client processes keep text clipboard and file transfer, but cannot
  initialize CLIPRDR file-copy FUSE as root.
  R-S11c-10r closes the Linux clipboard FUSE direct-mount/PATH-helper abstraction in
  `libs/clipboard/src/platform/unix/fuse/mod.rs`: RustDesk no longer calls `fuser::spawn_mount2` for Linux
  clipboard. The module resolves only fixed absolute `fusermount3`/`fusermount` candidates to canonical helper
  targets after checking both the fixed candidate parent and canonical target parent are root-owned and not
  group/world-writable, then requires the executable metadata to be root-owned, executable, and not
  group/world-writable. It passes `_FUSE_COMMFD`, receives the `/dev/fuse` fd with `SCM_RIGHTS`, wraps it with
  `fuser::Session::from_fd(..., SessionACL::Owner)`, and owns unmount plus thread join in a RustDesk session
  guard without fuser's `BackgroundSession::join` panic path. `AutoUnmount`, `AllowOther`, and `AllowRoot` are
  not part of the clipboard option set. The
  remaining service-wide `mount`/`umount` syscall allowance is for the authenticated owner's root terminal
  semantics; clipboard FUSE no longer depends on direct RustDesk `mount(2)`/`umount(2)` authority.
  Remaining closure:
  no currently listed R-S11c-10 service/display discovery probe remains open; keep treating any newly found
  root-context shell interpolation as a new tracked closure item. `xrandr|tr` is closed by R-S11c-10c;
  `pgrep` and whiteboard Xwayland discovery are closed by R-S11c-10d; `os-release` parsing is closed by
  R-S11c-10e; `linux_desktop_manager` probing is closed by R-S11c-10f; SELinux status probing is closed by
  R-S11c-10g; config-home correction is closed by R-S11c-10h; runtime lifecycle `systemctl` command construction
  is closed by R-S11c-10i; Debian package lifecycle and systemd stop semantics are closed by R-S11c-10j;
  root/service helper command provenance is closed by R-S11c-10k; Linux `--server` tray cleanup is closed
  by R-S11c-10l; shared Linux helper command provenance and delayed reopen shell removal are closed by
  R-S11c-10m; Linux headless CM uid lookup is closed by R-S11c-10n; Linux clipboard FUSE stale unmount is
  closed by R-S11c-10o; Linux self-relaunch AppImage fallback is closed by R-S11c-10p; Linux clipboard FUSE
  root-process denial is closed by R-S11c-10q; Linux clipboard FUSE fixed-helper fd-passing mount is closed
  by R-S11c-10r.
- **R-S11b-4 — config secrecy statement after IPC closure — CLOSED 2026-07-09.** Platforms: all. Surface: at-rest password/PRS
  wrapper keyed by machine UUID. Boundary: local endpoint read ↔ connect-equivalent credential. Status:
  accepted residual only when endpoint compromise/local config read is in scope-out; not a permission boundary
  and not a substitute for IPC secrecy. Current state: R-S11b-4a closes the service-IPC export half for the
  desktop main channel: `src/ipc.rs` exports no `password_prs` or key-pair material, and the remaining
  password-storage/salt snapshot requests are denied for service-owned receivers by the same
  `current_process_allows_main_channel_permanent_password_storage_sync()` authority gate used by
  R-S11b-2. macOS's service-owned LaunchAgent root-credential delivery is not a generic snapshot path: it is the
  typed R-S11b-2e `_service` runtime snapshot, accepted only after socket audit-token installed-app proof, exact live
  argv, and parsed root-owned plist command-shape proof for the LaunchAgent job, and applied only to
  `RUNTIME_PERMANENT_PASSWORD_PRS`, never to serialized `Config`.
  R-S11b-4b closes the Unix at-rest file-mode half: `libs/hbb_common/src/config.rs::store_path`
  routes non-Windows writes through `confy::store_path_perms(..., 0o600)`, and
  `config::tests::store_path_writes_owner_only_permissions` behavior-tests the resulting mode. R-S11b-4c closes
  the Windows at-rest file-mode half: `libs/hbb_common/src/config.rs` now protects config directories before
  storing, protects final files after the `confy` temp-file rename, and refuses to load an existing Windows config
  file that cannot first be secured. The Windows DACL is explicit and protected, grants full access only to
  LocalSystem and the current process user SID, deduplicates the LocalSystem case, and does not rely on inherited
  `%APPDATA%`/profile ACLs. Verification closure: `scripts/verify.sh` runs the Unix mode test and the Windows SDDL
  shape test, asserts no main-IPC PRS/key export, service-owned storage/salt denial, the launchd-bound macOS
  runtime snapshot overlay, Unix 0600 writer shape, Windows protected-DACL API wiring, Windows load/store
  fail-closed hooks, and the absence of broad Windows principals in
  the config DACL source. Any future stronger storage (TPM/OS keychain) is defense-in-depth, not the cure for the
  IPC class.

**Checked during this audit and not opened under R-S11b/R-S11c:** Android exported components/service
surfaces remain contained by manifest/exported-permission shape; iOS has no controlled-side/root IPC surface
in scope; Unix IPC parent/socket hardening remains a prerequisite and is not the failing layer; FileTransfer
authorization, file-transfer symlink TOCTOU, port-forward plaintext, decompression amplification,
OS-login/PAM/LogonUser, deep-link password/config/import, and Windows terminal-helper SYSTEM-shell concerns
are tracked by their existing requirements/fixes, not reopened here. Dependency advisories are the separate
R-R3/Appendix D gated class: Rust and Dart package advisories are checked by the pinned advisory gates, while
native vcpkg codec advisories remain the Appendix C #2b watch/residual.

Current implementation is compliant with this R-S11b/R-S11c stronger requirement as of 2026-07-09. No
release or prerelease should be promoted on that fact alone; the separate live-QA, build, dependency, and
release-readiness items below still govern promotion.

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
- **R-B9/R-B10 legacy root Docker builder retirement (closed/gated 2026-07-11)** — the legacy root
  `Dockerfile`, its `entrypoint.sh`, and the translated upstream `docs/README-*.md` build instructions are
  deleted. The only supported Docker builders are the digest-pinned `scripts/Dockerfile.*` images created by
  `scripts/online-fetch.sh`; the legacy root Docker builder is absent, and `verify.sh` rejects any return of
  the root Dockerfile/entrypoint, translated upstream README build path, raw Sciter/rustup live-fetch snippets,
  unchecked CMake download, or `rustdesk-builder` root-Docker command.
`verify-release.sh` (8 source gates: compile/KATs/policy, runtime smoke, Flutter/Dart analyze,
native-codec watch, Apple source conformance, Rust advisory audit, Dart advisory audit, and the
build-harness fail-loud suite) is the source-side confirmation. The reproducible set folds in the
R-S19 structural closure of CWE-863 / CVE-2026-58056 (every peer-triggerable capability derived from
`AuthConnType` by construction).

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
Windows = §12.2 KVM golden-VM `DOUBLE_BUILD` A==B (exe + msi). `verify-release.sh` ALL 8 source gates
GREEN at this HEAD (incl. the port-forward runtime smoke, Apple source conformance, and the R-A9
wire-ciphertext test).

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

**DRILL D — machine-UUID PRS decrypt-fail → typed unavailable PRS → diagnosed park (CONFIRMED trigger; reboot-proof; closure gated by R-S9 PRS read-state).** `read_permanent_password_prs()` preserves the reason as `PermanentPasswordPrsRead::UndecryptableStorage`; `get_permanent_password_prs()` collapses it to empty only at the legacy CPace string boundary, where empty fails closed before keying. `direct_server` drops or parks the listener and logs undecryptable stored PRS distinctly from an intentionally missing/cleared password; `has_permanent_password()` returns false because the auth boundary has no usable PRS. Park triggers remain: (1) machine GUID changed (MachineGuid / `/etc/machine-id` / IOPlatformUUID differs from set-time); (2) `machine_uid::get()` fails at read-time, so the desktop at-rest key is unavailable and the machine-UUID-sealed PRS cannot open; (3) corrupted `password_prs` bytes. **Survives a restart** while stored bytes remain unchanged; recovery requires the machine key to become readable again or the password to be provisioned again. Windows/Linux/macOS only for the machine-UID failure case; Android/iOS use the documented mobile persisted-key wrapper. NEEDS-RUNTIME (justified): whether the GUID changed / `machine_uid` failed on the operator's box — the code fully determines the consequence and now surfaces it honestly.

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

**Headline (CONFIRMED).** The desktop "Unlock Security Settings" button gates the Safety tab — including the settings-page **"Set permanent password"** button — on `check_super_user_permission()`. The fork excised the *active* elevation ceremonies (R-X9 `run_uac`/`elevate` Windows; R-X11 `gtk_sudo` Linux) and rewired that check into a **passive "am I already elevated/root?" probe**, leaving the unlock button + ordinary settings controls behind it. The desktop GUI is **proven never-elevated**, so the probe always returns false, `onUnlock()` never fires, the click is silently swallowed — identically on Windows and Linux (BR-7). macOS diverges (genuine interactive admin dialog → works); Android has no such gate. One mechanism → BR-7, BR-2, settings-half of BR-3.

**The exact break — full chain (cfg-gated source).** `desktop_setting_page.dart:749-752` `locked=mainIsInstalled()`; `:766-778` `preventMouseKeyBuilder = ExcludeFocus+AbsorbPointer(absorbing:locked)`; `:1979-2020` `_lock.onPressed`: `unlockPin` empty → `callMainCheckSuperUserPermission()` **false** → `if(checked) onUnlock()` never runs, **no else** → silent no-op. → `flutter_ffi.rs:1918` → `ui_interface.rs:917` → `platform::check_super_user_permission()`: **Windows** `is_elevated(None)` (passive `TokenElevation`, `windows.rs:2335-2370`; `run_uac`/`elevate` excised) → false; **Linux** `Ok(is_root())`=`username()=="root"` (`linux.rs:1400,1052`) → false; **macOS** `MacCheckAdminAuthorization()` (`macos.mm:84`) → true; **Android/iOS** returns true but mobile UI has **no `_lock` at all**.

**GUI PROVEN never-elevated on Win/Linux.** Windows exe manifest is **asInvoker** — `res/manifest.xml` (via `build.rs:35`) + `runner.exe.manifest` have **no `<requestedExecutionLevel>`** → medium-integrity, no auto-UAC; install elevates only the *batch* (`runas`, `windows.rs:1853`), post-install GUI spawns with the caller's medium token (`windows.rs:2974-2980`); the service is a separate LocalSystem process. Linux GUI runs as the desktop user; root is the separate systemd `--service`. → `is_elevated`/`is_root`=false every ordinary launch → permanent silent no-op (matches BR-7).

**macOS unlock PROVEN WORKS from the framework contract (NOT NEEDS-RUNTIME).** `macos.mm:84-101`: fresh `AuthorizationCreate`+`AuthorizationCopyRights(kAuthorizationRightExecute, flags=InteractionAllowed|PreAuthorize|ExtendRights)`, returns `status==errAuthorizationSuccess`. Apple's Authorization Services contract: InteractionAllowed → the Security Server presents the admin dialog; the `kAuthorizationRightExecute` rule requires admin auth; returns success **only when the user authenticates as admin** (else Denied/Canceled). Fresh authRef per call → dialog every click. → macOS unlock **WORKS**; inert only on cancel/non-admin.

**Platform matrix (each cell from its own cfg-gated source).**
| Control | Windows | Linux/Debian | macOS | Android | iOS |
|---|---|---|---|---|---|
| Unlock Security Settings | **DEAD** (passive `is_elevated`, asInvoker) | **DEAD** (passive `is_root`, non-root) | **WORKS** (interactive admin dialog) | N/A (no `_lock`) | viewer-only |
| Set permanent password (GUI/CLI) | Settings button locked; home dialog/CLI work when user-owned writable | Settings button locked; home dialog/CLI work when user-owned writable | works after unlock or home dialog when user-owned writable | **WORKS** (menu+auto-prompt, no lock) | no controlled service |
| Pinned security toggles | greyed + locked | greyed + locked | greyed (pinned) even after unlock | greyed | n/a |
| Non-pinned Safety prefs | locked out | locked out | editable after unlock | editable | n/a |

**BR-6 consequences (CONFIRMED).** *Set password*: settings-page button (`:889`, inside locked card) `enabled=!locked=false`→`onPressed:null`+AbsorbPointer; desktop auto-prompt guarded `isAndroid||isIOS` (`server_model.dart:393`). The current home-dialog and CLI user-owned path is the typed `SetUserOwnedPermanentPassword` IPC operation gated by `permanent-password-user-owned-writable`; service-owned password provisioning remains closed until an admin-authorized service operation exists. *"Enable remote config modification"*: pinned `Y` (`config.rs:3265`), quadruple-inert (AbsorbPointer + `enabled=false` + `fakeValue=true` checked + `isOptionFixed→onChanged:null`) — already ON by policy, shown greyed.

**Complete R-S16 pinned set — 28 keys classified (CONFIRMED).**
- **(A) Correctly pinned AND UI-conformant, removed/hidden per R-G1 (13):** `verification-method`, `approve-mode` (R-X7a), `2fa`, `bot` (R-X7), `api-server`, `custom-rendezvous-server`, `relay-server`, `proxy-url` (Network/SOCKS removed R-G4), `enable-virtual-display`, `allow-websocket`, `allow-insecure-tls-fallback`, `allow-linux-headless`, `stop-service` (Stop button correctly **hidden**, `:430-454`).
- **(B) Correctly pinned BUT shown as greyed live-looking toggle — R-G1 VIOLATION (15):** `access-mode`=full, `enable-{keyboard,clipboard,file-transfer,audio,camera,terminal,tunnel,remote-restart,record-session,block-input(Win),privacy-mode,remote-printer(Win)}`, `allow-remote-config-modification`, `allow-only-conn-window-open` (greyed+fakeValue checkboxes `:813-905`); `enable-record-session` also greyed on Android. **This 15-toggle set is the concrete backbone of BR-14.**
- **Verdict:** the reject-set is **correctly scoped**; the defect is UI honesty — 15/28 rendered as greyed *actuating* toggles instead of read-only/removed (§19 live-looking-dead), compounded by the dead lock.

**Password PROVEN structurally excluded from the reject-set (CONFIRMED).** `is_option_can_save` operates only on the options HashMap; the password is `config.password`/`password_prs` — **struct fields** (`config.rs:236,1425`) written via `Config::set_permanent_password`. The user-owned typed IPC operation reaches that setter directly after the receiver ownership gate, bypassing `set_options`/`purify_options` by design, so the option reject-set **structurally cannot swallow the password.** BUILTIN/HARD funnels empty on a fork build (R-A4) → `is_disable_change_permanent_password`/`isUnlockPinDisabled`/`is_disable_settings` all false. The lockout is entirely the Dart `locked` gate. (Corrects the pre-audit hypothesis.)

**Every control trapped behind `locked` (exhaustive) — 5 non-pinned victims beyond the password:** `share-rdp` (Win), `allow-auto-disconnect`+timeout+Apply, `keep-awake-during-incoming-sessions`, the `unlock-pin` setter — all non-pinned/writable but locked out on Win/Linux. The **unlock-PIN is chicken-and-egg dead** (its only setter lives inside the card it would unlock).

**BR-2 one-way trap — fully source-determined; installer-elevation REFUTED.** `locked` is a non-persisted `_SafetyState` field; success `Offstage`-hides the button + releases AbsorbPointer ("disappeared"/"rearranged"), re-inits `true` on next tab build. The button can only vanish via a successful unlock (needs `is_elevated=true`), and the app **never produces an elevated GUI** → the "installer→elevated GUI" theory is **REFUTED**; the one success could only be a manual **"Run as administrator"** launch. Every ordinary launch → inert.

**BR-3 reconciliation (re-proven).** The connection-gated block is dead (`canBeBlocked()` always false — `IS_REMOTE_MODIFY_…` None for direct + `access-mode` pinned full). A live connection does NOT block settings; BR-3's "while connected" is a **misattribution** of the always-on `locked` gate; "no default to enable remote control" is moot (pinned ON, shown greyed).

**Sweep 1 — siblings.** (1) 5 non-pinned controls trapped by the lock; (2) unlock-PIN chicken-and-egg; (3) **`hide_cm()` orphaned dead code** — defined `desktop_setting_page.dart:937-975`, **never called** (§19); (4) the 15 greyed pinned toggles (R-G1). Verified-CLEAN (don't re-flag): Network/Account + SOCKS/ID-Relay removed (R-G4); Android verification/approve/OTP removed (R-X7a); `service()` hides "Stop" when pinned; typed user-owned password IPC arm + home dialog sound.

**Sweep 2 — platform (per cfg).** Win/Linux: unlock DEAD, settings-page password button locked, home password dialog works only when the receiver is user-owned writable, 15 greyed toggles, 5 non-pinned locked out. macOS: unlock WORKS then password+non-pinned editable, and the home password dialog works when user-owned writable; pinned stay greyed. Android: no lock, password works (`server_page.dart:60`+auto-prompt), pinned greyed. iOS: viewer-only. Shared `_Safety`/`_lock` on Win/Linux/macOS — only `check_super_user_permission` diverges.

**NEEDS-RUNTIME: none** source/framework-derivable. Sole residual is a *user-action* fact (whether the operator's one BR-2 success was a manual Run-as-admin launch — the only source-consistent path).

**Superseded by R-S11b/R-S11c for installed-service password setting.** User-owned mode may keep the
typed GUI/CLI password setter; installed service-owned mode requires a typed, admin-authorized service
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

### Cavity 5 — File-transfer host session/user context (BR-1): superseded Linux findings from 2026-07-07

**Status.** The original finding was correct for the then-current Linux path: file transfer, host audio,
chat, and voice depended on a desktop `--cm` process, while a headless/logind-less direct `--server`
could wait forever on a console session that would not arrive. The current Linux bootstrap no longer
uses `is_prelogin()` as that sole decision. `start_ipc` first recognizes `is_headless_no_console_user()`;
when no console user exists, the CM is launched as the authenticated `--server` process owner instead
of through `run_as_user(None)`.

**Current shape.** Linux still uses `loginctl` for seat0 discovery when logind exists, but the no-logind
case is now an explicit headless service-user case rather than a CM-spawn deadlock. R-S11c-10m also
removes the stale shared `run_cmds` shell API and keeps `loginctl` behind fixed, trusted executable
candidates. Windows pre-logon file transfer remains refused by design. Android remains in-process for
file operations. macOS headless is not converted by the Linux headless rule because `/dev/console`
does not give the same cheap no-console signal without risking login-window behavior.

### Adversarial-verification + completeness pass: FINDINGS (Opus 1M, read-only, 2026-07-07) ✅ — investigation confidence HIGH

**Verdict: all five cavities' core claims remain CONFIRMED** (independently re-traced). Net = two corrections, a materially larger cavity-5 scope, three cross-cavity misses, and one spec-violating treatment flag.

**Cavity 5 UNDER-COUNTED — the headless CM-spawn hang breaks a CLUSTER, not just file-transfer (CONFIRMED).** The `is_prelogin()`-gated `--cm` dependency also kills, on a logind-less Linux box:
- **F2 — Host audio** (`audio_service.rs:98-99` → `ipc::connect("_pa")`; the `_pa` server is CM-spawned only, `flutter.rs:1588`) → host→viewer audio breaks on headless Linux via the SAME hang. (Clipboard-text stays clean — in-process `arboard`.)
- **F3 — Whiteboard is no longer part of this hang cluster:** R-S11c-8 removed the prelogin wait and fixed `_whiteboard` connect/listen path; the helper now uses a launch-scoped endpoint and per-connection authority.
- **F4 — Chat + voice-call** are CM-hosted (`connection.rs:2782` `send_to_cm(ChatMessage)`; voice-accept via `rx_from_cm`) → non-functional with no CM.
So T5 fixes more than BR-1 (file-transfer + audio + chat/voice) without counting whiteboard as a remaining CM-spawn hang site.

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
  Follow-up 2026-07-11: macOS explicit service uninstall no longer writes the dead `stop-service` option, and `verify.sh` rejects desktop production Config/IPC writers for that key.
- **T3 — UI coherence remainder (cavity 3):** ✅ **DONE `79078c0`** — removed the directly-visible Linux "Allow linux headless" R-G1 toggle (it gates the compiled-out R-X14 subsystem → R-G1 *delete*, not read-only) + the dead WaylandCard (R-X12, verified-Offstage, −159 ln) + the §19 no-leftovers sweep of the orphaned Wayland/headless backends (`main_show_option`; the Wayland restore-token FFI/IPC chain + its `Data` variant + web stubs; 3 lang keys × 51 locales); kept the conditionally-live home-page Wayland cards + their keys. R-G8 branding flagged for operator (NOT rebranded; "Powered by RustDesk" already de-branded); ~1,200-line account/AB compile-out deferred. dart-verify + flutter-verify + verify.sh green; find-the-flaw APPROVE + reviewed the §19 sweep.
- **HELD for operator reconciliation:** the Printer (excising `enable-remote-printer` contradicts R-S16/R-D8/R-G7). BR-16 = already fixed at HEAD (ship-forward, no code).

### Deferred (post-treatment) audits — run AFTER the cavity decisions are made and the changes implemented
- **Android background battery-drain audit.** Once the Android controlled-side model (cavity #4) is finalized and built, specifically audit the battery cost of keeping the listener / foreground-service active in the background — Doze / App-Standby behavior, any wakelock / the R-T13 CPU-keepalive, the persistent FGS notification, and network-wake — to confirm that treating the phone as an always-reachable host does not hurt background battery life too much. The operator is pro-"Android-as-a-computer" but wants this validated. By nature partly a real-device measurement (NEEDS-RUNTIME), paired with a from-source review of what stays awake.

_Status (2026-07-07): **cavities 1 & 2 re-drills = EXHAUSTIVE / done** (all proven from source). Cav 1 = the Windows `--service`-death wedge (no SCM recovery; reboot recovers most triggers) + reboot-proof PRS-unavailable park (now diagnosed/gated by R-S9 read-state) + no slot leak possible. Cav 2 = the dead elevation-gated unlock on Win/Linux (macOS works, Android has no lock), the 28-key pinned set with **15 greyed R-G1 toggles = BR-14's backbone**, the password proven structurally un-swallowable, `hide_cm()` dead. **Cavity 3 = EXHAUSTIVE / done** (§19 largely already done R-G2..G7; surviving iceberg = 5 clusters: the unshipped-driver Printer BR-13 self-contradictory vs the native-driver-minimization pin; the tray "Stop service" mislabel+self-DoS shown-by-default with no non-destructive quit; the NOVEL directly-visible Linux "Allow linux headless" greyed R-G1 toggle; the desktop "Listening" config-lie [mobile has the honest 2-fact template]; the Android "Start service" mislabels; + ~1,200 ln deferred account/AB scaffolding + dead WaylandCard). **Cavity 4 = EXHAUSTIVE / done** (BR-17 boot-consent = `onStartCommand` requesting MediaProjection because the plumbed-but-unread `EXT_INIT_FROM_BOOT` never splits boot from Start; consent-on-connect PROVEN FEASIBLE via a notification / full-screen-intent [BAL constraint; sideloaded FSI]; BR-16 Terminal-opacity ALREADY FIXED at HEAD `8c0180d`, ship-forward; scam-dialog + ServerInfo-green-lie siblings). **ALL 5 CAVITIES = EXHAUSTIVE / done.** Cav 5 = BR-1 is only HALF-fixed: `8ec46d3` closed the "No active console user" refusal but NOT the real breakage — the file-transfer `--cm` process never spawns on a logind-less host because `start_ipc` hangs in `loop{if !is_prelogin() break}` and `is_prelogin()==true` with no seat0 (the fork's own smoke test asserts it); terminal/screen work in-process/X11; Android works because its CM is in-process. **The adversarial-verification pass = done; investigation confidence HIGH.** It confirmed every cavity core, EXTENDED cav 5 (the headless CM-hang breaks a cluster — file-transfer + audio + whiteboard [2nd hang site] + chat/voice), TIGHTENED cav 4 (consent-on-connect = tap-to-consent only), and found 3 cross-cavity misses (N1/F1 Android orphaned-listener race reopening "Stop-doesn't-stop"; N3 Linux crash-loop start-limit lockout; F5 MediaProjection release leak). One spec-tension HELD for operator reconciliation: excising `enable-remote-printer` contradicts R-S16/R-D8/R-G7. **Ledger `f0f4037` + T5 `98fc028` + T2 `b1c243c` pushed.** SEQUENTIAL IMPLEMENTATION (each: Opus 1M → find-the-flaw → my review → commit only if clean). **T5 DONE** (`98fc028`, headless CM cluster). **T2 DONE** (`b1c243c`, settings unlock/password + unlock-PIN excision). **T4 DONE** (`66ec419`). **T1 DONE** (`741d3b1`). **T3 DONE** (`79078c0`). ✅ **ALL 5 TREATMENTS COMPLETE** (T5 `98fc028`, T2 `b1c243c`, T4 `66ec419`, T1 `741d3b1`, T3 `79078c0` — each verified + adversarially reviewed + pushed to origin/master). **NEXT: Phase 4 — the full R-B2 rebuild** (cold double-build Debian/Android/Windows via `build-release.sh` + the gate suite) to byte-reproducibly confirm the whole implementation. **HELD for operator:** the Printer (R-S16/R-D8/R-G7 tension); consent-on-connect (UX, tap-to-consent design in cavity 4); the ~1,200-line account/AB compile-out (deferred); the R-G8 About-page branding (SHOULD). **Runtime confirmations that need real hardware:** the Windows `windows.rs` compile + SCM-restart (VM `.msi` build / a Windows box); the T5 file-transfer round-trip + the honest status (a rebuilt haggai `.deb`). Plus the deferred Android battery audit._

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
peer's media through in-process C codecs (libvpx/libyuv/opus/zstd + Windows
CLIPRDR; AV1/libaom is runtime-quarantined and no longer linked) — is dispositioned **`ACCEPT` + SHOULD-sandbox**: "a *universal residual*
... bounded operationally (connect only to peers you trust) ... recorded as a
**documented residual** not closable by keying — the fork SHOULD sandbox the
decode path." It is **not** a MUST.

**AV1/libaom runtime quarantine (closed 2026-07-11).**
Current public descriptions and upstream patches localize CVE-2026-56208/56209/
56210/56211 to encoder/control surfaces rather than a proven viewer decoder path.
The fork nevertheless closes the AV1 runtime exposure directly: AV1 is not
advertised by encoder or decoder capability messages, not accepted from
`codec-preference`, not offered in the desktop/mobile/toolbar UI, not benchmarked
at startup, not constructed by the server encoder config, and hostile peer
`Av1s` frames are locally unsupported before any native decoder or recorder
worker is created. A stale AV1 preference falls back to the normal software
policy, and VP9 remains the software fallback.

**AV1/libaom dependency removal (closed 2026-07-11).**
The runtime quarantine is backed by deletion of the native dependency itself:
`vcpkg.json` no longer lists `aom`; `res/vcpkg/aom`, `libs/scrap/src/common/aom.rs`,
and `libs/scrap/src/bindings/aom_ffi.h` are deleted; `libs/scrap/build.rs` no
longer generates `aom_ffi.rs`; `EncoderCfg` has no AV1/libaom variant; and the
offline Linux, Android, Windows, Apple source-conformance, dev-check, README,
build-Dockerfile, and tracked build-scaffold paths do not install, stub, or
reference `aom`. `docs/NATIVE-CODEC-WATCH.md` records `aom` as a retired library
rather than a watched package, and `verify.sh` fails if a future source module,
FFI binding, bindgen package, overlay path, manifest entry, build-Dockerfile,
build-scaffold, or ledger shape reintroduces libaom.

**The remaining native-decode residual is still armed, not latent (recorded 2026-07-05 under the universal-deployment re-rating).**
The pinned in-process decoders on the peer-reachable **viewer** path still carry
open native-memory-safety risk (see `docs/NATIVE-CODEC-WATCH.md`):
- **libvpx 1.15.2** — the VP8/VP9 decoder: **CVE-2026-1861**, a decoder heap buffer overflow (malformed
  video → OOB heap write; fixed in Chrome 144.0.7559.132 via "enhanced bounds checking in the libvpx
  decoder"). The pinned 1.15.2 (a 2025 release) predates the fix; the fixed libvpx commit is not yet pinned.
So the spec's "pinned ≠ CVE-free" caveat is **not hypothetical**: there is live
native codec risk on bytes an in-process viewer decodes when connected to a
hostile-but-password-correct box — in **every** binary (every build ships the
full viewer, R-R2b). This does not change the `ACCEPT`/SHOULD disposition, but
it keeps the SHOULD-sandbox a high-value open hardening item for the remaining
viewer decode/compression paths. The controlled/`--server` role is
**unaffected** by video decode: it encodes its own screen; its only inbound
native decode is Opus, gated behind an operator-accepted voice call (R-S19), plus
64 MiB-bounded zstd.

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
  operations. The service-owned credential/action class is now tracked and gated under
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
- **Apple R-R2 release gate integration — ✅ CLOSED 2026-07-11.** `scripts/apple-conform-check.sh`
  still runs outside the default fast `verify.sh` loop because it needs the `rd-apple-check`
  image plus Apple target cross-checks, but it is now part of the release source-gate bundle:
  `scripts/verify-release.sh` runs it with `verify.sh`, `smoke-server.sh`, `dart-verify.sh`,
  `native-codec-watch.sh`, `audit.sh`, `dart-audit.sh`, and `test-build-faillo.sh`. The fast
  verifier asserts that full bundle, including the Apple gate and the release-gate ledger/requirements
  wording, so future Apple-source drift fails release verification rather than passing a
  "complete/proven" milestone silently.
- **R-R3 dependency-advisory gates** — `scripts/audit.sh` builds a digest-pinned Rust 1.75 audit image,
  installs the pinned `cargo-audit` and `cargo-deny` versions from `scripts/pins.env`, bakes the pinned
  RustSec advisory-db snapshot, derives cargo-audit ignores only from `deny.toml` TOML ignore objects,
  then runs both `cargo-audit` and `cargo-deny check advisories`. `scripts/dart-audit.sh` runs pinned
  offline OSV for `flutter/pubspec.lock` and requires reason-bearing future accepts. `scripts/verify.sh`
  pins that structure; `scripts/native-codec-watch.sh` covers the vcpkg native-codec watch separately.
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
> fixed**. The detailed obsolete pin-item fixes are not retained as live implementation guidance. The
> non-pin items in this backlog (the dead-scaffolding excisions) stand.

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

- **[I-1/I-2/I-3] Retired host-key/fingerprint/pin GUI defects.** Closed by deleting the host-key
  identity, pin store, fingerprint surfaces, first-contact/mismatch dialogs, and related CLI/FFI
  rather than repairing them. The live design is pure password-PAKE with no per-box identity.

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

- **[I-8] Retired `--get-fingerprint` phantom-key race.** Closed by deleting the fingerprint/pin
  workflow with R-S17/R-P5. Desktop no longer mints a host key while answering metadata; mobile's
  legacy `key_pair` remains only as its documented at-rest wrapper key pending Keychain/Keystore work.

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
first spec change in this run that is not disclosure-only. The 2026-07-10 IPC/options audit added the
second normative closure in this area: R-S16's read funnel now explicitly includes whole-map option reads
(`Config::get_options` / UI cache / CLI `--option` / IPC `Data::Options(None)`), with pinned policy
overlaid last. The 2026-07-11 macOS service-owned-password hardening added parsed
LaunchAgent plist command-shape proof, R-S11e-2 client-side `_service` server authentication, and direct
authorization-before-password service requests with no pending plaintext cache; the Linux helper-provenance
follow-up added R-S11e-3 canonical target binding for fixed helper launches; the Windows elevated command-file
follow-up added R-S11d-32 identity and content binding across the close/reopen handoff. The other
requirements.html edits are disclosure/inventory updates, and the
native-codec-watch ledger is re-confirmed valid against each.
The current snapshot (matching the `docs/NATIVE-CODEC-WATCH.md` pin consumed by
`scripts/native-codec-watch.sh`) is:

```text
1dc8b83021e3d701a4a598d91aba9a626366b0e2620820ad15207fb978bf5ea1  requirements.html
```

`requirements.html` is not edited by routine implementation work; the only deliberate
exception is an audit-status disclosure update like this one, which re-pins the hash here,
and in `docs/NATIVE-CODEC-WATCH.md`.
