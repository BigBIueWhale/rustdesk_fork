# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Superseded work-log material (intermediate `PARTIAL`/`TODO`/deferred
notes, and — as of 2026-06-28 — the reverted native-worker-sandbox slices) is
removed from this live ledger because it is misleading as current status. Git
history remains the traceability record for that intermediate work.

## Current Verdict

> **Current `.6` source verdict (2026-07-14): implementation and release-harness state are tracked here. Artifact and reproducibility proof exists only for an exact clean pushed commit whose complete `scripts/build-release.sh` transaction succeeds and emits the matching `dist/SHA256SUMS`; this source ledger makes no publication claim.** Earlier artifact hashes in this file prove only the older commits named beside them and must not be promoted as evidence for the current source tree.

**Current machine inventory expectation.** `Cargo.lock` has 910 package records: 38 git-sourced records from
27 unique git source URLs, including 28 rustdesk-org records from 21 unique rustdesk-org URLs.
`flutter/pubspec.lock` has 199 package records, including 8 git records and 7 rustdesk-org records;
`flutter/pubspec.yaml` declares 58 main and 6 dev dependencies, a 64-name union. `.github/workflows/` has
zero enabled definitions, seven inert `.disabled` reference definitions, one documentation file, and eight
regular files total; Debian, Android, and Windows releases are script-owned targets, not CI jobs. `build.py`
has 531 lines and the tree has six tracked `build.rs` files. The legacy root Docker builder is absent;
there is no root `Dockerfile`, root `entrypoint.sh`, or translated upstream README build path. The Rust inventory has 766 lexical `unsafe {`
blocks across 243 tracked Rust files, 66 of which contain at least one; this is explicitly not AST proof.

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
`520 - name_len` underflow (each overflow-safe, unit-tested). The release harness
defines the required Debian/Android/Windows R-B2 cold double-build, and the Apple
SDK-free source-conformance gate covers the macOS/iOS code paths (R-R2). Current
artifact evidence is authoritative only through the exact-commit R-B2 manifest.

## RESOLVED — TCP tunneling hardening (2026-07-13)

PF-1 through PF-5 are closed for desktop port-forward and RDP mappings while the
sealed framed tunnel and `AuthConnType::PortForward` remain unchanged.

- **PF-1 — FIXED.** `LoginConfigHandler.port_forward` is deleted. The tunnel-only
  `Client::start_port_forward` API requires a private-field `PortForwardTarget`
  whose host is at most 253 bytes and is exactly an ASCII DNS name, IPv4 literal,
  or bracketed parseable IPv6 literal; whitespace, control bytes, NUL, empty hosts,
  unbracketed IPv6, and ports outside 1–65535 fail before connect/login. The target
  is passed by value through setup and directly into that connection's proactive
  login. Ordinary `Client::start` rejects `PORT_FORWARD`/`RDP` without the target.
- **PF-2 — FIXED.** Mapping listeners use `tcp::new_exclusive_listener` on
  `127.0.0.1`: no `SO_REUSEPORT` on Unix; Windows leaves `SO_REUSEADDR` unset and
  sets `SO_EXCLUSIVEADDRUSE` before bind. The shared exclusive socket path
  propagates option errors. Linux/macOS test a second exclusive bind; the native
  Windows test explicitly enables `SO_REUSEADDR` on a hostile second socket and
  proves that it cannot bind the occupied port.
- **PF-3/PF-4 — FIXED.** Every mapping owns one cancellation token and a `JoinSet`
  containing all accepted setup and relay work. A closed cancellation control and
  one-slot coalescing RDP-launch channel replace general `Data` lifecycle queues.
  Control close and sender EOF stop acceptance, cancel connect/CPace/login/relay,
  and join every task. The bounded-command supervisor, mapping tasks, and all joins
  live on a named OS thread with its own current-thread Tokio runtime. One
  process-lifetime reaper owns a closed 32-slot handoff queue and is the only code
  that calls `JoinHandle::join`. Normal close submits ownership with a completion
  reply; outer-future cancellation and startup failure submit ownership without a
  waiter. Every handoff is nonblocking. Reaper bootstrap failure, a full queue, or a
  disconnected queue is process-fatal rather than blocking an executor or detaching
  ownership. Command EOF globally closes and drains mappings before that independent
  runtime is destroyed. No claim extends past process death. Removal replies only
  after drain, and duplicate replacement creates/inserts the new mapping only after
  the old mapping and all its children have completed.
  Mapping ownership is process-bounded to 32 permits. Accepted connections are
  nonblockingly bounded to 32 per mapping and 128 process-wide; both permits live
  through setup and relay, and over-limit accepted sockets are dropped immediately.
  Completed connection tasks are eagerly reaped before another accept so sustained
  ready listeners cannot accumulate completed `JoinSet` entries.
- **PF-5 — FIXED.** Setup no longer receives or polls the local application stream.
  The local `Framed<TcpStream, BytesCodec>` reader is created only after `PeerInfo`;
  before authorization, buffering is limited to the kernel socket receive buffer.
  The obsolete pre-login `Vec`, `Data::Login`, and `Data::Message` setup paths are
  deleted. Local/remote read and write errors terminate the connection explicitly.

Deterministic Rust tests cover immutable interleaved targets, bounded host/port and
bracketed-IPv6 validation, cancellation in connect/keying/login/relay, control EOF,
owned-task drain, duplicate replacement ordering, the literal 32/33 mapping boundary,
the literal 32-per-mapping and 128-process connection boundaries with permit recovery,
sustained completion reaping, authorization-before-relay, and exclusive second bind.
Linux runs the shared native behavior tests. macOS and Windows retain source and
cross-compile gates for the same implementation; their native builders must execute
the platform bind test, including the Windows hostile-`SO_REUSEADDR` case. This Linux
host does not claim native Windows execution.

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
startup, graceful shutdown, and the no-plaintext wire-capture. Reproducible-build checks passed for the
historical commits recorded with that validation; this paragraph is not artifact evidence for the current tree.

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

**R-S14 macOS hardened-runtime JIT entitlement minimization — CLOSED / GATED (2026-07-11).**
Platform: retained macOS source-conformance path. Endpoint/action: Xcode entitlement selection for
Debug, Profile, and Release hardened-runtime builds. Boundary: future macOS app process executable-memory
rights ↔ the minimum entitlement set required by that build configuration. Attack surface closed:
the old combined `DebugProfile.entitlements` file is deleted. Debug now uses `Debug.entitlements`
and is the only configuration with `com.apple.security.cs.allow-jit`; Profile uses
`Profile.entitlements` with network-server profiler support but no JIT exception; Release uses
`Release.entitlements` with no JIT exception. The Xcode project binds each configuration to its own
entitlement file, and `scripts/apple-conform-check.sh` exact-matches the three macOS entitlement maps
plus the empty iOS entitlement map. This is not a root/LPE path; it removes an unnecessary
hardening-runtime executable-memory exception from Profile/Release while preserving the Debug-only
JIT case.

**R-S14 Android service-destroy capture-resource teardown — CLOSED / GATED (2026-07-11).**
Platform: Android controlled-side foreground service. Endpoint/action: `MainService.onDestroy()`,
explicit app Stop (`destroy()`), and the `MediaProjection`/`VirtualDisplay`/`ImageReader`/`Surface`
objects created for screen capture. Boundary: foreground-service lifetime ↔ all capture resources
derived from the user-granted projection token. Attack surface closed: service destruction no longer
stops only the `MediaProjection` while leaving the rest of the capture pipeline to process death or
implicit projection invalidation. `MainService.onDestroy()` and explicit `destroy()` both call
`releaseCaptureResources()`, which runs `stopCapture()`, releases the retained reusable
`VirtualDisplay`, and stops/clears `MediaProjection`; `stopCapture()` now nulls the released `Surface`
so the shared teardown is idempotent when explicit Stop later reaches `onDestroy()`. Verification
closure: `scripts/verify.sh` gates both lifecycle callers, the shared teardown sink, the
`stopCapture()`/`VirtualDisplay.release()`/`releaseMediaProjection()` chain, the nulled `Surface`, and
the retained `START_NOT_STICKY` restart barrier. This is not a root/LPE path; it completes the Android
R-D7a/R-S14 resource-lifetime invariant for retained capture grants.

**R-X6/R-S14 Android final APK manifest authority — CLOSED / GATED (2026-07-11).**
Platform: Android release APK. Endpoint/action: the single merged `AndroidManifest.xml` packaged into the
signed APK, after app/source/library manifest merging. Boundary: co-installed apps and library-provided
manifest declarations ↔ RustDesk app components, permissions, and controlled-side foreground services.
Attack surface closed: the shipped APK is no longer trusted by source XML inspection alone. The app
manifest removes merged `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, `SYSTEM_ALERT_WINDOW`, and
`androidx.profileinstaller.ProfileInstallReceiver`; `PermissionRequestTransparentActivity` and
`MainService` are explicitly `android:exported="false"`. `scripts/build-android.sh` now runs
`scripts/verify-android-apk-manifest.py` after `apksigner verify` and before hashing the signed APK.
The verifier parses `aapt2 dump xmltree` from the pinned SDK and requires package/minSdk/targetSdk,
`allowBackup=false`, the approved permission set, the exact final component inventory, and only
`MainActivity` exported with the launcher plus `rustdesk` deep-link filters. Any forbidden permission,
ProfileInstaller receiver, unexpected component, missing explicit exported flag, exported service,
exported receiver, exported provider, or additional exported activity fails the Android build. This is
not a root/LPE path; it makes the package authority claim true for the release artifact rather than only
for the source manifest.

**R-X6/R-S14 Android legacy JAR-signature META-INF authority — CLOSED / GATED (2026-07-11).**
Platform: Android release APK. Endpoint/action: package-manager signature verification for the shipped APK.
Boundary: Android 5.x/6.x v1/JAR signing compatibility ↔ runtime Java resources packaged under `META-INF/`.
Attack surface closed: the fork no longer ships an APK whose supported platform set includes API 22/23, where
v2/v3 APK signatures are ignored and arbitrary runtime `META-INF/` entries can remain outside the JAR-signature
integrity model. A historical prerelease artifact demonstrated the issue with `apksigner verify --verbose` warnings for
AndroidX/kotlinx metadata plus R8-shrunk `kotlinx.coroutines` service-loader resources; mutating
`META-INF/services/p5.v` still verified for an API 22/23 range, while API 24+ rejected the modified APK through
v2/v3 whole-APK verification. Those coroutine service resources are runtime library behavior, not removable
packaging junk, so the authority model changes at the support floor: `ANDROID_MIN_SDK`, Gradle
`minSdkVersion`, and the final APK manifest verifier now require API 24. `scripts/build-android.sh` signs with
`--min-sdk-version "$ANDROID_MIN_SDK"`, explicitly disables v1 signing, explicitly enables v2/v3 signing, and
runs `apksigner verify -Werr --min-sdk-version "$ANDROID_MIN_SDK" --verbose` before the final manifest verifier,
hashing, and double-build comparison. The build asserts v1 false, v2/v3 true, and no `not protected by signature`
warning. `scripts/verify.sh` gates the pin, Gradle value, manifest-verifier value, container signing pin,
v1/v2/v3 signing flags, warning-as-error verification, and this requirements/ledger disposition. Cost:
Android 5.x/6.x compatibility is intentionally removed.

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

**R-S11b/R-S11c/R-S11i — service-owned IPC authority — SOURCE IMPLEMENTED; CURRENT NATIVE WINDOWS WORKTREE VALIDATION AND FINAL CLEAN COLD RELEASE BUILD PENDING.**
Installed-service unattended credentials and machine remote-access policy are owned by the root,
LocalSystem, or LaunchDaemon authority that enforces them. Password bodies use only the raw `_password` and
`_service_password` protocols. Ordinary main and `_service` IPC contain no password-bearing request, generic
credential writer, whole-config import, or fallback. Path locality and executable equality are prerequisites,
not authority by themselves.

Tracking rule for this block: every remediation item must name the platform(s), endpoint/message/action,
privilege boundary, exact attack surface, and closure condition. A fix is not complete until the old path is
unreachable and a source/test/AST gate prevents reintroduction.

**Completed source slices:**
- **R-S11b-1 — Linux/macOS generic `_service` boundary — SOURCE IMPLEMENTED.** `_service` is a narrow,
  frame/deadline/capacity-bounded control protocol. It carries no password body, whole `Config`/`Config2`, generic
  config mutation, storage/salt write, or password mutation request. Linux service password mutation is on raw
  `_service_password`. macOS generic `_service` retains only no-secret right readiness and the narrow read-only
  runtime snapshot request/response, plus unrelated explicitly admitted service controls.
- **R-S11b-2a/R-S11c-1a — ordinary main IPC cannot mutate passwords — SOURCE IMPLEMENTED.** Service-owned
  receivers are marked by exact process role and reject user-owned mutation authority. Ordinary main IPC has no
  password-bearing request or write. Its password-related surface is limited to nonsecret capability/status data
  used before disclosure or after raw-operation admission. Whole-config, standalone salt, and storage/salt import
  paths remain absent.
- **R-S11b-2b/R-S11c-1b — user-owned raw password mutation — SOURCE IMPLEMENTED.** Linux and macOS use
  `_password`; Windows uses the same postfix as a first-instance local-only message pipe. The fixed raw protocol
  is outside serde, JSON, `Bytes`, `BytesMut`, `BytesCodec`, and `Framed`: a canonical 36-byte header identifies
  version, kind, UUID, and exact lengths; one bounded body follows; status is a canonical 32-byte operation-bound
  frame; Windows additionally requires a canonical 28-byte operation-bound ACK before disconnect. Peer authority
  is proved before secret-body transfer. Inbound bytes remain in one fixed 5120-byte wiping allocation transferred
  into redacted `SensitivePassword`; retries share its `Arc`. Temporary raw frames, unused tails, and
  `SensitiveAuthorization` wipe on drop/error. Android/iOS remain app-owned in-process paths.
- **R-S11b-2c/R-S11c-1d — Linux service-owned unattended password provisioning — SOURCE IMPLEMENTED.** The
  caller authenticates the root `--service` receiver before writing raw `_service_password`. The root listener
  snapshots and proves the caller from `SO_PEERCRED` before reading the secret body. The polkit subject is the
  socket-derived PID, UID, and `/proc/<pid>/stat` start time; only the exact trusted absolute `/usr/bin/pkcheck`
  and `com.carriez.RustDesk.set-unattended-password` action are admitted. `pkcheck` is polled under a 120-second
  bound and is killed and reaped on timeout, shutdown, or status failure. A 64-entry no-eviction admission ledger,
  keyed by process-random HMAC-SHA256 fingerprints, serializes one matching caller through `Authorizing`,
  `Committing`, `Recoverable`, and `Complete`. After authorization the root service authenticates the exact
  service-owned replica by uid, executable, argv, launch-parent environment, and live ancestry before sending the
  same UUID/value on raw `_password`; the child independently proves the root parent before reading it. Ordinary
  main IPC carries no password fallback. A nonsecret status query is used only for admitted uncertainty. The
  packaged polkit policy remains administrator-authenticated.
- **R-S11b-2d/R-S11c-1e — Windows service-owned unattended password authority — SOURCE IMPLEMENTED; CURRENT
  NATIVE WINDOWS WORKTREE VALIDATION PENDING.** The stable LocalSystem SCM service is the sole durable credential
  writer and replay/finality owner. Mutation enters through raw `_service_password`, not `_service` or an old
  service-main credential endpoint. One `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`,
  max-instances-one message pipe is held for process life and serially reused. The service DACL admits Interactive
  Users only to reach preauthorization; exact executable, finite client role, process generation, active principal,
  and process token are proved before header wait, so arbitrary Interactive Users cannot hold the server in a
  header read. Header-message impersonation precedes body allocation/read; body-message impersonation plus fresh
  executable/role, generation, process token, and stable active-session/principal proof precedes direct
  nonblocking admission. The active principal is sampled session-before, between, and after two token reads.
  Process handles include `SYNCHRONIZE`; clients request `FILE_WRITE_ATTRIBUTES` without `GENERIC_WRITE` or
  `FILE_CREATE_PIPE_INSTANCE`. `GetSecurityInfo` exact-matches the live kernel owner/group/DACL to the retained
  creation descriptor before reuse. Status must receive the matching operation ACK before `DisconnectNamedPipe`.
  Overlapped timeout performs `CancelIoEx` and exact `GetOverlappedResultEx` drain. Listener workers and the
  first-instance sentinel are process-lifetime owned; each client transaction has a dedicated supervisor that owns
  and joins the blocking worker across async cancellation. The exact service-owned child receives only a
  generation-bound read-only replica over `_service_credential`; `_service_main_control` remains independent.
  An authorized active-principal exact RustDesk role may consume bounded local work; arbitrary Interactive Users
  are rejected before header wait, and no password or administrator authority is exposed by either case.
- **R-S11b-2e/R-S11c-1f — macOS service-owned unattended password provisioning — SOURCE IMPLEMENTED; APPLE
  SOURCE-CONFORMANCE GATE AVAILABLE.** Generic `_service` proof and password `_service_password` proof use separate
  fixed capacities. The accepted socket's uid, effective-pid metadata, and `LOCAL_PEERTOKEN` audit token are
  captured immediately. Root PrivilegedHelperTools and installed-app code identities are checked from that audit
  token plus trusted installed path; no PID-only, path-only, or subprocess-code-signing fallback exists.
  Security.framework/code/launchd proofs run on exactly owned OS threads, return through one-shot ownership, and
  are synchronously joined; timeout, cancellation, panic, lost result, or lost join ownership aborts the process.
  The authenticated no-secret right-readiness exchange precedes the user-paced Authorization Services prompt; a
  fresh one-second raw transport deadline begins after the prompt. The dedicated right is admin-only, nonshared,
  and timeout zero. The external capability is self-wiping in Rust, and native create/verify stack copies use
  `explicit_bzero`. The root LaunchDaemon verifies the capability and commits the raw password operation. The
  64-entry no-eviction replay ledger uses a process-random HMAC-SHA256 key and retains no plaintext. The
  service-owned LaunchAgent receives only a nonpersistent runtime snapshot after installed-app audit-token proof,
  exact `--server --service-owned-server` live argv, launchd PID/path, and root:wheel non-writable ACL-free parsed
  plist proof for exact `Label`, `ProgramArguments`, `RunAtLoad`, and `KeepAlive`. Password mutation has no JSON
  request and no ordinary-main fallback. Shutdown closes admission, drains accepted tasks and mutations, then
  clears entries, HMAC key, and tags.
- **R-S11b-3a — service-marked server rejects ordinary options IPC — CLOSED 2026-07-08.** Platforms:
  Windows installed service-launched `--server`, Linux root-service-launched root or active-user `--server`,
  and macOS LaunchAgent `--server` source path. Endpoint/action: main IPC `MainIpcRequest::SetOptions`.
  Boundary: user-owned IPC caller ↔ service-owned remote-access policy. Attack surface closed: service-owned
  receivers reject typed option writes before `privacy_mode::switch` or `Config::set_options`; the daemon returns
  `MainIpcResponse::OptionsSet(IpcMutationResult::{Applied,Rejected,InternalFailure})`; IPC callers persist/cache
  only after `Applied` and do not locally persist when the daemon is unreachable. User-owned
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
  shape, generic config helpers, proxy IPC variant, and every password-bearing main request or handler sink;
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
  `Config::set_option`, `Config::set_options`, `MainIpcRequest::SetOptions`, and callers that sync or cache
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
  Platforms: Linux, Windows, and macOS desktop main IPC. Endpoint/action: the closed
  `MainIpcRequest`/`MainIpcResponse` protocol. Boundary: local IPC caller ↔ daemon-owned credential, identity,
  proxy, trust-anchor, and machine-policy state. Attack surface closed: adding a future IPC request cannot inherit
  authority through `_ => true`; the exhaustive handler classifies every request as a typed read, an
  authority-gated mutation, or a platform-specific validation. Any new `MainIpcRequest` variant fails compilation
  until it is classified, and `scripts/verify.sh` rejects wildcard handler arms. The
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
- **R-S11c-13 — service-owned process close has dedicated receiver authority — CLOSED 2026-07-09; tightened 2026-07-12.**
  Platforms: Windows installed service-owned main server; the Linux/macOS main protocol has no process-close
  request. Endpoint/action: process close is absent from `MainIpcRequest` and general `_service`. Windows uses the
  SYSTEM-only `_service_main_control` endpoint with typed `WindowsServiceMainRequest::Shutdown` /
  `ShutdownAccepted`. Boundary: local IPC peer ↔ service-owned process-control action. Attack surface closed: an
  ordinary main-channel or `_service` peer has no close vocabulary. SCM stop/preshutdown is the sole service-loop
  stop authority; the service authenticates `_service_main_control` as the exact retained child PID and creation
  time before requesting graceful shutdown. The child acknowledges on the control endpoint, closes admission,
  drains owned transactions and password finality, and only then exits. Verification asserts the closed main
  protocol, dedicated control endpoint and budget, exact-child authentication, absence of general `_service`
  close, and Appendix C #31.
- **R-S11c-14 — service-owned voice-call input IPC mutation gate — CLOSED 2026-07-10.**
  Platforms: Linux, Windows, and macOS desktop main IPC. Endpoint/action:
  `MainIpcRequest::SetVoiceCallInput`. Boundary: ordinary local main-IPC peer ↔ service-owned runtime audio-selection
  state. Attack surface closed: the last unconditional typed main-channel state mutation is no longer admitted
  for service-owned receivers. User-owned receivers keep the operation; service-owned receivers reject it
  regardless of ordinary/same-service peer identity because there is no service-owned voice-input control path
  that should ride the ordinary main IPC channel. Verification closure: `scripts/verify.sh` asserts the
  `allows_main_channel_voice_call_input_write` receiver-authority helper, the gated
  `MainIpcRequest::SetVoiceCallInput` handler arm, and absence of an unconditional service-owned write path.
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
  logs store/load/remove failures. Present-but-unreadable or corrupt TOML/raw encrypted payloads are preserved as
  sibling recovery files instead of being deleted, then immediately rehardened through a shared recovery-file
  helper: Unix opens the preserved file with `O_NOFOLLOW`, verifies the opened object is a regular file, and
  applies descriptor `fchmod(0600)`; Windows applies the same protected config DACL used for normal config files.
  Verification closure: `scripts/verify.sh` asserts the typed
  peer-config load status, exact-path loaded-and-semantically-default empty-peer cleanup, the raw helper shape,
  Windows ACL preparation, Unix owner-only permissions, Windows replace-existing/write-through replacement,
  corrupt-payload preservation and hardening, absence of direct `File::create(Self::path())` / ignored `write_all`
  in those stores, and the raw/TOML recovery permission, symlink-rejection, replacement, transient-load,
  RDP-password, and alias-path cleanup-policy regression tests.
- **R-S11c-2a/R-S11c-3a — Windows session selection removed; SAS is a dedicated service capability — CLOSED 2026-07-08; tightened 2026-07-12.**
  Platform: Windows installed service. Raw `Data::UserSid`, `Data::SAS`, and caller-selected session launch remain
  deleted. Remote Ctrl+Alt+Del is consumed as per-connection edge state before ordinary key injection and uses only
  `RequestServiceOwnedSasDispatch` on the dedicated one-slot SYSTEM-only `_service_sas` endpoint. General
  `_service` cannot dispatch SAS. The requester must be the exact live LocalSystem
  `--server --service-owned-server` generation retained by the SCM supervisor; the final dedicated worker retains
  a duplicate pipe handle and process handle, rechecks PID, creation time, liveness, token session, and LocalSystem
  under impersonation, reads `SoftwareSASGeneration` without mutation, and accepts only documented service values.
  `ServiceOwnedSasDispatchAccepted(true)` means the void `SendSAS` call was dispatched, not that secure-desktop
  activation was observed. Verification covers endpoint separation/budgets, SYSTEM-only DACLs, exact generation,
  final liveness, dedicated worker ownership, read-only policy, deadline ordering, and native Windows tests.
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
  server-validated FileTransfer sessions with server-validated file capability, so Remote, ViewCamera,
  Terminal, PortForward, unauthorized, id-zero, and no-file-capability sessions do not create CM file
  authority. Android remains an in-process channel and keeps the same receiver-side `CmFileAuthority`
  derivation before `handle_fs`. Verification closure: `scripts/verify.sh` runs `cm_file_authority_*`
  tests and source-gates the server token registry, the `ValidateCmConnection` callback, validation
  before `add_connection`, desktop `AuthorizedFS` token matching, desktop legacy `Data::FS` rejection,
  and Android pre-`handle_fs` gating; `scripts/apple-conform-check.sh` mirrors the desktop source
  assertion for macOS.
- **R-S11c-22 — Windows CM non-file clipboard authority — CLOSED 2026-07-11.**
  Platform: Windows installed/root server mode. Endpoint/action: the root clipboard service's helper
  request to `_cm` for non-file host clipboard content. Boundary: authenticated helper endpoint proof
  ↔ active Remote connection clipboard capability. Attack surface closed: the clipboard service no
  longer sends a bare `Data::ClipboardNonFile(None)` request after proving only the `_cm` endpoint.
  Each Windows `ConnInner` carries a `CmClipboardAuthority` lease with the connection id, validated
  CM connection type, and random `cm_auth_token`; the service selects that lease only from current
  clipboard-service subscribers and sends `Data::AuthorizedClipboardNonFile`. CM validates the tuple
  through the main server before calling `check_clipboard_cm()`. The server registry records a live
  `cm_clipboard` bit that is Remote-only, derives from `can_sub_clipboard_service()`, and is refreshed
  when peer clipboard/keyboard disable options change. FileTransfer, ViewCamera, Terminal, PortForward,
  no-subscriber, stale-token, wrong-token, wrong-type, disabled, and endpoint-proof-only requests do not
  read the desktop clipboard. Verification closure: `scripts/verify.sh` runs the Remote-only authority
  unit test and source-gates the authorized request variant, subscriber lease extraction, live registry
  bit, validation-before-read ordering, bare-request rejection, requirements disposition, and absence of
  `ClipboardNonFile(None)` sends from the Windows clipboard service.
- **R-S11c-23 — Windows Flutter runner Rust core DLL load provenance — CLOSED 2026-07-11.**
  Platform: Windows runner before Rust-side service/UI dispatch. Surface: `flutter/windows/runner/main.cpp`
  previously loaded the Rust core with bare `LoadLibraryA("librustdesk.dll")`. Boundary: root-capable Windows
  service/runner startup ↔ ambient DLL search order. Attack surface closed: the runner no longer delegates
  core module selection to the standard DLL search order before Rust-side service, IPC, or policy code runs.
  It resolves the running executable path with `GetModuleFileNameW(nullptr, ...)`, constructs the sibling
  absolute `librustdesk.dll` path, and calls `LoadLibraryExW` with
  `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`, `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`, and
  `LOAD_LIBRARY_SEARCH_SYSTEM32`, so dependency resolution is restricted to the bundle/application directory
  plus System32 rather than current directory or `PATH`. Startup fails closed if the executable directory or
  bundled core cannot be loaded. This was not promoted to a proven default standard-user-to-SYSTEM issue because
  the installed service bundle normally has `librustdesk.dll` beside the executable in Program Files, but a
  root-capable runner must bind its core to its own bundle and not to ambient process search state. Verification
  closure: `scripts/verify.sh` gates the executable-relative path, restricted `LoadLibraryExW` flags, absence of
  the bare DLL load, and requirements disposition.
- **R-S11c-24 — Desktop Dart FFI Rust core library provenance — CLOSED 2026-07-11.**
  Platform: Linux and Windows Flutter desktop Dart FFI initialization. Surface:
  `flutter/lib/models/native_model.dart` reopened the Rust core with bare `DynamicLibrary.open("librustdesk.so")`
  on Linux and bare `DynamicLibrary.open("librustdesk.dll")` on Windows after the native runners had already
  safely preloaded the bundled core. Boundary: privileged-capable desktop process ↔ platform library search
  semantics for the second FFI handle. Attack surface closed: the Dart FFI layer now follows the same bundle
  authority as the native runner. Linux resolves `Platform.resolvedExecutable`, derives its parent, and opens
  `lib/librustdesk.so`; Windows opens sibling `librustdesk.dll`. Android keeps the packaged `librustdesk.so`
  loader name, and macOS keeps `DynamicLibrary.process()` to avoid duplicating Rust global state. Verification
  closure: `scripts/verify.sh` gates the executable-directory helper, resolved-executable use,
  executable-relative Linux/Windows library paths, Android/macOS exceptions, init helper use, absence of bare
  desktop `librustdesk` opens, and requirements disposition.
- **R-S11c-25 — Windows terminal service principal authority — CLOSED 2026-07-12.** Platform: Windows
  installed-service and direct server modes. Endpoint/action: an authenticated remote Terminal login creating or
  reconnecting a persistent PTY. Boundary: service-owned LocalSystem server process ↔ its served Windows
  logon-session user. Attack surface closed: the terminal no longer decides whether to launch as a user from uninstall
  registry metadata. A stale compatibility uninstall key could make `is_installed()` false while the fixed-root
  `--server --service-owned-server` child was positively running as LocalSystem; the resulting no-token branch
  opened the shell directly in the service process. The authority now comes only from the proved process role.
  A service-owned LocalSystem server derives the served session from its own process token, obtains that session's
  `WTSQueryUserToken` token, proves that it is primary, and derives the reconnect principal from token session ID,
  user SID, and
  `TOKEN_STATISTICS.AuthenticationId`; any failure rejects Terminal before the connection's authorization-success
  edge. A direct non-LocalSystem server uses its process owner. The LocalSystem-without-session-token and
  service-owned direct-PTY states are rejected again at the terminal sink, and the helper itself refuses to run as
  LocalSystem. Persistent service IDs require canonical `ts_<UUID>` form and are atomically bound to the exact
  reconnect principal. Each entry owns the original primary token through a non-`Copy`, single-close RAII owner;
  reconnects never replace it with another token merely because the logon principal matches. Token object ID and
  modification ID are revalidated before launch. An exclusive opaque attachment lease carries entry identity,
  attachment generation, and authority epoch through every action, output read, persistence mutation, and cleanup;
  concurrent attachment is rejected and conditional `Arc` identity prevents stale-connection ABA removal. Same SID
  in another session or another logon session cannot attach to an existing PTY. Preparation reserves only attachment
  ownership before `authorized = true`; persistence and reconnect state remain staged, so failed preauthorization
  preserves an existing service and removes only a newly reserved entry. A current-authority checkpoint precedes the
  checked login-response write. With no option processing in between, activation consumes that checkpoint under the
  service lock, commits the staged persistence state, installs the exact subscriber, and makes output eligible; a
  concurrent revocation fails that minimal post-write transition and closes the connection. Opening records an
  epoch-bound reservation with a shared cancellation capability. A bounded ordered action worker, reached only by
  nonblocking `try_send`, creates the PTY/helper outside the Tokio connection task and service lock; revocation signals
  that same capability, helper pipe polling observes it, and a constructed direct child or helper job is already under
  `TerminalSession` ownership before later fallible work. Commit still requires the exact generation, epoch,
  reservation identity, and uncancelled capability. A committed or reconnected session remains output-invisible until
  its exact `TerminalOpened` response is enqueued under the service lock. Natural close response and exact-Arc removal
  share that lock, so neither output nor a delayed close can cross an ID reuse. Input and resize use nonblocking sends
  and linearize against the exact session Arc plus lease generation. Services are limited to 64 sessions, and each
  output poll has one shared 64-chunk/256-KiB budget across all sessions and replay; split tails remain owned for later
  polls. Sorted session IDs, a persistent rotating start cursor, and per-session quanta prevent a continuous producer
  from starving another terminal. Orderly exit becomes pending state and emits `TerminalClosed` only after replay,
  deferred tails, and the disconnected reader channel are exhausted across bounded polls. Direct PTY launch drops the
  parent's slave descriptor immediately after spawn and retains only the master, so child exit can end the blocking
  reader and complete that barrier. For an attached session's close response, reader-only completion starts a bounded
  direct-child status grace and re-queries the retained child on each poll; a real status wins, grace expiry is
  reported as `-1`, and writer failure remains immediate. Transport-worker completion is nevertheless immediate for
  reconnect admission and detached cleanup, so a dead persistent session is never republished during that grace.
  A service-entry monitor revalidates the served WTS principal after logoff
  events and every second even while detached. Revocation advances the epoch, marks action/output authority fatal,
  signals openings, takes the token, and drains exact session Arcs in one service-lock critical section; it then removes
  only that registry Arc and enqueues session teardown without waiting for a session mutex or join. Teardown admission
  transfers ownership to a bounded queue serviced by four fixed workers created before service admission. Every lease
  and opening reserves a global teardown permit before it can create resources; the permit remains owned through
  rollback or complete action/output/session-worker joins, so repeated replacement cannot grow pending teardown
  without bound. Queue insertion shares no mutex with worker cleanup. Session entries expose the shutdown atomic and,
  on Windows, a shared `TerminateJobObject` capability outside the session mutex, so revocation stops the helper job
  before deferred cleanup; an unexpected termination failure aborts the service so process teardown closes the sole
  service-owned job handle and activates kill-on-close rather than continuing with a revoked shell. The old revoked Arc
  cannot remove or mutate a replacement entry, so the opaque ID is immediately reusable by a new logon principal.
  Detached monitoring removes naturally exited direct/helper sessions by exact Arc identity and releases all live
  process, pipe, and job ownership rather than preserving a dead session as reconnectable. An attached connection observes the fatal latch on its
  one-second timer, and fatal persistence/action authority errors close it instead of becoming remote terminal
  diagnostics. The boolean `is_specified_user`, bare service-ID lookup,
  ignored service-creation error, registry selector, token-presence helper dispatch, and `ensure_primary_token` fallback are
  deleted. Microsoft documents that
  `WTSQueryUserToken` returns a primary token; the removed fallback called `DuplicateToken`, which produces an
  impersonation token that cannot be used by `CreateProcessAsUser`. The helper boundary is logon-scoped too: its
  pipe DACL names only SYSTEM and the token's enabled logon SID. The service owns a duplex server handle so
  `SetNamedPipeHandleState` has the documented mode-change access; the logon SID receives and requests only
  `FILE_WRITE_DATA|SYNCHRONIZE` for helper-to-service flow or `FILE_READ_DATA|SYNCHRONIZE` for service-to-helper flow,
  never generic-write/append/pipe-instance rights. The service then checks the connected client PID while retaining
  that process object and rechecks the helper process token's session, user SID, logon SID, and `AuthenticationId`.
  Pipe connection uses non-overlapped `PIPE_NOWAIT` polling with a timeout-and-authority-cancellable joined worker,
  then restores `PIPE_WAIT` before synchronous I/O; no pending stack `OVERLAPPED` exists. On helper shutdown,
  `CancelSynchronousIo` repeatedly targets both retained worker thread handles until each worker is observably
  finished before join, with only the documented `ERROR_NOT_FOUND` no-pending-operation race accepted; every framed
  input read also checks the shutdown latch before issuing another synchronous operation. An unexpected cancellation
  failure terminates the dedicated helper process while both join handles remain owned; it never detaches a worker and
  continues. The helper receives a
  non-inherited user environment and the same token's
  validated profile directory, with no service environment/current-directory fallback. It is created suspended,
  assigned before resume to a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job, and transferred as one RAII process-tree
  owner so revocation terminates the helper, ConPTY shell, and descendants before tracked join reaping. The retained
  helper process handle supplies its real exit status; the dedicated helper entrypoint exits with the shell code or
  status 1 on helper infrastructure failure, while transport/status-query failure is reported as `-1`, never clean zero.
  Helper output EOF receives a three-second status grace, longer than the two-second I/O cancellation deadline, before
  it is classified as transport failure; writer failure remains immediate.
  Verification closure: the Linux-visible 47-test terminal suite covers process-role combinations, canonical IDs,
  exact session/SID/logon-ID binding, exclusive attachment, generation/epoch advance, replacement-entry and
  closed-session ABA, dead-reconnect sync preservation, preactivation rollback, post-checkpoint worker-failure rejection,
  in-flight opening cancellation, detached revocation, and reader- or writer-terminated dead-session removal, stale
  opening/proxy/output rejection, opened-response publication, second-generation close ABA, held-session-mutex
  monitor/activation bounds, committed-plus-opening session limits, fair bounded continuous-refill output polling,
  synthetic and real-PTY multi-poll final-output-before-close ordering, bounded permit release, nonblocking teardown admission, completed
  detached teardown, helper/direct reader-status grace and direct status re-query, immediate writer-failure classification,
  permanent fatal-output quiescence, fatal persistence/action propagation, and nonblocking
  input/action backpressure. Windows-only helper
  tests create both real pipe directions, prove blocking round trips after `PIPE_WAIT` restoration, exercise external
  opening cancellation and pending synchronous-read cancellation across read re-entry, and cover exact client masks, principal comparison,
  and job ABI layout. `scripts/build-windows.ps1` runs the terminal suite natively, offline and locked, before every
  artifact build; `scripts/verify.sh` runs the Linux-visible suite and gates that native-Windows step plus the source
  contracts above. The committed Windows VM double build remains the platform runtime and deterministic-artifact proof.
- **R-S11c-26 — protected service IPC resource boundary — SOURCE IMPLEMENTED; NATIVE/ARTIFACT EVIDENCE IS
  OWNED BY THE EXACT-COMMIT R-B2 TRANSACTION.** Platforms: Linux, macOS, and Windows installed-service IPC.
  Endpoint/action: generic `_service` controls and read-only snapshots, raw `_service_password` mutation, Windows
  `_service_credential`, `_service_main_control`, and `_service_sas`. Boundary: kernel-proved local peer ↔ bounded
  root/LaunchDaemon/LocalSystem work ownership before receiver-authorized dispatch. Generic `_service` uses the
  32 KiB protected codec, one request, bounded read/write deadlines, and fixed transaction capacity; it contains no
  password body. Raw `_password`/`_service_password` are outside serde/`Bytes`/`Framed`, use canonical fixed frames
  and one fixed wiping body allocation, and require mutual endpoint proof before secret transfer. macOS keeps generic
  and password proof capacities separate: no-secret right readiness completes, the user-paced Authorization Services
  prompt runs, and only then does a fresh one-second raw transport deadline begin. Linux binds raw service-password
  admission to socket identity and bounded polkit. Windows holds one first-instance max-instances-one local message
  pipe for process life, serially reuses it, rejects wrong principal/role before header wait, and retains exact
  listener/client supervisor and overlapped-cancellation ownership. Service control, read-only replica, and SAS use
  independent endpoints and budgets. Linux/macOS task owners and Windows supervisors drain every accepted operation
  during shutdown; admitted password mutation is not aborted, and replay entries, tags, and keys are cleared only
  after drain. Passwords are capped at 4096 bytes and macOS authorization at 1024 bytes. Verification closure:
  `scripts/verify.sh` gates the generic protected-service envelope, raw protocol, endpoint separation, capacities,
  timeout/admission ownership, and non-aborting drain; `scripts/apple-conform-check.sh` mirrors the macOS source gates.
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
  root service state; service-owned unattended password provisioning remains the raw `_service_password` plus
  socket-bound polkit path.
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
  state; service-owned unattended password provisioning remains the raw `_service_password` plus socket-bound
  polkit path. Verification
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
- **R-S11d-1 — Windows Amyuni IDD helper launch provenance — CLOSED 2026-07-10; tightened 2026-07-12.** Platform:
  Windows runtime virtual-display helper path. Endpoint/action: `deviceinstaller64.exe` under `usbmmidd_v2`,
  launched to install/remove the Amyuni virtual-display driver. Boundary: installed Program Files helper payload ↔
  service/runtime helper execution. Attack surface closed: the runtime helper derives `usbmmidd_v2`,
  `deviceinstaller64.exe`, and `usbmmIdd.inf` only from the fixed
  Program Files service root returned by `fixed_service_install_path("")`, requires handle-level identity between
  the running executable directory and that fixed service root plus identity between the running executable and the
  fixed installed service executable, rejects reparse/symlink-backed helper directories, helper files, and INF
  files, propagates helper-path trust failures instead of falling through to SetupAPI, and executes
  `paths.exe_path` as the `CreateProcessW` application path. MSI explicit-uninstall cleanup is self-contained
  SetupAPI code and launches no installed helper. Verification closure: `scripts/verify.sh` asserts the runtime
  fixed-root file-identity proof, non-reparse helper/INF checks, absolute-path helper launch, and `paths.exe_path`
  launch, rejects swallowed
  helper trust failures, lossy path/INF fallback, `ShellExecuteA`, and bare `INSTALLER_EXE_FILE` launch, and checks
  this ledger/requirements disposition.
- **R-S11d-2 — Windows Amyuni IDD cleanup completion authority — CLOSED 2026-07-10.** Platform:
  Windows MSI commit-phase explicit-uninstall custom action. Endpoint/action:
  `RemoveAmyuniIdd` removing the `usbmmidd` Amyuni virtual-display device through SetupAPI. Boundary: installed
  privileged driver state ↔ privileged MSI cleanup state. Attack surface closed: cleanup no longer hides native
  SetupAPI failure from MSI. The native path returns a `DriverUninstallStatus` plus `HRESULT`:
  complete enumeration proving no present matching hardware ID is a successful no-op, successful removal of all
  matching present devices is success, and enumeration/property/class-installer/remove failures are fatal. The
  commit action has no `CustomActionData`, install-root, installed-helper, or process-launch dependency. It signals
  SetupAPI reboot-required state through WiX, and the WiX action is `Return="check"`. The action is
  scheduled only after a successful explicit uninstall transaction; upgrade preserves the installed driver. Stale
  bare-`netsh` `ShellExecuteW` firewall helper examples and their
  commented reactivation path are deleted. Verification closure: `scripts/verify.sh` asserts the native status
  contract, HRESULT propagation, complete-enumeration/not-present branch, MultiSZ hardware-ID scan, reboot
  signaling, explicit-uninstall commit scheduling, absence of installed-helper/caller-data dependencies,
  `RemoveAmyuniIdd` `Return="check"`, and this ledger/requirements disposition.
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
- **R-S11d-8 — Windows RDP viewer credential handling and command provenance — CLOSED 2026-07-13.** Platform:
  Windows viewer-side RDP tunnel convenience. Endpoint/action: launching `mstsc.exe` for an ephemeral loopback
  tunnel. Boundary: same-user viewer credential handling and local command provenance, not a service/SYSTEM
  escalation path. Attack surface closed: RustDesk no longer accepts, stores, transports, seeds, snapshots,
  restores, or deletes an RDP username or password. The legacy `rdp_username` and `rdp_password` peer options are
  retired and removed whenever peer configuration is loaded or stored, with the legacy file rewritten without
  them. The tunnel supervisor receives only the remote port. It resolves `mstsc.exe` through the checked
  `GetSystemDirectoryW` trusted-tool resolver and launches it with exactly the ephemeral
  `/v:localhost:<port>` endpoint and `/prompt`; authentication and any OS-approved credential retention remain in
  the trusted Windows RDP client UI. Verification closure: `scripts/verify.sh` asserts the exact argument set,
  trusted executable resolution, retired-option scrubbing and rewrite tests, absence of credential UI and
  transport, and absence of `cmdkey`, ambient `mstsc`, Credential Manager APIs, `TERMSRV/localhost`, password
  arguments, environment plumbing, and credential leases.
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
  string while leaving `lpApplicationName` null. The Rust FFI now passes an explicit application path, a
  separately quoted command line, and the executable parent as explicit current directory; the C++ side requires
  all three, copies the command line into a dynamically sized mutable buffer, and calls `CreateProcessAsUserW`
  with the explicit application path and current directory. Token-switched Rust launches require an absolute
  existing executable file, reject NUL-bearing application/current-directory/argv/environment data, use Windows
  command-line quoting for argv, and reuse the same provenance helper for service-owned `--server` and
  user-session helper launches. The old preformatted command-string wrapper is deleted.
  Verification closure: `scripts/verify.sh` asserts the explicit application-name/current-directory FFI shape, absence of
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
- **R-S11d-37 — Windows service-owned server child executable provenance — CLOSED 2026-07-11.**
  Platform: Windows installed service. Endpoint/action: LocalSystem `--service` spawning the service-owned
  `--server --service-owned-server` child, the service-owned `--server` entrypoint, and service-owned main-IPC
  receiver authentication before password-bearing commits. Boundary: fixed Program Files service executable ↔
  LocalSystem service-owned child/process authority. Attack surface closed: after R-S11d-13 the child launch was
  already bound to `lpApplicationName`, but that application was still chosen from `std::env::current_exe()`.
  The service-owned child image is now derived from `fixed_service_install_path("")`; the fixed service directory,
  running service directory, fixed service executable, and running service executable are opened no-follow and must
  be non-reparse regular directory/file objects as appropriate; Win32 handle identity must prove running directory
  == fixed service root and running executable == fixed service executable before the child is launched. The child launch then passes
  that fixed executable and its parent directory to `CreateProcessAsUserW`. `core_main.rs` refuses a Windows
  service-owned `--server` marker unless the process is LocalSystem and the same fixed-root proof succeeds. The
  service-owned main-IPC authenticator now proves the named-pipe server executable against the fixed service
  executable before the existing LocalSystem and exact `--server --service-owned-server` argv checks, so
  password-bearing service commits no longer authenticate the receiver against the caller's current executable.
  Verification closure: `scripts/verify.sh` asserts the fixed service executable helper, no-follow non-reparse
  directory/file checks, handle-identity comparisons, service-owned launch helper use, explicit child current directory,
  service-owned entry guard, fixed-exe main receiver proof, exact argv helper, absence of the old current-exe
  service-owned receiver proof, and this ledger/requirements disposition.
- **R-S11d-38 — Windows inactive RustDesk IDD loader excision — CLOSED 2026-07-12.**
  Platform: Windows virtual-display runtime, build/package graph, and Flutter client/UI compatibility surface.
  Endpoint/action: the inactive RustDesk IDD implementation, its `libs/virtual_display` wrapper and
  `dylib_virtual_display` plugin, Windows package staging, peer platform additions, and virtual-display toolbar
  controls. Boundary: privileged installed desktop/service package ↔ native plugin loading and driver-control
  implementation authority. Attack surface closed: the fork no longer builds, packages, loads, advertises, or drives
  the unsupported RustDesk IDD implementation. The only supported Windows virtual-display implementation is Amyuni:
  `virtual_display_manager` owns the small `MonitorMode` shape and dispatches to `amyuni_idd`, the Windows build no
  longer compiles or copies the dynamic plugin DLL, Cargo no longer includes the deleted crates, and client/UI
  support accepts only `amyuni_idd` for virtual-display controls. Verification closure: `scripts/verify.sh` asserts
  the deleted crate directory is absent, the workspace/dependency/lockfile/build-copy artifacts are absent, legacy
  RustDesk IDD platform-addition/UI names are absent from source/build metadata, `MonitorMode` is owned by
  `virtual_display_manager`, and this ledger/requirements disposition.
- **R-S11d-39 — Windows obsolete updater authority excision — CLOSED 2026-07-12.**
  Platform: Windows normal GUI startup plus the cross-platform Flutter FFI and UI residue of the removed
  self-updater. Endpoint/action: an unconditional startup sweep over old `rustdesk-*.msi` and
  `rustdesk-*.exe` files in `std::env::temp_dir()`, the uncalled `download-file-<version>` asset-name query,
  its Windows registry probe, and updater-only Flutter state and translations. Boundary: a process that may
  run elevated ↔ ambient temporary-directory files without producer, owner, or provenance proof. Attack
  surface closed: the updater has no supported producer or consumer, so the fork deletes the sweep instead of
  assigning ownership semantics to an obsolete facility. Normal startup no longer enumerates or deletes
  installer-shaped files from ambient temporary storage; the dead FFI query, registry helper, state field,
  comments, and four exclusively owned language keys are absent on every desktop platform. This was not
  promoted to a confirmed default local-to-SYSTEM exploit: the observed deletion used `remove_file`, and no
  supported updater path supplied a victim file. It was still invalid filesystem authority in a
  privileged-capable process. Verification closure: `scripts/verify.sh` gates absence of the Rust sweep,
  filename query, MSI probe, Dart state, updater-only translation entries, and this ledger/requirements
  disposition; `scripts/dart-verify.sh` independently gates the Flutter state and UI strings.
- **R-S11d-25 — Windows Amyuni SetupAPI install reboot-required completion — CLOSED 2026-07-10.**
  Platform: Windows runtime Amyuni virtual-display driver install fallback. Endpoint/action: direct SetupAPI
  `win_device::install_driver()` path used when the AMD64 `deviceinstaller64.exe` helper is unavailable. Boundary:
  driver install/update completion ↔ immediate virtual-display use. Attack surface closed: direct SetupAPI install
  can no longer report success when `UpdateDriverForPlugAndPlayDevicesW` sets `reboot_required`, because that state
  means the driver cannot be treated as immediately usable. The fallback now follows the same install/update policy
  as the checked helper path: reboot-required install fails closed before `check_install_driver()`
  returns and before monitor plug-in proceeds. Remove/cleanup reboot-required remains accepted under the cleanup
  policy; this entry is only the install/update fallback. Verification closure: `scripts/verify.sh` asserts the
  direct SetupAPI install call, the `reboot_required` branch, fatal install reboot-required error, absence of the old
  discarded install result shape, and this ledger/requirements disposition.
- **R-S11d-26 — Windows app-name identity contract — CLOSED 2026-07-11.** Platform: Windows
  signed custom-client runtime config and MSI packaging. Endpoint/action: custom `app-name` reaching executable
  names, install paths, URI scheme, service name, HKCR/HKLM registry keys, firewall rule labels, and shortcuts.
  Boundary: signed/build-time branding input ↔ privileged Windows system identifiers.
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
  Windows runtime/service-adjacent path selection. Endpoint/action: active-user home fallback and root recording
  directory selection. Boundary: Windows system/profile root authority ↔ process environment text. Attack surface
  closed: profile and ProgramData roots no longer derive from `SystemDrive`. Active-user home uses
  `FOLDERID_UserProfiles` plus a single-component username guard before joining; root recording uses the shared
  `FOLDERID_ProgramData` helper and fails closed if resolution fails. Verification closure: `scripts/verify.sh`
  rejects `SystemDrive` in the affected Windows sources and asserts the known-folder, username-component, and
  root-recording invariants.
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
- **R-S11d-33 — Windows MSI deferred install-root provenance — CLOSED 2026-07-11; narrowed 2026-07-12.** Platform:
  Windows MSI deferred no-impersonation runtime-generated broker cleanup. Boundary: MSI execution-script
  `CustomActionData` and directory resolution ↔ LocalSystem file authority. Attack surface closed: the
  package-level private `App.InstallFolder` proof is no longer the only check before the deferred DLL consumes
  privileged install-root state. `res/msi/CustomActions/CustomActions.cpp` now normalizes deferred install folders,
  rejects empty/relative/root/path-too-long values, requires the install directory to be an immediate child of
  `FOLDERID_ProgramFiles` or `FOLDERID_ProgramFilesX86`, requires the Program Files parent and any existing install
  directory to be non-reparse directories, and uses the normalized install folder only for exact runtime broker
  cleanup. Service state is declarative and Amyuni cleanup is a self-contained SetupAPI commit action after
  R-S11e-20; neither consumes install-root custom action data. This is
  privileged-state correctness hardening, not a newly proven low-privilege LPE in the
  current MSI: the package already keeps `App.InstallFolder` private under `ProgramFiles6432Folder` with no browse
  surface. Verification closure: `scripts/verify.sh` gates the Program Files directory declaration, absence of
  directory-setter UI/actions, the native install-root validator, normalized runtime cleanup root, absence of
  unrelated consumers, and this ledger/requirements disposition.
- **R-S11d-16 — Windows MSI service-state and SAS policy persistence — CLOSED 2026-07-10.**
  Platform: Windows MSI install/upgrade/uninstall and runtime Ctrl+Alt+Del. Endpoint/action: per-machine
  LocalSystem service creation/start and HKLM `SoftwareSASGeneration` handling. Boundary: installing user's
  profile/config and installer UI properties ↔ per-machine service presence and machine policy. Attack surface
  closed: MSI no longer reads `[AppDataFolder]...\config\...\toml` or any `stop-service` property to decide
  whether to create/start the service. The MSI service path now follows the fork's pinned runtime policy:
  declaratively create/start the per-machine service on install/repair/upgrade and stop/remove it on uninstall or
  upgrade. The obsolete `STOP_SERVICE`, `SetPropertyServiceStop`,
  `SetPropertyFromConfig`, `SetPropertyIsServiceRunning`, `TryDeleteStartupShortcut`, and `ReadConfig` custom
  action surfaces are deleted. Persistent installer writes to `SoftwareSASGeneration` are deleted from both MSI
  installer paths; no uninstall-time blind delete is added because prior installers did not record
  ownership or the original machine-policy value. Runtime SAS does not mutate `SoftwareSASGeneration`: it opens
  the policy read-only, accepts only the documented service-enabled values `1` and `3`, and rejects absent,
  malformed, unsupported, Ease-of-Access-only, or disabled policy before `SendSAS`. Verification closure:
  `scripts/verify.sh` asserts declarative MSI service ownership, absence of the deleted service/config/SAS custom
  actions and persistent installer SAS writes, the runtime
  known-value-only read-only policy decision, caller result propagation, and this ledger/requirements disposition.
**Release-blocking source items — implemented; final validation remains open:**
- **R-S11b-2 — installed-service unattended password ownership.** Windows installed service, Linux installed
  service, and macOS LaunchDaemon mode terminate credential mutation in the privileged authority that enforces the
  credential. Android is app-UID/service-owned; portable desktop mode remains user-owned. Password bodies exist
  only on raw `_password`/`_service_password`, after mutual endpoint proof. Ordinary main and `_service` IPC carry
  no password mutation, generic credential/config write, whole-config import, or storage/salt write. Linux adds
  socket-bound polkit authorization and exact root-parent/service-replica proof. macOS adds a dedicated
  nonshared timeout-zero Authorization Services capability, root helper/installed-app audit-token proof, and exact
  LaunchAgent runtime-snapshot proof. Windows terminates mutation in the stable LocalSystem SCM authority and gives
  the retained child only a generation-bound read-only replica. The final clean committed cold release build and
  current native Windows worktree validation are still required.
- **R-S11e — Linux polkit policy/package assurance — CLOSED 2026-07-10.**
  Platform: Linux `.deb` installed-service mode. Endpoint/action: the single local admin-authorized
  service-owned unattended-password change. Boundary: user-session process and distro-local polkit policy
  state ↔ root service credential commit. Attack surface closed: no new credential mutation path is added;
  raw `_service_password` remains the only Linux service-owned password ingress, using
  the SO_PEERCRED-derived peer process subject, `/usr/bin/pkcheck --action-id ... --process ... --allow-user-interaction`,
  and a root-service raw `_password` commit into the proved service-owned replica. This slice closes the residual assurance
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
- **R-S11e-2 — macOS service client-side server authentication — SOURCE IMPLEMENTED.** Generic `_service`
  carries only no-secret readiness/runtime-snapshot control; raw `_service_password` carries mutation. Both client
  paths snapshot peer uid, effective-pid metadata, and `LOCAL_PEERTOKEN` immediately and prove a root peer whose
  Security.framework live code satisfies the pinned privileged-helper requirement at the exact trusted
  `/Library/PrivilegedHelperTools/com.carriez.rustdesk_service` path. Root:wheel ownership, non-writable
  directory/file mode, executable type, no symlinks, and no extended ACLs are required. Effective pid is metadata,
  not code authority. No unauthenticated, PID-only, path-only, or subprocess-code-signing fallback exists, and no
  password body is sent before the raw endpoint proof completes.
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
- **R-S11e-4 — macOS service proof ownership — SOURCE IMPLEMENTED.** Generic `_service` and password
  `_service_password` have independent proof capacities. The accepted socket's uid, effective-pid metadata, and
  `LOCAL_PEERTOKEN` are captured immediately. Security.framework proof executes on a dedicated exactly owned OS
  thread and is synchronously joined; timeout, cancellation, panic, lost result, or lost join ownership aborts the
  process. No generic frame or raw password header/body is read before endpoint proof succeeds.
- **R-S11e-5 — Linux service-owned replica receiver proof — SOURCE IMPLEMENTED.** After polkit authorization,
  the root service connects to raw `_password` and authenticates the replica from `SO_PEERCRED`, current executable,
  exact `--server --service-owned-server` argv, service-parent environment, expected uid, and live ancestry before
  sending the body. The child independently authenticates the root `--service` parent before reading it. No
  password value is constructed in or sent through ordinary main IPC; that channel can only recover nonsecret
  status after admission.
- **R-S11e-6 — Linux `_service_password` client-side server authentication — SOURCE IMPLEMENTED.** The caller
  connects to raw `_service_password` and proves the receiver is uid 0, the current trusted executable, exact
  `--service` role, and rooted in non-writable trusted path metadata before sending the canonical header/body. A
  path squatter or non-root/wrong-role process receives no password bytes. Generic `_service` carries no password
  request.
- **R-S11e-7 — user-owned permanent-password receiver authentication — SOURCE IMPLEMENTED.** Linux/macOS
  `_password` mutually proves same uid, current executable, and exact user-owned server role before secret-body
  transfer. Windows `_password` mutually proves exact executable/role/generation/token on the retained first-instance
  pipe. The nonsecret writability query cannot redirect the subsequent raw operation, installed-service routing is
  preferred, and status recovery reuses the same UUID/value without an ordinary-main password write.
- **R-S11e-8 — macOS service-owned password right normalization before authorization — SOURCE IMPLEMENTED.**
  Platform: macOS installed-service mode. Endpoint/action: no-secret right readiness through authenticated generic
  `_service`, followed by user-paced Authorization Services and raw `_service_password`. Boundary: UI/CLI password entry and Authorization Services
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
  the authorization grant. The prompt is intentionally outside the bounded proof worker; a fresh one-second raw
  transport deadline starts after it returns. Verification closure: `scripts/verify.sh` and
  `scripts/apple-conform-check.sh` gate the readiness request/result, generic service allowlist, ordering from
  authenticated readiness through `AuthorizationCopyRights` to fresh raw transport, exact native dictionary
  validation, absence of the old existence-only helper, and this requirements/ledger disposition.
- **R-S11e-9 — macOS service audit-token peer code identity — SOURCE IMPLEMENTED.**
  Platform: macOS installed-service mode. Endpoint/action: generic `_service` and raw `_service_password`
  client-side server authentication, receiver-side admission, and the read-only runtime snapshot requester. Boundary:
  local Unix-domain socket peers ↔ root privileged helper/app credential authority. Attack surface closed: macOS
  `_service` code identity no longer depends on re-observing an effective pid/path or shelling out to filesystem
  `codesign` after accept. The connected socket's uid, `LOCAL_PEEREPID` metadata, and `LOCAL_PEERTOKEN` are captured
  as `MacosPeerProcessIdentity`; Security.framework resolves live peer code from the audit token through
  `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)`; app/helper requirements are validated with
  `SecCodeCheckValidity(..., STRICT_VALIDATE)`; and the path from `SecCodeCopyPath` is used only for secondary
  installed-location, owner, mode, symlink, and ACL checks. `_service` client auth now requires a root peer whose
  audit-token code is the trusted privileged helper; receiver admission snapshots carry the audit token into an
  exactly owned OS-thread proof that is synchronously joined before any generic frame or raw password header is read;
  timeout, cancellation, panic, lost result, or lost join ownership is process-fatal. The runtime snapshot requester must be the
  audit-token trusted installed app before launchd argv/plist proof is considered. There is no unauthenticated,
  PID-only, path-only, or subprocess-code-signing fallback. Verification closure: `scripts/verify.sh` and
  `scripts/apple-conform-check.sh` gate the direct `security-framework` dependency, `LOCAL_PEERTOKEN`,
  `LOCAL_PEEREPID`, legacy `LOCAL_PEERPID` absence, audit-token identity capture, native strict validation, Rust
  `MACOS_CODESIGN` absence, service-client/server/snapshot wiring, exactly owned proof-thread joins, and this
  requirements/ledger disposition.
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
- **R-S11e-11 — Windows service-owned password receiver proof — SOURCE IMPLEMENTED; CURRENT NATIVE WINDOWS
  WORKTREE VALIDATION PENDING.** Mutation terminates directly in the stable LocalSystem SCM service on raw
  `_service_password`. The client authenticates the fixed service image, LocalSystem token, exact service role,
  and process generation before sending. The process-lifetime first-instance listener preauthorizes the exact
  active-principal RustDesk role before header wait, proves the header message by impersonation before body read,
  and revalidates the body message plus fresh process/token/session identity immediately before nonblocking
  admission. The retained child is never a durable commit receiver; `_service_credential` supplies only its
  generation-bound read-only replica.
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
  the FileTransfer login shape, CM FileTransfer-only file-authority binding, Unix headless username/refusal
  guards, and the FileTransfer capability confinement set. No runtime behavior changed in this slice.
- **R-S11e-15 — Linux pkcheck request-time peer identity binding — SOURCE IMPLEMENTED.**
  Platform: Linux `.deb` installed-service mode. Endpoint/action: local admin-authorized
  service-owned unattended-password changes through raw `_service_password`. Boundary: untrusted local IPC
  subject ↔ root service polkit authorization and credential commit authority. Attack surface closed: the root
  service no longer builds the `pkcheck --process pid,start-time,uid` subject from split observations after the
  accept-time executable proof. `linux_polkit_subject_for_peer` now derives the subject from
  the accepted raw socket identity, so the request-time subject proof revalidates the `SO_PEERCRED`
  pid/uid, proves the connected peer is still the current executable, checks the live `/proc` uid still matches the
  socket uid, and uses that same identity's process start time for the race-resistant polkit subject. This is
  correctness hardening rather than a newly proven default LPE: the old path still had the active-user/root UID gate,
  same-executable accept proof, trusted fixed `pkcheck`, `auth_admin` policy, and service-owned receiver commit proof.
  Verification closure: `scripts/verify.sh` gates the live peer-identity subject, the start-time accessor, the
  requirements/ledger disposition, and absence of the old direct `linux_proc_start_time(peer_pid)` subject assembly.
- **R-S11e-16 — permanent-password provisioning ingress — CLOSED 2026-07-12.** Platforms: Linux, macOS,
  and Windows desktop CLI, including installed-service and user-owned headless operation. Endpoint/action:
  `rustdesk --password` and the value passed into owner-aware raw password routing. Boundary:
  operator-entered CPace owner credential ↔ OS process metadata, shell history, and local process observers.
  Attack surface closed: the permanent password is no longer accepted as a positional process argument. Bare
  `--password` reads and confirms the value with echo disabled from the controlling terminal;
  `--password-stdin` is the only noninteractive ingress, refuses a terminal stdin, and reads one bounded UTF-8
  line. Both command forms require exact command shape, preserve an explicit empty value as credential removal,
  and enforce the common 4096-byte unattended-password ceiling before the password reaches IPC or Argon2id.
  A positional value on either command is a nonzero usage failure and never reaches
  `ipc::set_permanent_password`; no argv, environment-variable, compatibility, or local-persistence fallback
  remains. The user-owned/service-owned routing and receiver-side authorization model is unchanged. Verification
  closure: `core_main::tests` covers exact command parsing, positional-secret rejection, empty/CRLF/no-newline
  stdin handling, UTF-8 rejection, and the byte ceiling; `scripts/verify.sh` gates the prompt/confirmation,
  noninteractive TTY refusal, bounded reader, no positional extraction, safe deployment/smoke commands, and
  Appendix C #121; `scripts/apple-conform-check.sh` mirrors the desktop CLI source and documentation gates.
- **R-S11e-17 — typed connection-manager file response authority — CLOSED 2026-07-12.** Platforms:
  Linux, Windows, macOS, and Android controlled-side file operations; retained iOS source types. Endpoint/action:
  CM file results crossing back into an authenticated `Connection` and then onto the keyed peer stream. Boundary:
  local CM/file worker result authority ↔ authenticated network message construction. Attack surface closed:
  `Data::RawMessage`, raw protobuf directory/result blobs, raw serialized `FS::SendConfirm`, and the legacy
  ID-only CM result variants are deleted. CM returns only the closed serde-native `CmFileResponseKind` DTO set
  in a `CmFileResponse` envelope bound to exact `conn_id` plus the connection's random `cm_auth_token`.
  `Connection` mints monotonic generations for read/write jobs and bounded one-shot requests; mutation results
  echo an exact typed operation descriptor. CM job IDs are never reused during a connection. Reads track the
  current file and exact digest-confirmation phase. Writes use exclusive active, digest-checking,
  peer-confirmation, and finalizing phases; an unresolved digest admits neither blocks nor successful completion,
  while a peer error remains terminally admissible. Every response is checked against authenticated FileTransfer
  mode, session token, generation, operation kind/path, phase, expected ID/path/file number, metadata limits, and
  bounded error text. Windows drive descriptors are accepted only for an authorized virtual-root listing; transfer
  manifests retain strict relative-name validation. Finalizing authority remains until CM acknowledgement, and
  stale/cross-kind responses do not consume current authority. A failed helper-channel enqueue retires its pending
  authority and returns a peer error instead of leaving advanced state live. CM filesystem authority is FileTransfer-only;
  Remote clipboard authority is separate and Remote-only. `Connection` alone constructs peer protobuf messages.
  Structured `_cm` frames have a 128 MiB decoder ceiling. Before a split typed `ReadBlock` payload is read, the
  bridge checks FileTransfer mode/connection/token, reduces the decoder ceiling to 256 KiB, and applies a five-second
  deadline; generation/current-file phase is checked before peer message construction. Verification closure:
  `cm_file_response_authority_*`, `cm_file_authority_*`, typed directory/block tests, `scripts/verify.sh`, and
  `scripts/apple-conform-check.sh` gate the complete session/generation/phase/size model and absence of every raw or
  legacy response surface; Appendix C #122 records CWE-441/CWE-863 and the all-platform impact.
- **R-S11e-18 — Windows named-pipe impersonation restoration — CLOSED 2026-07-12.** Platform: Windows
  installed-service IPC. Endpoint/action: connected-client token impersonation for raw `_service_password`,
  elevated `_service` RDP requests, and LocalSystem service credential control. Boundary:
  client-token authorization proof ↔ reuse of the privileged IPC runtime thread. Attack surface closed: the
  former `Drop`-only guard logged `RevertToSelf` failure and returned, although Windows leaves the thread in the
  client context after that failure. The IPC listener runs a current-thread Tokio runtime, so subsequent service
  tasks could execute under the stale client token. Every named-pipe impersonation now runs on a dedicated,
  disposable OS thread over a duplicated parent-owned pipe handle. The service waits for that thread before using
  any result. Successful and ordinary `Result`-failed token checks call `RevertToSelf` before normal thread return.
  The release profile remains globally process-fatal on panic and makes no panic-containment claim. A failed
  `RevertToSelf` records no usable result and calls `ExitThread`, so no reusable impersonated thread reaches the
  Tokio runtime while the service process and its sole child-job handle remain alive. Verification closure:
  `scripts/verify.sh` parses the helper, token-authority wrapper, and SAS
  dispatch to require one confined impersonation site, duplicated-handle lifetime, restore-before-normal-return,
  disposable-thread termination on restoration failure, parent wait-before-result, and absence of process abort;
  Appendix C #123 records the Windows-only impact; the repository Windows build gate compiles the target API shape.
- **R-S11e-19 — Windows service-owned child tree supervision — CLOSED 2026-07-12.** Platform: Windows
  installed service. Endpoint/action: SCM start, stop, preshutdown, per-session service-owned server launch,
  liveness, session handoff, and port-forward preservation. Boundary: LocalSystem SCM service ownership ↔ the
  complete privileged `--server --service-owned-server` process tree and clean service completion. Attack surface
  closed: the service no longer stores or overwrites a raw child process handle, launches a replacement before old
  tree absence, treats an unknown port-forward count as zero, lets busy `_service` traffic suppress liveness, or
  reports stopped after merely closing a process handle. Each launch creates and configures a fresh unnamed,
  non-inheritable `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job first; `LaunchProcessWin` uses `STARTUPINFOEXW`, a
  one-entry `PROC_THREAD_ATTRIBUTE_JOB_LIST`, `EXTENDED_STARTUPINFO_PRESENT`, and disabled handle inheritance so
  `CreateProcessAsUserW` creates the child under job ownership before its initial thread can run. The service retains
  RAII job/process handles, immutable PID/creation-time identity, and served session; job accounting proves aggregate active-process absence.
  Desired, listener, and served sessions are separate. Active or unknown port-forward state preserves the old child
  and is re-queried; zero permits retirement; a dead main child retires remaining descendants regardless of the
  count. Port-forward queries and graceful close authenticate the connected main IPC server as the retained PID.
  Runtime handoff has a bounded wait per attempt and retains a still-live main child for a later authenticated
  shutdown retry. Only after the main child has observably exited are remaining descendants terminated through the
  exact job, replacement starts only after zero active processes, and every child launch shares the stop-transition
  lock. SCM Stop/Preshutdown uses a capacity-independent in-process channel, reports
  StartPending/StopPending checkpoints, and advertises STOP plus PRESHUTDOWN; `_service Data::Close`, nested runtime
  stop, Shutdown handling, and detached transaction tasks are deleted. Every accepted service transaction is
  tracked and drained without aborting an admitted password mutation. SCM retries authenticated exact-child
  shutdown while the main child is live and retains the job through status/accounting failures. Checkpoints may
  advance periodically while active retry, transaction drain, child shutdown, or job-empty accounting continues;
  they do not claim that a transaction or process count decreased. Accounting and descendant-termination failures retain the sole job handle and retry. `SERVICE_STOPPED`
  follows exact-tree absence; a prior loop or status error uses a service-specific failure code rather than a clean
  stop. Verification closure: pure `windows_service_` transition tests cover no-target launch,
  active/unknown deferral, idle replacement, dead-main reaping, and same-session stability; the repository Windows
  build runs that suite natively before artifacts; `scripts/verify.sh` gates creation-time job assignment, exact-child
  IPC, job accounting/termination, SCM status ordering, transaction drain, deleted paths, requirements, ledger, and
  Appendix C #124.
- **R-S11e-20 — Windows Installer sole machine-state authority — SOURCE IMPLEMENTED; NATIVE/ARTIFACT EVIDENCE IS OWNED BY THE EXACT-COMMIT R-B2 TRANSACTION.** Platform: Windows
  setup, install, repair, upgrade, and uninstall. Endpoint/action: UAC-approved setup bootstrap, Program Files
  payload deployment, LocalSystem service ownership, firewall authorization, machine registry/shortcuts, fixed
  certificate/driver/runtime-file cleanup, and runtime broker refresh. Boundary: caller-controlled application image
  and generated command program ↔ administrator-approved machine-state mutation and future LocalSystem execution.
  Attack surface closed: the application no longer implements EXE install/uninstall, generated batch/VBS execution,
  prior-uninstall-string replay, caller-`current_exe` helper execution, public install/helper verbs, direct Windows
  service installation, or an in-app Flutter installation route. The old flow elevated System32 `cmd.exe` but then
  let the generated command program execute a caller-context Flutter runner which loaded adjacent
  `librustdesk.dll`; after UAC approval, a prepared application directory could therefore execute elevated and create
  the LocalSystem service. The setup executable is now an MSI-only bootstrapper recognized solely by exact
  `rustdesk-setup.exe` basename derived from the running executable rather than command-line `argv[0]`. Its embedded
  command grammar is closed to no arguments, the exact silent option, or an elevation-only internal marker; running
  executable resolution failure and every other argument shape are fatal. Its embedded
  manifest must contain exactly one root
  `rustdesk-installer.msi`; the elevated leg stages only that file under a protected no-reparse Program Files
  directory, resolves `msiexec.exe` through `GetSystemDirectoryW`, passes explicit arguments without a shell, waits,
  always suppresses restart initiation, and accepts only 0 or 3010. It never loads or executes packaged application
  code. The Windows build compiles only the Flutter distribution, builds, canonicalizes, and validates the MSI first,
  creates a dedicated one-file setup payload from those final MSI bytes, hash-checks it, packs it offline/locked,
  removes staging in `finally`, and emits only exact output paths.
  The MSI alone creates and ACLs `ProgramData\<Product>\config`; runtime code has no authority to create or
  repair that machine credential root. WiX `ServiceInstall` with the documented null-StartName LocalSystem default, `ServiceControl`, nested
  `ServiceConfigFailureActions` preserving 5/10/30-second restart backoff, and a file-bound inbound TCP/21118
  `fire:FirewallException` transactionally own service and firewall state. The basename process killer and custom
  service/firewall source, exports, and schedules are deleted. Exact test-certificate and fixed-root Amyuni cleanup run
  only in the commit phase of explicit uninstall; upgrade preserves them and a later package failure cannot roll back
  files/service/firewall around irreversible cleanup. Certificate cleanup deletes only the fixed fingerprint after
  blob validation. Exact runtime-generated broker cleanup remains a checked deferred action before package file
  removal. Runtime broker refresh now requires
  the fixed service image, a non-reparse System32 source, the fixed Program Files destination, and byte equality;
  replacement is atomic when a prior broker exists, and the launch path propagates verification failure. It uses no
  shell, UAC, or basename kill. Verification closure:
  portable pure tests cover exact setup-name and 0/3010 status policy; a Windows-target isolated portable compile
  passed historically for an earlier source state; `scripts/verify.sh` gates the sole-authority topology, deleted
  paths, declarative MSI resources, exact one-file build payload, broker provenance, R-S11f, this ledger entry,
  and Appendix C #125. Current Windows artifact evidence is authoritative only through the exact-commit R-B2 manifest.
- **R-S11e-21 — raw password transaction finality and service-owned SAS — SOURCE IMPLEMENTED; NATIVE/ARTIFACT
  EVIDENCE IS OWNED BY THE EXACT-COMMIT R-B2 TRANSACTION.** Ordinary main IPC remains a closed bounded
  nonsecret protocol. Password bodies use only raw `_password`/`_service_password` with canonical header/body/status
  frames and a Windows operation-bound ACK. Each operation UUID is bound to owner kind and an HMAC-SHA256 value
  fingerprint under a process-random key. `Prepared`/`Pending` admission is irrevocable; a mismatched replay rejects;
  the admitted worker owns completion; and `Applied` follows successful durable storage. Each transport and
  authorization attempt is deadline-bounded. Exact ownership drain is not detached, while uncertain client recovery
  reuses the same UUID/value for at most 600 seconds before returning an explicit unknown-outcome error.
  `Rejected`, `InternalFailure`, and `ShuttingDown` are terminal; only explicit `Unknown` continues recovery. Each
  64-entry process-lifetime ledger admits new work by evicting only its oldest terminal result and never evicts
  `Prepared`, `Pending`, `Authorizing`, `Committing`, `Recoverable`, or Windows `Active` work. A denied Linux
  pre-admission authorization is removed immediately and consumes no replay capacity. Evicted IDs become `Unknown`;
  retained terminal IDs remain value-bound, and restart is not durable exactly-once. Linux's outer admission
  separately serializes one caller through `Authorizing`, `Committing`, `Recoverable`, and `Complete`. Shutdown
  closes admission, drains transactions and workers, then wipes entries, tags, and HMAC keys. Windows SAS remains
  on its independent one-slot endpoint, bound to the retained LocalSystem child generation through supervisor proof
  and final impersonated dispatch; its result proves dispatch acceptance, not secure-desktop activation. SCM may
  remain `STOP_PENDING`, and `SERVICE_STOPPED` follows exact-job zero.

- **R-S19a — connection-owned controlled-input execution — SOURCE IMPLEMENTED; NATIVE/ARTIFACT EVIDENCE IS OWNED BY THE EXACT-COMMIT R-B2 TRANSACTION.**
  Windows, Linux, and macOS Remote connections each own one bounded input worker from authorization through joined
  teardown. Android validates both the raw inbound key and the modifier-rewritten event; iOS has no controlled-input
  server and retains source-conformance scope only. Item/byte caps, bounded wheel and gesture magnitudes, structural
  event validation, nonblocking admission, and atomic cancellation/dispatch admission make malformed, full, or
  disconnected queues fail closed. Final physical key and mouse-button ownership is process-wide and
  reference-counted by connection: physical down occurs only on the first owner, physical up only after the final
  owner, and teardown releases exactly the closing connection's ownership. Temporary modifiers participate in the
  same ownership model and are released on every Result/error path. Native backends are Result-bearing; uncertainty
  after a native dispatch or release failure is fail-stop rather than guessed state or continued injection.
  Windows uses one stable executor for injection and BlockInput so aggregate BlockInput acquire/release ordering,
  physical dispatch, and cleanup cannot cross threads or reorder. macOS completes its synchronous dispatch-queue
  barrier before worker completion; its privacy blackout contains no `CGEventTap` callback or run-loop source and
  cannot implicitly suppress local input. Explicit BlockInput remains a separate Remote-only connection capability.
  Linux clears global remaps only after the final worker exits. Worker supervision
  owns joins from creation, queued events are destroyed without execution after cancellation, and no Tokio executor
  is synchronously blocked by native completion. Source gates, Linux tests, Apple conformance, Android validation,
  and native Windows input-lifecycle suites cover the platform contracts. Appendix C #126 and R-S19a are the
  normative closure; current artifact evidence is authoritative only through the exact-commit R-B2 manifest.

- **R-S11e-22 — Windows machine credential store and former local-authority/LPE class — SOURCE IMPLEMENTED; NATIVE/ARTIFACT EVIDENCE IS OWNED BY THE EXACT-COMMIT R-B2 TRANSACTION.**
  The MSI alone provisions `ProgramData\<Product>\config` with a protected inheritable DACL containing only
  SYSTEM and Administrators full-control ACEs; accepted owner is SYSTEM or Administrators. Runtime has no create,
  ACL repair, profile fallback/rewrite, alternate root, or pathname fallback. The stable LocalSystem SCM supervisor
  retains handle-relative `NtCreateFile` traversal with `FILE_OPEN_REPARSE_POINT`; every component rejects
  reparse points and is post-open checked for identity, type, owner, and DACL. Startup fails unless the existing
  root, ACL, persistent-ACL volume, supervisor read/write authority, and matching-serial volume durability handle
  are all proved. Only SCM has durable write authority and owns that volume handle; the exact retained child has a
  generation-bound read-only runtime replica. Mutation performs pre-rename file sync, handle-relative replacement,
  renamed-file `NtFlushBuffersFile`, then `FlushFileBuffers` on the matching volume. Any post-replacement
  durability or identity ambiguity is process-fatal, never false success or false failure. The intentional cost is
  a potentially blocking whole-volume flush and administrative volume access for every credential namespace
  mutation. Stop/apply drains admitted work and may remain `STOP_PENDING`; stopped follows exact-job zero, with
  periodic checkpoints permitted during active retry/drain. Credential transport uses a redacted
  `SensitivePassword` that owns either the originating string or one fixed inbound raw allocation through an `Arc`;
  retries clone only that `Arc`. The final secret allocation, raw stack frames, fixed body, unused tail, and
  authorization capability are zeroized on drop/error; Windows public setters wrap before policy/authorization
  failure paths. This scoped guarantee does not claim that every allocator, kernel, transport, or OS copy is wiped. This
  closes the former Windows machine-credential local-authority/LPE/storage class described by Appendix C #128 at
  source level; final native/cold validation remains outstanding.
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
  remains high risk because main IPC is same-session. Endpoints: `MainIpcRequest::SetOptions`, trusted-device removals,
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
  (`Config::get_options`, the UI cache, CLI `--option`, and `MainIpcRequest::StatusSnapshot`) now overlay
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
  R-S11c-10s closes the Linux Flutter runner Rust core library load provenance path in
  `flutter/linux/main.cc`: the installed runner/service executable no longer asks the dynamic loader to resolve a
  bare `librustdesk.so` name through ambient library search. It loads `$ORIGIN/lib/librustdesk.so`, matching the
  Debian bundle layout and the existing `$ORIGIN/lib` install RPATH, with explicit immediate/local binding. Missing
  bundled core or missing `rustdesk_core_main` now makes the runner exit nonzero. The legacy package-manager advice
  path is deleted, so a load failure no longer probes `PATH` for `apt`, `dnf`, `yum`, `zypper`, or `pacman`.
  R-S11c-10t closes the Linux Debian package tree authority in `build.py`, `scripts/build-debian.sh`, and
  `scripts/verify-debian-package-authority.py`. Debian packaging has one supported Flutter constructor; the unused
  `--package` and non-Flutter cargo-bundle/repackaging surfaces are absent. It removes prior Linux Flutter output,
  requires the exact bundle root/runtime-library/fixed-resource shape with only generated `flutter_assets` variable.
  `build.py` and the independent artifact verifier each enumerate the exact library set. Ignored Flutter plugin
  registrants and generated CMake metadata are regenerated build mechanics, not source authority; the actual staged
  bundle and emitted `.deb` are the dependency/plugin-output drift boundaries. It copies the exact four
  maintainer-script bodies without preserving checkout modes. The exact control inventory
  includes `conffiles` for `startwm.sh`/`xorg.conf` and `md5sums` covering every non-conffile data file. The finalizer
  rejects unexpected entries, nested control directories, links, special files, and hardlinked regular files, then
  makes every directory `0755`, the runner and `startwm.sh` `0755`, all other data and ordinary control files `0644`,
  and all maintainer scripts `0755`. One `subprocess.run(..., check=True)` argv boundary invokes
  `dpkg-deb --root-owner-group -b`; AST validation admits only that archiver and the exact PE canonicalizer process,
  pins the complete top-level import inventory, rejects decorators, direct and re-exported alternate process-launch
  members, callable aliases, direct stores, dynamic namespace/evaluation APIs, function/module/frame namespace reach,
  and explicit early termination, and requires every package authority's loaded name/code origin to match its sole
  synchronous top-level definition. It resolves concatenated, joined, and interpolated constant strings, requires exact
  shell-wrapper and FFI-helper bodies, the four-function shell-call ownership inventory, and the exact 21-operation
  Flutter pre-finalization program,
  requires contiguous reachable direct staging/finalization/archive operations, and permits only the exact
  cleanup/versioned-rename/chdir publication tail afterward. The release
  wrapper validates the emitted archive and locale-independent exact extracted-script metadata before hashing it. The
  independent verifier reads raw tar headers and rejects duplicate, absolute, traversing, extended, parser-normalized,
  root-alias, wrong-prefix, wrong-trailing-slash, alternate regular/contiguous/sparse typeflags, nonempty regular-file
  link names, non-root owner names, nonzero name/linkname/uname/gname/prefix padding, or otherwise non-canonical
  members; requires exact link-free data/control/conffile/md5 inventories; and checks every member's numeric ownership,
  raw type, and mode.
  Source tests construct the authority fixture from tracked inputs, prove success without generated plugin metadata,
  and prove stale or malformed ignored metadata has no effect. One-sided producer-library removal and rename,
  finalizer-level missing/extra plugin libraries, and archive-level missing/extra/substituted/non-ELF plugin libraries
  are explicit negatives. Production tests invoke the real finalizer under `umask 077` with `0600`/`0700` inputs.
  Handcrafted package mutations cover wrong control/data modes, extra/missing/nested/special members, regular stowaways,
  links, raw-header aliases,
  wrong-identity ELF objects, malformed conffiles/md5sums, and invalid/empty/multiple/legacy ELF search paths; source
  negatives cover hardlinked and individually symlinked scripts, a symlinked script directory, stale data,
  decorated constructor replacement, direct OS-process imports, byte-valued spawn/exec and re-exported subprocess
  launches, literal/concatenated/joined/interpolated-f-string/aliased archive commands, early termination, direct or
  dynamic authority rebinding, intervening or reordered package operations, user ownership, and writable/private modes.
  R-S11c-10u closes the Linux XDO libxdo dynamic-library provenance path in
  `libs/libxdo-sys-stub/src/lib.rs`: the service-reachable Linux input backend no longer opens bare
  `libxdo.so.*` names through ambient dynamic-loader search. The wrapper now considers only fixed absolute
  system-library candidates for versioned `libxdo.so.4` and `libxdo.so.3`, rejects unversioned `libxdo.so`,
  rejects `/usr/local`, relative, shell-discovered, `ldconfig`, and `pkg-config` discovery paths, and resolves each
  candidate through a trust predicate before opening it. The candidate directory chain, canonical target directory
  chain, and canonical target file must be root-owned and not group/world-writable; the target must be a regular
  file. Protected distro symlinks are accepted only when the canonical target is also protected. The final open uses
  `Library::open(Some(path.as_path()), RTLD_NOW | RTLD_LOCAL)` on that canonical absolute path, and missing or
  untrusted `libxdo` leaves XDO disabled rather than falling back to loader search. This was not promoted to a
  proven default local-user-to-root issue because the shipped systemd unit does not inject attacker-controlled
  loader state and default system library directories should not be user-writable, but root/headless service-owned
  native code loading now has the intended source-level provenance boundary. `libs/libxdo-sys-stub` is a workspace
  member so `scripts/verify.sh` can run the focused root-exercised trust tests.
  R-S11c-10v — obsolete generated Docker build helper excision — closes the `build.py`
  `generate_build_script_for_docker()` path by deleting it. The helper had no parser option, caller, documentation,
  or supported build workflow, but retained fixed `/tmp/build.sh` write/chmod/execute authority and a fixed
  `/tmp/flutter_rust_bridge` clone destination. It also downloaded an obsolete Flutter archive and shallow-cloned
  mutable Flutter Rust Bridge and vcpkg repositories outside the pinned offline build inputs. This was not promoted
  to a proven shipped-runtime LPE because the function was unreachable and absent from supported build workflows.
  Retaining and hardening its temporary paths would nevertheless preserve an unowned, non-reproducible bootstrap
  mode contrary to R-B2. `scripts/verify.sh` gates absence of the helper name, public temporary paths, obsolete
  Flutter archive, mutable Flutter Rust Bridge clone, mutable vcpkg clone, and this requirements/ledger disposition.
  R-S11c-10w — verifier private scratch workspace authority — closes the host-side `scripts/verify.sh` public-temp
  redirection class. The supported day-to-day verifier, also invoked as the first `scripts/verify-release.sh` gate,
  wrote grep/test output through 65 fixed `/tmp/rd_verify_*.$$`, `/tmp/r_s11b3_*.$$`, and
  `/tmp/r_s11c23_hits.txt` names. The repository does not invoke either verifier through `sudo`, so this was not
  promoted to a default build-host or shipped-runtime LPE; an operator running the verifier elevated on a shared host
  would nevertheless let the shell follow attacker-created public-temp symlinks before the checked command ran.
  `scripts/verify.sh` now creates one `/tmp/rustdesk-verify.XXXXXXXXXX` directory through checked `mktemp -d` under
  a controlled `077` umask, makes the path readonly in the shell, verifies current-UID ownership and mode `0700`,
  and places every generated checker output beneath it. One EXIT cleanup preserves the verifier's status, signal
  traps exit with the conventional nonzero signal statuses, cleanup disarms all traps before checked recursive
  removal, and cleanup failure changes the result to failure. The old PID-suffixed/fixed names and scattered
  per-file cleanup branches are absent. A separate structural verifier proves the exact full-line create, cleanup,
  signal, and metadata blocks without embedding its assertion literals in `verify.sh`; mutation-negative self-tests
  delete every required real line in memory and require rejection. The gate also rejects fixed-string self-inspection,
  old scratch prefixes, every direct public-`/tmp` redirection, and missing requirements/ledger disposition.
  The Python verifier now acquires the shell-created scratch root by retained no-follow descriptors; every allocation
  site uses descriptor-relative random creation and identity-checked recursive removal, and the closure probe receives
  an inherited scratch descriptor. Acquisition-failure and rename/replacement fixtures prove descriptor closure,
  ambiguous-edge preservation, and replacement non-mutation. Stateful subprocesses use authenticated transient cgroup
  scopes, and canonical publication state is collected by a pidfd-supervised isolated worker with complete observable
  metadata, resource bounds, and deadline fixtures. Source mutation gates independently remove these authorities.
  R-S11c-10x — Apple checker private host scratch authority — closes the host-side
  `scripts/apple-conform-check.sh` public-temp class. The supported Apple source-conformance checker, also invoked by
  `scripts/verify-release.sh`, redirected seven fixed/PID-suffixed diagnostic basenames and the per-target
  `apple-xcheck` log through public `/tmp`. No tracked caller elevates the checker or release verifier, so this was
  not promoted to a default build-host or shipped-runtime LPE; an elevated shared-host invocation would nevertheless
  follow attacker-created symlinks before the checked command ran. The checker now creates one
  `/tmp/rustdesk-apple-check.XXXXXXXXXX` directory with checked `mktemp -d` under umask `077`, makes the path variable
  readonly, proves with `lstat` that it is a current-UID mode-`0700` directory, and places every host-created
  diagnostic and target log beneath it. One EXIT cleanup preserves status, cleanup failure is failure, and HUP/INT/
  TERM retain nonzero signal statuses. The old host paths and scattered cleanup branches are absent. Fixed
  `/tmp/apple-vcpkg` and SDK-root `/tmp` values remain only inside fresh trusted-image `docker run --rm` containers
  and are not host filesystem authority; the unnecessary container-local `/tmp/rfe` diagnostic is replaced by
  in-memory stderr capture. The R-S11c-10x gate uses anchored source-shape
  assertions that cannot satisfy themselves, rejects old host prefixes and every direct public-temp redirection,
  and requires this requirements/ledger disposition.
  R-S11c-10y closes the Linux Debian shipped ELF runtime-library provenance class. The root-loaded Debian runner
  already had the intended `$ORIGIN/lib` bundle RUNPATH, but the bundled Rust core inherited Cargo's upstream
  release `rpath = true` and shipped a build-container RUNPATH that normalized from
  `/usr/share/rustdesk/lib/librustdesk.so` into `/tmp/tc/rustinstall/lib/rustlib/x86_64-unknown-linux-gnu/lib`;
  glibc used that RUNPATH for the core's direct dependencies such as `libpulse-simple.so.0` before default system
  directories. The same package sweep found copied Flutter plugin shared libraries with absolute
  `/src/flutter/linux/flutter/ephemeral` build RUNPATHs. Cargo release rpath is now pinned off in `Cargo.toml`,
  `build.py`, and `scripts/build-debian.sh`; Flutter plugin targets are built with install RUNPATH and
  `$ORIGIN`, so copied plugin artifacts are bundle-relative rather than build-tree-relative. The Debian package
  authority verifier now extracts each emitted `.deb` data archive, inspects every regular data member with ELF magic,
  requires current 64-bit little-endian x86-64 headers, `ET_EXEC`/`ET_DYN` for the runner, and `ET_DYN` for every other
  ELF. The runner has one exact mapped `/lib64/ld-linux-x86-64.so.2` interpreter; shared objects have none. Every load
  is non-W+X and ABI-aligned. Every admitted ELF has exactly one GNU-stack header with zero offset, addresses, and
  sizes, exact RW permissions without execute or extra bits, and ABI-valid alignment: 0 or 1 for no constraint, or a
  positive power of two. This admits the pinned producers' legitimate Dart 1, Flutter engine 0, and GNU 16 while
  preserving the Linux/glibc permission contract and rejecting noncanonical header state. It directly parses
  exactly one consistently `PT_LOAD`-mapped loader-visible `PT_DYNAMIC` containing 16-byte
  records, requires canonical 8-byte segment alignment and a `DT_NULL` terminator with zero-only remainder, and maps
  its unique nonempty bounded string table through program headers. The table must begin and end with NUL; every
  recognized loader string reference is bounded and ASCII. `DT_NEEDED` values are safe basenames, an optional sole
  `DT_SONAME` equals the installed basename, and CONFIG/DEPAUDIT/AUDIT/AUXILIARY/FILTER loader controls are forbidden.
  The verifier rejects legacy RPATH, malformed or multiple tags, and empty RUNPATH,
  requires the runner to have exactly `$ORIGIN/lib`, allows only `$ORIGIN` on `libflutter_linux_gtk.so` and Flutter
  plugin libraries, and requires every other ELF including `librustdesk.so` to have no runtime-search tag. Its
  handcrafted package and parser mutations cover wrong class/byte-order/machine/type, interpreter count/path/role;
  missing/duplicate GNU-stack headers, every nonzero no-content field, executable/missing/extra permission bits, and
  malformed alignment, with positive 0/1/16 producer alignments; W+X loads and dynamic-segment identities,
  segment/load disagreement, wrong alignment, missing termination, missing/duplicate/zero-sized/unmapped/oversized or
  non-NUL-bounded dynamic strings, out-of-bounds references, unsafe dependency/SONAME values, forbidden loader tags,
  `/tmp/rustdesk-bad`, empty, multiple, and legacy search paths, mandatory non-ELF substitution, and a bad ELF in the
  variable asset subtree; `scripts/build-debian.sh` runs the verifier before hashing each package.
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
  by R-S11c-10r; Linux Flutter runner core-library load provenance is closed by R-S11c-10s; Linux Debian package
  tree authority is closed by R-S11c-10t; Linux XDO libxdo dynamic-library provenance is closed by
  R-S11c-10u.
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
  IPC class. R-S11b-4d also hardens corrupt-config recovery files: preserved TOML/raw encrypted payload backups are
  rehardened immediately after rename with Unix `O_NOFOLLOW` plus descriptor `fchmod(0600)` or the Windows protected
  config DACL, so weak inherited source permissions do not persist into recovery artifacts.

**Checked during this audit and not opened under R-S11b/R-S11c:** Android exported components/service
surfaces remain contained by manifest/exported-permission shape; iOS has no controlled-side/root IPC surface
in scope; Unix IPC parent/socket hardening remains a prerequisite and is not the failing layer; FileTransfer
authorization, file-transfer symlink TOCTOU, port-forward plaintext, decompression amplification,
OS-login/PAM/LogonUser and deep-link password/config/import concerns are tracked by their existing
requirements/fixes; the newly proven Windows service-terminal principal flaw is closed by R-S11c-25. Dependency advisories are the separate
R-R3/Appendix D gated class: Rust and Dart package advisories are checked by the pinned advisory gates, while
native vcpkg codec advisories remain the Appendix C #2b watch/residual.

The R-S11b/R-S11c source topology is implemented. That source status is not artifact or release proof;
native and reproducibility evidence is owned by the exact-commit R-B2 transaction and generated manifest.

**R-B2 — exact-commit release harness source implemented.**
`scripts/build-release.sh` is the sole release-build entry point. It requires a clean committed source tree,
runs the release gates, performs cold Debian/Android/Windows double-builds, requires A==B for each target, and
writes the coherent commit/version/artifact identity to `dist/SHA256SUMS`. Publication is a separate optional
action through `scripts/publish-github-release.sh`; it is not part of building or verifying `.6`.
Cargo version metadata is generated from `CARGO_PKG_VERSION` and the canonical pinned `SOURCE_DATE_EPOCH` only
under Cargo's private `OUT_DIR`. The root and Apple Cargo gates mount source read-only, require
`src/version.rs` to remain absent, and keep the Android target check non-root. Explicit malformed or out-of-range
epochs fail the build; only an absent epoch retains wall-clock behavior for ordinary developer builds.
The same root build script requires one canonical newline-terminated `FORK_VERSION` whose numeric base equals
`CARGO_PKG_VERSION`; it has no missing, unreadable, empty, malformed, mismatched, or package-version fallback.
Each pass gives every target builder an absent publication path and leaves its creation to that builder. Windows
VM lifecycle state is a pass-private sibling of the source and output roots, not a descendant of `OUT_DIR`.
The Windows harness canonicalizes and rejects equal, ancestor, or descendant state/output paths before creating
either path and re-proves disjointness afterward. Executable transaction fixtures prove output absence at target
entry, state/output disjointness, exact pass isolation, target-owned creation, Windows no-clobber publication, and
the absence of Windows state authority from Debian and Android; structural mutations make each boundary mandatory.

**R-B10 Android Gradle execution cache — SOURCE IMPLEMENTED; ARTIFACT PROOF PENDING.**
The immutable online Gradle seed is projected descriptor-relatively into a fresh non-root owner-only execution
cache. The projector rejects mode, ownership, topology, mount, link, mutation, and destination-identity drift,
verifies complete bytes and inventory, and rejects ambient Gradle init authority. The sole tracked init script
sets Gradle's real offline start parameter; the former ignored `org.gradle.offline` project property is absent.
The pinned-image gate executes Gradle 7.6.4 under the production no-network/non-root confinement and proves the
enabled, unset, and malformed flag states. The online-input mutation suite is now a mandatory release gate.
Current artifact evidence remains open until a clean pushed exact commit completes the full R-B2 transaction.

The release source-gate boundary is closed before expensive input copying. `scripts/verify-release.sh
--preflight` proves a fixed `/usr/bin/grep` that is an executable, root-owned, non-group/world-writable regular
file and identifies as GNU grep. Every migrated exhaustive forbidden-pattern scan distinguishes match (0),
clean no-match (1), and operational failure (all other statuses); scanner failure terminates instead of becoming
a false absence. The preflight runs under the release child environment before `require_online_complete` and
the private online snapshot copy. Structural mutation tests remove or reorder that boundary, corrupt status
capture, and reintroduce an undeclared `rg` dependency.

The non-root portable password smoke does not traverse or relax the mode-0700 release source snapshot. Root in
the disposable container stages exactly the server, seeder, probe, and bind shim as root-owned read/execute-only
files beneath a protected `/tmp/rd-smoke-nonroot` fixture; UID 4000 owns only its mode-0700 fixture home. The
runner proves the exact portable executable, non-service role, process UID, credential replacement, exact PID
termination/reap, and unchanged source inode/mode/content. Structural mutations reject source traversal, a
missing fixture member, broad process killing, or a release snapshot relaxed from mode 0700.

The first exact-commit transaction at `6cf6719f7d57b01149b161997685a77c618c782f` passed all nine source gates
inside pass A, including the private non-root smoke, then stopped before Debian compilation at `A before debian`.
Root-running verification containers had created ignored Cargo and Flutter state; the host-UID `git clean -ffdx`
correctly refused 8,646 inaccessible removals. That attempt produced no platform artifact, A/B equality result,
manifest, publication, or release evidence.

Pass A and pass B are independent `git clone --no-hardlinks --no-checkout --reject-shallow` repositories. Each checks out the pinned
commit detached, removes every remote, owns a private `.git` object database, rejects replacement/graft/alternate,
shallow, sparse, and index-masking state, runs strict `git fsck`, and proves mount and inode-link closure before use.
The release transaction creates no Git worktree registration and never reads, prunes, adopts, or removes the invoking
repository's worktree registry.

Every source consumer that necessarily generates Flutter, Gradle, or package state is enclosed by generated-state
resets; compilation-only consumers mount source read-only. The normalizer accepts only a recorded pass-A or
pass-B device/inode identity, rejects descendant mounts, requires `fs.protected_hardlinks=1`, and
re-verifies the digest-pinned Debian image. One no-pull, no-network container has a read-only root,
no-new-privileges, a nonrecursive bind, and exactly `DAC_READ_SEARCH` plus `CHOWN`. Its helper retains every directory
and non-directory inode descriptor, exact directory inventory, edge, mount identity, mode, link count, and internal
hardlink count before mutation. Special objects, external hardlinks, changed inventories, or changed authorities abort.
The 524,288-entry authority bound carries a 256-descriptor reserve over an enforced depth limit of 128, at most 64
pre-existing descriptors, at most eight transient descriptors, one root, and contingency. The helper rejects excess
depth or inherited descriptors before mutation, fixes and re-proves its soft `RLIMIT_NOFILE` at 524,544 before
enumerating inherited descriptors, and rejects a
lower hard limit. Docker fixes both limits at 524,544. Release preflight proves host and pinned-container capacity before
the authenticated online snapshot or a build is created.
The committed helper is opened once during workspace creation. Every host and container closure, normalization,
preflight, and deletion execution reads from that descriptor and verifies the complete bounded in-memory bytes against
the committed digest; no release operation executes or mounts the mutable helper pathname.
The retained authority records and re-proves every file type, owner, group, mode, and link count before mutation. Only
after that complete acquisition does it normalize ownership and modes through retained descriptors, stripping
setuid, setgid, sticky, and group/world-write bits and returning the root to the invoking UID/GID at mode 0700. It
re-proves the complete authority and postconditions before returning. Git then removes ignored state, requires an
equivalent `-nffdx` dry run to be empty, and re-proves detached HEAD, index, and tracked bytes.

Production workspace deletion no longer normalizes the workspace or its authenticated online snapshot. Cleanup opens
the exact helper, proves pathname/descriptor identity and its committed digest, and retains that descriptor. Every
terminal invocation receives at most 1 MiB directly from the retained descriptor, hashes the complete bytes in memory
against the committed digest, and only then compiles and dispatches them. Privileged execution resolves no mutable
helper pathname. One no-pull, no-network, read-only-root container receives the workspace by nonrecursive bind and has
only `DAC_OVERRIDE` and `FOWNER`. Before the online snapshot or any build, a disposable fixture
proves that exact image, bind, descriptor, limit, and capability path against root-owned mode-0000 state and a
current-user sticky-directory entry, then proves content deletion, empty-root removal, and absence. The helper
acquires the complete bounded mount, type, depth, inventory, and hardlink authority before deletion; removes only
descriptor-relative authenticated regular-file, symlink, and directory edges; requires every retained non-directory
link count to reach zero; and proves the original mode-0700 root remains empty with unchanged identity and metadata.
The host then re-authenticates the still-open helper bytes, re-acquires that exact empty root and its protected parent,
refuses any late content instead of traversing it, removes only the root through its retained parent,
requires the root link count to reach zero, synchronizes the parent, proves pathname absence, and closes the helper.
Any uncertain precondition or postcondition preserves state and exits nonzero. The invoking UID is the cooperating
release authority, admitted trees must remain quiescent, and deliberately concurrent same-UID namespace mutation is not
claimed to be contained.
Production cleanup without the exact pinned image preserves the workspace and fails; recursive host removal is confined
to the non-privileged fixture transaction.

Fail-loud dirty probes use exclusive random files. The production dirty-source proof runs in its own mode-0700,
complete-history, no-hardlink clone attached as `master` to the exact expected commit; it proves that baseline clean,
introduces the probe as the sole invalid source state, invokes the clone's committed release wrapper, and removes its
mount-closed and inode-link-closed root through recorded descriptor authority. Identity, unlink, or absence failure emits status 125 plus a
dedicated marker, either of which the result classifier rejects. Every negative lifecycle case requires its exact
reached-state and failure diagnostic. The source verifier and release orchestrator install traps before allocation,
block further managed signals during cleanup, preserve primary and cleanup failures, and defer green markers until
publication reconciliation and descriptor-bound workspace removal succeed. A missing closure probe, mount, external
hardlink, changed identity or inventory, cgroup ambiguity, publication ambiguity, or Windows ownership uncertainty
preserves unresolved state and exits nonzero.

The verifier launches every lifecycle-capable fixture behind a trusted gate in a random authenticated transient
systemd user scope. Acquisition proves the exact unit name, independent description, transient/collection policy,
invocation ID, control-group path, gated helper membership, and retained descriptor-walked cgroup-v2
`cgroup.events`/`cgroup.kill` authority before the target receives its environment or inherited descriptors. The
parent then transmits the bounded exact environment and descriptor-number allowlist over the gate's sole Unix
`SOCK_SEQPACKET` control channel and transfers exactly those descriptors with `SCM_RIGHTS`; the gate collision-isolates
them, restores only the requested inheritable descriptor numbers, closes the channel, and executes the target. The
scope launcher is synchronous: acquisition failure waits for either completed launcher failure or the exact
nonce-described unit, never a quiet-period inference. Target identity is retained by pidfd and aggregate output is
bounded. Deadline expiry signals the exact unit with `SIGTERM`, preserves a bounded grace for shell EXIT traps, then
writes `1` to the retained `cgroup.kill` descriptor. Normal target exit while the scope remains populated is failure.
Completion requires recursive `populated 0`, launcher reap, unit collection, and cgroup-path absence. Temporary
`SIGHUP`, `SIGINT`, and `SIGTERM` handlers span before/command/after state; signals during `Popen` acquisition are
deferred until process ownership is assigned, and repeated signals stay blocked through cleanup and state proof.
Behavioral fixtures cover post-spawn exceptions, pre-assignment and live parent signals, graceful TERM,
TERM-resistant `setsid`, normal exit with a lingering descendant, and a pipe-closing double fork. A complete
finalization fault fixture injects and requires propagation of forced-kill, launcher-reap, cgroup-descriptor-close,
unit-collection, and cgroup-path failures. This closes ordinary daemonization and process-group escape. It deliberately
does not claim to contain hostile same-UID code that migrates to a sibling cgroup, creates another user unit, or
delegates work to Docker; repository fixtures are cooperative and may not use those channels.

One canonical current-principal mode-0700 scratch root is acquired component-by-component with `O_NOFOLLOW`; its
parent and root descriptors, device/inode identities, mount ID, and exact edge are retained. Every subordinate fixture
directory is randomly named and created, traversed, normalized, and removed descriptor-relative. Root and child
acquisition-failure fixtures prove descriptor inventory equality; a child whose mount authority was not acquired is
preserved as one ambiguous edge and removed only after independent re-acquisition. Managed consumers receive only the
exact descriptors they need and normally address fixtures through unresolved `/proc/self/fd/*` paths. Two narrow test
contracts require canonical names: Debian/Android build-script contract fixtures reject noncanonical repository paths,
and the closure API itself requires a canonical tree root. Those calls re-prove the retained scratch edge before and
after use but are race-detecting, not coherent against a deliberately concurrent same-principal pathname writer. A
real managed consumer fixture renames a live child, installs a replacement, proves the consumer wrote only through the
retained descriptor, and proves cleanup preserved the replacement. Cleanup rechecks every child edge, mount ID, and
filesystem boundary; final success requires the retained root descriptor to be empty. The shell-created root is
removed only through the closure probe's retained parent/root descriptors and recorded device/inode identity, and any
scratch-cleanup failure is reported without losing the original failure.

The before/after proof snapshots canonical `dist`, every `.dist-release-*` name, and the recorded private workspace
identity. Publication traversal runs in a fresh isolated Python process that
inherits the repository descriptor and is supervised by pidfd, deadline, and aggregate result bounds. It rejects links
and special files; records ctime, `statx` masks/attributes/mount ID, mount flags, visible xattr digests, explicit ACL and
file-capability probes, inode flags, extended inode flags, exact content and EOF; and compares before/after metadata,
two directory inventories, and final parent edges. Independent constants, predicates, source mutations, and behavioral
fixtures cover total entries, depth, content bytes, per-value xattr bytes, per-inode xattr-name bytes and count,
aggregate xattr bytes and count, repository entry and name-byte inventories, canonical namespace entries, serialized
worker result, aggregate worker output, and elapsed time. Behavioral state-difference fixtures additionally cover
same-size content, visible xattr, ctime-only, symlink, noncanonical external content, and blocked-worker deadline cases.
The proof is explicitly race-detecting under the verifier UID, not a coherent transaction against a privileged writer;
Linux may hide inaccessible xattrs and cannot instantly kill a worker stuck in uninterruptible kernel I/O.

Transaction fixtures initialize an independent Git repository and reset fixtures use an independent no-hardlink clone.
Detached exact-commit source validation is branch-neutral and takes an independently supplied commit; only the real
release wrapper requires attached `master`. Exact snapshot contracts require private object storage, remote removal,
strict object validation, mode 0700, mount closure, and complete inode-link closure. Mutations remove each authority
stage independently.

The focused Docker regression first requires production admission to reject an external hardlink without changing its
outside inode. It then creates internally closed hardlinks, root-owned mode-0000 Cargo and Flutter trees, a root-owned
mode-6755 file, and an external symlink in the private snapshot. Ordinary Git cleanup must fail and preserve both
hostile trees. The exact production normalizer must transfer every retained inode to the invoking UID/GID, restore
directory access, and reduce the special file to mode 0755 before production reset removes generated state without
changing the external target or tracked snapshot. Exact Docker allowlists and structural mutations reject missing,
reordered, broadened, networked, recursively bound, symlink-following, hardlink-unprotected, mode-weakening,
postcondition-free, or bypassed normalization.

Release verification is reset both before and after its writable consumer, so pass B is re-proved after pass A and no
ignored state can become verifier input. Final APK certificate verification precedes the last A/B byte comparison and
manifest write. Final `dist` installation requires an exact canonical current-UID/current-primary-GID parent with owner
read/write/traverse, no group/world write, and no extended POSIX ACL. An advisory lock on the exact Git common-directory
inode excludes cooperating release orchestrators. Publication is Linux ext4-only: descriptor-bound `fstatfs` magic must
agree with the exact runtime mount's `/proc/self/mountinfo` type, and descriptor-bound `FS_IOC_GETFSUUID` must return the
nonzero 16-byte external ext4 UUID. That complete UUID is recorded with opaque parent, payload, and prior-destination
handles. Folded `f_fsid` and runtime mount IDs remain live-process authority only.

Every untrusted file edge is acquired first with `O_PATH|O_NOFOLLOW`, rejected unless it is a stable regular file, then
reopened nonblocking through its retained `/proc/self/fd/N` authority and re-proved. FIFO or other special-file
substitution therefore cannot block record, source, release, or cleanup inspection before type rejection. The exact
five files remain current-UID/current-GID, mode 0444, single-linked, xattr-free, bounded, synchronized, and manifest-bound.
The same-parent payload root is mode 0700 while staging and explicitly finalized and synchronized at mode 0555 only
after exact content and security proof.

The canonical mode-0400 v3 journal is linked and parent-synchronized in `initializing` state before payload creation.
The empty payload is then created and parent-synchronized; its persistent handle is durably committed in `staging`
before source copying begins. A fully synchronized and finalized payload advances to manifest-bound `prepared`.
First installation uses `RENAME_NOREPLACE`; replacement uses one same-parent `RENAME_EXCHANGE`. The parent is
synchronized before prepared-state classification may durably authorize `rollback` or `cleanup`, and partial deletion
is legal only after that exact authorization. Recovery removes an initializing record only when no payload exists,
preserves an unbound observed payload as ambiguous, rolls back a staging payload only through its recorded handle,
and removes the journal only after the authorized payload is absent and the surviving destination is re-proved.

Public verification never recovers or repairs. It rejects any reserved `.dist-release-*` state before exact destination
proof and scans again afterward. Empty recovery synchronizes and rescans the complete reserved namespace. Unknown,
malformed, wrong-token canonical, multiple, oversized, substituted, unsupported-filesystem, missing-prior, changed-security, and unclassifiable
states are preserved and rejected. First-install and replacement fixtures restart at `staging`, `prepared`, durable
rollback, exchange, durable cleanup, and payload removal. Separate fixtures cover an unbound post-creation payload,
wrong-token payload and next-record names, first-install no-clobber race, partial deletion, malformed reserved names, record multiplicity/size, destination ABA,
root and entry modes, hardlinks, xattrs, missing prior state, incomplete payload, and special-file substitution. These
are logical process-restart proofs, not physical power-loss simulation. The invoking UID must keep the namespace
cooperative; root, kernel, trusted storage, and ext4 remain trusted. `RELEASE OK` is emitted only from signal-excluded
EXIT finalization after publication reconciliation, descriptor-bound private-workspace deletion, and final parent sync.

The exact pushed `705fe02c2b3690ac15dbe44e3b836012bfd1ce5d` build completed and reverified the canonical online
snapshot, then stopped before platform compilation when pass-A verifier fixtures treated the outer detached release
worktree as ambient stale state and invoked master-only source checks. It produced no artifact or manifest. The
transaction-scoped fixture Git authority and branch-neutral exact-source contract above remove those assumptions;
artifact evidence remains pending a new exact clean pushed commit and complete cold build.

The exact pushed `b66d44d39317e3e3070aea54a8977d874116fc6c` cold build passed eight release gates, including the full
runtime server smoke, then failed in pass A because the production dirty-source case invoked the master-only release
wrapper from the detached pass repository. Cleanup then failed closed before mutation: the authenticated online tree
alone had 188,598 descendants while the retained-authority helper admitted only 131,072; the complete retained workspace
had 203,012 descendants. No Debian, Android, or Windows artifact, manifest, publication, release, or prerelease was
created. Log `/tmp/rustdesk-build-b66d44d.log` has SHA-256
`ca08d47857c7b243c445b5c011436f350148ccd72e15bbab1d658bba3de71d12`. The isolated production fixture,
explicit capacity and capability proof, 524,288-entry bounded authority, authenticated executor, and empty-root-only
terminal deletion design above supersede those failed paths. Exact-commit artifact evidence remains open pending a
complete cold build from the exact pushed commit.

The exact pushed `6d4030c05eae830c43d90d0a233759f660297db2` cold build passed all nine pass-A release gates, including
core verification, the Windows harness, runtime server smoke, Flutter/Dart, native codec, Apple, Rust/Dart audit, and
all fail-loud fixtures. Its first Debian package build then failed closed because `dpkg-deb` rejected mode-`0700`
`preinst`; the private release snapshot's `umask 077` modes had crossed the package boundary through mode-preserving
control-script copies. The same review established that ordinary copied payload files could retain private
`0600`/`0700` modes even after `--root-owner-group` normalized archive ownership. The wrapper removed its workspace
and produced no artifact, manifest, publication, release, or prerelease. Log `/tmp/rustdesk-build-6d4030c.log` has
SHA-256 `aa19faf67ca0debec5fc1c9b5c7f3268e5f9baed92e878fe4d69d9ffd511a537`. The single exact-mode Debian tree
constructor and archive-wide verifier above replace mode inheritance; exact-commit artifact evidence remains open
pending a complete cold build from the corrected pushed commit.

The exact pushed `3bd8d4faad27d484d8d77d7e5aff91ce5dd4debf` cold build passed all twelve release source gates,
built and verified pass-A Debian SHA-256
`0cfd0dfabef51b26aa91be5d242172d23572b9ecc658f6cda96242fa5afb68f0` and Android SHA-256
`b9729f337970868422530bdb9fa909ae7d6f918273bd015963e61a759c4a9f61`, then stopped before Windows VM
startup because the outer orchestrator had precreated the Windows publication path and nested harness state
beneath it while the Windows builder correctly required an absent `OUT_DIR` for atomic publication. No Windows
target build, pass B, manifest, publication, release, or prerelease followed. The retained workspace was proved
mount- and inode-closed and removed through the authenticated descriptor-based cleanup helper. Log
`/tmp/rustdesk-build-3bd8d4f.log` has SHA-256
`b946f9501a6e6115302cfc99029eb21b1b062739a2c827d01916ada1133dbb07`. The output-ownership and disjoint-state
contract above removes the contradiction; exact-commit artifact evidence remains open pending a complete cold
build from the corrected pushed commit.

The exact pushed `f4e77bebb1d8f05045b4d2d27c091a2f58103d64` cold build passed eleven of twelve release source
gates and stopped in `smoke-server.sh` before any Debian, Android, or Windows target build. Under the
source-gate load, the root portable password stage and headless file-transfer stage acted after fixed
eight- and six-second startup delays before their independent IPC and direct-listener threads were ready;
the former completed no mutation and the latter's execution-time `grep` discarded the pre-listener
`CONNECT_FAIL` diagnostic. The isolated workspace was proved and removed, and no artifact, manifest,
publication, release, or prerelease was created. Log `/tmp/rustdesk-build-f4e77be.log` has SHA-256
`54a90796f549a8e8b7d6f6ec6374bb07bcc20431191ca82e6e24cd9b189ef3c7`. A standalone rerun reproduced
both failures, while an immediate exact stage-2b run that first observed the live TCP and IPC objects
completed the production password transaction and credential keying in 8.7 seconds. The source contract
now removes every startup, event, capture, and teardown timing guess. A fixed 60-second monotonic checker
captures the child start identity once immediately after spawn and requires that retained identity for every
later observation and pidfd signal. Listening and parked proofs require exact TCP/UDP state, exact-process
listener ownership, transition records, and both UID-scoped Unix-listener kernel inodes in that process's
descriptor table. A dedicated typed main-IPC readiness response is connected under one hard deadline, bound
by `SO_PEERCRED` to the retained PID, and start-identity checked before request and after response; the shell
adds an outer hard timeout and re-proves both IPC inode mappings afterward. Probe and log files are
descriptor-pinned, cleanup authority records device/inode identity before removing only exact entries, and
the limiter's sole 64-second semantic interval continuously checks the retained child. The behavioral fixture
rejects dead or substituted processes, foreign-owned IPC listeners, stale socket paths without a successful
typed transaction, and a transaction that exceeds its complete deadline. Runtime containers mount source
read-only; only the full-transcript build stage receives a writable bind. Isolated stages preserve their real
exit status and use non-pipeline output assertions. The password watchdog is derived from the exported
600-second admitted-operation recovery bound and has a finite forced-kill ceiling, and the file-transfer probe
reports success only after successful serialization, successful protocol sends, and a non-empty
`PeerInfo.username`. Exact-commit artifact evidence remains open pending a complete cold build from the
corrected pushed commit.

`docs/RELEASE-VERIFICATION.md` makes the manifest itself an independently authenticated input and rejects
same-host package/checksum substitution, partial sets, identity mismatch, or any unsigned override.
`docs/ANDROID-SIGNING-RECOVERY.md` closes the Android break-glass obligation: verified offline backup is the
only loss recovery for the existing identity; suspected compromise retires that package identity and requires
a new package name, new key/pin, clean build, authenticated notice, and data-wiping uninstall/reinstall. The
current pipeline has no ad hoc certificate-lineage or pin-bypass path.

Historical double-builds at older named commits exercised the harness and produced byte-identical artifacts.
Those commits include `6fbae50`, `ede091e`, and `a5bd577`; their artifact hashes are intentionally not
repeated in this live ledger because they prove only those old source states. The `5e03011` MSI proof was later
invalidated across calendar days and led to the `SOURCE_DATE_EPOCH` fix. These records establish historical
harness behavior, not current `.6` release evidence.

The required sequence is: settle source and normative documentation, update inventory and codec/status hashes,
bump `FORK_VERSION` last, verify, commit, push the exact clean HEAD, then run the full cold build. This tracked
source does not substitute for the generated exact-commit artifact manifest, and no `.6` publication is claimed.
## Historical live-QA closure (2026-07-06 through 2026-07-07)

Acceptance testing of the old `v1.4.7-hardened.1` prerelease exposed five clusters: Windows service/status
resilience, desktop settings/password coherence, stale UI surfaces, Android boot/capture lifecycle, and
logind-less Linux connection-manager startup. The investigation log and its temporary present-tense
investigation and treatment notes are superseded by the implemented closure rows in this ledger.

The corresponding source treatments landed historically as `98fc028` (headless CM startup), `b1c243c`
(settings/password and unlock-PIN excision), `66ec419` (Android boot/capture/listener teardown and honest
status), `741d3b1` (Windows resilience and honest desktop status), and `79078c0` (remaining UI coherence).
Later service, IPC, installer, input, and tunnel hardening further supersedes that snapshot. These old commits and
their tests are historical traceability only; they do not prove current `.6` artifacts, whose native and
reproducibility evidence must name the exact commit in the R-B2 manifest.
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

**R-B13 / Appendix C #129 — CVE-2026-1861 / CVE-2026-2447 libvpx remediation — SOURCE CLOSED; ARTIFACT EVIDENCE IS OWNED BY THE EXACT-COMMIT R-B2 TRANSACTION.**
The advisory affects the VP9 encoder's `write_superframe_index` path, not the
VP8/VP9 viewer decoder. The prior decoder characterization was incorrect.
libvpx v1.15.2 and v1.16.0 both predate the fix. The fork retains v1.15.2 and
applies canonical upstream commit
`d5f35ac8d93cba7f7a3f7ddb8f9dc8bd28f785e1` as overlay port revision 1. The
source archive and exact patch bytes are independently SHA512-pinned and captured
for offline builds. Linux x64 and Android arm64 staged native trees are keyed to
the baseline plus complete libvpx source/overlay identity. Windows verifies the
same inputs and an exact 25-package MSYS2 plus pinned native-tool acquisition closure, disables
binary caching, and rebuilds changed libvpx in each clean offline build overlay;
it cannot silently retain the vulnerable library from the golden image.
R-B13 and Appendix C #129 are the normative pin, cache-identity, forced-rebuild,
encoder-finding, and accepted-decoder-residual disposition.
`scripts/native-codec-watch.sh` rejects pin/patch/ref drift, network source
fallback, existence-only Linux/Android caches, missing Windows rebuild plumbing,
or any unresolved advisory ledger entry, and its mutation self-test proves those
rejections.

**The remaining native-decode residual is distinct (recorded 2026-07-05 under the universal-deployment re-rating).**
The in-process VP8/VP9, image, audio, clipboard, and compression decode paths on
the peer-reachable **viewer** surface retain the general native-memory-safety
residual accepted by Appendix C #2b. Closing this VP9 encoder CVE does not claim
those decoders are vulnerability-free. The controlled/`--server` role encodes
its own screen; its inbound native decode remains Opus behind an
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

- **UPCOMING RELEASES — Linux service-child lifecycle ownership — USER-REQUESTED
  2026-07-16; OPEN.** Replace process-name/text-based server cleanup with an
  init-system-independent ownership protocol. This is required to support Debian
  installations using SysV init, OpenRC, runit, or a manually supervised daemon;
  systemd cgroups may be defense-in-depth on systemd hosts, but MUST NOT be the
  foundation of correctness. This item is future-release work and is explicitly
  **not authorization to stop, restart, upgrade, reconfigure, or otherwise disturb
  the currently deployed host service**, which is operationally running an older
  release.

  Required implementation and release closure:

  - The `--service` supervisor must retain direct ownership of every server child
    it launches. Normal replacement/shutdown must target that owned `Child` or a
    Linux `pidfd`, send `SIGTERM`, wait for a bounded graceful-exit interval, and
    use `SIGKILL` only for the same revalidated child if the interval expires.
  - Each service-owned server must inherit a dedicated parent-liveness
    pipe/socket (or an equivalently race-safe kernel primitive) across the actual
    privilege-drop/exec path. Supervisor death closes the channel and causes that
    child to shut down; this behavior must not depend on systemd and must not
    apply to user-owned/portable `rustdesk --server` processes.
  - Crash recovery must use an atomically written, root-owned child record that
    binds at least PID, `/proc/<pid>/stat` start time, boot identity, executable
    device/inode, service generation, and the service-owned role marker. A new
    supervisor must open a `pidfd` where supported and revalidate every available
    identity field immediately before signaling. Missing, malformed, stale, or
    ambiguous evidence must fail closed by signaling nothing and reporting the
    condition; a PID or command line alone is never ownership proof. A compatible
    fallback for supported kernels without `pidfd` must perform the same
    start-time/file-identity revalidation around `kill(2)` and handle the residual
    race explicitly.
  - Delete the global `ps | grep | awk | xargs kill`, broad `pkill -f`, and any
    equivalent sweep as lifecycle authorities. The current `/proc/<pid>/exe`
    pathname-string fallback must not be treated as executable identity across
    mount namespaces: use file identity plus the service-owned relationship.
    Another installation, a portable server, a build/smoke process, and a Docker
    process must remain untargetable even when their visible argv contains
    `rustdesk --server` or their in-namespace path is identical.
  - On systemd, `KillMode=control-group` remains an additional containment layer
    for unit-owned descendants, never a substitute for the portable supervisor
    protocol. Packaging and service scripts for every supported init path must
    invoke the same graceful supervisor shutdown rather than rediscovering
    processes by name.
  - Release gates must behavior-test normal restart, graceful stop, a wedged
    child requiring bounded escalation, supervisor crash, stale/corrupt records,
    PID reuse, executable replacement/deletion, identical argv from a different
    executable, an identical in-container pathname backed by a different inode,
    user-owned and non-root servers, and the real privilege-drop/exec chain. At
    least one Debian non-systemd lifecycle harness is mandatory alongside the
    systemd test. The release must also prove that a concurrent Docker smoke
    `rustdesk --server` survives every service lifecycle event for which it is
    not an owned child.

- **CURRENT RELEASE HARNESS — same-host smoke coexistence with an operational
  older RustDesk service — USER-REQUESTED 2026-07-16; CLOSED / RUNTIME PROVEN.**
  The current release verifier must
  be safe to run on a build host whose currently deployed RustDesk release is
  operationally untouchable and may still contain the historical root
  `ps | grep -E 'rustdesk +--server' | ... | kill -9` cleanup. The verifier and
  smoke harness MUST NOT request sudo/polkit, stop/restart/upgrade/reconfigure the
  service, signal any pre-existing RustDesk process, or require a VM merely to
  avoid that historical matcher. Failure to establish safe coexistence must stop
  before the runtime stage and leave the release smoke **unproven**; it must never
  silently skip the gate or claim a full release pass.

  Required smoke-harness closure:

  - Remove literal `rustdesk --server` text from host-visible Docker-client and
    container-shell command lines. In particular, do not pass the current large
    inline `bash -c` stage bodies through `docker run`; invoke mounted, immutable
    stage files (or an equivalently inspectable mechanism) whose contents are not
    copied into those processes' argv.
  - Launch the exact built RustDesk executable through a minimal audited smoke
    launcher that supplies a neutral test-only `argv[0]` and exact argument 1
    `--server`. The executable file, `/proc/<pid>/exe`, role argument, environment,
    HOME/config behavior, privilege/UID cases, IPC, bind shim, and runtime code
    must otherwise remain the same. A source/behavior gate must prove that Linux
    RustDesk role selection and security identity ignore `argv[0]`, consume
    `--server` from argument 1, and obtain executable identity from
    `current_exe()`/`/proc`; any future semantic use of `argv[0]` invalidates this
    compatibility launcher and fails the release gate.
  - Before the smoke, record the host's pre-existing matcher baseline without
    signaling anything. While every runtime stage is live, prove that no new
    Docker client, shell, launcher, RustDesk server, helper, or cleanup process is
    selectable by the historical regex. The expected old host server may remain
    in the immutable baseline; the smoke must add zero matches. The proof must
    cover the full host-visible process tree, not only `/proc` inside the
    container.
  - Add a non-destructive regression fixture for the historical selector and
    prove it selects a production-shaped `argv[0]=rustdesk, argv[1]=--server`
    control process but does not select any smoke process. Separately prove via
    `/proc/<pid>/exe` and NUL-delimited `/proc/<pid>/cmdline` that the smoke still
    runs the exact intended executable with exact role argument; textual evasion
    must not become executable substitution or role weakening.
  - Preserve the existing network invariants: Docker publishes no host port, the
    test listener is rewritten only to container loopback `127.0.0.1:21118`, and
    the runtime socket audit still requires exactly one IPv4 TCP listener and
    zero UDP. Smoke cleanup must retain and signal only stage-owned identities,
    never use `pkill`/name scans, and remain bounded on every failure path.
  - `scripts/verify-release.sh` must exercise this coexistence contract as part
    of the mandatory smoke gate. Its test must include an inert pre-existing
    production-shaped matcher baseline and must fail if any stage reintroduces a
    host-visible `rustdesk +--server` candidate. Documentation and diagnostics
    must distinguish this current harness compatibility work from the separate
    upcoming-release fix to RustDesk service-child ownership above. This smoke
    work must be completed before the current verifier is resumed on the
    operational host.

  Implemented current-release closure: `scripts/smoke-server-stage.sh` removes
  inline stage bodies from host-visible Docker argv; the descriptor-bound
  `scripts/smoke-server-launcher.c` executes the intended ELF with neutral
  `argv[0]=rd-smoke-server` and exact argument 1 `--server`; and
  `scripts/smoke-process-guard.py` records and monitors the full host `/proc`
  selector baseline without signal authority. Each server start separately
  proves exact PID/start time, executable device/inode, and NUL-delimited argv.
  The release source gate rejects host networking/PID sharing, published ports,
  inline shell bodies, broad signals, selector-shaped launches, weakened process
  proof, or any Rust semantic dependency on argv zero. Runtime source remains
  read-only after the build, binds only container loopback, and the existing
  one-TCP/zero-UDP audit remains mandatory. This closure makes no lifecycle
  change to RustDesk itself and does not close or advance the upcoming-release
  service-child ownership item above.

  Closure evidence (2026-07-16): the complete default `scripts/smoke-server.sh`
  passed beside three stable pre-existing historical-selector matches. The
  whole-host monitor reported `baseline_matches=3` and zero new matches; every
  tested server reported exact executable device/inode plus
  `argv0=rd-smoke-server role=--server`; the runtime socket proof reported only
  `127.0.0.1:21118` inside the container and zero UDP; and the final guard drain
  completed cleanly. No service operation or pre-existing-process signal was
  performed. The separate upcoming-release Linux service-child lifecycle item
  remains **OPEN**.

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
- **R-V3 independent CPace audit — ⛔ OUTSTANDING; AI REVIEW PERFORMED 2026-07-02 (findings
  resolved @4eb6912).** The published AI-conducted review (docs/CRYPTO-AUDIT-2026-07-02.md)
  reproduced the §10.4 construction byte-for-byte with a separately implemented stack
  (libsodium ristretto255 + from-scratch encoding/HKDF) against the published CFRG
  draft-21 vector AND both fork anchors; first-principles analysis of the state machine,
  two-key secretbox, constant-time paths, R-P3 MAC composition, R-S17 host-proof, and
  Argon2id PRS. Three findings raised and RESOLVED: F-1 (viewer stored plaintext → now
  the derived Argon2id PRS), F-2 (constant-time gate added to verify.sh + ignored dudect
  probe), F-3 (deps already resolved in-tree). This was a Claude Opus single-model review,
  not organizationally independent and not a professional external cryptographic audit.
  It therefore does not satisfy R-V3's required independent expert sign-off. The external
  audit remains a production-exposure blocker; scope and limitations of the completed AI
  review are recorded in the report.
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
  The AI review above is complete (2026-07-02, docs/CRYPTO-AUDIT-2026-07-02.md); the independent
  external expert audit required by R-V3 remains outstanding.
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
  `scripts/verify-release.sh` runs it with `verify.sh`, the Windows harness self-test, the online-input mutation
  suite, the Android Gradle execution-cache gate, the Android Rust target check, `smoke-server.sh`,
  `dart-verify.sh`, `native-codec-watch.sh`, `audit.sh`, `dart-audit.sh`, and `test-build-faillo.sh`. The fast verifier asserts that exact ordered twelve-gate
  bundle, including the Apple gate and the release-gate ledger/requirements
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
  and the `Dialog2FaField`/`kUseTemporaryPassword` Dart stubs.
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
green (the `verify-release` bundle — verify.sh / Windows harness self-test / smoke-server / dart-verify /
native-codec-watch / apple-conform / audit / dart-audit / test-build-faillo — plus `flutter-verify` for the flutter-feature
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

Excise by root cause, not by scattered line. Each source change reruns the applicable focused gates; R-B2
reproducibility is established only by the final clean committed Debian/Android/Windows cold double-build, not
separately claimed for every `.6` removal. Any code-audit help
uses **Opus-1M subagents told to research extensively** — the recurring failure mode in this very
sweep was agents trusting a stale comment (e.g. "the dialog shows the fingerprint" — it does not), so
every claim must be verified against source. Tiers 1–2 are the priority (a user sees them / a box can
mis-pin); Tiers 3–4 are the coherence work that lets this tree finally read as
correct-from-the-first-place. This section supersedes the "Inert dead-code leftovers" sample above.

**Active native-codec requirements ledger.** The SHA-256 consumed by
`scripts/native-codec-watch.sh` and recorded identically in
`docs/NATIVE-CODEC-WATCH.md` is:

```text
90fce7314b16cc7de651ce746891b5878a354b173e82d752ba7d2df84f1c2aef  requirements.html
```

This hash binds the final normative requirements text, including R-B9, R-B13, and Appendix C #130. It is a
source-ledger identity; exact-commit artifact evidence is carried separately by the R-B2 manifest.
