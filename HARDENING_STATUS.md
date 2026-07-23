# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Superseded work-log material (intermediate `PARTIAL`/`TODO`/deferred
notes, and — as of 2026-06-28 — the reverted native-worker-sandbox slices) is
removed from this live ledger because it is misleading as current status. Git
history remains the traceability record for that intermediate work.

## Current Verdict

> **Current `.6` source verdict (2026-07-14): implementation and release-harness state are tracked here. Artifact and reproducibility proof exists only for an exact clean pushed commit whose complete `scripts/build-release.sh` transaction succeeds and emits the matching `dist/SHA256SUMS`; this source ledger makes no publication claim.** Earlier artifact hashes in this file prove only the older commits named beside them and must not be promoted as evidence for the current source tree.

**Current machine inventory expectation.** `Cargo.lock` has 905 package records: 36 git-sourced records from
26 unique git source URLs, including 26 rustdesk-org records from 20 unique rustdesk-org URLs.
`flutter/pubspec.lock` has 199 package records, including 8 git records and 7 rustdesk-org records;
`flutter/pubspec.yaml` declares 58 main and 6 dev dependencies, a 64-name union. `.github/workflows/` has
zero enabled definitions, seven inert `.disabled` reference definitions, one documentation file, and eight
regular files total; Debian, Android, and Windows releases are script-owned targets, not CI jobs. `build.py`
has 531 lines and the tree has six tracked `build.rs` files. The legacy root Docker builder is absent;
there is no root `Dockerfile`, root `entrypoint.sh`, or translated upstream README build path. The Rust inventory has 871 lexical `unsafe {`
blocks across 247 tracked Rust files, 74 of which contain at least one; this is explicitly not AST proof.

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
and the flag-gated sinks the guard's message set misses now key on `AuthConnType`/exact voice-call
input ownership —
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

**R-S14/R-T4 Android MediaProjection owner and capture-demand finality — SOURCE CLOSED / GATED;
EXACT TARGET-LOCAL APK VALIDATED 2026-07-23; PHYSICAL-DEVICE AND FULL RELEASE VALIDATION PENDING.**
Platform: Android controlled-side foreground
service. Endpoint/action: authorized connection admission/removal, projection consent/replacement/
revocation, `MainService.onDestroy()`, explicit app Stop (`destroy()`), and the `MediaProjection`/
`VirtualDisplay`/`ImageReader`/`Surface` objects created for screen capture. Boundary: one exact
foreground-service projection/callback owner plus live PAKE-authorized Remote demand ↔ every capture
resource derived from the user-granted projection token. The 2026-07-11 correction made service
destruction and explicit Stop share complete resource teardown, but the inherited start path still
registered no `MediaProjection.Callback`, swallowed a revoked-grant `SecurityException`, and then
reported capture active even if no `VirtualDisplay` existed. Fresh consent replaced projection state
without an exact callback transition. Native last-connection teardown also treated view-camera,
unauthorized, and disconnected rows as desktop-capture demand.

Initial source closure: installation now retires the old projection while preserving only live capture demand,
registers one exact callback before display creation, and resumes only if that demand remains. Exact
`onStop()` ignores a replaced callback, clears readiness, and fully releases the display, reader,
surface, raw-video, and audio pipeline. Start propagates a Boolean display result and commits active
state only after a non-null `VirtualDisplay`; revoked/stopped/null state fails, fully retires the bad
owner, and asks for fresh consent. Explicit stop clears demand, while service teardown also unregisters
and stops the exact projection. That intermediate correction defined a Rust-side last-live-connection
classifier as authorized, non-disconnected Remote only—never FileTransfer, ViewCamera, Terminal, or
PortForward—and covered it with a focused Rust regression. The later exact service-owned demand
correction below supersedes that split classifier/stop-edge topology. `scripts/verify.sh` and the semantic mutation verifier
bind the owner/callback order, transactional active-state commit, delayed-consent demand gate, full
teardown, native classifier, requirement, disposition, and this ledger. The persistent foreground
service/listener design remains intact; file transfer remains independent. This controlled-side
defect is not source proof of the reported Android outgoing-viewer hang and is not a root/LPE,
host-modification, public-exposure, container-escape, exploitation, or compromise finding. Exact APK
compilation and the original swipe/relaunch sequence remain R-B2/R-B10 device-validation obligations.

Follow-up correction (2026-07-23), **exact Android connection-type resource authority**: the earlier
classifier closure was incomplete. `Data::Login` already carried the server-resolved
`CmAuthConnType::{Remote,FileTransfer,ViewCamera,Terminal,PortForward}`, but `ConnectionManager` discarded
that enum while constructing the serialized `Client`. Rust last-connection teardown and Kotlin
`MainService.add_connection` then independently reconstructed Remote by negating parallel presentation
booleans; both predicates omitted PortForward. A password-authenticated tunnel could consequently request
or reuse MediaProjection despite needing no display, and could make Rust retain the capture pipeline after
the last real Remote disconnected. This was a defense-in-depth R-S19 capability-coherence and resource
ownership defect, not a PAKE/password bypass, local privilege escalation, public-listener change, host
modification, or evidence of exploitation.

The validated enum now crosses the `Client` boundary intact. Android has one closed exact-tag decoder;
unknown, case-varied, or future unhandled tags
fail closed before notification, voice ownership, or capture demand. The foreground service admits
MediaProjection demand only for exact Remote and voice-call ownership only for exact Remote/ViewCamera;
parallel booleans and `port_forward` remain presentation data and no longer decide either resource. The
Android-free Kotlin transition regression, shared source gate, focused voice
ownership verifier, and independent workspace mutation verifier bind the carry-through and both policies.
The persistent service is deliberately unchanged: Android documents that a started service has a lifecycle
independent of its creating Activity
(<https://developer.android.com/develop/background-work/services>), while MediaProjection separately requires
callback registration before `createVirtualDisplay()` and exact resource cleanup on `onStop()`
(<https://developer.android.com/reference/android/media/projection/MediaProjection.html>). The design
implication is persistent listener/service ownership plus exact per-connection capture demand—not killing the
service to recover incoherent state.

Prior exact-type follow-up verification (2026-07-23): the Android-free Kotlin decoder/policy regression compiled with
the pinned Kotlin 2.1.21 compiler and passed every canonical/noncanonical/type-policy assertion. The pinned Android
release graph completed `:app:compileReleaseKotlin` with only `:app:compileFlutterBuildRelease` excluded because
this bounded check did not generate the separate Rust/Flutter bridge: `BUILD SUCCESSFUL` in 27 seconds, with 228
actionable tasks (227 executed, one up-to-date) and only existing SDK/plugin/deprecation warnings. Both focused
then-current Rust classifier tests passed; pinned Rustfmt passed the changed Rust file; the focused Android ownership verifier rejected
all 61 deliberate mutations; the independent workspace verifier passed normally and through its complete source
mutation matrix; edited Bash syntax and native-codec normal/self-test gates passed; and the requirements hashes
match. No APK was assembled or installed. Full exact-commit APK/release artifacts and real-device behavior remain
R-B2/R-B10 obligations. The Rust classifier and detached stop edge from that checkpoint are superseded by the
exact service-owned owner set below rather than retained as current design.

Second follow-up correction (2026-07-23), **serialized service-owned capture demand and exact callback-object
lifetime**: the exact-type correction still split one resource decision across independent Rust connection tasks.
`ConnectionManager::remove_connection` mutated `CLIENTS`, released that lock, computed that no Remote remained,
and only afterward called `MainService.rustSetByName("stop_capture")`. A concurrent newly authorized Remote could
enter JNI first and request capture; the older removal could then deliver its stale global stop last. The final
native map would contain a live Remote while persistent `MainService.captureRequested` was false. That is a
source-proven mechanism directly consistent with screen control hanging while a separate file-transfer connection
works and Force Stop repairs process state, although exact device causality is still not claimed.

`MainService` now owns a service-owned exact Remote connection-ID set. Its synchronized Rust callback dispatch
upserts only a positive, authorized, exact-Remote ID, retires only the exact removed ID, and reconciles the complete
set to capture start/stop before releasing the same service monitor. Both distinct-connection delivery orders
therefore converge: removing one owner cannot clear another, and there is no detached stop that can arrive after a
newer admission. Removal attempts capture-owner and voice-owner retirement independently and reconciles capture
afterward even if the other subsystem reports a rejected identity, so a partial cleanup result cannot leave the
derived capture state stale. The Rust global demand snapshot/classifier and `stop_capture` command are deleted.
Service teardown closes further controlled-resource admission before clearing capture/voice owners and releasing
MediaProjection; late pointer/key and controlled-state callbacks are refused.

The JNI object lifetime is closed at the same boundary. Initialization now retains the exact callback-owning
`MainService` separately from a process-lifetime global reference to Android `applicationContext`; the NDK context
receives only that retained application object, never a Service or JNI local reference whose native call has
returned. `onDestroy()` stops the server and uses exact-object JNI release to clear only its own `GlobalRef`; a
delayed old Service cannot clear a replacement. Kotlin behavior regressions cover unauthorized and non-Remote
exclusion, concurrent Remote aggregation, remove→add and add→remove convergence, same-ID type replacement, and full
clear. Focused/shared/independent mutation gates bind the serialized owner update, reconciliation, stale-stop
absence, teardown admission latch, exact JNI object release, R-S14, Appendix C #205, and this ledger. Exact
APK validation is recorded below; physical-device reproduction and the full R-B2/R-B10 release remain open.

The same service/listener generation now continues through every accepted Android `Connection`, its independent
connection-manager callback thread, and controlled input JNI call. Native dispatch holds the exact callback-context
read guard and refuses a zero, stopped, or replaced generation before entering Java, so an old connection's delayed
add/remove/voice/input event cannot mutate a replacement Service even if the server has restarted and eventually
reuses the same positive connection ID. `startServer(this, ...)` returns that exact generation only after JNI proves
the caller is the currently retained `MainService` object; an overlapping obsolete Service therefore cannot bind
its generation to a replacement callback owner. `stopServer(generation)` uses compare-and-exchange rather than an
unconditional global bump, so delayed destruction of an obsolete Service cannot stop the replacement listener.
Exact object identity, exact listener generation, and the service-owned connection-ID set are therefore one closed
lifecycle boundary rather than three independently timed best-effort facts.

Final confined verification (2026-07-23): the Android-free Kotlin regression compiled with pinned Kotlin 2.1.21
and passed exact connection-type decoding, capture/voice policy, positive owner admission, two-Remote aggregation,
both cross-connection delivery orders, same-ID type replacement, and clear. Locked/offline pinned Android Rust
`cargo ndk check --release --features flutter --lib` passed. A disposable, non-root, networkless full Android
arm64 release graph generated `app-arm64-v8a-release.apk` (45.0 MB); the build tool reported success, while the
outer disposable-cache cleanup wrapper separately returned nonzero until immutable cache permissions were
normalized and the scratch was removed. The APK was neither retained, installed, nor published. Locked/offline
Rust 1.75 `cargo check --lib --features linux-pkg-config` also passed the shared library with existing warnings
only. The focused ownership verifier passed and rejected all 101 deliberate mutations; the independent workspace
verifier passed normally and across its complete source-mutation matrix. Pinned Rustfmt, edited Bash/Python syntax,
native-codec normal/self-test gates, synchronized requirements hashes, unchanged `Cargo.lock`, and
`git diff --check` passed. This is source/build evidence, not a claim that the original swipe/relaunch/Force-Stop
sequence has been reproduced on a physical Android device; that device validation remains open.

Exact target-local signed-artifact validation (2026-07-23): the first official A/B attempt at clean pushed commit
`5c64523493ea7c9c46f48753b8cfbc6e637d9bbd` stopped before source snapshotting or compilation. The reviewed
2026-07-22 Rust advisory refresh had changed six locked registry packages and correctly pinned the resulting
Cargo-vendor subtree as `3caca8746b4ada39db1d9ecd63db1cf2d3786e050a5bced400e4d2cf6bb45bea`, but had omitted the
encompassing full-`online/` closure update. The old full pin was `a7581f0ffa4fa924d4eacfe6c2bef9dec37a2ce2d06740c04037489341d904ac`;
the current tree computed as `5ad074e7bfba62f87d3dc58614c0b33749b513d353bcaf6eaa315a6d8bf67d07`.
The exact aggregate delta—ten additional files, two fewer directories, and 71,618 additional content bytes—was
identical to the reviewed vendor-subtree delta; the vendor source-map hash remained pinned and unchanged, and no
non-vendor entry had a post-refresh modification time. The build gate therefore failed closed on an incomplete
maintenance transaction; it did not fetch, regenerate, trust, or compile the stale tree.

Commit `29915f0075f4d1464361f218e61dd7d7e7072b85` completed and pushed the enclosing closure pin after the
canonical record was written and both the full tree and vendor subtree were independently reverified. The exact
clean pushed commit then completed the default target-local A/B transaction in immutable Android builder image
`sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121`, numeric UID/GID 1000,
with no network, a read-only root, all capabilities dropped, no-new-privileges, bounded resources, private
exact-commit sources, and the fresh private 25.7-GB closure snapshot. Passes A/B completed native release builds in
2m27s/2m23s and independently produced identical Gradle projection
`b95fd5dae80230287c850081fdf0804503888bb67f337649f24b1075770f02b2`. Both 44,966,946-byte APKs
were one-signer v2/v3 valid and passed the manifest, mobile at-rest bootstrap, certificate, checksum, source
pre/postcondition, and independent remount validators. They were byte-identical at SHA-256
`20af1c99178feb02e3a584a4148dbc5ce8129261361f7f37d0c09461d3e6f02e`; the retained 113,790-byte
transaction log has SHA-256 `bc8f14c77662d06b9c08cb27c62cfd251447e335463f2add7214bf031c3d8d50`.
The published APK/checksum are current-UID/GID, mode 0400, one link, and the private workspace was removed.
This validates packaging of the service-owned capture/generation correction at that exact commit. It does not
reproduce the swipe/relaunch/Force-Stop sequence on a physical device and is not the full independent-snapshot
R-B2/R-B10 release transaction; both remain open.

**R-D7a/R-T4 Android outgoing-client Activity/isolate ownership — SOURCE IMPLEMENTED / GATED;
ANDROID ARM64 RELEASE TARGET BUILD VALIDATED; ON-DEVICE VALIDATION PENDING
(2026-07-18).** Platform: Android viewer-side sessions in a process deliberately retained by the controlled-side
`MainService`; the service/listener/capture lifetime is unchanged. Endpoint/action: Flutter Activity/isolate
creation and teardown, `MainService.onTaskRemoved()`, JNI
client-session ownership, and Rust `session_add_existed`/`session_add`/`session_start_`. Boundary: one outgoing
Flutter UI owner ↔ the process-static native peer/session table that survives task removal. Attack surface closed
in source: the old argument-free global client drain is deleted. Each Activity allocates a monotonic native
generation before `super.onCreate`; Dart binds that generation to its isolate-wide UUID before `runApp`; Rust
admits add/attach/start only while a read-held exact owner binding remains live through table insertion or I/O-loop
spawn. Owner replacement and exact generation+UUID retirement hold the opposing write lock through the UUID-scoped
drain, so neither a delayed obsolete Activity/task callback nor a check/use race can retire, insert, start, or close
the replacement owner's sessions. Starting a replacement generation proactively drains the superseded UUID; task
removal consumes only owner pairs recorded by stopped Activities. An invalid/missing/stale binding fails closed,
while `MainService` remains persistent and continues owning only incoming controlled-side service state.
Follow-up closure (2026-07-19): a stopped `MainActivity` can remain in Android's back stack while a newer
instance advances the native generation; returning to that older instance runs `onStart()` without another
`onCreate()`. It now reconciles only when its isolate UUID is still the exact current native owner. The read-only
resume returns that UUID's authoritative generation when Android may have interrupted an earlier JNI response;
it never mints a generation, replaces an owner, or drains sessions. If another isolate has become current, the
stale Activity retires only its own exact recorder/session authority and finishes without altering the replacement.
Thus an OS-restored Activity cannot keep rendering with stale authority or reclaim a newer isolate, and delayed
teardown still cannot retire the replacement. Initial Dart owner registration also fails visibly closed: a false
result closes that stale Activity before `runApp`, rather than launching a UI whose native add/start calls must
all fail.
Follow-up closure (2026-07-20), **Android outgoing-viewer I/O and media-worker completion ownership**:
the UUID/generation transition previously proved only that a close was requested and the stale map entry was
removed. Initial viewer start discarded its I/O `JoinHandle`; reconnect overwrote the prior handle without a
join; and the video decoder, audio decoder, and voice-capture workers discarded their own handles. The retained
Android process could therefore outlive the task while an old outgoing worker tree still owned native state—the
observed shape in which file transfer (a separate session) remained usable but screen control hung until Android
Force Stop terminated the process. Git history places these detach shapes in the fork baseline rather than the
recent owner-generation work; this is a source-proven mechanism consistent with the report, not yet an on-device
causal reproduction. Initial start now retains the exact I/O worker. Reconnect and final owner teardown serialize
through that worker slot, request close, join the old round, and only then admit replacement. The I/O worker in
turn owns its exact video/audio decoder and voice-capture workers, closes their channels/signals, and transfers
their exact handles to a bounded fixed completion pool before awaiting them and marking the round disconnected.
Explicit session close and test cleanup use the same completion sink. The incoming `MainService`, controlled
listener, projection grant, and capture resources are deliberately unchanged.
Follow-up correction (2026-07-21), **shared controlled-audio and hard-drop completion ownership**: the broader
worker audit found one exception to that closure. `start_audio_thread()` still returned only its channel sender and
discarded the controlled-side voice decoder's `JoinHandle`; accepted format and sender were separate connection
fields; call close retained both; audio disable merely dropped them; and `OwnedMediaThread::Drop` plus
`VoiceCallThread::Drop` joined inline. The sender-only and compatibility-named constructors are deleted.
`start_audio_thread()` is now the sole owning constructor. A controlled connection owns accepted format plus exact
decoder as one `ControlledAudioThread`, refuses overlapping call requests, clears voice authority first, and
closes/awaits that owner on call close, audio disable, format-start failure, and connection close. Normal viewer
and controlled teardown transfer handles to a bounded four-thread completion pool before awaiting; cancellation
after transfer cannot orphan them, while hard `Drop` closes admission and uses a nonblocking handoff to the same
pool. Accepted calls establish Drop-visible global-input ownership before their first await, and close disables
that global input before clearing the flag, so cancellation cannot strand it. Exhaustion or completion-authority
loss aborts instead of detaching. Moving `Connection.closed = true` until after its synchronous CM notification
also preserves the existing Drop fallback if cancellation lands during a
worker wait. This controlled-side defect is shared across platforms and could overlap peer-audio native state; it
is adjacent to, but not claimed as the cause of, the Android outgoing-viewer screen-control report.
Follow-up correction (2026-07-22), **shared outgoing-viewer reconnect round ownership**: the retained exact-worker
join still inherited one earlier state-machine error: `Session::reconnect()` discarded an explicit retry whenever
the current worker was `Connecting`. That let a stuck connection start retain the peer/type worker slot while the
user's retry did nothing. A concurrently completing old `Client::start()` also published `connection_ready`
without proving that its round still owned the session. Android's persistent process can carry this incoherent
viewer state across task swipe/relaunch, while file transfer remains usable through its separate `ConnType`
session. The mechanism is therefore source-proven and consistent with the report, but it is shared viewer-core
code and is not claimed as an on-device causal reproduction or as an Android-only defect.

The session now has one checked monotonic round owner. Explicit reconnect acquires the worker slot, publishes the
replacement round, wakes an exact connecting start (or sends `Data::Close` to an established round), joins the
prior worker and its owned media children, rechecks terminal owner retirement, and only then spawns the
replacement. `Client::start()` races both final retirement and exact-round replacement. Its notification waiters
are registered before the durable round check, closing cancellation-before-registration and check/wait gaps. A
successful start, establishment error, and final disconnected transition are admitted only while that exact round
is current; a stale successful start drops its peer and drains its worker owner without publishing readiness.
Final owner close remains terminal and cannot be reversed by a queued reconnect. This is the common outgoing
viewer core used by Android, desktop, iOS, and future macOS builds; only the generation/UUID layer and persistent
foreground-service amplification are Android-specific.
Verification closure in source: Rust regression tests cover stale-isolate cleanup, owner-scoped control/file-session
drain, delayed-callback ABA rejection, admission/transition lock exclusion, current-isolate lost-response
reconciliation, and stale-Activity replacement-owner refusal. They now also hold a synthetic outgoing worker open, prove an owner transition
cannot report completion before releasing and joining it, prove a media owner closes admission before joining
its exact worker, cancel an exact connecting round, reject stale success/error publication, and prove durable
supersession covers cancellation before waiter creation. `scripts/verify.sh` gates the typed JNI surface, absence of
argument-free/global drain APIs, registration-before-UI-or-exit order, owner-scoped Activity/service teardown,
read-only current-isolate resume reconciliation, stale-Activity takeover refusal, lock-held add/start/retire
ordering, initial I/O-handle retention,
reconnect/final joins, connecting-round replacement, current-round-only publication, child-worker ownership, the
fixed completion pool, nonblocking hard-drop handoff, the sole
owning audio constructor, and controlled voice-audio close/join sinks. A disposable tracked-file candidate snapshot completed one
offline arm64 release APK compile through `scripts/android-apk-build.sh` in the pinned Android builder as UID/GID
1000 with networking disabled, including the Rust/JNI, Dart/Flutter, Kotlin, and Gradle stages; the expected APK
was checked for nonzero size and then discarded with the scratch tree. This is target-integration evidence, not the
R-B2 final signed/reproducible artifact proof. The real-device connect → swipe-away → relaunch → reconnect sequence
remains pending and is not claimed here. This lifecycle split is Android-specific: iOS has no retained Android
foreground service and keeps the shared next-isolate stale-UUID cleanup. The generation/UUID layer is
Android-specific, while exact outgoing I/O/media-worker completion is shared by Android, desktop, iOS, and future
macOS builds through the common viewer core.

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
Platforms: all controlled-side direct-listener/CPace targets; desktop machine-UUID storage and mobile OS-key
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

**R-S11b/R-S11c/R-S11i — service-owned IPC authority — SOURCE IMPLEMENTED; RECORDED NATIVE WINDOWS CREDENTIAL EVIDENCE; CURRENT CLEAN COMMITTED COLD RELEASE BUILD PENDING.**
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
  `Committing`, `Recoverable`, and `Complete`. After authorization the stable root service is the sole durable
  writer. It persists first, reads the resulting canonical PRS, and authenticates the exact service-owned child by
  executable, argv, direct parent, launch-parent environment, and current runtime generation before sending the
  same UUID with PRS—not plaintext—on raw `_password`; the child applies it only as a nonpersistent runtime replica
  and independently proves its direct root parent. Before any child listener, raw `_service_credential` performs
  the same generation-bound proof and supplies the root PRS-or-empty snapshot. Post-persistence divergence
  fail-stops the service generation. Ordinary main IPC carries no password fallback. A nonsecret status query is
  used only for admitted uncertainty. The packaged polkit policy remains administrator-authenticated.
- **R-S11b-2d/R-S11c-1e — Windows service-owned unattended password authority — SOURCE IMPLEMENTED; NATIVE
  CREDENTIAL-PATH EVIDENCE RECORDED AT THE NAMED TREE.** The stable LocalSystem SCM service is the sole durable credential
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
  are rejected before header wait, and no password or administrator authority is exposed by either case. Retry 15
  authenticated staged executable-affecting tree `ad2dd37c3698945d1071e091c68d26d64bc32b54` in two fresh
  networkless Windows guests. Both passed the native service/credential/SAS/password-finality/input suites and the
  release build, proved the root and portable compiled resources byte-equal with linked VERSIONINFO, and produced
  byte-equal host-revalidated setup/MSI artifacts with package code
  `{6C338D23-A4FA-5F24-B182-47F4526233A8}`. The host equality gate published setup SHA-256
  `66326a7aac84de392268e5cd743adcaa0c1b0c6d880435c80145593c0d7ad2f9` and MSI SHA-256
  `8220ef94cc59bb01fb8c23754d801aaee58648c7ac15d3a864af515addd583ec`; both PTY-driven passes completed with
  no cleanup prompt. This is current-worktree native evidence, not the clean committed R-B2 cold-release transaction;
  the evidence-only ledger wording added afterward does not alter the validated executable inputs.
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
  validates the connected pipe client's elevated token at the receiver, writes the current MSI product's exact
  64-bit install-registry value directly as LocalSystem, and returns `Data::ServiceOwnedShareRdpResult(bool)`.
  R-S11e-23 deletes the retired Inno/WOW64 selector that could previously redirect that policy to stale package
  metadata. The main IPC channel rejects
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
  cfg-isolated to Android/iOS as device-id metadata; after the 2026-07-18 OS-key slice it is also only a
  decrypt-only migration fallback for old mobile at-rest ciphertext after a live OS key has been installed and
  tried, not the primary wrapper key or an unavailable-OS-key fallback. Verification
  closure: `scripts/verify.sh` runs the pk-fallback tests and
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
  UI/FFI setters, or server-pushed option maps. R-S11b-3j subsequently deletes the structured proxy store and
  transport. The retired option names remain pinned empty here because whole-map reads must still mask stale
  stored/default/signed-custom values rather than disclose old proxy-shaped credential strings. `get_key`
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
- **R-S11b-3j — structured SOCKS/proxy transport and credential store deleted — CLOSED/GATED 2026-07-20.**
  Platforms: all direct-IP viewer builds. Endpoint/action: outbound `connect_tcp_local`, `Config2` persistence,
  and the dormant proxy/TLS connector modules. Boundary: local/default/signed-custom configuration ↔ outbound
  route selection and stored proxy credentials. Attack surface closed: direct connections no longer branch on
  configuration at all. `Socks5Server`, `NetworkType`, the `Config::set_socks`/`get_socks`/`get_network_type`/
  `is_proxy` APIs, `Config2.socks` password encryption, `FramedStream::connect`, the proxy-only server validator,
  and the complete `proxy.rs`/`tls.rs` modules are absent. The `tokio-socks`, `tokio-native-tls`, `native-tls`,
  and `httparse` package records leave the lockfile with that code. Retired proxy option names remain pinned empty
  solely to mask stale strings in broad option reads; they have no actuator or structured store. Existing TOML
  with a historical `socks` table remains readable because `Config2` does not deny unknown fields, while a focused
  regression proves the table and its credential strings are never serialized again. `scripts/verify.sh` gates
  the complete source/module/dependency absence, the direct-only connector shape, the retained stale-value pins,
  and the focused regression. The synchronized machine inventory proves 905 Cargo packages, 36 Git records from
  26 source URLs (26 rustdesk-org records from 20 URLs), and 871 lexical unsafe blocks across 247 Rust files.
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
  before `launchctl bootstrap`. `uninstall.scpt` boots out the daemon and removes the deployed helper plus any install-temp
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
  postconditions, propagates synchronous uninstall result, and verifies current-session
  LaunchAgent plus privileged-daemon lifecycle completion. R-S11bi subsequently replaces the initially used
  implicit-domain legacy launchctl verbs with explicit-domain `print`/`bootout`/`enable`/`bootstrap` state proof.
  The Flutter daemon install card keeps its
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
- **R-S11c-10b — Linux helper/tray process cleanup shell pipelines — CLOSED 2026-07-09;
  ALL CURRENT-IMAGE LIFECYCLE AUTHORITY DELETED 2026-07-19.** Platform: Linux installed-service
  helper and tray cleanup. Historical surfaces: `stop_subprocess()`, the server/CM sweeps, and
  `stop_tray_processes()` in `src/platform/linux.rs`. Boundary: service/user helper cleanup ↔ local process table.
  Attack surface closed: root-context cleanup no longer interpolates the
  app name into `ps | grep | awk | xargs kill -9` shell pipelines. It enumerates `/proc/<pid>/cmdline`
  directly and historically matched RustDesk `--cm-no-ui` and `--tray` helpers by `/proc/<pid>/exe` equality to the
  current executable plus exact argv before signaling positive, non-current pids. R-S11c-27a subsequently deletes
  the analogous global `--server` sweep entirely: process-table discovery is no longer service-child
  lifecycle authority. R-S11e-43 later deletes the Xorg basename/argv kill and config-path classification
  residue because R-X14 removed RustDesk's Xorg launcher, leaving no owned Xorg identity to clean up. R-S11e-44
  deletes the service-owned headless-CM process sweep and binds each CM to its exact server parent at spawn.
  R-S11e-45 deletes the final current-image enumerator, the `--cm` restart heuristic, and the `--tray` signal path;
  no global current-image process-table cleanup remains. R-S11e-46 then limits automatic Linux tray creation to a
  non-root user-session principal and makes the tray receiver reject root, so the root service child cannot turn its
  selected display endpoint into an independent privileged UI. Verification closure: `scripts/verify.sh` runs the
  focused replacement/principal regressions, requires the complete deletion, retains the non-root tray receiver's
  same-UID singleton check, and rejects any restored CM/server/Xorg/tray lifecycle sweep or privileged tray edge.
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
  subscriber ids (`pid`, `uid`, and Linux `/proc` start time), while viewer-side `CLIENT_SERVER` voice-call capture is bound to
  the current process identity. The server accepts a Linux `_cm` endpoint only when its socket-credential identity is the
  exact direct child it launched and its CM role is bound into the server-scoped launch-token proof, stores that identity
  only for the lifetime of the CM IPC bridge, and rejects stale/reused, launch-tokenless, wrong-role, or non-child identities before
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
  CM role-bound launch-token and exact direct-parent checks, stale `_cm`/`_pa` socket probe checks, old message absence, and the service-layer
  subscriber-id snapshot. The fixed-path CM endpoint-selection class is closed separately below for macOS and
  non-audio helper consumers.
- **R-S11c-11 — Desktop `_cm` endpoint-selection identity — CLOSED 2026-07-09; Windows extended 2026-07-11.** Platforms: Linux,
  macOS, and Windows desktop CM paths before any non-audio helper authority is disclosed. Endpoint/action:
  server-side selection of the fixed `_cm` listener that receives `Data::Login`, `cm_auth_token`,
  file-authority messages, chat, voice-call state, and future downstream helper leases. Boundary: same-UID
  local process ↔ connection-manager endpoint. Attack surface closed: macOS and Windows no longer accept a raw
  fixed-path `_cm` connect as endpoint identity. The server authenticates the selected CM process shape
  (current executable and the complete exact selected `--cm`/`--cm-no-ui` role on Unix; on Windows through
  the named-pipe server PID), proves the server launch token
  to the CM over a server-proof HMAC context, and then sends a fresh endpoint challenge; the CM listener only
  answers after accepting a current-executable peer with the complete exact `--server` or
  service-owned `--server --service-owned-server` role and verifying that peer's launch-token proof,
  and answers with an endpoint-proof HMAC keyed by the server-minted launch token inherited through the CM
  launch environment. Windows CM launch paths now pass that token environment through both the active-session
  launcher and same-user launcher, and the Windows server-side secondary `_cm` clients for clipboard-file sync
  and privacy-mode state perform the same authenticated connect before sending data. The old Flutter
  theme/language notification side-channel is no longer a `_cm` IPC client.
  Linux keeps a PID-reuse-resistant socket identity (`pid`, `uid`, and proc start time), requires the selected
  CM to be the server's exact direct child, and binds the expected CM role into the same mutual pre-disclosure
  launch-token proof. This deliberately avoids relying on ptrace-gated executable, argv, or environment reads
  across the installed service's nondumpable root-to-user boundary. Stale, preexisting, launch-tokenless,
  wrong-role, wrong-token, non-child, fixed-path squatting listeners, and
  same-binary `--server` signing-oracle attempts fail before `Data::Login` or the per-connection CM token is
  sent. Verification closure: `scripts/verify.sh` runs the `cm_endpoint_proof_*` unit test and asserts the
  server/endpoint challenge/proof variants, directional HMAC proof/verify helpers, server-side proof before
  CM stream use, CM listener server-proof verification before endpoint proof and before spawning the normal
  IPC loop, complete exact macOS process-role and Windows process-shape checks, macOS and Windows
  launch-token environment propagation,
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
  launched to install the Amyuni virtual-display driver. Boundary: installed Program Files helper payload ↔
  service/runtime helper execution. Attack surface closed: the runtime helper derives `usbmmidd_v2`,
  `deviceinstaller64.exe`, and `usbmmIdd.inf` only from the fixed
  Program Files service root returned by `fixed_service_install_path("")`, requires handle-level identity between
  the running executable directory and that fixed service root plus identity between the running executable and the
  fixed installed service executable, rejects reparse/symlink-backed helper directories, helper files, and INF
  files, propagates helper-path trust failures instead of falling through to SetupAPI, and executes
  `paths.exe_path` as the `CreateProcessW` application path. R-S11e-89 later deletes the MSI and dead runtime
  device-removal surfaces because no exact device-instance ownership exists; no installed helper remove mode remains.
  Verification closure: `scripts/verify.sh` asserts the runtime
  fixed-root file-identity proof, non-reparse helper/INF checks, absolute-path helper launch, and `paths.exe_path`
  install launch, rejects swallowed
  helper trust failures, lossy path/INF fallback, `ShellExecuteA`, and bare `INSTALLER_EXE_FILE` launch, and checks
  complete removal-surface absence plus this ledger/requirements disposition.
- **R-S11d-2 — Windows Amyuni IDD cleanup completion authority — INTERMEDIATE DESIGN CLOSED 2026-07-10;
  SUPERSEDED AND EXCISED BY R-S11e-89 ON 2026-07-22.** Platform:
  Windows MSI commit-phase explicit-uninstall custom action. Endpoint/action:
  `RemoveAmyuniIdd` removing the `usbmmidd` Amyuni virtual-display device through SetupAPI. Boundary: installed
  privileged driver state ↔ privileged MSI cleanup state. The original closure made inherited cleanup completion
  fail closed rather than hiding native SetupAPI failure from MSI. The native path returned a
  `DriverUninstallStatus` plus `HRESULT`:
  complete enumeration proving no present matching hardware ID is a successful no-op, successful removal of all
  matching present devices is success, and enumeration/property/class-installer/remove failures are fatal. The
  commit action has no `CustomActionData`, install-root, installed-helper, or process-launch dependency. It signals
  SetupAPI reboot-required state through WiX, and the WiX action is `Return="check"`. The action is
  scheduled only after a successful explicit uninstall transaction; upgrade preserves the installed driver.

  That completion proof did not establish deletion authority. The later ownership audit found that the current
  package ships no Amyuni payload and records no durable current-MSI-product-to-exact-device-instance edge, while
  the action enumerated every present display device and globally removed every shared-`usbmmidd` hardware-ID match.
  R-S11e-89 therefore deletes the action, schedule, export, dedicated SetupAPI source/header and project inputs, and
  both dead Rust removal functions; it preserves detection, use, monitor plug/unplug, and checked fixed-root install.
  R-S11e-90 subsequently deletes the containing custom-action project after moving the remaining broker cleanup into
  declarative MSI state.
  Uninstall now leaves separately owned device state untouched. Stale
  bare-`netsh` `ShellExecuteW` firewall helper examples and their
  commented reactivation path remain deleted. Verification closure: `scripts/verify.sh` and the independent
  mutation-backed validator assert complete device-removal absence, complete RustDesk-authored custom-action
  absence, retained
  install/use behavior, R-S11bw, Appendix C #216, and this superseding disposition.
- **R-S11d-3 — Windows runtime process command provenance — CLOSED 2026-07-10; AUTHORITY MODEL SUPERSEDED BY
  R-S11e-36/R-S11e-37 ON 2026-07-19.** Platform: Windows runtime process probes in
  `src/platform/windows.rs`. The original slice removed `cmd`/`tasklist`/`taskkill` shell selection and deleted the
  service-start IPC-occupant `NtTerminateProcess`/`PROCESS_ALL_ACCESS` fallback. Its intermediate native design still
  treated a basename as process authority: it terminated every matching privacy broker and treated every matching
  `consent.exe` as UAC state. R-S11e-36 deletes broker basename termination and makes privacy instances exact-job/PID
  owned. R-S11e-37 makes ToolHelp only a fixed `consent.exe` candidate source and admits state only after current-session,
  retained-process-handle, and exact no-reparse System32 image proof; it also deletes the unused substring-based
  LogonUI detector. Verification now forbids the superseded termination helpers and binds that final receiver-owned
  process-state model. The IPC bind failure continues to report the occupied endpoint and exit fail-closed.
- **R-S11d-4 — Windows MSI runtime-generated executable cleanup completion authority — INTERMEDIATE DESIGN
  SUPERSEDED AND EXCISED BY R-S11e-90 ON 2026-07-23.** Platform: Windows MSI uninstall/major upgrade.
  Endpoint/action: cleanup of the fixed runtime-generated `RuntimeBroker_rustdesk.exe` sibling in the installed
  Program Files application component. The 2026-07-10 correction made the inherited deferred no-impersonation
  custom action fail closed on malformed path data and deletion failure. The later abstraction audit established
  that no custom code or caller-provided path is needed: the standard Windows Installer `RemoveFile` table directly
  represents an author-specified file not installed by `InstallFiles`, gated by the owning component's removal
  state. R-S11bx/R-S11e-90 therefore replaces the action with one exact non-wildcard declarative row and deletes the
  complete RustDesk-authored cleanup-action DLL, schedule, build, preprocessing, and native dependency surface. This
  entry records the superseded completion check and makes no claim that the deleted custom action remains part of the
  current design.
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
- **R-S11d-10 — Windows portable RuntimeBroker cleanup command provenance — CLOSED 2026-07-10; IMPLEMENTATION
  EXCISED BY R-S11e-36 ON 2026-07-19.** The original intermediate closure resolved `taskkill.exe` through
  `GetSystemDirectoryW`, but a trusted executable did not make machine-wide basename termination an owned action.
  The portable wrapper does not own installed-service privacy mode, so R-S11e-36 deletes broker copying and cleanup
  rather than retaining that compatibility surface. No `taskkill`, broker-copy path, or portable basename cleanup
  remains; current verification forbids all three and this entry records the superseded history without requiring
  deleted code.
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
  returns and before monitor plug-in proceeds. This entry is only the install/update fallback; R-S11e-89 later
  deletes every device-removal path rather than retaining a cleanup reboot policy without ownership. Verification
  closure: `scripts/verify.sh` asserts the
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
- **R-S11d-33 — Windows MSI deferred install-root provenance — INTERMEDIATE DESIGN CLOSED 2026-07-11;
  SUPERSEDED AND EXCISED BY R-S11e-90 ON 2026-07-23.** Platform: the former Windows MSI deferred
  no-impersonation runtime-generated broker cleanup. Boundary: MSI execution-script
  `CustomActionData` and directory resolution ↔ LocalSystem file authority. The original closure stopped relying on
  only the package-private `App.InstallFolder` proof: the now-deleted `CustomActions.cpp` normalized deferred install
  folders, rejected empty/relative/root/path-too-long values, required an immediate child of
  `FOLDERID_ProgramFiles` or `FOLDERID_ProgramFilesX86`, rejected reparse-backed Program Files/install directories,
  and supplied only that normalized root to exact broker cleanup. That was privileged-state correctness hardening,
  not proof of a low-privilege LPE; the package already kept `App.InstallFolder` private under
  `ProgramFiles6432Folder` with no browse surface. R-S11e-89 separately removed Amyuni device cleanup because the
  package owns no exact device instance. The original gate covered the native validator and normalized cleanup root.
  R-S11bx/R-S11e-90 removes the deferred action,
  its `CustomActionData`, and this validator entirely; the fixed broker filename is now declarative component state.
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
  socket-bound polkit authorization, stable-root durable storage, a raw `_service_credential` PRS snapshot, and
  direct-parent/current-generation service-replica proof. The child is a nondumpable runtime-only replica. macOS adds a dedicated
  nonshared timeout-zero Authorization Services capability, root helper/installed-app audit-token proof, and exact
  LaunchAgent runtime-snapshot proof. Windows terminates mutation in the stable LocalSystem SCM authority and gives
  the retained child only a generation-bound read-only replica. The final clean committed cold release build is
  still required.
- **R-S11e — Linux polkit policy/package assurance — CLOSED 2026-07-10.**
  Platform: Linux `.deb` installed-service mode. Endpoint/action: the single local admin-authorized
  service-owned unattended-password change. Boundary: user-session process and distro-local polkit policy
  state ↔ root service credential commit. Attack surface closed: no new credential mutation path is added;
  raw `_service_password` remains the only Linux service-owned password ingress, using
  the SO_PEERCRED-derived peer process subject, `/usr/bin/pkcheck --action-id ... --process ... --allow-user-interaction`,
  and a root-service durable commit followed by raw `_password` PRS convergence into the proved runtime-only
  service-owned replica. This slice closes the residual assurance
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
  Endpoint/action: fixed helper launches such as the then-present `w` display fallback, `xrandr`/
  `xdg-screensaver`/`systemctl` app-side helpers, and shared `loginctl`/notification helpers. Boundary: privileged
  RustDesk process execution authority ↔ local filesystem helper resolution. Attack surface closed: fixed helper
  resolution no longer verifies metadata through one path and executes the original candidate string. Resolvers reject
  relative and parent-traversal candidates, require the candidate parent directory to be root-owned and not
  group/world-writable, canonicalize the helper, require the canonical path and canonical parent to remain clean
  absolute trusted state, require the canonical executable to be a root-owned regular executable with no group/world
  write bits, and return the canonical `PathBuf` that is passed to `Command::new`. This closes the symlink-chain
  target-swap class for privileged helper launches without changing helper command semantics. Verification closure:
  `scripts/verify.sh` runs app-side and shared helper resolver tests and requires canonicalization, candidate/canonical
  parent trust, executable-bit checks, canonical return wiring, and requirements/ledger disposition. R-S11e-42 later
  deletes the `w` display fallback entirely; this entry continues to describe the remaining helper resolver contract.
- **R-S11e-4 — macOS service proof ownership — SOURCE IMPLEMENTED.** Generic `_service` and password
  `_service_password` have independent proof capacities. The accepted socket's uid, effective-pid metadata, and
  `LOCAL_PEERTOKEN` are captured immediately. Security.framework proof executes on a dedicated exactly owned OS
  thread and is synchronously joined; timeout, cancellation, panic, lost result, or lost join ownership aborts the
  process. No generic frame or raw password header/body is read before endpoint proof succeeds.
- **R-S11e-5 — Linux service-owned replica receiver proof — SOURCE IMPLEMENTED.** Before listener admission, the
  child requests raw `_service_credential`; the root service proves the exact child from `SO_PEERCRED`, current
  executable, exact `--server --service-owned-server` argv, direct parent, launch-parent environment, and current
  service generation before returning a canonical PRS-or-empty snapshot. The child independently authenticates
  its direct root `--service` parent. After polkit-authorized mutation, root persists first and converges that exact
  child through raw `_password` with the same UUID and canonical PRS, never plaintext; the child applies only a
  nonpersistent runtime override. No password-equivalent value is sent through ordinary main IPC; that channel can
  only recover nonsecret status after admission.
- **R-S11e-6 — Linux `_service_password` client-side server authentication — SOURCE IMPLEMENTED; proof wording
  corrected by R-S11e-94.** The caller connects to raw `_service_password` through the protected root-owned service
  IPC path and requires a positive uid-0 peer PID from `SO_PEERCRED` before sending the canonical header/body. It does
  not depend on an unprivileged process reading protected root `/proc` executable or argv metadata. A non-root path
  squatter receives no password bytes; a process already running as root remains inside the trusted service boundary.
  Generic `_service` carries no password request.
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
- **R-S11e-10 — macOS residual process launch provenance — CLOSED 2026-07-11; ROOT-TO-USER
  LAUNCH CLAIM SUPERSEDED BY R-S11e-38 ON 2026-07-19.**
  Platform: macOS desktop/server source. Endpoint/action: post-keying wake/user-activity notification and
  root-capable `launchctl asuser` helper launch for CM/whiteboard bootstrap. Boundary: authenticated Remote
  connection or service-owned server helper launch ↔ local process creation/provenance. Attack surface closed:
  the connected-session wake path no longer spawns `/usr/bin/caffeinate -u -t 5`; it calls the native
  `MacDeclareRemoteUserActivity` bridge, which invokes
  `IOPMAssertionDeclareUserActivity(..., kIOPMUserActiveRemote, ...)` through IOKit. The first closure also removed
  the `/usr/bin/env KEY=VALUE ...` argv bridge. Later platform-contract review established that the remaining
  `/bin/launchctl asuser <uid> <current_exe> ...` path was not a credential drop: Apple's `launchctl(1)` contract
  says `asuser` adopts bootstrap/audit context but does not modify UID/GID. Its environment-key allowlist therefore
  did not make the abstraction correct. R-S11x/R-S11e-38 deletes that generic launcher and makes unexpected root
  CM/whiteboard bootstrap fail before spawn; the installed service-owned server is already the per-user LaunchAgent.
  No ordinary-user-to-root path was proved in the old fixed call sites. Verification now gates the explicit IOKit
  link/native activity path, both subprocess deletions, the fail-closed service topology, and the superseding
  requirements/ledger disposition.
- **R-S11e-11 — Windows service-owned password receiver proof — SOURCE IMPLEMENTED; CURRENT NATIVE WINDOWS
  WORKTREE VALIDATED VIA R-S11b-2d; EXACT-COMMIT R-B2 EVIDENCE PENDING.** Mutation terminates directly in the
  stable LocalSystem SCM service on raw `_service_password`. The client authenticates the fixed service image, LocalSystem token, exact service role,
  and process generation before sending. The process-lifetime first-instance listener preauthorizes the exact
  active-principal RustDesk role before header wait, proves the header message by impersonation before body read,
  and revalidates the body message plus fresh process/token/session identity immediately before nonblocking
  admission. The retained child is never a durable commit receiver; `_service_credential` supplies only its
  generation-bound read-only replica. This row is the receiver-proof slice of the same current-worktree native
  Windows evidence recorded in R-S11b-2d/R-S11c-1e above: retry 15 of staged tree
  `ad2dd37c3698945d1071e091c68d26d64bc32b54` passed the native service/credential/SAS/password-finality/input
  suites in two fresh networkless Windows guests. That remains current-worktree native evidence only; exact
  committed cold-release artifact evidence still belongs to R-B2.
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
  runtime-file cleanup, and runtime broker refresh. Boundary: caller-controlled application image
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
  directory, calls `MsiInstallProductW` directly with `REBOOT=ReallySuppress`, scopes the exact interactive/silent
  Installer UI level with restoration, and accepts only 0 or 3010. It creates no installer helper child and never
  loads or executes packaged application code. The Windows build compiles only the Flutter distribution, builds,
  canonicalizes, and validates the MSI first,
  creates a dedicated one-file setup payload from those final MSI bytes, hash-checks it, packs it offline/locked,
  removes staging in `finally`, and emits only exact output paths.
  The MSI alone creates and ACLs `ProgramData\<Product>\config`; runtime code has no authority to create or
  repair that machine credential root. WiX `ServiceInstall` with the documented null-StartName LocalSystem default, `ServiceControl`, nested
  `ServiceConfigFailureActions` preserving 5/10/30-second restart backoff, and a file-bound inbound TCP/21118
  `fire:FirewallException` transactionally own service and firewall state. The basename process killer and custom
  service/firewall source, exports, and schedules are deleted. The package creates no certificate-store state, and
  R-S11e-88 deletes its inherited LocalSystem cross-user certificate scanner instead of retaining an unowned legacy
  cleanup heuristic. The package also creates and owns no exact Amyuni device instance; R-S11e-89 deletes the
  inherited hardware-ID-wide device-removal action and both dead runtime removal functions rather than treating
  separately owned display-device state as uninstall residue. R-S11e-90 replaces exact runtime-generated broker
  cleanup with a non-wildcard `RemoveFile On="uninstall"` row owned by the application component and deletes the
  RustDesk-authored custom-action DLL/build surface completely. Runtime broker refresh now requires
  the fixed service image, a non-reparse System32 source, the fixed Program Files destination, and byte equality;
  replacement is atomic when a prior broker exists, and the launch path propagates verification failure. It uses no
  shell, UAC, or basename kill. Verification closure:
  portable pure tests cover exact setup-name and 0/3010 status policy; the R-S11e-87 slice recorded an exact Rust 1.75
  Windows-MSVC cross-target type check for the current typed Installer API; `scripts/verify.sh` gates the sole-authority topology, deleted
  paths, declarative MSI resources, exact one-file build payload, broker provenance, R-S11f, this ledger entry,
  Appendix C #125, and the later #213–#217 closures. Current Windows artifact evidence is authoritative only through
  the exact-commit R-B2 manifest.
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
- **R-S11e-23 — Windows current-package registry authority — SOURCE IMPLEMENTED; NATIVE/ARTIFACT EVIDENCE IS
  OWNED BY THE EXACT-COMMIT R-B2 TRANSACTION.** Platform: Windows installed service and desktop package-state
  queries. Endpoint/action: current-install classification, installed build-date read, and the LocalSystem-owned
  `share_rdp` policy read/write reached through the typed elevated `_service` operation. Boundary: retired installer
  compatibility metadata ↔ current MSI package identity and service-owned machine policy. Attack surface closed:
  runtime no longer searches the retired Inno Setup `{54E86BC2-6C85-41F3-A9EB-1A94AC9B1F93}_is1` keys or a manually
  addressed `Wow6432Node` view before the current product key. A stale administrator-owned legacy `InstallLocation`
  therefore cannot make the current package appear absent, redirect build metadata, or split RDP session-sharing
  policy into a retired package namespace. This was not promoted to a promptless standard-user-to-SYSTEM finding:
  HKLM uninstall state is normally administrator-owned, and the policy mutation already requires receiver-side
  elevated-token proof. It was nevertheless the wrong authority abstraction after R-S11e-20 made MSI the sole
  machine-state owner, and the same stale installed-state class had previously contributed to the independently
  closed R-S11c-25 terminal principal defect.

  Closure: runtime derives exactly
  `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\<current constrained product name>`, matching the
  current MSI component, and opens only the explicit 64-bit view with `KEY_WOW64_64KEY`. The service policy write,
  fixed-name policy read, and fixed-name build-date read share that one package namespace; the generic registry-value
  facade is deleted. Installed-state classification additionally requires the current key's nonempty
  `InstallLocation` to equal the supported fixed Program Files service root and requires the exact product
  executable to pass opened-object regular-file/non-reparse proof. There is no default-path, legacy-key,
  alternate-view, or registry-selected executable fallback. Verification closure: the native Windows unit test pins
  the exact subkey; `scripts/verify.sh` binds the current MSI writer, explicit 64-bit read/write flags, fixed-root and
  executable-object proof, typed consumers, requirements/ledger disposition, and absence of every retired selector
  token. Appendix C #131 records the source-level finding; exact native/artifact proof remains with R-B2.
- **R-S11e-24 — Windows privacy-display registry recovery authority — SOURCE IMPLEMENTED; NATIVE/ARTIFACT
  EVIDENCE IS OWNED BY THE EXACT-COMMIT R-B2 TRANSACTION.** Platform: Windows virtual-display privacy mode.
  Endpoint/action: capture the GraphicsDrivers Connectivity `Recent` value around privacy-mode activation and restore
  it after the normal display-mode rollback. Boundary: ordinary/user-profile configuration and startup state ↔ an
  elevated HKLM registry writer. Attack surface closed: inherited `RegRecovery` was serde/JSON data in the generic
  `reg_recovery` option and carried an arbitrary HKLM path, value name, raw old/new bytes, and integer registry types.
  Startup `--server` deserialized and replayed that request; the stale-value comparison did not authenticate it because
  the serialized `new` value was also caller-provided. This was not promoted to a demonstrated promptless
  standard-user-to-SYSTEM exploit: the supported installed child reads the protected ProgramData config root created
  by MSI and has no durable config-write authority after R-S11e-22, while a user-profile server needs deliberate
  elevation before the HKLM sink succeeds. That same split proves the abstraction was wrong: it was non-durable where
  the supported service needed it and over-authoritative where an elevated user-profile process could consume it.

  Closure: `RegRecovery` is now a private process-local object that has no serde implementation and contains only one
  directly enumerated Connectivity child name plus the prior raw `Recent` value read by that process. A process-local
  collection retains every changed child instead of the inherited nondeterministic first `HashMap` match, and restore
  attempts every retained value before reporting aggregate failure. The restoring module derives the fixed
  `HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Connectivity` parent and fixed
  `Recent` value name, rejects empty, nested, control-bearing, or overlong child names, and exposes no registry root,
  path, value-name, or type selector. `PrivacyModeImpl` owns the snapshot collection and consumes it once after its
  normal display restore. The generic config key, JSON conversion, startup replay, exported startup helper, and arbitrary
  registry-type converter are deleted. This preserves the supported same-process normal turn-off behavior; it does not
  claim durable crash recovery. Per R-S11j, a future durable design must use documented Windows CCD topology APIs or a
  narrow service-owned transaction with receiver-side operation validation, never generic config replay. Verification
  closure: native Windows unit tests pin fixed target derivation, invalid-subkey rejection, and multi-display retention;
  `scripts/verify.sh` asserts process-local ownership, the fixed-target writer, the requirements/ledger/Appendix C #132
  disposition, and
  absence of serialized/config/startup recovery. Exact native/artifact proof remains with R-B2.
- **R-S11e-25 — Linux service-owned config-root authority — SOURCE IMPLEMENTED AND FOCUSED LINUX TESTED;
  FINAL EXACT-DEBIAN-ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: Linux service supervisor and its
  service-owned server child. Endpoint/action: choose the home and project directory from which the service reads
  unattended credentials, salts, identity compatibility data, and machine policy. Boundary: inherited launcher
  environment ↔ root/service-owned configuration authority. Attack surface closed: the ordinary
  `directories-next` path uses `XDG_CONFIG_HOME` or `HOME/.config`, `Config::get_home` accepted ambient `HOME`, and
  the root/headless child explicitly copied the supervisor's `HOME` after `env_clear`. That made service policy depend
  on systemd/OpenRC/runit/sudo/manual-launch environment behavior instead of one application-owned rule. This is not
  promoted to a demonstrated promptless standard-user-to-root primitive: the practical impact also depends on which
  environment a privileged launcher preserves and who owns the selected filesystem target. It is nevertheless the
  wrong authority model for the process that enforces unattended access.

  Closure: only exact Linux `--service` and service-owned child roles initialize an immutable process-local root. The
  initialization occurs after signed `custom.txt` may set the constrained application name and before the first
  `Config` access; it resolves the current effective uid through `getpwuid`, validates an absolute clean passwd home
  and one constrained project component, and binds both `Config::get_home` and `Config::path` to
  `<passwd home>/.config/<directories-next project name>`. Missing account data and inconsistent reinitialization fail
  closed. The root/headless child derives `HOME` independently from the same password database and never copies
  supervisor `HOME`; its cleared environment does not carry `XDG_CONFIG_HOME`. Ordinary user-owned `--server`,
  viewer, and UI roles retain intentional XDG redirection. Verification closure: three `hbb_common` Linux tests cover
  effective-uid lookup, exact derivation/rejection, and a subprocess with hostile ambient `HOME`/`XDG_CONFIG_HOME`;
  `scripts/verify.sh` runs those tests and source-gates the process root, passwd lookup, role set, initialization
  ordering, fail-closed path,
  root-child environment, R-S11k, and Appendix C #133. The focused tests passed in a non-root, network-disabled Docker
  container. This source proof does not close the existing R-S11c-27 requirement for final execution of the exact cold
  Debian artifact, and it does not claim overall R-B2 completion.
- **R-S11e-26 — Linux service-child environment authority — SOURCE/RUNTIME IMPLEMENTED AND BEHAVIOR-TESTED
  2026-07-18; FINAL EXACT-DEBIAN-ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: Linux root service
  supervisor and both its root/login-screen and active-user server
  children. Endpoint/action: construct the environment passed across the exact service-owned child exec. Boundary:
  init/manual/sudo launcher environment and discovered desktop-session metadata ↔ root or privilege-dropped server
  process. Attack surface closed: the old root branch called `start_server(None, ...)`, overloading absence of a
  desktop to mean “retain root,” then copied ambient `DISPLAY`, `XAUTHORITY`, `WAYLAND_DISPLAY`,
  `DBUS_SESSION_BUS_ADDRESS`, `TERM`, `PULSE_LATENCY_MSEC`, and `PIPEWIRE_LATENCY` back into the child after
  `env_clear`. A privileged launcher that preserved caller-selected variables could therefore select local display,
  IPC, or audio endpoints consumed by the root child. The same ambient `TERM`/`TMUX`/`STY` state also influenced the
  supposedly bounded terminal fallback. This is a privileged-launch confused-deputy and parser/endpoint-exposure
  defect, not a demonstrated promptless standard-user-to-root primitive: practical exploitation also requires a
  privileged launcher that admits hostile environment input.

  Closure: `ServiceChildPrincipal::{RootService, ActiveDesktopUser}` now represents privilege selection independently
  of the mandatory selected `Desktop` argument. Both service-loop branches pass that snapshot. The launcher clears
  inheritance once, derives root `HOME` from the effective uid's passwd record, derives non-root identity/home/runtime
  variables from the validated credential drop, and copies only nonempty X11/Wayland/D-Bus selectors from the desktop
  snapshot. The ambient root-variable loop, Pulse/PipeWire forwarding, `set_x11_env` process-global handoff, and
  supervisor `TERM`/`TMUX`/`STY` reads are deleted. Terminal choice is a bounded desktop-uid observation or fixed
  terminal-capability fallback. The actual-binary, network-disabled manual lifecycle fixture launches the root service
  with hostile HOME/XDG, X11, Wayland, D-Bus, terminal, Pulse, and PipeWire values; it exact-checks the root allowlist,
  passwd home, and the fixture desktop's `DISPLAY=:0` plus passwd-home `.Xauthority`, rejects every hostile value, and
  retains the exact non-root environment/UID/GID/group/capability proof. The current binary passed that lifecycle in
  a disposable networkless container, including
  `SERVICE_LIFECYCLE_ROOT_ENVIRONMENT=pass authority=desktop-snapshot ambient=excluded`, active-user UID/GID and exact
  supplementary groups, zero live capability sets, graceful/forced/crash/pre-pidfd recovery (the latter later
  superseded by R-S11c-27u), and unrelated portable
  process noninterference. `scripts/verify.sh` binds the typed principal/desktop API, explicit selectors, absence of
  ambient reads and process-global mutation, hostile fixture, mandatory runtime result, R-S11l, and Appendix C #134.
  This source/runtime slice does not claim final execution of the exact cold Debian artifact or overall R-B2
  completion.
- **R-S11e-27 — Linux service-owned working-directory authority — SOURCE, FOCUSED, AND
  ACTUAL-DEBUG-BINARY RUNTIME VERIFIED 2026-07-18; FINAL EXACT-DEBIAN-ARTIFACT EXECUTION REMAINS WITH
  R-B2/R-S11c-27.** Platform: Linux root service supervisor and both root/login-screen and active-user
  service-owned server children; the custom-client loader correction is shared by every platform/build mode.
  Endpoint/action: process startup cwd and optional signed `custom.txt` source selection before app-name, config,
  and IPC namespace initialization. Boundary: init/manual/sudo launcher filesystem context ↔ service-owned runtime
  identity and every later relative-path consumer. Attack surface closed: Rust `Command` inherited the supervisor's
  cwd into both service children, while the supervisor itself retained whatever directory launched it. Debug builds
  additionally read `./custom.txt` first and returned after any readable cwd file, including an invalid payload that
  suppressed the executable-bound sidecar. A valid RustDesk-signed payload can change `APP_NAME` before the Linux
  service config root and IPC paths are selected, so publisher signature validity did not make ambient cwd a sound
  deployment selector. Release builds did not compile the cwd loader and an untrusted local user cannot forge the
  Ed25519 signature; this is classified as a debug/manual privileged-launch identity/namespace confused deputy and
  future-relative-path authority defect, not a demonstrated production-release exploit or promptless local
  privilege escalation.

  Closure: the debug cwd override is deleted rather than root-gated. `load_custom_client()` now derives the optional
  sidecar only from an absolute `current_exe()` path (retaining the existing macOS Resources mapping), while mobile
  embeddings keep the explicit in-memory signed payload API. Exact Linux `--service` and service-owned child roles
  set cwd to `/` before `global_init()` or custom loading and exit if that fails. `try_start_server_()` independently
  applies `Command::current_dir("/")` before spawn, so the local child-launch surface no longer encodes Rust's
  inherit-parent default. Ordinary user-owned viewer/server cwd behavior remains unchanged.

  Verification closure is bound at the same boundary: a focused unit regression pins absolute,
  executable-relative custom sidecar derivation; `scripts/verify.sh` rejects the deleted debug/`./custom.txt`
  loader, missing or late supervisor/child cwd binding, absent fail-closed behavior, and documentation drift. The
  networkless actual-debug-binary lifecycle fixture launches service paths from a UID-4000-owned mode-0700 directory
  containing malformed `custom.txt`, reads both exact live `/proc/<pid>/cwd` links, requires `/`, and fails if the
  ambient file reaches the signed-config parser. `scripts/smoke-server.sh` makes the exact
  `SERVICE_LIFECYCLE_WORKING_DIRECTORY` result mandatory. R-S11m and Appendix C #135 record the normative and defect
  dispositions. The focused Rust regression passed (1/1); the non-root, network-disabled, source-read-only verifier
  source pass succeeded and five isolated mutations were rejected for the intended cwd/sidecar/runtime-proof
  regressions. The canonical smoke harness built the current debug binary in Docker and the network-disabled service
  lifecycle stage emitted the mandatory
  `SERVICE_LIFECYCLE_WORKING_DIRECTORY=pass supervisor=/ child=/ ambient=excluded` result across normal, recovery,
  hostile-record, forced pre-pidfd, root, and active-user paths (the pre-pidfd case was later superseded by
  R-S11c-27u). Its host identity monitor and portable/sibling
  noninterference checks passed, as did the subsequent SysV, native OpenRC, native runit, loopback-listener, PAKE,
  session, tunnel, file-transfer, and wire-capture stages. The full verifier-workspace mutation self-test was also
  attempted twice in a constrained container but stopped at its pre-existing descriptor-owned scratch-replacement
  fixture (`scratch replacement fixture missed the descriptor-owned directory`); that unrelated assertion was not
  bypassed or weakened, so this entry claims the focused source/mutation/runtime evidence, not that self-test. This
  slice does not claim final execution of a cold release `.deb` or overall R-B2 completion.
- **R-S11e-28 — Linux service-owned inherited descriptor authority — SOURCE, FOCUSED, AND
  ACTUAL-DEBUG-BINARY RUNTIME VERIFIED 2026-07-18; FINAL EXACT-DEBIAN-ARTIFACT EXECUTION REMAINS WITH
  R-B2/R-S11c-27.** Platform: Linux root service supervisor and
  root/login-screen, active-user, and direct pre-pidfd service-owned server children (the pre-pidfd case was later
  superseded by R-S11c-27u). Endpoint/action: inherited
  file-descriptor table at exact service-role bootstrap and supervisor-to-child `fork`/`exec`. Boundary:
  init/manual/sudo launcher and privileged supervisor kernel-object capabilities ↔ service-owned runtime and
  privilege-dropped child. Attack surface closed: Linux preserves an open descriptor across `execve` unless
  `FD_CLOEXEC` is set. The service bootstrap did not close launcher descriptors, and the child pre-exec hook
  cleared close-on-exec only for its exact executable without first constraining every other inherited descriptor.
  A root-open file, directory, device, socket, or namespace handle can therefore remain usable after uid drop even
  where pathname permission prevents reopening it. A pre-fix current debug binary launched directly as the exact
  service-owned child retained fd 198 to a root-owned mode-0600 file in the live process. That proves the capability
  leak at the supported manual/supervisor boundary; it does not prove that an ordinary user can cause a correctly
  configured privileged launcher to admit an arbitrary descriptor. Standard managers and sudo commonly mitigate
  this class, so it is classified as a privileged-launch confused deputy and root-to-child capability leak, not a
  demonstrated promptless standard-user-to-root escalation.

  Closure: exact Linux service roles now preserve only descriptors 0–2 as deliberate launcher process I/O. Before
  cwd, global, custom-client, config, IPC, or network initialization, the supervisor and final child call
  `close_range(3, UINT_MAX, 0)` and fail closed; if that syscall is unavailable or rejected, raw `close` plus
  `fcntl(F_GETFD)` verification walks the canonical `/proc/sys/fs/nr_open` bound and treats only `EBADF` as already
  closed. Before every child credential change, the allocation-free `pre_exec` hook applies
  `close_range(..., CLOSE_RANGE_CLOEXEC)` with a raw `fcntl(F_GETFD/F_SETFD)` fallback over the parent-resolved
  bound. Only the forked active-user child then clears `FD_CLOEXEC` on the already-opened, identity-checked exact
  executable object; the final RustDesk image closes that descriptor during owning-supervisor liveness proof and
  then closes every remaining non-stdio descriptor. The parent keeps its own descriptor table unchanged.

  The full Linux library compiles under pinned Rust 1.75 in a non-root, network-disabled, capability-free,
  no-new-privileges container with source and Cargo caches read-only. Shell/Python syntax checks and the dependency
  inventory self-test pass. `scripts/verify.sh` and the verifier-workspace validator bind the `close_range` fast
  paths, bounded raw-syscall fallbacks, canonical kernel bound, pre-exec-before-credentials ordering, final-image
  close-before-initialization ordering, exact-executable exception and close, R-S11n, Appendix C #136, and the
  mandatory hostile lifecycle result. Mutation cases replace `CLOSE_RANGE_CLOEXEC`, weaken the pre-exec policy,
  delete final-image cleanup, delete live supervisor descriptor inspection, and downgrade the top-level result.
  The lifecycle fixture opens fd 198 without close-on-exec to a root-only file in every manual launch path and
  compares that object's device/inode against every live supervisor and child descriptor. The rebuilt current
  debug binary and smoke readiness example passed that networkless Docker lifecycle fixture: graceful, forced,
  crash/restart, pre-pidfd recovery (later superseded by R-S11c-27u), active-user credential drop, cwd,
  portable-sibling, and cross-container
  identity checks passed, and the fixture emitted
  `SERVICE_LIFECYCLE_FILE_DESCRIPTOR_AUTHORITY=pass supervisor=excluded child=excluded ambient=excluded` with
  staged binary SHA-256 `6009233598bc73c1f75f77c5676a1a116326f99e663efcdc30aa78cbac68308b`. This is current
  debug-binary runtime evidence only; final exact release `.deb` execution remains open under R-B2/R-S11c-27.
  The helper adds one reviewed lexical
  `unsafe {` block; after R-S11e-36 the current inventory is 851 blocks across 251 tracked Rust files/73 nonzero
  files with digest `9fca7dae635a8c456a8da3ccfd0d8b150936f2ef1c3d80ce687eb84f5ae450bc`.
- **R-S11e-29 — Linux service-originated helper inherited descriptor authority — SOURCE AND
  MUTATION VERIFIED 2026-07-18; FINAL EXACT-DEBIAN-ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.**
  Platform: Linux root/service-originated helper launches. Endpoint/action: the `sudo -E env` probe,
  `run_as_user` sudo/env launches used for tray/CM/whiteboard-style user-session helpers, and argv-only delayed
  reopen helpers. Boundary: root/service-owned runtime descriptors ↔ helper images that should receive only argv,
  environment, and stdio. Attack surface closed: Linux preserves descriptors across `execve` unless `FD_CLOEXEC` is
  set. The exact service-owned child path was closed by R-S11e-28, but the adjacent generic helper-launch abstraction
  still built `Command` objects without RustDesk-owned descriptor policy. Sudo commonly closes non-stdio fds by
  default through sudoers `closefrom` policy, but that is configurable host policy and cannot be the product's
  authority boundary. A root-open config, IPC/listener, service-runtime, directory, socket, or other kernel object
  could therefore be inherited by a helper image if it was open and not close-on-exec at that launch point. This is a
  privileged-launch/root-to-helper capability leak and source-authority defect, not a demonstrated promptless
  ordinary-user-to-root escalation.

  Closure, consolidated into the shared layer by R-S11e-32:
  `libs/hbb_common/src/platform/linux.rs::configure_command_close_nonstdio_on_exec` resolves the canonical
  `/proc/sys/fs/nr_open` descriptor bound in the parent, then registers a Linux `pre_exec` hook that preserves
  descriptors 0–2 and marks every descriptor above stderr close-on-exec before the helper image runs. It uses the
  same `close_range(..., CLOSE_RANGE_CLOEXEC)` fast path and raw `fcntl(F_GETFD/F_SETFD)` fallback as R-S11e-28.
  The sudo environment-preservation probe now creates a mutable command, configures the descriptor hook before
  `output()`, logs and skips the probe if the hook cannot be configured, and no longer silently collapses probe
  execution errors. Both `run_as_user` sudo branches call the hook before `sudo.spawn()?`. The delayed reopen
  scheduler and reopened child likewise configure the hook before spawning. The direct service-child executable-fd
  exception is not shared with these helpers.

  `scripts/verify.sh` and `scripts/verify-verifier-workspace.py` bind the helper implementation, parent-resolved
  descriptor bound, pre-exec close-on-exec policy, sudo probe ordering, both `run_as_user` branches, delayed reopen
  helper launches, R-S11o, Appendix C #137, and this ledger entry. The verifier mutation suite renames the helper,
  deletes/renames probe and reopen helper calls, and removes `run_as_user` branch calls; each mutation must be
  rejected. This slice adds one reviewed lexical `unsafe {` block for the new helper-launch `pre_exec` registration;
  after R-S11e-36 the current inventory is 851 blocks across 251 tracked Rust files/73 nonzero
  files with digest `9fca7dae635a8c456a8da3ccfd0d8b150936f2ef1c3d80ce687eb84f5ae450bc`.
- **R-S11e-30 — Linux service-owned pkcheck inherited descriptor authority — SOURCE AND
  MUTATION VERIFIED 2026-07-18; FINAL EXACT-DEBIAN-ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.**
  Platform: Linux service-owned unattended-password authorization. Endpoint/action: root service invocation of
  the fixed trusted `/usr/bin/pkcheck` helper for `com.carriez.RustDesk.set-unattended-password`.
  Boundary: root/service-owned runtime descriptors ↔ the external polkit authorization checker, which should
  receive only the deliberate action/process/interaction argv and null stdio. Attack surface closed: after
  R-S11e/R-S11e-1/R-S11e-15 the service already resolved and authenticated the trusted pkcheck executable and
  bound the polkit subject to the socket-derived caller identity, but `src/ipc.rs` still built a direct
  `std::process::Command::new(pkcheck).spawn()` shape. Linux would preserve any root-service descriptor that lacked
  `FD_CLOEXEC` into that helper image. This is a root-service-to-helper descriptor-capability leak and
  source-authority defect, not a demonstrated promptless ordinary-user-to-root escalation.

  Closure: the shared `hbb_common::platform::linux::configure_command_close_nonstdio_on_exec` policy is public to
  workspace crates and the
  pkcheck authorization path uses it before `command.spawn()`. `src/ipc.rs` now builds a mutable command, supplies
  only the fixed pkcheck argv, null-routes stdio, registers the parent-bound close-on-exec pre-exec hook, rejects
  the service-owned password operation if the hook cannot be configured, and only then executes the helper. The
  direct service-child executable-fd exception remains unavailable here.

  `scripts/verify.sh` and `scripts/verify-verifier-workspace.py` bind the pkcheck command shape, descriptor-policy
  call, fail-closed diagnostic, ordering before spawn, direct-spawn absence, R-S11p, Appendix C #138, and this
  ledger entry. Focused Docker verification passed for the extracted source gate, verifier workspace validation,
  targeted pkcheck source mutations, dependency inventory, native-codec requirements hash, Linux `cargo check`, and
  the targeted Linux password-authorization source-contract unit test. This slice adds no new production
  `unsafe {` block; the existing helper pre-exec registration from R-S11e-29 is reused.
- **R-S11e-31 — Linux same-executable child inherited descriptor authority — SOURCE, ACTUAL-CHILD, AND MUTATION
  VERIFIED 2026-07-18; FINAL EXACT-DEBIAN-ARTIFACT EXECUTION REMAINS
  WITH R-B2/R-S11c-27.** Platform: Linux same-executable desktop helper launches. Endpoint/action:
  `src/common.rs::run_me`/`run_me_with_env`, including the root service-owned server's same-user headless
  connection-manager route as well as user-owned URL, tray, and whiteboard consumers. Boundary: descriptors held
  by the current RustDesk image ↔ a fresh RustDesk child whose deliberate contract is only argv, explicit
  environment additions, and stdio. Attack surface closed: the exact service image, sudo/reopen helpers, and
  pkcheck were constrained by R-S11e-28 through R-S11e-30, but the generic current-executable launcher still used
  a direct `Command::spawn` with no descriptor policy. On a headless installed-service server this is not merely a
  user convenience: `src/server/connection.rs` deliberately takes the same-user branch and starts CM through
  `run_me_with_env`. A sensitive non-stdio descriptor without `FD_CLOEXEC` could therefore cross into the root CM
  image. The same unsound ambient inheritance applied to ordinary user-owned consumers. This is a
  root-service-to-child capability leak on that CM route and descriptor-authority hygiene defect elsewhere, not a
  demonstrated promptless ordinary-user-to-root escalation; it depends on a sensitive live descriptor lacking
  close-on-exec at the launch point.

  Closure: on Linux, `run_me_with_env` now applies
  `configure_command_close_nonstdio_on_exec` before its only spawn. That reuses the parent-resolved
  `/proc/sys/fs/nr_open` bound, raw `close_range(CLOSE_RANGE_CLOEXEC)` fast path, and raw
  `fcntl(F_GETFD/F_SETFD)` fallback from R-S11n/R-S11o. A configuration error becomes an `io::Error` and no child
  is started. No executable-fd exception exists at this API. Non-Linux launch behavior and the child argv,
  environment, and stdio contract are unchanged.

  The Linux unit regression is an actual three-image descriptor proof without root or test-only `unsafe`: a
  `/bin/sh` launcher opens descriptor 9 across `exec`; the intermediate exact RustDesk test image compares the
  live `/proc/self/fd` target's device/inode and refuses to proceed unless descriptor 9 is present; it then calls
  `run_me_with_env`; and the final exact test image proves no live descriptor matches that same object.
  `scripts/verify.sh` and `scripts/verify-verifier-workspace.py` bind the descriptor-policy-before-spawn ordering,
  fail-closed error conversion, single spawn shape, actual-child proof, service-owned CM consumer, R-S11q,
  Appendix C #139, and this entry. The focused Rust 1.75 test passed in a non-root, networkless, capability-free,
  source-read-only Docker run (all three outer/launcher/final test images passed), and the full library test target
  compiled. The extracted source gate, semantic source validator, full in-memory source-mutation suite, Rust 1.75
  formatting check, dependency inventory and its self-test, native-codec watch, requirements-hash equality, shell
  syntax, and diff hygiene passed. The mutation review also narrowed the adjacent pkcheck spawn mutation to its
  unique production context after the old fragment was found in both production and a Rust source-contract test;
  all runtime mutation targets are now effective. This slice adds no dependency and no lexical `unsafe {` block;
  it reuses the production hook added by R-S11e-29.
- **R-S11e-32 — Linux external-helper descriptor allowlist authority — SOURCE, ACTUAL-CHILD, AND MUTATION
  VERIFIED 2026-07-18; FINAL EXACT-DEBIAN-ARTIFACT EXECUTION REMAINS WITH
  R-B2/R-S11c-27.** Platform: Linux ordinary external and same-executable child launches outside the specialized
  exact service-child bootstrap. Endpoint/action: shared `loginctl` and desktop-notification helpers; root-crate
  sudo/env, pkcheck, xdg-screensaver, xrandr, `w`, delayed reopen, and systemctl helpers; clipboard fusermount
  mount/unmount; same-executable `run_me_with_env`; and the feature-inert hardware-codec check launcher. Boundary:
  descriptors held by a possibly root/service-owned RustDesk image ↔ child images whose authority is normally
  argv, explicit environment, and stdio. The clipboard mount protocol deliberately adds exactly one non-stdio
  Unix socket. Attack surface closed: R-S11e-29 through R-S11e-31 placed the ordinary pre-exec hook in the root
  crate and covered the privileged helpers found in those slices, but shared `hbb_common` and dependent crates
  could not call that API. The remaining command enumeration found direct launches without a RustDesk-owned
  descriptor contract. The root service repeatedly reaches `loginctl` through desktop refresh and can reach
  display/service helpers. A sensitive ambient descriptor lacking `FD_CLOEXEC` could therefore enter an external
  image. Clipboard FUSE additionally cleared `FD_CLOEXEC` on `_FUSE_COMMFD` in the multithreaded parent before
  spawning, creating a process-wide inheritance race. This is a root/service-to-helper capability leak on
  service-reachable paths and descriptor-authority hygiene defect elsewhere, not a demonstrated promptless
  ordinary-user-to-root primitive; it depends on a sensitive live inheritable descriptor.

  Closure: `libs/hbb_common/src/platform/linux.rs` now owns the ordinary Linux helper policy. The parent reads and
  canonically validates `/proc/sys/fs/nr_open`, validates an explicit duplicate-free allowlist containing only
  non-stdio descriptors within that bound, and captures both as pre-exec data. The forked child uses raw
  `close_range(CLOSE_RANGE_CLOEXEC)` with a raw `fcntl(F_GETFD/F_SETFD)` fallback to mark every descriptor above
  stderr close-on-exec, then clears `FD_CLOEXEC` only for each explicit exception. The convenience API supplies an
  empty allowlist. All enumerated production launches use that shared policy. Clipboard mount allowlists only its
  exact `_FUSE_COMMFD` socket; that socket remains close-on-exec in the parent and becomes inheritable only in the
  forked child immediately before exec. Clipboard unmount and every other ordinary helper remain stdio-only. The
  specialized R-S11n exact service-child executable-fd handoff remains local and unchanged.

  The Rust 1.75 actual-child regression is a real three-image proof: a shell exec injects descriptor 9; the
  intermediate hbb_common test image proves the live descriptor's device/inode; one child launched through the
  explicit API proves that exact object remains descriptor 9; and a second child launched through the default API
  proves no live descriptor matches it. A companion regression rejects stderr, duplicate, and out-of-range
  allowlist entries. The exact regression passed in a non-root, networkless, capability-free, no-new-privileges
  Docker run with the source mounted read-only. Focused clipboard/FUSE compilation and the full RustDesk Linux
  library check with `unix-file-copy-paste` passed under the same constraints. `scripts/verify.sh` and
  `scripts/verify-verifier-workspace.py` bind the shared syscall/validation/ordering implementation, every
  enumerated helper family, the exact FUSE exception, absence of the parent-side inheritability window, both
  actual-child branches, invalid allowlists, R-S11r, Appendix C #140, and this entry. Final exact release `.deb`
  execution remains open under R-B2/R-S11c-27. The extracted R-S11e-29 through R-S11e-32 source gate, semantic
  source validator, and complete in-memory source-mutation matrix passed. The full behavioral verifier self-test
  was also attempted, but its pre-existing descriptor-owned scratch replacement fixture fails identically at the
  parent commit in this isolated Docker environment before mutation dispatch; the focused mutation dispatch was
  therefore run and passed separately. The shared low-level implementation has four reviewed lexical `unsafe {`
  blocks while the superseded root helper contributed one removed block: the net inventory change is three, for a
  then-current total of 801 blocks across 244 tracked Rust files/67 nonzero files. R-S11e-33 later removes two
  additional blocks from the still-tracked platform module and deletes one zero-unsafe example; after R-S11e-36
  the current inventory is 851 blocks across 251 tracked Rust files/73 nonzero files with digest
  `9fca7dae635a8c456a8da3ccfd0d8b150936f2ef1c3d80ce687eb84f5ae450bc`.
- **R-S11e-33 — desktop fatal-signal default disposition — SOURCE, COMPILE, TARGETED-TEST, AND MUTATION VERIFIED
  2026-07-18; FINAL EXACT RELEASE ARTIFACTS REMAIN WITH R-B2.** Platforms: Linux, macOS, and Windows non-mobile release desktop images, including
  viewer, server, and installed-service roles that share `core_main`. Endpoint/action: the process-wide
  `SIGSEGV` registration and callback. Boundary: a synchronous memory-integrity failure interrupting arbitrary
  process state ↔ Rust crash-reporting, configuration, input-cleanup, and child-process authority. Attack surface
  closed: every non-mobile release process installed `breakdown_signal_handler` with `libc::signal`. That handler
  allocated and symbolized a backtrace, formatted strings, read and wrote configuration, logged, launched a Linux
  desktop-notification helper, called a callback stored in mutable global state, entered native input-cleanup
  backends, and then reported success through `process::exit(0)`. A fault can interrupt any of those allocators,
  locks, loggers, configuration paths, or native backends while their state is inconsistent. Re-entering them from
  the signal handler is therefore undefined or deadlock-prone, while normal success exit suppresses truthful
  abnormal-signal status, supervisor `Restart=on-failure` recovery, and ordinary platform crash diagnostics. This
  is a crash-path privilege/availability amplifier and forensic-integrity defect, not a demonstrated standalone
  local privilege escalation: an attacker still needs a genuine fault or authority to signal the process, and the
  deleted Linux notification launcher used fixed executable paths and constant text.

  Closure: R-S11s leaves fatal memory-integrity signals at the operating system's default disposition. The
  registration call and API, handler, mutable-global callback, input-cleanup consumer, Linux crash-notification
  helper/example, and `hbb_common`'s direct `backtrace` dependency are deleted. No Rust allocator, lock, logger,
  configuration writer, graphics/codec option mutator, native input backend, callback, subprocess launcher, or
  normal exit handler now runs in `SIGSEGV` context. Default abnormal termination preserves truthful process
  status, systemd `Restart=on-failure` behavior, and platform crash/core policy. This does not change the separately
  owned graceful `SIGTERM`/`SIGINT` service/direct-server shutdown paths. `scripts/verify.sh` and
  `scripts/verify-verifier-workspace.py` bind complete symbol/dependency/example absence, the Cargo.lock edge,
  R-S11s, Appendix C #141, and this ledger entry. The extracted source gate and normal semantic source validator
  passed; a focused fixture rejected all 11 independent callback/helper/dependency/example/gate/ledger mutations.
  Rust 1.75 passed `cargo check --locked -p hbb_common`, the full Linux library check with
  `linux-pkg-config,unix-file-copy-paste`, and all three affected `r_s11c10m_command` tests. Locked offline Cargo
  metadata, the dependency inventory and its behavioral self-test, Python/shell syntax, native-codec watch,
  requirements-hash equality, and diff hygiene passed. Rust source edits are deletion-only; the local development
  image does not contain the Rust 1.75 rustfmt component, so no formatter result is claimed. This slice removes two
  lexical `unsafe {` blocks from the still-tracked platform module and deletes one zero-unsafe example. R-S11e-34
  subsequently adds the reviewed macOS descriptor helper and brings the already-compiled portable PTY crate into
  tracked source authority; R-S11e-35 deletes one obsolete Windows launcher block and R-S11e-36 adds one reviewed
  Windows privacy-broker wrapper block, so the current inventory is 851 blocks across 251 tracked Rust files/73
  nonzero files with digest `9fca7dae635a8c456a8da3ccfd0d8b150936f2ef1c3d80ce687eb84f5ae450bc`. Exact Linux/macOS/Windows release-artifact
  compilation/execution remains part of the final R-B2 transaction and is not claimed here.
- **R-S11e-34 — macOS child inherited descriptor authority — SOURCE, RUST 1.75 HOST-ANALOGUE BEHAVIOR, AND
  MUTATION VERIFIED 2026-07-18; NATIVE APPLE EVIDENCE REMAINS WITH R-B2.** Platform: macOS production child launches in viewer, controlled-side,
  LaunchAgent, and root LaunchDaemon roles. Endpoint/action: service install/uninstall and LaunchAgent lifecycle
  helpers; the LaunchDaemon's `launchctl print` service-owned snapshot authorization query; `launchctl asuser`
  root-to-user helper transitions; same-executable CM/tray/whiteboard launches; the portable-PTY terminal shell;
  app reopen, lock-state, and lock-screen tools; and the feature-inert hardware-codec checker. Boundary:
  descriptors held by the current
  RustDesk process, including root/service-owned IPC, credential-operation, log, directory, and kernel-object
  capabilities ↔ a child image whose deliberate authority is only argv, explicitly selected environment, and
  stdio. Attack surface closed: Darwin preserves descriptors across `exec` unless `FD_CLOEXEC` is set. Pinned
  Rust 1.75's macOS `Command` path uses `posix_spawn` without Apple's close-by-default extension; the production
  ordinary `Command` launch inventory supplied no application-owned non-stdio policy. The terminal path used the
  pinned `portable-pty` fork instead; its post-fork `close_random_fds` allocated, walked `/dev/fd`, ignored
  enumeration and close failures, and directly closed every descriptor above stderr. Besides violating the
  post-fork async-signal-safe contract, that could close Rust's internal exec-error pipe before `exec` and make a
  failed terminal image appear spawned. A sensitive descriptor lacking close-on-exec
  could therefore enter `launchctl`, `osascript`, `open`, `ioreg`, `CGSession`, or a new RustDesk child. The
  LaunchDaemon authorization query and root/user transition make this a privileged-to-helper capability-boundary
  defect. It is not promoted to a demonstrated promptless ordinary-user-to-root primitive: exploitation still
  requires a live sensitive inheritable descriptor. Separately, an unused public `hbb_common` alert API retained
  `osascript` 0.3 solely to execute a PATH-selected dependency-owned helper beyond RustDesk's command policy.

  Closure: `libs/hbb_common/src/platform/macos.rs` now owns one stdio-only ordinary-command policy. Before registering the
  hook, the parent reads `RLIMIT_NOFILE`, rejects zero, infinity, or a value above the fork's bounded 1,048,576
  descriptor operating envelope, and enumerates `/dev/fd`. The latter preserves coverage for inherited live
  descriptors above a soft limit that a launcher lowered after opening them. The post-fork hook performs only raw
  async-signal-safe `fcntl(F_GETFD/F_SETFD)` operations, marks every live descriptor above stderr close-on-exec,
  treats only `EBADF` as absence, and returns every other failure to `Command` so the child launch fails closed.
  The parent descriptor table is unchanged. No macOS production child protocol requires a non-stdio exception, so
  this API has no allowlist surface. Every enumerated launch family applies the policy before `status`, `output`, or
  `spawn`; the service-owned snapshot query rejects before executing `launchctl` if setup fails. The unused alert
  API, `osascript` dependency, lockfile package, and hbb_common dependency edge are deleted rather than wrapped.
  The exact pinned `portable-pty` 0.8.1 source from RustDesk's WezTerm fork commit
  `80174f8009f41565f0fa8c66dab90d4f9211ae16` is now owned in `libs/portable_pty`, with its remaining source kept
  byte-for-byte and provenance recorded. Its Unix PTY spawn prepares the same finite bound and `/dev/fd` snapshot
  in the parent, then uses only raw `fcntl(F_GETFD/F_SETFD)` in the existing pre-exec closure. It marks rather than
  closes non-stdio descriptors, so Rust's exec-error pipe remains usable until successful `exec`; only `EBADF` is
  absence and every other error aborts spawn. The conservative policy applies to every Unix PTY child, avoiding a
  weaker Linux terminal path while closing the macOS production shell inventory. The direct root dependency and
  lock record now resolve that audited in-tree crate; its still-external `filedescriptor` edge remains exactly
  pinned to the same RustDesk WezTerm fork branch.
  One cfg-macOS unit regression pins finite/zero/infinite/over-bound descriptor-limit validation. A second uses
  `/bin/sh` only as a separate test launcher: it opens descriptor 9, execs an intermediate copy of the exact test
  image, proves the live descriptor's device/inode, and has that image launch a final copy through the production
  policy; the final image must not contain that exact object. The parent test process never clears its own
  close-on-exec flags, so the regression introduces no process-wide inheritability race. Three portable-PTY tests
  separately pin the bound, prove an invalid executable is reported as a spawn error, and inject descriptor 9
  through the actual PTY spawn path before proving the exact device/inode absent from the final image.

  Primary contracts used for the design are Apple's `getrlimit(2)` documentation, Rust 1.75's exact Unix
  `Command` implementation, Rust's `CommandExt::pre_exec` safety contract, and POSIX's async-signal-safe `fcntl`
  contract:
  https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getrlimit.2.html,
  https://github.com/rust-lang/rust/blob/1.75.0/library/std/src/sys/unix/process/process_unix.rs,
  https://doc.rust-lang.org/1.75.0/std/os/unix/process/trait.CommandExt.html#method.pre_exec, and
  https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html.

  `scripts/verify.sh`, `scripts/apple-conform-check.sh`, and the semantic workspace verifier bind the bounded
  parent preparation, raw close-on-exec primitive, high-descriptor coverage, fail-closed error semantics, exact
  production launch inventory including the terminal PTY, all five regressions, dependency deletion/in-tree
  ownership, R-S11t, Appendix C #142, and this entry. The
  normal semantic verifier and both extracted shell gates passed. The complete in-memory source-mutation stage
  passed after rejecting every primitive, launch-site, actual-child, dependency, gate, and documentation mutation;
  its older Linux codec check was made platform-specific after the new macOS sibling correctly exposed the prior
  ambiguous marker. Rust 1.75 accepted locked offline Cargo metadata and `rustfmt --check` for every touched Rust
  file. A direct Rust 1.75 build of the shared module against locked `libc` 0.2.171 passed both tests on the Linux
  host analogue, including the three-image injected-descriptor flow. That host analogue proves the source test and
  generic Unix fork/exec behavior, not Darwin; native macOS compilation and execution of both tests, plus signed
  Apple artifact inspection, remain explicitly pending under the exact-commit R-B2 transaction. Two broader
  `hbb_common` check attempts stopped before compilation because offline Cargo would not accept the read-only
  cached Git checkout; neither is counted as compile evidence and no cache ownership or permissions were changed.
  With correctly user-owned disposable Cargo tmpfs and read-only cached leaves, the later locked offline
  `portable-pty` test target compiled under Rust 1.75 and all three Unix tests passed, including the nested final
  worker and preserved exec-error reporting. Native Darwin execution remains pending.

  The dependency inventory and its behavioral self-test pass. Removing `osascript` and resolving `portable-pty`
  in-tree leaves 909 Cargo package records with package digest
  `a7906255d35ff864234e67599d47986faf3f6eb0e6121638e0d6ba5dc7d82e73` and 37 git-sourced records. This slice
  adds three reviewed lexical `unsafe {` blocks in the previously zero-unsafe macOS shared module. Vendoring makes
  48 already-compiled upstream unsafe blocks visible to tracked-source inventory and the replacement PTY policy
  adds one net block relative to that upstream source; those 48 are newly auditable, not newly executable behavior.
  R-S11e-35 subsequently deletes one obsolete Windows launcher block and R-S11e-36 adds one reviewed Windows
  privacy-broker wrapper block, so the current inventory is 851 blocks across 251 tracked Rust files/73 nonzero
  files with digest `9fca7dae635a8c456a8da3ccfd0d8b150936f2ef1c3d80ce687eb84f5ae450bc`. The native-codec watch and synchronized
  requirements SHA-256 `f8fc0ac0fec37684d260ae4b5b02f97dfcedde0f0ac77e945854849add9d4341` pass. Exact
  Linux/macOS/Windows release-artifact compilation/execution remains part of final R-B2 and is not claimed here.
- **R-S11e-35 — Windows dormant generic process-launch authority — SOURCE, EXACT-SOURCE RUST 1.75
  TARGET-COMPILE/HOST-BEHAVIOR, AND SOURCE-MUTATION VERIFIED 2026-07-19; NATIVE WINDOWS EVIDENCE REMAINS WITH
  R-B2.** Platform: Windows controlled-side, viewer, and installed
  service images. Endpoint/action: the inherited public `run_exe_direct*`, `run_exe_in_cur_session*`,
  `run_exe_in_session*`, and `run_background` helpers in `src/platform/windows.rs`. Boundary: a future local
  caller's executable/session/argv/environment selection ↔ the current process token, including LocalSystem or an
  elevated token. Attack surface closed: repository-wide call and history inspection proved these generic APIs had
  no remaining caller after the updater, portable SYSTEM helper, caller-selected session IPC, and old whiteboard
  launch paths were deleted or replaced. They therefore did not establish a current ordinary-user-to-SYSTEM
  exploit. Retaining them was still the wrong authority abstraction: a future caller could choose an executable or
  session while the callee supplied privileged process authority, `ShellExecuteW` delegated application selection
  to shell semantics, and pinned Rust 1.75's Windows `Command` implementation calls `CreateProcessW` with
  `bInheritHandles=TRUE`, so a direct privileged use would also inherit every independently created inheritable
  handle.

  Closure: all four generic launcher families and the `ShellExecuteW` import/call are deleted. The remaining Windows
  user-helper API is a typed current-image request: `Tray` carries no value, while `ConnectionManager` and
  `Whiteboard` carry only a base64 token that must decode to exactly 32 bytes and whose decoded buffer is zeroed.
  The receiver derives the exact argv role, environment keys, parent PID, current executable, and current session;
  an extra role, environment key/value, parent, executable, or session is not representable. A LocalSystem caller
  then uses the existing explicit-application/current-directory
  `CreateProcessAsUserW` path whose native call has `bInheritHandles=FALSE`; a non-System caller can start only the
  same current image under its current principal. The independent SCM child path remains fixed to the proved Program
  Files service image, creation-time job-owned, and unaffected.

  Primary contracts used are Rust 1.75's exact Windows process implementation and Microsoft's `CreateProcessW` and
  process-inheritance documentation:
  https://github.com/rust-lang/rust/blob/1.75.0/library/std/src/sys/windows/process.rs,
  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw, and
  https://learn.microsoft.com/en-us/windows/win32/procthread/inheritance.
  A pure Windows unit regression pins all typed variants and rejects empty/wrong-length token state. `scripts/verify.sh` and the
  semantic workspace verifier bind
  the current-image/current-session call graph, receiver-side role/environment policy, native handle-inheritance
  denial, obsolete symbol absence, R-S11u, Appendix C #143, and this entry.

  Verification: Rust 1.75 `rustfmt --check`, Python bytecode compilation, `bash -n`, the semantic verifier's normal
  source audit, and its complete source-mutation set pass. The dependency inventory passes its 103-check behavioral
  self-test and live comparison; removing `run_background` removes one lexical `unsafe {` block, leaving 850 blocks
  across 251 tracked Rust files/73 nonzero files with digest
  `f0c6bc04d921ed43e90425cce27aaec28b5d43e0ae3b5aa2b9bae25400abb5b4`. The native-codec watch normal and mutation
  self-tests pass against requirements SHA-256
  `f8fc0ac0fec37684d260ae4b5b02f97dfcedde0f0ac77e945854849add9d4341`. Disposable exact-source harnesses compile
  and execute the policy under the host Rust 1.75 standard library and metadata-compile both the policy and the
  changed facade for `x86_64-pc-windows-msvc`. A full offline root-crate Windows check was attempted but stopped in
  unchanged native dependencies before the root crate: this Linux image has no MSVC `lib.exe`/cross C toolchain, so
  `libsodium-sys`, `ring`, `mozjpeg-sys`, and `zstd-sys` cannot build for the MSVC target. The verifier's broader
  executable self-test also retains its pre-existing scratch-replacement fixture failure; the source-mutation stage
  was therefore invoked independently through the verifier and passed. No native Windows execution or exact
  artifact evidence is claimed; those remain with the final R-B2 transaction.
- **R-S11e-36 — Windows privacy-broker process and window authority — SOURCE, RUST 1.75 PARSE + LINUX
  PORTABLE-CHECK, AND SOURCE-MUTATION VERIFIED 2026-07-19; NATIVE WINDOWS EVIDENCE REMAINS WITH R-B2.** Platform: Windows controlled-side
  installed-service privacy mode, plus the portable packer's extraction path. Endpoint/action: controlled
  `--server` startup, privacy-mode broker creation/injection/window selection, and portable setup. Boundary: the
  LocalSystem or user-owned RustDesk process's termination/window-control authority ↔ another session,
  installation, test, or portable instance selected only by global process basename or window title. Proven old
  path: every Windows controlled-server startup called `try_kill_broker`; that helper enumerated the machine for
  every `RuntimeBroker_rustdesk.exe` basename and used the current process token to terminate every accessible PID.
  Portable extraction independently ran trusted `taskkill.exe /F /IM RuntimeBroker_rustdesk.exe` before replacing
  its broker copy. Privacy-mode startup then accepted the first top-level `RustDeskPrivacyWindow` before creating
  or proving a broker it owned. The demonstrated impact is cross-instance/cross-session denial and confused-deputy
  window show/hide authority. This inspection did not establish a promptless ordinary-user-to-SYSTEM
  code-execution primitive.

  Closure: both basename cleanup paths and their machine-process termination helper are deleted; portable setup no
  longer copies or kills an installed-service privacy broker. One privacy-mode instance now creates a fresh unnamed,
  non-inherited job and configures `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. It initializes `STARTUPINFOW.cb`, creates
  the fixed installed broker suspended with `bInheritHandles=FALSE`, retains the exact process/thread handles and
  immutable PID, and assigns that process to the job before DLL injection or thread resume. These handles live in a
  pending RAII owner until injection succeeds, `ResumeThread` proves the expected single suspend count, the retained
  process handle remains live, and a window owned by that exact PID becomes ready; only then is ownership committed
  to the privacy-mode instance. Every earlier return drops pending ownership: closing the final configured job handle
  kills an assigned process tree, while a pre-assignment or failed-job-close path can terminate only its retained
  exact process handle. Normal stop and owner death use the same retained kill-on-close job rather than process-name
  discovery. Window title is now only a candidate filter: `FindWindowExA` enumerates matching top-level windows,
  `GetWindowThreadProcessId` must equal the retained immutable PID, and retained-handle liveness is checked before
  and after selection. A foreign same-title window and a pre-existing broker are never adopted.

  The design follows Microsoft's job-object, assignment, nested-job, and startup-structure contracts:
  https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects,
  https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject,
  https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs, and
  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow.
  `scripts/verify.sh` and the semantic workspace verifier bind the job configuration, valid suspended launch,
  handle/PID retention, assignment-before-injection/resume transaction, exact-PID window selection with liveness,
  obsolete global cleanup absence, R-S11v, Appendix C #144, and this entry. Their mutation fixtures cover each
  authority edge and documentation/gate anchor. In the existing non-root, network-disabled Rust 1.75 image, Python
  bytecode compilation and `bash -n` pass; the exact R-S11e-36 shell section passes; the semantic verifier's normal
  source audit and its complete in-memory source-mutation set pass; and all four changed Rust files pass Rust 1.75
  parse-only validation. The dependency inventory passes its behavioral self-test and live comparison. The native
  codec watch normal and mutation self-tests pass against synchronized requirements SHA-256
  `8441f7aa49ec9375e013776120b6cc452ffbf4882af160bd80f102634197f7e8`. An isolated disposable copy of the portable
  crate compiles on Linux under Rust 1.75 with the existing dependency cache mounted read-only; Cargo regenerated
  only that tmpfs copy's already-stale crate-local lock, because the repository normally resolves the crate through
  the root workspace lock. The initial root-workspace attempt stopped before compilation at an unrelated uncached
  `hwcodec` Git dependency, and the isolated `--locked` attempt stopped at that pre-existing private-lock drift;
  neither stopped attempt is counted as compile evidence.

  Vendored `winapi` 0.3.9 signatures were inspected directly for the job, wait, and information-class types; this
  caught and corrected an initially wrong module import that parse-only could not detect. None of the existing
  offline images contains a Windows Rust standard library, and `rustfmt` is likewise absent, so no Windows target
  type-check, formatting-tool claim, native execution, exact Windows artifact, or final R-B2 evidence is made. The
  broad executable verifier self-test still stops before its source-mutation stage at the scratch-replacement
  fixture (`descriptor-owned directory` missed, cleanup retained state); running the clean pre-slice `HEAD` in a
  separate tmpfs snapshot produces the identical failure, while invoking the source-mutation stage independently
  through the verifier passes. The top-level `verify.sh` was not run because it builds an image, creates Docker
  volumes, and deliberately executes root test containers; only its extracted read-only source gate was run here.
  This slice adds one reviewed lexical `unsafe {` block in the Windows-only PID/liveness wrappers, leaving 851
  blocks across 251 tracked Rust files/73 nonzero files with digest
  `9fca7dae635a8c456a8da3ccfd0d8b150936f2ef1c3d80ce687eb84f5ae450bc`.
- **R-S11e-37 — Windows residual process-state authority — SOURCE, RUST 1.75 PARSE + EXACT-SOURCE POLICY TEST,
  AND SOURCE-MUTATION VERIFIED 2026-07-19; NATIVE WINDOWS EVIDENCE REMAINS WITH R-B2.** Platform: non-installed Windows controlled
  side, plus one unused Windows platform probe. Endpoint/action: magnification-privacy capture switching while UAC
  is active, portable-client UAC status reporting, and the dormant LogonUI process query. Boundary: host-wide process
  enumeration text ↔ current RustDesk session capture state. Proven old path: `is_process_consent_running` returned
  true for any ToolHelp entry whose basename was `consent.exe`, without checking process session or full image path.
  A real consent process in another RDP session or a same-user executable renamed to that basename could therefore
  switch this process's capture behavior and reported UAC state. Separately, the module retained an unused generic
  `get_pids` helper that used substring matching for `LogonUI.exe`. These were cross-session/same-user state confusion
  and availability/privacy-correctness defects, not process-control authority or a demonstrated privilege escalation.

  Closure: the basename is now only a fixed, exact candidate filter. The receiver first derives its own process
  session and the no-reparse trusted `GetSystemDirectoryW` path for `consent.exe`. A same-session candidate is opened
  with `PROCESS_QUERY_LIMITED_INFORMATION`; the RAII process handle remains owned while
  `QueryFullProcessImageNameW` obtains the Win32 path and the candidate session is observed a second time, and the
  candidate is admitted only when normalized full path and pinned session both equal the receiver-derived
  expectations. Wrong-session candidates are ignored before open,
  wrong-image candidates are logged and ignored, and failure to open/authenticate a current-session candidate is an
  error so capture fails closed. The process query conveys no termination, token, window, or launch authority. The
  unused `get_pids`/`is_logon_ui` surface is deleted. `get_process_executable_path` now reuses the retained-handle
  primitive rather than opening and manually closing a second process handle shape.

  Microsoft's `ProcessIdToSessionId` and `QueryFullProcessImageNameW` contracts are the primary platform basis:
  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-processidtosessionid and
  https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew. The native
  Windows regression pins case-insensitive exact System32 image equality and rejects a same-basename user path and
  another session. `scripts/verify.sh` and the semantic workspace verifier bind fixed candidate selection,
  receiver-session derivation, System32/no-reparse target, retained-handle full-image query, exact policy, obsolete
  heuristic absence, R-S11w, Appendix C #145, and this ledger entry. Their mutation matrix independently removes or
  weakens every proof edge and documentation/gate anchor. This slice also reconciles stale R-S11d-3/R-S11d-10 and
  Appendix C #38/#45 text that still required the broker basename-kill implementation deleted by R-S11e-36.

  Verification: in the existing non-root `rd-devcheck` image with source read-only, network disabled, all
  capabilities dropped, no-new-privileges, and tmpfs-only outputs, the exact shell gate, Python parse, normal
  semantic workspace audit, complete independently invoked source-mutation matrix, dependency inventory and its
  103-check self-test, requirements-hash equality, diff hygiene, and native-codec normal/mutation checks pass.
  Rust 1.75 parses the complete Windows platform source as edition 2021. A generated harness compiles the exact two
  production policy functions extracted from the read-only source and passes the three exact path/session cases
  (1/1). Cached `windows` 0.61.1 source signatures were directly checked for ToolHelp result shapes,
  query-only `OpenProcess`, `QueryFullProcessImageNameW`, and typed `ERROR_NO_MORE_FILES`. The correctly invoked
  broad verifier self-test still stops at its pre-existing scratch-replacement fixture (`descriptor-owned directory`
  missed; retained scratch state) before source mutations; that failure was not weakened or counted, while the full
  source-mutation stage passes independently. The top-level verifier was not run because it builds a Docker image,
  creates volumes, and executes root test containers.

  Exact native Windows compilation/execution and final artifact evidence remain with R-B2; no such evidence is
  inferred from source conformance. The existing image has no Windows Rust standard library and no Rust 1.75
  rustfmt component, so no Windows type-check, native runtime, or formatter-tool result is claimed. Consolidating the
  process-image query behind one retained-handle primitive and
  deleting the unused LogonUI snapshot removes one lexical `unsafe {` block. The current inventory is 850 blocks
  across 251 tracked Rust files/73 nonzero files with per-file digest
  `3e6b6efdea22e9dc967553eb7999340a6335efcda2e48f7109ddd6592d1628eb`.
- **R-S11e-38 — cross-platform root-to-user helper launch authority — SOURCE IMPLEMENTED AND SOURCE-GATED
  2026-07-19; NATIVE WINDOWS/macOS EVIDENCE REMAINS WITH R-B2.** Platforms: Linux, macOS, and Windows desktop
  controlled-side helper launch. Endpoint/action: starting the connection manager, whiteboard, or tray from a
  server process. Boundary: a root/LocalSystem server's process/session authority ↔ a user-context helper selected
  through caller-supplied role, environment, and user identity. Proven old path: Linux exported `run_as_user` with
  arbitrary argv, arbitrary syntactically valid environment names/values, and an optional caller-provided
  UID/username tuple. It probed whether `sudo -E` preserved an injected sentinel and selected either that path or
  `sudo -u ... env`; the effective environment therefore depended partly on sudoers/PAM/site policy. macOS exported
  arbitrary argv and a four-key environment union through `launchctl asuser`. The allowlist prevented current
  callers from adding other environment names, but Apple documents that `asuser` changes bootstrap, exception-server,
  and audit-session context without modifying UID/GID, so it was not the credential transition the abstraction
  claimed. Repository callers supplied fixed CM/whiteboard shapes, and source/history inspection found no untrusted
  ordinary-user path selecting those raw parameters; this is conceptual/future privileged-launch authority, not a
  demonstrated promptless local privilege escalation.

  Closure: both Unix generic launchers are deleted. Linux also deletes its sudo/environment candidates, `sudo -E`
  probe, arbitrary environment filtering, and UID/username launch tuple. Its installed root supervisor already
  owns the exact credential transition by dropping the supervised service-server child before exec; its deliberate
  headless-root mode and ordinary user server continue same-principal `run_me_with_env` helper launches. The macOS
  service-owned server is already the per-user LaunchAgent, so an unexpected root Linux/macOS server now returns a
  clear error before starting CM or whiteboard instead of inventing another transition. Windows remains the only
  necessary cross-session exception: `WindowsUserHelperLaunch` has exactly `Tray`, `ConnectionManager`, and
  `Whiteboard` variants. CM/whiteboard callers can supply only a token that base64-decodes to exactly 32 bytes;
  the receiver zeroes the decoded validation buffer and derives role argv, environment keys, parent PID, current
  image, and current session before the existing `CreateProcessAsUserW(..., bInheritHandles=FALSE, ...)` path.
  Same-principal launches use the same typed API and current image. The R-S11u/R-S11e-35 ledger and Appendix C #93
  are corrected rather than left claiming that raw environment allowlists or `launchctl asuser` formed the right
  abstraction.

  Primary contracts: Apple's `launchctl(1)` manual at
  https://keith.github.io/xcode-man-pages/launchctl.1.html and the sudoers environment manual at
  https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf. `scripts/verify.sh`, `scripts/apple-conform-check.sh`, and the
  semantic workspace verifier bind the two Unix abstraction deletions, both fail-closed call sites, intended
  same-user paths, typed Windows roles/token validation/receiver-derived values, R-S11x, Appendix C #146, and this
  entry. Exact native Windows/macOS release behavior and artifacts remain owned by the final clean R-B2 transaction;
  source conformance does not substitute for them.

  Verification: the normal semantic workspace audit and its complete independently invocable in-memory source-
  mutation matrix pass; the latter includes the Unix abstraction reintroductions, both fail-closed call sites,
  typed Windows role/token/parent policy, both shell gates, R-S11x, Appendix C #146, and this entry. The verifier now
  exposes `--source-mutations-only` so this exact stage can run without pretending the unrelated pre-existing
  descriptor-owned scratch-replacement fixture passed. Extracted `verify.sh` R-S11e-35/R-S11e-38/R-S11e-29 gates
  and the Apple R-S11c-11/R-S11c-8/R-S11c-5/R-S11e-38/R-S11e-34 source slice pass. Rust 1.75 parses all five edited
  Rust files, and `cargo check --offline --locked --lib --features linux-pkg-config` completes under Linux using the
  host Cargo cache read-only and a container-tmpfs target. A harness compiled and executed the exact production
  Windows typed policy (all roles, exact receiver parent, short/malformed-token rejection), and the same policy
  metadata-compiles for `x86_64-pc-windows-msvc`. The three smaller edited Rust files are Rust 1.75 rustfmt-clean;
  edited hunks in the two large platform files match rustfmt, while unrelated pre-existing formatting differences
  remain untouched. Dependency inventory plus all 103 behavioral checks, native-codec normal/self-test, Bash/Python
  syntax, diff hygiene, and requirements-hash synchronization pass.

  Checks ran as an unprivileged UID in local containers with networking disabled, all capabilities dropped,
  no-new-privileges, source read-only, and tmpfs-only outputs. The existing Apple image was used for the extracted
  gate; a full wrapper attempt was stopped and is not counted when it began rebuilding that already-present image,
  and the existing image identity remained unchanged. No Docker socket was mounted into a test container. No host
  RustDesk process/service/configuration, listener, firewall, or network namespace was inspected or changed. The
  top-level verifier/full release build was not run because it deliberately builds images and executes root service
  fixtures, and the controlling prompt forbids the long full release build. Native Darwin/Windows execution and
  exact release-artifact evidence therefore remain explicitly pending under R-B2.
- **R-S11e-39 — Linux service-owned pkcheck inherited environment authority — SOURCE IMPLEMENTED AND SOURCE-GATED
  2026-07-19; EXACT DEBIAN ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: Linux
  installed/service-owned unattended-password receiver.
  Endpoint/action: the root service's fixed `/usr/bin/pkcheck --action-id
  com.carriez.RustDesk.set-unattended-password --process <pid,start-time,uid> --allow-user-interaction` child.
  Boundary: root supervisor launch environment ↔ the external helper whose successful exit is accepted as the
  administrative authorization decision. Proven old path: R-S11e/R-S11e-1/R-S11e-15/R-S11e-30 already bound the
  action, live kernel-derived subject, trusted root-owned executable, timeout/reap behavior, and inherited
  descriptors, but `std::process::Command::new(pkcheck)` still inherited the supervisor's complete environment.
  The official `pkcheck(1)` contract describes the program as a wrapper around the polkit D-Bus interface, and the
  D-Bus specification makes `DBUS_SYSTEM_BUS_ADDRESS` the environment-selected system-bus address, falling back to
  the well-known local system-bus socket only when it is absent. Ambient loader, path, home, and locale variables
  were likewise unnecessary inputs to an exit-status-only privileged authorization helper.

  Authority assessment: the packaged systemd, SysV, OpenRC, runit, and manual configurations and the inspected
  service call graph expose no proved ordinary-user write into the root supervisor's environment. A hostile value
  requires a privileged or otherwise misconfigured launcher. This is therefore conceptual privileged authorization-
  endpoint/future-deployment authority and defense in depth, not a demonstrated promptless ordinary-user-to-root
  primitive and not evidence that the polkit daemon or policy was bypassed on a supported deployment.

  Closure: `configure_linux_pkcheck_environment` calls `Command::env_clear()` immediately after the trusted image is
  selected. The authorization command adds no environment variables and then applies only its fixed argv, null
  stdio, R-S11p descriptor policy, bounded execution, and fail-closed result handling. The change is deliberately
  confined to pkcheck; display/session helpers whose protocol explicitly needs selected environment values are not
  broadened or refactored. A two-hop Linux unit regression gives an intermediate test image a hostile
  `DBUS_SYSTEM_BUS_ADDRESS`, applies the exact production environment policy to a final test image, and proves that
  the final image receives no environment entry except its test-only role marker. `scripts/verify.sh` and the
  semantic workspace verifier bind the primitive, production call and ordering before descriptor configuration and
  spawn, absence of explicit replacement variables, actual-child proof, R-S11y, Appendix C #147, this entry, and
  independent source mutations. Primary contracts:
  https://polkit.pages.freedesktop.org/polkit/pkcheck.1.html,
  https://dbus.freedesktop.org/doc/dbus-specification.html, and
  https://doc.rust-lang.org/std/process/struct.Command.html#method.env_clear.

  Verification: Rust 1.75 compiled and executed the two-hop focused regression in the existing `rd-devcheck` image;
  all three parent/launcher/worker invocations reported the one selected test passing, with 305 tests filtered out.
  A separate `cargo check --offline --locked --lib --features linux-pkg-config` completed in 28.11 seconds. The normal
  semantic workspace verifier and its complete independently invocable in-memory source-mutation matrix pass; the
  mutations independently remove environment clearing, add a replacement bus selector after clearing, remove the
  production policy call, invert the actual-child bus-address assertion, or rename the shell gate, normative
  requirement, Appendix row, and hardening record; each is rejected by its intended contract. The extracted
  R-S11e-30/R-S11e-39 shell gates, Bash/Python syntax, exact
  Rust 1.75 rustfmt check, native-codec normal/self-test, requirements-hash synchronization, and `git diff --check`
  pass. The first focused-test setup attempt is not counted: an unpinned rustup channel tried to write an update
  check under the read-only container root. Pinning the already-installed exact `1.75.0-x86_64-unknown-linux-gnu`
  toolchain produced the passing run. A first combined native/format command placed a Docker volume option after the
  image name, so both native gates passed before the command ended on the resulting missing `/toolchain` path; the
  correctly composed command was rerun and all three checks passed.

  Checks ran as the invoking non-root UID in the existing local image
  `sha256:b2b892936a87b2fcd6aff35f709d025947b4d6f1de735d04ed1fc413f9b7bb58`, with networking disabled, all
  capabilities dropped, no-new-privileges, source read-only, Cargo registry/git caches read-only, and build outputs
  in disposable tmpfs. No image was built or pulled and no Docker socket, host PID/network namespace, published
  port, service/config path, or host root identity entered a container. No host RustDesk process/service/config,
  listener, firewall, or networking state was inspected or changed. The long top-level verifier and full release
  build were not run because they deliberately build images and/or execute root service fixtures and the controlling
  prompt forbids that expansion. Exact clean Debian artifact execution remains owned by R-B2/R-S11c-27; this source
  slice does not substitute for that release evidence. Publication evidence is recorded after commit and push.
- **R-S11e-40 — Linux loginctl session-query authority — SOURCE IMPLEMENTED AND SOURCE-GATED 2026-07-19;
  EXACT DEBIAN ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: Linux installed supervisor and
  service-owned/user-owned desktop processes. Endpoint/action: the shared fixed-path `loginctl` calls used to list
  logind sessions and read `Type`, `State`, `Seat`, `LockedHint`, and (after R-S11e-42) `Display`. Boundary:
  root/service process launch state and
  locally reported logind data ↔ active-user selection, display-protocol classification, lock state, and
  service-child replacement decisions.

  Proven old path: R-S11c-10m and R-S11e-32 already required a fixed canonical root-owned executable plus a
  stdio-only descriptor boundary, but `run_loginctl(Option<Vec<&str>>)` still encoded a generic argv surface and
  inherited the caller's complete environment. Session listing invoked the default human-oriented command, ignored
  child exit status, decoded with lossy UTF-8, searched an entire row for `seat0`, and treated every state string
  containing `active` as active. `get_display_server_of_session(session)` correctly queried one explicit session,
  then on empty/tty/unspecified output substituted the calling process's `XDG_SESSION_TYPE`; that value describes the
  caller and need not describe the queried session. The official systemd 252 `loginctl(1)` contract designates
  `show-session` for computer-parsable output, provides property/no-legend/no-pager controls, defines nonzero exit as
  failure, and warns that inherited pager state is an elevated-command boundary. The pinned systemd 252 source emits
  SESSION/UID/USER/SEAT/TTY; current systemd 260 preserves those first four authority fields while appending
  LEADER/CLASS/TTY/IDLE/SINCE presentation fields. The logind contract limits session State to
  online/active/closing and Type to unspecified/tty/graphical protocols.

  Authority assessment: no inspected packaged systemd/SysV/OpenRC/runit/manual launcher gives an ordinary user a
  proved write into the root supervisor environment, and the parsed output comes from the local system logind
  service rather than a network peer. A hostile `DBUS_SYSTEM_BUS_ADDRESS`, pager, loader value, or forged logind
  response therefore requires privileged/misconfigured launch state or already-compromised local OS authority. The
  concrete bugs are cross-session ambient-state confusion and permissive parsing; the privilege classification is
  conceptual receiver/future-deployment authority and defense in depth, not a demonstrated promptless
  ordinary-user-to-root primitive.

  Closure: `LoginctlQuery` has only `ListSessions` and `SessionProperties`; the latter accepts only the closed
  `LoginctlProperty::{Type,State,Seat,LockedHint}` vocabulary, extended only with the exact-session `Display`
  property by R-S11e-42. It emits fixed local queries with explicit
  `--no-pager`, list-only `--no-legend`, `show-session --property=...`, and `--` before the separate session ID.
  `configure_loginctl_environment` clears every inherited variable before argv and the existing descriptor policy
  are applied. `run_loginctl` requires a successful exit. The strict list parser requires UTF-8 and validates the
  stable leading SESSION/UID/USER/SEAT authority fields, including canonical decimal UIDs, while ignoring only
  version-dependent trailing presentation fields. The property parser requires exactly-once requested rows;
  malformed, missing, duplicate, or unrequested authority data fails closed. Seat/state/lock decisions compare the
  parsed field/value exactly. Empty, tty, unspecified, or unavailable session Type now uses only the compile-pinned
  X11 constant; production session
  selection contains no `XDG_SESSION_TYPE` read. Both strict lifecycle fixtures accept only the new production argv.
  Primary contracts:
  https://www.freedesktop.org/software/systemd/man/252/loginctl.html,
  https://github.com/systemd/systemd/blob/v252/src/login/loginctl.c,
  https://github.com/systemd/systemd/blob/v260/src/login/loginctl.c,
  https://wiki.freedesktop.org/www/Software/systemd/logind/, and
  https://doc.rust-lang.org/std/process/struct.Command.html#method.env_clear.

  Verification: Rust 1.75 compiled and ran five focused tests in the existing non-root networkless devcheck image.
  Pure tests bind exact typed argv, pinned/current list shapes, stable leading-field/UID rejection,
  requested-property exactness and duplicate/missing/extra-row rejection, exact active-state behavior, and
  X11-owned fallback. A two-hop actual-child test puts hostile
  `DBUS_SYSTEM_BUS_ADDRESS`, `SYSTEMD_PAGER`, and `XDG_SESSION_TYPE` values in an intermediate image, applies the
  production environment policy, and proves the final child receives none of them and no environment entry except
  its test role marker. The full offline Linux library check completed with only the repository's existing warning
  set. Rustfmt, both fixture syntax checks, the extracted R-S11e-40 shell gate, the normal semantic verifier, and its
  complete independent source-mutation suite passed. The native-codec ledger and self-test passed, as did the
  dependency inventory and all 103 inventory mutations (909 Cargo packages; 850 lexical unsafe blocks across 251
  tracked Rust files). These gates bind production ordering, forbidden old parsing/ambient shapes, both strict
  fixtures, R-S11z, Appendix C #148, and this ledger entry. Publication evidence is recorded after commit and push.

  All code/test execution for this slice uses the invoking non-root UID in an existing local image, networking
  disabled, all capabilities dropped, no-new-privileges, read-only source/Cargo inputs, and tmpfs outputs. No image
  is built or pulled; no Docker socket, host PID/network namespace, port publication, service/config path, or host
  root identity is used. No host RustDesk process/service/configuration, listener, firewall, or network state is
  inspected or changed. The long full release build and root service fixtures remain excluded. Exact clean Debian
  artifact execution remains owned by R-B2/R-S11c-27 and is not inferred from this source slice.
- **R-S11e-41 — Linux systemctl service-lifecycle authority — SOURCE IMPLEMENTED AND SOURCE-GATED 2026-07-19;
  EXACT DEBIAN ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: Linux privileged desktop service
  installation and uninstallation. Endpoint/action: the fixed-path `systemctl` child used to enable, start, disable,
  or stop the installed service. Boundary: already-privileged RustDesk launch state and signed application identity ↔
  systemd system-manager unit-file and runtime service authority.

  Proven old path: R-S11c-10i/R-S11e-32 already required direct argv, a canonical root-owned executable, the
  stdio-only descriptor contract, and checked child status. `systemctl_service(action: &str, app_name: &str)` still
  inherited the privileged process's complete environment, represented its command as a generic string, passed an
  unsuffixed unit whose type systemctl inferred, selected no explicit manager scope, and retained ambient stdin and
  authorization interaction. systemd 252 documents `systemctl [OPTIONS...] COMMAND [UNIT...]`, the system/user
  scope distinction, zero-only success, `--no-ask-password`, elevated pager risk, and that enable searches unit-file
  directories and creates symlinks. Its pinned `acquire_bus` source also reads `SYSTEMCTL_FORCE_BUS`: a true value
  replaces the direct local-manager connection with the full D-Bus path, where the companion
  `DBUS_SYSTEM_BUS_ADDRESS` variable can select the endpoint. Its unit-load contract states that
  `SYSTEMD_UNIT_PATH` overrides the load path. The child also otherwise inherited pager, offline-mode, loader,
  search-path, locale, and home variables.

  Authority assessment: source/history review found only the fixed install/uninstall CLI calls, which first require
  the process already to have superuser authority; Linux has no in-process elevation on this path. The signed custom
  application name was already restricted to 1–64 ASCII bytes with a letter first, alphanumeric last, and only
  alphanumerics/hyphens. No inspected systemd/SysV/OpenRC/runit/manual launcher or repository call gives an ordinary
  user a proved write into the privileged environment, action, or application name. This is conceptual privileged-
  helper/future-deployment authority and deterministic receiver correctness, not a demonstrated promptless local
  privilege escalation or evidence of host compromise.

  Closure: `SystemctlServiceAction` represents exactly Enable/Start/Disable/Stop and serializes only the corresponding
  four verbs. `systemctl_service_unit` independently revalidates the signed application-name grammar at the
  privileged receiver, lowercases it, and appends the explicit `.service` suffix; invalid, path-shaped, option-shaped,
  suffixed, non-ASCII, or oversized input fails before process construction. `configure_systemctl_command` clears the
  entire child environment, adds no variable, nulls stdin, and emits exact
  `--system --no-pager --no-ask-password -- <typed verb> <validated unit>` argv. The existing trusted canonical image,
  non-stdio descriptor policy, spawn-error handling, and successful-exit requirement remain. Install/uninstall call
  only the typed variants and retain fail-fast lifecycle completion.

  Verification: Rust 1.75 compiled and ran two focused tests in the existing non-root networkless devcheck image.
  The pure regression covers all four action serializations, exact scope/noninteractive/terminator/unit argv, signed-
  grammar normalization, malformed target rejection, and both length boundaries. A two-hop actual-child regression
  gives an intermediate launcher hostile `SYSTEMCTL_FORCE_BUS`, `DBUS_SYSTEM_BUS_ADDRESS`, `SYSTEMD_UNIT_PATH`,
  `SYSTEMD_PAGER`, and `SYSTEMD_OFFLINE`, applies the production environment policy to the final child, and proves
  every hostile variable and every environment entry except its test role marker is absent. The image's systemd 252
  systemctl also parsed the exact option-terminator-before-command shape and reached command dispatch. Dedicated
  shell and semantic gates bind the
  typed policy, validator, argv/environment/stdin/descriptor/status ordering, consumers, regressions, R-S11aa,
  Appendix C #149, and this ledger; independent mutation cases cover the gate identity, ledgers, environment removal,
  verb, suffix, and system scope. The dedicated R-S11e-41 gate and adjacent R-S11e-32/R-S11c-16/R-S11c-10i gates,
  normal semantic verifier, complete source-mutation verifier, Bash syntax, native-codec watch and self-test,
  dependency inventory and its 103 checks, fresh full Linux library check, Rust 1.75 slice formatting, requirements-
  hash equality, and `git diff --check` all pass. Requirements SHA-256 is
  `939bf619bd2086e54c05bd1744c3978f881ef0078b851b02e1360891f8284282`, synchronized in both tracked ledgers.
  Publication evidence is recorded after commit and push.

  All project code/test execution for this slice uses the invoking non-root UID in an existing local image, networking
  disabled, all capabilities dropped, no-new-privileges, a read-only root filesystem, read-only source/Cargo inputs,
  and disposable tmpfs outputs. No image is built or pulled; no Docker socket, host PID/network namespace, port
  publication, service/config path, or host root identity is used. No host RustDesk process/service/configuration,
  listener, firewall, or network state is inspected or changed. The long full release build and root service fixtures
  remain excluded. Exact clean Debian artifact execution remains owned by R-B2/R-S11c-27 and is not inferred here.
- **R-S11e-42 — Linux selected X11 session display authority — SOURCE IMPLEMENTED AND SOURCE-GATED
  2026-07-19; EXACT DEBIAN ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: Linux installed supervisor
  and the root or privilege-dropped service-owned server it launches. Endpoint/action: selection of `DISPLAY` and the
  optional `XAUTHORITY` environment override for the active X11 desktop. Boundary: exact active logind
  session/UID/seat authority ↔ local X server endpoint and client credential selected for the service-owned child.

  Proven old path: `Desktop::refresh` first selected one exact session ID, UID, username, seat, and protocol through
  the R-S11z typed logind boundary. `Desktop::get_display_x11` then discarded the session ID. It searched loosely
  name-matched same-UID process environments; on failure it ran `w <username>`, parsed the third whitespace field of
  human-formatted output, scanned `/tmp/.X11-unix`, and finally invented `:0`. The socket helper sorted global `Xn`
  sockets and returned the first selected-user-owned socket, but if none matched it deliberately returned the last
  socket owned by somebody else. It proved only file type and owner, not association with the selected logind
  session. The final hostname/`localhost` text replacements could also turn some non-local strings into local display
  selectors. Xauthority discovery independently accepted the first named-process `XAUTHORITY` for the UID, without
  requiring that process's `DISPLAY` to match, then accepted the first same-UID Xorg `-auth` argument without tying
  that Xorg server to the chosen display. The positive `r_s11c10_x11_socket_display_discovery_reads_metadata` test
  explicitly required a missing username to receive another owner's `:7`, preserving the cross-owner fallback as
  intended behavior.

  Research and authority assessment: the official systemd 252 login1 interface exposes `Display` on the exact
  session object. `CreateSession` receives the graphical display; the pinned `pam_systemd` source obtains it from
  `PAM_XDISPLAY`; the pinned session D-Bus vtable directly maps `Display` to that session's stored field. A later
  `SetDisplay` is accepted only from that session's current controller and only for a graphical session. The X server
  manual defines `/tmp/.X11-unix/Xn` only as the Unix-domain socket for display number `n`; that name contains no
  logind session or user binding. Xlib/Xauthority documentation separately makes `DISPLAY` the mandatory endpoint,
  makes `XAUTHORITY` only the optional credential-file selector, defaults the latter to `$HOME/.Xauthority`, and
  records credentials by display. The old path therefore had a real deterministic cross-session/cross-owner endpoint
  selection defect. It is also a conceptual privileged-local-endpoint confused-deputy path when the selected child
  remains root: a global unowned X endpoint could be supplied to a privileged client. Source review did not prove a
  promptless ordinary-user-to-root exploit. A selected standard-user child drops to that UID before exec, same-UID
  process state is not a stronger principal, and code execution from a wrong root endpoint would require an
  additional reachable X-client defect or a privileged root-session precondition. This is not evidence that the host
  was compromised.

  Closure: `LoginctlProperty::Display` extends the closed R-S11z vocabulary. `get_x11_display_of_session` queries only
  the already-selected session and passes its result through `normalize_local_x_display_name`, which accepts and
  canonicalizes only local `:<u32>[.<u32>]` syntax. Missing, empty, malformed, remote/hostname-qualified, or
  unavailable values return no display. `get_display_x11` has no process, `w`, socket, hostname-rewrite, Xorg, or
  `:0` fallback. A retained active X11 session requeries the same session's Display and refreshes its credential hint,
  so temporary absence or a controller-authorized update can recover without retaining stale endpoint state.
  `xauthority_from_environ_for_display` reads `DISPLAY` and `XAUTHORITY` from one process environment, requires the
  former and the selected endpoint to name the same validated local numeric X server (screen suffix differences are
  equivalent), and accepts only a nonempty absolute control-free credential path. Process discovery remains
  selected-UID-only. If no such hint exists,
  no `XAUTHORITY` override is passed and the privilege-dropped child uses Xlib's standard passwd-derived
  `HOME/.Xauthority`; the sole explicit fallback is the existing selected-UID `/run/user/<uid>/gdm/Xauthority` file.
  Server-side Xorg `-auth` inference is deleted. The obsolete fixed `w` candidates/resolver, socket parser, cross-owner
  behavior, and positive socket regression are deleted with the fallback.

  Verification: Rust 1.75 compiled and ran both focused regressions in the existing networkless devcheck image. The
  shared test proves exact Display query argv/property parsing, strict local-display canonicalization and remote or
  malformed rejection, and screen-independent numeric-server identity. The root-library test proves that DISPLAY and
  XAUTHORITY come from one process image, `:7.0` is valid for selected server `:7`, wrong/remote displays fail, and
  relative credential paths fail. A first root regression run correctly failed when the draft compared canonical
  display strings including their screen suffixes; the implementation was changed to compare the validated numeric
  X server identity and the complete focused run then passed (one shared test with 150 filtered out and one root test
  with 307 filtered out). The full locked/offline Linux library check passed in 28.53 seconds with only the existing
  warning set. Both strict loginctl fixtures answer only the exact enumerated Display query with `Display=:0`.

  The extracted R-S11e-42 shell gate, normal semantic workspace verifier, and its complete independent source-mutation
  matrix pass. The mutations independently target the gate and legacy-absence gate, normative ID and authority text,
  Appendix row and disposition, ledger, local syntax, exact property, credential/display comparison, endpoint
  assignment, adjacent retained-session display/credential refresh, legacy fallback insertion, and fixture removal.
  Rust 1.75 full-file formatting for the shared file and edited-line formatting for the large root platform file,
  Bash/dash/Python syntax, requirements-hash equality, and `git diff --check` pass. Dependency inventory plus all 103
  behavioral checks pass with 909 Cargo packages and 849 lexical `unsafe {` blocks across 251 tracked Rust files; the
  count falls by one because deleting the obsolete socket regression deletes its test-only `geteuid` unsafe block.
  Native-codec normal and mutation checks pass against synchronized requirements SHA-256
  `057d8f0b17bbd921ab7d0e98de3cbf1f0c6d7dc4f613c4b5ca63281c67eec627`. Publication evidence is recorded after commit
  and push.

  All project code/test execution for this slice is constrained to the invoking non-root UID in the existing local
  devcheck image, with networking disabled, all capabilities dropped, no-new-privileges, read-only root/source/Cargo
  inputs, and disposable tmpfs outputs. No image is built or pulled and no Docker socket, host PID/network namespace,
  published port, service/config path, or host root identity enters a container. No host RustDesk process/service/
  configuration, listener, firewall, or networking state is inspected or changed. The long full release verifier and
  root service fixtures remain excluded. Exact clean Debian artifact execution remains owned by R-B2/R-S11c-27.
- **R-S11e-43 — Linux obsolete Xorg process authority — SOURCE IMPLEMENTED AND SOURCE-GATED 2026-07-19;
  EXACT DEBIAN ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: Linux installed supervisor and
  selected-desktop lifecycle. Endpoint/action: service startup/replacement cleanup plus the selected desktop's
  headless classification. Boundary: root supervisor signal/lifecycle authority ↔ global process-table command-line
  presentation and an externally owned X server.

  Proven old path: `stop_subprocess()` constructed `/etc/<app>/xorg.conf`, enumerated every visible process, and
  sent SIGKILL when argv zero's displayed basename compared case-insensitively to `Xorg` and any argument equaled
  that path. `Desktop::set_is_subprocess()` separately treated any process command line containing the same path as
  proof that the receiver-selected logind desktop was a RustDesk-created headless session. Neither path checked an
  owned parent/child generation, executable object, process start identity, UID, or selected logind session. Linux's
  `proc_pid_cmdline(5)` contract explicitly describes this file as the command line the process wants the observer
  to see and permits the process to rewrite its displayed argv; `execve(2)` receives the caller-supplied argument
  vector. The root service could therefore be induced by an ordinary process to terminate a selected process or to
  change service headless/restart state.

  The abstraction had also become obsolete. R-X14 commit `62177b1` deleted RustDesk's PAM authentication, Xorg and
  window-manager launchers, xauth writer, and child tracking from `linux_desktop_manager.rs`; current source retains
  existing-session discovery only. The supported headless model requires the administrator to pre-start an X
  server, which makes that external lifecycle specifically not a RustDesk-owned child. The packaged
  `startwm.sh`/`xorg.conf` conffiles remain root-trust administrator resources under R-X14/R-S11c-10t, but their
  pathname cannot mint process ownership.

  Closure: the Xorg basename matcher, global Xorg kill sweep, arbitrary config-path command-line scan,
  `is_rustdesk_subprocess` field, setter, and positive matcher test are deleted. This slice initially left the
  separately supported `--cm-no-ui` lifecycle for independent adjudication; R-S11e-44 subsequently deletes that
  global cleanup and kernel-binds the helper to its exact server parent. `Desktop::is_headless()` now means exactly
  that the typed logind selection produced no session ID. R-S11ac and Appendix C #151 bind this authority deletion.

  Verification: the focused headless-state regression and retained exact-argv matcher regression each pass with
  one selected test and 308 filtered out. The full locked/offline Linux library check passes with only the existing
  warning set. The extracted dedicated R-S11e-43 shell gate, normal semantic workspace audit, and complete
  independent source-mutation matrix pass; mutations independently reject gate/requirement/Appendix/ledger drift,
  non-session headless state, removal of the focused regression, and restored Xorg kill/classification/generic-
  cleanup symbols. The then-retained CM cleanup checks are superseded by R-S11e-44's deletion gates. Rust 1.75 reports no
  formatting change on any of the 14 edited current lines in the large platform source (unrelated pre-existing
  whole-file drift remains). Bash/Python syntax, requirements SHA-256 equality, `git diff --check`, dependency
  inventory plus its complete behavioral self-test, and native-codec normal/self-test all pass. The inventory remains
  909 Cargo packages and 849 lexical `unsafe {` blocks across 251 tracked Rust files; the synchronized requirements
  SHA-256 is `057d8f0b17bbd921ab7d0e98de3cbf1f0c6d7dc4f613c4b5ca63281c67eec627`.

  Every code/build/test execution is constrained to the
  invoking non-root UID in the existing local devcheck image with networking disabled, all capabilities dropped,
  no-new-privileges, read-only source/tool inputs, and disposable tmpfs outputs. No image build/pull, Docker socket,
  host PID/network namespace, published port, service/config mount, host root identity, or host RustDesk/network/
  firewall inspection is authorized. The long release verifier and root service fixtures remain excluded. Exact
  clean Debian artifact execution remains owned by R-B2/R-S11c-27; publication evidence is recorded after commit
  and push.
- **R-S11e-44 — Linux headless connection-manager parent authority — SOURCE IMPLEMENTED AND SOURCE-GATED
  2026-07-19; EXACT DEBIAN ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: Linux installed supervisor,
  its exact root or privilege-dropped service-owned `--server` child, and the same-principal `--cm-no-ui` helper
  started for a headless connection. Endpoint/action: service startup and server replacement cleanup plus headless
  CM launch/lifetime. Boundary: the root supervisor's machine-wide signal authority ↔ a helper whose actual owner is
  the exact server process that created it.

  Proven old path: service startup and both server-replacement branches called
  `stop_headless_connection_manager_processes()`. That function enumerated every visible process, required only
  `/proc/<pid>/exe` equality with the current service image and an exact displayed `--cm-no-ui` argument, then called
  `kill(pid, SIGKILL)` from the root supervisor. It retained no `Child`, pidfd, start time, process object, parent
  relationship, or generation between observation and signal. Any user can execute the genuine installed RustDesk
  image with that argument; an `execve`, exit, or PID reuse can also change the numeric target after the observations.
  This is root-originated process-table availability/confused-deputy and PID-race authority, not a demonstrated
  promptless ordinary-user-to-root primitive. Killing a selected process does not itself grant code execution.

  Closure: the supervisor cleanup function, direct SIGKILL wrapper, current-image kill sweep, and all three calls are
  deleted. This slice originally selected `run_me_with_env_and_parent_death` only for Linux `headless_cm`; R-S11e-95
  subsequently applies the same exact-parent lifetime to graphical Linux `--cm` because CM authority now depends on
  direct parenthood. Non-Linux launches retain their existing paths. The helper still derives the current executable,
  exact role argv, and CM launch-token/parent environment, but registers the Linux parent-death hook before the
  existing R-S11q descriptor hook. The parent captures its PID. In the forked child, the hook uses raw `prctl` to set
  `PR_SET_PDEATHSIG` to `SIGKILL`, then raw `getppid` and `ESRCH` failure to reject an already-changed parent before
  exec. Arming first closes the early-parent-exit race; ordinary RustDesk exec preserves the setting, and later loss
  of the creating server thread makes the kernel retire that exact CM image. Linux defines this relationship against
  the creating parent thread, so an unexpectedly lost server runtime worker may conservatively retire the helper;
  that is fail-closed availability and a later connection can create a fresh generation. Graceful last-client drain
  retains the existing `EXIT_ON_IDLE` path.

  Primary contracts:
  https://man7.org/linux/man-pages/man2/pr_set_pdeathsig.2const.html,
  https://man7.org/linux/man-pages/man2/getppid.2.html, and
  https://doc.rust-lang.org/1.75.0/std/os/unix/process/trait.CommandExt.html#method.pre_exec.
  A three-process regression starts a launcher copy of the exact test image, has it spawn a worker through the exact
  production parent-bound helper, receives the worker PID over a private Unix socket, retains that worker with a
  pidfd, kills/reaps the launcher, and requires the pidfd to report worker exit. `scripts/verify.sh` and the semantic
  workspace verifier bind hook-before-descriptor ordering, raw syscall and parent-comparison semantics, current
  all-Linux call-site selection, the actual-child proof, complete global cleanup absence, R-S11ad, Appendix C #152,
  and this entry. Independent source mutations remove or weaken each authority edge and documentation/gate anchor.

  Verification: Rust/Cargo 1.75 complete the locked/offline Linux library check with only the existing warning set.
  The new actual-child regression, the retained service-child parent-death regression, and the renamed exact-argv
  signal matcher each pass with one selected test, zero failures, and 309 filtered out. The extracted R-S11e-43,
  R-S11e-44, and R-S11c-10b shell gates pass without stderr. The normal semantic workspace audit and its complete
  independently invoked source-mutation set pass, including restored Xorg/generic-cleanup and global-CM-sweep
  mutations. Bash/Python syntax, `git diff --check`, Rust 1.75 formatting for `src/common.rs` and
  `src/server/connection.rs`, dependency inventory and all 103 inventory mutations, native-codec normal/self-test,
  and requirements-hash equality pass. The large Linux platform file has only its documented unrelated pre-existing
  whole-file formatting drift; none begins in the new parent-death implementation. The measured inventory is 909
  Cargo packages and 854 lexical `unsafe {` blocks across 251 tracked Rust files/74 nonzero files, with per-file
  digest `58c8a4c1cef49aa7fea95fb48545dd68451a4866badd7e780303bfb43ca76fd7`; the synchronized requirements SHA-256 is
  `a5ad2af8ede6c842c07bb5fbc1363cc55e4378ef0d80b2df47a32a131bc4b847`.

  Every code/build/test execution uses the invoking non-root UID in the existing local devcheck image, with
  networking disabled, all capabilities dropped, no-new-privileges, read-only source/toolchain/Cargo inputs, and
  executable output only on disposable tmpfs. No image build/pull, Docker socket, host PID/network namespace,
  published port, service/config mount, host root identity, or host RustDesk/network/firewall inspection occurs. The
  long release verifier and root service fixtures remain excluded. Exact clean Debian artifact execution remains
  owned by R-B2/R-S11c-27 and is not inferred from source conformance; publication evidence is recorded after commit
  and push.
- **R-S11e-45 — Linux remaining current-image process-table lifecycle authority — SOURCE-GATED 2026-07-19;
  EXACT DEBIAN ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform:
  Linux installed supervisor, its root or privilege-dropped service-owned `--server` child, and the separate tray.
  Endpoint/action: service-child replacement decisions and tray replacement at server startup. Boundary: the
  supervisor/server's lifecycle and signal authority ↔ unrelated processes selected through current-image pathname
  equality and displayed argv.

  Proven old path: `get_cm()` enumerated every `/proc/<pid>/exe` equal to the current service image and treated any
  exact displayed `--cm` argument as connection-manager state. An unprivileged user can execute the genuine installed
  image with that role. Holding the presentation suppressed the inherited hourly restart; removing it after the
  service had observed it could drive the 60-second delayed restart branch. Every Linux `--server` also called
  `stop_tray_processes()`, which selected all current-image processes displaying exact `--tray` and applied the
  server's SIGTERM authority before spawning a replacement. Active-desktop children normally had only same-UID
  signal permission, while a headless root child carried root signal authority. Linux documents proc cmdline as the
  command line a process wants an observer to see, `execve(2)` accepts caller-selected argv, and `kill(2)` applies the
  sender's UID/capability authority. Path plus argv therefore did not establish ownership.

  Closure: the current-image enumerator, path comparator, exact-argument authority helper, numeric signal wrapper,
  tray cleanup API/call, CM-presence heuristic, and `cm0`/`last_restart` elapsed-state branch are deleted. The timed
  restart comment identified SpotUdp/DNS as its owner, but R-D4 excised that rendezvous topology; the direct listener
  owns its own bounded bind/retry loop. `service_child_needs_replacement` now has the complete receiver-owned decision
  vocabulary: selected-logind headless transition, selected UID change, or selected display/Xauthority change.
  `should_start_server` separately observes exit of its retained exact `Child`, and explicit service shutdown still
  drains that exact child. A Linux server continues to start the current image with exact `--tray`; the existing
  `--tray` receiver performs its same-UID singleton check, so a new candidate exits when a tray already exists and no
  pre-existing process is signaled. R-S11ae and Appendix C #153 bind this deletion.

  Primary contracts:
  https://man7.org/linux/man-pages/man5/proc_pid_cmdline.5.html,
  https://man7.org/linux/man-pages/man2/execve.2.html, and
  https://man7.org/linux/man-pages/man2/kill.2.html. A pure regression covers stable selected state, display change,
  UID change, headless transition, and stable headless state. `scripts/verify.sh` and the semantic workspace verifier
  bind the closed replacement vocabulary, retained tray launch/singleton receiver, complete
  forbidden-symbol deletion, R-S11ae, Appendix C #153, this entry, and independent source mutations. This is a
  concrete ordinary-user-triggerable root-service restart-state spoofing/availability correction plus deletion of
  conceptual privileged or same-principal global-signal authority. It is not evidence of a promptless privilege
  escalation or host compromise; termination or restart influence did not grant root code execution.

  Verification: Rust/Cargo 1.75 completed the focused locked/offline regression with one selected test passed, zero
  failures, and 309 filtered out, then completed the full Linux library
  `cargo check --offline --locked --lib --features linux-pkg-config` in 27.21 seconds with only the repository's
  existing warning set. The extracted R-S11e-45 and adjacent R-S11c-10b shell gates pass. The normal semantic
  workspace audit and its complete independent source-mutation set pass; the mutations cover the gate, normative ID
  and authority clause, Appendix C row/disposition, ledger, restored CM/tray authority, server-side tray signaling,
  and the headless state edge. Bash/Python syntax and Rust 1.75 formatting for `src/core_main.rs` and every edited
  `src/platform/linux.rs` line pass; unrelated pre-existing whole-file Linux formatting drift remains untouched.
  Dependency inventory and all 103 inventory mutations pass: 909 Cargo packages and 853 lexical `unsafe {` blocks
  across 251 tracked Rust files/74 nonzero files, with per-file digest
  `35572ccbfbc3ac1f9467e23212dca00930c356f8f448dd5056a0f763a1292619`. The one-block decrease is the deleted raw
  `kill(2)` wrapper. Native-codec normal/self-test and requirements-hash equality pass at
  `4bc75ad3cdd8029873b6eae4d8a6f786dcd26bc180a1d4df220ce49bb5b60d01`.

  Every code/build/test execution used UID 1000 in the existing local
  `rd-devcheck@sha256:b2b892936a87b2fcd6aff35f709d025947b4d6f1de735d04ed1fc413f9b7bb58`, with networking
  disabled, all capabilities dropped, no-new-privileges, source/toolchain/Cargo inputs read-only, and executable
  outputs only on disposable container tmpfs. No image was built or pulled; no Docker socket, host PID/network
  namespace, published port, host service/config mount, host root identity, or host RustDesk/network/firewall
  inspection was used. The first compile setup reached only dependency build scripts and was not counted because an
  accidentally non-executable output tmpfs correctly denied their execution; the clean rerun changed only that
  container-local tmpfs to executable. The long release verifier and root service fixtures remain excluded. Exact
  clean Debian artifact execution remains owned by R-B2/R-S11c-27 and is not inferred from source conformance;
  publication evidence is recorded after commit and push.
- **R-S11e-46 — Linux privileged service-to-tray boundary — SOURCE-GATED 2026-07-19;
  EXACT DEBIAN ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: Linux installed supervisor,
  its root or privilege-dropped service-owned `--server` child, the independent `--tray` process, and the tray's
  no-argument Open child. Endpoint/action: automatic autostart-state maintenance and tray/UI launch during server
  startup. Boundary: the privileged controlled-side service role and its selected display credentials ↔ interactive
  per-user desktop UI and independently surviving child processes.

  Proven old path: `start_os_service` selects `ServiceChildPrincipal::RootService` for the root desktop and the GDM
  Wayland login screen. `try_start_server_` correctly clears the child environment, but then supplies the selected
  desktop's display/Xauthority or Wayland/runtime-directory and session-bus values because the controlled-side root
  server needs that endpoint. The common Linux `--server` arm unconditionally called `check_autostart_config()` and
  `run_me(["--tray"])`. The tray inherited the server's effective root principal and bounded environment, was not
  parent-death-bound to the retained service child, and its Open action used `run_me([])` to create the full GUI with
  that same root principal. A server replacement or exit therefore did not retire the privileged tray, and a tray
  interaction could create another root GUI. The shared Linux `is_root()` also compared the resolved effective
  account name to the literal `root`; numeric effective UID 0 is the kernel privilege identity, so a renamed UID-0
  passwd entry or unexpected name lookup would have made the new boundary incomplete. Git history attributes the
  unconditional common launch to the upstream import, not to the fork's recent service hardening.

  Authority model and closure: the root service-owned server retains its selected display endpoint for the listener,
  capture, and input roles, but Linux tray/autostart is classified as non-root user-session UI. The empty-argument
  automatic-tray path now requires `linux_user_session_ui_allowed(is_root())`. The Linux `--server` arm checks the
  same closed principal policy before either touching per-user autostart state or spawning the exact tray role. The
  shared Linux root predicate now uses the already-present safe `hbb_common::users::get_effective_uid() == 0`
  authority, never account-name equality. The `--tray` receiver independently checks that effective principal and
  exits 1 before singleton discovery or UI construction when UID 0, so a future privileged caller cannot bypass the
  spawning-side policy. Non-root portable and active-seat service-owned servers retain the existing exact tray
  launch, same-UID receiver singleton check, and Open behavior. No root service, listener, capture, input,
  display-selection, or privilege-drop logic changes.

  Primary contracts: the freedesktop Desktop Application Autostart specification defines application autostart as a
  user's post-login desktop-environment mechanism and its override under the user's configuration home
  (https://specifications.freedesktop.org/autostart/0.5/); the Wayland client API defines `WAYLAND_DISPLAY` and
  `XDG_RUNTIME_DIR` as the compositor connection selector (https://wayland.freedesktop.org/docs/html/apb.html); and
  polkit's privileged-execution security notes deliberately strip `DISPLAY`/`XAUTHORITY`, describing their retention
  for privileged GUI applications as discouraged legacy behavior
  (https://polkit.pages.freedesktop.org/polkit/pkexec.1.html). The service server is the narrow controlled-side
  exception that needs a selected graphical endpoint; the independent tray/viewer GUI is not.

  Proof and gates: `r_s11e46_linux_tray_requires_non_root_principal` binds root refusal and non-root preservation;
  `r_s11e46_linux_root_principal_is_numeric_effective_uid` binds UID 0 and representative nonzero UIDs.
  `scripts/verify.sh` extracts and binds the numeric effective-UID root predicate, closed UI policy, empty-argument
  guard, server-side autostart/tray guard, receiver-side non-success refusal before process discovery, regressions,
  R-S11af, Appendix C #154, and this entry.
  The semantic workspace verifier independently interprets those source regions and rejects mutations of the gate,
  policy, all three call-site/receiver edges, proof, normative requirement/title, Appendix row/disposition, and
  ledger. This closes a concrete promptless service-to-root-GUI creation path and an unbound privileged-UI lifetime.
  It does not claim a demonstrated ordinary-user-to-root exploit or host compromise: converting the pre-existing root
  GUI/display connection into attacker-controlled root execution would require an additional interaction or defect.

  Verification: Rust/Cargo 1.75 completed the focused locked/offline gate with both selected tests passed, zero
  failures, and 310 filtered out. The final full
  `cargo check --offline --locked --lib --features linux-pkg-config` completed in 27.40 seconds with only the
  repository's existing warning set. The extracted R-S11e-46 and adjacent R-S11e-45 shell gates pass. The normal
  semantic workspace audit and its complete independently executed source-mutation matrix pass; mutations cover the
  gate, numeric effective-UID source/comparison/proof, all three spawning/receiver boundaries, non-success ordering,
  normative ID/title/effective-UID clause, Appendix row/disposition, ledger, and preserved non-root assertions.
  Bash/Python syntax, `git diff --check`, Rust 1.75 formatting of `src/core_main.rs`, and an emitted-format hunk audit
  proving that neither edited region in the large Linux platform file intersects its unrelated pre-existing
  whole-file formatting drift pass. Dependency inventory and all 103 inventory mutations pass unchanged: 909 Cargo
  packages and 853 lexical `unsafe {` blocks across 251 tracked Rust files/74 nonzero files, digest
  `35572ccbfbc3ac1f9467e23212dca00930c356f8f448dd5056a0f763a1292619`. Native-codec normal/self-test and
  requirements-hash equality pass at
  `2ab29eb2732b6003e8f4a7aca74b973be35b2dd911e288f08db27db4433927e2`.

  Setup/failure accounting: the first syntax bundle reached only Cargo's rustup proxy because login-shell PATH
  rewriting defeated the direct toolchain path; the corrected command used the mounted exact binaries. The first
  full-repository format check exposed only the ledger's unrelated pre-existing formatting drift plus this slice's
  one core-main line wrap, which was corrected before all counted checks. Early mutation runs found a stale
  pre-rustfmt fixture line, then two old fixtures anchored to the deliberately replaced name-based root predicate,
  and finally a duplicate documentation substring whose mutation needed requirement-local extraction. Each fixture
  was corrected without removing or weakening a production assertion; the final complete mutation matrix passed. A
  redundant hash assertion at the end of the final composite check over-escaped an awk positional parameter after
  every preceding gate had passed; the direct constrained hash check then passed at the recorded value.

  Every code/build/test/verifier command used numeric UID/GID 1000 in the existing local
  `rd-devcheck@sha256:b2b892936a87b2fcd6aff35f709d025947b4d6f1de735d04ed1fc413f9b7bb58`, with networking
  disabled, a read-only root/source/toolchain/Cargo input set, all capabilities dropped, no-new-privileges, bounded
  pids, and executable output only on disposable tmpfs. No image was built or pulled; no Docker socket, host PID or
  network namespace, published port, host service/config mount, or root identity entered a container. No host
  RustDesk process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or host networking
  was inspected or changed. The long release verifier, root service fixtures, and full release build remain
  excluded. Exact cold final Debian artifact execution remains owned by R-B2/R-S11c-27 and is not inferred from this
  source proof; publication evidence is recorded after commit and push.
- **R-S11e-47 — macOS numeric service-principal authority — SOURCE-GATED 2026-07-19;
  NATIVE MACOS COMPILATION/EXECUTION AND EXACT SIGNED-ARTIFACT EVIDENCE REMAIN WITH R-R2/R-B2.** Platform: macOS
  common application dispatch, the dedicated service executable, and the root LaunchDaemon/PrivilegedHelperTools
  service listener. Endpoint/action: entering the protected `--service` role and binding its shared IPC endpoint.
  Boundary: an arbitrary local process principal and presentation-layer account lookup ↔ the UID-0 service receiver
  that supplies credential snapshots and coordinates the per-user LaunchAgent-owned controlled-side server.

  Proven old path and history: `src/platform/macos.rs::is_root()` implemented privilege classification as
  `crate::username() == "root"`; `crate::username()` resolves a presentation name through `whoami`, rather than
  returning the kernel credential itself. `start_os_service()` returned no result, performed no principal check,
  and swallowed `ipc::start` failure after logging it. The common `src/core_main.rs` `--service` arm and dedicated
  `src/service.rs` binary both invoked that receiver without a UID gate or non-success propagation. A non-root local
  process could therefore attempt to occupy the shared endpoint when the real LaunchDaemon was absent, and a UID-0
  process whose account-name resolution was unexpected could be misclassified by connection-manager/whiteboard
  root-transition guards. `git blame` attributes both the name predicate and direct service entry to upstream import
  `c2abd3b3`, not to a recent hardening slice.

  Authority model and closure: the macOS protected service role is exactly numeric effective UID 0. The shared
  predicate now delegates to a pure `effective_uid_is_root(uid)` comparison and obtains its live value through the
  narrow `unsafe { hbb_common::libc::geteuid() }` FFI call. Account names remain presentation-only.
  `start_os_service()` is now result-bearing, rejects every nonzero effective UID before logging the service principal or entering
  `ipc::start(POSTFIX_SERVICE)`, and returns listener errors rather than swallowing them. Both the common macOS
  `--service` branch and dedicated service executable log that failure and exit 1. The existing connection-manager
  and whiteboard fail-closed root-transition branches automatically consume the corrected shared predicate. The
  normal non-root per-user LaunchAgent server is intentionally unchanged. Independent service-client audit-token,
  UID-0, trusted PrivilegedHelperTools code-signature, receiver peer-credential, and installed-plist checks remain
  mandatory; this entry gate does not replace them.

  Primary contracts and classification: Apple's `getuid(2)`/`geteuid(2)` manual defines the effective UID as the
  process credential carrying additional permissions in set-ID execution
  (https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getuid.2.html),
  and Apple's `intro(2)` manual states that filesystem access is governed by effective UID/group state and that a
  process with effective UID 0 is superuser
  (https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/intro.2.html).
  This closes a concrete ordinary-user endpoint-occupancy/availability path and conceptual privileged-helper
  principal confusion. It does not claim credential disclosure, promptless privilege escalation, or host compromise:
  the independent client and receiver identity checks still reject an untrusted service peer.

  Proof and gates: `r_s11e47_macos_root_principal_is_numeric_effective_uid` binds UID 0 plus representative nonzero
  UIDs. `scripts/verify.sh` and `scripts/apple-conform-check.sh` extract the numeric predicate, effective-UID source,
  account-name absence, result-bearing receiver, check/log/listener ordering, both error-propagating executable
  entries, regression, R-S11ag, Appendix C #155, and this entry. The semantic workspace verifier independently
  interprets the same authority regions and carries complete mutations for both shell gates, requirement ID/title and
  numeric/order clauses, Appendix row/disposition, ledger, numeric comparison, effective-UID source, account-name
  reintroduction, result/guard/order/error handling, both callers, and the pure regression.

  Verification: both extracted R-S11e-47 gates pass. Rust 1.75 formatting/parser checks pass for all three edited Rust
  files; Bash syntax and in-memory Python compilation pass for every edited verifier. The normal semantic workspace
  audit and its complete independently executed source-mutation matrix pass. The latter rejects both gate deletions,
  normative ID/title/effective-UID/order clauses, Appendix row/disposition, ledger removal, numeric-comparison or
  effective-to-real-UID substitution, account-name reintroduction, missing result/guard/order/error propagation, both
  caller regressions, and proof deletion. The locked/offline Linux library
  `cargo check --features linux-pkg-config` completed in 38.46 seconds using the complete read-only cargo-vendor source
  map, with only the repository's existing warning set; this proves the shared dispatch remains Linux-compatible but
  is not counted as macOS compilation. Dependency inventory and all 103 inventory mutations pass: 909 Cargo packages
  and 854 lexical `unsafe {` blocks across 251 tracked Rust files/74 nonzero files, per-file digest
  `da946df73ff7346ff79a8c1ba6b0ecef0f4486de14ac9437fca96aefac247644`. The one-block increase is the reviewed,
  expression-scoped macOS `geteuid()` FFI call. Native-codec normal/self-test, `git diff --check`, and the synchronized
  requirements identity pass at `bf12999747458d36a204e7358a2d591a2d5f7ac452e492fb580cdcb7477af50e`.

  Failure accounting: the first Docker metadata query named an absent optional `Config.User` field and failed before
  starting a container. The first Python bytecode syntax command then tried to create `__pycache__` on the deliberately
  read-only source mount and was replaced by in-memory compilation; no source write occurred. The mutation suite found
  and caused correction of a substring-ambiguous gate assertion and then a diagnostic-order mismatch, without
  weakening a production assertion. A first Cargo attempt reached dependency compilation but found one pre-existing
  named-cache source unreadable by UID 1000; no ownership or permission was changed, and the successful rerun used the
  repository's complete read-only `online/cargo-vendor` source map. The image lacked its optional Rust 1.75 rustfmt
  component, so the already-installed host-owned 1.75 toolchain was mounted read-only and its formatter passed. A final
  cross-target availability audit caught that `hbb_common::users` is Linux-only before commit; the macOS source was
  corrected to the existing `libc::geteuid()` binding, requirements/gates/mutations/inventory were synchronized, and
  the entire final verification set then passed. No native Apple or signed-artifact result is inferred from Linux
  source conformance. The long release verifier and release builds stayed excluded by the active task instructions.

  Execution boundary: every project code/build/test/verifier command in this slice used numeric UID/GID 1000 in
  the existing local `rd-devcheck@sha256:b2b892936a87b2fcd6aff35f709d025947b4d6f1de735d04ed1fc413f9b7bb58`,
  with networking disabled, a read-only root/source/toolchain/Cargo input set, all capabilities dropped,
  no-new-privileges, bounded pids, and outputs only on disposable container tmpfs. No image build/pull, Docker socket,
  host PID/network namespace, published port, host service/config mount, or root identity was used. No host RustDesk
  process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or networking was inspected or
  changed. Publication evidence is recorded only after commit and push.
- **R-S11e-48 — Linux numeric selected-session service-child authority — SOURCE-GATED 2026-07-19;
  EXACT INSTALLED DEBIAN ARTIFACT EXECUTION REMAINS WITH R-B2/R-S11c-27.** Platform: the installed Linux root
  supervisor and its service-owned root or active-user `--server` child. Endpoint/action: selecting whether the
  child retains the supervisor's root credentials or executes the complete passwd-validated credential drop.
  Boundary: the typed active logind session's numeric UID and presentation username ↔ root child-launch authority.

  Proven old path and history: R-S11z already made list-sessions parsing strict UTF-8, fixed-field, and canonical for
  the numeric UID, but `start_os_service()` discarded that numeric authority and selected the root branch with
  `desktop.username == "root"`. `try_start_server_()` separately accepted a caller-supplied
  `ServiceChildPrincipal`. A renamed UID-0 account therefore entered `ActiveDesktopUser` and was deterministically
  rejected by `ServiceChildCredentials::resolve()`'s existing UID-0 refusal. Conversely, an internally inconsistent
  selected record carrying username `root` and a nonzero UID chose the no-drop root child. Git blame attributes the
  literal-name branch to upstream import `c2abd3b3`, not a recent fork hardening change.

  Authority model and closure: `selected_service_child_principal()` is the single receiver-owned derivation. Both
  UID and username empty is the no-selected-desktop state. Partial identity, nondecimal UID, and noncanonical decimal
  UID fail closed. Canonical UID 0 selects `RootService` regardless of account-name presentation; every nonzero
  selected user selects `ActiveDesktopUser`, except the deliberate existing selected GDM/SDDM Wayland login-screen root
  service path. The supervisor matches on that result to choose its retained owned-child slot. The launcher no
  longer accepts a principal argument: it derives the result again from the same immutable desktop snapshot and
  refuses launch without a selection. The active-user path still resolves the exact username through the password
  database, requires returned UID/name equality, resolves supplementary groups, and orders
  `setgroups`/`setresgid`/`setresuid` before `PR_SET_NO_NEW_PRIVS` and exec.

  Primary contracts and classification: systemd 252 login1 defines `ListSessions()` records as separate session ID,
  numeric user ID, user name, seat ID, and object path, and defines a session's `User` property as its Unix UID
  (https://www.freedesktop.org/software/systemd/man/252/org.freedesktop.login1.html). Linux `credentials(7)` defines
  user identities as integers and the effective IDs as kernel permission authority
  (https://www.man7.org/linux/man-pages/man7/credentials.7.html). This closes a concrete deterministic UID-0 service
  availability defect and conceptual privileged child-principal confusion. It does not demonstrate ordinary-user
  promptless privilege escalation: the input is a trusted local logind result, and forging an inconsistent pair
  requires prior root or OS-service integrity failure.

  Proof and gates: `r_s11e48_linux_service_child_principal_uses_selected_numeric_uid` binds a renamed UID-0 account,
  misleading `root` name with UID 1000, the retained GDM Wayland exception, empty selection, noncanonical UID, and
  partial identity. `scripts/verify.sh` extracts the derivation, launcher and supervisor call graph, credential-drop
  validation, regression, R-S11ah, Appendix C #156, and this entry; the semantic workspace verifier independently
  interprets the same regions and carries source mutations for every authority and documentation edge.

  Verification: the final Rust/Cargo 1.75 locked/offline Linux library gate compiled the complete library-test target
  in 1 minute 56 seconds; the selected regression passed with zero failures and 312 tests filtered out. The extracted
  R-S11e-45, R-S11e-46, R-S11e-47, and R-S11e-48 source gates all pass, proving that this dispatch change preserves
  the adjacent owned-lifecycle, root-to-tray, and macOS numeric-principal contracts. The normal semantic workspace
  audit and its complete independently executed source-mutation matrix pass. The matrix rejects the new gate,
  normative ID/title/name-prohibition/numeric-UID/launcher clauses, Appendix row/disposition, ledger, empty/partial/
  malformed/noncanonical policies, numeric root and login-screen classification, root/active results,
  caller-selected launcher/wrapper authority, launcher-without-selection acceptance, supervisor bypass, passwd
  UID/name and supplementary-group weakening, credential-drop ordering, regression deletion, and invalid-input proof
  reversal.

  Bash syntax and in-memory Python compilation pass for both edited verifiers. Rustfmt 1.75 reports no diff in any
  slice-owned Rust region; its remaining output starts in unrelated pre-existing service-lifecycle tests and the
  pre-existing SELinux test, which this slice does not reformat. `git diff --check` passes. Dependency inventory and
  all 103 inventory mutations pass unchanged: 909 Cargo packages and 854 lexical `unsafe {` blocks across 251 tracked
  Rust files/74 nonzero files, with per-file digest
  `da946df73ff7346ff79a8c1ba6b0ecef0f4486de14ac9437fca96aefac247644`. Native-codec normal/self-test and the
  synchronized requirements identity pass at
  `8cab215a43b2693a63f62b216570831b483ed9bae64f87f0a8e883cbf351367a`.

  Failure/setup accounting: the initial formatter run found the new launcher signature's one wrap along with the
  repository's unrelated recorded drift; that slice-owned wrap was corrected before the final inspection. The source
  mutation runner then found two overly short mutation needles that also matched unrelated Linux code, followed by
  one expected-diagnostic mismatch; each fixture was narrowed or corrected without weakening a production assertion,
  and the complete final matrix passed. Two attempts to run the verifier's broader process/cgroup transaction
  self-test inside the deliberately isolated container stopped at its protected user-systemd-bus prerequisite: first
  `/run/user/1000` and then its required Unix bus socket were absent. No host bus/service socket was mounted to bypass
  that isolation, and those attempts are not counted as evidence; the relevant normal semantic audit and complete
  in-memory source-mutation matrix are green.

  Execution boundary: every project code/build/test/verifier command used numeric UID/GID 1000 in the existing local
  `rd-devcheck@sha256:b2b892936a87b2fcd6aff35f709d025947b4d6f1de735d04ed1fc413f9b7bb58`, with networking
  disabled, read-only root/source/toolchain/vendor inputs, all capabilities dropped, no-new-privileges, bounded pids,
  and outputs only on disposable tmpfs. No image was built or pulled; no Docker socket was mounted into a container;
  no host PID/network namespace, published port, host service/config/user-bus mount, or root container identity was
  used. No host RustDesk process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or host
  networking was inspected or changed. The long release verifier, root service fixtures, full release build, and
  exact installed Debian artifact execution remain excluded and owned by R-B2/R-S11c-27. Publication evidence is
  recorded after commit and push.
- **R-S11e-49 — exact service-owned server process role — SOURCE-GATED 2026-07-19;
  NATIVE WINDOWS/MACOS AND EXACT INSTALLED-ARTIFACT EVIDENCE REMAIN WITH R-R2/R-B2.** Platforms: Linux, Windows,
  and macOS desktop process entry plus Windows machine-configuration
  bootstrap. Endpoint/action: classifying the internal service-owned `--server` child before selecting service
  configuration, IPC, credential-replica, SAS, terminal, or helper policy. Boundary: caller-supplied process
  arguments ↔ the role that an installed service actually created and protected receivers later authenticate.

  Proven old path and history: every supported launcher emits exactly `--server --service-owned-server`: Linux uses
  two fixed `Command::arg` calls, Windows passes that exact two-element slice to its fixed-image session launcher,
  and the macOS LaunchAgent plist carries the same two role tokens after the executable. Linux, Windows, and macOS
  protected peer authenticators independently require the complete shape. The shared
  `is_service_owned_server_process()`, however, used `std::env::args_os().any(...)` and returned true when the marker
  occurred anywhere. Windows `bootstrap()` repeated a whole-vector search for either `--service` or the child
  marker. A reordered, duplicated, unrelated-command, or extra-argument marker could therefore select in-process
  service-owned policy despite not matching any owning launch or receiver proof. Git history traces the broad helper
  to the original R-S11b service-password separation commit `32ad1353`; later exact peer proofs did not tighten the
  current-process half. The protected Windows `_service` listener itself was re-audited in this slice and remains a
  closed receiver: its ordinary channel admits only `Test` and typed `RequestServiceOwnedShareRdp`, while SAS has a
  separate one-message listener and authorization path. No broad Windows service message was found.

  Authority model and closure: one platform-independent `ServiceOwnedServerRole` parser consumes only arguments
  after `argv[0]`. It returns `Exact` only for the two tokens `--server`, `--service-owned-server` and no third token;
  any other occurrence of the internal marker is `Malformed`; marker-free invocations are `Absent`. Every existing
  service-child role consumer retains the shared boolean helper, which now means only `Exact`. `core_main()` checks
  the three-state result at its first statement and exits 1 for `Malformed`, before `global_init`, Linux config-root
  selection, Windows bootstrap, or command dispatch. Thus malformed marker text cannot silently downgrade to an
  ordinary `--server`. Windows bootstrap now recognizes only the shared exact `--service` supervisor predicate or
  the exact child predicate, and passes write authority only for the supervisor role. Executable identity, numeric
  OS principal, service parent/generation, fixed installed root, and protected-peer credentials remain separate
  proofs; none is inferred from `argv[0]` or marker text.

  Primary contracts and classification: Rust documents that the first `std::env::args` element may be arbitrary and
  must not be used as security identity, and directs callers to `args_os` when arguments may not be Unicode
  (https://doc.rust-lang.org/std/env/fn.args.html and https://doc.rust-lang.org/std/env/fn.args_os.html). Apple's
  launchd documentation defines `ProgramArguments` as a tokenized array containing the program and arguments
  (https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).
  Microsoft's `CreateProcessW` contract defines the child command line and its `argc`/`argv` parsing boundary
  (https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw).
  This closes deterministic role/configuration confusion and conceptual privileged-process policy ambiguity. It is
  not evidence of promptless privilege escalation or compromise: marker text never supplied the independent service
  principal, installed executable, owning parent, or receiver-authenticated peer identity.

  Proof and gates: `r_s11e49_service_owned_server_role_requires_exact_arguments` binds the exact positive case and
  marker-only, reordered, prefixed, suffixed, and duplicated malformed cases.
  `r_s11e49_unowned_roles_cannot_become_service_owned` binds empty, ordinary server, supervisor, and unrelated
  marker-free arguments to `Absent`. `scripts/verify.sh` extracts the parser, exact count/positions, marker
  classification, `argv[0]` skip, boolean consumer, early malformed exit/order, Windows exact consumer/write
  authority, both regressions, R-S11ai, Appendix C #157, and this entry. The semantic workspace verifier separately
  interprets the same regions and carries independent mutations for each authority and documentation edge.

  Verification: Rust/Cargo 1.75 completed the locked/offline Linux library-test target in 5 minutes 49 seconds; both
  selected regressions passed, zero failed, and 313 tests were filtered out. The extracted R-S11e-49 shell gate
  passes. The normal semantic workspace audit and its complete source-mutation matrix pass; the new independent
  mutations reject weakened argument-one/argument-two matching, extra-argument admission, count widening, missing
  malformed detection, wrong `argv[0]` skip, inverted boolean consumption, early-exit weakening, Windows exact-role
  or write-authority bypass, regression removal, gate deletion, requirement/title/clauses, Appendix C row/disposition,
  and ledger removal. Bash syntax and in-memory Python compilation pass. Rustfmt 1.75 reports no diff in
  `src/common.rs` or `src/core_main.rs`; its Windows output remains limited to four pre-existing unrelated hunks at
  lines 85, 5251, 5295, and 5704, with no hunk in the edited bootstrap region. `git diff --check` and synchronized
  requirements/native-watch/ledger identity pass at
  `d960425d27e0106747f79ab265ea9638c6b1482085238c65dcbfe15ce7075c8f`.

  Failure/setup accounting: the first pinned offline test attempt made no compilation progress because the read-only
  image prevented rustup metadata refresh; selecting the installed exact 1.75 toolchain fixed that without network or
  a writable toolchain. Two cache setup attempts then failed before compilation because one omitted the host's
  cached Git inputs and one remounted absolute cached Git metadata at a different path; mounting the same read-only
  cache at its recorded path fixed resolution. A 4 GiB run compiled the full library-test graph but was SIGKILLed at
  final rustc linking by the deliberate memory ceiling and is not counted as evidence. The successful rerun retained
  every isolation control, selected one compiler job and disabled test-profile debug information, and raised only the
  explicit memory/swap ceiling to 8 GiB. The first mutation run exposed one expected-diagnostic label mismatch; the
  label was corrected without weakening a validator or production assertion, and the complete rerun passed. One
  final source-bundle attempt used unavailable `rg` inside a shell conditional and therefore could not prove its
  legacy-pattern absence scan; that attempt is not counted. The complete rerun used the image's available recursive
  `grep` fallback and passed without diagnostic output.

  Execution boundary: every project code/build/test/verifier command used numeric UID/GID 1000 in the existing local
  `rd-devcheck@sha256:b2b892936a87b2fcd6aff35f709d025947b4d6f1de735d04ed1fc413f9b7bb58`, with networking
  disabled, read-only root/source/toolchain/Cargo inputs, all capabilities dropped, no-new-privileges, bounded pids,
  bounded CPU/memory, and outputs only on disposable tmpfs. No image was built or pulled; no Docker socket, host
  PID/network namespace, published port, host service/config mount, or root container identity was used. No host
  RustDesk process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or networking was
  inspected or changed. The long release verifier, service fixtures, full release build, native Apple/Windows runs,
  and exact installed-artifact execution remain excluded. Publication evidence is recorded in the private audit
  journal after commit and push.
- **R-S11e-50 — exact desktop service-supervisor process role — SOURCE-GATED 2026-07-19;
  NATIVE WINDOWS/MACOS AND EXACT INSTALLED-ARTIFACT EVIDENCE REMAIN WITH R-R2/R-B2.** Platforms: Linux and Windows
  installed service supervisors, plus the shared Linux/Windows/macOS desktop process entry. The installed macOS
  LaunchDaemon uses the separate dedicated no-argument `service` binary and is unchanged. Endpoint/action: selecting
  the root/LocalSystem service supervisor, Linux service-owned
  descriptor/working-directory/config-root policy, Windows machine-config write authority, and common service
  dispatch. Boundary: caller-supplied process arguments ↔ the exact supervisor role emitted by an installed service
  manager.

  Proven old path and history: every supported shared-image launcher is already exact. The systemd unit executes
  `/usr/bin/rustdesk --service`; the Debian SysV, OpenRC, runit, and manual definitions emit the same singleton role;
  and the Windows MSI installs the LocalSystem service with `Arguments="--service"`. The common dispatcher still
  selected service behavior from `args[0] == "--service"` without checking the count. Linux selected its
  service-owned descriptor, working-directory, and root config policy from only `args_os().nth(1)`. Windows
  `bootstrap()` likewise set the machine-config writer bit from only argument one. A suffix, prefix, duplicate, or
  mixed protected role therefore selected supervisor policy despite matching no shipped launcher. Git history
  attributes the prefix dispatcher to upstream import `c2abd3b3` and the Linux config-root prefix to `87b15905`.
  The preceding R-S11e-49 change correctly deleted Windows' whole-vector child-marker search, but its replacement
  narrowed `--service` only to argument one and still did not validate the complete supervisor vector; this slice
  closes that remaining defect explicitly.

  Authority model and closure: a platform-independent `ServiceSupervisorRole` parser consumes only arguments after
  `argv[0]`. It returns `Exact` only for the singleton `--service` vector, `Malformed` whenever the reserved marker
  occurs in any other vector, and `Absent` for marker-free roles. `core_main()` derives that state before any global
  initialization and exits 1 on `Malformed`; it cannot silently downgrade or accept a trailing-argument service
  role. Linux service-root selection and common service dispatch consume only `Exact`. On Windows the same exact
  state selects the early SCM-dispatch branch; only its SCM-created `ServiceMain` receives machine-config write
  authority, while ordinary bootstrap recognizes the independently exact R-S11ai/R-S11e-49 child and initializes
  only its read-only replica. Numeric root/LocalSystem authority, installed-image provenance, service-manager
  ownership, parent/generation proof, and protected IPC peer authentication remain separate requirements; argument
  text supplies none of them.

  Primary contracts and classification: Rust documents that `argv[0]` can be arbitrary, must not be security
  identity, and that `args_os` is required to preserve non-Unicode arguments
  (https://doc.rust-lang.org/std/env/fn.args.html and https://doc.rust-lang.org/std/env/fn.args_os.html). Microsoft's
  `CreateServiceW` contract states that a service binary path may contain arguments and those arguments are passed to
  the service entry point
  (https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew). Apple's launchd
  `ProgramArguments` contract defines a tokenized program-and-argument array
  (https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).
  This is deterministic supervisor/configuration-role confusion and conceptual privileged-process policy ambiguity,
  not evidence of promptless privilege escalation, compromise, or an OS-principal bypass: malformed argument text
  does not grant UID 0, LocalSystem, a trusted installed executable, or authenticated service IPC access.

  Proof and gates: `r_s11e50_service_supervisor_role_requires_exact_arguments` binds the singleton positive and
  suffix, prefix, duplicate, other-command, and mixed-protected-role negatives.
  `r_s11e50_marker_free_roles_cannot_become_service_supervisor` binds empty, ordinary server, exact service-owned
  child, tray, and unrelated marker-free roles to `Absent`. `scripts/verify.sh` extracts the parser states,
  full-iteration/position/count policy, malformed classification, `argv[0]` skip, exact-only boolean, pre-init
  rejection, Linux selection, common dispatch, Windows early SCM selection/SCM-owned write authority/read-only child
  bootstrap, all launcher definitions,
  regressions, R-S11aj, Appendix C #158, and this ledger. The semantic workspace verifier independently interprets
  those source/documentation/launcher regions and carries source mutations for every authority edge.

  Verification: Rust/Cargo 1.75 completed the locked/offline Linux library-test target in 5 minutes 49 seconds; both
  selected regressions passed, zero failed, and 315 tests were filtered out. The extracted R-S11e-50 shell gate
  passes. The normal semantic workspace audit and its complete source-mutation matrix pass. The matrix rejects
  position/count widening, missing marker or malformed classification, wrong `argv[0]` skip, inverted boolean
  consumption, a successful malformed-role return, weakened Linux selection or common dispatch, Windows exact-role
  bypass, regression removal, drift in each of the six supported shared-image launchers, gate deletion,
  requirement/title/clauses, Appendix C row/disposition, and ledger removal. Bash syntax and in-memory Python
  compilation pass. Rustfmt 1.75 reports no diff in `src/common.rs` or `src/core_main.rs`; its Windows output remains
  limited to four pre-existing unrelated hunks at lines 85, 5251, 5295, and 5704, with no hunk in the edited
  bootstrap region. Native-codec normal/self-test, `git diff --check`, and synchronized requirements/native-watch/
  ledger identity pass at `4d1478a7624e76e30c0f08a27537609fff07cef143cfe8ad1557d3925472d857`.

  Failure/setup accounting: the first focused test command used a login shell that reset `PATH`, so `cargo` was not
  found and no compilation occurred; the successful run invoked the installed exact Cargo/toolchain directly. The
  image's system Rust 1.75 toolchain lacks its rustfmt component, so the already-installed user-owned Rust 1.75
  toolchain was mounted read-only for formatting only. The initial semantic passes correctly rejected the stale
  requirements hash, an older macOS validator's dependency on the replaced dispatch spelling, and one
  formatting-sensitive exact token. Successive mutation runs then exposed overly broad adjacent-classifier/test
  extraction, a requirement boundary dependent on the next requirement's mutable ID, a later child-role exit that
  could mask removal of the supervisor exit, and shared launcher/Windows checks whose earlier diagnostic labels did
  not match the mutated authority. The affected verifier regions were narrowed to exact policy blocks or given
  mutation-independent structural boundaries; no production assertion was removed or weakened, and the complete
  final matrix passed.

  Execution boundary: every project code/build/test/verifier command used numeric UID/GID 1000 in the existing local
  `rd-devcheck@sha256:b2b892936a87b2fcd6aff35f709d025947b4d6f1de735d04ed1fc413f9b7bb58`, with networking
  disabled, read-only root/source/toolchain/Cargo inputs, all capabilities dropped, no-new-privileges, bounded pids,
  CPU, and memory, and output only on disposable tmpfs. No image was built or pulled; no Docker socket, host PID or
  network namespace, published port, host service/config mount, or root container identity was used. No host
  RustDesk process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or networking was
  inspected or changed. The long release verifier, root service fixtures, full release build, native Apple/Windows
  runs, and exact installed-artifact execution remain excluded. Publication evidence is recorded in the private
  audit journal after commit and push.
- **R-S11e-51 — Windows SCM-owned service entry authority — SOURCE-GATED 2026-07-19; NATIVE WINDOWS AND EXACT
  SIGNED-ARTIFACT EVIDENCE REMAIN WITH R-R2/R-B2.** Platform: Windows installed `SERVICE_WIN32_OWN_PROCESS`
  supervisor. Endpoint/action: selecting the
  durable machine-config writer, service log namespace, protected listeners, and supervised child runtime.
  Boundary: caller-selected exact `--service` role and Windows process principal ↔ SCM-owned service entry and
  status channel.

  Proven old path and history: after R-S11e-50 made the role vector exact, `core_main()` still ran `global_init()`,
  loaded the signed `custom.txt` identity, called `bootstrap()` with machine-config write authority, and initialized
  the `service` log before `start_os_service()` called `windows_service::service_dispatcher::start`. The wrapper
  caught that result, logged it, and returned `()`. Microsoft documents `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`
  when the image is run as a console application; the old exact-role console path could therefore perform
  service-specific setup before proving SCM ownership and then return through the ordinary successful `None` exit.
  Git blame attributes the swallowed dispatcher result and late common dispatch to the upstream import `c2abd3b3`;
  the machine-config receiver's independent LocalSystem-token rejection was added by the later fork hardening and
  already prevented a non-System caller from writing the durable store.

  Primary contracts and classification: Microsoft says an own-process service main thread should immediately call
  `StartServiceCtrlDispatcherW`, with initialization performed in the SCM-created `ServiceMain`; the call connects
  the main thread to SCM, returns `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` for a console launch, and otherwise does
  not return until the services have stopped
  (https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw and
  https://learn.microsoft.com/en-us/windows/win32/services/service-entry-point). Microsoft separately requires
  `ServiceMain` to register its control handler, report pending state, perform initialization, and report
  `SERVICE_STOPPED` with an error when initialization fails
  (https://learn.microsoft.com/en-us/windows/win32/services/service-servicemain-function and
  https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus). This was deterministic
  service-manager ownership/initialization-order confusion and false-success process status under an already
  privileged role. It was not an ordinary-user-to-LocalSystem escalation: argument text grants no token, and
  `Config::initialize_windows_service_owned_root` already rejects every token whose user is not LocalSystem before
  selecting or writing the machine store.

  Authority model and closure: after both protected-role classifiers reject malformed input, the Windows exact
  supervisor branch performs only the mandatory process-wide safe-DLL bootstrap and immediately calls a
  result-bearing `start_os_service()`. Dispatcher failure is printed and exits 1; no global/custom/config/log/listener
  initialization has occurred. A real SCM connection invokes `service_main`/`run_service`. That receiver registers
  its handler under the nonempty service name supplied as SCM `ServiceMain` argument zero and reports
  `SERVICE_START_PENDING` before global initialization, signed custom identity loading,
  ProgramData resolution, `initialize_windows_service_owned_root(..., true)`, and service-log initialization. Only
  after those steps succeed are the protected listener channels and child runtime created. An initialization error
  reports `SERVICE_STOPPED` with `ServiceSpecific(1)` before returning. The configuration initializer retains its
  independent LocalSystem-token check, so SCM ownership and principal are conjunctive receiver proofs. Ordinary
  Windows `bootstrap()` now selects only the exact service-owned child and passes write authority `false`; it cannot
  grant supervisor writer authority before dispatcher proof. Runtime errors after handler registration remain
  truthfully reported through the existing SCM status paths, so the dispatcher thread's eventual successful return
  is not misrepresented as their status channel.

  Verification: the extracted R-S11e-51 shell gate passes over the exact early core branch, result-bearing
  dispatcher, SCM-supplied nonempty service name, handler/pending/config/log/listener order,
  initialization-failure status, read-only child bootstrap, and LocalSystem receiver check. The independent
  semantic workspace audit and its complete source-mutation matrix pass. The matrix rejects pre-dispatch custom
  initialization, swallowed dispatcher errors, a successful dispatcher-failure return, empty-name admission,
  replacement of the SCM name with custom identity, pending-status reordering, writer movement or narrowing,
  initialization-failure status removal, child write widening, LocalSystem-check deletion, and requirement,
  Appendix C, gate, or ledger drift. Bash syntax and in-memory Python compilation pass. Rustfmt 1.75 reports no diff
  in `src/core_main.rs`; its Windows output remains limited to four pre-existing unrelated hunks at lines 85, 5281,
  5325, and 5734, with no hunk in either edited region. The focused R-S11e-49/R-S11e-50 shared process-role
  regressions completed earlier in this same slice with four selected tests passing and zero failing; the final
  source adjustment is Windows-gated and does not change those shared classifiers. Native-codec normal/self-test
  and synchronized requirements/native-watch/ledger identity pass at
  `d3326fbc4ad4fdc118ec37e7fb63235c9c3608c16ad48c2a530ba2cca0a65798`.

  Failure/setup accounting: the first final semantic run rejected an ordering window that began at handler
  registration and therefore could not see the newly added SCM-name derivation; the shell gate independently
  exposed the same stale boundary. Both windows now begin at `let service_name = arguments`, and the complete final
  semantic mutation matrix and extracted shell gate pass. The initial focused Cargo target used a no-exec tmpfs and
  failed before any test ran; the rerun used an executable disposable build tmpfs and passed. A full Apple wrapper
  attempt inside the isolated image stopped at its expected `docker not found` setup prerequisite because no Docker
  socket was mounted; it is not counted as an Apple result. Native Windows compilation/execution and a real SCM
  console-vs-service behavioral proof cannot be claimed from this constrained Linux source environment and remain
  exact-commit R-R2/R-B2 evidence.

  Execution boundary: every project build/test/verifier command used numeric UID/GID 1000 in the existing pinned
  `rd-devcheck@sha256:b2b892936a87b2fcd6aff35f709d025947b4d6f1de735d04ed1fc413f9b7bb58`, with networking
  disabled, read-only root/source/toolchain/Cargo inputs, all capabilities dropped, no-new-privileges, bounded pids,
  CPU, and memory, and disposable tmpfs output only. No image was built or pulled; no Docker socket, host PID or
  network namespace, published port, host service/config mount, or root container identity was used. No host
  RustDesk process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or networking was
  inspected or changed. The long release verifier, root service fixtures, full release build, native Apple/Windows
  runs, and exact installed-artifact execution remain excluded. Publication evidence is recorded in the private
  audit journal after commit and push.
- **R-S11e-52 — macOS service-owned configuration/log root — SOURCE-GATED 2026-07-19; NATIVE MACOS AND EXACT
  SIGNED-ARTIFACT EVIDENCE REMAIN WITH R-R2/R-B2.** Platform:
  macOS root LaunchDaemon/PrivilegedHelperTools receiver through both its dedicated no-argument executable and the
  shared application's exact `--service` entry. Endpoint/action: selecting the unattended credential/configuration
  namespace and rotating-file log directory before binding the protected service listener. Boundary: an inherited
  process environment and caller-selected `HOME` ↔ durable state read or written with effective UID 0.

  Proven old path and history: `src/service.rs` loaded custom identity and called `init_log(false, "service")`
  before `start_os_service()` checked effective UID. The shared macOS `--service` branch passed through the common
  `global_init`/custom-client/config/log path before reaching the same receiver check. On macOS,
  `Config::get_home()` and `Config::path()` ultimately used `directories-next` while `Config::log_path()` used
  `dirs-next`; their shared Unix substrate first reads inherited `HOME`. `Config::path()` then applies the vendored
  `directories-next 2.0.0` macOS `ProjectDirs::config_dir()` mapping under `Library/Application Support`. A UID-0
  manual, diagnostic, recovery, or future launcher invocation
  outside the installed LaunchDaemon's controlled environment could therefore select an ordinary-user-writable
  `~/Library/Application Support/<organization>.<application>` credential/config directory and
  `~/Library/Logs/<application>` rotating-log directory before the late principal gate. The installed plist itself
  is root-owned and `launchd` normally supplies a controlled environment, so this is not evidence that an ordinary
  user modified the installed service or obtained UID 0. `git blame` attributes the entry ordering and ambient path
  selection to upstream import `c2abd3b3`, not to this hardening continuation.

  Primary contracts and authority model: Apple's Secure Coding Guide identifies inherited environment variables as
  privileged-process attack input, recommends `launchd` for a controlled privileged-helper environment, requires
  privileged behavior not to depend on user-controllable environment/preferences, and says a helper must treat
  user-writable preference files as untrusted
  (https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/AccessControl.html,
  https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/DesigningSecureHelpers/DesigningSecureHelpers.html,
  and https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/SecurityDevelopmentChecklists/SecurityDevelopmentChecklists.html).
  Apple's `getpwuid_r(3)` contract supplies the numeric principal's password-database record independently of
  `HOME` (https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpwuid_r.3.html).
  The service storage authority is therefore one immutable process-local root derived from the already-required
  effective UID 0 password-database home, not from a launcher's environment.

  Closure: both service executables now call one `platform::macos::run_service()` bootstrap. Before reading even the
  signature-verified optional custom identity, it obtains numeric effective UID, rejects every nonzero value, resolves
  the same UID through the existing reentrant `getpwuid_r` helper, requires a clean absolute existing directory owned
  by UID 0 and not group/world writable, and otherwise returns an error. Only then may the custom identity establish
  the constrained application name. `Config::initialize_macos_service_owned_root` derives the exact existing macOS
  mapping—`<home>/Library/Application Support/<organization>.<application>` plus
  `<home>/Library/Logs/<application>`—and publishes it through `OnceLock`; an inconsistent second initialization is
  fatal. `Config::get_home`, `Config::path`, and `Config::log_path` consult that immutable root before their ordinary
  user-space ambient fallbacks. The bootstrap initializes the service logger only after publication and enters the
  independently numeric-UID-gated `start_os_service` listener last. Both callers emit a pre-logger diagnostic and
  exit 1 on any failure. Ordinary viewer, user-server, and per-user LaunchAgent path behavior is unchanged.

  Proof/gates: `r_s11e52_macos_service_owned_paths_ignore_ambient_home` binds the exact standard root config/log
  derivation and rejects a relative home, a slash-bearing identity, and a parent-directory identity. The R-S11e-52
  shell and Apple source gates extract the password-database principal proof, metadata checks, immutable derivation,
  all three config consumers, both centralized callers, complete principal/home → signed identity → config root → logger → listener
  ordering, R-S11al, Appendix C #160, and this ledger. The semantic workspace verifier independently interprets the
  same regions and carries source mutations for both gate identities, real-vs-effective UID, missing principal and
  metadata checks, constant/caller-selected UID lookup, bootstrap reordering, mutable root substitution, config/log
  path drift, inconsistent-reinitialization admission, all three consumer fallbacks, regression deletion,
  requirement clauses, Appendix disposition, and ledger drift.

  Verification: both final extracted R-S11e-52 shell/Apple gates pass. Bash syntax and in-memory Python compilation
  pass for every edited verifier, Rustfmt 1.75 reports no diff in all four edited Rust files, and the normal semantic
  workspace audit plus its complete independently invoked source-mutation matrix pass. The matrix rejects gate
  deletion or scope broadening, an application-independent log directory, principal/home/metadata weakening,
  real-for-effective UID substitution, caller-selected passwd lookup, bootstrap reordering, mutable or inconsistent
  root initialization, config/log derivation drift, any of the three ambient consumer fallbacks, either caller's
  failure-propagation removal, regression removal, normative/Appendix drift, and ledger deletion. The focused
  Rust/Cargo 1.75 locked/offline `hbb_common` regression completed in 1 minute 4 seconds: 1 passed, 0 failed, 151
  filtered. The final complete locked/offline Linux library `cargo check --features linux-pkg-config` completed in
  2 minutes 58 seconds with only the repository's existing warning set. That is shared-source Linux compatibility,
  not native macOS compilation.

  Independent inventories: dependency inventory and all 103 inventory mutations pass at 909 Cargo packages and 855
  lexical `unsafe {` blocks across 251 tracked Rust files/74 nonzero files, per-file digest
  `38d6395da84ce3ca90e8eb593c61006b6216c23e97149fa3e4f44cdb9a6590de`; the one-block increase is the reviewed,
  expression-scoped macOS `geteuid()` call. Native-codec normal/self-test, final `git diff --check`, Bash/Python/Rust
  syntax/format checks, and the synchronized requirements identity pass at
  `dd54f94705df4fcc38edc0f2c4bf504cdec4b66d12cbe27de6beffd3e8491e95`.

  Failure/review accounting: an initial semantic pass correctly rejected the stale derived requirements digest. The
  first broad root-package library-test attempt reached final linking but was killed by the 6 GiB container ceiling;
  it is not counted, and the corrected package-scoped regression is green. One first extracted Apple-gate command had
  a shell-quoting error and was replaced by the successful exact extraction. The mutation matrix exposed and caused
  correction of ambiguous log, adjacent Linux config-block, adjacent macOS/Windows entry-block, and requirement
  boundary assertions before its complete final pass. A human diff review then caught that the first derivation used
  `Library/Preferences`; inspection of the exact vendored `directories-next 2.0.0` source proved the compatibility
  path is `Library/Application Support`, and implementation, requirement, regression, gates, mutations, hashes, and
  every final check were corrected and rerun. One formatter container placed its read-only toolchain mount after the
  image name and therefore never started; the corrected invocation passed. One focused-test command named the
  non-installed `1.75` channel and stopped at the read-only Rustup boundary before compilation; the rerun selected the
  exact already-installed `1.75.0-x86_64-unknown-linux-gnu` toolchain and passed. No failed attempt is counted as
  evidence.

  Execution boundary: every project code/build/test/verifier command used numeric UID/GID 1000 in the existing pinned
  `rd-devcheck@sha256:b2b892936a87b2fcd6aff35f709d025947b4d6f1de735d04ed1fc413f9b7bb58`, with networking
  disabled, read-only root/source/toolchain/vendor inputs, all capabilities dropped, no-new-privileges, bounded pids,
  CPU, and memory, and disposable tmpfs output only. No image was built or pulled; no Docker socket, host PID/network
  namespace, published port, host service/config/user-bus mount, or root container identity was used. No host RustDesk
  process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or host networking was inspected
  or changed. Native macOS compilation/execution and exact installed signed-artifact evidence are not inferred from
  Linux source validation and remain mandatory R-R2/R-B2 evidence. The long release verifier, root service fixtures,
  full release build, and exact installed-artifact execution remain excluded. Publication evidence is recorded in the
  private audit journal after commit and push.
- **R-S11e-53 — authority-bearing IPC listener failure outcome — SOURCE, FOCUSED RUST, SOURCE GATES, AND
  MUTATION VERIFIED; NATIVE/ARTIFACT EVIDENCE PENDING 2026-07-19.** Platforms: Linux, macOS, and Windows
  desktop process-lifetime IPC receivers. Endpoints:
  the desktop main listener and its password listener, the Linux/macOS protected `_service` listener and its
  password listener, and the Windows service-owned main control and credential listeners. Boundary: an unexpected
  terminal loss of a local authority-bearing listener ↔ process-manager recovery and operator-visible service
  outcome.

  Proven old path and history: all three listener loops already separated ordinary process-wide cancellation from
  an unexpected stream `None`. Each unexpected branch stored a specific error, requested graceful shutdown, stopped
  accepting, drained admitted transaction tasks and password state, dropped its local listener guard, and called
  `finish_graceful_shutdown`. That sole finalizer nevertheless logged `exiting 0` and unconditionally called
  `process::exit(0)`. The protected Linux service listener additionally runs in a detached thread whose returned
  result is wrapped in `allow_err!`, so merely returning `Err` from the IPC future would still leave the supervisor
  process running without its protected control/credential receiver. `git blame` attributes the false-success
  finalization and listener-error flow to the earlier privileged-IPC consolidation `57bcb529`, not to R-S11e-52.
  The preceding adjacent hypothesis—that R-S11e-52's early macOS service entry accidentally skipped mandatory
  `global_init` policy—was disproved before this change: `global_init` has behavior only for Linux Wayland, while the
  R-S16 managed-store assertions remain at direct-listener startup on every platform.

  Primary contracts and authority model: pinned systemd 252 defines status zero as a clean exit and
  `Restart=on-failure` as recovery after a nonzero exit, and recommends that restart policy for long-running
  services (https://www.freedesktop.org/software/systemd/man/252/systemd.service.html). The shipped systemd unit uses
  that exact policy. Apple's launchd daemon guide defines `KeepAlive=true` as a continuously running job which
  launchd should keep trying to run
  (https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).
  Although the shipped macOS daemon restarts regardless of exit status, failure must remain distinguishable for
  diagnostics and any future conditional service-manager policy. The receiver-owned outcome is therefore a
  monotonic process-lifetime failure bit set at the listener-loss producer before cancellation, not a return value
  that can be discarded by a detached thread or overwritten by a later clean shutdown path.

  Closure: `request_graceful_shutdown_after_listener_failure` stores the failure latch with Release ordering and
  then invokes the unchanged cancellation request. All seven current unexpected listener-end branches use that helper; normal
  cancellation, SIGINT/SIGTERM, and service-manager stop paths continue to call the ordinary request and never set
  the latch. Under R-S11as the retained desktop owner receives and joins local IPC before the sole finalizer call;
  that finalizer waits for authenticated connection cleanup, then loads the monotonic latch with Acquire ordering
  and selects status 1 for failure or 0 for a normal request. R-S11e-58 makes protected Linux/macOS service IPC
  return the same post-drain failure to its foreground lifecycle owner instead of calling that process finalizer.
  Neither form introduces a second drain or an early pre-drain process exit. A later clean request cannot clear or
  downgrade the latched failure.

  Proof/gates: the focused Rust regression binds clean and failure status selection. The R-S11e-53 source
  and Apple gates bind the static latch, Release-before-cancellation producer ordering, exact seven error producers,
  Acquire-at-the-finalizer sink selection, process exit using the selected value, protected-service error return,
  unchanged drain-before-terminal-outcome ordering, R-S11am, Appendix C #161, and this ledger. The semantic workspace verifier independently interprets those regions
  and mutation-tests every producer, memory-order weakening, hardcoded-success restoration, regression/gate removal,
  and requirement/Appendix/ledger drift. Native Windows/macOS compilation and forced listener-loss execution remain
  R-R2/R-B2 evidence and are not inferred from the Linux source/test environment.

  Verification: the focused Rust regression passed (`1 passed`, 317 filtered) after compiling the root library with
  the audited vendored dependency tree. The R-S11e-53 shared and Apple source gates passed. The semantic workspace
  verifier passed normally and its complete source-mutation suite rejected gate deletion, each of the six producer
  downgrades, latch/removal/order weakening, drain removal, hardcoded-success restoration, clean-path
  misclassification, and normative/ledger drift. Shell syntax, in-memory Python syntax, and `git diff --check`
  passed; the pinned image does not contain `rustfmt`, so no formatter result is claimed and the two Rust edits were
  reviewed manually for local style after their successful Rust 1.75 compile. The native-codec source watch and its
  mutation self-test pass, as do the dependency inventory and all 103 inventory mutations (909 Cargo packages; 855
  lexical `unsafe {` blocks across 251 tracked Rust files). Every project check ran as numeric uid/gid 1000 in the
  exact pinned `rd-devcheck` image with no network, a read-only root/source tree, all capabilities dropped,
  `no-new-privileges`, and bounded resources; failed read-only Rustup/cache setup attempts were discarded as harness
  setup failures before the successful vendored run and are not counted as evidence. Native Windows/macOS compile
  plus forced listener-loss execution, exact-commit artifact/reproducibility evidence, and external audit remain
  R-R2/R-B2 work; this source closure does not claim them.
- **R-S11e-54 — Linux protected service IPC lifecycle ownership — SOURCE, FOCUSED RUST, SOURCE GATE, AND
  MUTATION VERIFIED; NATIVE INSTALLED/ARTIFACT EVIDENCE PENDING 2026-07-19.** Platform: Linux installed/manual
  root service. Endpoints: generic protected `_service` and
  raw `_service_password`. Boundary: root supervisor and service-owned controlled-child lifecycle ↔ readiness,
  failure, and complete ownership of locally admitted privileged administration work.

  Proven old path and history: `start_os_service` used an unconfigured `std::thread::spawn` whose closure wrapped
  the complete `ipc::start(POSTFIX_SERVICE)` result in `allow_err!` and discarded its `JoinHandle`. `new_listener`
  can fail while validating/scrubbing the secure parent, creating security attributes, binding either protected
  socket, applying its required mode, or activating the single process-lifetime listener guard. None of those
  failures prevented the root loop from selecting a principal and launching a service-owned child. The same root
  SIGTERM/SIGINT handler only cleared the service-loop boolean; it did not cancel or join protected IPC. Any normal
  stop or `?`-propagated loop error therefore returned from the process while the detached thread could still own an
  admitted polkit/password mutation, contradicting R-S11c-26's recorded non-aborting Linux drain. `git blame`
  attributes the detached `allow_err!` startup to the original upstream import `c2abd3b3`, not a recent hardening
  slice. This is deterministic privileged-operation finality and fail-open service availability/recovery, not a
  demonstrated bypass of the separate socket-peer, polkit-action, or replica-parent authorization checks.

  Primary contracts and authority model: Rust's standard-library channel contract makes readiness timeout and
  sender disconnection explicit outcomes, while `thread::Builder::spawn` returns the OS thread-creation error rather
  than panicking like the free `thread::spawn` convenience API (https://doc.rust-lang.org/std/sync/mpsc/ and
  https://doc.rust-lang.org/std/thread/struct.Builder.html). The root supervisor owns this receiver boundary: no
  controlled child may exist before both protected sockets and their shared listener guard are live, no worker
  result may be detached, and process return may not destroy admitted irreversible administration work.

  Closure: protected listener construction is factored from serving. The Linux-only entry reports readiness on a
  capacity-one channel only after generic `_service`, raw `_service_password`, and `LocalIpcListenerGuard` setup all
  succeed. `start_os_service` creates the named worker with fallible `Builder::spawn`, retains its handle, waits at
  most ten seconds for ready/error/disconnection before any desktop refresh or child selection, and treats a clean
  premature return, returned error, or panic as a service error. The signal handler first stops the loop and then
  cancels protected IPC admission; each live loop iteration observes premature worker completion. All loop errors
  are captured instead of escaping through `?`. Normal and error results converge on cancellation and exact worker
  join, without a transaction-drain timeout, before either the active-user or root child is terminated. This keeps
  the commit target alive for any admitted password transaction, preserves the first process error, still attempts
  both child cleanups, and reports secondary cleanup failures rather than discarding them. macOS's synchronous
  listener entry and Windows SCM-owned endpoint supervisors are unchanged.

  Proof/gates: focused pure regressions cover ready, setup-error, timeout, disconnected-sender, expected
  clean join, unexpected clean return, returned error, and panic classification. The R-S11e-54 source gate binds
  listener/guard-before-ready order, fallible named thread creation, ready-before-child order, signal cancellation,
  retained liveness observation, captured loop result, join-before-child termination, R-S11an, Appendix C #162, and
  this ledger while rejecting the detached `allow_err!` form. The semantic verifier independently interprets those
  regions and mutation-tests every load-bearing edge. Native installed-service stop/setup-failure injection and
  exact-commit artifact/reproducibility evidence remain R-R2/R-B2 and are not inferred from focused Linux tests.

  Verification: the focused locked/offline Rust 1.75 root-library run passed both R-S11e-54 regressions (`2 passed`,
  318 filtered) after compiling the real Linux source against the audited vendored tree. The exact extracted
  R-S11e-54 source gate passed. Normal semantic workspace verification and the complete source-mutation suite pass;
  the matrix rejects missing/early readiness, missing setup error/timeout/disconnection failures, either listener or
  guard removal, detached/generic thread startup, missing signal cancellation or liveness observation, uncaptured
  loop errors, both missing join sites, accepted unexpected clean/error/panic outcomes, test/gate removal, and
  normative/Appendix/ledger drift. Bash syntax, in-memory Python syntax, requirements-digest synchronization, and
  `git diff --check` pass. The native-codec watch and mutation self-test pass, as do dependency inventory and all 103
  inventory mutations (909 Cargo packages; 855 lexical `unsafe {` blocks across 251 tracked Rust files). The pinned
  image contains no `rustfmt`, so no formatter result is claimed; the successfully compiled Rust diff was reviewed
  manually against surrounding style.

  Failure accounting and execution boundary: one initial output tmpfs was root-owned mode 0755 and correctly refused
  UID 1000 before Cargo started; it is not evidence. The first real compile caught that the child terminator's typed
  success value needed an explicit local `.map(|_| ())` before cleanup-error merging; the correction is included and
  the clean rerun passes. Semantic verification caught one old generic-listener call assumption and three mutation
  fixture diagnostic/uniqueness issues; each was narrowed to the new authority edge without weakening production
  assertions, and the complete final matrix passes. Every project build/test/verifier command ran as numeric uid/gid
  1000 in the exact pinned `rd-devcheck` image with no network, read-only source/root/toolchain/vendor inputs, all
  capabilities dropped, `no-new-privileges`, bounded resources, disposable output, and no published ports. No host
  RustDesk process/service/configuration, listener, firewall, or network namespace was inspected or changed. Native
  installed-service setup/stop/failure injection, exact-commit artifact/reproducibility evidence, the wider open
  release ledger, and external audit remain pending; this source closure does not claim them.
- **R-S11e-55 — macOS LaunchDaemon protected IPC signal drain — SOURCE, SHARED/APPLE SOURCE GATES, SEMANTIC,
  AND MUTATION VERIFIED; NATIVE INSTALLED/ARTIFACT EVIDENCE PENDING 2026-07-19.** Platform: macOS
  root LaunchDaemon, through both the dedicated PrivilegedHelperTools service executable and the common app
  binary's exact `--service` entry. Endpoints: generic protected `_service` and raw `_service_password`. Boundary:
  launchd termination ↔ the receiver-owned admission close, accepted-work drain, password-mutation finality, and
  truthful ordinary service stop.

  Proven old path and history: both root-service entries centralize through `platform::macos::run_service`, which
  proves effective UID 0, selects the protected root configuration/log namespace, and synchronously calls
  `ipc::start(POSTFIX_SERVICE)`. The service-owned controlled-side `--server` process separately installs Tokio
  SIGTERM/SIGINT handling, but the root daemon installed no signal handler anywhere before entering its protected
  listener. The IPC future already observes the process cancellation token, closes admission, begins password-ledger
  shutdown, joins every accepted generic/password transaction, drains and clears the macOS no-eviction mutation
  ledger, drops its listener guard, and returns. With the inherited default SIGTERM disposition, launchd could
  terminate the complete root process before that existing drain became reachable. `git blame` traces the
  signal-less listener entry to the original service path; the later root-principal/config-root changes preserved
  it but did not create this defect. This is deterministic privileged-operation finality and service-stop
  correctness, not a peer-authorization bypass, remote signal primitive, or evidence of host compromise.

  Primary contracts and authority model: Apple's launchd job guide says system shutdown sends SIGTERM to every
  daemon launchd started and explicitly directs daemons to install a SIGTERM handler before their service loop
  (https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).
  Apple's daemon lifecycle guide says shutdown later escalates to SIGKILL
  (https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Lifecycle.html).
  POSIX gives SIGTERM a process-termination default disposition. The correct owner split is therefore one fallible
  pre-listener signal registration whose callback performs only the thread-safe process cancellation request; the
  already-owned async listener remains the sole transaction and credential-drain implementation.

  Closure: `install_macos_service_shutdown_handler` uses the existing `ctrlc` dependency with its already-pinned
  `termination` feature and maps registration failure into a service error. `start_os_service` still rejects a
  nonzero effective UID first, then installs the handler before opening either protected listener. Its callback
  contains only `request_graceful_shutdown`: it does not block on or create a runtime, join, sleep, log, exit, run a
  second finalizer, or set R-S11am's fatal-listener-loss latch. The synchronous listener observes cancellation and
  follows its existing complete drain before returning normally. Both service entrypoints retain their centralized
  `run_service` failure propagation; the separate LaunchAgent server, Linux supervisor, and Windows SCM paths are
  unchanged.

  Proof/gates and verification: the exact extracted shared and Apple source gates pass. They bind the termination
  feature, sole macOS registration, exact cancellation-only callback, root-before-handler-before-listener order,
  both entrypoints' convergence, and preservation of cancellation-before-transaction-join-before-password-ledger-
  drain/clear-before-listener-guard-drop. R-S11ao, Appendix C #163, and this ledger bind the normative closure. The
  normal semantic workspace verifier and complete independently invoked source-mutation matrix pass. Mutations
  reject removal of either gate, termination-feature removal, missing/renamed registration, fatal-latch substitution,
  callback logging or added work, swallowed registration failure, handler-before-root or listener-before-handler
  order, missing/reordered mutation drain, and requirement/Appendix/ledger drift. The existing R-S11e-47/R-S11e-52
  mutations independently retain both service-entry convergence and error propagation.

  Bash syntax, in-memory Python compilation, exact requirements-digest synchronization, and `git diff --check`
  pass. Native-codec normal/self-test and dependency inventory plus all 103 inventory mutations pass unchanged:
  909 Cargo packages and 855 lexical `unsafe {` blocks across 251 tracked Rust files. The already-present immutable
  Apple-check image contains no `rustfmt`, so no formatter/SDK-free Rust parse result is claimed. A direct offline
  Apple-target Cargo attempt remained non-evidence: it compiled dependencies only until UID 1000 correctly received
  `EACCES` on a root-owned cached `pin-utils` source before the RustDesk crate was reached. No ownership, mode,
  capability, image, or cache authority was changed to bypass that refusal. Native macOS launchd stop/upgrade
  behavior, compilation, signed installed-helper execution, and exact-commit artifact/reproducibility proof remain
  R-R2/R-B2 and are not inferred from Linux source inspection.

  Failure accounting and execution boundary: the first mutation run found the older R-S11e-47 root-before-log
  fixture's immediate adjacency had been intentionally split by the new mandatory handler; its target now preserves
  root-before-observable-work while including the intervening handler. A later mutation name retained the checked
  `ctrlc::set_handler` text as a substring, and two new entrypoint mutations duplicated earlier, more-specific
  validators; the mutation was made genuinely token-removing and the redundant twins were deleted without weakening
  production validation. The final complete matrix passes. A final combined rerun completed both semantic passes,
  then its digest-only shell tail failed because the outer shell expanded an `awk` `$1` under `set -u`; the simpler
  independent digest assertion passed, and no project assertion failed. Every project verifier/check command ran as
  numeric UID/GID 1000 in an existing digest-addressed image with networking disabled, source/root/toolchain/
  dependency inputs read-only, all capabilities dropped, `no-new-privileges`, bounded resources, disposable output,
  and no published ports. No image was built or pulled, and no Docker socket, host PID namespace, or host network
  namespace was exposed inside a container. No host RustDesk service/process/configuration/listener, firewall, or
  network policy was inspected or changed.
- **R-S11e-56 — desktop controlled-server signal/listener lifecycle ownership — SOURCE, SHARED/APPLE
  SOURCE GATES, SEMANTIC, AND MUTATION VERIFIED; NATIVE COMPILE/INSTALLED/ARTIFACT EVIDENCE PENDING
  2026-07-19.** Platforms: Linux service-owned child, macOS LaunchAgent controlled-side server, and Windows
  service-owned child, through their shared exact desktop `--server` entry. Endpoint/action: process termination,
  main/service-control IPC admission, the sole public direct TCP listener, and authenticated-session/local-IPC
  drain. Boundary: OS/service-supervisor lifecycle authority ↔ truthful controlled-service liveness and finality.

  Proven old path and history: desktop `server::start_server(true)` started main IPC and, on Windows, the
  service-main control/credential IPC thread before calling `direct_service::start_direct_only(None)`.
  `start_direct_only` then spawned `direct_server` and discarded its Tokio `JoinHandle`, spawned and discarded a
  separate signal task only after the public listener could begin binding, and parked the parent future forever.
  Unix SIGTERM/SIGINT construction failure was logged inside that detached task and returned only from the task.
  A clean return or unwind of `direct_server` was likewise unobserved, leaving main IPC and the process alive while
  the only public service had disappeared. `git blame` traces the detached listener/park to the direct-only lift and
  the detached signal task to the original R-T9 implementation; later Android generation and direct-IP hardening
  preserved the desktop topology but did not create it. This is deterministic service availability/recovery and
  admitted-session stop correctness, not a PAKE/authentication bypass, remote task-termination primitive, or
  evidence of host compromise.

  Primary contract and authority model: Tokio 1.44.2 documents `JoinHandle` as the owned permission to observe task
  completion and says dropping it detaches the task; awaiting it proves the spawned task's destructor has completed,
  while `&mut JoinHandle` is cancellation-safe in `select!`
  (https://docs.rs/tokio/1.44.2/tokio/task/struct.JoinHandle.html). Its Unix `signal` constructor is synchronously
  fallible and Tokio warns that the installed process disposition is never restored, even after every corresponding
  stream is dropped (https://docs.rs/tokio/1.44.2/tokio/signal/unix/fn.signal.html). The Windows-specific Ctrl-C
  constructor is likewise synchronously fallible and returns an owned stream
  (https://docs.rs/tokio/1.44.2/tokio/signal/windows/fn.ctrl_c.html). The correct local API therefore creates one
  platform signal owner before any controlled IPC/public-listener admission and transfers it into one async owner
  that retains the exact direct-listener task. Signals and authenticated service-control cancellation request the
  existing process token; the retained listener is joined before the existing sole session/IPC finalizer. Failure
  does not create another runtime, watchdog, timer, second drain, or compatibility fallback.

  Source closure: desktop `server::start_server(true)` now calls the cfg-specific fallible
  `install_controlled_server_shutdown_signals` before setting the server-running flag or starting Windows
  service-main IPC, ordinary main IPC, or the public listener. Unix owns exact SIGTERM and SIGINT Tokio streams;
  Windows owns the Windows-specific Ctrl-C stream, while normal SCM child shutdown remains the independently
  authenticated service-main `Shutdown` request. Any constructor error exits status 1 before admission.
  `start_direct_only`'s desktop parameter is now the already-installed signal owner rather than an irrelevant
  optional Android generation. It retains the sole `direct_server` `JoinHandle` and transfers it to
  `own_controlled_server_lifecycle`, whose one biased select observes process cancellation, signal receipt/stream
  loss, or task completion. A normal signal requests cancellation. Every normal path awaits the exact listener so
  its `ListenerBoundGuard`, socket, and future locals are destroyed before `finish_graceful_shutdown` drains
  authenticated sessions and local IPC. Signal-stream loss, listener clean return without cancellation, task
  cancellation, or unwind uses R-S11am's release/acquire failure latch before the same finalizer, producing status 1.
  The detached desktop signal task and unconditional desktop parking loop are deleted. Android still receives its
  captured foreground-service generation, retains the existing generation checks/runtime-unwind teardown, and never
  consumes the desktop signal owner or process-global cancellation token; iOS remains on the mobile signature.

  Evidence boundary and execution accounting: R-S11ap and Appendix C #164 bind this closure. The exact shared gate
  `(3b-iii-d9cf)` and Apple gate `(2b-iv-a-0e)` passed independently after whole-script `bash -n`; the semantic
  verifier passed both its positive source-contract run and the complete source-mutation matrix. Those checks bind
  pre-IPC registration, fallible Unix/Windows constructors, parameter transfer, cancellation/signal/listener
  selection, exact task join, fatal classification, listener-before-finalizer order, detached-task/desktop-park
  absence, and preserved Android generation ownership. The requirements digest and native-codec watch were updated
  and the offline native-codec source gate passed. Native init/launchd/SCM stop/failure injection and exact-commit
  artifacts remain R-R2/R-B2 and are not inferred from Linux source inspection. The pinned Rust 1.75 image has no
  rustfmt component, so no formatter result is claimed. Three isolated offline compile setups reached dependency
  compilation only and then UID 1000 correctly received `EACCES` on the existing root-owned cached `pin-utils`
  source before RustDesk was reached; the second and third attempts used readable target seeds but Cargo invalidated
  their fingerprints under the isolated logical inputs and still required that source. No cache ownership/mode,
  image, capability, or root authority was changed to bypass the refusal. All attempts used networking disabled,
  read-only source/toolchain/dependency/seed inputs, dropped capabilities, `no-new-privileges`, bounded resources,
  disposable tmpfs output, and no published ports; every container and output tmpfs has been removed. No host
  RustDesk service/process/configuration/listener, firewall, or network policy was inspected or changed.
- **R-S11e-57 — non-returning graceful-shutdown finalizer ownership — SOURCE, SHARED/APPLE SOURCE GATES,
  SEMANTIC, AND MUTATION VERIFIED; NATIVE SUPERVISOR/ARTIFACT EVIDENCE PENDING 2026-07-19.** Platforms: the Linux
  service-owned child, macOS LaunchAgent controlled server, and Windows service-owned child. Endpoint/action:
  transfer from the three controlled-server shutdown callers into the one shared
  authenticated-session/local-IPC/input drain and process-exit edge. Boundary: detached IPC runtime lifetime ↔
  main server runtime/process lifetime and truthful shutdown completion.

  Proven regression and responsibility: the inherited R-T9 finalizer used
  `SHUTDOWN_FINALIZER_STARTED.swap(...); return` to make duplicate calls look idempotent. That return was safe only
  while the old desktop parent parked forever and a detached signal/IPC thread necessarily owned process exit.
  R-S11e-56 commit `80f2f1d6f18aebb58e5595ed2e0ce177d50a39cc` correctly replaced that detached topology with a
  retained main-runtime listener/signal owner, but its new final `finish_graceful_shutdown().await` call composed
  with the older returning API. If main IPC, protected `_service` IPC, or Windows service-main IPC won the atomic,
  the Linux/Windows main server runtime could lose, return through `start_direct_only` and `start_server`, and let
  Rust `main` terminate the process while that detached IPC thread was still draining. The older return came from
  the original R-T9 work; the unsafe composition and resulting regression were introduced by R-S11e-56. This is a
  deterministic shutdown-finality/service-recovery defect, not a PAKE/authentication bypass, local privilege
  escalation, remote task-kill primitive, or evidence of host compromise.

  Primary contract and authority model: Rust's native-thread documentation states that when the main thread
  terminates the entire program shuts down even if other threads remain live
  (https://doc.rust-lang.org/stable/std/thread/index.html), and `std::process::exit` is explicitly non-returning and
  does not run other thread-stack destructors (https://doc.rust-lang.org/std/process/fn.exit.html). The shared
  finalizer therefore has one terminal owner, not an idempotent returning operation. Its atomic claim elects one
  caller to perform the existing bounded authenticated-session drain, wait for every local IPC listener guard,
  repair input state, acquire the monotonic fatal latch, and exit with the selected status. A losing caller has no
  completion value to receive because successful completion is process termination; it must remain alive on a
  non-polling pending future until the winner exits, without a second drain, second status decision, fallback, or
  timeout. This wait is deadlock-free only because each caller releases all authority the winner awaits before the
  call.

  Source closure: crate-private `finish_graceful_shutdown` now returns `!`. The sole atomic winner follows the unchanged drain and
  `process::exit`; every loser awaits `pending::<Infallible>()` and cannot return a runtime or main thread. The
  unused returning `begin_graceful_shutdown` entry is deleted rather than retained as a compatibility alias. The
  caller set is exact: the desktop direct owner invokes it only after direct-listener completion or exact task join;
  main IPC invokes it only after admitted transactions, the password-mutation ledger, and its listener guard drain;
  Windows service-main IPC invokes it after its bounded transaction drain and guard drop. Protected Linux/macOS
  service IPC returns its post-drain outcome to the foreground lifecycle owner under R-S11e-58. Followers therefore
  retain no listener guard or task handle needed by a winning finalizer's local-IPC barrier. R-S11am's
  release/acquire failure latch and status selection remain unchanged and winner-owned.

  Evidence boundary and execution accounting: R-S11aq and Appendix C #165 bind this correction. Shared gate
  `(3b-iii-d9cg)`, Apple gate `(2b-iv-a-0f)`, the independent semantic validator, and its mutation matrix bind the
  non-returning signature, one-owner/follower-pending order, obsolete-entry absence, exact three-caller set, all
  pre-call join/guard-release edges, and the existing drain/latch/exit order. The exact follower expression was
  separately type-checked by pinned `rustc 1.75.0`. Whole-script shell syntax, the exact extracted shared and Apple
  gates, semantic positive validation, the complete source-mutation matrix, requirements-digest synchronization,
  native-codec watch, and `git diff --check` passed in the recorded isolated verification run. No application binary,
  host service, or listener was executed. Native init/launchd/SCM execution and exact-commit artifacts remain
  R-R2/R-B2 and are not inferred from source checks. Every executable check used an existing image as numeric
  UID/GID 1000 with networking disabled, read-only source/toolchain/dependency inputs, all capabilities dropped,
  `no-new-privileges`, bounded resources, disposable outputs, and no published ports; no image was built or pulled.
  No host RustDesk service/process/configuration/listener, firewall, or network policy was inspected or changed.
- **R-S11e-58 — protected Unix service IPC foreground lifecycle ownership — SOURCE, PINNED RUST POLICY TYPECHECK,
  SHARED/APPLE SOURCE GATES, SEMANTIC, AND MUTATION VERIFIED; NATIVE SUPERVISOR/ARTIFACT EVIDENCE PENDING
  2026-07-19.** Platforms: Linux root service supervisor and both macOS root LaunchDaemon entries. Endpoints:
  protected generic `_service` and raw `_service_password`. Boundary: receiver-owned socket/transaction drain ↔
  foreground-owner process outcome and exact subordinate cleanup.

  Proven composition defect and history: R-S11e-54 made Linux `start_os_service` retain the named protected-IPC
  worker, wait for both listeners and their process-lifetime guard, observe premature completion, classify a returned
  error or panic, cancel and join the exact worker, and only then terminate its active-user and root controlled
  children. The shared Linux/macOS `run_service_ipc` nevertheless still called the non-returning process finalizer
  after an unexpected listener end. On Linux, that call ran inside the retained worker, so its `JoinHandle` never
  returned and the supervisor's recorded join/error/child-cleanup path could not execute. On macOS, the same call
  bypassed the synchronous `start_os_service`/`run_service` result path used by both supported service entries.
  `git blame` traces the protected receiver's finalizer call to R-S11e-53 listener-outcome hardening and the retained
  Linux ownership to R-S11e-54; their composition was inconsistent and R-S11e-57 then preserved the worker as one
  of four finalizer callers. This is deterministic cleanup, service-recovery, and lifecycle-authority correctness,
  not an IPC authorization bypass, local privilege escalation, remote listener-loss primitive, or evidence of host
  compromise.

  Authority model and source closure: the protected receiver owns only listener admission, admitted transaction
  join, platform password-ledger drain/clear, and `LocalIpcListenerGuard` release. After those releases it now passes
  `listener_error` through `protected_service_ipc_result`: ordinary signal cancellation returns `Ok(())`, while an
  unexpected generic/password listener end returns the exact recorded error. The worker contains no finalizer,
  process exit, new runtime, detached task/thread, timeout, or fallback. Linux receives that `Err` through its
  already-retained native thread join, preserves it as the service result, and still attempts termination of both
  exact controlled children. macOS returns the same error through the synchronous service entry; the common exact
  `--service` receiver and dedicated PrivilegedHelperTools executable already convert `run_service` failure to
  non-success. At this slice's closure the non-returning process finalizer had the truthful complete three-caller
  set: main IPC, Windows service-main IPC, and the retained direct-listener owner. R-S11as/R-S11e-59 subsequently
  made both desktop IPC loops result-returning and replaced that set with one post-join desktop-owner caller.

  Proof and execution boundary: the focused R-S11e-58 regression source binds normal success and exact error
  preservation, while a standalone pinned Rust 1.75 policy typecheck executes the same owned-`String`
  success/error classification without launching RustDesk.
  Shared gate `(3b-iii-d9ch)`, Apple gate `(2b-iv-a-0g)`, the independent semantic validator, and its mutation matrix
  bind classifier polarity, complete drain/guard-before-return order, worker terminal-authority absence, Linux
  returned-error classification and join-before-child cleanup, both macOS result-propagating entries, the
  then-current three finalizer callers (superseded by R-S11as), R-S11ar, Appendix C #166, and this ledger.
  Verification used the existing pinned development
  image as numeric UID/GID 1000 with networking disabled, read-only source/root/toolchain/dependency inputs, all
  capabilities dropped, `no-new-privileges`, bounded resources, disposable output, and no published ports; no image
  was built or pulled. The pinned policy typecheck, exact shared/Apple gates, semantic positive and complete
  mutation runs, shell and Python syntax, requirements-digest synchronization, native-codec watch, dependency
  inventory, and
  `git diff --check` passed. No application binary, service, socket, public listener, host RustDesk state, firewall,
  or network policy was executed, inspected, or changed. The application-level focused Cargo test was attempted in
  a fresh UID-1000 tmpfs target but could not read the pre-existing root-owned
  `pin-utils-0.1.0/src/lib.rs` cache entry; an earlier attempt also correctly refused the pre-existing target
  volume's unwritable `.cargo-lock`. Neither ownership/mode nor privilege was changed to bypass those refusals, and
  neither attempt is counted as passing evidence. Native init/launchd listener-failure injection,
  exact-commit artifact/reproducibility evidence, and external audit remain R-R2/R-B2/R-V3 work and are not claimed.
- **R-S11e-59 — desktop local-IPC readiness and retained native-worker ownership — SOURCE, PINNED LINUX
  MAIN-CRATE COMPILE, SHARED/APPLE SOURCE GATES, SEMANTIC MUTATIONS, AND SYNCHRONIZATION VERIFIED;
  NATIVE SUPERVISOR/ARTIFACT EVIDENCE PENDING 2026-07-19.** Platforms: Linux service-owned child, macOS
  LaunchAgent controlled server, and Windows
  service-owned child through the shared desktop `start_server(true)` entry. Endpoints: ordinary main IPC plus
  its permanent-password receiver, Windows service-main credential/control IPC, the sole public direct listener,
  and the process finalizer. Boundary: mandatory startup-policy proof and required local-control readiness ↔
  public-service admission, native runtime lifetime, and truthful process completion.

  Proven old path and responsibility: desktop `server::start_server(true)` used infallible free
  `std::thread::spawn` twice: ordinary `ipc::start("")` always ran on one detached current-thread Tokio runtime,
  and the exact Windows service-owned role ran `start_windows_service_main_ipc` on a second detached runtime.
  Neither thread reported listener readiness or retained a `JoinHandle`; both began before
  `direct_service::assert_startup_invariants`, because that mandatory R-A4 check lived inside the later
  `start_direct_only` call. Both IPC loops could call the process finalizer independently after listener loss.
  R-S11e-56 retained signals and the public task, R-S11e-57 kept losing finalizer callers alive, and R-S11e-58
  returned protected Unix service IPC to its foreground owner, but none transferred ordinary desktop IPC
  readiness/completion/thread authority to the retained public-service owner. `git blame` traces the ordinary
  detached spawn to the inherited desktop start path (`c2abd3b3`) and the separate Windows spawn/runtime to the
  service-main introduction (`57bcb529`); the recent retained-owner work exposed rather than created this gap.
  This was deterministic pre-invariant local admission, service-health, and cleanup correctness. The local
  listeners retained their separate receiver authorization, so this is not evidence of an IPC authorization
  bypass, local privilege escalation, remote trigger, or host compromise.

  Authority model and source closure: desktop `start_server` now calls the result-returning R-A4 assertion before
  signals or any local/public listener. After fallible signal registration, `start_direct_only` fallibly creates
  one named `rustdesk-desktop-ipc` worker with `thread::Builder`; only that new native thread constructs the single
  current-thread Tokio runtime, so no runtime is nested. It prepares ordinary main/password IPC and, for the exact
  Windows service-owned role, credential/control IPC on that same runtime. A Tokio one-shot reports success only
  after every required listener and `LocalIpcListenerGuard` is active; setup error, sender loss, worker completion,
  or signal/cancellation during startup is observed before a public listener can start. On Windows the two run
  futures share that one runtime with `tokio::join!`; either listener failure latches cancellation and both drains
  complete before the worker returns its outcome.

  The existing async controlled-server owner now selects cancellation, its already-installed signal streams,
  exact public-task completion, and exact IPC-worker completion. It treats unexpected return/error/panic as fatal,
  joins the public task, receives the IPC result, and transfers the native `JoinHandle` into `spawn_blocking` for an
  exact join before the sole `finish_graceful_shutdown` call. Main and Windows service-main IPC return only after
  admitted transaction/password drain and guard release; they contain no finalizer or process exit. The obsolete
  detached server spawns, independent Windows runtime entry, unused optimistic `SERVER_RUNNING` flag/accessors,
  atomic multi-finalizer election/follower pending path, and polling local-IPC barrier are deleted. Protected Unix
  service IPC keeps its R-S11ar foreground owner. Android still checks R-A4 in the shared mobile process and keeps
  foreground-service generation teardown; iOS remains mobile-process-owned.

  Proof and execution boundary: R-S11as and Appendix C #167 bind this closure. A real pinned Rust 1.75
  `cargo check --offline --locked --lib --features linux-pkg-config` passed for the main crate in the existing
  `rd-devcheck` image. To preserve UID-1000/no-root execution despite the pre-existing root-owned unreadable
  extracted `pin-utils` file, the check copied only the readable immutable registry archives/index and git cache
  into disposable UID-1000 tmpfs; Cargo freshly extracted dependencies there. Source, toolchain, and dependency
  inputs were read-only; networking was disabled; all capabilities were dropped; `no-new-privileges`, bounded
  memory/CPU/PIDs, a read-only container root, disposable tmpfs output, and no published ports were used. No image
  was built or pulled, no application binary/listener/service was run, and no host RustDesk process/configuration,
  firewall, or network state was inspected or changed. The focused validator passed its positive run and all 23
  deliberate source/normative mutations. The repository-wide semantic verifier passed its positive run and its
  complete in-memory source-mutation inventory, including the new R-S11e-59 mutations. Bash/Python syntax, the
  shared and Apple gate bindings, synchronized requirements SHA-256
  `8b7fb24f98ba3fb2d92da7aac02f7aeb2b862706ee4f28057d1facb958889695`, native-codec watch normal/self-test,
  and dependency inventory normal plus all 103 mutations passed (909 Cargo packages; 855 lexical `unsafe {`
  blocks across 251 tracked Rust files). Final diff hygiene passed. The repository-wide executable fixture self-test
  was attempted only in an isolated no-network container; its managed-scope fixtures require the real current-user
  systemd D-Bus. A fake
  container-local socket was correctly rejected, and the host user bus was deliberately not mounted, so that
  executable fixture is unavailable and is not claimed. Native init/launchd/SCM failure injection and exact
  artifacts remain R-R2/R-B2; external expert audit remains R-V3.
- **R-S11e-60 — Linux protected-service admission owns active-session identity work — SOURCE, PINNED LINUX
  MAIN-CRATE COMPILE, FOCUSED/REPOSITORY SEMANTIC MUTATIONS, AND SYNCHRONIZATION VERIFIED;
  NATIVE INSTALLED-SERVICE/ARTIFACT EVIDENCE PENDING 2026-07-19.** Platform: installed Linux root supervisor.
  Endpoints: world-connectable generic `_service` and raw `_service_password` Unix sockets. Boundary: arbitrary
  local socket admission ↔ root active-session/executable identity work and the fixed protected-transaction budgets.

  Proven old path and responsibility: after accepting either socket, `run_service_ipc` called the Linux
  service-scoped authorization snapshot before `try_acquire_service_ipc_transaction_slot` or
  `try_acquire_service_password_ipc_transaction_slot`. The snapshot resolved kernel peer credentials and then
  unconditionally called `active_uid_fresh`; on Linux that bypasses the service-loop cache and synchronously runs
  the fixed `loginctl`/login1 lookup as root. Only afterward did the branch acquire its four-slot semaphore and
  perform the executable/action-specific proof. Because the sockets deliberately admit local connection attempts,
  an arbitrary local principal could repeatedly induce root subprocess/D-Bus identity work outside either budget.
  `git blame` traces both orderings to the privileged-IPC hardening introduction (`57bcb529`), so this slice closes
  an availability edge in that implementation rather than an inherited host/runtime change. This was a concrete
  local resource-exhaustion/service-availability defect, not an authorization bypass, privilege escalation, remote
  trigger, public network listener, host compromise, or evidence that any service was altered outside this source
  tree.

  Authority model and source closure: each branch now acquires its existing fixed transaction permit immediately
  after accept (and generic connection wrapping) and before active-session or executable-identity work. The exact
  permit is transferred into the tracked transaction and remains held through authorization/dispatch; saturation
  rejects before identity work. UID 0 skips the irrelevant active-session lookup. For non-root peers, the root
  supervisor's already-maintained active-UID cache is exposed through a cached-only accessor with no live fallback.
  A missing or nonmatching cache rejects without `loginctl`. A match is negative-prefilter passage only and still
  invokes the existing fresh lookup as the final authority: stale just-switched-out users fail the fresh comparison,
  while just-switched-in users can only fail closed until the service loop refreshes the cache. The unused alternate
  `ConnectionTmpl::service_authorization_status` fresh-lookup path is deleted. macOS retains its independent
  console-owner/audit-token/code-signature plus authorization- and transaction-permit model unchanged.

  Proof and execution boundary: R-S11at and Appendix C #168 bind the receiver model. The focused Rust regression
  executes root, matching, nonmatching, missing-peer, and missing-cache prefilter cases. The standalone semantic
  validator binds both permit-before-authorization orders, cached-only access, root short-circuit, fresh final
  authority, exact permit transfer/lifetime, stale-path deletion, normative/ledger/gate synchronization, and rejects
  all 15 deliberate mutations. The repository-wide verifier independently owns the same source/normative contract
  and mutation anchors. A pinned Rust 1.75 offline main-crate check and the focused test passed under the existing
  constrained UID-1000 container policy; no application binary, listener, service, socket, host RustDesk state,
  firewall, or host network state was executed, inspected, or changed. Native installed-service contention,
  exact-commit artifact/reproducibility evidence, and external expert audit remain R-R2/R-B2/R-V3 and are not
  claimed.
- **R-S11e-61 — macOS privileged helper current-build binding — SOURCE IMPLEMENTED; NATIVE SIGNED-UPGRADE AND
  ARTIFACT EVIDENCE REMAIN R-R2/R-B2.** Platform: macOS source-conformance and any future signed macOS artifact.
  Surfaces: `src/platform/macos.rs`, `src/platform/privileges_scripts/install.scpt`, `src/ipc/auth.rs`, and the
  protected `_service`/raw password endpoints that rely on helper identity. Boundary: currently installed signed
  app build ↔ root LaunchDaemon helper selection and runtime IPC authority. Proven gap: the earlier exact-copy
  closure replaced the deployed helper whenever the installer ran, but `is_installed_daemon` returned true from
  the two plist files alone. An app replacement could therefore leave the prior same-Team helper running without
  offering reinstall. Installer input and runtime helper admission proved Team ID/identifier, path, ownership, and
  mode, but did not require the deployed bytes to equal the helper nested in the currently installed app. This was
  a privileged-component provenance/version-coherence defect with potential downgrade to defects in an older
  correctly signed helper, not evidence that a downgrade, privilege escalation, compromise, host service change,
  public listener, or network exposure occurred.

  Authority model and source closure: `/Applications/<App>.app` is the current build authority. Rust service
  installation now resolves `Contents/MacOS/service` only beside the fixed installed app executable and rejects a
  symlink or non-file source. The admin AppleScript rejects any helper argument other than that exact fixed path;
  requires the app and helper source to be root-owned and non-group/world-writable; validates the pinned outer app
  requirement with `--deep --strict --all-architectures`; validates every helper copy with the pinned helper
  requirement across all architectures; and, immediately before launchd replacement/load, repeats the outer-app
  proof and byte-compares deployed helper to bundled helper. Runtime `SecStaticCode` validation adds
  `CHECK_ALL_ARCHITECTURES` and, for the app bundle, `CHECK_NESTED_CODE`. Every trusted deployed-helper path then
  requires the protected installed app plus a no-follow regular-file, length-first, fixed-64-KiB streaming byte
  equality proof against its sealed `Contents/MacOS/service`. This composes with the existing root/wheel/mode/ACL,
  designated-requirement, audit-token, installed-app peer, console-owner, and fixed transaction/Security-framework
  capacity checks rather than replacing them.

  Lifecycle correction: service state is current only when both plists exist and the deployed bytes match the
  current app. A stale helper returns false, so the existing UI offers its admin-authorized install transaction and
  that transaction replaces/reloads the helper; it is never silently treated as current. Uninstall admission checks
  for any managed plist, deployed helper, or install-temp entry through no-follow metadata, so mismatch or partial
  installation cannot make cleanup unreachable. The focused Rust truth-table regression pins the status
  conjunction. `scripts/verify-macos-helper-build-binding.py` independently binds static-signature flags, bounded
  byte comparison, runtime trust composition, fixed installer input, pre-load revalidation, stale-state reinstall,
  partial-state uninstall, normative/ledger/source-gate synchronization, and rejects all 26 deliberate mutations.
  Shared and Apple source gates invoke the validator and its self-test. R-S11au and Appendix C #169 make the model
  normative. Apple's [Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
  documents `Contents/MacOS` helpers as nested code sealed into the outer resource envelope and requires recursive
  verification to validate nested code; its [static code validation flags](https://developer.apple.com/documentation/security/static-code-validation-flags)
  separately document all-architecture validation. Native signed app replacement, admin reinstall/relaunch,
  universal-binary rejection injection, and exact-commit artifact proof remain R-R2/R-B2. External expert audit
  remains R-V3.
- **R-S11e-62 — macOS variadic file-creation ABI — SOURCE IMPLEMENTED; SDK-BACKED NATIVE AND ARTIFACT
  EVIDENCE REMAIN R-R2/R-B2.** Platform: macOS source-conformance and Apple-target Rust compilation. Surfaces:
  `libs/hbb_common/src/config.rs`, `libs/hbb_common/src/fs.rs`, `src/ipc/fs.rs`, and the macOS clipboard
  paste/placeholder sources.
  Boundary: Rust's typed Darwin `mode_t` ↔ the C variadic `open`/`openat` ABI. Proven gap: Darwin's pinned libc
  exposes `mode_t` as `u16`, while Apple declares `open`/`openat` with an ellipsis. Three creation calls passed that
  narrow type directly and the pinned Apple-target compiler rejected them with E0617 before the hardened config and
  clipboard paths could be compiled. This was deterministic Apple build/ABI correctness and unreachable hardening,
  not evidence of runtime privilege escalation, public exposure, corrupted files, host changes, or compromise.

  Source closure: only the three variadic creation-mode arguments are explicitly promoted to `libc::c_uint`, as
  Rust's E0617 diagnostic requires and as the pre-existing portable file-transfer helper already did. The numeric
  modes, `O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW` protections, descriptor type checks, atomic config replacement, and
  clipboard cleanup are unchanged. Fixed-prototype `mkdir`, `mkdirat`, and `fchmod` calls deliberately retain
  `mode_t`; the correction is not a blanket type substitution. The already-correct promoted `i32` PID-file literal
  remains unchanged. `scripts/verify-macos-variadic-open-mode.py` binds the three corrected calls, both correct call
  shapes, the fixed-prototype distinction, requirements/ledger, and both source gates, and rejects 13 deliberate
  mutations. R-S11av and Appendix C #170 make the model normative.
  The pinned SDK-free Apple compiler cross-check establishes Rust ABI/source coherence only. SDK-backed execution,
  clipboard/config behavior, signed binaries, and exact-commit artifact proof remain R-R2/R-B2; external expert
  review remains R-V3.
- **R-S11e-63 — complete Windows production-listener DACL coverage — SOURCE IMPLEMENTED; NATIVE WINDOWS AND
  ARTIFACT EVIDENCE REMAIN R-R2/R-B2.** Platform: Windows desktop named-pipe listeners. Surfaces:
  `src/ipc.rs::new_listener`, the listener-postfix policy in `src/ipc/auth.rs`, fixed `_cm`, and the token-derived
  whiteboard listener. Boundary: unrelated local Windows account ↔ application-level helper authentication.
  Proven gap: the main, password, service, credential/control/SAS, and URL listeners already supplied explicit SDDL,
  but `_cm` and `_whiteboard_<hmac>` fell through `SecurityAttributes::empty()`. The pinned IPC dependency maps that
  value to null `SECURITY_ATTRIBUTES`. Microsoft documents that the resulting default named-pipe descriptor grants
  read access to Everyone and Anonymous and that a read-only client may connect to a duplex pipe. Exact process and
  bidirectional launch-token checks still prevented helper authority use, but they run after pipe acceptance. An
  unrelated local account could therefore enter pre-authentication; on `_cm`, an exact current-image `--server`
  process could repeatedly occupy the inline one-second launch-proof wait. This was cross-user local availability,
  not an authentication bypass, credential disclosure, privilege escalation, remote authority, host change, or
  evidence of compromise.

  Source closure: one exhaustive Windows listener-postfix policy now includes exact `_cm` and accepts a whiteboard
  postfix only when it uses the shared `_whiteboard_` prefix followed by exactly 32 lowercase hexadecimal characters.
  Both use the existing protected logon/session-scoped SDDL. The listener constructor has no Windows default/null
  descriptor branch: an unrecognized or malformed postfix fails before endpoint creation. The DACL still denies
  Network, omits Everyone/Anonymous/Administrators, admits LocalSystem for the required service/helper topology, and
  gives the active-session principal only the narrow client mask without `FILE_CREATE_PIPE_INSTANCE`; system-only
  credential/control/SAS endpoints remain unchanged. `_cm` exact-role plus mutual-HMAC authentication and whiteboard
  exact-parent plus token-derived endpoint and mutual-HMAC authentication remain independent receiver checks.
  `scripts/verify-windows-ipc-dacl-coverage.py`, the focused Windows regression, the shared source gate, and their
  mutation matrices bind production call-site coverage, exact dynamic-postfix syntax, explicit-SDDL-only creation,
  unknown-postfix refusal, and preservation of the application authentication layers. R-S11aw and Appendix C #171
  make the model normative. Native Windows multi-session execution and exact signed-artifact proof remain R-R2/R-B2;
  external expert review remains R-V3.
- **R-S11e-64 — smoke container image, network, and dependency authority — SOURCE IMPLEMENTED; CONTAINER
  EXECUTION AND EXACT-ARTIFACT EVIDENCE REMAIN R-B2.** Platform: Linux Docker runtime-smoke harness. Surfaces:
  `scripts/smoke-server.sh`, its five Docker launch sites, and the sole Cargo build in
  `scripts/smoke-server-stage.sh`. Boundary: repository-controlled smoke execution ↔ Docker daemon image,
  network, host/peer, and dependency-resolution authority. Proven gap: `BUILD_RUN` and the ordinary `RUN` used
  Docker's implicit default bridge, which Docker documents as providing outbound connectivity and access to the
  host and peer containers. The lifecycle, PID-reuse, and sibling containers already selected `--network none`,
  but all five launches named the mutable `rd-devcheck` tag without `--pull=never`; Docker's default missing-image
  policy could therefore pull. The sole Cargo build was neither locked nor offline, and ordinary runtime stages
  needlessly mounted the mutable registry cache. The old harness contained no `-p`/`--publish`, its bind shim
  rewrote the tested `0.0.0.0:21118` bind to container `127.0.0.1:21118`, and Docker blocks unpublished ports from
  outside the host by default. This was excessive harness egress, peer/host reach, implicit image acquisition, and
  dependency-resolution authority—not public DMZ port exposure, a host RustDesk/service/config mutation, privilege
  escalation, or evidence of compromise.

  Source closure: before any launch the harness locally inspects the already-present tag once, validates the
  canonical `sha256:<64 lowercase hexadecimal>` image ID, marks it immutable, and uses only that ID. Build, ordinary
  runtime, lifecycle, PID-reuse, and sibling launches all specify `--network none` and `--pull=never`; no launch
  publishes a port, selects host network/PID or privileged mode, or mounts the Docker socket. Network-none retains
  container loopback, which is the only network required by the same-container protocol/capture tests. The build
  retains read-write source plus explicit registry and Git caches and invokes Cargo exactly once with
  `--locked --offline`; missing locked inputs now fail closed. Ordinary runtime loses its unused dependency cache,
  and all non-build stages retain read-only source. Existing lifecycle capabilities and root service semantics are
  unchanged because they are the behavior the release smoke must exercise. R-S11ax and Appendix C #172 make this
  authority model normative. The shared workspace semantic validator covers the complete launch inventory and has
  deliberate mutations for image-ID validation/use, every network/pull class, cache separation, Cargo offline/lock
  enforcement, requirement/ledger/gate presence, and the sibling. The focused shared source gate duplicates the
  fail-loud launch-policy checks. No container, application binary, host listener, host firewall, or host RustDesk
  service was executed or changed while closing this source slice. Exact runtime-smoke execution and release-artifact
  evidence remain R-B2; external expert review remains R-V3.
- **R-S11e-65 — Windows token-switched helper environment finality — SOURCE IMPLEMENTED; NATIVE WINDOWS AND
  EXACT-ARTIFACT EVIDENCE REMAIN R-R2/R-B2.** Platform: Windows installed-service active-session tray,
  connection-manager, and whiteboard launches. Surfaces: `run_user_helper` →
  `run_current_exe_in_current_session_with_env` → `launch_process_in_session_with_env` → native
  `LaunchProcessWin`. Boundary: LocalSystem service launcher environment ↔ target-user helper process.
  Proven gap: the `as_user=TRUE` path called `CreateEnvironmentBlock(..., TRUE)` and ignored its Boolean result.
  Microsoft defines that flag as inheritance from the current process, so a successful launch incorporated the
  LocalSystem caller environment. On failure, CM/whiteboard merged only their two proof variables into an empty
  block; tray passed null, for which `CreateProcessAsUserW` inherits the calling process environment and does not
  adjust it for the supplied token. This could disclose service-owned ambient configuration/secrets to a
  lower-authority process or select the wrong profile/config namespace. It did not change the retained user token,
  explicit executable, or current directory and is not evidence of a SYSTEM shell, exploitation, or compromise.

  Source closure: every `as_user` launch now calls `CreateEnvironmentBlock` exactly once with inheritance disabled.
  False construction preserves `GetLastError`, closes the token, and returns before merge, attribute construction,
  or process creation. A nominally successful null result closes the token and fails as `ERROR_INVALID_DATA` at the
  same boundary. Only the successfully constructed target-user block reaches the existing case-insensitive merge;
  CM/whiteboard launcher proof variables still replace same-name profile variables, and the exact Unicode block is
  passed to `CreateProcessAsUserW`. Null/caller/LocalSystem fallback is therefore absent for user helpers. The
  distinct `as_user=FALSE` service-owned child remains unchanged and receives only its explicit supervisor PID and
  creation-time variables. R-S11ay and Appendix C #173 make the authority model normative. The shared semantic
  validator binds the single construction site, failure/null finality, non-inheritance, merge/launch order, and
  requirement/ledger/gate presence; its deliberate mutations cover inherited construction, ignored/inverted status,
  lost error preservation, continued failure, null acceptance, launch-time environment replacement, and document
  removal. The focused source gate independently rejects inherited construction and missing finality markers. Native
  Windows multi-session execution and exact signed-artifact proof remain R-R2/R-B2; external expert review remains
  R-V3.
- **R-S11e-66 — macOS administrator-script environment finality — SOURCE IMPLEMENTED; NATIVE macOS AND
  EXACT-ARTIFACT EVIDENCE REMAIN R-R2/R-B2.** Platform: macOS desktop service install and uninstall. Surfaces:
  `run_service_install` and `uninstall_service` → embedded `install.scpt`/`uninstall.scpt` →
  `/usr/bin/osascript` → `do shell script ... with administrator privileges`. Boundary: unprivileged RustDesk
  launcher process context ↔ administrator-authorized shell and child utilities. Proven gap: both callers directly
  constructed `MACOS_OSASCRIPT` without clearing the launch environment or selecting a working directory. Apple's
  `do shell script` contract says `osascript` inherits its launcher environment/CWD and the shell inherits them from
  `osascript`; Apple's secure-coding guidance treats inherited environment variables as an input to privileged
  programs. Thus caller-controlled ambient variables and CWD crossed into the privileged execution context. The
  generated shell bodies already select absolute system executables and retained embedded script bytes, quoted
  arguments, fixed installed-app/helper destinations, strict outer-app/helper signature checks, deployed/bundled byte
  equality, non-stdio descriptor closure, checked status, launchd state validation, and file postconditions. This was
  an ambient privilege-boundary integrity defect, not a caller-selected executable/script, proof of a working root
  exploit, evidence of compromise, or reason to weaken those existing checks.

  Source closure: `macos_privileged_service_script_command` now owns the one and only
  `Command::new(MACOS_OSASCRIPT)` site. Its narrow policy clears the complete inherited environment before adding the
  exact replacement set `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `LANG=C`, and `LC_ALL=C`, and fixes the working
  directory at `/`. Both install and uninstall obtain their command from that constructor before attaching the
  embedded script or arguments; there is no selective-preservation or compatibility fallback. The generic checked
  command helper remains responsible for fail-closed non-stdio descriptor setup and status, while all script,
  provenance, launchd, and postcondition behavior remains unchanged. R-S11az and Appendix C #174 make the model
  normative. A native-only actual-child unit regression proves that the policy emits exactly those three environment
  entries and `/` CWD. The workspace semantic validator binds complete reset, exact values/order, sole-constructor
  inventory, both callers, focused shared/Apple gates, requirement, Appendix row, and ledger; deliberate mutations
  cover partial clearing, each replacement variable/value, CWD, constructor/caller topology, regression removal, and
  documentary bindings. Native administrator-dialog/service-lifecycle execution and exact signed-artifact evidence
  remain R-R2/R-B2; external expert review remains R-V3.

  Verification: the final shared and Apple focused gates pass; workspace semantic verification passes normally and
  with its complete source-mutation matrix. Bash syntax, the native-codec watch and mutation self-test, dependency
  inventory and all 103 inventory mutations, requirements-digest synchronization, and `git diff --check` pass. The
  machine inventory exposed and this slice corrected stale requirement/verifier text from 850/73 to the already
  current 855 lexical unsafe blocks across 251 tracked Rust files, 74 containing at least one; no unsafe code was
  added. The available immutable images have no installed Rustfmt component, so no formatter pass is claimed. A
  non-root offline Apple-target root-library check progressed after readable crate archives were re-extracted into
  disposable storage, then stopped in third-party Objective-C/C build scripts because the image has no macOS SDK
  headers. That is not a source failure or a green Apple build. All substantive and final verifier/build/test runs
  used an already-present immutable image as UID/GID 1000 with network and image pulls disabled, read-only repository
  and inputs, disposable outputs, no published ports/capabilities, and no-new-privileges. Before those runs, three
  parser-only checks (`python -m py_compile` and two `bash -n` invocations) and one inventory `--help` invocation were
  mistakenly run as the unprivileged host user. They did not execute RustDesk, build an artifact, access a network,
  or use root; the generated ignored verifier bytecode was removed. This was still a process-boundary violation and
  is recorded rather than hidden. No host RustDesk, service, configuration, listener, firewall, or host-network state
  was inspected or changed.
- **R-S11e-67 — Linux clipboard fusermount process-context finality — SOURCE IMPLEMENTED; NATIVE INSTALLED-HELPER
  AND EXACT-ARTIFACT EVIDENCE REMAIN R-R2/R-B2.** Platform: Linux desktop clipboard file-copy FUSE. Surfaces:
  `mount_with_fixed_fusermount` and the `fixed_fusermount_unmount` teardown fallback. Boundary: ordinary user
  RustDesk process context ↔ the externally installed `fusermount3`/`fusermount` image that supplies the narrow
  setuid-root mount boundary. Proven gap: both launchers already used a canonical fixed helper whose file and both
  parents are root-owned and non-writable, an absolute current-user-owned prepared mountpoint, owner-only mount
  options, explicit argv, stdio pipes, and the R-S11e-32 descriptor policy; Linux euid 0 is separately refused before
  mountpoint setup. They nevertheless inherited the long-lived desktop process's complete environment and current
  directory. The dynamic loader's secure-execution filtering is implementation-dependent defense inside the child,
  not an application-owned input contract, and it does not establish that arbitrary non-loader variables are valid
  helper authority. Upstream documents fusermount as setuid root and its current mount utility deliberately supplies
  an empty environment when it spawns its own privileged `/bin/mount`/`/bin/umount` children. This was ambient
  process-context integrity debt at a privileged external-helper boundary, not a demonstrated working local-root
  exploit, remote trigger, exploitation incident, or evidence of compromise.

  Source closure: one `FusermountOperation` type distinguishes mount from unmount and one
  `configure_fusermount_process_context` policy owns the complete child context before argv, descriptor setup, or
  execution. It clears every inherited variable, fixes the initial directory at `/`, and nulls stdin. Mount adds only
  `_FUSE_COMMFD=<the exact allowlisted socket fd>`; unmount adds no environment entry. There is no preserved `PATH`,
  profile, temporary-directory, locale, loader, FUSE-device, or compatibility environment. Both callers use the typed
  policy exactly once and do not mutate environment or CWD afterward. Fixed executable provenance, euid-0 refusal,
  mountpoint safety, owner-only options, exact descriptor allowlisting, SCM_RIGHTS receipt, checked status, and
  no-follow teardown are unchanged. R-S11ba and Appendix C #175 make the model normative. Two actual-child unit
  regressions poison the `Command` with a sentinel and prove `/usr/bin/env` observes exactly the communication-fd
  entry for mount and an empty environment for unmount, with `/` selected in both cases. The shared source gate and
  semantic workspace validator bind policy inventory, typed caller topology, ordering, regressions, requirement,
  Appendix row, and this ledger; deliberate mutations cover environment reset, directory/stdin policy, operation
  typing, both callers, exact child output, and documentary bindings. Native execution against an installed setuid
  helper and exact Debian artifact evidence remain R-R2/R-B2; external expert review remains R-V3.

  Verification: the focused two-test Rust 1.75 actual-child filter passes, as does the complete 29-test clipboard
  library target when run serially. One preceding parallel full-target run passed 27 tests and timed out in two
  unchanged `read_node_*` tests; the exact three-test cluster and then the complete target passed with one test
  thread, so the red run is retained as scheduler-sensitive evidence rather than hidden or reclassified as green.
  The full RustDesk Linux library check with `linux-pkg-config,unix-file-copy-paste` completes successfully; its
  existing warnings are unchanged. The semantic workspace validator passes normally and with its complete source-
  mutation matrix, and the focused shell gate executes successfully. Bash syntax, native-codec watch normal/self-
  test, dependency inventory normal/all 103 mutations, requirements-digest synchronization, and diff hygiene pass.
  The available immutable Rust 1.75 image has no installed Rustfmt component; no networked install or toolchain
  mutation was attempted. An initial test setup correctly failed because executable Cargo temporaries had been
  prohibited, and a second reached the pre-existing root-owned unreadable `pin-utils` extracted cache entry. Neither
  condition was bypassed with root or a permission change: final compilation re-extracted the read-only crate
  archives and Git inputs into disposable user-owned tmpfs storage. All substantive checks ran in the already-present
  immutable image as UID/GID 1000 with networking and pulls disabled, source/toolchain/input caches read-only, root
  filesystem read-only, disposable output/cache storage, no capabilities, no-new-privileges, bounded pids, and no
  published ports or Docker socket. No host RustDesk, service, configuration, listener, firewall, or host-network
  state was inspected or changed.
- **R-S11bb/R-S11e-68 — IPC lifecycle-split checker coverage — SOURCE CHECKERS REPAIRED/GATED; NATIVE AND
  EXACT-ARTIFACT EVIDENCE REMAIN R-R2/R-B2.** Platforms: shared desktop password-IPC assurance, Linux semantic
  verification, and macOS source conformance. Boundary: prepared listener ownership ↔ retained runner admission,
  authorization, transaction drain, and terminal outcome. R-S11as correctly replaced the monolithic main listener
  with `prepare_main_ipc`/`run_main_ipc`; service IPC likewise uses `prepare_service_ipc`/`run_service_ipc` behind a
  thin wrapper. The Apple password checker, the structured Linux password-IPC verifier, and an embedded shared gate
  still parsed `start_main_ipc`; the structured verifier also expected listener construction and execution inside
  the thin service wrapper. Those structural failures stopped later security assertions and mutation fixtures from
  executing. Its service-password order also predated R-S11at and incorrectly placed identity work before bounded
  admission. One Apple proof-worker mutation targeted the first generic thread-builder token rather than the exact
  Security.framework worker. This was fail-loud assurance drift after a correct runtime refactor, not a runtime
  listener/authentication defect, privilege escalation, exploitation, or evidence of compromise.

  Checker closure: each verifier separately extracts the preparation and runner functions. Preparation assertions
  bind both ordinary and dedicated raw-password endpoints before readiness; runner assertions bind proof-before-
  secret admission, sole authenticated handler ownership, transaction/worker drain, sensitive-ledger clearing,
  listener-guard drop, and returned outcome. The thin service wrapper is checked only for prepare-then-run ownership.
  Linux service-password ordering now preserves R-S11at's transaction permit before active-session/executable
  identity work. The Apple proof-worker mutation uses the unique `let worker = std::thread::Builder::new()` binding.
  R-S11bb and Appendix C #178 make this executable assurance topology normative. The workspace semantic validator
  binds all three checker sources and documentary surfaces with deliberate mutations.

  Verification: the structured Linux verifier passed both normal execution and its adversarial self-test; the Apple
  password checker's `r_s11b`, `r_s11b2`, and `r_s11e16` structural/mutation groups passed; and the shared embedded
  raw-password checker plus the R-S11bb source gate passed. The workspace verifier passed normally and its complete
  in-memory semantic source-mutation matrix rejected every affected checker, ordering, requirement, Appendix, and
  ledger mutation. Native-codec normal/self-test, dependency inventory and all 103 self-tests, Bash/Python syntax,
  requirements-hash equality at `ada3cca27f8576b60311f945dd17d19fbcba56583b7ea908208494119be24506`, and
  `git diff --check` passed. During development, the workspace validator first exposed an R-S11bb assertion placed
  against the unrelated macOS descriptor source and then a retired-name absence check that included the shell gate's
  deliberate rejection string; both scopes were narrowed to the actual shared checker body before the passing runs.
  A broad executable `--self-test` invocation without its mandatory separately owned scratch directory was correctly
  rejected and is not counted; the explicit complete source-mutation mode is the applicable adversarial evidence for
  this checker-only slice. All substantive checks used the pre-existing immutable `rd-devcheck` image as UID/GID
  1000 with no network, capabilities, new privileges, writable source, published ports, or Docker socket. Native
  Apple execution and clean exact-commit release artifact proof remain R-R2/R-B2; external review remains R-V3. No
  runtime Rust source is changed by this checker-repair slice, and no host RustDesk/service/configuration/network state
  was inspected or changed.
- **R-S11bc/R-S11e-69 — Dart/FRB verifier container authority — SOURCE CLOSED/GATED; CONFINED COLD DART/FRB
  EXECUTION RECORDED; BROADER RELEASE EVIDENCE OPEN.** Platform: the Linux Docker build host used by the release
  source-verification bundle. Endpoint/action: `scripts/dart-verify.sh` Pub resolution, Flutter Rust Bridge generation, Flutter analysis,
  and the focused direct-address test. Boundary: untrusted build/code-generation dependencies and mutable tool state
  ↔ the developer's real source worktree, offline-input closure, Docker daemon image/cache state, and DMZ-host
  network. The inherited verifier built the mutable `rd-devcheck`/`rd-fluttercheck` tags, created four reusable named
  volumes, used Docker's default bridge and implicit image-pull policy, and ran its tools as the default container
  root user with the real repository mounted read-write. It also wrote a fixed `/tmp` log and used an ignored
  build-runner priming attempt before retrying code generation. Docker's documented bind-mount semantics allow a
  writable container bind to create, modify, or delete host files; its default runtime user is UID 0, and its default
  missing-image pull policy may consult external state. A failed or compromised Pub/build-runner/FRB/analyzer step
  could therefore modify or root-own repository files, communicate externally, or consume mutable daemon-side
  tool/cache state. No port was published and no RustDesk binary or service was run, so this was build-host and
  supply-chain authority debt, not evidence of a public listener, host RustDesk mutation, container escape,
  privilege escalation incident, or compromise.

  Source closure: the verifier rejects UID or primary GID zero and selects the locally provenance-verified immutable
  Debian-builder image ID. It validates the canonical offline closure, then creates a current-user mode-0700 private
  workspace and a complete read-only private online snapshot whose identity is checked before and after use. A
  normalized archive captures exactly the tracked plus nonignored current source state; its digest is checked again
  after every gate. FRB receives a read-only source snapshot and writes only to its own private invoking-user-owned
  copy/output. Analysis receives a second private writable copy with freshly generated bindings. The real worktree
  is never mounted into either container. Both launches use `--pull=never`, `--network=none`, read-only root filesystems,
  the invoking numeric UID:GID, all capabilities dropped, no-new-privileges, fixed PID/memory/no-swap/CPU bounds,
  and a size-bounded `nosuid,nodev` tmpfs. The only mounts are the private writable work copy and read-only private
  offline snapshot; there are no named volumes, image builds, published ports, host namespaces, or Docker socket.
  Pub resolution is offline and lock-preserving. Analyzer warnings/info retain their accepted nonfatal baseline, but
  any nonzero analyzer status is final rather than inferred away by matching one diagnostic string. The former
  ignored build-runner priming fallback is absent: a pinned FRB-generation failure is final. `scripts/frb-codegen.sh` now carries the same explicit non-root, pull,
  capability, no-new-privileges, and resource limits. R-S11bc and Appendix C #180 make this exact two-launch
  authority model normative, and `scripts/verify-dart-verifier-authority.py` binds it with deliberate mutations.

  Verification: the focused validator passed under the immutable non-root verifier image with all 48 deliberate
  mutations rejected. A complete cold `scripts/dart-verify.sh` transaction then reverified canonical closure
  `a7581f0ffa4fa924d4eacfe6c2bef9dec37a2ce2d06740c04037489341d904ac`, built and reverified a complete private
  offline snapshot, generated and atomically published the FRB outputs inside private state, received analyzer exit
  status zero with zero Flutter analyzer errors, passed all six direct-address tests, passed the complete Dart excision grep set, reverified the
  private closure, and proved the real normalized source archive unchanged. FRB/ffigen emitted the existing
  unresolvable-module warnings and a `Dart_Handle` typedef-redefinition diagnostic before completing successfully;
  this run is therefore recorded as successful but not diagnostic-free. The validator initially used Python features
  absent from the pinned Debian-builder Python 3.6 and two first-draft mutation fixtures did not target their intended
  assertions; those checker-only defects were corrected before the recorded 48-mutation pass. The independent
  workspace verifier passed normally and passed its complete source-mutation matrix while binding the focused
  checker, both launchers, shared gate, normative requirement, disposition, and ledger. The dependency inventory
  passed normally and with all 103 self-test checks; native-codec watch passed normally and with its full mutation
  self-test; Bash syntax, in-memory Python compilation, the synchronized requirements SHA-256, and `git diff
  --check` passed.

  Remaining scope: this slice does not claim that all of `verify.sh`, advisory gates, smoke/lifecycle fixtures,
  online acquisition, platform builders, or every other Docker consumer has the same containment; those remain
  independent audit surfaces. It does not close the clean cold R-B2 build, R-B10 exact Android artifact evidence,
  native installed-platform behavior, or R-V3 review.
- **R-S11bd/R-S11e-70 — one confined owner for Flutter-side Rust verification — SOURCE CLOSED/GATED;
  EXACT R-B2 ARTIFACT EVIDENCE OPEN.** Platform: the Linux Docker build host used by source and release
  verification. Endpoint/action: the retired manual `scripts/flutter-verify.sh`/`scripts/Dockerfile.fluttercheck`
  path and the replacement shipped-feature Rust library check inside `scripts/dart-verify.sh`. Boundary: Rust/FRB
  build dependencies and mutable Cargo/native state ↔ the developer worktree, Docker daemon state, DMZ-host
  network, and the truthfulness of release feature coverage. The orphaned harness built the mutable
  `rd-devcheck`/`rd-fluttercheck` tags with live dependency downloads, created reusable daemon-global Cargo/Git/target
  volumes, ran as default container root with default bridge networking, and mounted the real repository read-write.
  It tolerated a failed FRB invocation if two generated Rust files existed and checked
  `flutter,linux-pkg-config`; no tracked caller or release gate invoked it, while the Debian artifact actually builds
  `flutter,unix-file-copy-paste` against the staged vcpkg native set. The harness published no port and executed no
  RustDesk process or service. This was a real parallel build-host/supply-chain authority path and an assurance
  mismatch, not evidence of a public listener, host RustDesk mutation, container escape, exploitation, or compromise.

  Source closure: both orphaned files are deleted rather than preserved as an alias or alternate entrance. After the
  R-S11bc transaction has successfully generated all FRB outputs, preserved `pubspec.lock`, analyzed authored Dart,
  and passed the focused direct-address test, its existing immutable nonroot/networkless analyzer container extracts
  the hash-verified pinned Rust 1.75 toolchain. Before any Flutter wrapper command it explicitly resolves the
  extracted SDK's own `packages/flutter_tools` package with `dart pub get --offline`; network isolation remains a
  backstop rather than silently containing an implicit online bootstrap. It builds a private Cargo home from the complete staged vendor source
  map with `[net] offline = true`, requires `/online/vcpkg/installed/x64-linux/lib`, puts nonincremental target state
  under the current-user-owned disposable analysis snapshot, records `Cargo.lock`, and runs
  `cargo check --offline --locked --features flutter,unix-file-copy-paste --lib --color never`; a nonzero status or
  lock change is final. The container keeps the existing immutable image ID, `--pull=never`, `--network=none`,
  read-only root, numeric invoking UID:GID, capability drop, no-new-privileges, resource ceilings, two-mount inventory,
  no ports/socket/host namespaces, final private-online proof, and normalized real-source postcondition. No new
  container launch, image build, named volume, host worktree mount, root authority, distro-native approximation, or
  ignored fallback is introduced. The source comment that named the deleted generator now points to the sole owner.

  Verification: R-S11bd and Appendix C #181 bind the consolidated topology. The focused semantic validator rejects
  all 60 deliberate mutations spanning the pinned Rust input, offline Flutter-tool/Cargo configuration, staged vcpkg
  root, private target, exact feature command, lock postcondition, deleted-source inventory, retired-file absence,
  requirement, disposition, and this ledger. The first cold attempt failed before Docker because the normalized
  archive inventory incorrectly retained intentionally deleted tracked paths; the inventory now filters the NUL-safe
  Git list by `lexists`, is mutation-bound, and excludes both retired files. The second cold attempt completed full
  FRB generation but was deliberately stopped after `flutter analyze --no-pub` triggered a non-offline Flutter-tools
  Pub bootstrap that made no progress for more than ten minutes under network isolation; the container and complete
  private workspace were removed, and explicit offline tool-package resolution was added rather than accepting the
  implicit attempt. These were fail-closed verifier defects, not ignored failures or successful evidence.

  The final complete cold transaction reverified canonical closure
  `a7581f0ffa4fa924d4eacfe6c2bef9dec37a2ce2d06740c04037489341d904ac` and immutable Debian-builder image
  `sha256:6766564c65b0daead7d7031fcf0ff9ec8becab6ef9e3f9a7efd9f02f1b893776`, built and reverified a fresh
  25-GiB private offline snapshot, generated and atomically published all FRB outputs, explicitly resolved both
  Flutter tool/project packages offline without lock drift, received analyzer status zero with zero errors, and passed
  all six direct-address tests. The new exact
  `cargo check --offline --locked --features flutter,unix-file-copy-paste --lib --color never` completed in 1m58s
  from the staged vendor/vcpkg closure with 59 existing warnings; it was successful but not warning-free. All Dart
  excision greps, `Cargo.lock` identity, private-closure postcondition, and normalized real-source postcondition passed.
  FRB retained its already-recorded unresolvable-module warnings and `Dart_Handle` typedef diagnostic before
  succeeding; that phase likewise is not claimed diagnostic-free. Independent workspace mutation, dependency
  inventory, native-codec, syntax, requirements-hash, diff, and publication evidence are recorded before publication.
  This strengthens source verification but does not substitute for the clean exact-commit R-B2 Debian double build,
  package/manifest/lifecycle evidence, native installed behavior, or R-V3 independent review.
- **R-S11be/R-S11e-71 — Dart advisory result and scanner authority — SOURCE CLOSED/GATED; ACQUISITION REMOVED FROM VERDICT PATH;
  CONFINED CURRENT SCAN RECORDED; INDEPENDENT IMAGE DISTRIBUTION AND BROADER RELEASE EVIDENCE OPEN.** Platform: the
  Linux Docker build host used by the release source-verification bundle. Endpoint/action: `scripts/dart-audit.sh`
  executing pinned OSV-Scanner against `flutter/pubspec.lock` and interpreting the result through the reason-bearing
  Pub advisory policy. Boundary: live network/image acquisition, mutable Docker identity, stale advisory data,
  scanner/database/tool failure, and untrusted machine output ↔ a green release verdict, the developer checkout,
  Docker daemon state, and the DMZ-host network. The inherited script first erased OSV's result status, discarded
  stderr, defaulted a missing `results` member to clean, and ran a mutable tag as root with bridge networking,
  writable rootfs, implicit pulls, and the whole checkout. The earlier R-S11be repair correctly made result finality
  and scanner execution nonroot/networkless, but it still ran a live Docker build on every verdict invocation. That
  build fetched APT packages, the OSV release binary from GitHub, and the current mutable GCS `Pub/all.zip` before
  producing and tagging the image. It consequently retained unnecessary Docker/network/build authority and had no
  age bound independent of successful live acquisition. These were release-assurance and build-host/supply-chain
  defects, not evidence of exploitation, a container escape, privilege escalation, compromise, a public listener,
  RustDesk execution, host-service/configuration mutation, or host firewall/network mutation.

  Source closure: verdict execution and acquisition are now separate. `scripts/dart-audit.sh` rejects effective UID
  or primary GID zero and never builds, pulls, or resolves a tag. It requires only the already-present exact content
  ID `sha256:f80e9869536995a1db9c14ab07c7b2ddfc83a4eaef52be2e49971c767323de0d`; absence is final, with no fallback.
  Before Docker, `scripts/dart-audit-result.py` reads the real policy and lockfile through descriptor-stable
  `O_NOFOLLOW` regular-file checks, rejects hardlinks, validates the policy plus the lockfile's one top-level package
  map, and writes stable mode-0600 private copies and hashes inside an identity-bound current-user mode-0700
  workspace. The database pin is 19,437 bytes with SHA-256
  `8b1d25767804f7487d7a26d9ae001c00813329252157eb7d267a8fb6f575b87c` and immutable capture mtime epoch
  `1782347599` (2026-06-25T00:33:19Z). A fork-owned exact 30-day capture-age ceiling has no caller override and is
  checked before Docker and before green; the current snapshot is eligible on 2026-07-20 but will fail closed after
  the exact boundary unless image, bytes, capture metadata, and policy review are deliberately refreshed together.

  A mount-free preflight checks the scanner's exact 2.4.0/Scalibr 0.4.5 version report, upstream commit/build report,
  binary hash, database hash, and database regular-file size/mtime/mode/UID/GID/link metadata. Preflight and scan
  address only that content ID and run with `--pull=never`, `--network=none`, a read-only root, numeric invoking
  UID:GID, all capabilities dropped, no-new-privileges, bounded PID/memory/no-swap/CPU/tmpfs resources, and an
  inherited 64-MiB output-file ceiling. Neither has a port, host namespace, Docker socket, named volume, or real
  repository mount. The scanner's sole mount is the stable private lockfile copy. Status 0/1 alone reach the
  evaluator; all other statuses are infrastructure failure. JSON must name at most one exact lockfile source, Pub
  packages, and typed vulnerabilities/aliases/ranges/events. The separate stderr parser accepts only the pinned
  binary's four telemetry lines: exact walk root, exact lockfile plus positive package count, bounded timing grammar,
  and exact local Pub database. Any extra warning/diagnostic fails. Status/finding cardinality, reason-bearing accept
  IDs/aliases, freshness, and both real/private input hashes must agree before cleanup can publish green.

  Verification: the evaluator's 31 policy/freshness/status/schema decisions pass, including exact-age boundary and
  one-second-stale cases, future/noncanonical epochs, hardlink refusal, private staging, strict scanner telemetry,
  infrastructure statuses, malformed schema, and status/result disagreement. The focused semantic validator rejects
  all 61 deliberate mutations across live-acquisition absence, immutable pins, capture age, stable inputs, preflight
  bytes/metadata, output/resource/privilege/mount confinement, telemetry, JSON/status finality, source postconditions,
  shared-gate wiring, R-S11be, Appendix C #182, and this ledger. The exact existing image passed its mount-free
  preflight and current offline scan: OSV status 0, 199 packages reported from the exact private lockfile, an explicit
  empty `results` list, and only the four accepted telemetry lines. A separate disposable private-lockfile probe
  changed only `archive` from 3.6.1 to vulnerable 3.3.7; the same confined scanner returned status 1, and the strict
  evaluator also returned 1 while naming both pinned-snapshot GHSA findings and their 3.3.8 fix. No image was built or
  pulled. Syntax, independent
  workspace/source mutation, requirements-hash, native-codec, diff, and publication evidence are recorded before
  publication. `scripts/Dockerfile.dart-audit` remains an explicit acquisition recipe only; independently archived
  and provenance-verified distribution of a refreshed image is still open, as are Rust advisory image distribution,
  other Docker consumers, exact R-B2/R-B10 artifacts, installed-platform behavior, and R-V3 external review.
- **R-S11bf/R-S11e-72 — Rust advisory freshness, result finality, and scanner authority — SOURCE
  CLOSED/GATED; CURRENT SNAPSHOT/POLICY REVIEWED AND SCANNERS GREEN 2026-07-22; INDEPENDENT IMAGE DISTRIBUTION AND
  BROADER RELEASE EVIDENCE OPEN.** Platform: the Linux Docker build host used by the release source-verification
  bundle. Endpoint/action: `scripts/audit.sh` validating `Cargo.lock` through pinned `cargo-audit` and `cargo-deny`
  plus the reason-bearing `deny.toml` policy. Boundary: live acquisition, mutable Docker/cache/index state,
  scanner/database failures, and machine output ↔ a green release verdict, the developer checkout, Docker daemon
  state, and the DMZ-host network. The inherited gate built `rd-audit` from live APT/crates.io/GitHub on each
  invocation, discarded the returned image content identity, and ran both scanners by mutable tag as Docker's
  default UID 0 with bridge networking, writable roots, implicit pulls, the whole checkout, and reusable named
  Cargo registry/Git volumes. Its 2025-11-30 database omitted the 2026 RustSec series, while `cargo-audit 0.21.1
  --no-fetch` bypassed the tool's fetch-path freshness check. Offline `cargo-deny` also treated missing mutable
  crates.io yank state as non-fatal index warnings. These were deterministic false-green release-assurance and
  build-host/supply-chain authority defects. The path did not publish a port, run RustDesk, touch a host RustDesk
  service/configuration, or inspect/mutate host firewall/network state, and supplies no evidence of exploitation,
  compromise, container escape, or privilege escalation.

  Acquisition closure: `scripts/Dockerfile.audit` is an explicit online recipe, never a verdict-time dependency.
  It takes no filesystem context, uses the official `rust:1.88-bookworm` manifest-list digest
  `sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0`, and sets `USER 1000:1000` before every
  one of its five project-owned `RUN` instructions across both stages. The builder installs released
  `cargo-audit 0.22.2` and `cargo-deny 0.20.2` from their packaged lockfiles, removes registry/Git/target state in
  the same build layer, and fetches only RustSec commit `b5fc89b8be99e96f79194d8a6f11e9b4143b99f0`, committer epoch
  1784303558 (2026-07-17T15:52:38Z). The runtime stage copies only the two tools and clean database with numeric
  ownership. A first candidate `sha256:cf6939d6...` was rejected because pre-`FROM` ARG scope left the Rust/base
  provenance labels empty. The corrected, untagged 569-MB candidate is
  `sha256:c8ef1aae7df528285a50bbf55d80bc6807d0beb75126f8a33e37e7bec5b862b9`; inspection and a mount-free,
  networkless, read-only preflight proved Linux/amd64, default and effective UID:GID 1000, the complete base/tool/DB
  labels, Rust 1.88.0, clean exact database, and scanner hashes
  `bcd015b7b140f87024349670d1fd4cae09415049394a96d8f82776032f9a76e0` /
  `5e4a31300be4ee99625751025b4c1a0c3965b747c60fecaebd7454f17dc944ad`. The recipe itself is SHA-256 pinned.

  Verdict closure: `scripts/audit.sh` refuses effective UID or primary GID zero, never builds/pulls/resolves a tag,
  and accepts only the locally present immutable image ID. Before Docker it validates `deny.toml` as exact
  `{ id, reason }` objects, stages stable regular non-link copies in an identity-bound mode-0700 private workspace,
  and enforces exactly 90 days of maximum RustSec age with no caller override. It now also binds image OS,
  architecture, numeric default user, base digest, tool versions, database commit/epoch, and all acquisition labels
  before the mount-free binary/database preflight. All three Docker launches use `--pull=never`, `--network=none`,
  read-only roots, the invoking numeric UID:GID, all capabilities dropped, no-new-privileges, and fixed
  PID/memory/no-swap/CPU plus size-bounded `noexec,nosuid,nodev` tmpfs resources. Each Docker client inherits an
  at-most-64-MiB output-file limit while preserving any stricter caller limit. They publish/expose no port and use
  no host namespace, Docker socket, privilege/capability addition, or named volume.

  `cargo-audit` sees only the private bundle, scans the exact lockfile/database with `--no-fetch --deny warnings
  --json`, and must return status 0 with a bounded structured object whose database field exists, dependency count
  is nonzero, reasoned ignore set is exact, vulnerability found/count/list fields agree at zero, and warning fields
  are empty. `cargo-deny` sees source read-only while private tmpfs mounts shadow `.cargo/`, `.git/`,
  `.harness-state/`, `online/`, `target/`, `flutter/.dart_tool/`, and `flutter/build/`; only the dedicated vendor
  subtree is exposed separately read-only. The refreshed canonical `online-input-provenance-v1` root is
  `3caca8746b4ada39db1d9ecd63db1cf2d3786e050a5bced400e4d2cf6bb45bea` over 51,022 files, 12,171 directories,
  zero symlinks, and 2,300,105,420 content bytes. Cargo 1.88 metadata was reproducibly OOM-killed under the old
  2-GiB ceiling; the smallest tested successful bound is 3 GiB, with equal memory/swap limits and an 8-MiB no-exec
  target tmpfs. The 0.20.2 CLI uses global `--config` plus locked/offline mode; its private database copy is verified
  before and after. Only status zero and a well-formed JSON-lines stream ending in one zero-error advisory summary
  is green; the only accepted diagnostic is `advisory-not-detected`. Lockfile, policy, vendor map, and vendor subtree
  are reverified before cleanup-bound green.

  Dependency review: the current database exposed 15 new unique IDs. Five Rust-1.75-compatible updates were applied
  rather than ignored: `bytes 1.11.1`, `crossbeam-epoch 0.9.20`, `rustls-webpki 0.103.13` plus its minimum
  `rustls-pki-types 1.12.0`, `anyhow 1.0.103`, and `memmap2 0.9.11`, eliminating eight IDs. Cargo's exact registry
  checksums match all six newly vendored directories; locked/offline full-workspace metadata accepts the minimally
  edited lockfile, and a focused Rust 1.75 compile of all six packages passes. The seven remaining new IDs have
  source-specific reasons: quick-xml's affected roles are local-output, macOS-only plain-reader, or pinned
  build-time XML; time's fixed release requires Rust 1.88 while locked callers do not parse attacker RFC-2822 text;
  build-only shadow-rs uses none of git2's three affected APIs; and ttf-parser's maintenance notice covers local
  system-font parsing with no drop-in migration. The complete exact accept set is 41 IDs, not a wildcard.

  Dependency-inventory reconciliation (2026-07-23): the fail-closed inventory correctly remained red after the
  six reviewed registry-package upgrades above and after four later authority-hardening source changes. The package
  topology remains 905 records, 36 Git records, and 26 unique Git source URLs; only the complete package-record
  identity moved to `1289e88c63677833d40600e08616163ae345920d7ff6381d69b7ea26f0d361fc`. The lexical Rust
  inventory remains 247 tracked files and 74 matching files, while the total moved from 855 to 859 and the per-file
  identity moved to `e84d5ffaae33889085987b5a49a7be444a94ea6cc467c4e199f91a16372638bf`. The complete
  attributed delta is `libs/portable/src/main.rs` 11→13 (typed Windows Installer FFI: three calls replace one
  `GetSystemDirectoryW` call), `src/ipc/fs.rs` 33→34 (effective-UID proof for incumbent-listener authentication),
  `src/platform/macos.rs` 30→32 (two effective-UID reads binding LaunchAgents to explicit `gui/<uid>` domains), and
  `src/virtual_display_manager.rs` 20→19 (unowned Amyuni uninstall FFI deleted). These are narrow FFI boundaries in
  already-reviewed hardening commits, not additional message, process-launch, or privilege authority. No block was
  consolidated merely to lower the lexical metric. Historical evidence below retains the count measured at its own
  commit; any later package-record or per-file unsafe change must make the live inventory red again and receive the
  same attribution before its baseline advances.

  Current reconciliation verification: a non-root, networkless, read-only-root container verified the exact pinned
  vendor-subtree root and, independently, the lockfile package checksum plus every vendored file digest for each of
  the six upgraded crates. Rust 1.75.0 accepted locked/offline metadata for all 14 workspace packages. The normal
  dependency inventory and all 103 adversarial inventory fixtures passed; the semantic workspace verifier passed in
  normal mode and rejected its complete source-mutation matrix; the Rust-audit authority verifier rejected all 53
  deliberate mutations; and the native-codec watch passed both normal and mutation modes with the synchronized
  requirements hash. These are source and metadata gates, not new R-B2 artifact, installed-platform, device, or
  independent-review evidence.

  Verification: production-equivalent confined scanner launches against the exact new image returned cargo-audit
  status 0 over 905 packages with exactly 41 accepts and zero stderr; cargo-deny returned status 0 with 76 policy
  notes and seven explicit obsolete-accept warnings, with no index/network failure. The existing strict result
  validators accepted both schemas. The rootless image build and every scanner/probe ran in Docker; the host was
  used only for source reads/edits, Git, and direct Docker control. The host orchestration script itself was not run
  outside Docker, and no Docker socket was delegated into a container. No full release build is counted here.
  Final focused proof revalidated shell/Python syntax; all 20 policy/freshness/result decisions; all 53 deliberate
  acquisition/verdict mutations; the exact 51,022-file vendor root; and both the normal and mutation-mode
  native-codec requirements/hash gate. `git diff --check` was clean. The independent whole-workspace meta-verifier
  is not counted as passing in this transaction: its pinned devcheck image is absent locally, and a supplemental
  immutable image cannot supply the required live per-user systemd/D-Bus authority inside this deliberately
  networkless, capability-free container. The test was not weakened and no host execution, image pull/build,
  Docker-socket delegation, or privilege expansion was used to manufacture a result. Independently
  archived/provenance-verified distribution of this image, exact clean R-B2/R-B10 artifacts, installed-platform
  evidence, and R-V3 external review remain open; neither this item nor the overall release is claimed complete.
- **R-S11bg/R-S11e-73 — main verifier container and root-test authority — SOURCE IMPLEMENTED/GATED;
  CONFINED FULL-GATE EXECUTION VERIFIED 2026-07-20; INDEPENDENT IMAGE ACQUISITION AND BROADER RELEASE EVIDENCE
  OPEN.** Platform:
  the Linux Docker build host used by the primary `scripts/verify.sh` source/behavior/compile gate. Endpoint/action:
  117 Cargo test/check/clean invocations and the two IPC filesystem tests that construct a foreign-owned service
  directory. Boundary: build scripts, test binaries, mutable build outputs, image/tag/cache state, and Docker
  networking/root authority ↔ the real developer checkout, ignored signing/harness state, Docker daemon state,
  DMZ-host network, and truthfulness of the main verification verdict. The inherited gate created three reusable
  daemon-global Cargo registry/Git/target volumes, rebuilt the mutable `rd-devcheck` tag from live image/APT inputs
  on every invocation, and ran every Cargo command by tag under Docker default UID 0, default bridge, implicit
  missing-image pull policy, and a writable root. The checkout bind was read-only and no port was published. Only
  `test_ensure_secure_ipc_parent_dir_recreates_foreign_service_dir` and
  `test_ensure_secure_ipc_parent_dir_foreign_nonempty_fails_closed` needed euid 0 to `chown` a private fixture;
  the ACL branch additionally needs `CAP_FOWNER`. That narrow fixture need did not justify ambient root for all
  builds and tests. This was high-frequency build-host/supply-chain, persistent-state, and verdict-authority debt,
  not evidence of a public listener, host RustDesk execution, host service/configuration/firewall mutation, Docker
  escape, exploitation, host privilege escalation, or compromise.

  Source closure: the verifier now rejects host effective UID or primary GID zero and never builds, pulls, tags,
  or resolves an image or creates/uses a named volume. `DEV_CHECK_IMAGE_ID` pins the already-present local content
  identity `sha256:2f0406ee5b7dcd5683d900fb8b45668abd69934e6b4bdbf4737165fc01e72398`. A mount-free
  nonroot preflight verifies Rust/Cargo 1.75.0, both binary hashes, the sorted installed-package manifest hash, and
  the required sodium environment. `scripts/Dockerfile.devcheck` has a review-recipe hash, but independently
  archived acquisition and reproducible distribution of this opaque image remain open; loss of the content ID is
  a hard failure, never authority to build or fetch it.

  Before Cargo, one current-user mode-0700 identity-bound workspace receives a normalized NUL-safe archive of
  exactly tracked plus nonignored current source and a race-detecting read-only snapshot of the complete canonical
  Cargo vendor subtree. Ignored `.git`, `.harness-state`, `online`, and worktree `target` state cannot reach build
  code. A private mode-0400 complete 26-source Cargo map points at `/vendor`. The closed command wrapper accepts
  only Cargo or the exact version-metadata checker. Resolving/compiling commands receive
  `--config /tmp/cargo-config.toml --offline --locked`; the nested mount path is deliberate because Cargo 1.75's
  source-path resolver panics for a command-line config mounted directly under `/`. The sole exact
  `cargo clean -p rustdesk` operation uses
  `CARGO_NET_OFFLINE=true` and an ephemeral Cargo home populated from the same map because Cargo 1.75 panics when
  `clean` receives the command-line config; that cleanup acts only on the private target and executes no package code.
  Every ordinary launch uses the exact image ID, `--pull=never`, `--network=none`, a read-only root, the invoking
  numeric UID:GID, all capabilities dropped, no-new-privileges, nonincremental target state, bounded PID/memory/
  no-swap/CPU/tmpfs resources, and exactly four private mounts: source read-only, vendor read-only, target writable,
  and Cargo config read-only. It receives no real checkout, Git/signing state, named volume, Docker socket, port,
  or host namespace.

  The complete IPC filesystem module first runs nonroot. A separate nonroot `--no-run` emits bounded Cargo JSON;
  `scripts/prepare-root-ipc-test.py` selects exactly the root crate library-test artifact, rejects duplicate,
  non-test, noncanonical, linked, or writable inputs, then descriptor-stably copies and hashes it into a private
  mode-0555 file beneath the mode-0700 workspace. The non-owner execute bits are required because the isolated UID-0
  container intentionally lacks `CAP_DAC_OVERRIDE`; the private parent and read-only bind retain host confidentiality
  and immutability. Each root-required test runs by exact name in a fresh container whose sole host mount is that file
  read-only. The root container has no pull/network/port/host-namespace authority, a read-only root,
  no-new-privileges, all capabilities dropped then exactly `CHOWN`/`FOWNER` added, bounded resources, and private
  tmpfs fixtures. It has no source, vendor, target, Cargo config, or other writable host mount.
  `RUSTDESK_ROOT_IPC_FS_HARNESS=1` makes a wrong euid or unavailable POSIX-ACL exercise fail instead of silently
  taking the ordinary skip path. Status, output bounds, skip absence, exact test name, and one-pass result agree.

  Before green, the private vendor closure, normalized real-source digest, source-map and recipe hashes, and local
  image ID are rechecked. Identity-bound private-tree cleanup owns every output and suppresses the deferred green
  marker on failure. The root-artifact helper has ten behavioral checks, including rejection of the package name
  or a generic `lib` kind in place of the exact `librustdesk` `cdylib`/`staticlib`/`rlib` target; the
  online-provenance helper tests the
  subtree snapshot; and the focused semantic validator deliberately mutates the image/build/tag/volume absence,
  private inputs, ordinary/root Docker inventories, exact capabilities, wrapper, artifact selection, required ACL
  coverage, postconditions, R-S11bg, Appendix C #184, and this ledger.

  Confined runtime evidence: from clean candidate `a576ce296e6d22b8bef4781966819ede7556587a`, the complete
  `scripts/verify.sh` transaction exited zero with
  `VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green`. The exact
  `librustdesk` test artifact was selected from bounded Cargo JSON, descriptor-stably copied and hash-checked, and
  the two foreign-owner/POSIX-ACL tests passed separately under only `CAP_CHOWN`/`CAP_FOWNER`; ordinary Cargo and
  version-metadata work remained nonroot. The final private-vendor, normalized-real-source, local-image-identity,
  and cleanup postconditions passed. Before that final green run, fail-closed full transactions exposed stale
  textual assertions for the current retained-listener/finalizer, Linux service-child recovery/cleanup, deleted
  generic sudo/env launcher, staged xrandr command, descriptor allowlist, macOS installer-versus-daemon path, Cargo
  source mount, and other already-implemented authority shapes. Those assertions were corrected to bind the current
  stronger implementations; no failed transaction was counted as evidence. Bash syntax, exact focused assertions,
  the complete workspace/source-mutation suite, and all 63 focused main-verifier authority mutations then passed.
  No image was built, pulled, fetched, or tagged during implementation or verification.

  This closes only the source-defined main-verifier authority. It does not close independently archived devcheck
  image acquisition, the intentionally release-blocking RustSec refresh, exact clean cold R-B2 artifacts, installed
  platform behavior, or R-V3 independent review, and neither this item nor the overall release is claimed complete.
- **R-SV4a — direct-only viewer transport and state finality — SOURCE IMPLEMENTED; EXACT GENERATED/PLATFORM
  ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Platforms: every viewer, including Android, iOS, Linux, macOS, Windows,
  and the authored web bridge. Boundary: direct transport establishment ↔ proactive login option construction ↔
  session/reconnect API. Proven defect: `_start` returned a hardcoded `direct=true`, but `send_login` ran before the
  I/O loop copied that value into `LoginConfigHandler.direct`. The login option builder therefore observed `None` and
  applied the inherited non-direct cap to custom image quality above 100 and Flutter custom FPS above 30 on a real
  direct connection. The constructor also returned dead rendezvous feedback/update tuples; login state, the
  `Interface` trait, FPS control, Rust FFI, generated/authored Dart, and the web bridge retained relay-choice state;
  and a first-message reset predicate was named and gated as a relay retry. This was real cross-platform viewer
  correctness/state debt, not network egress, authentication bypass, privilege escalation, Android foreground-
  service authority failure, exploitation, or evidence of compromise.

  Source closure: the direct constructor returns only an already-keyed `Stream` and the fixed `TCP` label. Its
  callers have no direct boolean to propagate. `LoginConfigHandler` and `Interface` contain no force/direct relay
  state. Login-time custom quality/FPS is unconditionally direct, including before the first I/O-loop iteration, and
  FPS control has one direct-only coefficient. Session creation and reconnect remove the relay boolean at the Rust
  FFI boundary, authored Dart, and web bridge; FRB regeneration derives the same ABI. Reset retry depends only on
  the receiver-owned `received` boundary and is named `before_first_peer_message`. R-SV4a and Appendix C #176 bind
  the invariant. The feature-gated CLI caller now implements the current `Interface`, consumes the fixed stream label
  rather than misnaming it as a boolean, and supplies its prompted password through `get_connect_password` before
  PAKE keying. Its binary entry now uses the locked Clap 4 `Command`/typed accessor API instead of the non-compiling
  Clap 3 `App`/usage parser, with `--server` represented as a value-free flag. Four focused CLI regressions bind
  prompted and explicit-password precedence plus flag/value parsing. Focused client tests prove uncapped pre-login
  custom quality (and FPS under `flutter`) plus opposite retry outcomes across the first-message boundary. Shared and
  post-codegen Dart gates reject every retired relay-state symbol or parameter. Exact generated-binding/platform-
  artifact evidence remains R-B2/R-B10; external review remains R-V3.

  Verification: exact Rust 1.75 locked/offline library filters pass for both direct-only pre-login quality and the
  first-peer-message retry boundary. The feature-gated CLI's two password-source tests, binary's two Clap parser
  tests, and complete `cli,linux-pkg-config` check pass. Fresh FRB 1.80.1 generation from `flutter_ffi.rs` produces
  a one-argument `sessionReconnect`/`wire_session_reconnect` ABI and no `forceRelay`/`_forceRelay` or
  `force_relay` residue; `flutter analyze --no-pub lib/` reports zero errors (39 pre-existing warnings and 224
  informational diagnostics). The same Rust regression and a complete locked/offline
  `flutter,linux-pkg-config` check pass against that generated bridge. The semantic workspace validator passes
  normally and with its complete source-mutation matrix, including the CLI password and Clap parser mutations.
  Native-codec watch normal/self-test, Bash syntax, requirements-digest synchronization, `git diff --check`, and
  semantic binding of the shared source gate pass. Exact Rust 1.75 rustfmt accepts every slice-owned hunk; its only
  remaining whole-file output is the same unrelated parent-commit formatting in `flutter_ffi.rs` and
  `ui_session_interface.rs`, proven identical against `HEAD` and deliberately not reformatted.

  Failed setup attempts are retained as evidence rather than hidden: the first Cargo cache was root-owned and
  unreadable at `pin-utils`; early FRB harnesses omitted the exact Rustfmt or writable Git input, exhausted a small
  tmpfs, or let Flutter enter its own online-mode package-resolution path despite a networkless container; a first
  analyzer invocation returned nonzero solely for the existing warning/info baseline; and one textual generated-
  ABI assertion required matching the generator's closure formatting rather than a semicolon. No permission or
  ownership change, root fallback, dependency fetch, or source workaround was used. Only disposable verifier
  containers owned by this slice were stopped. Final runs re-extracted read-only Cargo archives/Git inputs into
  user-owned tmpfs, used the preserved offline Flutter snapshot and exact Rust 1.75 Rustfmt, and ran as UID/GID 1000
  in already-present immutable images with pulls/networking disabled, a read-only root and host checkout, all
  capabilities dropped, no-new-privileges, bounded pids, disposable outputs, and no ports or Docker socket. No host
  RustDesk process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or host network
  state was inspected or changed.
- **R-SV5a — obsolete numeric-ID query command and user-main-IPC scope — SOURCE CLOSED/GATED;
  EXACT PACKAGED-ARTIFACT EVIDENCE REMAINS R-B2.** Platforms: the desktop CLI on Linux, macOS, and Windows;
  the user-main-IPC scope consequence existed only on installed root Unix launches. Boundary: argv dispatch ↔
  active-user IPC namespace selection ↔ side-effect-free stored compatibility identity. The direct-only fork still
  accepted `--get-id` and printed `ipc::get_id()`. On installed root Linux/macOS, the same argument was classified
  with management commands and therefore selected `UserMainIpcScope`, carrying cross-principal IPC routing solely
  for an identity capability the fork no longer supports. This was dead command and IPC-scope authority debt, not
  password disclosure, network egress, authentication bypass, a demonstrated privilege escalation, exploitation,
  or evidence of compromise.

  Source closure: the `core_main` handler is deleted and the scope classifier accepts only the separately retained
  `--option` management command. A focused regression proves that `--get-id` has no user-main-IPC scope;
  the shared verifier, Apple checker, semantic validator, deliberate mutations, R-SV5a, and Appendix C #177 bind
  both absences. Internal `Config::get_id()`/`ipc::get_id()` compatibility reads are not blanket-deleted in this
  slice: they remain side-effect-free metadata reads for separately audited consumers and are not a CLI identity
  capability. Exact Debian/Windows packaged-artifact absence remains part of the clean R-B2 build obligation;
  external review remains R-V3.

  Verification: exact Rust 1.75 locked/offline compilation and all five `core_main::tests` pass, including the
  focused obsolete-command scope regression. The focused shared R-SV5a shell gate and the Apple CLI structural
  group pass; the workspace semantic validator passes normally and against its complete deliberate source-mutation
  matrix, including independent handler, scope, regression, checker, requirement, Appendix, and ledger mutations.
  Dependency inventory is clean and all 103 inventory self-tests pass. Native-codec watch normal/self-test, Bash
  and Python syntax, requirements-digest synchronization, exact Rust 1.75 Rustfmt, and `git diff --check` pass.
  The full Apple target/build checker and exact release artifacts were not run in this narrow slice: the former is
  outside the no-long-build constraint and the latter remains R-B2. A diagnostic execution of the Apple checker's
  other, unrelated `b2` structural group reports a pre-existing stale `start_main_ipc` marker; only its independently
  emitted CLI group is claimed here and that group is clean.

  Two initial Cargo setups failed closed: one exposed a missing writable extraction destination for `base64`, and
  the next left rustc's `/tmp` on the read-only root. Neither was bypassed with root, a permission/ownership change,
  or a dependency fetch. The passing run used a tmpfs Cargo overlay over read-only re-extracted crate, registry, and
  Git inputs plus the prior user-owned compilation cache. All substantive checks ran as UID/GID 1000 in the existing
  immutable image with pulls and networking disabled, source and input caches read-only, the container root read-only,
  capabilities dropped, no-new-privileges, bounded pids, no published ports, and no Docker socket. No host RustDesk
  process, service, binary, configuration, listener, firewall, or host-network state was inspected or changed.
- **R-SV6a — account/control-plane compatibility surface deleted — SOURCE CLOSED/GATED;
  EXACT PACKAGED-ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Platforms: desktop assignment and Unix
  user-main-IPC selection; Rust/Flutter login metadata and Android/web deployment bridge surfaces. Boundary:
  operator argv and active-user IPC namespace ↔ deleted account server authority; stale local account cache ↔
  peer-visible profile metadata. After the account HTTP sinks were deleted, `--assign` still parsed a bearer token
  and address-book passwords from argv, assembled an account request body, and selected `UserMainIpcScope` for an
  installed-root Unix launch. Refusal-only deployment Rust/FFI/generated/web methods, API/audit/public-host/avatar
  resolvers, an unused session audit resolver, account-only built-in keys, and the stale `user_info` profile fallback
  also remained. The absent HTTP sinks prevented current account egress, so this was conceptual authority,
  credential-handling, cross-principal-routing, and future-reactivation debt—not a demonstrated request, local-to-root
  escalation, exploitation incident, or evidence of compromise.

  Authority model and source closure: this serverless direct-IP fork has no account control plane. The assignment
  handler and its IPC classification are deleted rather than refused. The deployment backend, Flutter FFI export,
  generated Rust wire functions, and authored web bridge method are absent. The API/custom-rendezvous/audit/public-
  host/avatar resolver cluster and account-only `register-device`/`allow-https-21114` keys are absent. Login avatar
  and display name come only from trimmed build-local options, with the local OS username as the display-name
  fallback; relative avatar text is never expanded into an API URL. Empty `api-server` and
  `custom-rendezvous-server` pins remain only as stale-value masking and defense in depth, with no resolver or
  actuator. The focused scope regression, shared Rust/Dart source gates, Apple source checker, R-SV6a, Appendix C
  #179, and independent semantic validator/mutations bind those absences. Exact current-commit packaged artifacts
  remain part of R-B2/R-B10; this slice does not claim them.

  Verification: exact Rust 1.75 locked/offline compilation passed both the focused `core_main::tests` group (five
  tests, including the option-only classifier and explicit `--assign` rejection) and a separate production
  `cargo check --lib --features linux-pkg-config`. Exact Rust 1.75 rustfmt accepts `config.rs`, `client.rs`,
  `common.rs`, `core_main.rs`, `ui_interface.rs`, and the directly edited `ipc.rs` with child formatting disabled;
  the deletion-only `flutter_ffi.rs`/`ui_session_interface.rs` hunks introduce no formatter output, while those two
  whole files retain the same unrelated parent-commit import-order/line-wrap drift recorded by prior slices. The
  shared account source gate, generated-shaped Dart absence gate, and Apple CLI structural group with deliberate
  handler/scope mutations pass. The independent semantic verifier passes normally and against its complete source-
  mutation matrix, including account handler, scope, Rust/FFI/web surface, local profile, config-key, shared/Dart/
  Apple checker, requirement, Appendix, and ledger mutations. Dependency inventory is clean and all 103 inventory
  self-tests pass; native-codec watch normal/self-test, Bash/Python syntax, synchronized requirements SHA-256, and
  `git diff --check` pass. A disposable Flutter Rust Bridge generation reached and produced all three primary Rust/
  Dart binding outputs with the deployment ABI absent; the legacy generator's subsequent Flutter artifact-preload
  phase could not complete against the deliberately read-only SDK, so no full Dart analyzer or exact generated-
  artifact claim is made here. Those remain in R-B2/R-B10.

  Failed setups stayed fail-closed: the first Cargo run had no Git checkout seed; the next reached the pre-existing
  root-owned unreadable `pin-utils` source; a first exact-rustfmt extraction exhausted an undersized tmpfs; and
  several disposable bridge runs exposed, in order, an unwritable destination, Rustup update scratch, missing Git
  seed, missing Rustfmt, and immutable Flutter cache writes. None was bypassed with root, permission/ownership
  changes, a dependency fetch, a mutable image build, or a host-source write. Passing compilation rebuilt a
  user-owned Cargo home from read-only `.crate`/Git seeds in tmpfs. Every substantive run used immutable image IDs as
  UID/GID 1000 with pulls/networking disabled, read-only source/root/seeds, all capabilities dropped,
  no-new-privileges, bounded pids/CPU/memory, disposable outputs, no published ports, and no Docker socket. Only the
  slice-owned stalled disposable bridge containers were stopped. No host RustDesk process, service, binary,
  configuration, listener, firewall, UFW/nftables/iptables state, or host-network state was inspected or changed.

- **R-SV6a-1 — logout and API-server presentation residue — SOURCE IMPLEMENTED/GATED;
  EXACT PACKAGED-ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Platforms: shared desktop IPC plus the Flutter and
  localization sources included by desktop, Android, iOS, and future Apple artifacts. Boundary: deleted account
  control plane ↔ local presentation/status compatibility. Upstream `UserModel.logOut({apiServer})` posted the
  local ID/UUID and bearer header to `$apiServer/api/logout`, then reset account/address-book state. History proves
  that `ee5bb33` removed the server-config-change caller, `bf0878d` removed the visible caller, `f90f197` removed
  the HTTP request but retained a caller-less reset stub, `d5aec5b` deleted the stub, and `3309b49` deleted the
  complete account model. Current Flutter/Android/iOS/Rust protocol source therefore had no logout operation,
  endpoint, caller, or account principal. A later typed main-IPC allowlist in `57bcb52` nevertheless admitted
  `MainStatusOptionKey::ApiServer` in both directions with no Dart consumer, while the template and all 49 full
  translation maps retained the caller-less `Logout` key. This was dead presentation/reactivation debt—not a
  current account request, egress path, authorization bypass, local-to-root path, privilege escalation, exploitation
  incident, host mutation, public listener, or evidence of compromise.

  Authority model and source closure: a binary with no account principal has no login/logout lifecycle and does not
  present an account-server address through IPC. `ApiServer` and both `OPTION_API_SERVER` mappings are removed from
  `MainStatusOptionKey`, so a desktop status/options message carrying `api-server` is unallowlisted and rejected.
  The dead `Logout` localization entry is deleted from the master and every translation map; authored/generated
  Flutter retains no `logOut`/`log_out`, `apiServer`, or `/api/logout` vocabulary. The
  `(OPTION_API_SERVER, "")` `PINNED_SETTINGS` entry deliberately remains: it masks stale persisted/default/signed-
  custom configuration at the central read/write funnel but is no longer an IPC presentation or mutation contract.

  Verification evidence and exact limitations before publication: the complete `scripts/dart-verify.sh` transaction
  passed with canonical offline closure
  `a7581f0ffa4fa924d4eacfe6c2bef9dec37a2ce2d06740c04037489341d904ac`, freshly generated Flutter Rust Bridge
  output, zero Flutter analyzer errors, all address/saved-peer/retired-role-swap tests, the exact locked/offline
  `flutter,unix-file-copy-paste` Rust library check, every Dart source gate including the expanded account/logout
  family, and an unchanged source worktree. The focused Rust allowlist regression then passed under the default
  library surface: 1 passed, 0 failed, 326 filtered. Its only accommodation was a container-tmpfs compatibility
  object delegating the old builder's missing libc `renameat2` wrapper to `SYS_renameat2`; it changed no repository
  or image bytes. The first two diagnostic attempts are not counted green: the checked-in stale generated bridge
  failed its expected ABI comparison when `flutter` was enabled without regeneration, and the non-Flutter test
  binary compiled but could not link until that old-glibc compatibility object was supplied.

  The shared and Apple exact source-gate blocks passed; the focused independent semantic validator passed normally
  and rejected all 17 declared deliberate reintroductions across IPC, authored/freshly-generated Flutter,
  localization, retained pin, gates,
  requirement, Appendix C #191, and ledger. Edited-shell Bash parsing, Python parsing, `git diff --check`, Rustfmt
  for `src/ipc.rs` with child modules excluded, and native-codec watch in normal and deliberate-mutation self-test
  modes passed. A whole-module Rustfmt diagnostic reported only pre-existing formatting differences in unchanged
  `src/ipc/auth.rs` and `src/ipc/fs.rs`; it did not report this slice's `src/ipc.rs` edit and is not counted as a
  whole-module pass. The full `scripts/verify.sh` transaction remains unavailable because its exact pinned
  dev-check image is absent, and the complete Apple script was deliberately not invoked because its preflight
  builds Docker images. This source slice does not claim the still-pending clean cold release, Apple artifacts,
  mobile on-device storage-key proof, refreshed advisory data, or R-V3 external review. No host RustDesk
  process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or host-network state was
  inspected or changed.

- **R-SV6b — dormant rendezvous/NAT compatibility authority deleted — SOURCE CLOSED/GATED;
  EXACT PACKAGED-ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Platforms: the shared Rust viewer and
  configuration source used by desktop, Android, iOS, and future Apple artifacts. Boundary: operator-supplied direct
  address ↔ viewer routing/login identity ↔ historical rendezvous configuration. R-SV6a stated that the empty
  `custom-rendezvous-server` policy pin had no resolver or actuator, but its gate inspected only the account resolver
  cluster in `src/common.rs`. The client still parsed `<id>@<server>`, retained `other_server`, conditionally persisted
  `other-server-key`, and rewrote login metadata through `Config::get_rendezvous_server()`. That resolver still
  selected policy, process, persisted, and fallback state, while `Config2` stored rendezvous-server, NAT-type, and
  migration-serial fields behind live accessors. `Client::_start` rejected the resulting non-direct address before any
  dial, so this was a dormant future-reactivation and authority-coherence defect—not a demonstrated network request,
  local-to-root path, privilege escalation, exploitation incident, or evidence of compromise.

  Authority model and source closure: the exact address accepted by the direct-address choke point is the sole routing
  input and login username. `LoginConfigHandler` now assigns that address without parsing cross-server grammar; the
  `other_server` field, public-server sentinel, persisted key, and conditional login rewrite are absent. The config
  resolver, process/fallback/timeout/registration constants, rendezvous default port, NAT/serial accessors, dead
  common wrapper, and Config2 fields are deleted. Historical TOML network fields are accepted only by serde's
  unknown-field behavior and are not serialized back; a focused regression proves that with nonempty/nondefault
  legacy values. The empty
  `custom-rendezvous-server` pin remains only as R-SV6a's stale-value mask and has no reader or actuator. This is the
  structural completion of R-X6's earlier key-stripping rule: there is no cross-server key field left to sanitize.

  Verification closure: focused hbb_common and shared-client Rust regressions bind legacy-field non-adoption and exact
  login identity. `scripts/verify.sh` gates the one-field Config2 schema, all deleted symbols, exact address/login
  assignment, both regressions, requirement, Appendix C #186, and this ledger. The Apple source checker applies the
  same shared-source contract, and the independent workspace semantic validator plus deliberate mutations bind the
  client state/parser/login path, config schema/resolver, dead wrapper, tests, both source gates, requirement,
  Appendix row, and ledger. Exact current-commit packaged artifacts remain R-B2/R-B10; the separately itemized Tier 4
  Dart presentation/formatting residue, installed-platform evidence, refreshed advisory data, independent image
  provenance, and R-V3 external review remain open. No host RustDesk process/service/binary/configuration/listener,
  firewall, UFW/nftables/iptables state, or host-network state was inspected or changed for this source slice.

- **R-SV6c — rendezvous peer-presence and compatibility status plane deleted — SOURCE CLOSED/GATED;
  EXACT PACKAGED-ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Platforms: shared Rust, desktop/Android/iOS Flutter,
  generated Flutter Rust Bridge, web compatibility implementation, and retained Apple source. Boundary: absent
  rendezvous presence authority ↔ saved-peer presentation ↔ separately retained local main-IPC status and direct
  listener reachability. Commit `d5aec5b` had already deleted the live `ONLINE` latency map, `Data::OnlineStatus`,
  `status_num`, mobile `_connectStatus`, peer-query backend/runner/FFI, peer online field/callback, Status sort,
  visibility tracking, invisible dot, and 300-ms polling loop. The Tier 4 itemized row nevertheless remained in its
  original open-finding form, the source gates covered only the old network send and one authored Dart call, and
  source scars plus `main_check_connect_status`/`OnlineStatusWidget` still described unrelated retained operations
  in the retired rendezvous vocabulary. Android and iOS also invoked that no-op desktop-main FFI at startup. This was
  a regression-boundary, cross-platform API, and audit-coherence defect—not a live rendezvous request, credential
  disclosure, local-to-root path, privilege escalation, exploitation incident, host mutation, public listener, or
  evidence of compromise.

  Authority model and source closure: no rendezvous authority means no saved-peer presence state, query, event,
  callback, polling, sort, dot, constant-false substitute, or compatibility alias exists. Obsolete explanatory scars
  are deleted. The independent retained worker is now `start_main_status_sync`/`sync_main_status`, exposed as the
  typed one-shot `main_start_status_sync`/`mainStartStatusSync`; it continues to consume only
  `get_main_status_snapshot` for local options, UI metadata, Windows file-transfer state, and connection-manager
  lifecycle. Dart invokes it only on native desktop, so Android/iOS/web do not attempt main-daemon synchronization.
  The controlled-side widget is `DirectListenerStatusWidget`; its green state still comes only from the actual
  `direct-listener-bound` fact, while `local-permanent-password-set` selects the actionable failure explanation.
  Video/session count and protobuf per-display availability remain separate typed facts.

  Verification closure: `scripts/verify.sh` gates the complete Rust absence inventory and positive typed worker;
  `scripts/dart-verify.sh` checks authored plus freshly generated Dart and the retained direct-listener facts; the
  Apple source checker binds the shared Rust deletion and ensures iOS inherits no peer-presence backend. The
  independent workspace semantic validator and deliberate mutations bind every source family, the desktop-only
  trigger, retained status semantics, all three gates, R-SV6c, Appendix C #187, and this ledger. Exact current-commit
  packaged artifacts remain R-B2/R-B10; installed-platform evidence, refreshed advisory data, independent image
  provenance, and R-V3 external review remain open. No host RustDesk process/service/binary/configuration/listener,
  firewall, UFW/nftables/iptables state, or host-network state was inspected or changed for this source slice.

- **R-SV6d — public/custom-rendezvous selection state deleted — SOURCE CLOSED/GATED;
  EXACT PACKAGED-ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Platforms: shared Rust, desktop/Android/iOS Flutter,
  generated Flutter Rust Bridge, web compatibility implementation, and retained Apple source. Boundary: the
  direct-only viewer's actual connection semantics ↔ a retired boolean that classified a nonexistent rendezvous
  deployment. History proves `d5aec5b` deleted `using_public_server`, `main_is_using_public_server`, the generated/
  web `mainIsUsingPublicServer` operation, and the saved-peer loop's 20-second-public/6-second-custom cadence choice;
  `9ff2ac1` then removed the last quality-policy dependency together with late relay/direct state and added the
  direct-only custom-quality regression. Current source already contained none of those live paths, but the Tier 4
  row still cited the former `src/common.rs:1133`, source gates did not bind this exact predicate/API family, and the
  custom-quality dialog retained an explanatory compatibility scar. This was misleading API, regression-boundary,
  and audit-coherence debt—not a live rendezvous request, credential disclosure, local-to-root path, privilege
  escalation, exploitation incident, host mutation, public listener, or evidence of compromise.

  Authority model and source closure: direct-address routing has no public/custom-server classification. No Rust
  predicate, FFI/generated/authored/web method, JavaScript compatibility key, constant result, renamed boolean, or
  explanatory source scar exists. The pinned-empty `custom-rendezvous-server` option remains only R-SV6a's stale
  persisted-value mask and has no classifier or actuator. The retained pre-login option builder carries configured
  custom quality/FPS under the unconditional direct policy, with no UI-feature compile guard and with the focused
  `180`/`90` regression proving no public/relay cap. The custom-quality dialog derives FPS and extended-quality
  availability only from the peer version. R-SV6c's saved-peer presence loop remains absent, so there is no
  public/custom polling cadence to select.

  Verification closure: `scripts/verify.sh` binds the complete Rust/API absence plus the positive direct-quality,
  version-only dialog, and no-cadence semantics and executes the UI-feature-independent direct-quality/FPS
  regression; `scripts/dart-verify.sh` checks authored and freshly generated Dart; the Apple source checker binds the
  shared Rust and Flutter closure. The independent workspace semantic validator
  and deliberate mutations bind every source family, both former-consumer outcomes, all three gates, R-SV6d,
  Appendix C #188, and this ledger. Exact current-commit packaged artifacts remain R-B2/R-B10; installed-platform
  evidence, refreshed advisory data, independent image provenance, and R-V3 external review remain open. No host
  RustDesk process/service/binary/configuration/listener, firewall, UFW/nftables/iptables state, or host-network state
  was inspected or changed for this source slice.

- **R-G9 — minimal presentation and compatibility serialization contracts — SOURCE CLOSED/GATED;
  EXACT PACKAGED-ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Platforms: shared Rust CM IPC and server
  connection code, desktop/Android/iOS Flutter presentation models, Android's foreground service consumer, and
  retained Apple source. Boundary: authenticated connection capability authority ↔ local CM presentation data; and
  deleted account/address-book provenance ↔ locally saved peer JSON. Source and history prove that
  `sameServer`/`same_server` had exactly one semantic consumer: the account/address-book `syncFromRecent` path
  deleted in `3309b49`. Current source had no producer or consumer, only parse/copy/reserialize plumbing. Separately,
  the server copied `restart`, `recording`, and `block_input` from the live `Connection` into `Data::Login`, then
  into the serialized CM `Client`; neither Flutter's controlled-side `Client.fromJson` nor Android
  `MainService` read those keys. This was dead compatibility-contract and future-reactivation debt—not a live
  permission bypass, network request, credential disclosure, local-to-root path, privilege escalation, exploitation
  incident, host mutation, public listener, or evidence of compromise.

  Authority model and source closure: the saved-peer DTO no longer declares, parses, copies, or serializes the
  cloud-provenance field; historical JSON containing `same_server` is ignored and a Flutter regression proves it is
  not serialized back. CM login IPC, `ConnectionManager::add_connection`, and the serialized CM `Client` no longer
  carry the three unread policy booleans. The authenticated server `Connection` remains their sole controlled-side
  authority: initialization still derives them from the pinned policy, `confine_capabilities_to_conn_type` removes
  them from narrower session types, restart and block-input remain gated at their native sinks, and the server still
  reports disabled values through `Permission::Restart`, `Permission::Recording`, and `Permission::BlockInput`.
  The viewer still consumes those permission messages and its retained actions remain permission-gated. R-G6's
  `forceAlwaysRelay` field/action was already absent and directly gated; it was not a current serialized field.

  Verification closure: the focused Rust serialization regression constructs both `Data::Login` and `Client`,
  proves the three keys are absent, and positively proves a consumed CM field remains. The focused Flutter
  regression feeds legacy `same_server` input and proves output omission. `scripts/verify.sh`,
  `scripts/dart-verify.sh`, and `scripts/apple-conform-check.sh` bind the negative DTO surfaces and positive live
  capability path. The independent workspace semantic validator and deliberate mutations cover each producer,
  consumer, regression, gate, R-G9, Appendix C #189, and this ledger. Exact current-commit native/platform package
  evidence, installed-device behavior, refreshed advisory data, independently archived verifier-image provenance,
  and R-V3 external review remain open under their existing rows. No host RustDesk process, service, binary,
  configuration, listener, firewall, UFW/nftables/iptables state, or host-network state was inspected or changed for
  this source slice.

- **R-G4a — switch-sides role-swap compatibility state excision — SOURCE CLOSED/GATED;
  EXACT PACKAGED-ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Platforms: shared viewer/server Rust,
  desktop/Android/iOS Flutter presentation, generated Flutter Rust Bridge, and retained Apple source. Boundary: the
  deleted switch-sides/session-role transition ↔ compatibility state and local CM presentation. History proves the
  removal was intentionally staged: `79c261d` deleted the Flutter triggers, confirmation, switch-back listener, and
  CM button; `2bdd516` deleted the FRB operations; `9d617e7` deleted Rust orchestration but explicitly deferred the
  lower-case Sciter compatibility surface; `f8717e7` deleted the wire messages and responder, with the historical
  true assignment to `from_switch`, while its case-sensitive gate still deferred lower-case names; `0d2c882`
  deleted Sciter; and `d5aec5b` deleted the empty `switch_sides()` stub. Current source nevertheless still accepted
  and stored an unread viewer `switch_uuid`, initialized the server `from_switch` flag only to false, serialized that
  flag through CM IPC and Rust/Flutter controlled-client DTOs, and exposed a `switch_back` trait/event with no Dart
  listener. This was misleading compatibility API/state and future-reactivation debt—not a current authorization
  bypass, network request, credential disclosure, local-to-root path, privilege escalation, exploitation incident,
  host mutation, public listener, or evidence of compromise.

  Authority model and source closure: this fork has no switch-sides role transition. `LoginConfigHandler` has no
  switch UUID; the server `Connection` has no role-switch flag; local CM `Data::Login`, serialized Rust `Client`, and
  Flutter `Client` carry no role-switch state; and `InvokeUiSession`/`FlutterHandler` expose no switch-back callback
  or event. Historical Flutter CM JSON containing `from_switch` is ignored and never serialized back. The deletion
  does not substitute a new authority: `self.authorized = true` remains a single assignment at the CPace-keyed
  authorization edge, while ordinary consumed CM capability facts such as `keyboard` remain serialized and tested.

  Verification closure: the focused Rust serialization regression proves `from_switch` absent from both local CM
  payloads while positively retaining `keyboard`; the focused Flutter regression feeds historical `from_switch`
  input and proves output omission. `scripts/verify.sh`, `scripts/dart-verify.sh`, and
  `scripts/apple-conform-check.sh` bind the production Rust, authored/generated Dart, serialization regressions,
  sole authorization assignment, R-G4a, Appendix C #190, and this ledger. The independent workspace semantic
  validator and deliberate mutations cover every state/API source family and all three gates. Exact current-commit
  native/platform package evidence, installed-device behavior, refreshed advisory data, independently archived
  verifier-image provenance, and R-V3 external review remain open under their existing rows. No host RustDesk
  process, service, binary, configuration, listener, firewall, UFW/nftables/iptables state, or host-network state was
  inspected or changed for this source slice.

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
  committed only by the LocalSystem service through a typed elevated `_service` request and, after R-S11e-23,
  stored only in the current MSI product's exact 64-bit package namespace; service identity/salt
  reads are side-effect-free after R-S11b-3e; desktop at-rest wrapper reads no longer mint key material after
  R-S11b-3f; trust-anchor/proxy-shaped option keys are pinned empty after R-S11b-3g, and the structured proxy
  credential store plus alternate transport are deleted after R-S11b-3j; whole-map option reads
  (`Config::get_options`, the UI cache, CLI `--option`, and `MainIpcRequest::StatusSnapshot`) now overlay
  `PINNED_SETTINGS` last after R-S11b-3i, so broad reads cannot surface stale default/stored/signed-custom
  values for pinned policy keys; and the main IPC mutation
  policy is exhaustive after R-S11b-3h, with no wildcard arm that could admit a future
  identity/salt/key/proxy/trust-store write without an explicit receiver-authorized gate.
**Contained hardening items from the same audit:**
- **R-S11c-6 — Windows named-pipe endpoint hardening.** Platform: Windows desktop. Endpoint:
  predictable `\\.\pipe\<APP>\query{postfix}` names and broad/default permissions across production listeners.
  Boundary: local process ↔ IPC endpoint identity. Attack surface: pipe squatting, spoofing/confusion, or
  denial of service even where message auth blocks higher impact. Current state: every production Windows listener,
  including `_cm` and the strictly formed token-derived whiteboard endpoint, builds
  an explicit SDDL DACL: LocalSystem can create/own service-side pipe instances; a non-System user-owned
  server gets its own logon/user SID for server-instance creation; the active session identity gets only the
  client read/write/synchronize mask and not `FILE_CREATE_PIPE_INSTANCE`; `Everyone` and the Administrators
  group are absent from the base DACL. Windows clients open the pipe with that explicit non-generic mask and
  verify the connected server PID/executable, with `_service` additionally requiring a LocalSystem server.
  The long-lived `_service` listener is recreated on active-session changes so its DACL and the runtime
  expected-session check do not drift. Unknown listener postfixes fail closed instead of receiving Windows' default
  descriptor. Status: closed for the named-pipe endpoint boundary.
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
  desktop-discovery cluster with `users` + direct `/proc` reads and a source gate; later R-S11e-42/R-S11e-43 delete
  its obsolete Xorg endpoint/credential and subprocess-classification paths. R-S11c-10b closes the remaining
  CM/Xorg/tray shell cleanup pipelines with direct `/proc` parsing and signals; R-S11e-43 subsequently deletes the
  Xorg signal path rather than treating process text as ownership. Its historical `/proc`-selected global server
  cleanup is likewise deleted, not retained as authority, by R-S11c-27a.
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
  the then-present root-to-user `sudo` transition, `env` fallback, `w`, `xrandr`, `xdg-screensaver`, and `systemctl`
  resolve only trusted fixed `/usr/bin`/`/bin` candidates and now execute the trusted canonical target after
  candidate-parent, canonical-parent, root-owned, non-writable, and executable-bit checks; the then-present `--cm`
  detection was `/proc`/current-exe/argv-backed instead of `ps` before R-S11e-45 deleted that lifecycle heuristic;
  and the X11
  socket fallback read `/tmp/.X11-unix` socket metadata plus passwd ownership instead of parsing `ls`. R-S11e-42
  later deletes both `w` and the X11 socket fallback because helper provenance and native metadata did not make
  either source authoritative for the already-selected logind session.
  R-S11c-10l first replaced Linux `--server` tray cleanup's PATH-selected `pkill -f` with exact executable/argv
  selection. R-S11e-45 completes the authority correction by deleting process-table tray signaling entirely:
  `--server` starts a tray candidate, and the `--tray` receiver's same-UID singleton check decides whether that new
  helper should run without signaling any pre-existing process.
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
  rejects unexpected entries, nested control directories, every symlink except the exact package-owned relative data
  symlink `/usr/bin/rustdesk -> ../share/rustdesk/rustdesk`, special files, and hardlinked regular files, then
  makes every directory `0755`, the root/root primary runner `0755`, its byte-identical root/root service-child
  image `0711`, `startwm.sh` and the other executable data files `0755`, all other data and ordinary control files
  `0644`, and all maintainer scripts `0755`. One
  `subprocess.run(..., check=True)` argv boundary invokes
  `dpkg-deb --root-owner-group -b`; AST validation admits only that archiver and the exact PE canonicalizer process,
  pins the complete top-level import inventory, rejects decorators, direct and re-exported alternate process-launch
  members, callable aliases, direct stores, dynamic namespace/evaluation APIs, function/module/frame namespace reach,
  and explicit early termination, and requires every package authority's loaded name/code origin to match its sole
  synchronous top-level definition. It resolves concatenated, joined, and interpolated constant strings, requires exact
  shell-wrapper and FFI-helper bodies, the four-function shell-call ownership inventory, and the exact 27-statement
  Flutter pre-control-staging program, including the exact service-child byte copy and sole command-symlink constructor,
  requires contiguous reachable direct staging/finalization/archive operations, and permits only the exact
  cleanup/versioned-rename/chdir publication tail afterward. The release
  wrapper validates the emitted archive and locale-independent exact extracted-script metadata before hashing it. The
  independent verifier reads raw tar headers and rejects duplicate, absolute, traversing, extended, parser-normalized,
  root-alias, wrong-prefix, wrong-trailing-slash, alternate regular/contiguous/sparse typeflags, nonempty regular-file
  link names, non-root owner names, nonzero name/linkname/uname/gname/prefix padding, or otherwise non-canonical
  members; requires exact data/control/conffile/md5 inventories, including exactly that one data symlink while
  excluding it from `md5sums`; and checks every member's numeric ownership, raw type, and mode.
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

**R-B2 verifier fixture primary-error preservation — CLOSED / GATED (2026-07-19).** The verifier's
descriptor-owned `ScratchRoot.directory` context previously raised an edge/cleanup error from its `finally` block
without retaining an exception already raised by the fixture body. That contradicted the release contract that
cleanup uncertainty augments rather than replaces the original failure. It also made an execution-environment
failure before managed-child launch look like a descriptor-routing defect: a numeric UID without a passwd entry
first failed at `pwd.getpwuid`, and a later user-systemd access attempt failed before unit creation, but the live-edge
fixture reported only `scratch replacement fixture missed the descriptor-owned directory` and final scratch state.
This was verifier failure-classification and evidence-integrity debt, not a shipped RustDesk runtime or privilege-
escalation path.

`ScratchRoot.directory` now captures the body exception, accumulates exact-tree removal, descriptor close, and
post-cleanup scratch-authority failures independently, and reports them through the shared
`report_cleanup_failures` contract. Successful exact cleanup still removes the owned tree; an edge replacement,
mount/identity uncertainty, descriptor-close error, or postcondition failure remains fatal and is never repaired.
When cleanup also fails, the body exception remains primary and the complete cleanup failure is attached as a
secondary note. A missing current-principal passwd entry is now an explicit verifier failure rather than a raw
`KeyError`; ambient `HOME` is not accepted as authority. A dedicated behavioral fixture renames the live child,
installs an empty replacement, injects a distinct body failure, requires that exact failure plus the exact
changed-edge cleanup note, proves both ambiguous directory identities and inventories remained unchanged, and only
then independently restores and removes the recorded edges. The semantic verifier binds the primary-error capture,
cleanup accumulator, note proof, fixture dispatch, and independent weakening mutations.

Focused non-root, network-disabled, capability-free, no-new-privileges containers pass Python parsing, normal
semantic verification, the exact primary/secondary-error behavioral fixture, and the complete independently invoked
source-mutation matrix. The broad executable self-test is not promoted as passing in this execution model: its
managed-command stages intentionally require a real same-principal systemd user scope, while `systemctl --user`
from the diagnostic container was rejected with `No data available` before transient-unit creation. The earlier
misdiagnosis is closed; exact managed-scope execution remains an environment prerequisite rather than being
skipped, emulated, or weakened.

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
  replaces the unstretched hash; no offline-crackable material (R-S6); desktop
  at-rest storage remains the Appendix C #14 machine-UUID HARDEN+ACCEPT residual,
  while mobile source now uses OS-protected storage keys with on-device/artifact
  validation still pending.
- **client AiTM (cert-validation on retry)** (`30794`) → insecure-TLS-fallback
  excised, pinned `N`.
- **`CVE-2026-58056` session-type-confusion** (a FileTransfer-authorized peer
  injecting keyboard/mouse + reaching screenshot/display handlers) → **covered by
  R-S19 AuthConnType confinement, not by broad PAKE authorization alone**. PAKE
  keeps the class out of the unauthenticated-network/password-bypass bucket: a
  peer still needs the CPace password and remains the §2 trusted owner. That does
  not make session type an inert tag. R-S19 now treats session-type confinement as
  normative least-privilege: input is Remote-only; desktop capture is
  Remote-or-ViewCamera; capability booleans are derived from `AuthConnType`
  before peer login options; clipboard text, voice/audio, block-input, privacy,
  restart, screenshot-source, viewer-clipboard, CLIPRDR-to-CM, and Android
  MediaProjection edge cases are independently gated. The live evidence is the
  R-S19 status block above, the `connection.rs`/`video_service.rs`/viewer/mobile
  source gates, and the generalized `scripts/verify.sh` R-S19/CVE-2026-58056
  checks.
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
  2026-07-16; SOURCE/RUNTIME/RELEASE-GATE IMPLEMENTED THROUGH R-S11c-27s; EXACT COLD
  ARTIFACT EXECUTION PENDING.** The process-name/text-based server cleanup replacement is
  implemented in source, runtime, package, and release-gate form by R-S11c-27a–s below:
  the service-child authority is the init-system-independent ownership protocol, not
  process-name discovery. The parent release item remains open only because the exact
  clean committed cold transaction has not yet emitted the bound final `.deb` lifecycle
  marker and full R-B2 manifest. This item remains explicitly **not authorization to stop,
  restart, upgrade, reconfigure, or otherwise disturb the currently deployed host service**,
  which is operationally running an older release.

  - **R-S11c-27a — direct Linux service-child ownership and supervisor-death binding — SOURCE IMPLEMENTED
    2026-07-16; PARENT ITEM REMAINS OPEN.** This coherent first slice replaces server process-table authority
    on the live supervisor path. `try_start_server_()` retains an `OwnedServiceChild` containing the final
    RustDesk `Child`; there is no `sudo`, `env`, or `run_me` wrapper between the supervisor and server. Root
    children launch `/proc/self/exe` directly, while active-desktop children use the same descriptor-bound
    executable object across the credential transition as completed and behavior-tested by R-S11c-27h below.
    For an active desktop, the parent resolves the exact passwd identity
    and supplementary groups before `fork`, clears the inherited root environment, supplies only the bounded
    session environment, and performs raw `setgroups` → `setresgid` → `setresuid` syscalls in the pre-exec
    hook. It then sets irreversible `PR_SET_NO_NEW_PRIVS`, preventing the final `exec` (and later descendants)
    from reacquiring setuid/setgid or file-capability privilege. The same hook arms `PR_SET_PDEATHSIG(SIGKILL)`
    and immediately verifies `getppid()` against the expected supervisor, closing the set-after-parent-exit race.
    Because Linux may clear the setting while executing a privileged/capability-bearing file, the final
    service-owned `--server` image re-arms and revalidates it before starting server state. Normal replacement
    and service shutdown send `SIGTERM` to the retained child and act only on that same `Child`; R-S11c-27c below
    now bounds both the graceful and forced reap phases. Abnormal supervisor death uses the kernel binding to stop its
    exact child independently of any init system. Ordinary portable/user-owned `--server` launches do not carry
    the service marker and do not enter this path. The old `stop_rustdesk_servers()`/`force_stop_server()` global sweep and every
    `kill_current_exe_processes_with_arg("--server", ...)` call are deleted, so another installation, smoke
    process, portable server, or container is not selected by visible path text or argv. Verification:
    `r_s11c27a_linux_service_child_parent_death_kills_owned_child` uses an exec-chained supervisor/worker plus
    `pidfd` to behavior-test the actual post-exec kernel helper, and `scripts/verify.sh` binds the direct-child,
    native credential drop, pre/post-exec parent-death checks, bounded exact-child termination, environment
    clearing, and no-server-sweep source shape.

  - **R-S11c-27b — durable Linux service-child record and pidfd-first crash recovery — SOURCE IMPLEMENTED
    2026-07-16; PARENT ITEM REMAINS OPEN.** The service now acquires one close-on-exec, nonblocking exclusive
    `flock` lease in a descriptor-opened `/run/rustdesk` directory whose opened inode must be a root-owned
    mode-0700 directory. A second installed/manual supervisor fails before it starts IPC or a child. Each
    supervisor obtains a fresh canonical generation UUID from the kernel and passes it only in the cleared
    service-child environment. After `Command::spawn()` has completed the real privilege-drop/exec boundary,
    the supervisor reads the exact child's `/proc` identity and refuses registration unless UID, boot ID,
    start time, executable device/inode, exact three-element service role, and unique generation entry all
    agree. It then writes the bounded, versioned, strict-order record to a newly-created root-owned mode-0600
    temporary inode, `fsync`s it, publishes with `renameat2(RENAME_NOREPLACE)` (atomic `renameat` compatibility
    fallback under the exclusive lease), and `fsync`s the directory. Existing, malformed, linked, mis-owned,
    mis-moded, overlong, noncanonical, or wrong-role records are never overwritten. Normal replacement and
    stop still act only on the retained direct `Child`; record removal occurs only after that child is reaped
    and only when the parsed record equals the retained identity.

    Crash recovery is a separate pre-loop path. Missing evidence logs and signals nothing. A valid record from
    another boot or an absent/exited PID is reported stale and removed without signaling. On Linux 5.3+ the
    new supervisor first opens `pidfd_open(2)`, then immediately before `SIGTERM` revalidates current boot ID,
    `/proc/<pid>/stat` field 22 both before and after the inspection, `/proc/<pid>` UID, dereferenced
    `/proc/<pid>/exe` device/inode (so path replacement, deletion, and mount-namespace pathname aliases do not
    weaken identity), exact role argv, and the generation environment entry. Bounded exit polling occurs on
    the pidfd itself. A still-live child is fully revalidated again before pidfd-bound `SIGKILL`; any mismatch
    or unreadable live identity signals nothing further, preserves the record, fails `--service` nonzero, and
    lets the init supervisor report/retry rather than starting a second child. Pre-5.3 kernels use the same
    full revalidation immediately before each `kill(2)` and during the bounded waits; the diagnostic explicitly
    records that the final check-to-kill PID-reuse race cannot be eliminated without pidfds. This is a
    compatibility fallback, not an assurance-equivalent claim. The systemd unit creates the identical
    root-only runtime directory, preserves crash evidence across automatic restart, admits the pidfd/atomic
    publication syscalls through its allowlist, and retains `KillMode=control-group` only as an additional
    containment layer. The design follows the Linux `pidfd_open(2)`, `pidfd_send_signal(2)`, `proc_pid_stat(5)`,
    `proc_pid_exe(5)`, `flock(2)`, `openat(2)`, and `renameat2(2)` contracts. Focused tests prove strict record
    rejection, exact role/generation matching, mode-0600 no-replace publication, preservation on wrong-record
    removal/publication, and the earlier real post-exec parent-death behavior; `scripts/verify.sh` binds those
    tests and the recovery/source/unit shape. The syscall implementation adds 23 reviewed lexical `unsafe {`
    blocks; after the later R-S11e-36 Windows privacy-broker closure, the current machine inventory is 851 across
    251 tracked Rust files/73 nonzero files, with the added deterministic Windows resource producer containing no
    lexical unsafe block and per-file-count digest
    `9fca7dae635a8c456a8da3ccfd0d8b150936f2ef1c3d80ce687eb84f5ae450bc`.

  - **R-S11c-27c — bounded direct-child graceful/forced termination — SOURCE IMPLEMENTED
    2026-07-16; PARENT ITEM REMAINS OPEN.** The direct-child stop helper no longer consumes its
    `OwnedServiceChild` before it has proof of reap and no longer follows `Child::kill()` with an unbounded
    `Child::wait()`. It borrows the owning `Option`, sends `SIGTERM` to the retained exact child, polls
    `try_wait()` for at most eight seconds, then sends `SIGKILL` through that same `Child` and polls for at most
    a second eight-second interval. The durable record and direct `Child` ownership are released only after
    successful reap and exact record removal. A wait error, failed KILL followed by an expired wait, or a target
    still unreaped at the forced deadline preserves both authorities and returns an error. `stop_server()`, the
    replacement decision, every loop transition, and final shutdown now propagate that error out of
    `start_os_service()`, so an uncertain old child cannot be followed by a replacement launch or reported as a
    clean service exit.

    The focused pinned-container behavior test execs the real test image as the retained worker twice: the first
    child takes the default graceful `SIGTERM` exit, while the second is first placed in a kernel-stopped state so
    TERM cannot complete and the exact-child KILL/reap branch is required. Both paths must finish inside their
    explicit test deadlines, release direct ownership, and remove only the matching durable record.
    `scripts/verify.sh` additionally rejects an unbounded `process.wait()` in this helper, requires ownership to be
    taken only after exact record removal, and binds error propagation before replacement. This decision follows
    Rust's `std::process::Child` contract (there is no `Drop` cleanup; `try_wait` is the nonblocking exit/reap
    observation) and Linux `kill(2)`, `wait(2)`, and `signal(7)` (signal delivery is not reap; `WNOHANG` reports a
    still-running child without blocking; SIGKILL cannot be caught, blocked, or ignored). It adds no unsafe block
    and leaves the settled lexical unsafe inventory unchanged.

    This is source and focused behavior closure for the direct-child stop primitive, not the installed release
    matrix. Real installed/package-managed graceful restart/stop remain mandatory alongside crash/restart,
    hostile record/file/PID cases, non-root/portable and container noninterference, the actual privilege-drop chain,
    pre-pidfd runtime exercise, and SysV/OpenRC/runit/manual/non-systemd packaging proof. The parent item and upcoming
    release therefore remain **OPEN**.

  - **R-S11c-27d — isolated Linux supervisor-crash/restart recovery behavior — SOURCE/FOCUSED BEHAVIOR
    IMPLEMENTED 2026-07-16; PARENT ITEM REMAINS OPEN.** The pinned Linux test now crosses the previously separate
    parent-death and durable-record paths without using `/run/rustdesk`, root, service IPC, or any pre-existing PID.
    A mode-0700 private runtime uses the same close-on-exec, nonblocking exclusive `flock` helper as production. One
    test supervisor launches a post-exec BusyBox `yes` fixture with exactly three kernel-visible argv elements
    (`yes`, `--server`, `--service-owned-server`), the real generation environment, and the production
    no-new-privileges/parent-death pre-exec hook; it then publishes the production record. A concurrent contender
    must fail the live lease. The test kills that supervisor, observes the exact child exit on its retained pidfd,
    then starts a fresh test process which must acquire the released lease, run the production recovery path, and
    remove only the exited exact record. BusyBox is a dev-check-image fixture only and is not a runtime or release
    dependency.

    The same test then behavior-checks the recovery decision in both directions. A live process with exact service
    argv and generation is left alive and its record preserved when the structurally valid evidence carries a
    different start time (the PID-reuse shape), a different executable inode despite identical argv, or a different
    generation; a malformed-role record is likewise preserved byte-for-byte and signals nothing. Finally, the
    unmodified exact record authorizes pidfd-bound recovery of that one live fixture and exact record removal. The
    behavior follows the Linux `PR_SET_PDEATHSIG`, `flock(2)`, `pidfd_open(2)`, `pidfd_send_signal(2)`,
    `proc_pid_stat(5)`, and `proc_pid_exe(5)` contracts. `scripts/verify.sh` runs the test and source-gates its lease
    conflict, post-exec crash, fresh-process recovery, hostile-evidence survival, and exact-match positive branch.
    The production syscall shape is unchanged and the settled lexical unsafe inventory remains unchanged.

    This slice by itself is not installed lifecycle or release evidence. At this point in the sequence, the real
    RustDesk privilege-drop/exec chain, forced PID reuse, cross-mount/container inode cases, non-root/portable
    coexistence, pre-pidfd runtime fallback, non-systemd packaging, and concurrent Docker survival remained in the
    parent matrix. Later slices below supply all of those cases except actual forced numeric-PID reuse and the still
    open packaging/release variants; R-S11c-27n specifically supplies the cross-mount/container case.

  - **R-S11c-27e — executable-object replacement/deletion recovery behavior — SOURCE/FOCUSED BEHAVIOR
    IMPLEMENTED 2026-07-16; PARENT ITEM REMAINS OPEN.** The pinned Linux test replaces the synthetic changed-inode
    shape with live filesystem and process evidence in a mode-0700 private runtime. It copies the BusyBox fixture to
    two distinct regular executable inodes, launches the first with exact service role argv and generation, and
    records its production `/proc` identity. While that process remains live, the test atomically renames the second
    inode over the first process's launch pathname. Dereferenced `/proc/<pid>/exe` must retain the original recorded
    device/inode even though its diagnostic link text now ends in ` (deleted)`.

    The replacement inode is then launched from the same pathname with byte-for-byte identical role argv and
    generation. A structurally valid record carrying the replacement process's PID/start time/UID/generation but the
    original process's real device/inode must fail production recovery for executable-identity mismatch, remain on
    disk, and leave both processes alive. The exact original record must subsequently recover only the original
    executable object while the replacement process survives. A third exact-role fixture is recorded and directly
    unlinked; its procfs executable object must retain the recorded device/inode and exact recovery must terminate
    only that object, again leaving the replacement process alive. This follows the Linux `rename(2)`, `unlink(2)`,
    procfs magic-link, `proc_pid_exe(5)`, `pidfd_open(2)`, and `pidfd_send_signal(2)` contracts and proves that neither
    the pathname text nor exact argv is signal authority. `scripts/verify.sh` runs the behavior and source-gates the
    real replacement, real unlink, cross-object negative record, record preservation, sentinel survival at every
    recovery decision, and both exact positive branches. No production API/syscall or unsafe inventory changed.

    This slice is same-mount private-runtime behavior, not an installed package-update transaction, cross-mount or
    mount-namespace proof, an identical in-container pathname case, or forced PID reuse. R-S11c-27n below supplies
    the cross-mount/mount-namespace and identical-path cases; actual forced numeric-PID reuse and the remaining
    packaging/release matrix remain **OPEN**.

  - **R-S11c-27f — actual-binary manual/non-systemd supervisor lifecycle behavior — SOURCE/RUNTIME IMPLEMENTED
    2026-07-16; PARENT ITEM REMAINS OPEN.** Baseline execution of the real debug `rustdesk --service` binary in a
    fresh no-network, no-published-port container exposed a production lifecycle defect that the earlier synthetic
    child tests could not: normal pidfd-bound `SIGTERM` killed the supervisor itself with status 143. Its
    `ctrlc::set_handler` covered `SIGINT` only under the prior dependency feature set, so final exact-child
    termination, reap, durable-record removal, and the service `Exit` record never ran. `PR_SET_PDEATHSIG(SIGKILL)`
    still prevented an orphan, but that crash containment was not a graceful manual or systemd stop.

    The pinned `ctrlc` dependency now enables its Unix `termination` feature, under which the one supervisor handler
    receives `SIGINT`, `SIGTERM`, and `SIGHUP`. Handler-registration failure propagates from `start_os_service()`
    before runtime-directory acquisition instead of being printed and ignored; the handler changes only the owned
    loop's `AtomicBool`, after which the existing final `terminate_child()` calls remain the sole child authority.
    The direct `--server` image no longer installs a second process-wide `ctrlc` handler that could preempt its Tokio
    R-T9 drain. Its modifier/key-release cleanup instead runs inside `finish_graceful_shutdown()`, after the bounded
    session drain and local-IPC shutdown and immediately before the terminal success record/process exit. This
    introduces no new dependency package, production syscall, or lexical `unsafe {` block; after the separate
    deterministic Windows resource-producer addition, R-S11e-28 descriptor closure, and R-S11e-29 helper-launch
    descriptor hook, and the later R-S11e-36 Windows privacy-broker closure, the current inventory is 851 across 251
    tracked Rust files/73 nonzero files.

    `scripts/smoke-service-lifecycle.sh` is a mandatory `scripts/smoke-server.sh` stage, invoked from a read-only
    source mount in a `--network none` container. A strict root-owned `loginctl` fixture admits exactly one active
    root X11 seat and rejects every unknown argv, allowing the unmodified production desktop-discovery and service
    launch path to run without a test-only production knob. For every generation the stage strictly parses the
    root-owned mode-0600 record, verifies boot/start/executable/UID/generation fields against procfs, requires exact
    `/proc/self/exe`, `--server`, `--service-owned-server` argv, launch-parent/generation environment bindings,
    direct PPID, root UID, `NoNewPrivs: 1`, and a successful typed parked-IPC transaction. Supervisor stop is sent
    only through its retained PID/start identity and a pidfd. Two complete launches must terminate the child at exit
    status 0, reap it, remove the exact record, exit the supervisor at status 0, and produce distinct child and
    generation identities. A third child is placed in the real kernel-stopped state through a pidfd; supervisor
    `SIGTERM` must then take at least 7.5 seconds but no more than 20 seconds, log the eight-second graceful timeout,
    send KILL only to its retained child, reap signal 9, remove the record, and exit 0. The clean rerun observed
    8.156 seconds.

    In the same namespace a copied, root-owned executable is descriptor-execed with neutral argv as UID 4000 after
    supplementary groups and all inheritable/ambient/bounding capabilities are removed and `NoNewPrivs` is set.
    Its exact `rd-smoke-server`, `--server` role has no service environment marker and its typed UID-scoped parked
    IPC remains live through both normal generations and forced escalation, proving the service never selects an
    unrelated portable server. Readiness failures are now terminal (`exit 1` rather than a return that Bash could
    continue when the checker is used in a conditional); stable-log pinning and the readiness self-test close the
    evidence race observed while developing this stage. The production fix follows the pinned crate's termination
    contract plus Linux `kill(2)`, `wait(2)`, `signal(7)`, and pidfd contracts: signal delivery is not reap, exact
    child resources are released only by wait, and stopped tasks cannot handle TERM while KILL cannot be caught,
    blocked, or ignored.

    This closes actual-binary manually supervised normal-stop/restart, real stopped-child escalation, and non-root
    portable coexistence behavior. This slice is not an installed package transaction, installed
    systemd/SysV/OpenRC/runit integration, Debian-without-systemd proof, pre-pidfd runtime proof, forced PID reuse,
    broader malformed/stale-record proof, the non-root active-desktop credential-drop branch,
    cross-mount/namespace/container inode replacement, or concurrent separate-Docker survival. Later slices below
    supply all of those cases except actual forced numeric-PID reuse and the still-open OpenRC/runit/manual and
    release variants; R-S11c-27n specifically supplies the cross-container case.

  - **R-S11c-27g — actual-binary manual supervisor crash/restart recovery behavior — SOURCE/RUNTIME IMPLEMENTED
    2026-07-17; PARENT ITEM REMAINS OPEN.** The same mandatory no-network, read-only-source lifecycle stage now
    crosses abrupt supervisor death and production recovery with the real debug `rustdesk --service` image. Before
    the crash it opens pidfds for both the supervisor and its strictly validated service child, rechecks each retained
    `/proc/<pid>/stat` start identity, then sends `SIGKILL` only through the supervisor pidfd. The child pidfd must
    become readable within ten seconds and the same PID/start identity must no longer be running; the observed
    development run completed that kernel parent-death transition in 3 ms. The supervisor must reap from the harness
    with status 137 rather than reporting a graceful exit.

    The stage captures the root-owned mode-0600 record's device/inode/owner/mode/link-count/size tuple and SHA-256
    before the crash. After both exact processes exit, that same record identity and byte hash must still exist,
    proving the abrupt path preserved its durable crash evidence rather than silently cleaning or replacing it. The
    unrelated capability-free UID-4000 portable server is strictly revalidated before and after the crash. A fresh
    real supervisor is then launched while the stale bytes still exist. It must acquire the released close-on-exec
    lease, log production classification of the old child as exited or absent without signaling, remove only the
    exact stale record, publish a different record hash for a distinct child/start identity tuple and generation, and
    reach a successful typed parked-IPC transaction. That new generation must subsequently take the normal exact-child graceful
    shutdown path, while the portable server remains live through recovery and stops cleanly only when the harness
    explicitly targets its retained identity.

    The behavior matches Linux `PR_SET_PDEATHSIG` (parent-thread death delivers the configured process-directed
    signal; credential changes or privileged exec can clear it, which is why production arms after the drop and
    re-arms in the final image), `flock(2)` (the lease is released when all references to its open file description
    close; `O_CLOEXEC` prevents the service child retaining it), and pidfd polling/signaling (a stable task reference
    becomes readable on exit and avoids numeric-PID reuse). An initially over-specific harness assertion expected a
    new durable record to have a different inode number; runtime correctly demonstrated immediate filesystem inode
    reuse. That invalid assertion was removed. The valid transition proof is unchanged old metadata plus old hash
    before recovery, followed by a different strict record hash and generation after recovery. This slice changes no
    production Rust code, dependency, syscall, or lexical unsafe inventory.

    This closes the real-binary manually supervised crash/restart case only. This slice is not installed
    service-manager or package-update evidence, and it does not cover hostile malformed records, forced PID reuse,
    the installed privilege-drop chain, pre-pidfd fallback, cross-mount/container namespace identity, Debian
    non-systemd init integration, or concurrent separate-Docker survival. Later slices below supply those cases
    other than actual forced numeric-PID reuse and the still-open packaging/release variants; R-S11c-27n supplies the
    cross-container case. The parent item and upcoming release remain **OPEN**.

  - **R-S11c-27h — actual-binary non-root active-desktop privilege-drop/exec behavior — SOURCE/RUNTIME IMPLEMENTED
    2026-07-17; PARENT ITEM REMAINS OPEN.** The mandatory no-network lifecycle stage now changes its trusted fixed
    `loginctl` fixture from root X11 seat0 to a real passwd-backed `rdseat` X11 seat with UID/GID 4001 and a distinct
    supplementary group 4101, while the unrelated capability-free UID-4000 portable server remains live. This drives
    the production `Desktop::refresh()` and `ServiceChildCredentials::resolve()` branch in the actual debug
    `rustdesk --service` binary rather than substituting a unit helper or a test-only Rust entry point.

    The first baseline execution found a production defect: `Command` runs `pre_exec` before `execve`, and after
    `setresuid(4001, 4001, 4001)` resets process dumpability, the child could no longer dereference its configured
    `/proc/self/exe` through procfs's ptrace credential check; every launch failed with `EACCES`. Production now opens
    the supervisor's exact executable object while still privileged, keeps that descriptor `FD_CLOEXEC` in the
    multithreaded parent, and names `/proc/self/fd/<N>` only for the credential-dropping child. The fork-only raw
    pre-exec sequence performs `setgroups` → `setresgid` → `setresuid`, clears `FD_CLOEXEC` on that one descriptor,
    sets `PR_SET_NO_NEW_PRIVS`, and arms the parent-death signal. The final image validates a dedicated descriptor
    environment binding and immediately closes the descriptor before re-arming parent liveness. Root children retain
    the prior `/proc/self/exe` path. This preserves executable device/inode identity across concurrent package-path
    replacement without a globally inheritable descriptor window or a descriptor leak.

    The root supervisor's existing registration checks intentionally require procfs authority to revalidate the
    non-root child's executable object and bounded launch environment. Docker root lacks `CAP_SYS_PTRACE` by default,
    so the isolated stage now adds exactly that capability; the deployed inverse `CapabilityBoundingSet` intentionally
    retains and documents it. The harness strictly parses the mode-0600 record and procfs state, requires all four UID
    and GID slots to equal 4001, exact supplementary groups `4001 4101`, `NoNewPrivs: 1`, and zero `CapInh`, `CapPrm`,
    `CapEff`, and `CapAmb` (the kernel bounding set is not falsely treated as cleared by the UID transition). It
    requires descriptor-shaped argv bound to the same recorded executable, proves the executable descriptor is no
    longer open, and accepts only the exact rebuilt environment: fixed `PATH`, passwd `HOME`/`USER`/`LOGNAME`,
    UID-scoped runtime directory, discovered `DISPLAY`/`XAUTHORITY`, bounded `TERM`, and exact parent/generation/fd
    bindings. A capability-free probe running as the same UID/GID/groups must complete typed parked IPC. The observed
    generation `8cb29b16-4a32-431c-91bb-5ed710abb6e3` then shut down gracefully and was reaped with its record removed;
    the UID-4000 portable server survived and stopped only through its separately retained identity.

    Two subsequent complete-smoke attempts built the corrected binary but stopped before runtime when the host
    historical-selector monitor enumerated a short-lived unrelated PID and procfs returned `ESRCH` while opening its
    command line. The guard now treats only `ENOENT`/`ESRCH` as the normal process-exit race and continues to fail on
    permission or malformed-record errors; its self-test fixes both classifications. This changes no process
    selection rule and does not admit a new historical `rustdesk --server` match.

    A third complete-smoke attempt reached the corrected non-root branch and exposed a separate fixture mismatch:
    the build stage's `umask 077` had recreated the root-owned debug binary as mode `0700`. Holding an open descriptor
    preserves executable-object identity but correctly does not bypass the inode's execute permission, so Linux
  rejected the UID-4001 exec. At that historical slice the build stage changed only the completed smoke binary to
  root-owned mode `0755` and the lifecycle required that owner/mode precondition. R-S11cb now keeps the private build
  output executable for staging but models the installed service image as root-owned mode `0711`. Source inputs and
  all other private fixture outputs remain under the restrictive umask.

    The corrected complete default smoke then passed. Its integrated lifecycle observed root graceful generation
    `0cbc0ad2-3ec7-4e61-929d-3c1b372cc244`, restart generation `64097d5d-1e74-4913-87bb-a26914213bb2`, an
    8.136-second stopped-child escalation, crash generations `eafe5eab-5398-490b-94c2-43e74f218225` →
    `1e9d4403-08ca-47b4-a41c-f0c16c5ff77d` with exact-child exit observed after 3 ms, and non-root generation
    `8fec6741-eb22-4cfb-8e7a-c14b8bd0bc6a`. The UID-4000 portable server and the host historical-selector baseline
    both remained unchanged, and every downstream default socket, IPC, keying, session, transfer, limiter,
    forged-frame, shutdown, and wire-capture stage passed. Retained log:
    `/tmp/rustdesk-smoke-rs11c27h-pass.log`, SHA-256
    `cbc010da4894e98ffd0b12b8e425dccbc6f26c711bf94bf4b7582757df5e4938`.

    The verifier's sealed workspace/source-ordering self-contract now recognizes the split root `/proc/self/exe` and
    non-root descriptor role, the installed-mode build output, the switchable active seat, the exact dropped
    capability and typed-IPC assertions, and the lifecycle's explicit `CAP_SYS_PTRACE` procfs authority. Its mutation
    suite independently makes each of those critical contracts invalid and requires the validator to reject it.

    This closes the actual-binary manually supervised non-root active-seat credential-drop/exec case and fixes the
    launch defect it exposed. This slice is not installed-package/systemd lifecycle evidence and does not cover
    installed supervisor crash while owning a non-root child, hostile malformed records, forced PID reuse,
    pre-pidfd fallback, cross-mount/container namespace identity, Debian non-systemd init integration, or concurrent
    separate-Docker survival. Later slices below supply those cases other than actual forced numeric-PID reuse and
    the still-open packaging/release variants; R-S11c-27n supplies the cross-container case. The parent item and
    upcoming release remain **OPEN**.

  - **R-S11c-27i — actual-binary hostile service-child record rejection behavior — SOURCE/RUNTIME IMPLEMENTED AND
    BEHAVIOR-TESTED 2026-07-17; PARENT ITEM REMAINS OPEN.** The mandatory network-isolated manual lifecycle stage
    now drives the real root-owned `rustdesk --service` binary over seven durable-record cases before granting it any
    child-launch or IPC-listener authority. A capability-free UID-4000 BusyBox sentinel deliberately has the exact
    three-argument service-owned role and one controlled generation while differing from the RustDesk executable;
    the independently launched real RustDesk portable server remains live under the same UID with its exact portable
    two-argument role. The decoy is then frozen with a pidfd-bound `SIGSTOP` so it remains inspectable without a
    BusyBox `yes` CPU loop. Both processes are retained by PID/start-time identity and revalidated after every case.

    The matrix injects: a truncated canonical-schema record; a canonical record with untrusted mode `0644`; the
    exact-role decoy with a changed recorded start time (a logical reused-PID ambiguity only); that decoy with a
    changed executable device/inode; a changed UID; a changed generation; and the actual RustDesk portable process
    with its exact executable identity but no service-owned role marker. Each fixture is created relative to the
    root-owned mode-0700 runtime-directory descriptor with `O_EXCL|O_NOFOLLOW`, persisted before invocation, and
    captured by device/inode/owner/mode/link-count/size/time metadata plus SHA-256. The real supervisor must exit
    exactly status 1 with the common core fail-closed diagnostic and the case-specific parser or identity reason,
    leave the record metadata and bytes unchanged, publish no temporary record, and leave both exact sentinels live.
    Only then does the harness reopen the fixed record without following links, recheck its regular/root/single-link
    identity and full hash, unlink that exact fixture relative to the retained directory descriptor, and fsync the
    directory before proceeding.

    The focused actual-binary lifecycle passed after the stopped-decoy hardening. The retained final run emitted an individual success marker and
    SHA-256 for all seven distinct fixture records, then the exact aggregate matrix marker. It subsequently kept all
    pre-existing lifecycle checks green: root graceful stop/restart, an 8.560-second stopped-child escalation,
    supervisor-crash recovery from generation `b54c8546-f838-4a11-8c84-3f691cf2420e` to
    `d4c9d92d-6b4b-41de-b748-3f23d7412494` with exact-child exit observed after 2 ms, real UID/GID-4001 active-seat
    descriptor exec, and final UID-4000 portable noninterference. Retained 2,204-byte mode-0664 log:
    `/tmp/rustdesk-lifecycle-rs11c27i-pass2.log`, SHA-256
    `725a1ec0df92f82de4952fced22414599ba5f804a582eb724f65386744282d4a`. This slice needed no production Rust,
    dependency, syscall, or unsafe-inventory change because the audited parser/recovery path already enforced the
    required fail-closed decision; it adds real-image behavior evidence and sealed regression contracts for it.

    The complete default runtime smoke also passed with the new lifecycle matrix integrated before all downstream
    runtime stages. It observed the same hostile-record aggregate marker, active-seat generation
    `47bb87ec-e78d-4f42-a28b-5bef38fc07b3`, UID-4000 portable noninterference, and an unchanged three-entry host
    historical-selector baseline, then completed the default build, socket, IPC/password, keying, session,
    port-forward, file-transfer, forged-frame, limiter, shutdown, and wire-capture stages. Retained 262,167-byte
    mode-0664 log: `/tmp/rustdesk-smoke-rs11c27i.log`, SHA-256
    `9874d87b00cfd1512f4f41a886b6d94802e58e483e57b2141604b31c6cf80019`.

    This slice deliberately does **not** claim actual forced kernel numeric-PID reuse: changing the recorded
    `/proc/<pid>/stat` start-time field demonstrates fail-closed treatment of ambiguous evidence, not that Linux
    recycled a PID during the test. Actual forced PID reuse remains open. Later R-S11c-27k supplies the separately
    tracked forced pre-pidfd compatibility branch, R-S11c-27l/m supply installed SysV/systemd behavior, and
    R-S11c-27n supplies cross-mount/container-namespace identity. OpenRC/runit/manual packaging integration,
    exact-commit cold artifact evidence, and external expert R-V3 review also remain open. The parent item and
    upcoming release remain **OPEN**.

  - **R-S11c-27j — concurrent separate-Docker service noninterference behavior — SOURCE/RUNTIME IMPLEMENTED AND
    BEHAVIOR-TESTED 2026-07-17; PARENT ITEM REMAINS OPEN.** The default runtime smoke now starts a second Docker
    container before the manual lifecycle stage runs. That sibling container is not started with a host or joined PID
    namespace, has `--network none`, receives the repository as read-only, receives only a private `/sibling` control
    bind as writable, and has no Docker socket or host service authority. Inside that sibling namespace, the mounted
    `sibling-docker-server` stage runs the exact built RustDesk executable through the existing neutral
    `smoke-server-launcher`, proves the process identity with `smoke-process-guard.py`, waits for the no-password
    parked state, publishes `SIBLING_DOCKER_READY`, and then stays alive under repeated PID/start-time checks until
    the parent smoke writes an exact `stop` control file.

    The main smoke then runs the existing networkless `rustdesk --service` manual lifecycle matrix in a separate
    container: hostile durable-record rejection, graceful stop/restart, bounded stopped-child escalation, supervisor
    crash/recovery, non-root active-seat descriptor exec, and UID-4000 portable noninterference. Only after that
    lifecycle stage finishes does the host smoke require the sibling container still to be running, drain it through
    its private control file, require `SIBLING_DOCKER_SURVIVED=pass`, remove that exact container, and emit
    `SIBLING_DOCKER_NONINTERFERENCE=pass`. The capture is written to a private host-guard log file rather than a
    shell command substitution so the cleanup state mutates in the parent shell; the regression validator rejects the
    earlier subshell shape, missing network isolation, any sibling `--pid` sharing, missing survivor markers, or loss
    of the R-S11c-27j stage status.

    The clean default runtime smoke passed with the new sibling integrated before all downstream stages. It observed
    the seven-case hostile-record aggregate marker, stopped-child forced reap at 8.580 s, crash recovery from
    `25dbf5c3-373a-46c7-a808-02697d527334` to `bad6ab5b-c604-434f-a3a4-3f5fa884dcdd` with exact-child exit after
    2 ms, UID/GID-4001 active-seat descriptor exec generation `b2cc8018-8ab0-4ac2-b5de-cdb8a75f1cb2`, UID-4000
    portable noninterference, sibling identity `pid=7 start=34393775`, sibling survivor container
    `39be79d274a7`, and the unchanged three-entry host historical-selector baseline. It then completed all default
    downstream build, socket, IPC/password, keying, session, port-forward, file-transfer, forged-frame, limiter,
    shutdown, and wire-capture stages. Retained 286,092-byte mode-0664 log:
    `/tmp/rustdesk-smoke-rs11c27j-pass2.log`, SHA-256
    `6b117c61bdbc8b937ced2b4836a0388f8aadb328aa542897dec64fcf6bd38855`.

    This slice deliberately proves only concurrent separate-Docker noninterference for the manual lifecycle harness.
    It is not installed package/service-manager stop/restart evidence, installed supervisor crash/restart evidence
    over a non-root child, actual forced numeric-PID reuse, or cross-mount/container-namespace identity proof. The
    later R-S11c-27k slice supplies the forced pre-pidfd compatibility branch, R-S11c-27l/m supply installed
    SysV/systemd behavior, and R-S11c-27n supplies the cross-container identity case. Actual forced numeric-PID
    reuse, OpenRC/runit/manual packaging integration, exact-commit cold artifact evidence, and external expert R-V3
    review remain open. The parent item and upcoming release remain **OPEN**.

    This remains deliberately **partial closure only**. R-S11c-27d–k collectively supply focused hostile-record,
    real manually supervised lifecycle, non-root privilege-drop, concurrent separate-Docker, and forced pre-pidfd
    branch behavior. R-S11c-27l/m add installed SysV and systemd transactions, and R-S11c-27n adds the
    cross-mount/container-namespace identical-path case. Actual forced numeric-PID reuse is still distinct from the
    logical start-time mismatch and forced compatibility-branch tests. Packaging/service integration for OpenRC,
    runit, and the packaged manually supervised path, exact-commit cold artifact evidence, and external expert R-V3
    review also remain mandatory before this parent item or the upcoming release can close.

  - **R-S11c-27k — pre-pidfd fallback recovery behavior — HISTORICAL RUNTIME EVIDENCE FROM 2026-07-17;
    FALLBACK SUPERSEDED AND EXCISED BY R-S11c-27u/R-S11e-93 ON 2026-07-23; PARENT ITEM REMAINS OPEN.** This section
    records the behavior of the then-current source and is not a statement of the current recovery contract. Linux
    service recovery selected a pidfd when available and fell
    back to numeric-PID `kill(2)` only when `pidfd_open(2)` returned an unsupported-kernel error. The fallback first
    verifies the complete durable identity (PID/start time/boot/executable device+inode/UID/generation/service-owned
    argv and environment role), revalidates that identity immediately before each `SIGTERM` or `SIGKILL`, and uses
    identity-revalidating bounded waits between signals. It explicitly reports that its final identity-check-to-kill
    race cannot be eliminated and is not assurance-equivalent to the pidfd path. It never uses a name/path sweep or
    numeric PID alone.

    To exercise that otherwise unreachable branch on the current pidfd-capable test kernel, debug builds now accept
    `RD_SERVICE_SMOKE_FORCE_PRE_PIDFD=1` only while opening a recorded service-child pidfd. The constant and
    environment read are compiled only under `debug_assertions`; the release branch of the helper is an unconditional
    `false`. When forced, the ordinary `rustdesk --service` recovery path returns the existing `Unsupported` state,
    logs a smoke diagnostic, and enters the same production compatibility branch used after an unsupported-kernel
    result. There is no alternate signal implementation or weakened identity predicate in the test hook.

    The networkless lifecycle fixture starts the actual built RustDesk binary independently with neutral argv
    `rd-smoke-server --server --service-owned-server`, a canonical generation, and a launch-parent binding to the
    harness. Before writing a canonical root-owned mode-0600 record, it proves the live PID/start time, exact argv,
    executable device+inode, all four UID fields, generation, and launch parent. The recovering real service receives
    the debug-only force flag, must terminate that exact prior child gracefully, must replace the record with a
    different PID/start-time and generation, and must emit both the forced-unsupported and residual-race diagnostics.
    The fixture fails if the old child remains live or lacks the real server's graceful-shutdown marker. Cleanup is
    also bound to the retained exact PID/start-time pair.

    The focused build completed successfully; retained 274,713-byte mode-0664 log
    `/tmp/rustdesk-build-rs11c27k.log`, SHA-256
    `fcd9ee1f1f830d881f7bfce828a1658df62e4d1dbca5a37b888cf5c63ae994e2`. The focused networkless lifecycle run
    passed with forced fallback generation `b5460ea3-4ffc-4ebd-9453-9b1217adad97` recovered to
    `42178088-d5c1-4d4c-b5d3-1c121b532d92`. The same run retained all seven hostile-record decisions, root graceful
    stop/restart, an 8.154-second stopped-child escalation, supervisor-crash recovery with exact-child exit after
    3 ms, UID/GID-4001 active-seat descriptor exec, and UID-4000 portable noninterference. Retained 2,358-byte
    mode-0664 log `/tmp/rustdesk-lifecycle-rs11c27k.log`, SHA-256
    `b325d4fd69507bcc3211b8095f21a475612654d0bbaba3fefd68465eb9f29ff1`.

    The complete default runtime smoke then passed with the new fallback case integrated into the mandatory
    lifecycle stage and the separate sibling-Docker survivor active. It observed fallback generation
    `a99cdcc5-9528-4ed1-bcf1-1aa6528ba017` recovered to `c06cf01c-acff-4403-a6ac-22ffb552878d`, all seven hostile
    records, an 8.139-second stopped-child escalation, supervisor-crash recovery with exact-child exit after 2 ms,
    UID/GID-4001 active-seat generation `f054d164-c7e9-4b48-ac5d-403321e6f16d`, UID-4000 portable
    noninterference, and sibling survivor container `86ac457cebe1`. The host historical-selector baseline stayed at
    three entries, and all downstream socket, IPC/password, keying, session, tunnel, file-transfer, forged-frame,
    limiter, shutdown, and wire-capture stages reached `SMOKE OK`. Retained 286,275-byte mode-0664 log
    `/tmp/rustdesk-smoke-rs11c27k.log`, SHA-256
    `5a0069a48f764c5693fd5d04375a68a97d3fe5704355e4e846945c312926d80b`.

    The sealed workspace validator binds the exact debug-only constant, debug and release helper arms, helper call,
    forced `Unsupported` return, signal revalidation, both bounded revalidating waits, residual-race diagnostic,
    exact-child fixture, force use, result marker, and top-level stage status. Its mutation suite rejects removal of
    those contracts, and the dirty-tree validator passed. This is a current-kernel forced compatibility-branch test;
    it does **not** claim execution on an actually old kernel and does not remove the documented residual race.

    This historical slice closed only the then-retained pre-pidfd fallback runtime checklist item. R-S11c-27u later
    deleted that compatibility branch rather than accepting its irreducible check-to-signal race. Later
    R-S11c-27l/m supply installed
    SysV/systemd stop/restart and supervisor-crash behavior, and R-S11c-27n supplies cross-mount/container-namespace
    identity. Actual forced numeric-PID reuse, OpenRC/runit/manual packaging integration, exact-commit cold artifact
    evidence, and external expert R-V3 review remain open. The parent item and upcoming release remain **OPEN**.

  - **R-S11c-27u — pidfd-unavailable live recovery refusal — SOURCE IMPLEMENTED AND CONFINED
    SOURCE/MUTATION/COMPILER VERIFICATION PASSED 2026-07-23; UPDATED EXACT-BINARY LIFECYCLE FIXTURE NOT EXECUTED;
    PARENT ITEM REMAINS OPEN.** The previous unsupported-pidfd branch completely revalidated a durable child identity before
    every numeric-PID `kill(2)`, but the final check could not bind the later signal to the same process across PID
    recycling. Current recovery therefore has no raw numeric-PID `SIGTERM`, `SIGKILL`, or revalidating-wait fallback.
    A live recorded child is signaled only after `pidfd_open(2)` and only through `pidfd_send_signal(2)`, with the
    existing complete identity checks immediately before each signal.

    `PidFdOpen::Unsupported` now enters a classification-only handler. `Exited` or `Absent` permits removal of the
    exact stale record without signaling. `Match`, `Mismatch`, or `Unavailable` preserves that record and returns an
    error; the ordinary service entry reports the lifecycle authority failure and exits before its IPC listener or a
    replacement child can be created. This is not a blanket Linux-5.3 minimum: no-record startup works without a
    pidfd, and routine restart/shutdown still uses the supervisor's directly owned Rust `Child`. Only crash recovery
    of a still-live durable-record target requires the stable process descriptor.

    The renamed debug-only `RD_SERVICE_SMOKE_FORCE_PIDFD_UNAVAILABLE=1` hook can force only the existing
    `Unsupported` classification and is compiled to `false` in release builds. The networkless actual-binary fixture
    constructs one exact live service-owned child and canonical root-only record, runs the real `--service` entry,
    requires exact status 1 plus both forced-unavailable and fail-closed diagnostics, and proves unchanged record
    identity/bytes, absence of the temporary record, and survival of both the exact child and unrelated portable
    server. Only after the refusal is proven does the fixture remove the exact record and terminate the retained
    child through its pidfd-bound test authority. R-S11ca, Appendix C #220, the shared source gate, and the independent
    semantic/mutation verifier bind this contract. Confined evidence is recorded in R-S11e-93 below. The updated
    fixture itself was not executed because it models the installed UID-0 service lifecycle, while this slice's
    execution policy required numeric UID/GID 1000 with all capabilities dropped. This source change therefore does
    not claim current exact-binary refusal behavior, an installed Debian artifact run, old-kernel execution, overall
    R-B2/R-B10 completion, or external R-V3 review.

  - **R-S11c-27l — installed Debian SysV lifecycle — SOURCE/RUNTIME IMPLEMENTED AND BEHAVIOR-TESTED 2026-07-17;
    PARENT ITEM REMAINS OPEN.** The sole Linux `.deb` now carries a package-owned mode-0755
    `/etc/init.d/rustdesk` conffile in addition to the primary hardened systemd unit. Both backends start the same
    foreground `/usr/bin/rustdesk --service` supervisor. The SysV path uses `start-stop-daemon --background
    --make-pidfile` to own `/run/rustdesk.pid`, waits for a stable live process before reporting start success, and
    binds every status/start/stop decision to that PID file plus the exact installed executable, `rustdesk` process
    name, and root UID. Stop has exactly one authority call with the bounded `TERM/30/KILL/5` schedule and
    `--remove-pidfile`; it has no executable-only second pass, `pidof`, process-table/name/argv scan, or direct signal
    fallback. A missing PID file makes repeated stop idempotent, while a symlink or mismatched live PID still reaches
    the fail-closed `start-stop-daemon` identity check. The misleading systemd `PIDFile=/run/rustdesk.pid` declaration
    is removed because a `Type=simple` unit owns its main process directly and never created that SysV-owned file.

    Debian maintainer scripts now test the standard running-systemd marker `/run/systemd/system` before any lifecycle
    action. The systemd branch retains `deb-systemd-helper`, `deb-systemd-invoke`, and the fixed manager reload. The
    non-systemd branch registers the packaged LSB init script with `update-rc.d` and calls it only through
    `invoke-rc.d`, including pre-upgrade and prerm stop; no maintainer script executes `/etc/init.d` directly. This
    follows Debian Policy's init-script maintainer-script contract and `invoke-rc.d` policy layer, while the exact
    PID+executable+name+UID stop predicate follows `start-stop-daemon`'s warning that a stale PID file alone is not
    safe. `requirements.html` R-R2a now states the non-contradictory model: `.deb` is the sole Linux package/update
    authority, systemd is the primary confined deployment, and package-owned init adapters are persistence backends
    for that same artifact and supervisor rather than alternate package, update, or sandbox models.

    At the recorded R-S11c-27l run, `build.py` staged the init conffile through the then-current exact, link-free,
    root-normalized package finalizer. That run predates R-S11bz's sole package-owned relative
    `/usr/bin/rustdesk -> ../share/rustdesk/rustdesk` data symlink; the current finalizer admits exactly that link, and
    the old run is not current artifact proof. The artifact verifier binds the init path, mode, conffile exclusion from
    `md5sums`, build-constructor copy, Git executable mode, and negative mutation suite; the maintainer-script verifier
    separately seals backend selection, legal helper syntax, lifecycle ordering, the singular exact SysV stop, and the
    absence of rediscovery fallbacks. The
    release runtime smoke has a mounted `debian-sysv-installed-lifecycle` stage and preserves an explicit
    R-S11c-27l status.

    The focused runtime test ran the real root-owned mode-0755 debug RustDesk executable in a networkless Debian 12
    container with a read-only source mount, a private PID namespace, no Docker socket, and no published port. It
    built two minimal dpkg transactions containing the exact production maintainer scripts, init script, unit, and
    executable; installed version 1.0 through `dpkg`; proved the package-started root supervisor; started an actual
    neutral-argv UID-4000 portable RustDesk server; restarted the installed service; upgraded to 2.0; stopped it;
    substituted a root-owned PID file pointing at an unrelated root `sleep` executable; proved the mismatched process
    survived the stop; started over that stale record; removed and purged the package; and revalidated the portable
    RustDesk and wrong-executable sentinels after every lifecycle event. The source mount metadata and hashes remained
    unchanged. Retained 195-byte mode-0664 log `/tmp/rustdesk-sysv-rs11c27l.log`, SHA-256
    `678192e21c3598236bad7dba681d0b643df109fc6f4702de805921e97b415982`. The complete default runtime smoke then
    passed with this installed lifecycle stage in its normal orchestration path. Its host historical-selector monitor
    retained the three-entry baseline with zero new matches; the build ran inside its build container; runtime stages
    used networkless containers with read-only source mounts and no published port; the new stage reported the exact
    Debian-12/UID-4000/wrong-executable-survival marker; and every downstream socket, password, PAKE, authorization,
    tunnel, file-transfer, limiter, forged-frame, and wire-capture check ended at `SMOKE OK`. Retained 263,015-byte
    mode-0664 log `/tmp/rustdesk-smoke-rs11c27l.log`, SHA-256
    `b8f0222db93f3e7648e5a75f05bd4fbab127fd454f97be7e97c19bf07c93d04d`.

    This closes the package-owned SysV adapter and the mandatory Debian-without-systemd lifecycle run. It is not a
    final-release `.deb` artifact test, not installed systemd stop/restart evidence, not installed supervisor
    crash/restart evidence over a non-root service child, and not actual forced numeric-PID reuse into another
    root-owned instance of the same executable. R-S11c-27n below supplies the cross-mount/container-namespace
    identity case. OpenRC, runit, and manually supervised packaging integration; exact-commit cold artifact evidence;
    and external expert R-V3 review remain open. The parent item and upcoming release remain **OPEN**.

  - **R-S11c-27m — installed Debian systemd lifecycle — SOURCE/RUNTIME IMPLEMENTED AND BEHAVIOR-TESTED 2026-07-17;
    PARENT ITEM REMAINS OPEN.** The release gate now installs the exact production service unit, Debian maintainer
    scripts, and actual debug RustDesk executable into a disposable Debian 12 guest whose real PID 1 is systemd
    252. This closes the separately tracked installed-systemd normal stop/restart and installed supervisor
    crash/restart evidence, including the real active-seat non-root service child. It does not change production
    service code or the deployed host service: the evidence showed that the R-S11c-27a–l ownership behavior already
    composes correctly with the packaged systemd unit.

    The host orchestrator runs only as the unprivileged build user and requires user-readable/writable `/dev/kvm`.
    It verifies a dated Debian genericcloud qcow2 against the publisher-derived SHA-512 pin, rejects links, unexpected
    ownership/mode/link count, a backing file, a wrong format, or a structurally invalid image, and creates a
    throwaway qcow2 overlay. QEMU receives `-nic none`: there is no virtual NIC, tap, bridge, host forward, or
    published port. The source executable, exact service/package fixtures, guest driver, fixed `loginctl` fixture,
    and runtime libraries are placed on an immutable ISO9660 payload attached read-only; source hashes are compared
    again after guest shutdown. The guest has no shared-directory write protocol back to the repository. The pinned
    base is cached only by the explicit `online-fetch.sh --debian-systemd-smoke-image` network acquisition mode under
    current-user-owned mode-0700 `.harness-state`; it is test infrastructure, not a release build input or artifact.

    Runtime libraries are staged from the already-required `rd-devcheck` image by a separate Docker invocation as
    the host UID/GID with no network, a read-only image root, a read-only repository bind, all capabilities dropped,
    no-new-privileges, and a 64-process limit. Docker supplies no PID/cgroup sharing, Docker socket, published port,
    or host service-manager authority. The guest alone runs as root because it must exercise real `dpkg` maintainer
    scripts and its own systemd manager. All package, `/usr`, `/run`, cgroup, user, loader-cache, and service changes
    land only in the disposable overlay, which is removed at the end. No host root, `sudo`, host PID/cgroup namespace,
    host package manager, host systemd command, or host RustDesk lifecycle operation is used.

    Inside the guest, the fixture first proves Debian bookworm, PID-1 systemd, the running-systemd marker, read-only
    source mounts, absence of a pre-existing RustDesk install and `policy-rc.d` suppression, and exact source
    metadata/hashes. A fixed fail-closed `loginctl` admits only one active X11 seat, UID/GID 4001 with supplementary
    group 4101; unexpected argv exits 64. `dpkg -i` executes the unmodified production maintainer scripts and starts
    `rustdesk.service`. The installed fragment must byte-match `res/rustdesk.service`, have no drop-in, and pass
    `systemd-analyze verify`. Its root `MainPID` must execute the installed RustDesk inode with exact
    `/usr/bin/rustdesk --service` argv in `system.slice/rustdesk.service`; its runtime directory must be root-owned
    mode 0700.

    Each generation's strict root-owned mode-0600 durable record is parsed and matched to live procfs evidence. The
    service child must be the direct child of the unit `MainPID`, execute the installed inode through
    `/proc/self/fd/<n>` with exact `--server --service-owned-server` role, have all four UIDs/GIDs set to 4001, retain
    exactly groups 4001/4101, carry zero inheritable/permitted/effective/ambient capabilities, set no-new-privileges,
    expose only the bounded production environment, and share the exact RustDesk service cgroup. A second copy of
    the actual binary runs concurrently as UID 4000 under a distinct transient
    `rustdesk-portable-smoke.service` cgroup with neutral `--server` argv; its PID/start-time, four UIDs, argv, and
    cgroup are revalidated after every installed-service event.

    The behavior transaction proves four distinct installed generations. A normal `systemctl restart` reaps the
    prior supervisor and child and creates a fresh generation without disturbing the portable unit. A deliberate
    `systemctl stop` reaps both, suppresses automatic restart, and removes the runtime directory; `systemctl start`
    creates another fresh generation. Supervisor crash is injected through systemd's exact unit authority with
    `systemctl kill --kill-whom=main --signal=KILL`, not a process-name scan or unvalidated numeric-PID signal.
    The prior direct child must disappear, `Restart=on-failure` must produce a new `MainPID` and generation,
    `NRestarts` must increment, and the fresh supervisor must report exact exited/stale durable-record recovery. The
    UID-4000 portable unit must remain live throughout. Finally, `dpkg -r` must stop/reap the installed supervisor
    and non-root child and remove the executable link/unit/runtime directory; purge must remove the SysV conffile;
    only the fixture's explicit final portable-unit stop may terminate the unrelated process.

    `scripts/smoke-debian-systemd-lifecycle.sh`, its guest driver, and its strict `loginctl` fixture implement this
    test. `scripts/verify.sh` binds their executable modes, immutable image pins/fetch authority, network/privilege
    isolation, exact package/unit/child/cgroup identities, lifecycle events, portable survival, and result markers.
    `scripts/verify-verifier-workspace.py` treats all three scripts and the fetch path as sealed inputs and rejects
    mutations that restore a VM network, weaken Docker staging, omit the exact unit/cgroup/portable proofs, replace
    unit-scoped crash injection with a raw PID signal, remove unexpected-argv rejection, alter the image pin, or
    unwire the release gate. `scripts/verify-release.sh` runs the installed-systemd test immediately after the normal
    runtime smoke, whose build stage supplies the exact debug executable.

    The final focused networkless KVM run passed. It reported normal restart generation
    `e646bd7a-0c86-4f98-b993-27d480217b7e` → `a7239aee-d69b-4c92-a773-562f2f09f4a5`, deliberate stop/start generation
    `f8db9dc7-bc5e-4aae-97e0-d240c429f684`, and supervisor-crash recovery to
    `d512d040-d567-460f-a11d-f5550c929110` with `NRestarts=1`. The exact Debian-12/systemd-252/seat-UID-4001/
    portable-UID-4000 marker, cloud-init completion marker, and networkless/read-only/pinned-base isolation marker
    all passed; the dependency bundle contained 100 files. Retained log `/tmp/rustdesk-systemd-rs11c27m.log` is
    840 bytes, mode 0664, SHA-256 `72e5da081d821a9fa367b8d28205174a9e3755731246fc44dd6239b60968a7a2`.

    This closes installed systemd stop/restart and installed supervisor crash/restart with the real non-root child.
    This slice is not a final-release `.deb` artifact test, actual forced numeric-PID reuse,
    cross-mount/container-namespace identity, or OpenRC/runit/manually supervised packaging integration; R-S11c-27n
    below supplies the cross-container identity case. Exact-commit cold artifact evidence and external expert R-V3
    review also remain open. The parent item and upcoming release remain **OPEN**.

  - **R-S11c-27n — cross-container executable identity — SOURCE/RUNTIME IMPLEMENTED AND BEHAVIOR-TESTED
    2026-07-17; PARENT ITEM REMAINS OPEN.** The mandatory runtime smoke now proves the previously separate
    cross-mount/container-namespace case with the actual RustDesk image, rather than inferring it from same-mount
    executable replacement or a neutral sibling role. Two concurrent, networkless Docker containers independently
    copy the same read-only built source object to the identical `/usr/bin/rustdesk` pathname in their private
    writable layers. Each copy must byte-match the same SHA-256 source while having a device/inode identity distinct
    from that source and from the other container's installed copy. The orchestrator also requires different mount-
    namespace and PID-namespace inode identities. Neither container joins a host or peer PID namespace, receives a
    Docker socket, publishes a port, or receives host service authority.

    The sibling executes its private `/usr/bin/rustdesk` through the descriptor-bound smoke launcher with neutral
    `argv[0]=rd-smoke-server` and the exact `--server --service-owned-server` role. It supplies a fresh canonical
    generation and its real launch parent, enters no-new-privileges with every inheritable/permitted/effective/
    bounding/ambient capability set empty, and parks without a listener. The process guard binds readiness to its
    retained PID/start time, dereferenced `/proc/<pid>/exe` device/inode, exact three-element argv, parent, unique
    generation entry, root UID tuple, and capability state. The neutral argv keeps the fixture invisible to the
    operational older host service's historical `rustdesk +--server` text selector; it does not weaken the RustDesk
    service-owned role, which is independently checked in the exact argument vector and environment.

    Concurrently, the main lifecycle namespace installs the same bytes at its own `/usr/bin/rustdesk`. Every actual
    `--service` generation must publish the device/inode of that installed object, and the harness now compares the
    live service child's `/proc/<pid>/exe` object both to the strict durable record and to the expected installed
    object. The complete hostile-record, graceful stop/restart, stopped-child TERM-to-KILL escalation, supervisor
    crash/recovery, forced pre-pidfd fallback, active-seat non-root descriptor-exec, and portable-server
    noninterference matrix then runs while the sibling remains alive under repeated PID/start-time checks. Only
    after all main-namespace authority has drained may the outer harness stop the sibling through its private
    control file and exact container ID.

    This evidence follows the Linux contracts that mount namespaces present distinct mount hierarchies,
    `/proc/<pid>/exe` is a dereferenceable reference to the executed object (including after unlink), PID namespaces
    isolate PID-number visibility and signal targets, and `pidfd_open(2)`/`pidfd_send_signal(2)` bind recovery signals
    to one opened process. Production code is unchanged: normal lifecycle still owns the direct `Child`; crash
    recovery still requires boot ID, start time, UID, executable device/inode, exact role, and generation before its
    pidfd-bound signal. Identical path text, bytes, role text, or a plausible generation never becomes authority.

    `scripts/smoke-server-launcher.c` now accepts only the optional literal service-owned role and keeps the final
    exec descriptor-bound. `scripts/smoke-process-guard.py` has a separate exact service-owned proof. The release
    smoke cross-compares source hashes and object/namespace identities before accepting
    `CROSS_CONTAINER_EXECUTABLE_IDENTITY=pass`. `scripts/verify.sh` binds the production identity predicate, both
    fixtures, the exact-role launcher/guard, cross-container comparisons, isolation, result markers, and this ledger
    row. `scripts/verify-verifier-workspace.py` seals those inputs and its mutation suite rejects loss of the exact
    role, installed path, executable-object, mount-namespace or PID-namespace separation, stage status, and ledger
    gate.

    The complete runtime smoke passed with common source identity `66306:103678568` and SHA-256
    `67927cd9ae12c2fa2f5352ea2a366436eaab64751727c7c4ac6d9c8b2f77d0c0`; main and sibling installed objects were
    respectively `180:92288192` and `177:92288157`, mount namespaces `4026533569` and `4026533119`, and PID
    namespaces `4026533574` and `4026533529`. Sibling generation
    `f1f28d9f-2d00-4186-88fe-9d91afc85044` survived the full main lifecycle and was then explicitly drained. The
    whole-host historical-selector monitor retained its three-entry baseline with zero new match, and every
    downstream socket/password/PAKE/session/tunnel/file-transfer/forged-frame/limiter/wire-capture stage reached
    `SMOKE OK`.

    This closes the cross-mount/container-namespace executable-identity and identical-in-container-path checklist
    items. R-S11c-27o below supplies actual forced kernel numeric-PID reuse. Final-release `.deb` artifact proof,
    OpenRC/runit/manual packaging integration, exact-commit cold artifact evidence, and external expert R-V3 review
    remain open. The parent item and upcoming release remain **OPEN**.

  - **R-S11c-27o — actual kernel numeric-PID reuse — SOURCE/RUNTIME IMPLEMENTED AND BEHAVIOR-TESTED
    2026-07-18; PARENT ITEM REMAINS OPEN.** The mandatory runtime smoke now proves the exact stale-PID race that
    R-S11c-27 still needed: a dead service-owned RustDesk child leaves a strict durable record for PID `50000`, and
    a different live RustDesk service-owned child is then forced by the kernel allocator to reuse that same numeric
    PID inside a private Docker PID namespace. The second child intentionally uses the same executable object and
    service-owned role but has a different `/proc/<pid>/stat` start time and different canonical service generation.
    Production recovery must reject the stale record before any signal, preserve the record bytes, leave the
    unrelated reused-PID child alive, and exit fail-closed with the concrete start-time mismatch diagnostic.

    `scripts/smoke-service-pid-reuse.sh` is a dedicated bounded fixture for this case. It runs only from the
    mounted stage dispatcher and never installs into or modifies the host. The fixture remounts `/proc/sys` writable
    only inside the container's private PID namespace, writes `target_pid - 1` to
    `/proc/sys/kernel/ns_last_pid`, reads the forced predecessor back, and immediately launches the next RustDesk
    service-owned child. It remounts `/proc/sys` read-only again after each forced allocation. The two RustDesk
    children are launched through the audited descriptor-bound smoke launcher as exact
    `rd-smoke-server --server --service-owned-server` roles with no-new-privileges and empty inheritable, ambient,
    and bounding capability sets. The durable record is written with exclusive no-follow open, full-write looping,
    root-owned mode-0600 file authority, boot ID, PID, start time, executable device/inode, UID, generation, and
    role. Cleanup removes only the exact record identity and SHA-256 it created.

    `scripts/smoke-server.sh` keeps this proof separate from the ordinary lifecycle container because forcing
    kernel PID allocation requires container-local checkpoint/restore-style authority. The new `PID_REUSE_RUN`
    container uses `--network none`, `--read-only`, `--pids-limit 128`, `--cap-drop ALL` plus only
    `SYS_ADMIN`, `CHECKPOINT_RESTORE`, and `SETPCAP`, no-new-privileges, an unconfined AppArmor profile for the
    container-local procfs remount, read-only source bind, and private tmpfs `/tmp` and `/run`. It does not use
    `--privileged`, host networking, host PID namespace sharing, published ports, the Docker socket, host systemd,
    package manager authority, or any host RustDesk service authority. The tested RustDesk children and the
    recovery supervisor then drop their capability sets before executing RustDesk; the elevated authority exists
    only around the fixture's private PID allocator setup.

    The runtime proof passed with original generation `c43b6eab-16fb-4b0c-aabd-de0eebd312ff` and reused generation
    `ad49ed73-0794-429e-a8d8-c6a9ed863b68`. Both live children received PID `50000` and used executable identity
    `66306:103678568`; the stale record start time was `38877641`, while the reused live child start time was
    `38877752`. Recovery exited `1`, logged `Linux service lifecycle authority failed closed:` and the exact
    `start time changed from 38877641 to 38877752` mismatch, preserved record SHA-256
    `ea02c7853f5836bbe3f9bb714098b947a8ff7552cc5655390517743744f04a59`, and the process guard revalidated the
    reused child as the exact surviving service-owned role before fixture cleanup. Retained log
    `/tmp/rustdesk-rs11c27o-pid-reuse.log` is 858 bytes, mode 0664, SHA-256
    `5417929969680708ab5656e539e0385a9eb640d9ccb2a2fa30d3ecb7d1285050`.

    `scripts/verify.sh` now seals the unchanged production start-time predicate and pidfd recovery call, the new
    mounted stage, the isolated Docker argv, the forced `ns_last_pid` write/readback ordering, proof that the first
    and second children share the same numeric PID but not start time, same-executable-object proof, fail-closed
    diagnostic proof, no-signal survivor proof, forbidden broad-authority strings, and this ledger row.
    `scripts/verify-verifier-workspace.py` loads the PID-reuse fixture as a first-class sealed input and its
    mutation suite rejects weakening the result marker, removing same-PID proof, weakening the isolated container
    argv, or dropping the R-S11c-27o stage status.

    This closes the actual forced kernel numeric-PID-reuse checklist item for service-child recovery. It is not a
    final-release `.deb` artifact proof, OpenRC/runit/manual packaging integration, exact-commit cold artifact
    evidence, or external expert R-V3 review. The parent item and upcoming release remain **OPEN**.

  - **R-S11c-27p — packaged OpenRC/runit/manual supervisor templates — SOURCE/PACKAGE INTEGRATED
    2026-07-18; NATIVE OPENRC/RUNIT EVIDENCE IS PROVIDED BY R-S11c-27q/r; PARENT ITEMS REMAIN OPEN.** The Debian
    package source now carries explicit service-manager templates under
    `res/service-managers/{openrc,runit,manual}` and stages them as exact mode-0755 regular files under
    `/usr/share/rustdesk/files/{openrc,runit,manual}`. They are downstream/administrator integration inputs,
    not an excuse for maintainer scripts to infer or rewrite the host's selected service topology. The existing
    systemd-versus-SysV package lifecycle remains the only automatically selected package path; no OpenRC runlevel,
    runit service link, or manual supervisor state is created behind the administrator's back.

    The OpenRC template uses its documented foreground-daemon pattern: fixed
    `command=/usr/bin/rustdesk`, exact `command_args=--service`, `command_background=true`, fixed root-owned
    `/run/rustdesk.pid`, root identity, fixed working directory/umask, and bounded `TERM/30/KILL/5` retry. It has
    no custom start/stop function and no `procname` fallback. The runit and manual templates contain only a strict
    shell setup followed by `exec /usr/bin/rustdesk --service`, so the service manager owns the actual RustDesk
    supervisor PID rather than a shell wrapper. None names `--server`, the service-owned child role, `/proc`, or a
    process-discovery/sweep tool. Normal manager stop therefore reaches only the foreground `--service` process;
    direct child/pidfd ownership, bounded child drain, and crash recovery remain inside the init-independent
    R-S11c-27a–o supervisor protocol.

    `build.py`'s closed Debian directory/file/executable inventories now require all three templates and its sole
    package constructor copies their fixed source tree before canonical finalization. The independent artifact
    verifier mirrors that exact inventory, mode policy, source Git-mode proof, constructor call shape, synthetic
    package tests, and mutation fixtures. `scripts/build-debian.sh` extracts every completed `.deb`, requires each
    template to be a non-linked mode-0755 regular file, byte-compares it with source, and runs the shared semantic
    checker on the extracted payload. `scripts/verify-debian-maintainer-scripts.py` pins the OpenRC authority fields,
    rejects process rediscovery/custom lifecycle functions, and exact-matches both foreground exec wrappers.
    `scripts/verify.sh` and `scripts/verify-verifier-workspace.py` gate the source/package/documentation contract.
    `docs/DEPLOYMENT.md` documents the three package paths, single-manager rule, and exact foreground stop model.

    This slice closes the missing source/package templates and the already-runtime-tested manual-supervisor wrapper
    integration. R-S11c-27q/r subsequently supply native OpenRC and runit evidence; this row does **not** claim a
    built final-release `.deb`. Final-release `.deb` artifact proof, exact-commit cold artifact evidence, and
    external expert R-V3 review remain open. The parent item and upcoming release remain **OPEN**.

  - **R-S11c-27q — native OpenRC lifecycle authority — SOURCE/RUNTIME IMPLEMENTED AND BEHAVIOR-TESTED
    2026-07-18; NATIVE RUNIT EVIDENCE IS PROVIDED BY R-S11c-27r; PARENT ITEMS REMAIN OPEN.** A dedicated mounted
    lifecycle stage now runs the real built RustDesk binary under Debian bookworm's exact
    `openrc=0.45.2-2+deb12u1` package in the existing
    disposable, network-disabled lifecycle container. The fixture initializes an empty private OpenRC softlevel,
    installs byte-identical copies of the production OpenRC template and RustDesk executable, and installs only
    the bounded `loginctl` test fixture needed to select the root smoke seat. It does not start a host runlevel,
    modify a host service, publish a container port, or share the host PID namespace.

    The native transaction proves that OpenRC's fixed root-owned mode-0644 single-link pidfile names a live
    root-UID `/usr/bin/rustdesk --service` supervisor executing the exact installed file object. The RustDesk
    supervisor, rather than OpenRC or the harness, publishes the strict mode-0600 child record and directly owns
    the exact `/proc/self/exe --server --service-owned-server` child: parent PID, start time, boot UUID, executable
    device/inode, UID, generation UUID, NNP state, environment authority, typed parked IPC, and zero TCP-listen/UDP
    surface are checked at runtime. A separate UID-4000, no-new-privileges, capability-free RustDesk server with
    neutral argv and a distinct executable object survives native start, restart, stop, start-over-stale-pidfile,
    failed crash restart, explicit recovery, and final stop.

    The test preserves an OpenRC 0.45.2 behavior that must not be papered over: normal `stop` terminates the exact
    tracked supervisor and its child but leaves `/run/rustdesk.pid`. A subsequent native `start` safely overwrites
    that root-owned pidfile with a fresh PID/start identity and generation. If the backgrounded supervisor is
    instead killed without OpenRC observing the exit, OpenRC still reports manager state `started`; direct
    `restart` fails at its exact stop boundary because no matching `/usr/bin/rustdesk` is alive. The harness proves
    that this failure changes neither the durable child record nor the unrelated process, then uses OpenRC's
    explicit `rc-service rustdesk zap` state reset followed by `start`. Fresh RustDesk recovery discards the exited
    exact child record without signaling it, publishes a different supervisor/child/generation, and again leaves
    the portable process untouched. Supervisor crash and child parent-death exit are observed through retained
    pidfds; no process-name, command-line, or numeric-PID sweep is available to the fixture.

    `scripts/verify.sh` seals the exact Debian OpenRC pin, mounted networkless dispatch, lifecycle result, native
    command sequence, strict supervisor/child/portable identities, explicit stale-state behavior, pidfd-only crash,
    source-mount postcondition, forbidden broad-authority strings, and this row. The workspace verifier loads the
    OpenRC fixture as a first-class source and mutation-tests the package pin, native dispatch/status, portable
    survivor proof, and explicit crash recovery result.

    This closes native OpenRC runtime evidence for the shipped template; R-S11c-27r separately supplies native
    runit runtime evidence. This row does **not** claim a built final-release `.deb`, exact-commit cold artifact
    evidence, or external expert R-V3 review. Those items and the upcoming release remain **OPEN**.

  - **R-S11c-27r — native runit lifecycle authority — SOURCE/RUNTIME IMPLEMENTED AND BEHAVIOR-TESTED
    2026-07-18; PARENT ITEMS REMAIN OPEN.** A dedicated mounted lifecycle stage now runs the real built RustDesk
    binary under Debian bookworm's exact `runit=2.1.2-54` package in the existing disposable, network-disabled
    lifecycle container. The fixture creates one root-owned private service tree, installs byte-identical copies of
    the production runit `run` wrapper and RustDesk executable, places a `down` marker before starting the manager,
    and installs only the bounded `loginctl` fixture needed to select the root smoke seat. It does not link a host
    service, start a host runit instance, modify a host service, publish a container port, or share the host PID
    namespace.

    The native transaction binds the whole ownership chain rather than inferring it from process names. One exact
    root-UID `/usr/bin/runsvdir` process directly owns exactly one exact `/usr/bin/runsv` process for the private
    `rustdesk` directory. Its root-owned non-group/world-writable `supervise/control` and `supervise/ok` FIFOs are the
    only manager control objects used. That `runsv` owns one root-UID `/usr/bin/rustdesk --service` foreground
    supervisor executing the exact installed file object. RustDesk, rather than runit or the harness, publishes the
    strict mode-0600 child record and directly owns the exact
    `/proc/self/exe --server --service-owned-server` child: parent PID, start time, boot UUID, executable
    device/inode, UID, generation UUID, NNP state, environment authority, typed parked IPC, and zero TCP-listen/UDP
    surface are checked at runtime.

    Native `sv -w 30 restart` drains the prior supervisor/child and starts different PID/start and generation
    identities without replacing the owning `runsv`. Native `sv -w 30 stop` removes the RustDesk durable record,
    terminates both exact identities, exposes runit's `down` state, and leaves the manager and unrelated process
    alive; `start` then creates a fresh exact chain. An exact retained-pidfd `SIGKILL` of the RustDesk supervisor
    proves the service child exits through parent-death binding. The unchanged `runsv` automatically starts a fresh
    RustDesk supervisor, which rejects the exited strict record without signaling it and publishes a new child and
    generation. Finally, an exact retained-pidfd `SIGHUP` to `runsvdir` exercises its documented native contract:
    `runsvdir` exits 111 after signaling its monitored `runsv`; runsv's shutdown drains the exact RustDesk
    supervisor and child with no durable record left. No process-name, command-line, or numeric-PID sweep is
    available to the fixture.

    A separate UID-4000 RustDesk portable server executes a distinct file object with exact neutral argv,
    no-new-privileges, and five zero capability sets. Its PID/start/executable/UID/argv/environment identity is
    rechecked after every native transition and it survives start, restart, stop, start, supervisor crash,
    automatic recovery, and final manager shutdown. The first focused transaction emitted
    `RUNIT_NATIVE_LIFECYCLE=pass os=debian-12 runit=2.1.2-54 portable_uid=4000 normal_restart=pass
    crash_recovery=automatic manager_shutdown=hup-111 child_exit_ms=3`.

    `scripts/verify.sh` seals the exact Debian runit pin, mounted networkless dispatch, full lifecycle result,
    precise manager/supervisor/child/portable identities, private FIFO authority, automatic crash recovery, native
    HUP/111 shutdown, source-mount postcondition, forbidden broad-authority strings, and this row. The workspace
    verifier loads the runit fixture as a first-class source and mutation-tests the package pin, native
    dispatch/status, portable role, automatic recovery, and final runtime result.

    This closes native runit runtime evidence for the shipped template. It does **not** claim a built final-release
    `.deb`, exact-commit cold artifact evidence, or external expert R-V3 review. Those items, the parent item, and the
    upcoming release remain **OPEN**.

  - **R-S11c-27s — final Debian artifact lifecycle gate — SOURCE/RELEASE-TRANSACTION IMPLEMENTED AND
    BEHAVIORALLY WIRED 2026-07-18; EXACT COLD ARTIFACT EXECUTION PENDING; PARENT ITEM REMAINS OPEN.** The prior
    installed-systemd and SysV evidence deliberately constructed minimal packages around the real debug executable
    and exact production lifecycle files. That proved the supervisor and maintainer-script behavior, but it did not
    prove that the independently built, byte-reproducible `rustdesk-x86_64.deb` actually carries and executes that
    behavior. The release transaction now closes the missing *gate*: after both complete release snapshots have
    produced their four artifacts and A==B has been established, but before `SHA256SUMS` or final publication, it
    invokes the pinned networkless systemd VM lifecycle against the exact pass-A `.deb`, then repeats the A==B
    comparison. A lifecycle failure, artifact mutation, source mutation, or missing result marker aborts release.

    Admission is bound to the private release transaction rather than an arbitrary pathname. The selected `.deb`
    must be a current-user/current-group mode-0400, single-link, non-symlink regular file; its SHA-256 must equal the
    independently compared pass-B artifact; and the lifecycle driver must run from the clean detached snapshot at
    the exact 40-hex release commit. The driver rechecks canonical path, metadata, link count, package name,
    architecture, SHA-256, clean/no-generated Git state, and the independent closed-inventory Debian artifact
    verifier before extracting into private scratch. It records device/inode/size/owner/mode/link identity and
    digest before any consumer, rechecks both after the VM, and places the package itself—not a reconstructed
    package tree—on an immutable ISO9660 payload. Runtime libraries are derived from the exact extracted artifact in
    the existing current-UID, all-capabilities-dropped, no-new-privileges, networkless Docker staging step.

    Inside the disposable Debian 12 KVM guest, the artifact SHA-256, `rustdesk` package identity, `amd64`
    architecture, and read-only payload mount are revalidated before installation. The offline cloud image is
    intentionally minimal, so the fixture supplies the exact artifact-derived runtime library bundle and uses
    dpkg's narrowly named `--force-depends` admission only to turn absent fixture package dependencies into warnings;
    dpkg still unpacks and configures the exact archive and executes its real preinst/postinst/prerm/postrm scripts.
    The test requires configured `ii` state, a clean `dpkg --verify`, the byte-exact production unit, and the complete
    R-S11c-27m normal restart, stop/start, non-root child authority, unit-scoped supervisor crash/recovery, portable
    sibling survival, removal, and purge transaction. Success additionally requires the exact artifact SHA-256 and
    release commit in `DEBIAN_RELEASE_ARTIFACT_LIFECYCLE`; the host accepts no unbound success marker. This does not
    claim APT dependency-resolution coverage, which is separate from the lifecycle behavior under test.

    The release-snapshot path also fixes a concrete cold-transaction defect: ignored `.harness-state` content is
    correctly absent from the clean detached source clones, so their pre-build systemd source gate could not find the
    cached cloud image by a snapshot-relative default. `build-release.sh` now passes the canonical host cache file
    explicitly; `verify-release.sh` captures and unsets that environment, then supplies the image/scratch pair only
    to the systemd gate so unrelated source consumers never inherit those paths. The lifecycle driver independently
    requires the publisher-pinned SHA-512, current-user mode-0444
    single-link file, standalone qcow2 format, and structural integrity. Every mutable overlay, ISO, serial log, and
    extracted package path instead lives beneath a current-user mode-0700 directory inside the private release
    workspace. QEMU still receives `-nic none`; Docker receives no published port, host PID/cgroup namespace, Docker
    socket bind, or added capability; and root exists only inside the throwaway VM for dpkg and its private systemd.

    `build-release.sh --self-test` now synthesizes both artifact passes, proves the final lifecycle is invoked exactly
    once with the pass-A path, A/B digest, exact commit, pinned-image handoff, and private scratch, and proves the
    lifecycle occurs between two A==B comparisons and before manifest/publication. `scripts/verify.sh` and the
    verifier-workspace semantic/mutation suite seal the host and guest artifact bindings, release ordering, source
    snapshot handoff, confinement, result marker, and this ledger row. This row records only an implemented and
    behaviorally wired release gate: no current final `.deb` satisfies the new gate, and the prohibited long cold
    release build was not run during this slice. Final-release `.deb` runtime proof therefore remains **PENDING**
    until the next clean exact-commit cold transaction emits the bound marker. Exact-commit four-artifact evidence
    and external expert R-V3 review also remain open; the parent item and upcoming release remain **OPEN**.

  - **R-S11c-27t/R-T4 — Linux headless CM bootstrap cancellation ownership — SOURCE IMPLEMENTED/GATED
    2026-07-21; FINAL NATIVE/RELEASE/DEVICE ITEMS REMAIN OPEN.** Endpoint/action: the per-connection
    `try_start_cm_ipc()` task selects or starts the connection manager and bridges that connection's typed CM
    messages. Boundary: the owning `Connection` and its lifetime/command/readiness senders ↔ the asynchronously
    spawned CM bootstrap/bridge. The ordinary connected bridge already terminated when its command receiver closed,
    but no dedicated future made owner loss independently selectable throughout bootstrap, and two
    inherited pre-bridge paths did not carry that owner lifetime consistently. The desktop prelogin loop could wait
    indefinitely after the connection disappeared. On Linux, the headless-user loop deliberately used the
    connection-owned desktop-readiness receiver as a wake-only hint, yet treated `Ok(None)` exactly like a timeout
    or signal. Dropping `LinuxHeadlessHandle` permanently closed that receiver; with no selected username, each
    subsequent receive was immediately ready and the detached bootstrap could hot-loop. A connection could also
    disappear immediately before CM launch or during the bounded endpoint retry without stopping those actions.

    Every desktop `Connection` now owns the sole sender of a dedicated one-shot lifetime channel. The bootstrap
    future is raced against its receiver, and `Connection::Drop` closes that lifetime before any other connection
    cleanup; owner loss therefore cancels an async pre-bridge wait without requiring command traffic. Once
    authenticated bootstrap signals completion, biased selection transitions to draining the live bridge instead
    of cancelling it, so the queued graceful/hard-Drop CM close notification is forwarded before command-receiver
    closure terminates the bridge. The command receiver remains an additional fail-closed authority before each
    target/prelogin selection, headless-user iteration, CM launch, and post-launch endpoint attempt. A small
    Linux-only readiness result distinguishes
    `OwnerClosed` from `Wake`: timeout and an actual signal remain bounded state-recheck events, while sender closure
    is terminal before username refresh. Five current-thread async regressions prove closed/signaled readiness,
    closed/live connection-owner outcomes, and post-bootstrap bridge drain after owner closure. The source gate and independent semantic mutation verifier bind the
    lifetime channel construction/wiring, owner/task `select!`, cancellation-before-cleanup order, four command
    checks and their state/launch/retry ordering, terminal closed-readiness handling, removal of the inherited
    TODO/ignored timeout shape, R-T4, Appendix C #204, and this row.

    Focused verification used the existing Rust 1.75 devcheck image as numeric UID/GID 1000 with the reviewed
    vendor snapshot, no network, a read-only source mount, and a fresh disposable target: the complete library test
    target compiled and all five lifecycle regressions passed (5 passed, 0 failed, 328 filtered). Exact Rust 1.75
    rustfmt passed for `src/server/connection.rs`; the extracted shell gate, Bash parse, normal independent semantic
    verifier, and complete deliberate source-mutation matrix passed in separate non-root networkless containers.
    The newly pinned exact verifier image is not locally present, so the repository-wide `scripts/verify.sh` entry
    point and a full release transaction are not claimed green; the existing image supplied focused diagnostic
    evidence only.

    Evidence boundary: this is a source-level lifecycle and local availability correction. It does not claim that
    the Tokio bridge task is synchronously joined by `Connection::Drop`; owner loss cancels its future at the outer
    `select!` only before authenticated bootstrap completes, after which command closure drains it. A bounded
    synchronous launch already admitted before concurrent owner loss may finish before that future is polled, after
    which no remaining bootstrap work continues. R-S11ad separately kernel-binds any
    launched no-UI CM child to its exact server parent. No native packaged artifact, Android swipe/relaunch device
    sequence, long cold release transaction, or external R-V3 review is claimed here. The defect is not evidence of
    host RustDesk modification, a public
    listener, firewall change, root/container escape, exploitation, or compromise, and it is not a source-proven
    cause of the reported Android outgoing-viewer symptom. The broader R-B2/R-B10/device and parent release items
    remain **OPEN**.

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
    supervisor must open a `pidfd` and revalidate every available identity field
    immediately before signaling. Missing, malformed, stale, or ambiguous evidence
    must fail closed by signaling nothing and reporting the condition; a PID or
    command line alone is never ownership proof. If `pidfd_open(2)` is unavailable,
    an already-exited or absent record may be removed without signaling, but a live,
    mismatched, or unverifiable record must be preserved and startup must fail before
    listener or replacement-child authority. No numeric-PID recovery signal fallback
    is compatible with this requirement.
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
- **R-S11bh/R-S11e-74 — mobile legacy at-rest migration requires live OS-key authority — SOURCE
  CLOSED/GATED 2026-07-21; NATIVE FAILURE INJECTION, iOS ARTIFACT, REAL-DEVICE, AND EXACT-RELEASE
  EVIDENCE REMAIN OPEN.** Platforms: Android and iOS, with desktop compatibility preserved. Endpoint/action:
  `password_security::open_at_rest_payload` and `open_with_existing_key_pair`, reached by permanent-password,
  PRS, ID, peer-password, and encrypted JSON config reads. Boundary: transiently unavailable or rejected
  AndroidKeyStore/iOS Keychain key ↔ plaintext config-keypair legacy migration authority. The initial OS-key
  implementation in `09a7409912ed15e0422cdad65a4bb34e8c3f6af3` correctly made the OS key primary but sent
  both current-key mismatch and total OS-key unavailability through `Config::get_existing_key_pair()`. On an
  older mobile config, the latter branch could decrypt a credential without the intended OS authority. The
  peer-config loader would also receive `should_rewrap=true` and immediately store the decrypted password and
  password-equivalent PRS; because encryption could not obtain the missing OS key, the vector encryptor returned
  empty fields, risking destructive credential replacement. This contradicted both startup diagnostics that said
  encrypted reads fail closed. It is a source-proven local storage-authority and credential-availability defect,
  not evidence of device/host compromise, a public listener, a host RustDesk/service/firewall mutation, Docker
  escape, or privilege escalation.

  The correction is one platform decision at the sole legacy-keypair read boundary. On Android/iOS,
  `legacy_key_pair_fallback_authorized` returns true only when `primary_key.is_some()`: the OS-protected key was
  installed and tried, but the payload is old. If the OS key is unavailable, authorization returns before
  `Config::get_existing_key_pair()`, so no legacy plaintext, rewrap marker, or migration write can result. With a
  live OS key, genuine legacy ciphertext still decrypts and sets `should_rewrap=true`. Desktop preserves its
  existing machine-UID-unavailable keypair recovery and keeps `should_rewrap=false`. The focused Rust regression
  pins all three decisions (mobile missing-key denial, mobile live-key migration, desktop recovery). The standalone
  `scripts/verify-mobile-at-rest-fail-closed.py` binds the policy expression, platform classifier, authorization
  before keypair access, sole keypair-read inventory, dispatcher edges, rewrap result, immediate peer migration
  sink, Android/iOS startup order and diagnostics, requirement/disposition/ledger, and shared/Apple wiring; its
  12 deliberate mutations must all fail. R-S11bh and Appendix C #197 make the corrected authority normative.
  No device/emulator, AndroidKeyStore/Keychain failure injection, iOS compile/sign, or new APK build occurred in
  this source slice. The existing older Android signed-artifact result below predates this correction and is not
  promoted to exact-current evidence; live Android/iOS storage behavior, iOS artifact proof, and the exact clean
  R-B2 release transaction remain open.
- **R-S11bi/R-S11e-75 — macOS launchd lifecycle uses explicit modern domains — SOURCE CLOSED/GATED
  2026-07-21; NATIVE APPLE AND EXACT SIGNED-ARTIFACT LIFECYCLE EVIDENCE REMAIN OPEN.** Platform: macOS
  service installation, restart, and uninstallation. Endpoint/action: the root LaunchDaemon lifecycle inside
  `install.scpt`/`uninstall.scpt` and the current-user LaunchAgent lifecycle in `src/platform/macos.rs`. Boundary:
  a successful local/admin wrapper result ↔ the exact launchd domain and service definition reaching the requested
  loaded or absent state. The first R-S11c-16 correction (commit `8ef29da804ecea6878e77ab88fdb7bca64638df3`)
  used `launchctl list <label>`, legacy `load -w`/`unload -w`, and legacy `remove`. Apple's current launchctl
  contract classifies those commands as legacy, says load/unload return nonzero only for improper usage and
  otherwise return zero, and says remove returns without waiting for the job to stop. The code additionally mapped
  every nonzero label query to absence without proving that its intended domain was reachable. Its postconditions
  could therefore be false after a domain/query or lifecycle failure. This is a source-proven local lifecycle
  finality and availability defect, not evidence of exploitation, a stopped host service, host mutation, a public
  listener, Docker root, privilege escalation, or compromise.

  The correction keeps the existing service topology and changes only lifecycle authority. Privileged scripts
  derive the exact `system/<service-label>` target. The Rust path derives `gui/<numeric-effective-uid>` from
  `geteuid()` and appends the exact server label. `launchctl_service_loaded` first requires a successful
  `launchctl print <domain>`; only then may a failed `print <service-target>` mean absence. A present service is
  removed only by checked `bootout <service-target>`, followed by the same domain-aware negative proof. Install and
  restart clear the persistent disabled override left by older `unload -w` runs with checked `enable`, use checked
  `bootstrap <domain> <plist>`, and require the exact service target to print successfully. The privileged uninstall
  proves its system target absent before deleting the root plist/helper, and Rust proves the current GUI target
  absent before wrapper success. Legacy `list`, `load`, `unload`, and `remove` are absent from these lifecycle paths;
  fixed `/bin/launchctl` provenance, administrator-script environment closure, non-stdio descriptor closure,
  helper/plist identity checks, and outer return propagation remain unchanged.

  The focused Rust regression pins GUI-domain and service-target derivation. The standalone
  `scripts/verify-macos-launchd-lifecycle.py` parses the relevant Rust functions and both privileged scripts,
  enforces operation ordering and legacy-command absence, binds requirement/disposition/ledger and shared/Apple
  wiring, and rejects 16 deliberate mutations. R-S11bi and Appendix C #198 make the corrected contract normative.
  Linux-side rustfmt/source checks and mutation tests do not compile or execute macOS launchd. No native Mac,
  signed application, installed LaunchDaemon/LaunchAgent, or artifact was exercised; native Apple and exact R-B2
  lifecycle evidence remain open.
- **R-S11bj/R-S11e-76 — Android APK builder container and source authority — SOURCE CLOSED/GATED
  2026-07-21; EXACT TARGET-LOCAL APK VALIDATED 2026-07-23; FULL RELEASE AND DEVICE EVIDENCE REMAIN OPEN.**
  Platform: Android artifact
  construction, signing, and verification. Endpoint/action: the four local Docker launches used for keystore
  inspection, offline compilation, signing, and signed-APK verification. Boundary: checked-in exact-commit source,
  signing secrets, verified offline inputs, and private intermediate artifacts ↔ an already-present pinned builder
  image and the final host-side artifact publication. Before this correction, compilation mounted the real repository
  read-write, signing mounted the final output directory read-write, verification mounted the repository read-only for
  two checker scripts, and the compile used a fixed daemon-global container name. The launches were networkless and
  numeric-nonroot, but did not explicitly refuse pulls, make the container root read-only, remove all capabilities,
  set no-new-privileges, or bound processes, memory, CPU, and scratch space. A clean-tree check occurred before the
  live mount, so a concurrent edit could also make consumed source differ from the named commit. This is source-proven
  excessive build authority and a reproducibility race; it is not evidence that Docker gained root, changed a host
  service or firewall, exposed a port, escaped, exploited anything, or compromised a host or device.

  `scripts/build-android.sh` now rejects `ALLOW_DIRTY_TREE`, resolves one full clean `HEAD`, rejects symlink/gitlink/
  special tree entries, archives the commit once into a mode-protected private workspace, and retains a non-writable
  authority extraction. Each build pass creates a freshly absent writable extraction; the new descriptor-based
  `scripts/verify-android-build-source.py` requires the initial inventory to contain no extras and match every
  committed regular file/directory, owner, byte digest, and canonical full mode, rejects symlink/hardlink substitution and
  unstable reads, and after compilation proves every committed input still matches while allowing generated outputs.
  The writable tree is removed before signing, so the second pass starts from a fresh extraction rather than prior
  generated state. Neither the real repository nor final output directory is mounted into a container.

  One common launcher now binds every keytool/build/sign/verify invocation to `/usr/bin/docker`, the existing immutable
  image ID, `--pull=never`, `--network=none`, a read-only root, the invoking numeric uid/gid, all capabilities dropped,
  no-new-privileges, explicit PID/memory/CPU limits, and bounded task-specific tmpfs. The compile sees only its private
  writable source plus the immutable inner script and verified online closure; signing sees only private pass output,
  read-only signing files, exact-commit verifier scripts, and online inputs; verification sees only the APK and those
  read-only checker/input files. There is no port publication, host namespace, Docker socket, privileged/cap-add path,
  image build, or image pull. Signed private output passes signature/certificate, manifest, mobile-key, and checksum
  validation before host-side publication; final APK/checksum bytes are compared to the private result and the
  published hash is checked again. Standalone builds retain their default A/B comparison, while `build-release.sh`
  retains its stronger independent-snapshot A/B authority.

  `scripts/verify-android-builder-authority.py` binds the shell topology, forbidden mounts/flags, comparator semantics,
  requirement/disposition/ledger, and shared-gate wiring and rejects deliberate weakening mutations. The independent
  workspace verifier also binds that focused verifier and its policy anchors. This source slice did not itself run
  the Android builder or exercise Android. The later exact target-local A/B transaction at
  `29915f0075f4d1464361f218e61dd7d7e7072b85`, recorded under R-S14/R-T4 and R-S11bm/R-S11e-79, validates the
  current builder path and signed APK; full R-B2/R-B10 release and real-device behavior remain open.
- **R-S11bk/R-S11e-77 — Android exact-commit snapshot mode authority — SOURCE CLOSED/GATED
  2026-07-21; EXACT TARGET-LOCAL APK VALIDATED 2026-07-23; FULL RELEASE AND DEVICE EVIDENCE REMAIN OPEN.**
  Platform: Android artifact source staging.
  Endpoint/action: exact clean commit archive extraction into the immutable authority and per-pass writable build
  copy. Boundary: Git's committed regular/executable distinction ↔ filesystem permissions consumed by the offline
  build and its independently strict Gradle-init authority. The first exact-current target-local attempt at clean
  commit `d8d9ddafe4e406c3bd46d17b8d286961a81ecb15` verified its private 25-GiB online snapshot, every Android input
  pin, immutable builder image, and signing certificate, then stopped before compilation: the comparator accepted
  `0664` checked-in files inherited from archive extraction, but `scripts/android-gradle-cache.py` correctly
  refused group-writable `scripts/android-gradle-offline.init.gradle`. No APK was signed or published. This was a
  fail-closed source-mode coherence defect, not execution of the file, weakened Gradle authority, root/container
  escape, host/service/firewall mutation, port exposure, exploitation, or compromise.

  `scripts/build-android.sh` now maps the already-closed Git inventory deterministically after each extraction. The
  immutable root, every directory, and every executable are exactly `0555`; immutable ordinary files are `0444`.
  Each private writable root, directory, and executable is exactly `0755`; writable ordinary files are `0644`.
  Archive-producer and extractor umasks are no longer semantic inputs. `scripts/verify-android-build-source.py`
  binds those complete modes on both roots, all committed directories, and all committed files in addition to its
  existing owner/type/link/stable-read/digest checks. Its self-test rejects noncanonical authority and candidate
  roots, directories, regular files, and executable transitions. The strict Gradle-init ownership/mode policy is
  unchanged. `scripts/verify-android-builder-authority.py`, the shared R-S11e-76/R-S11e-77 gate, and the independent
  workspace meta-gate bind both normalization operations, every comparison level, the negative tests, R-S11bk,
  Appendix C #200, and this ledger row with deliberate mutations. The later exact target-local A/B transaction at
  `29915f0075f4d1464361f218e61dd7d7e7072b85` crossed this mode authority and produced byte-identical validated
  signed APKs; full R-B2/R-B10 release and device behavior remain open.
- **R-S11bl/R-S11e-78 — Android bounded scratch lifecycle — SOURCE CLOSED/GATED 2026-07-21;
  EXACT TARGET-LOCAL APK VALIDATED 2026-07-23; FULL RELEASE AND DEVICE EVIDENCE REMAIN OPEN.** Platform: Android
  offline artifact compilation.
  Endpoint/action: the pinned toolchain extraction, native JNI compilation, and private Gradle-cache projection
  inside the existing non-root networkless Android compile container. Boundary: verified immutable offline inputs
  and disposable build state ↔ the explicit 10-GiB <code>/tmp</code> tmpfs and 12-GiB memory/no-swap ceiling.
  The first exact build at pushed commit <code>fea99e583a560736771606a39f58a309ad550a2a</code> passed both
  exact-source comparisons and strict Gradle authority, then failed closed with <code>ENOSPC</code> while extracting
  LLVM. The inner harness had already projected 4,694,925,312 allocated bytes of Gradle state before retaining
  9,093,156,864 bytes of expanded Rust-installer, Android cross-std, Flutter, and LLVM payloads and adding the
  645,922,816-byte installed Rust toolchain. This was a deterministic resource-lifecycle contradiction before
  compilation, not an unbounded host write, partial-toolchain execution, root/container escape, host service or
  firewall mutation, port exposure, exploitation, or compromise.

  The correction keeps every outer authority bound unchanged and shortens inner ownership instead. Host Rust and
  Android cross-std installers are installed first, removed immediately, and proven absent before Flutter or LLVM
  extraction. LLVM remains available for bridge generation and native JNI compilation; after the JNI library and
  NDK runtime are copied into the private source output, LLVM is removed and proven absent and its environment is
  cleared. Only then does offline mode materialize the writable Gradle cache exactly once for final packaging.
  Installed Cargo deliberately remains because <code>flutter/android/app/build.gradle</code> executes
  <code>cargo metadata</code> while configuring the final build. Direct measurement in the already-present pinned
  image gives an 8,133,832,704-byte toolchain live set after installer retirement, a 2,352,091,136-byte base after
  LLVM retirement, and about 7.05 GB after adding the 4,694,925,312-byte Gradle projection. No larger tmpfs/cgroup,
  host scratch, extra mount, image operation, privilege, capability, network, or persistence fallback was added.

  <code>scripts/verify-android-builder-authority.py</code> binds the exact phase inputs, ordering, retirement
  postconditions, retained Cargo consumer, unchanged outer limits, R-S11bl, Appendix C #201, and this row, with
  deliberate mutations for each closure edge. The independent workspace verifier and shared source gate retain
  their existing enforcement roles. The later exact target-local A/B transaction at
  `29915f0075f4d1464361f218e61dd7d7e7072b85` crossed the unchanged scratch bounds twice and produced
  byte-identical validated signed APKs; the complete R-B2/R-B10 transaction and device behavior remain open.
- **R-S11bm/R-S11e-79 — Android tool preferences scratch ownership — SOURCE CORRECTION AND EXACT
  CORRECTED-COMMIT A/B CLOSED/GATED 2026-07-21; FULL RELEASE AND DEVICE EVIDENCE REMAIN OPEN.** Platform: Android offline artifact compilation.
  Endpoint/action: Android SDK/AGP user-preference state created during final Flutter/Gradle packaging. Boundary:
  numeric non-root build identity and the existing bounded ephemeral `/tmp` tmpfs ↔ the deliberately read-only
  container root and image-account home. The first exact build at pushed commit
  `c413f4e86cd05b4aac5f19bbdd9b79d4c63f50b5` proved R-S11bl through bridge generation and a complete release
  native Rust/JNI build, retired LLVM, and verified the deferred Gradle projection. AGP 7.3.1 then failed closed
  while applying `com.android.application` because it tried to create `/home/ubuntu/.android` on the read-only
  root. Shell `HOME=/tmp/buildhome` was already present, but Java's `user.home` remained account-backed. This was
  a separate hermetic-state ownership/availability defect, not ENOSPC, root execution, a host write, container
  escape, host service or firewall mutation, port exposure, exploitation, or compromise.

  The initial correction at pushed commit `ba29c955ea61a374318f94ad7a24699c987256a6` used Android's official
  `ANDROID_USER_HOME` preference-directory contract. Its clean default A/B transaction completed successfully:
  both passes produced the same signed and externally validated APK SHA-256
  `918456d08bb6b7a5ef3bf767ce7aa1395afb30dfefea56fca23cca0699d9e603`, with manifest, mobile at-rest bootstrap,
  v2/v3 signing, checksum, exact-source postconditions, and offline cache projection all green. Both passes also
  emitted the same nonfatal warning for `/home/ubuntu/.android/analytics.settings`, so that result is retained as
  baseline artifact evidence but is not misrepresented as complete preference ownership. Direct `javap` inspection
  inside the pinned non-root, networkless, read-only-root builder established that AGP 7.3.1's exact
  `com.android.tools.analytics-library:shared:30.3.1` dependency predates `ANDROID_USER_HOME`: its
  `AnalyticsPaths.getAndEnsureAndroidSettingsHome()` checks `ANDROID_PREFS_ROOT`, then `ANDROID_SDK_HOME`, then JVM
  `user.home`.

  The dual-variable correction at pushed commit `b757d8207a8be8fc063661dfba1369428021debd` was then tested through
  the exact default path rather than accepted from source reasoning. Its pass A authenticated the complete online
  snapshot, reproduced the private exact source, generated the bridge, completed the release native Rust/JNI build
  in 2m27s, retired LLVM, and verified the deferred Gradle projection. AGP then failed closed while deriving its
  default debug-keystore location. Inspection of exact `com.android.tools:common:30.3.1` bytecode proved why:
  `ANDROID_USER_HOME` is a final path, whereas `ANDROID_PREFS_ROOT` is a parent to which current tools append
  `.android`. Giving both the same string therefore produced two different resolved locations, which
  `PathLocator.singlePathOf()` rejects. The failed private build published no APK and its owned workspace was
  removed. This was another fail-closed compatibility/availability finding, not a reason to widen the root,
  resources, privileges, or mounts.

  The corrected single-input design clears `ANDROID_USER_HOME` and `ANDROID_SDK_HOME`, then exports only
  `ANDROID_PREFS_ROOT=/tmp/android-preferences-root`. Before any extracted toolchain or Android/Gradle consumer,
  each fresh container requires that root absent, creates both it and its `.android` child as real mode-0700
  directories, and proves current numeric-UID ownership and mode for both. The exact pinned legacy analytics
  component uses the private root directly; current location code resolves the private child, so both semantics
  are owned without conflicting injections. The tree remains on the already-authorized 10-GiB tmpfs and is
  discarded with the pass. Competing Android homes and JVM-wide Java options/home overrides are explicitly
  refused; there is still no host mount, writable root, scratch or memory increase, persistence fallback, image
  operation, privilege, capability, network, or port. `scripts/verify-android-builder-authority.py` binds the exact
  single root, competing-input clearing/refusal, freshness, both private constructions/postconditions, ordering
  before tool consumers, R-S11bm, Appendix C #202, and this row with deliberate mutations; the shared verifier and
  independent workspace meta-gate retain their enforcement roles.

  Exact target-local artifact evidence: clean pushed commit
  `36ed7a621496ed470cad5347f7598c18858de827` ran the default A/B transaction in the already-present immutable
  builder image `sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121` against independently reverified
  online closure `a7581f0ffa4fa924d4eacfe6c2bef9dec37a2ce2d06740c04037489341d904ac`. Both passes completed the native
  release build, produced the same Gradle projection
  `d125106b46b68b91618ca0c612f163098c1a3141d9bbe47bf7cf07d6353d7dab`, and emitted byte-identical v2/v3-signed
  APKs with SHA-256 `918456d08bb6b7a5ef3bf767ce7aa1395afb30dfefea56fca23cca0699d9e603`. Manifest, mobile at-rest bootstrap,
  certificate, checksum, exact-source pre/postconditions, and host publication checks passed. The complete retained
  log contained neither the legacy `/home/ubuntu/.android/analytics.settings` warning nor the conflicting-location
  and debug-keystore diagnostics, and the wrapper reported `ANDROID_PREFERENCES_RESULT=clean`. This is exact
  named-commit target-local A/B evidence. It is not the independent-snapshot full R-B2/R-B10 release transaction
  and does not prove Android device behavior; those obligations remain open.

  Exact current source/artifact follow-up: clean pushed commit
  `29915f0075f4d1464361f218e61dd7d7e7072b85`, which includes the complete persistent-service capture-owner and
  listener-generation correction, completed the same official default A/B transaction against refreshed canonical
  online closure `5ad074e7bfba62f87d3dc58614c0b33749b513d353bcaf6eaa315a6d8bf67d07`. Both passes independently
  produced Gradle projection `b95fd5dae80230287c850081fdf0804503888bb67f337649f24b1075770f02b2` and
  byte-identical, one-signer v2/v3-valid, fully artifact-validated APKs at SHA-256
  `20af1c99178feb02e3a584a4148dbc5ce8129261361f7f37d0c09461d3e6f02e`. This supersedes the older
  target-local artifact as the current named-commit APK evidence. It still is not physical-device validation or
  the complete independent-snapshot R-B2/R-B10 release transaction.
- **R-S11bn/R-S11e-80 — installed-service ownership uses exact executable identities — SOURCE
  IMPLEMENTED/GATED 2026-07-22; NATIVE MACOS AND EXACT PACKAGED-ARTIFACT EVIDENCE REMAIN
  R-R2/R-B2.** Platforms: Linux and macOS installed desktop entry processes; Windows retains its
  separately proved exact current-MSI-package executable classifier. Endpoint/action:
  `platform::is_installed()`, consumed before unattended-password and machine-policy routing,
  root CLI user-main-IPC selection, installed UI state, and other service-aware behavior. Boundary:
  the running executable identity ↔ the decision that machine credentials/policy belong to the
  root/LaunchDaemon service and therefore may never fall back to user-owned storage after service
  denial or unavailability. Linux previously accepted every lossy current-executable string beginning
  with `/usr` or `/nix/store`; macOS accepted every string beginning with
  `/Applications/<app>.app`. Those prefixes also describe sibling names, helper executables, copied
  bundles, and future files beneath the tree rather than one supported app entry. This was a
  source-proven caller-side authority-classification defect and possible fail-closed availability
  error. It is not evidence of an unprivileged local-to-root write: the privileged receivers retain
  independent polkit/Authorization Services, peer-process, and installed-helper proofs, and no real
  machine, service, credential, listener, firewall, or package was exercised or changed.

  The classifier now compares `Path` values without lossy conversion or prefix matching. Linux has
  one closed two-entry inventory: the packaged `/usr/share/rustdesk/rustdesk` runner and exact
  `/usr/bin/rustdesk` entry, covering the documented platform-dependent `current_exe` symlink result
  without admitting their directories. macOS derives and admits only
  `/Applications/<app>.app/Contents/MacOS/<app>`. Current-executable lookup failure and `/usr` or app
  bundle prefixes, sibling/helper names, copied bundles, Nix-store paths, and every unlisted path
  classify non-installed. That false result preserves portable user ownership; an exact installed
  path still selects service ownership before service readiness and therefore retains R-S11b's
  no-fallback rule. Receiver authorization remains independent and unchanged.

  Focused Rust regressions accept only the supported Linux entries and exact macOS app executable and
  reject directory, prefix-confusion, helper, copied-bundle, and Nix-store examples. The standalone
  `scripts/verify-installed-service-classifier.py` parses both platform implementations, binds the
  closed inventories, exact equality, fail-closed lookup result, tests, R-S11bn, Appendix C #207,
  this row, and shared/Apple gate wiring, and rejects 16 deliberate mutations. Linux compilation and
  test execution use the existing pinned Rust 1.75 offline container. The Apple checker proves source
  shape only; no native Mac, signed app, installed service, or exact release artifact is claimed, and
  those evidence obligations remain R-R2/R-B2.
- **R-S11bo/R-S11e-81 — Unix desktop helper IPC accepts only exact process roles — SOURCE
  IMPLEMENTED/GATED 2026-07-22; NATIVE MACOS AND EXACT PACKAGED-ARTIFACT EVIDENCE REMAIN
  R-R2/R-B2.** Platforms: Linux and macOS desktop connection-manager and helper-listener IPC.
  Endpoint/action: the server authenticates the selected `_cm` endpoint's `--cm` or `--cm-no-ui`
  role before the mutual launch-token proof and any helper authority disclosure; CM and whiteboard
  listeners authenticate the connected main server's `--server` role before answering an endpoint
  challenge or accepting typed traffic. Boundary: the already-connected local peer PID ↔ receiver-owned
  classification of that process's complete launch role. The inherited shared predicate enumerated all
  processes with the current executable name, lowercased only `argv[1]`, accepted any command line with
  at least two elements, and then searched the result for the connected PID. A same-image process with
  `--CM`, `--SERVER`, or any arbitrary suffix therefore satisfied a claimed first-argument role. Git
  history traces the global first-argument helper to imported baseline `c2abd3b3` and the macOS endpoint
  wrapper's reuse of it to `806fce15`. This is a source-proven receiver role-confusion/assurance defect,
  not a demonstrated local-to-root write or evidence of host compromise: exact connected-peer PID,
  current executable, UID/session where applicable, server-parent ancestry, launch-token HMAC, endpoint
  challenge, typed connection authority, and privileged service authorization remain separate proofs.

  Receiver authority is now explicit and closed. After arbitrary `argv[0]`, the CM classifier accepts
  exactly one case-sensitive argument matching the selected `--cm` or `--cm-no-ui` mode. The helper
  server classifier accepts only exact `--server` or exact
  `--server --service-owned-server`, preserving both the user-supervised and installed-service-owned
  server contracts without admitting a prefix, suffix, duplicate, case variant, reordered marker, or
  wrong role. Linux reads `/proc/<connected-pid>/cmdline`; macOS reads that connected PID's process argv.
  Acquisition failure denies the connection. The unused global same-name process scan helpers are
  deleted. No executable, UID/session, parent, token, HMAC, endpoint-challenge, capability, or service
  authorization check is weakened or merged into argv classification.

  The focused Rust regression accepts all four legitimate vectors and rejects missing, case-varied,
  suffixed, wrong-role, and service-marker-plus-suffix forms. The standalone
  `scripts/verify-unix-helper-process-role.py` parses the exact-length and case-sensitive predicate,
  the closed CM/server inventories, direct peer-PID readers, fail-closed branches, removal of ambient
  scan helpers, test negatives, R-S11bo, Appendix C #208, this row, and shared/Apple gate wiring, and
  rejects 18 deliberate semantic mutations. The independent workspace verifier passes its complete
  current-tree source-mutation matrix with the new focused verifier sealed as an input. The shared and
  Apple gates also replace their former greps
  for the weak first-argument helper with direct-argv and exact-role assertions. Linux compilation and
  tests use the exact installed Rust 1.75 toolchain and reviewed offline Cargo/vcpkg inputs in a bounded
  non-root, network-disabled, read-only-source container: the focused regression passes 1/1 with 339
  unrelated tests filtered. Rustfmt reports no slice-owned difference; two pre-existing unrelated
  `auth.rs` hunks remain outside this change. The repository-pinned main-verifier image is absent locally,
  so the already-present content-addressed dev-check image supplies diagnostic evidence only and is not
  substituted for release provenance. The Apple result is source shape only: no native Mac, signed app,
  installed service, exact release artifact, or end-to-end helper connection is claimed, and those
  evidence obligations remain R-R2/R-B2.
- **R-S11bp/R-S11e-82 — outgoing voice-call capture is event-driven and exact-subscription-owned —
  SOURCE IMPLEMENTED/GATED 2026-07-22; EXACT NATIVE/APK/DEVICE/ARTIFACT EVIDENCE REMAINS
  R-B2/R-B10.** Platforms: the shared non-iOS outgoing viewer (Android plus desktop; iOS has no local
  audio-service voice-capture worker). Endpoint/action: an accepted outgoing voice call subscribes one
  synthetic `ConnInner` to the process-local audio service and forwards its audio frames into that
  exact viewer round. Boundary: the viewer round's `VoiceCallThread` owner ↔ the subscription, audio
  receiver, global voice-input selection, and dedicated worker handle. The inherited worker created a
  separate standard-library stop channel, then executed an unconditional loop that called
  `try_recv()` on both stop and audio. With neither channel ready it performed no wait at all, so every
  active voice call could consume a CPU core while idle. The stop sender did not itself revoke the
  exact service subscription keeping the audio receiver open. Git history places this loop in the
  imported baseline. This is a source-proven shared resource-availability and lifecycle-coherence
  defect. Android's persistent process can amplify its duration, but it is not an on-device causal
  reproduction or proved explanation of the reported one-host screen-control hang; it is unrelated to
  host RustDesk, firewall/listener state, Docker privilege, exploitation, or compromise.

  `VoiceCallThread` now owns one durable stop flag, the exact subscribed synthetic `ConnInner`, and the
  exact worker handle. Every normal voice-call close, reconnect/final viewer teardown, and hard-Drop
  handoff reaches the same `stop()`: it publishes retirement first, then unsubscribes that exact
  connection. Removing the service copy and dropping the owner's retained sender closes the channel,
  waking a worker blocked without audio. The worker uses `blocking_recv()` on its dedicated standard
  thread—no sleep, polling, nested runtime, or detached task—and rechecks the stop flag after wake, so
  already queued audio cannot cross retirement. Spontaneous audio-channel closure performs an
  idempotent unsubscribe and restores voice-input state. Named-thread spawn failure immediately rolls
  back the just-created subscription and input selection. The existing fixed media-completion pool
  retains and joins the exact handle; this slice does not weaken its bounded admission or abort-on-loss
  rules.

  Focused behavior regressions prove that an idle receiver remains blocked, exact subscription-channel
  closure wakes it within a fixed test deadline, a durable stop suppresses already queued audio, and a
  live message preserves object identity. The standalone
  `scripts/verify-viewer-voice-call-worker.py` binds the composite owner, stop-before-unsubscribe
  ordering, blocking receive and post-wake check, worker cleanup, spawn-failure rollback, existing
  completion-pool sinks, polling-channel absence, R-S11bp, Appendix C #209, this row, and shared-gate
  and Apple-gate wiring; its combined R-S11bp/R-S11bq self-test now rejects 36 deliberate semantic
  weakenings. The independent
  workspace verifier passes normally and its complete current-tree source-mutation matrix rejects the
  registered weakened contracts. Exact Rust 1.75 locked/offline compilation from the reviewed local
  vendor closure in a fresh bounded, non-root, network-disabled tmpfs target passes both focused tests:
  2 passed, 0 failed, 340 unrelated tests filtered. Python byte-compilation, edited-shell syntax,
  `git diff --check`, requirements-hash equality, and native-codec normal/self-test gates also pass.
  The available diagnostic image has no Rustfmt component, so no formatter result is claimed. No current
  APK, native Android/desktop voice-call session, real device, exact release artifact, or R-B2/R-B10
  transaction is claimed here.
- **R-S11bq/R-S11e-83 — voice-call input selection has exact concurrent owners — SOURCE, FOCUSED RUST,
  SOURCE GATE, AND MUTATION VERIFIED; EXACT NATIVE/APK/DEVICE/ARTIFACT EVIDENCE REMAIN OPEN.** Platforms: the shared Rust audio service used by
  non-iOS outgoing viewers and
  controlled Remote/ViewCamera connections on Android and desktop. Endpoint/action: selecting and restarting
  the one process-wide physical voice-call input while independently owned calls start, stop, reconnect, close,
  or are cancelled. Boundary: each exact call owner ↔ the shared audio-input selection and capture-service
  restart. The inherited `VOICE_CALL_INPUT_DEVICE: Option<String>` exposed one
  `set_voice_call_input_device(device, set_if_present)` function for both selection and ownership. Every
  outgoing worker and accepted controlled connection selected that global, while independent worker-exit,
  explicit-close, asynchronous-close, and `Connection::Drop` paths unconditionally wrote `None`. The controlled
  connection separately carried `voice_calling: bool`. Multiple outgoing sessions and multiple controlled
  connection IDs are valid process state; no source invariant serialized them. One call could therefore clear
  and restart input still required by another, and the boolean, worker, and global selection could diverge. This
  is a source-proven shared resource-availability/lifecycle defect. It is not evidence of host RustDesk
  modification, a public listener, firewall change, Docker privilege, exploitation, or compromise, and it is
  not a device reproduction or proved cause of the reported one-host screen-control symptom.

  `VoiceCallInputState` now owns the selected device plus a checked active-owner count. Only
  `acquire_voice_call_input()` can construct the private, non-cloneable `VoiceCallInputLease`: the first owner
  installs its default only when no selection exists, later owners share the one physical stream, and operator
  device selection changes that stream without changing ownership; the public selection API accepts only a
  concrete device, so it cannot clear the lease-owned state. Releasing a non-final lease does nothing to
  the selection; final release alone clears it and requests restart. Acquisition overflow returns failure without
  mutation, while impossible release underflow logs the invariant failure and aborts instead of silently
  continuing with corrupt accounting. The obsolete `set_if_present` API is deleted.

  `VoiceCallThread` now owns its lease alongside the exact subscription, durable stop flag, and worker handle.
  Stop publishes retirement, removes the exact subscription, and then drops only that lease; the worker and its
  spawn-failure branch have no global-`None` cleanup authority, so lexical lease drop supplies exact rollback.
  Controlled `Connection` stores `Option<VoiceCallInputLease>` instead of `voice_calling`, acquires before its
  first response await, reports refusal if acquisition fails, derives overlap/audio admission from lease
  presence, and takes only its exact lease during explicit close, asynchronous close before its first cleanup
  await, and hard `Drop`.

  Layer boundary: this Rust ownership slice did not by itself make the separate Android native recorder
  state machine correct. Its source tracing found that `MainService.rustSetByName("update_voice_call_state")`
  receives an exact controlled connection ID but switches the process-wide `AudioRecordHandle` directly for
  each individual state event; a false event can switch out while another ID remains active, and ordinary
  connection removal does not send an exact native owner-retirement event. Outgoing activity voice-call events
  likewise reached `MainActivity` without a native Activity-session owner and could cross the activity/service
  recorder handoff. R-S11br/R-S11e-84 independently closes that Android source topology; both layers remain
  required and neither substitutes for the other. No
  current APK, native Android/desktop voice-call transaction, real-device sequence, exact release artifact, or
  R-B2/R-B10 transaction is claimed here.

  Verification: exact Rust 1.75 locked/offline library tests compiled against the complete pinned read-only
  `online/cargo-vendor` source map in a fresh non-root/network-disabled tmpfs target. Both R-S11e-83 ownership
  regressions passed (`2 passed`, `0 failed`, `342 filtered`); the two adjacent R-S11e-82 event-driven worker
  regressions also passed (`2 passed`, `0 failed`, `342 filtered`). Compilation completed with the repository's
  existing warning set and is not claimed warning-free. The focused semantic verifier passed normally and rejected
  all 36 registered R-S11bp/R-S11bq mutations. The independent workspace verifier passed normally and its complete
  current-tree in-memory source-mutation matrix passed. Python byte-compilation, edited Bash syntax, retired-symbol
  residue checks, `git diff --check`, requirements-hash equality, and native-codec normal/self-test gates passed.
  The available image has no Rustfmt component, so no formatter result is claimed. The workspace verifier's broader
  behavioral self-test was attempted but is not counted: its managed-command fixture requires a real current-UID
  systemd user-bus socket, and the isolated container deliberately mounts no host runtime directory or bus. The
  current repo-pinned full-verifier image is not locally present, and the binding loop excludes the long release
  build, so no repository-wide `scripts/verify.sh` or release transaction result is claimed.
- **R-S11br/R-S11e-84 — Android native voice-call capture has exact process-wide owners — SOURCE,
  FOCUSED KOTLIN, SOURCE GATE, AND MUTATION VERIFIED 2026-07-22; EXACT TARGET-LOCAL APK VALIDATED
  2026-07-23; NATIVE DEVICE AND FULL RELEASE EVIDENCE REMAIN R-B10/R-B2.** Platform: Android API 30+
  native playback/microphone
  capture inside the one application process retained by `MainService`. Endpoint/action: controlled-side
  `add_connection`/`update_voice_call_state`/`remove_connection` JNI callbacks, outgoing Flutter
  `on_voice_call_started`/`on_voice_call_closed`, Activity creation/resume/destruction, service task removal and
  destruction, and MediaProjection playback start/stop. Boundary: exact live controlled connection or current
  Flutter Activity-session owner ↔ the process-wide `AudioRecord`, its blocking reader worker, and the exact
  MediaProjection playback grant.

  The inherited topology gave `MainService` and `MainActivity` separate `AudioRecordHandle` objects. Outgoing
  events selected one from current service-binding timing; controlled connection state switched the service
  recorder immediately from each connection's Boolean event. A false event from one connection could therefore
  switch out a second live call, ordinary connection removal sent no native retirement event, and Activity/task
  replacement could retain or address stale native state. `AudioRecordHandle.createAudioRecorder()` accepted a
  built but uninitialized recorder, `startAudioRecorder()` returned no success state, buffer setup could retain a
  partial recorder, and a null result from the blocking read loop did not terminate the loop. This is a
  source-proven Android native resource/lifecycle defect and a plausible contributor to state that survives an
  Activity swipe until Force Stop kills the service process. It is not an on-device reproduction or causal proof
  of the reported one-host screen-control symptom, and it is not evidence of host modification, Docker/root use,
  listener exposure, firewall change, privilege escalation, exploitation, or compromise.

  The inherited Rust Activity-resume state also admitted an older Activity carrying a different Flutter-isolate
  UUID by minting it a fresh generation and closing the current replacement isolate's sessions. The native recorder
  coordinator correctly refused that cross-isolate transfer only after Rust had already mutated ownership, which
  could leave Rust session authority and the persistent recorder assigned to different Activities. Resume is now a
  read-only exact-current-UUID check in Rust; a stale isolate cannot replace or drain the current owner, and both
  Kotlin failure branches attempt only exact recorder-owner retirement before the stale Activity finishes.

  `VoiceCallAudioCoordinator` is now the sole process-wide serialized owner of one `AudioRecordHandle`. Its pure
  `VoiceCallOwnerState` records voice-capable controlled IDs separately from the exact active subset; updates are
  admitted only for registered IDs, removal retires registration plus activity, and one connection cannot clear
  another. The outgoing owner is the positive native Activity generation plus canonical isolate UUID already used
  by the Rust session-owner gate. New Activity creation invalidates the previous native owner before Flutter can
  run; registration follows Rust owner admission with rollback; resume requires the exact current UUID and a
  generation equal to the current owner for an idempotent ordinary resume, or a newer generation for lost-response
  recovery, while preserving active state; older generations, stale Activity destruction, and stale service task callbacks
  cannot alter the replacement. Activity/task teardown retires the exact native owner before matching Rust
  sessions, while service destruction clears only controlled owners. `src/flutter.rs` now notifies the service of
  exact connection removal before publishing UI removal. Service binding has no audio-ownership semantics and the
  obsolete local/service recorder callbacks and state booleans are deleted.

  The shared outgoing response path now stops the prior exact voice worker, constructs the replacement, and
  publishes `on_voice_call_started` only after that worker exists. Lease-acquisition or worker-spawn failure instead
  publishes closed state and sends the peer an explicit close request, so Android native capture cannot be activated
  for a call whose Rust audio worker never started.

  Reconciliation has one closed priority: any active voice owner selects `VOICE_COMMUNICATION`, otherwise the live
  exact MediaProjection selects playback capture, otherwise capture stops. Playback reuse also requires object
  identity with the recorder's recorded projection, so grant replacement cannot retain the old capture. Recorder
  creation proves `RECORD_AUDIO` plus `AudioRecord.STATE_INITIALIZED`; buffer size must be positive, is widened
  before multiplication, and must fit `Int`; direct-buffer allocation failure releases the partial recorder.
  Start commits only after `RECORDSTATE_RECORDING`, publishes an unstarted named worker only after all resources
  exist, and rolls back if start or thread launch fails. A null blocking read is terminal. Spontaneous completion
  stops and releases its exact recorder; explicit stop first publishes retirement, stops to unblock the read,
  joins the exact worker while restoring interruption, then clears the exact recorder/reader/mode/projection/raw
  flag. There is no second recorder, binding fallback, hot loop, detached cleanup, or ambient global close.

  The design follows Android's official lifecycle and media contracts: a started service can outlive Activity
  binding and receives `onTaskRemoved`, while `onDestroy` is its resource-release sink
  (<https://developer.android.com/reference/android/app/Service>); started-plus-bound service lifetime is not
  defined by the binding alone (<https://developer.android.com/develop/background-work/services/bound-services>);
  competing audio captures are not a reliable ownership mechanism and `VOICE_COMMUNICATION` is privacy-sensitive
  (<https://developer.android.com/media/platform/sharing-audio-input>); `AudioRecord` construction must be checked
  for `STATE_INITIALIZED` and stopped/released after use
  (<https://developer.android.com/reference/android/media/AudioRecord>); and MediaProjection-backed capture must
  own its callback/revocation lifecycle (<https://developer.android.com/media/platform/av-capture>). The design
  implication is one application-owned state machine whose exact call owners are independent of Activity/service
  binding and whose playback mode remains subordinate to the exact live projection.

  Follow-up verifier correction (2026-07-23): the older shared R-D7a lifecycle block still named the deleted
  takeover regression and required resume to take the owner write lock, mint replacement authority, drain the
  displaced UUID, and drop that lock. Those assertions predated this row's cross-isolate refusal fix and made the
  broad gate reject the correct source while the focused gate required the opposite policy. The shared block now
  requires the current stale-Activity refusal regression and a read-only resume with no write or session-drain
  authority. The focused verifier also rejects the superseded summary/gate forms, and the independent verifier
  mutation-binds those checks. Runtime source and normative R-S11br policy did not change in this correction.

  Verification: `scripts/android-voice-call-owner-state-test.kt` compiles the Android-free owner model and executes
  invalid/unregistered admission, two-controlled-owner aggregation, stale outgoing update/teardown refusal,
  same-or-newer resume with active-state retention plus older/cross-isolate refusal, controlled/outgoing overlap,
  isolate invalidation, and service clearing. `scripts/verify-android-voice-call-ownership.py` binds the complete
  Kotlin/Rust topology, lifecycle
  ordering, one-recorder count, mode priority, projection identity, buffer/start/worker cleanup, platform-channel
  completion, worker-before-native start publication, requirement, disposition, ledger, and shared-gate wiring, and
  rejects 61 deliberate semantic mutations. The independent workspace verifier loads every new source, validates the
  focused verifier rather than
  trusting its output, and mutation-binds the new gate/requirement/disposition/ledger plus the updated
  MediaProjection audio-retirement contract.

  Exact current-source verification passed in confined non-root, network-disabled, read-only-source containers:
  the Android-free Kotlin owner transition regression compiled and executed; the focused verifier passed normally
  and rejected all 56 registered mutations; and the independent workspace verifier passed normally plus its complete
  in-memory source-mutation matrix. The Android release Kotlin compilation completed with `BUILD SUCCESSFUL` in 30
  seconds (`228` actionable tasks: `227` executed, `1` up-to-date); existing unrelated deprecation and static-analysis
  warnings remain and no APK was assembled. Locked/offline Rust 1.75 library tests passed all three Android
  Activity-owner regressions (`3 passed`, `0 failed`, `347 filtered`) and both adjacent event-driven voice-worker
  regressions (`2 passed`, `0 failed`, `348 filtered`); pinned Rustfmt passed the two changed Rust files and
  `Cargo.lock` remained byte-identical. Python byte-compilation, edited Bash syntax, requirements-hash equality
  (`19765e32030adbbb3c25b2f98ec28a09ba6f6bd8da2b95287911023b8797e120`), and native-codec normal/self-test gates
  passed. These checks used no published port, Docker socket, host PID/network namespace, host service/config mount,
  host networking, added capability, or root process.

  This source slice did not itself exercise Android or assemble an APK. The later exact target-local A/B
  transaction at `29915f0075f4d1464361f218e61dd7d7e7072b85`, recorded under R-S14/R-T4 and
  R-S11bm/R-S11e-79, validates that this source is packaged in the byte-identical signed APK. No Android device,
  installed voice-call transaction, original swipe/relaunch sequence, OEM task behavior, or full R-B2/R-B10
  release transaction is claimed; those remain open.
- **R-S11bs/R-S11e-85 — Unix incumbent-listener identity is explicit — SOURCE IMPLEMENTED AND CONFINED
  FOCUSED/WORKSPACE VERIFIED 2026-07-22; EXACT INSTALLED ARTIFACTS PENDING.** Platform: Linux and macOS pathname
  Unix-domain listeners.
  Endpoint/action: the singleton check performed before binding main, user/service password, `_service`, `_pa`,
  `_cm`, `_url`, and launch-token-derived whiteboard endpoints. Boundary: a namespace entry accepting `connect(2)`
  ↔ authority to keep the legitimate RustDesk image from reclaiming its local listener pathname.

  The inherited default returned true immediately after any successful connection. Except for the stronger Linux
  `_cm`/`_pa` checks and `_service` liveness exchange, no peer UID, PID, executable, role, or launch proof entered
  the incumbent decision. An unrelated same-UID executable could therefore bind a user-owned endpoint first and
  hold local availability without ever passing that endpoint's later receiver authentication. This was not message
  authorization: accept-time UID/executable/role/token/capability checks still rejected its traffic. It was a
  deterministic local singleton-availability and lifecycle-authority ambiguity, not credential disclosure, LPE,
  remote reachability, exploitation evidence, host mutation, or compromise.

  `probe_existing_listener` now returns `ResultType<bool>` and treats connected peer identity as fallible evidence.
  For every endpoint not already covered by the stronger Linux `_cm`/`_pa` proofs, it requires the connected
  socket's kernel-reported peer UID and PID, exact equality with the current effective UID, and a positive match
  between the peer and current executable. A positive UID or executable mismatch is a foreign stale candidate;
  missing peer credentials or an unavailable executable proof propagates an error through `check_pid` and
  `new_listener`, preserving the ambiguous live namespace entry instead of unlinking it and creating split-brain
  listener state. The protected `_service` path additionally retains its bounded typed `Data::Test` round trip;
  once current identity is proven, a failed or malformed liveness response is now an error rather than cleanup
  authority. Incumbent probing remains separate from and weaker than normal message admission; no new request is
  admitted by this change.

  Linux documents `SO_PEERCRED` as the read-only credentials of the peer process connected to the Unix socket,
  captured at `connect`, `listen`, or `socketpair` time (<https://man7.org/linux/man-pages/man7/unix.7.html>), and
  documents `/proc/<pid>/exe` as the executed-program reference with ptrace-governed read/dereference permission
  (<https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html>). The implementation deliberately propagates the
  latter permission/identity failure instead of treating absence of proof as proof of staleness. macOS continues to
  use the existing connected-socket peer UID/PID and same-file executable implementation.

  Confined verification used development image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` with a read-only root filesystem and
  source mount, UID/GID 1000, no network, all capabilities dropped, `no-new-privileges`, and tmpfs-only build/cache
  state. Locked/offline `cargo test --lib --features linux-pkg-config r_s11e85_` compiled the library-test graph and
  passed the focused policy regression (`1 passed`, `0 failed`, `344 filtered`). The standalone semantic verifier
  passed all 18 deliberate mutations; the independent workspace verifier passed both its normal validation and full
  source-mutation matrix. Python byte-compilation, edited Bash syntax, `git diff --check`, native-codec normal and
  self-test gates, and requirements-hash synchronization
  (`19765e32030adbbb3c25b2f98ec28a09ba6f6bd8da2b95287911023b8797e120`) passed. Pinned Rustfmt 1.75 parsed all
  three touched Rust files and reported no changed hunk; its whole-file check remains nonzero solely for pre-existing
  drift in `src/ipc/auth.rs` around lines 1759/2268 and `src/ipc/fs.rs` around lines 1003/1142, which this narrow slice
  does not rewrite. `Cargo.lock` remained unchanged. No published port, Docker socket, host PID/network namespace,
  host service/config mount, host networking, added capability, or root process was used.

  The residual same-account denial of service is explicit: code already running under the same UID can mutate its
  own mode-0700 socket directory repeatedly, so this slice does not claim a stronger OS-principal isolation boundary
  than the platform provides. Exact installed Apple/Linux artifacts and the cold R-B2 release transaction remain
  separately open.
- **R-S11bt/R-S11e-86 — Windows Installer never launches the remote-control application — SOURCE IMPLEMENTED
  AND CONFINED SOURCE/MUTATION VERIFIED 2026-07-22; NATIVE MSI AND EXACT ARTIFACT EVIDENCE REMAIN
  R-B2/R-B10.** Platform: the per-machine WiX Windows Installer package. Endpoint/action: completion of an
  interactive installation and optional tray-selection property. Boundary: administrator approval to perform the
  finite machine-state transaction ↔ authority to create a long-lived interactive RustDesk desktop/tray process.

  `res/msi/Package/Package.wxs` declares `Scope="perMachine"`. The inherited
  `res/msi/Package/Components/RustDesk.wxs` nevertheless defined installed-file Type 18-style `LaunchApp` and
  `LaunchAppTray` executable custom actions targeting `App.exe`. Both were sequenced after `InstallFinalize` with
  `Return="asyncNoWait"`; `LaunchApp` ran for every non-basic-UI install that was not an ordinary uninstall, while
  `LaunchAppTray` was selected by the public `LAUNCH_TRAY_APP` property, defaulted in
  `Fragments/AddRemoveProperties.wxs`. Thus an interactive remote-control process could survive the transaction
  under whichever principal and token serviced the installation. Windows Installer immediate custom actions use
  user context by default, but that is not a stable ordinary-desktop-user identity: an elevated installer client or
  an over-the-shoulder UAC credential prompt can supply administrator authority, and Windows Installer documents
  additional system-context custom-action cases. This finding is an authority/principal ambiguity and unnecessary
  post-install execution surface, not proof of a promptless LPE, remote exploit, host compromise, or use of the path.

  The closure is deletion-first. Both executable custom-action definitions, both sequence entries, the obsolete
  `LAUNCH_TRAY_APP` property, and all MSI `asyncNoWait` application-start behavior are removed. No de-elevation
  shim, token discovery, Explorer trampoline, shell command, compatibility fallback, or replacement background
  launch is introduced. The existing declarative `ServiceInstall` and `ServiceControl` entries remain: installation
  can install/start the machine-owned `--service` runtime, while a person starts the interactive UI later through
  the installed shortcut or executable under that person's ordinary launch authority.

  The shared R-S11e-20/R-S11e-86 gate rejects each retired definition, schedule, file reference, selector, and
  asynchronous form across the complete package WiX source tree, while retaining the exact service declaration checks.
  The independent workspace validator and deliberate mutations bind that gate, the two declarative service entries,
  R-S11bt, Appendix C #213, this ledger entry, and the current requirements-hash scope. Its normal source path scans
  the aggregate of every current package `.wxs`; its individually loaded component/property fragments keep the exact
  mutation targets independent of that aggregate. The first mutation run exposed and rejected an incomplete test
  construction in which the aggregate was not rebuilt after an individual-fragment mutation. After the validator
  was corrected to inspect both views, the complete repository-wide source-mutation matrix passed, including the
  nine new application-launch/service-preservation/documentation mutations and the updated hash-scope mutation.

  Confined verification used the already-present immutable development image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` with UID/GID 1000, a read-only root
  filesystem and source mount, no network, all capabilities dropped, `no-new-privileges`, bounded PID/memory/CPU
  limits, and tmpfs-only scratch state. `bash -n` passed the edited shared gate; Python byte-compilation passed the
  independent verifier; both modified WiX documents parsed as XML; and normal semantic validation plus the full
  in-memory source-mutation matrix returned `verify-verifier-workspace: ok`. A separate recursive package probe
  found none of the seven retired tokens, proved both service declarations remain, and proved the synchronized
  requirements SHA-256
  (`c232fe6d7174b54f1b9caf095b4f71fd4d75694784894983c38cf78d519a9cde`). Native-codec normal and self-test gates
  also passed. No image was pulled or built; no port, Docker socket, host PID/network namespace, host service/config
  mount, host networking, added capability, or root process was used. No host RustDesk process, service, listener,
  configuration, device, firewall, or network state was inspected or changed.

  Primary platform contracts: Microsoft documents that custom actions run with user privileges by default and also
  describes elevated/system custom-action contexts
  (<https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security>); installed-file executable custom
  actions are Type 18 and must be sequenced after their source is installed
  (<https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-18>); `asyncNoWait` permits continuation
  without waiting for the custom-action thread
  (<https://learn.microsoft.com/en-us/windows/win32/msi/synchronous-and-asynchronous-custom-actions>); and UAC
  over-the-shoulder elevation uses credentials supplied by an administrator
  (<https://learn.microsoft.com/en-us/windows/win32/msi/using-windows-installer-with-uac>). No native MSI was built or
  executed by this source slice. Final WiX compilation, Windows install/repair/upgrade/uninstall behavior, service
  behavior, installed shortcut behavior, and exact signed-artifact proof remain the cold R-B2/R-B10 obligations.
- **R-S11bu/R-S11e-87 — protected Windows setup uses the typed Installer API — SOURCE IMPLEMENTED AND
  CONFINED SOURCE/MUTATION/CROSS-TARGET VERIFIED 2026-07-22; NATIVE INSTALLER AND EXACT ARTIFACT EVIDENCE REMAIN
  R-B2/R-B10.** Platform: the UAC-approved Windows setup bootstrapper in `libs/portable`. Endpoint/action: after
  extracting the sole embedded `rustdesk-installer.msi` into the protected Program Files staging directory,
  invoke Windows Installer and retain the exact completion status. Boundary: the user-selected setup process's
  environment, working directory, inheritable process state, and child lifetime ↔ the administrator-authorized
  per-machine MSI transaction.

  The inherited protected leg derived a fully qualified, regular, non-reparse System32 `msiexec.exe`, constructed
  the exact `/i <staged-msi> /norestart` argv (plus `/qn` for silent mode), spawned it through Rust `Command`, waited,
  and accepted only 0 or 3010. The fixed executable, fixed one-file manifest, protected staging root, no-reparse
  checks, and closed argv substantially constrained the path. However, Microsoft documents that a child process
  inherits the parent's environment and current directory by default and that the standard DLL search path can
  include the current directory and `PATH`. This setup is deliberately launched from a user-selected file location
  and context before UAC. Source inspection did not prove a missing Windows Installer dependency, attacker-selected
  DLL load, promptless LPE, exploitation, host compromise, or use of this path; the defect was an unnecessary
  conceptual privileged child-process authority boundary.

  Source closure deletes the System32 discovery helper and the entire `msiexec` spawn/wait abstraction. The already
  elevated setup now enables the pinned Windows bindings for `ApplicationInstallationAndServicing` and calls
  `MsiInstallProductW` directly with the already validated local MSI path and the sole property
  `REBOOT=ReallySuppress`. Interactive mode explicitly selects `INSTALLUILEVEL_DEFAULT`; silent mode explicitly
  selects `INSTALLUILEVEL_NONE`. `MsiSetInternalUI` returns the exact prior process UI level, which a non-cloneable
  lexical owner restores on every normal/error return. The typed unsigned result accepts only `ERROR_SUCCESS` (0)
  and `ERROR_SUCCESS_REBOOT_REQUIRED` (3010); `ERROR_SUCCESS_REBOOT_INITIATED` (1641) remains rejected because the
  property forbids the installer from initiating a reboot. This removes only the bootstrapper-created child. It
  does not claim that the Windows Installer service and this package's declarative/custom-action transaction create
  no processes of their own.

  R-S11bu and Appendix C #214 make that authority model normative. The shared R-S11e-20/R-S11e-87 gate binds the
  exact Cargo API feature, Installer call, reboot property, both UI levels, prior-level owner/restoration, child-
  process absence, and typed status regression. The independent workspace semantic validator binds the same source,
  requirement, disposition, ledger, and current requirements-hash scope; its deliberate mutations independently
  restore a child, weaken each UI/property/status decision, or remove each documentation/gate edge. Most confined
  checks used the already-present immutable development image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`; the format-only check used the
  already-present Debian image `sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818`
  with the read-only Rust 1.75 host toolchain mounted into the container. Every check ran as UID/GID 1000 with no
  network, a read-only root and source, all capabilities dropped, `no-new-privileges`, bounded PID/memory use, and
  private tmpfs-only writable state. Rust 1.75 formatting passed; all three Linux
  `portable` unit tests passed offline, including the exact unsigned 0/3010 acceptance and 1641 rejection policy;
  and Rust 1.75 `cargo check --locked --offline --target x86_64-pc-windows-msvc` type-checked the Windows-only API
  path through `portable` and pinned `windows` 0.61.1. That cross-target check used a private read-only current-source
  snapshot with empty compile-only `data.bin` and `app_metadata.toml` fixtures because those two generated inputs are
  absent from the source tree; it is not a package or runtime test. The normal semantic validator, its complete
  source-mutation matrix, shell syntax check, Python compile check, native-codec hash watch and its negative self-test,
  and `git diff --check` also passed. An initial minimal Debian test container lacked `cc`, and an initial private
  build tmpfs was mounted `noexec`; both attempts failed closed before validation, no root/network/host execution was
  introduced, and the environment was corrected instead of weakening a gate. No image was pulled or built; no port,
  Docker socket, host namespace, host service/config mount, added capability, or root process was used. No host
  RustDesk process, service, listener, configuration, device, firewall, or network state was inspected or changed.
  Native Windows interactive/silent
  install, repair, upgrade, uninstall, reboot-required behavior, exact MSI service/custom-action behavior, and
  signed-artifact proof remain the clean cold R-B2/R-B10 obligations; this source slice does not claim them.

  Primary platform contracts: Microsoft documents default environment/current-directory inheritance for child
  processes (<https://learn.microsoft.com/en-us/windows/win32/procthread/inheritance>) and DLL preloading risk from
  current-directory/search-path resolution
  (<https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security>).
  `MsiInstallProductW` is the application-facing typed install API and uses the current Installer UI settings
  (<https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msiinstallproductw>);
  `MsiSetInternalUI` defines the default and silent levels
  (<https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msisetinternalui>); and
  `REBOOT=ReallySuppress` suppresses every Installer-initiated restart/prompt
  (<https://learn.microsoft.com/en-us/windows/win32/msi/reboot>).
- **R-S11bv/R-S11e-88 — Windows uninstall never deletes unowned certificate state — SOURCE IMPLEMENTED AND
  CONFINED SOURCE/STRUCTURE/MUTATION VERIFIED 2026-07-22; NATIVE MSI TABLE/UNINSTALL AND EXACT ARTIFACT EVIDENCE REMAIN
  R-B2/R-B10.** Platform: the per-machine Windows Installer custom-action DLL and the application Windows native
  build. Endpoint/action: the explicit-uninstall commit phase's `RemoveTestCertificates` action. Boundary: authority
  to uninstall this package ↔ LocalSystem mutation of machine and independently user-owned certificate stores.

  The inherited WiX declared `RemoveTestCertificates` with `Impersonate="no"`, `Execute="commit"`, and
  `Return="check"`, scheduled only for explicit uninstall after the transaction succeeded. The action called
  `DeleteRustDeskTestCertsW`, whose dedicated 260-line implementation opened
  `HKLM\Software\Microsoft\SystemCertificates`, the custom-action account's corresponding `HKCU`, and the same
  namespace below every loaded `HKEY_USERS` subkey. It enumerated every store and deleted the fixed-fingerprint
  registry key when its `Blob` ended in an embedded WDK test-certificate byte suffix. The same deletion source was
  also compiled into the application native library despite having no remaining application caller. A complete
  repository source/package inventory found no certificate component, certificate import/API call, certificate
  manifest, ownership record, or certificate-creation operation: this package only deleted certificate state.

  Microsoft defines a no-impersonation commit custom action as system-context work after successful script
  processing; it also warns that commit-action failure may initiate rollback that cannot undo the commit action's
  direct state change. Windows defines local-machine stores as global machine state and current-user/HKEY_USERS stores
  as separate per-account state. Microsoft further limits test signatures to development/test and requires a
  production driver to be release signed. Thus a fixed fingerprint and suffix narrowed what the scanner could
  delete, but neither proves that the current package created or exclusively owns the matching certificate. This
  was unnecessary LocalSystem cross-user/cross-product trust-store deletion authority and a potential administrative
  state deletion, not evidence of a remote trigger, promptless LPE, attacker-selected target, exploitation, host
  compromise, or use of the path.

  The closure is deletion-only. The WiX declaration and schedule, custom-action export and function, header symbol,
  Visual C++ project input, application `build.rs` input, and the entire registry/blob scanner are gone. There is no
  migration, legacy-upgrade, best-effort, current-user-only, or reduced-fingerprint replacement. This certificate
  slice initially retained checked runtime-broker cleanup and Amyuni device cleanup. R-S11e-89's later ownership
  audit deletes the Amyuni action as unowned too, so checked deferred cleanup of the exact runtime-generated broker
  file under the validated private Program Files root is now the sole package custom action. R-S11f now requires
  exact current-package ownership for custom actions and forbids certificate
  store mutation; R-S11bv and Appendix C #215 bind complete absence. The shared R-S11e-20/R-S11e-88 gate and the
  independent semantic validator cover source-file absence, application and custom-action build metadata, WiX
  declaration/schedule, DLL header/implementation/export, certificate-store/package APIs, the sole retained action,
  normative text, ledger, disposition, and requirements-hash scope. The active requirements SHA-256 is
  `77d1066651f07c69081897fa06883f1c5415bc8f0bd5edd44b03a05d5da19dda`.

  Confined verification used the already-present immutable development image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` with UID/GID 1000, no network, a
  read-only root and source, all capabilities dropped, `no-new-privileges`, bounded PID/memory use, and private
  tmpfs-only writable state. Bash syntax and Python byte-compilation passed; the normal independent semantic
  validator and its complete repository source-mutation matrix returned `verify-verifier-workspace: ok`. The 21
  new deliberate mutations restore each retired source/build/WiX/header/call/export surface, weaken the exact
  retained-action inventory, or remove each gate/requirement/disposition/ledger edge; the existing synchronized
  hash-scope mutation now binds R-S11bv/#215. Four pre-green mutation runs exposed test-construction weaknesses:
  duplicate ownership of one shared-heading target, an aggregate WiX view not rebuilt from an independently mutated
  fragment, substring rather than exact `.def` export matching, and a replacement rejection token that retained the
  original as a prefix. Each fixture/assertion was made independently falsifiable before the full matrix passed.
  Exact Rust 1.75 formatting of `build.rs` passed in the already-present Debian image
  `sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818` with the toolchain mounted read-only.
  Independent XML parsing accepted both changed WiX documents and the Visual C++ project; a direct production
  inventory at the R-S11e-88 closure commit proved the source absent, every retired/API token absent, and the then-two
  custom-action declarations, exports, schedules, and implementations present. R-S11e-89 separately revalidates the
  current sole-action inventory after Amyuni removal. Native-codec hash watch and its negative
  self-test passed. No image was pulled or built; no port, Docker socket, host namespace, host service/config mount,
  added capability, or root process was used. No host RustDesk process, service, listener, configuration, device,
  firewall, or network state was inspected or changed. The custom-action DLL was not compiled and an MSI was not
  built or executed on this Linux source-verification host. Native MSI table inspection and real installed
  explicit-uninstall behavior remain the clean cold
  R-B2/R-B10 obligations; this source slice does not claim them.

  Primary platform contracts: Microsoft documents system-context no-impersonation commit execution
  (<https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options>), commit-action
  timing and rollback limitations (<https://learn.microsoft.com/en-us/windows/win32/msi/commit-custom-actions>),
  independent local-machine and current-user certificate stores
  (<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores>),
  and that test signatures are for development/test rather than production release
  (<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/introduction-to-test-signing>).
- **R-S11bw/R-S11e-89 — Windows uninstall never removes an Amyuni device without exact device-instance ownership —
  SOURCE IMPLEMENTED AND CONFINED SOURCE/STRUCTURE/MUTATION VERIFIED 2026-07-22; NATIVE MSI TABLE/UNINSTALL AND
  EXACT ARTIFACT EVIDENCE REMAIN R-B2/R-B10.** Platform: the per-machine Windows Installer custom-action DLL and
  Windows runtime virtual-display manager. Endpoint/action: the explicit-uninstall commit phase's
  `RemoveAmyuniIdd` action and the dormant Rust Amyuni removal helpers. Boundary: authority to uninstall this package
  ↔ global mutation of display-device state that may have been provisioned and may still be used by another product
  or administrator.

  The inherited WiX declared `RemoveAmyuniIdd` with `Impersonate="no"`, `Execute="commit"`, and `Return="check"`,
  scheduled after successful explicit uninstall. Its DLL called `UninstallDriver(L"usbmmidd", ...)`; the dedicated
  SetupAPI source enumerated every present display device, read each `SPDRP_HARDWAREID` MultiSZ, and sent
  `DIF_REMOVE` with `DI_REMOVEDEVICE_GLOBAL` for every entry containing `usbmmidd`. The checked completion work in
  R-S11d-2 correctly stopped hiding enumeration, property, class-installer, removal, and reboot results, but it did
  not prove that this MSI owned any matched device.

  A complete creation/package/use/removal inventory found no such ownership edge. The active Windows release invokes
  `build.py --flutter`; `build.py` has an empty third-party resource feature catalog, so the release distribution and
  MSI contain no `usbmmidd_v2`, `usbmmIdd.inf`, or `deviceinstaller64.exe` payload. Schema-disabled workflow text is
  only historical staging guidance. The runtime still supports a separately provisioned fixed-Program-Files payload,
  detects and uses an existing driver, and explicitly notes that other processes may control it, but neither that
  path nor the MSI records a durable current-product-to-exact-device-instance identifier. Both Rust removal functions
  had no live caller. A shared hardware ID classifies a compatible device; it is not proof of lifecycle ownership.

  Microsoft documents that `DI_REMOVEDEVICE_GLOBAL` removes a device globally from all hardware profiles and removes
  device registry information
  (<https://learn.microsoft.com/en-us/windows/win32/api/setupapi/ns-setupapi-sp_removedevice_params>), and that
  `DIF_REMOVE` removes the devnode and its hardware/software/hardware-profile registry keys, distinct from deleting a
  driver package
  (<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/dif-remove>,
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/using-setupapi-to-uninstall-devices-and-driver-packages>).
  `SPDRP_HARDWAREID` is a `REG_MULTI_SZ` list of hardware IDs
  (<https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertya>).
  Commit actions run after successful script processing, while no-impersonation script actions execute outside the
  installing user's impersonation context
  (<https://learn.microsoft.com/en-us/windows/win32/msi/commit-custom-actions>,
  <https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security>).

  This was unnecessary LocalSystem/administrator global cross-product device-deletion authority and a potential
  administrative-state deletion or availability impact. It is not evidence of a remote trigger, promptless LPE,
  attacker-selected target, exploitation, host compromise, or use of the path. The correct current lifecycle is
  deletion-only: the WiX declaration and schedule, action implementation and export, dedicated SetupAPI source/header
  and Visual C++ project inputs, runtime removal policy/mode, and both dead Rust removal functions are gone. Amyuni
  detection, use, monitor plug/unplug, fixed-root/reparse-checked helper installation, direct SetupAPI installation,
  and fatal install reboot-required handling remain unchanged. Uninstall leaves separately owned device state alone.
  There is no friendly-name, hardware-ID, INF-name, current-presence, current-driver, best-effort, or narrower-scan
  fallback. Any future removal feature must first define a reviewed lifecycle that durably records and re-proves
  current-product ownership of an exact device instance.

  R-S11f, R-S11bw, Appendix C #216, the shared R-S11e-20/R-S11e-89 gate, and the independent semantic/mutation
  validator bind complete source/build/WiX/export/call absence, exact sole-custom-action inventory, retained install
  helper signature/call shape and device-I/O behavior, current no-payload evidence, ledger/disposition, and
  requirements-hash scope. The synchronized active requirements SHA-256 is
  `77d1066651f07c69081897fa06883f1c5415bc8f0bd5edd44b03a05d5da19dda`.

  Confined verification used the already-present immutable development image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`; the format-only check used the
  already-present Debian image
  `sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818` with the exact host Rust 1.75
  toolchain mounted read-only. Every test ran as UID/GID 1000 with no network, a read-only root and source, all
  capabilities dropped, `no-new-privileges`, bounded PID/memory use, and private tmpfs-only writable state. Bash
  syntax and Python byte-compilation passed. The normal independent semantic validator and its complete repository
  source-mutation matrix returned `verify-verifier-workspace: ok`. The Amyuni mutation set restores the deleted
  header/source, WiX declaration/schedule/commit action, DLL entry/export/project input, runtime and direct-SetupAPI
  removal functions, helper remove mode and reboot policy, or weakens sole-action inventory, current no-payload
  evidence, every retained install/device-I/O invariant, shared rejection/success text, requirement, Appendix row,
  ledger, and synchronized hash scope. Two pre-green full mutation runs exposed fixture weaknesses: the first still
  targeted a now-formatted string literal followed by a comma, and the second changed the build command by adding a
  suffix while leaving the required command as a matching prefix. Both fixtures were made independently falsifiable
  before the complete matrix passed.

  Exact Rust 1.75 formatting passed for both changed Rust files after applying the formatter's sole import-layout
  correction. A disposable, offline, vendor-backed Rust 1.75 Windows-MSVC crate type-checked the exact current
  `src/platform/win_device.rs` with its pinned `winapi` 0.3.9 and `thiserror` 1.0.61 dependencies. A full root
  Windows-MSVC `cargo check --lib` was also attempted with the current read-only tree and pinned 2.4-GB vendor input;
  it stopped before reaching the RustDesk crate because this Linux verifier has neither a cross-configured
  `libsodium` pkg-config sysroot nor MSVC `lib.exe` for `mozjpeg-sys`/`zstd-sys`. That attempt is not claimed as a
  successful full application check. Independent XML parsing accepted both changed WiX files and the Visual C++
  project. A direct production inventory proved both dedicated removal files and every retired token absent, exactly
  one DLL custom-action declaration/export/entrypoint present, the install/use and fatal install-reboot paths retained,
  and no Amyuni payload staged by the current release build. Native-codec hash watch and its negative self-test passed.

  No image was pulled or built; no port, Docker socket, host namespace, host service/config mount, device mount, added
  capability, or root process was used. No host RustDesk process, service, listener, configuration, device, firewall,
  or network state was inspected or changed. The custom-action DLL was not compiled and an MSI was not built or
  executed on this Linux source-verification host. Native MSI-table inspection, real installed explicit-uninstall
  behavior, the clean cold exact-commit Windows release, and the current exact APK remain pending R-B2/R-B10
  obligations; this source slice does not claim them.
- **R-S11bx/R-S11e-90 — Windows runtime-broker cleanup is declarative with no RustDesk-authored cleanup action — SOURCE
  IMPLEMENTED AND CONFINED SOURCE/STRUCTURE/MUTATION VERIFIED 2026-07-23; NATIVE MSI TABLE,
  INSTALLED LIFECYCLE, AND EXACT ARTIFACT EVIDENCE REMAIN R-B2/R-B10.** Platform: the per-machine Windows
  Installer package and offline Windows build closure. Endpoint/action: removal of the fixed runtime-generated
  `RuntimeBroker_rustdesk.exe` sibling during application-component removal. Boundary: administrator-approved MSI
  transaction ↔ privileged code and target selection inside the Windows Installer execution service.

  The last custom action accepted `[App.InstallFolder]` as deferred `CustomActionData`, loaded an embedded native
  DLL outside the installing user's impersonation context, normalized and classified a Program Files path, cleared
  attributes, opened the fixed broker path without following a reparse point, and marked that object for deletion.
  R-S11d-4/R-S11d-33 had correctly made this inherited code fail closed and constrained its target. The remaining
  question was whether the abstraction itself was necessary. It was not: the action had one fixed filename in the
  same directory as the package-owned `App.exe` component and performed no operation outside standard file removal.

  Microsoft documents that the `RemoveFile` table removes author-specified files not installed by `InstallFiles`,
  with each row gated by a linked component's action state, and that `InstallMode=2` applies when that component is
  removed. WiX v4 maps this contract directly to `RemoveFile Name=... On="uninstall"` under `Component`, defaulting
  the target directory to that parent component. The package schedules `RemoveExistingProducts` early, after
  `InstallInitialize`, so old-product removal during a major upgrade reaches the same component-removal contract.
  Primary contracts: <https://learn.microsoft.com/en-us/windows/win32/msi/removefile-table>,
  <https://learn.microsoft.com/en-us/windows/win32/msi/removefiles-action>, and
  <https://docs.firegiant.com/wix/schema/wxs/removefile/>.

  The final design has one exact non-wildcard
  `<RemoveFile Id="Remove.RuntimeBroker" Name="RuntimeBroker_rustdesk.exe" On="uninstall" />` inside `App.exe`.
  There is no RustDesk-authored caller path, property setter, custom schedule, `CustomActionData`, embedded cleanup
  binary, entrypoint/export, C++ project, preprocessing rewrite, project/solution reference, or custom cleanup code.
  The complete `res/msi/CustomActions` directory and `Package/Fragments/CustomActions.wxs` are deleted. The Windows
  build no longer stages the old `packages.config` native dependencies, and the offline capture no longer restores
  DUtil/WcaUtil. Its exact six-package WiX 4.0.5 closure is pinned to
  `62afa1543d52461ee0b80334c4c3a1d6bf1b54d94f3cd745869102ed613f3b58`; this digest was independently reproduced
  from the prior pinned eight-package archive by deleting only the `wixtoolset.dutil` and `wixtoolset.wcautil`
  top-level directories and applying the same sorted, fixed-mtime, numeric-owner, `gzip -n` recipe inside a
  networkless, non-root, read-only container. The derived archive contains exactly SDK, Firewall, Heat, Netfx, UI,
  and Util package roots and is 52 MiB compressed.

  This is deliberately an application-authoring claim, not a claim that the final MSI `CustomAction` table is empty.
  WiX documents that extensions typically combine compiler support with extension-owned implementation actions, and
  this package retains pinned typed Firewall, Netfx, UI, and Util extensions. R-B2/R-B10 must enumerate and attribute
  the native package's resulting action/binary tables, prove that any retained action comes only from the expected
  pinned typed-extension resource, and reject any RustDesk-authored general path, command, script, or cleanup binary.

  Confined verification used the already-present immutable development image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` with UID/GID 1000, no
  network, a read-only root and source, all capabilities dropped, `no-new-privileges`, bounded PID/memory use, and
  private tmpfs-only writable state. Bash syntax, Python byte-compilation, and independent parsing of all eleven WiX
  source/project XML documents passed. The normal independent semantic validator and its complete repository
  source-mutation matrix returned `verify-verifier-workspace: ok`; the matrix includes exact-row/location, deleted
  directory/fragment, project/solution/preprocess/build/offline dependency, closure digest, preexisting-cache
  verification order, authored-versus-extension action boundary, shared gate, requirements, Appendix, ledger, and
  hash-scope mutations. One pre-green mutation run exposed a fixture-ordering weakness: deleting the cache digest
  check reached the earlier exact-count rejection instead of the intended ordering rejection. The mutation now keeps
  both checks but moves one after an unreachable return, independently proving the verify-before-skip invariant.

  In the already-present pinned .NET SDK image
  `sha256:d80fdd84f7e18eea12f8e45c52914f1353395009c95c41197178ea19944e6d48`, the old pinned archive was
  extracted to private tmpfs, only DUtil/WcaUtil were removed, and the exact committed sorted/fixed-mtime/
  numeric-owner/default-level-`gzip -n` recipe reproduced
  `62afa1543d52461ee0b80334c4c3a1d6bf1b54d94f3cd745869102ed613f3b58`. An offline `dotnet restore` of
  the current copied `Package.wixproj` succeeded with only those six retained package roots. A synthetic `wix build`
  attempt on Linux is not counted as schema or MSI evidence: WiX explicitly reported that it supports only Windows
  and that subsequent behavior was undefined, then rejected directory semantics before producing an MSI. Native-codec
  watch and its negative self-test passed. Direct inventories proved the exact `RemoveFile` row occurs once inside
  `App.exe`, every retired source/build/package token is absent from production surfaces, both deleted paths are
  absent, both synchronized requirements hashes equal
  `7bf9c13e9dd2f1835e1a57c3f4f679c7482068b3258e2b789965c8edba4c7aa2`, and `git diff --check` is clean.

  Process note: before the confined rerun, Bash syntax and Python byte-compilation were inadvertently invoked once as
  the ordinary host user. They used no root, network, service, listener, firewall, device, namespace, or Docker-socket
  authority, wrote no tracked file, and are not counted as verification evidence; both were rerun successfully in the
  confined container. No image was pulled or built, no port was published, and no host RustDesk process, service,
  configuration, listener, firewall, network, or device state was inspected or changed. The custom-action DLL was not
  compiled, and neither a native MSI nor a release artifact was built or executed.

  This removes unnecessary RustDesk-authored privileged native execution and supply-chain/build surface; it does not
  allege that the tightly validated prior fixed-file action was a demonstrated LPE, attacker-selected deletion,
  exploitation, compromise, or host event. The runtime creation/refresh path remains fixed-service-image, fixed Program Files,
  non-reparse System32-source, byte-verified, and atomic-replacement bound. R-S11f, R-S11bx, Appendix C #217, the
  shared R-S11e-20/R-S11e-90 gate, and the independent semantic/mutation verifier bind the exact declarative row,
  total RustDesk-authored cleanup-action/build/dependency absence, six-package closure pin, requirements disposition,
  ledger, and synchronized requirements hash. Native MSI table inspection, real
  install/repair/major-upgrade/uninstall behavior, the clean cold exact-commit Windows release, and the current exact
  APK remain open R-B2/R-B10 obligations; source
  conformance must not be reported as those native/artifact proofs.
- **R-S11by/R-S11e-91 — Debian vendor unit is package-owned and administrator unit state is preserved — SOURCE
  IMPLEMENTED AND CONFINED SOURCE/PACKAGE/MUTATION VERIFIED 2026-07-23; CLEAN EXACT-COMMIT PACKAGE AND INSTALLED
  LIFECYCLE EVIDENCE REMAIN R-B2.** Platform: Debian package construction and systemd package lifecycle.
  Endpoint/action: installation, upgrade, removal, and purge of `rustdesk.service`. Boundary: dpkg-owned vendor files
  and Debian service-manager helper state ↔ administrator-owned primary unit, mask, replacement, and drop-in state
  below `/etc/systemd/system`.

  The inherited package did not ship the systemd unit at its installed vendor path. It shipped a private copy below
  `/usr/share/rustdesk/files/systemd`; `postinst` unconditionally removed the exact `/etc/systemd/system/rustdesk.service`
  object, removed both system and user vendor paths, recreated `/usr/lib/systemd/system`, and copied the private
  template into place. `prerm` deleted the same three unit paths before dpkg's package-file removal phase and reloaded
  systemd while the unit's ownership was still script-defined. Because an administrator mask is the exact `/etc`
  object linked to `/dev/null`, this could erase a deliberate mask or replacement. This is local package-authority and
  availability debt, not evidence that an administrator object existed or was deleted on a real host, that Docker
  acquired root, that a public listener was opened, or that a machine was compromised.

  The authority model is now conventional and closed. `build.py` places the byte-exact `res/rustdesk.service` directly
  at `/usr/lib/systemd/system/rustdesk.service`; the exact package inventory admits that root/root mode-0644 ordinary
  file and its three vendor directories, excludes the legacy `/usr/share` template, and includes the unit in generated
  `md5sums`. Dpkg owns install, replacement, and removal. `postinst`, `prerm`, and `postrm` contain no primary systemd
  unit path. They retain only checked `deb-systemd-helper`/`deb-systemd-invoke` lifecycle operations and the fixed
  manager reload. `prerm` stops/disables before removal; after dpkg removes the vendor
  file, `postrm remove|purge` reloads the manager, while purge separately clears helper and root service-config state.
  The exact upgrade-only `preinst` read predicate remains so an existing old unit is stopped before transition; it
  neither writes nor removes any unit object. Administrator masks, replacement units, primary-unit links, and drop-ins
  are not package-script state.

  The focused semantic validator rejects every systemd search-path reference outside that one `preinst` predicate,
  enforces the revised stop/disable/remove/reload order, and remains failure-propagating. The package authority
  validator binds the direct constructor commands and exact inventory, byte-compares an emitted unit with source,
  verifies its mode/link/owner and `md5sums` membership, and deliberately mutates the constructor back to the legacy
  template, restores each of the three script deletions, removes the post-removal reload, corrupts the unit bytes, and
  changes its mode. The release artifact gate independently extracts and compares the systemd unit. The disposable
  installed-system fixture now creates an administrator-owned `/etc/systemd/system/rustdesk.service` link before
  installation and requires that exact link to survive install, removal, and purge while the dpkg-owned vendor unit is
  installed and removed normally. Debian's primary contracts are
  <https://www.debian.org/doc/debian-policy/ch-opersys.html#starting-system-services>,
  <https://www.debian.org/doc/debian-policy/ch-files.html#configuration-files>, and
  <https://manpages.debian.org/unstable/systemd/systemd.unit.5.en.html>.

  Confined focused verification used the already-present immutable Debian builder image
  `sha256:6766564c65b0daead7d7031fcf0ff9ec8becab6ef9e3f9a7efd9f02f1b893776` as UID/GID 1000 with
  `--pull=never`, no network, a read-only root and source, all capabilities dropped, `no-new-privileges`, bounded
  PID/memory/no-swap/CPU use, and private tmpfs-only writable state. Bash syntax passed for all changed shell scripts;
  in-memory Python compilation passed for all changed validators; the maintainer-script semantic validator passed;
  and the package authority self-test returned `ok  Debian package tree is root-owned, exact-mode, link-free, and
  source-gated`. That result predates R-S11bz's package-owned command symlink and is retained only as evidence for
  this earlier vendor-unit slice. Its production-constructor fixture, exact archive parser/inventory/mode/digest checks, legacy
  constructor and maintainer-script mutations, wrong-unit-content mutation, and wrong-mode mutation all ran.

  The complete independent semantic source-mutation matrix required Python `tomllib`, which the pinned Debian image's
  Python 3.6 does not provide, so it ran in the already-present immutable development image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` under the same confinement and returned
  `verify-verifier-workspace: ok`. A separate normal semantic pass returned the same result. Native-codec watch plus
  its negative mutation self-test passed, `git diff --check` was clean, and the synchronized requirements digest is
  `54d0f62a0a6e14b1ee4cadc660944bea16583d3c0ddf9678ae8b94e83a2a5f5a`. Two earlier confined syntax attempts
  terminated before project validation because Python 3.6 first tried to write `__pycache__` beside the read-only
  source and then decoded the large verifier as ASCII; the final in-memory UTF-8 compilation corrected both harness
  invocations. Neither attempt wrote source or exercised package lifecycle code.

  No image was built or pulled, no port or host namespace was used, and no container ran as root or received a host
  service/configuration/device/Docker-socket mount. No `.deb` was built or installed and no maintainer script was
  executed against a host root filesystem. No host RustDesk process, service, configuration, listener, firewall,
  network, or device state was inspected or changed.

  This source slice does not claim a newly built `.deb`, installation on this host, or execution of the privileged
  systemd fixture. The current clean exact-commit Debian cold build and installed install/upgrade/removal/purge run
  remain R-B2. No host RustDesk process, service, configuration, listener, firewall, network, or device state is in
  scope for this source change.
- **R-S11bz/R-S11e-92 — Debian primary command is package-owned and maintainer scripts never mutate `/usr/bin` —
  SOURCE IMPLEMENTED AND CONFINED SOURCE/PACKAGE/MUTATION VERIFICATION PASSED 2026-07-23; CLEAN EXACT-COMMIT
  PACKAGE AND INSTALLED LIFECYCLE EVIDENCE REMAIN R-B2.** Platform: Debian package construction and every package lifecycle
  phase. Endpoint/action: install, upgrade, removal, and purge of `/usr/bin/rustdesk`, plus the inherited pre-install
  cleanup of `/usr/bin/libsciter-gtk.so`. Boundary: dpkg-owned package data and conflict/error-unwind state ↔
  administrator- or other-package-owned primary command paths executed by root maintainer scripts.

  The inherited archive contained no `/usr/bin/rustdesk` member. `postinst configure` instead used `ln -f -s` to
  replace that path after dpkg unpacked the package, and `prerm` deleted it before dpkg's own file-removal phase. The
  link therefore had no package-database ownership, conflict, backup, or unwind record. `preinst` additionally
  deleted `/usr/bin/libsciter-gtk.so` during install and upgrade even though the current Flutter package contains no
  Sciter payload. Those actions could silently replace or delete a pathname owned by an administrator or another
  package and could remove a program the package database never attributed to RustDesk. This is local package
  authority and availability debt, not evidence that a conflicting host file existed, any path was actually
  overwritten, Docker acquired root, a public listener was opened, the action was remotely triggered, or a machine
  was compromised.

  The corrected package has one command authority. `build.py` creates an exact relative symbolic-link data member
  `/usr/bin/rustdesk -> ../share/rustdesk/rustdesk`; its target remains the root/root mode-0755 ordinary UI/service
  payload. R-S11cb adds a separate byte-identical root/root mode-0711
  `/usr/share/rustdesk/rustdesk-service-child` payload that is never the primary command. The finalizer admits
  exactly that one single-link mode-0777 symlink, rejects every
  other link/hardlink/special file, checks the exact target again after mode finalization, and excludes symlinks from
  generated `md5sums`. The independent archive parser requires canonical raw link metadata, root/root ownership,
  symbolic-link type, mode 0777, exact relative target bytes, a closed link inventory, and no symlink digest entry.
  The emitted-package check and disposable installed-system fixtures are wired to prove the same target and require
  `dpkg-query -S /usr/bin/rustdesk` to attribute it to the installed package when those artifact/lifecycle gates run.

  `preinst`, `postinst`, `prerm`, and `postrm` now contain no `/usr/bin` path. The stale Sciter deletion and empty
  install branch are deleted; no cleanup, migration, alternatives, diversion, absolute-link, copied-binary,
  hardlink, or maintainer-script fallback remains. Service launchers keep the exact `/usr/bin/rustdesk --service`
  protocol, but package files—not a root script—supply that entry. The focused maintainer validator, constructor and
  archive self-tests, shared source gate, and independent workspace verifier bind wrong/missing/extra/absolute links,
  regular-file substitution, wrong mode, hardlinked symlink, symlink `md5sums` drift, restoration of each retired
  maintainer-script operation, R-S11bz, Appendix C #219, and this row. Debian Policy §6, §7.6, and §10.1 are the
  primary packaging contracts.

  Final confined verification used already-present immutable images only. In
  `sha256:6766564c65b0daead7d7031fcf0ff9ec8becab6ef9e3f9a7efd9f02f1b893776`, Bash syntax passed for every changed
  shell script, in-memory UTF-8 compilation passed for every changed Python file, the maintainer-script validator
  passed, and `verify-debian-package-authority.py --self-test` returned
  `ok  Debian package tree is root-owned, exact-mode, exact-command-symlink-only, and source-gated`. In
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`, normal independent semantic validation
  and the complete in-memory source-mutation matrix each returned `verify-verifier-workspace: ok`; native-codec watch
  normal and negative self-test modes passed against requirements SHA-256
  `cf3803de25034ebbdfa68d768a981992507e87dc4ff78bbbd260beb2d1533ca0`. Every project/test process ran as numeric
  UID/GID 1000 with `--pull=never`, no network, a read-only root and source mount, all capabilities dropped,
  no-new-privileges, bounded PIDs/CPU/memory/no-swap, and private tmpfs writes. No image was built or pulled; no port,
  host namespace, Docker socket, host service/config/device path, or root identity entered a test container.

  No `.deb` was built or installed for this source slice, no maintainer script ran against a host root filesystem,
  and no host RustDesk process, service, configuration, listener, firewall, network, or device state was inspected or
  changed. The exact cold Debian release artifact and installed install/upgrade/removal/purge run remain R-B2.
  Current APK/device, native Apple/Windows installed-platform evidence, and external R-V3 review remain open; this
  slice is not overall completion.
- **R-S11ca/R-S11e-93 — Linux crash recovery signals only through a stable pidfd — SOURCE IMPLEMENTED AND CONFINED
  SOURCE/MUTATION/COMPILER/INVENTORY VERIFICATION PASSED 2026-07-23; UPDATED EXACT-BINARY LIFECYCLE FIXTURE NOT
  EXECUTED; INSTALLED ARTIFACT EVIDENCE REMAINS R-B2.** Platform: Linux `rustdesk --service` recovery after a supervisor crash.
  Endpoint/action: root-originated `SIGTERM`/`SIGKILL` toward the process named by the durable
  `/run/rustdesk/service-child.record`. Boundary: time-bounded `/proc` identity observations and a recyclable numeric
  PID ↔ stable kernel process-reference authority.

  The deleted compatibility branch was careful but could not be made correct. It compared PID/start time, current
  boot ID, executable device/inode, all UID fields, exact service-owned argv, and the unique generation environment;
  it repeated those checks immediately before each numeric-PID `kill(2)` and during both bounded waits. A target
  process could nevertheless exit and its PID be reused between the last successful inspection and the signal.
  Linux's `pidfd_send_signal(2)` exists specifically to address that class: after a pidfd has been opened for one
  process, later PID recycling does not retarget operations through the descriptor. The former warning accurately
  disclosed the race but accepting it still left root lifecycle authority capable of reaching an unrelated process.
  This is a narrow local crash-recovery availability/authority defect, not evidence that the race occurred, a host
  process was signaled, Docker obtained root, a public listener was created, a firewall changed, exploitation
  happened, or a machine was compromised.

  Current source removes `send_revalidated_service_child_pid_signal` and
  `wait_revalidated_service_child_pid_exit` completely. The only recovery signal helper calls
  `SYS_pidfd_send_signal` on the already-opened descriptor. When `pidfd_open` returns `ENOSYS`, the new handler may
  delete only an exact record whose identity inspection reports `Exited` or `Absent`, because that operation sends no
  signal. `Match` fails with an explicit required-pidfd diagnostic; `Mismatch` and `Unavailable` also fail, preserving
  the record and signaling nothing. `start_os_service` already sequences lease acquisition and recovery before IPC
  listener creation, so every refusal precedes both network/service endpoint authority and child launch. No-record
  startup and the supervisor's routine directly owned-`Child` shutdown remain unchanged, avoiding a needless blanket
  rejection of older kernels.

  The actual-binary lifecycle fixture was changed from “fallback succeeds” to “unsafe recovery is refused.” It binds
  one canonical live child/record, forces only `PidFdOpen::Unsupported` through a debug-only environment name that is
  inert in release builds, requires service exit status 1, compares full record metadata and SHA-256 before and after,
  rejects a temporary record, and re-proves the exact child plus unrelated UID-4000 portable server are alive. Test
  cleanup removes only the retained exact record and uses Python's `pidfd_open`/`pidfd_send_signal` path against the
  retained start-time identity. The top-level smoke consumer now requires
  `SERVICE_LIFECYCLE_PIDFD_UNAVAILABLE_REFUSAL`, and source/semantic mutation gates bind the safe-state split,
  live-record refusal, fallback-symbol absence, pre-listener order, runtime preservation, R-S11ca, Appendix C #220,
  and this ledger entry.

  Confined verification used immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` as numeric UID/GID 1000 with
  `--pull=never`, no network, a read-only root and source mount, all capabilities dropped, no-new-privileges, bounded
  PIDs/CPU/memory/no-swap, and private tmpfs outputs. Bash parsing and in-memory Python compilation passed; normal
  independent semantic validation passed; the complete in-memory source-mutation matrix passed after independently
  rejecting weakened live/stale/mismatch/unverifiable decisions, record metadata/byte/temp-path preservation,
  release-hook closure, recovery dispatch, reintroduced fallback symbols, gate wiring, requirement, Appendix row,
  and ledger identities. The Rust 1.75.0 locked/offline `cargo check --lib --features linux-pkg-config` completed in
  1m30s with only the repository's existing warning set. Dependency inventory normal mode and all 103 adversarial
  checks passed: deleting the sole raw recovery `kill` block changed only `src/platform/linux.rs`, reducing the
  lexical unsafe total from 859 to 858 and moving the per-file digest from
  `e84d5ffaae33889085987b5a49a7be444a94ea6cc467c4e199f91a16372638bf` to
  `32ae35db8dfec93d8fa9de08be93fb595ebc8254e9a71f6606c35aa7190fb67c`; package/vendor/workflow topology stayed
  unchanged. Native-codec normal and negative self-tests passed against requirements SHA-256
  `31eb86ec577062999f519f00680e85a04d10e4a687c8daa182b1db0d433d22d1`.

  The immutable image lacks the `rustfmt` component. Invoking its rustup proxy on a read-only root stopped while
  trying to create an update temporary file, so no formatting result is claimed; the Rust compiler accepted the
  source. A first confined Python-compile attempt likewise stopped because explicit `py_compile` tried the read-only
  source `__pycache__`; the corrected run bound its cache to private tmpfs and passed. Before confined validation, a
  mistaken host-side parser-only `bash -n`/`py_compile` invocation ran without root, project binaries, network,
  ports, Docker mounts, or service paths and changed no tracked file; it is not counted as evidence and is recorded
  as a procedural deviation. The first new semantic pass also exposed and then rejected a local verifier-variable
  wiring error, while two mutation iterations exposed overly broad/underbound mutation targets; those checks were
  tightened rather than bypassed and the complete final matrix passed.

  The updated exact-binary lifecycle fixture was not executed: it intentionally models a UID-0 installed service,
  whereas every permitted project/test process in this slice had to remain numeric UID/GID 1000 with all
  capabilities dropped. No root container, host namespace, Docker socket mount, port publication, host RustDesk
  process/service/configuration, listener, firewall, or device path was used or changed. Consequently this slice does
  not claim current exact-binary pidfd-unavailable refusal, clean exact-commit Debian package
  construction/installation, an installed old-kernel run, Android device evidence, native Apple/Windows evidence, or
  independent R-V3 review; those broader items remain open.
- **R-S11cb/R-S11e-94 — Linux stable service credential ownership and nondumpable runtime replica — SOURCE
  IMPLEMENTED; CONFINED COMPILER AND SEMANTIC/MUTATION VERIFICATION PASSED 2026-07-23; NATIVE INSTALLED-SERVICE
  BEHAVIOR AND EXACT ARTIFACT EVIDENCE REMAIN R-B2/R-S11c-27.** Platform: Linux installed-service mode when the
  stable root `--service` supervisor selects an active-desktop
  `--server --service-owned-server` child. Endpoint/action: polkit-authorized permanent-password mutation, initial
  credential snapshot, and the child process's access to the password-equivalent CPace PRS. Boundary: stable root
  durable machine authority ↔ replaceable active-user runtime authority and ordinary same-uid process-inspection
  authority.

  The prior architecture authorized in root but committed in the child. After polkit succeeded, root forwarded the
  plaintext over raw `_password`; `spawn_password_mutation` then called
  `Config::set_permanent_password_persisted` inside the active-user child, so the selected desktop uid/config root
  chose durable machine credential state. The child also retained the PRS while an ordinary final-image exec did
  not explicitly hold dumpability off. Linux documents that credential changes reset dumpability but ordinary exec
  can restore it, and that ptrace-style checks govern `ptrace`, `process_vm_readv`, and `/proc/<pid>/mem`. Kernel
  `ptrace.c` also distinguishes the sole-tracer check in attach from the general `__ptrace_may_access` decision used
  by those other interfaces: making root the child's registered tracer would prevent a second attach but would not
  itself close every classic same-uid read path during a dumpable exec interval. The application cannot treat either
  that tracer relationship or an optional restrictive Yama setting as its credential boundary. This was a local
  credential-authority/confidentiality defect requiring local same-uid process authority; it is not evidence that
  memory was read, a password was stolen, a host process/service/configuration/firewall changed, Docker gained root,
  a public listener was created, exploitation occurred, or a machine was compromised.

  Current source makes root the sole durable writer. The root commit worker persists the submitted plaintext,
  reads the resulting root PRS tri-state, and sends the exact service-owned child only a canonical PRS-or-empty
  `SensitivePassword` replica under the same UUID. The child-side mutation worker recognizes its exact Linux
  service-owned role and calls only `set_permanent_password_prs_for_runtime`; that setter accepts empty or canonical
  base64 for exactly 32 decoded bytes, wipes decoded/re-encoded temporaries and any replaced replica, overrides stale
  user-profile state without persistence, and advances the credential generation. If root storage is undecryptable,
  the PRS cannot be read after persistence, the child returns anything but `Applied`, or transport/finality cannot
  converge, root latches authority failure and cancels the generation. The existing owned IPC drain completes, the
  supervisor treats the lost protected-IPC worker as fatal, stops the exact child, and lets the service manager
  start a fresh generation rather than serving divergent credentials.

  Startup uses a separate raw `_service_credential` listener with its own capacity-two semaphore. Admission occurs
  before `/proc` identity work; the root reads no request body until it proves the exact child. The bodyless kind-3
  request and kind-4 response reuse the canonical 36-byte raw header and bind one UUID; a replica body is exactly
  empty or 44-byte canonical base64. Root reauthenticates the accepted identity before reading credential state.
  The child connects to service IPC, proves a kernel-credential uid-0 peer whose PID is both its launch-parent marker
  and its actual direct parent, receives and validates the operation-bound replica, and installs it before startup
  invariants or any local/public listener. It does not depend on reading protected root `/proc` metadata. Root
  independently proves the accepted child has the exact service-owned argv, direct parent, and current generation.
  Explicit empty
  root state suppresses stale user-profile storage; unavailable, malformed, wrong-operation, wrong-peer, or
  undecryptable state exits the child before admission. Both root-to-child mutation and child-to-root snapshot proof
  now require direct parent PID plus the root supervisor's current runtime generation, not ancestry alone.

  The active-user launch closes the exec-time same-uid inspection window without ptrace. Debian packaging keeps the
  ordinary UI/service image root:root mode 0755 so its established same-uid `/proc` executable proofs remain usable,
  and adds a separate byte-identical root:root mode-0711 service-child image. Before dropping privilege, the root
  supervisor opens the running fixed primary and no-follow child objects, proves the primary path/mode, protected
  child parent, child ownership/mode/length, exact byte equality, and selected child inode; it also requires
  `/proc/sys/fs/suid_dumpable` to contain exactly `0`. An already execute-only root-owned manual service image can use
  its current inode directly. Linux's unreadable-executable exec transition
  therefore starts the final active-user image nondumpable instead of briefly restoring classic same-uid inspection.
  The final image first verifies its initial `PR_GET_DUMPABLE == 0`, reasserts `PR_SET_DUMPABLE(0)`, reads the state
  back, writes one bounded bootstrap marker, and stops itself. Root constructs and atomically publishes the exact
  durable child record only while that child is stopped, then sends `SIGCONT`. Root-principal children share the
  explicit nondumpable marker/stop publication boundary. All metadata, policy, marker, stop, identity, record, resume,
  and cleanup failures are fail-closed. The systemd unit permits neither the individual `ptrace` syscall nor
  `@debug`; its already-retained `CAP_SYS_PTRACE` permits the root supervisor's exact nondumpable-child `/proc`
  proofs without becoming the exec-transition boundary. The unsupervised recovery test hook is
  `debug_assertions`-only, compiles to false in release, and the real supervisor's `env_clear()` never propagates it.

  Final review rejected an earlier package draft that made the primary executable itself mode 0711. That would
  also make every ordinary user-launched RustDesk process nondumpable and break the fork's existing same-uid
  `/proc/<peer>/exe` proofs between ordinary RustDesk processes. The corrected package split confines unreadable-exec
  behavior to `rustdesk-service-child`. The constructor makes that member by direct byte copy, and both source and
  archive verifiers require primary mode 0755, child mode 0711, exact ELF policy on both, and byte-for-byte equality.
  At runtime the root supervisor accepts the package child only after fixed-path, protected-parent, metadata, length,
  and streaming byte comparison against its open running image; peer authentication then binds the selected child's
  device/inode rather than incorrectly requiring that its pathname equal the primary UI image.

  `scripts/verify-linux-service-password-ipc.py` now parses the codec, config, IPC/auth, server, and Linux launcher
  sources and binds framing, ordering, budgets, root persistence, child runtime-only application, plaintext
  absence, fail-stop, pre-listener snapshot, asymmetric direct-parent/generation proof, initial/final nondumpability,
  execute-only installed metadata, kernel policy, stopped record publication, and
  release-fixture closure. Its complete self-test deliberately weakens canonical length, capacity, persistence
  ownership, PRS-vs-plaintext delivery, fail-stop, startup snapshot, dumpability, executable mode, kernel policy,
  parent/generation,
  and release gating and rejects every mutation. The meta-verifier binds the new checker invocation and critical
  handler/capacity/bootstrap checks. Shared verification requires R-S11cb, Appendix C #221, this ledger identity,
  the 44-byte bound, and the narrow systemd syscall row.

  Confined evidence used only already-present immutable images as numeric UID/GID 1000 with no network, a read-only
  root/source/toolchain, all capabilities dropped, no-new-privileges, bounded PIDs/CPU/memory, and private tmpfs
  outputs. Final Rust 1.75.0 locked/offline `cargo check --config online/cargo-vendor-config.toml --lib --tests
  --no-default-features --features linux-pkg-config -j1` completed in 5m12s with only the repository's existing
  warning set. Focused test-profile execution then passed five tests: streaming service-child byte identity including
  changed/trailing/truncated negatives (1/1), operation-bound and wrong-operation credential snapshots (2/2), exact
  credential-replica framing (1/1), and canonical nonpersistent PRS replica/clear behavior (1/1). Normal
  Linux-password semantic/package validation, both complete deliberate-mutation matrices, dependency inventory and
  all 103 inventory self-tests, native-codec normal/negative checks, meta-verifier normal/source-mutation checks,
  Bash parsing, and private-tmpfs Python compilation passed. Two stale meta-verifier self-test literals for the
  corrected dedicated child/27-statement package constructor were rejected, updated to the actual contract, and the
  complete matrix was rerun successfully. Rustfmt found no drift in a newly touched hunk; the whole-file check remains
  non-clean only at explicitly untouched pre-existing locations in `src/ipc/auth.rs` and `src/platform/linux.rs`.

  One dependency-inventory invocation was mistakenly executed directly on the host as the ordinary user. It was
  read-only, used no root/network/service/device/port authority, changed no file, and is not counted; normal mode and
  all 103 mutations were rerun in the confined container. Separately, an incorrect formatter toolchain mount caused
  Docker to create one empty named volume, `rust1.75.0-x86_64-unknown-linux-gnu`. No project process used it, it
  contains no files, and it was left untouched rather than silently removed. Neither deviation touched RustDesk,
  services, listeners, firewall state, or a device. No root container, host namespace, Docker socket mount, port
  publication, host RustDesk process/service/configuration, listener, firewall, network, or device path was used,
  inspected, or changed. The final exact-state review and publication identity are recorded in the external audit
  ledger after publication; the source slice does not claim native
  systemd/SysV/OpenRC/runit behavior, same-uid inspection-denial behavior, a built/installed Debian artifact, a
  clean exact-commit cold release, Android device behavior, native Apple/Windows behavior, or independent R-V3
  review.
- **R-S11cc/R-S11e-95 — Linux nondumpable service child and connection-manager use kernel parent authority —
  SOURCE IMPLEMENTED; CONFINED COMPILER AND SEMANTIC/MUTATION VERIFICATION PASSED 2026-07-23; NATIVE
  INSTALLED-SERVICE BEHAVIOR AND EXACT ARTIFACT EVIDENCE REMAIN R-B2/R-S11c-27.** Platform: Linux installed-service
  mode after the stable root supervisor has launched the active-user, nondumpable
  `--server --service-owned-server` image. Endpoint/action: the service child's graphical/headless connection
  manager, the `_cm` listener and launch proof, main-IPC connection-capability validation, and the `_pa` capture
  capability. Boundary: nondumpable service server ↔ its exact CM child, and CM ↔ its exact server launch parent.

  R-S11cb intentionally made the active-user service image unreadable and nondumpable. A CM spawned through
  `current_exe()` executes that same dedicated image and remains nondumpable. The retained Linux `_cm` proof still
  attempted to read the other same-uid process's `/proc/<pid>/exe`, `cmdline`, and `environ` into
  `PeerProcessIdentity`. Linux subjects the executable link to ptrace read access, so the new confidentiality
  boundary could reject the legitimate parent/child pair it was meant to protect. The CM-dependent control/audio
  path could therefore fail while an independent file-transfer path continued. This was a hardening-induced local
  functional and helper-authority incompatibility, not evidence of exploitation, remote authentication bypass,
  Docker root access, a host service/configuration/firewall change, a public listener, or machine compromise.

  Linux CM and PA flows now use a deliberately minimal `LinuxProcessIdentity` containing only PID, UID, and process
  start time. A Unix socket supplies the peer PID/UID; `/proc/<pid>/stat` adds the non-reused start identity. The
  server accepts `_cm` only when that live identity is its exact current direct child. In the reverse direction the
  CM requires its launch-parent marker to equal its current kernel parent and requires the main socket peer to equal
  that parent's PID/UID/start-time identity before asking for a connection capability. No executable, argv,
  environment, token, or other ptrace-gated metadata crosses this nondumpable boundary. The fresh launch-token proof
  remains mutual and is additionally domain-separated by the complete exact `--cm` or `--cm-no-ui` role; a proof
  from one role cannot authorize the other. Both graphical and headless Linux launches use the existing
  `PR_SET_PDEATHSIG(SIGKILL)` plus pre-exec parent recheck path, preventing an orphaned CM from outliving the server
  parent whose authority it carries.

  The per-connection PulseAudio authority also retains only the minimal kernel identity. The service server records
  the exact authenticated CM child for each active subscriber and rechecks both process start and direct parent
  before issuing capture authority. The CM-side PA listener accepts an external owner only when it is the exact
  launch parent and the exact peer on the protected main socket, then asks that peer to validate the per-connection
  random token. A user-owned same-process path remains supported through exact self identity. Incumbent `_cm`
  probing now requires both exact direct-parent identity and mutual role-bound HMAC; `_pa` probing uses the exact
  minimal identity. No same-UID-only fallback, executable-procfs fallback, body-before-proof path, or generic config
  authority was added.

  `scripts/verify-linux-nondumpable-cm.py` independently binds the three-field identity closure, kernel socket
  credential and start-time derivation, direct-parent proofs in both directions, role-domain-separated mutual HMAC,
  parent-death launch path, retained-CM liveness, incumbent probes, main validation ordering, PA ownership, focused
  Rust regressions, R-S11cc, Appendix C #222, this ledger identity, and shared-gate wiring. Its self-test rejects 17
  deliberate weakenings. The workspace meta-verifier separately binds the focused checker semantics, invocation,
  requirement, Appendix row, and ledger.

  Confined validation used immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` as numeric UID/GID 1000 with
  `--pull=never`, no network, a read-only root/source/toolchain, all capabilities dropped, no-new-privileges, bounded
  PIDs/CPU/memory/no-swap, and private tmpfs output. The final Rust 1.75.0 locked/offline
  `cargo check --config online/cargo-vendor-config.toml --lib --tests --no-default-features --features
  linux-pkg-config -j1` completed with only the repository's existing warning set. Focused R-S11e-95 tests, normal
  and 17-mutation focused verification, meta-verifier normal/source-mutation checks, Bash/Python syntax,
  dependency-inventory normal/self-test, native-codec normal/self-test, requirements-hash synchronization, and
  touched-source formatting/diff checks are recorded in the external audit ledger with the final publication
  identity.

  No release build, package installation, root container, host namespace, Docker socket mount, port publication,
  host RustDesk process/service/configuration, listener, firewall, network, or device path was used, inspected, or
  changed. This source slice therefore does not claim current native service-child/CM behavior, an installed Debian
  package, a clean exact-commit cold release, Android device behavior, native Apple/Windows behavior, or independent
  R-V3 review.
- **R-S11cd/R-S11e-96 — Linux nondumpable service child and whiteboard use kernel parent authority —
  SOURCE IMPLEMENTED; CONFINED RUST 1.75 COMPILER/TEST AND SEMANTIC/MUTATION VERIFICATION PASSED
  2026-07-23; NATIVE INSTALLED-ARTIFACT EVIDENCE PENDING.** Platform: Linux installed-service mode after the active-user
  `--server --service-owned-server` image is deliberately unreadable and nondumpable. Endpoint/action:
  same-principal `--whiteboard` overlay launch, token-derived `_whiteboard_<hmac>` listener admission,
  directional mutual launch proof, and helper lifetime. Boundary: the overlay helper ↔ the exact server
  process and thread that launched it.

  The source-proven old path recorded the launch parent and required that exact socket PID, but then called
  `ensure_peer_executable_matches_current_by_pid_opt` and the server-role argv reader before answering the
  mutual HMAC challenge. The server and helper both execute the dedicated mode-0711 service-child image.
  Linux subjects `/proc/<pid>/exe` dereference to ptrace access checks, and the capability-free non-root
  reproduction recorded for this slice changed that same-UID read from success to `EACCES` immediately after
  `PR_SET_DUMPABLE(0)`. `/proc/<pid>/stat` remained readable. The hardened service confidentiality boundary
  could therefore make a legitimate overlay reject its own server before proof. This is a hardening-induced
  local availability and helper-authority incompatibility, not evidence of exploitation, remote bypass, Docker
  root access, host service/configuration/firewall mutation, a public listener, or compromise.

  Linux whiteboard admission now derives one minimal PID/UID/start-time identity for the connected Unix peer,
  requires the immutable launch-parent PID to equal the helper's current kernel parent, and requires the socket
  identity to equal that exact live parent before answering any challenge. It does not read executable, argv,
  environment, or token metadata across the nondumpable boundary. Non-Linux admission retains its existing exact
  parent PID, current executable, and complete server-role checks.

  The existing fresh 32-byte launch secret, HMAC-derived endpoint name, directional server/endpoint challenge
  domains, proof-before-stream-spawn order, and per-connection drawing tokens remain. Both directional proofs now
  also bind the fixed `--whiteboard` role. The helper derives that role from its complete exact argv before
  answering; missing, extra, case-varied, or different roles fail closed. Every same-principal Linux whiteboard
  launch uses `run_me_with_env_and_parent_death`, which arms the existing pre-exec
  `PR_SET_PDEATHSIG(SIGKILL)` and parent recheck before the descriptor policy and exec. The overlay and inherited
  launch secret therefore cannot remain after loss of the exact creating server thread.

  `scripts/verify-linux-nondumpable-cm.py` now covers CM, PA, and whiteboard. It binds the Linux exact-parent
  identity, socket PID/UID/start-time proof, absence of ptrace-gated whiteboard proof, non-Linux proof retention,
  fixed-role HMAC and complete helper argv, parent-death launch, receiver proof-before-traffic order, focused tests,
  R-S11cd, Appendix C #223, this ledger identity, and shared-gate wiring. Its self-test rejects 25 deliberate
  CM/PA/whiteboard weakenings. The independent workspace meta-verifier binds the focused runtime-validation region,
  wrong-role regression, shared compiled-test invocation, shared heading, all three Apple source assertions,
  requirement, Appendix row, and ledger identity; its normal and complete source-mutation modes pass.

  Confined validation used immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` as numeric UID/GID 1000 with
  no network, all capabilities dropped, no-new-privileges, a read-only root and source tree, vendored dependencies,
  and ephemeral tmpfs compiler output. Rust 1.75.0 locked/offline tests passed all four R-S11e-95/R-S11e-96
  kernel-identity and role/token-proof regressions plus the actual-child R-S11e-44 parent-death regression. The
  normal default-feature `cargo check --features linux-pkg-config` passed with only the repository's existing
  warning set. Focused 25-mutation verification, workspace normal/source-mutation verification, Bash/Python syntax,
  dependency-inventory normal/self-test (unchanged 871 lexical unsafe blocks), native-codec normal/self-test,
  requirements-hash synchronization, `Cargo.lock` immutability, touched-source Rust 1.75 formatting, and
  `git diff --check` also passed. The full Apple wrapper was deliberately not invoked because it unconditionally
  rebuilds and retags Docker images before source checking; its three changed whiteboard assertions were instead
  syntax-checked, independently inspected, and mutation-bound by the workspace verifier.

  No native installed service, overlay UI, package, release artifact, Android/iOS device, host RustDesk process,
  listener, firewall, or configuration is exercised by this source row. Exact native installed-service/overlay and
  final Debian artifact evidence remain R-B2/R-S11c-27; the prohibited long cold release build remains unrun.
- **R-S11ce/R-S11e-97 — Linux unprivileged clients authenticate root service endpoints without root procfs —
  SOURCE IMPLEMENTED; CONFINED RUST 1.75 FULL LIB/TEST TYPECHECK AND SEMANTIC/MUTATION VERIFICATION PASSED
  2026-07-23; NATIVE INSTALLED-SERVICE/ARTIFACT EVIDENCE PENDING.** Platform: Linux
  installed-service mode. Endpoint/action: client-side authentication of the generic, nonsecret `_service`
  liveness channel and the dedicated raw `_service_password` channel before any request/header/body is sent.
  Boundary: active-user UI/CLI process ↔ stable uid-0 service listener.

  The retained implementation contradicted the already-normative R-S11i model. Both client paths connected to the
  fixed root service socket and then tried to read the root peer's `/proc/<pid>/cmdline` and dereference
  `/proc/<pid>/exe` to prove `--service` plus a protected executable. Linux subjects the executable link to
  `PTRACE_MODE_READ_FSCREDS`; an ordinary active-user client cannot inspect a uid-0 service this way. The proof
  could therefore reject the legitimate installed service before generic liveness or the raw password header,
  while adding no meaningful authority against a process already capable of presenting uid 0.

  Both client paths now terminate in one decision over the connected Unix socket's kernel credentials: uid must be
  present and exactly zero, and PID must be present and positive. Generic framed `_service` and raw
  `_service_password` use thin transport-specific wrappers around that decision. The client no longer reads the
  root peer's executable, argv, environment, start time, ancestry, or any other procfs process metadata. The fixed
  service path and root-owned mode-0711 service IPC parent remain separately enforced; a non-root path squatter is
  rejected before any password bytes, and a process that can present uid 0 is already inside the root authority
  boundary. The opposite-direction controls are unchanged: the root listener still snapshots and proves the
  active/root caller and exact polkit subject before reading the password body, and `_service_credential` retains
  the exact direct-parent/current-generation proof in both directions.

  `r_s11e97_linux_root_service_peer_requires_kernel_uid_and_positive_pid` covers the common decision and is
  compiled/typechecked by the full lib/test target. The Linux password semantic verifier binds both call paths,
  shared decision, uid/PID requirements, absence of the retired root-procfs proof, and deliberate non-root/procfs
  regressions. Its normal and complete deliberate-mutation modes pass. The shared source gate binds R-S11ce,
  Appendix C #224, and this ledger identity.

  Confined validation used immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` as numeric UID/GID 1000 with
  no network, all capabilities dropped, no-new-privileges, a read-only root/source tree and Rust 1.75 toolchain,
  locked/offline vendored dependencies, and an ephemeral executable tmpfs output tree. The full
  `cargo check --lib --tests --no-default-features --features linux-pkg-config` target passed, compiling and
  typechecking production code plus the focused regression. The direct focused `cargo test` attempt compiled the
  project through the final link and exposed no source error, but the linker was killed at the container's 6 GiB
  memory cap; it is therefore not recorded as an executed-test pass. The focused semantic verifier passed normally
  and rejected every deliberate mutation, including non-root peer acceptance and a reintroduced root-procfs read.
  No native installed service, password transaction, package, release artifact, host RustDesk process, listener,
  firewall, or configuration was exercised. Native installed-service liveness/password behavior and exact
  Debian-artifact evidence remain R-B2/R-S11c-27; the prohibited long cold release build remains unrun.
- **R-S11cf/R-S11e-98 — Debian builder private-source and container authority — SOURCE IMPLEMENTED;
  EXACT SOURCE COMMIT `547da491d182b98c31184a509e192977bcd7cb18` CONFINED
  SEMANTIC/MUTATION/WORKSPACE AND AUTHORITY-RUNTIME PROBES PASSED 2026-07-23;
  EXACT COLD DEBIAN ARTIFACT EXECUTION REMAINS R-B2/R-S11c-27.** Platform: the Linux Docker build host used by the
  direct and release-child Debian artifact builders. Endpoint/action: the sole offline compiler-container launch
  in `scripts/build-debian.sh`. Boundary: the exact committed source, verified offline input closure, and
  invoking-user output path ↔ compiler/build-script/native-dependency execution and Docker daemon authority.

  The inherited direct path mounted the real developer checkout read-write at `/src`. The container already used
  the invoking numeric UID/GID, removed its network namespace, published no port, and received no Docker socket or
  host namespace, but it retained the default writable root filesystem, default capability set, privilege-gain
  semantics, implicit image-pull behavior, unbounded process/memory/CPU/scratch resources, and one fixed
  daemon-global name. A faulty or compromised build dependency could therefore alter or delete worktree files,
  leave ambiguous generated state, exhaust host resources, or use broader container authority than compilation
  requires. This is build-host and supply-chain authority debt. It is not evidence that a root container ran, a
  container escaped, a public listener was exposed, a host RustDesk process/service/configuration/firewall was
  changed, or any machine was exploited or compromised.

  Direct mode now records one full clean commit and gives each A/B pass a distinct current-user mode-0700
  `git clone --no-hardlinks --no-checkout --reject-shallow`. Each clone is detached at that exact commit, has its
  remote removed, owns its private `.git`, and rejects shallow, graft, alternate, replacement-ref, sparse, and
  index-masking state; `git fsck --full --strict` verifies its object database before use. Release-child mode
  accepts only the already-private detached R-B2 source snapshot and requires `DOUBLE_BUILD=0`, leaving
  independent pass ownership with the outer release transaction. The real direct-build checkout is never a
  compiler mount.

  The sole compiler launch addresses `/usr/bin/docker` and the already-proven immutable image ID with
  `--pull=never`, `--network=none`, a read-only root, the invoking numeric UID:GID, all capabilities dropped,
  no-new-privileges, 1,024 PIDs, 16 GiB memory with no swap expansion, four CPUs, and a 12-GiB executable
  `nosuid,nodev` `/tmp` tmpfs. Its only host inputs are the private writable build tree and the complete verified
  private online snapshot read-only. An empty 1-MiB read-only/no-exec/nosuid/nodev tmpfs hides `/src/.git`, so
  compiler code receives no private Git object, config, or index inode. There is no fixed name, port,
  host namespace, Docker socket, image build/pull fallback, privilege mode, or added capability. After either
  failed or successful compilation, the host re-proves the source root device/inode, exact commit, private Git
  authority, canonical index flags, unchanged index, and every tracked worktree byte before selecting an artifact.
  Generated ignored/untracked state dies with the current-user-owned private workspace.

  `scripts/verify-debian-builder-authority.py` binds the exact source branch, private-clone construction, Git
  authority/postconditions, direct A/B separation, release-child outer ownership, complete Docker launch inventory,
  forbidden ambient authority, R-S11cf, Appendix C #225, this ledger identity, shared-gate wiring, and workspace
  ownership through deliberate mutations.

  Exact-source verification at `547da491d182b98c31184a509e192977bcd7cb18` is confined and does not compile
  RustDesk. The focused verifier passes on the pinned
  Python 3.6 Debian-builder image and rejects all 32 deliberate source/requirement/ledger weakenings. The independent
  workspace meta-verifier passes normally and rejects its complete in-memory source-mutation matrix while binding
  the new verifier, shared gate, normative requirement, Appendix row, and ledger. A neutral runtime probe used the
  exact Debian builder image and production launch flags against a disposable private fixture; it observed
  UID/GID 1000, zero effective capabilities, `NoNewPrivs: 1`, a writable private source, empty/read-only hidden
  `.git`, read-only online input, and read-only container root, while the underlying private Git canary remained
  unchanged.
  A separate direct-source probe reproduced the exact non-hardlinked detached clone, remote removal, private
  mode-0700 root, full strict fsck, clean tracked/index postconditions, and private generated-output allowance.
  Debian package-authority synthetic mutations and the source polkit validator pass. Dependency inventory
  normal/self-test, native-codec normal/self-test, Bash and Python syntax, synchronized requirements SHA-256
  `d588b090ad2a843e682363b84f8991ea014a0f48b3dc98fee91584be641554be`, and `git diff --check` pass.
  Every executable verifier ran as numeric UID/GID 1000 in an already-present immutable image with
  `--pull=never`, no network, a read-only root and source, all capabilities dropped, no-new-privileges, bounded
  resources, no port, and no Docker socket.

  Source-gate and authority-probe success do not claim a compiled `.deb`, installed-service behavior, the final
  Debian lifecycle marker, or the complete cold R-B2 transaction; those remain R-B2/R-S11c-27. No host RustDesk
  process/service/configuration/listener, firewall/network state, native device, or installed package was used,
  inspected, or changed.
- **R-S11cg/R-S11e-99 — Android signing-identity generation authority — SOURCE CLOSED/GATED AND
  EXACT-COMMIT DISPOSABLE END-TO-END VALIDATED 2026-07-23; ESTABLISHED PROJECT IDENTITY UNTOUCHED.**
  Platform: Android build tooling on the unprivileged Linux build host. Endpoint/action: the one-time creation of
  the stable self-managed RSA signing identity required by R-B2. Boundary: a requested absent protected keystore
  leaf and optional protected password file ↔ randomness, `keytool`, the local Docker daemon, private staging, and
  durable final publication.

  The inherited generator selected `${HARNESS_PREFIX}-android-builder`, accepted a shell-interpolated alias, and
  ran a networkless but otherwise ambient container: default root identity, writable root, default capabilities
  and privilege-gain semantics, no process/memory/CPU/scratch ceilings, and implicit image-pull behavior. It
  mounted the complete permanent output directory read-write, copied the password value into the inner
  `keytool` argv, generated a missing password through host `openssl`, and let `keytool` create the irreplaceable
  identity directly at its final path. A malformed alias or faulty image/tool therefore had broader host-output,
  secret, and publication authority than necessary. The old container published no port and had no network,
  Docker socket, or host namespace. This is source-proven signing-tool/build-host authority debt, not evidence
  that the established signing identity changed, container root became host root, Docker escaped, a public
  listener appeared, or any host/device/service/firewall was modified, exploited, or compromised.

  `scripts/gen-android-keystore.sh` now refuses effective UID or primary GID 0, fixes the alias to
  `rustdesk-fork`, uses `/usr/bin/docker`, closes Docker host/context/TLS/configuration authority, loads the
  immutable `ANDROID_BUILDER_IMAGE_ID`, and requires its complete pinned local provenance. Keystore/password
  leaves must be distinct canonical absolute no-symlink paths beneath the same current-UID mode-0700 directory;
  that directory and its current-UID mode-0700 parent are created only when absent. An existing keystore is
  refused without inspection or overwrite. An existing password must be a nonempty current-UID mode-0600
  single-link regular file.

  The generator creates a mode-0700 random stage inside that signing directory, snapshots its narrow worker
  read-only, and gives Docker an empty private configuration whose owner/mode/link/bytes are reproved before and
  after daemon operations. Password creation, key creation, and independent certificate inspection are three
  operations in the already-present immutable builder. Every operation is
  `--pull=never`, networkless, read-only-root, numeric non-root, capability-free, no-new-privileges, and
  independently bounded for PIDs, memory with no swap expansion, CPU, and non-executable `nosuid,nodev` tmpfs.
  No final signing directory, repository, Docker socket, port, host namespace, added capability, or image
  build/pull path is present. The only writable bind is the narrow private output subdirectory. A missing
  password is derived from 33 bytes of `/dev/urandom` inside the first container and moved out of that writable
  mount before key generation. Both key-generation password inputs and the independent-verifier key/password
  inputs are exact read-only files. `keytool` receives only `-storepass:file`/`-keypass:file` paths, never secret
  argv or environment bytes.

  Password and staged-keystore inode/metadata/size/timestamp state plus SHA-256 are captured and reproved around
  key generation and independent inspection. The worker fixes RSA-4096, SHA256withRSA, 10000-day validity, alias,
  and subject; inspection emits exactly one uppercase certificate SHA-256. A newly generated password is
  atomically hard-linked and filesystem-synchronized first, so a visible keystore cannot lack its matching
  password. The verified key is then atomically hard-linked to the still-absent final leaf, both filesystems are
  synchronized, staging links are removed, and final current-UID/mode/link/byte postconditions are reproved.
  A publication race may leave only the already-durable matching password, never a key without its password;
  retry deliberately consumes that password.

  `scripts/verify-android-keystore-authority.py` binds the fixed image/alias, path and secret metadata,
  private staging, all three launch inventories, forbidden ambient authority, file-only password flow,
  independent verification, stability proofs, password-before-key synchronization/publication, R-S11cg,
  Appendix C #226, this ledger, operator documentation, shared-gate wiring, and workspace ownership through
  deliberate mutations. The independent workspace verifier binds the focused verifier and all policy anchors.

  Exact clean source commit `c89082124cff95a1c0a67ababcd4a5de57d5996f`, tree
  `07741ba2a4a6239d1e19d9d71440560338d11a24`, was exercised through both publication branches. A fresh
  mode-0700 `/tmp` fixture with no password produced a disposable random password and key, independently
  inspected the fixed alias/properties, synchronized both, and left current-UID mode-0600 single-link final
  files; an immediate retry failed on the pre-Docker existing-keystore no-clobber guard. A separate fixture with
  an existing mode-0600 password produced and independently inspected a disposable key while its password digest
  and single-link metadata remained unchanged. Both trees and their random keys were removed. A neutral launch
  with the exact Android image and key-generation bounds observed UID/GID 1000, zero effective capabilities,
  `NoNewPrivs: 1`, read-only root, only loopback, and a narrow writable output whose worker-umask canary was
  current-UID mode 0600.

  The focused verifier passes under the immutable Python 3.6 Debian-builder image and rejects all 30 deliberate
  weakenings. From the same clean commit, the independent workspace verifier passes normal validation and its
  complete in-memory source-mutation catalog in immutable verifier image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`.
  Dependency inventory normal plus 103 self-tests, native-codec normal/self-test, Bash/Python syntax,
  requirements SHA-256 `0db1cf9a1c331b4c59b37c4b93853632a728d661c837fe81a7a645fea9dbe593`,
  and diff checks pass. Full executable workspace fixture mode expects a live current-user systemd D-Bus socket;
  the confined verifier deliberately had none, failed closed, and was not given a host session-bus mount. No
  claim is made for that fixture mode.

  No established keystore/password was listed, opened, mounted, hashed, regenerated, replaced, or otherwise
  inspected. No APK was built or signed, no Android device was used, and no host RustDesk
  process/service/configuration/listener, firewall/UFW/nftables/iptables, or host network state was inspected or
  changed. This closes future one-time generator source/runtime authority only; current APK identity, device
  upgrade behavior, the complete R-B2 release transaction, native Apple/Windows evidence, and external review
  remain separate obligations.
- **R-S11ch/R-S11e-100 — Windows helper container and KVM authority — SOURCE IMPLEMENTED;
  PROVISION-TIME GOLDEN HASH-ORDER WORDING CORRECTED 2026-07-23; EXACT CORRECTED-COMMIT EVIDENCE
  PENDING.** Platform: the unprivileged Linux build host and the pinned
  Ubuntu helper used around the Windows KVM harness. Endpoint/action: WiX extraction, offline-ISO creation,
  output-disk creation, overlay EFI preparation, result extraction, MSI canonicalization, and read-only golden
  completion/inventory inspection. Boundary: caller Docker authority, captured helper/archive bytes, private
  build outputs, the exact golden image, and `/dev/kvm` ↔ containerized `tar`, `genisoimage`, Python,
  libguestfs/supermin, and QEMU.

  The three consumers previously contained seven independent helper launch shapes. The build path eventually
  resolved the immutable image ID and every launch was networkless with no published port, Docker socket, or
  host namespace, but the helpers retained a writable container root, default capabilities and privilege-gain
  semantics, implicit pull behavior, no resource ceilings, caller Docker-client configuration, and broad
  writable run/pass/script mounts. Provision and diagnostic verification selected a mutable
  harness-prefixed tag, ran as container root, mounted the complete harness-state tree read-only, and granted
  `/dev/kvm`. This is source-proven build-output/device authority debt. It is not evidence that a helper
  listened publicly, container root became host root, Docker escaped, the established golden changed, host
  RustDesk or a host service/firewall/network setting changed, or any system was exploited or compromised.

  `scripts/windows-helper-runtime.sh` now owns the only helper-container launch. It refuses host UID or
  primary GID 0, validates the root-owned fixed `/usr/bin/docker`, fixes the local Unix daemon, rejects
  context/TLS endpoint inputs, and replaces any inherited client configuration with a random current-UID
  mode-0700 runtime containing a mode-0600 single-link canonical `{}` config. The runtime supplies
  `--host`/`--config` explicitly and re-proves that authority before and after every daemon operation. It
  verifies the exact `WIN_HELPER_IMAGE_ID`, embedded role/base/Dockerfile/dpkg provenance, and independently
  pinned captured image archive. `scripts/offline-image-provenance.py` now uses `/usr/bin/docker` and its
  embedded-provenance reader itself refuses root and runs non-root/no-pull/networkless/read-only-root with all
  capabilities dropped, no-new-privileges, and explicit process/memory/no-swap/CPU/tmpfs bounds.

  The captured Ubuntu image's `/boot/vmlinuz-6.8.0-134-generic` is root-owned mode 0600, so a direct UID-1000
  libguestfs invocation correctly failed. The correction does not add root or `CAP_DAC_READ_SEARCH`.
  `scripts/windows-helper-extract-kernel.py` is snapshotted mode 0400 and executed as the invoking numeric
  UID:GID inside the same exact image. It parses the already-pinned offline Docker archive as data, requires
  one image and unique referenced layers, rejects duplicate/ambiguous/whiteout kernel members, extracts exactly
  `boot/vmlinuz-$WIN_HELPER_KERNEL_VERSION` no-clobber, independently verifies
  `SHA256_WIN_HELPER_KERNEL`, synchronizes the file/directory, and leaves a private mode-0400 kernel. The runtime
  mounts that leaf read-only and fixes `SUPERMIN_KERNEL`, modules, version, cache, and temporary roots, allowing
  supermin/QEMU to remain UID 1000.

  Every launch is `--pull=never`, networkless, read-only-root, numeric non-root, capability-free,
  no-new-privileges, and bounded by one of three explicit PID/memory/no-swap/CPU/tmpfs profiles. Caller
  options accept only lexically canonical explicit bind mounts backed by regular files/directories, refuse
  special files and protected runtime targets, and require writable sources to be current-UID, not
  group/world writable, and single-link when regular. The build's six operations now mount the
  exact WiX archive/private output, verified online snapshot plus exact manifest/private ISO output, exact raw
  output disk, exact relative-backed overlay plus private golden, exact read-only output disk plus fresh extract
  directory, and exact read-only MSI/worker plus fresh canonical output. No whole run root, pass root, source
  scripts tree, or permanent output tree is writable. The relative `../golden.qcow2` backing identity resolves
  to the same private leaf in host and container layouts.

  Provision and golden verification address the immutable ID and mount only the exact golden leaf read-only at
  `/authority/golden.qcow2`; their snapshotted fixed worker has only `marker` and `inventory` operations.
  Existing-golden reuse and diagnostic verification hash-check before inspection. During a new provision, the
  loop reads only the exact provision-owned in-progress leaf to test the terminal marker and verifies the final
  pinned hash immediately before accepting that marker as completion. Ordinary build libguestfs receives no host
  device. Only these two golden-read consumers receive exactly `/dev/kvm:rwm` and its one non-root numeric
  supplemental group, while retaining zero capabilities and no-new-privileges. No consumer has an image
  build/pull fallback, mutable helper tag, privileged/root identity, added capability, published port, Docker
  socket, host namespace, or broad harness-state mount.

  `scripts/verify-windows-helper-authority.py` binds the shared runtime, all six build and two golden-inspection
  consumer shapes, fixed image/client/config, archive/kernel derivation and pins, provenance-reader confinement,
  exact mounts, relative overlay, sole KVM grant, forbidden authority, R-S11ch, Appendix C #227, this ledger,
  operator documentation, shared-gate wiring, and independent workspace ownership through deliberate mutations.
  Before the hash-order wording/gate clarification, clean implementation commit
  `bc3bb5be0083e0cbd6d124ecb7e70b1ed74c0c57` (tree
  `4003869e60bf43004634463f960b2b93918c37f3`) rejected all 39 then-defined deliberate weakenings under
  immutable verifier image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`;
  the independent workspace source-mutation catalog passed under the same image. The broader Windows-harness
  verifier passed 139 mutations and four bounded behavioral suites under exact helper image
  `sha256:aa9abae2debc838591649fb0b7b94f9f2f24e7848c699cd70e1103a690db21ce`.
  Dependency inventory and all 103 inventory self-tests, Bash syntax and isolated Python bytecode compilation,
  offline-image-provenance self-test, native-codec normal/negative gates, `git diff --check`, and synchronized
  requirements SHA-256 `b3925b07de72130f148c0c47338aa3c6089f12360cab8a84a51410f51fb07e92`
  also passed from that clean commit. Those results validate the unchanged runtime implementation but are not
  claimed as exact evidence for the corrected normative text and added hash-order mutations; the corrected
  source/evidence identity remains pending in this commit. The monolithic `scripts/verify.sh` was deliberately not invoked because it
  includes two UID-0 containers with `CAP_CHOWN`/`CAP_FOWNER`; running those would have violated this
  investigation's explicit no-root boundary. Its R-S11ch focused gate and independent ownership binding were
  instead executed directly under the non-root confined images above. No full-verifier verdict is claimed.

  Disposable private 64-MiB raw disks exercised the production runtime under both TCG and the exact KVM
  authorization. Both completed partition/VFAT guestfish operations as UID/GID 1000 with the exact derived
  kernel, zero added capabilities, no network, read-only root, no-new-privileges, and bounded scratch/resources;
  outputs remained current-user mode-0600 single-link files and were removed. A production-layout disposable
  qcow2 overlay recorded `../golden.qcow2`, resolved the exact synthetic read-only base at the same identity
  inside the container, accepted a write through the overlay, and returned that byte through a separate
  read-only invocation. A deliberately mode-0644 writable probe was rejected before its helper launch; the
  production `umask 077` shape then passed. Archive/image provenance and the independent derived-kernel pin were
  reproved before and after extraction. These exact-commit probes built or pulled no image and did not open the
  established golden, boot or define a VM/domain, compile Windows/RustDesk, access a host service, or
  inspect/change host RustDesk, listeners, firewall/UFW/nftables/iptables, or host network state. Full golden
  behavior, Windows artifacts, double-build equality, and the complete cold release remain R-B2 obligations.
- **Mobile (iOS + Android) at-rest config wrapper keyed by OS-protected mobile storage —
  SOURCE IMPLEMENTED 2026-07-18; ANDROID SIGNED-ARTIFACT VALIDATED 2026-07-18; ON-DEVICE AND iOS
  ARTIFACT VALIDATION PENDING.** This is the mobile face of
  Appendix C #14. The old path on BOTH iOS and Android keyed `password_prs` at rest with the config
  keypair PK (`get_uuid()` / `Config::get_key_pair().1` — the off-file `machine_uid` block is
  cfg-compiled out on both mobile platforms), which is itself stored in plaintext in the same TOML, so the
  `symmetric_crypt` wrapper added no confidentiality over a plain config read. The current source removes
  that path as the primary key source: `libs/hbb_common/src/lib.rs::at_rest_storage_key()` on mobile now
  returns only an already-installed 32-byte process key accepted by `set_mobile_at_rest_storage_key()`;
  empty/wrong-length keys and failed encrypt→decrypt self-tests are rejected. `get_uuid()` is separated
  back into mobile device-id metadata through `mobile_device_id()`, so the OS storage key is not exported
  through `main_get_uuid`. Android process startup
  (`flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainApplication.kt`) obtains a private
  random storage key from `MobileAtRestStorageKey.kt`, where it is wrapped by `AndroidKeyStore` AES-256-GCM
  with StrongBox requested first and an ordinary AndroidKeyStore fallback, non-auth-bound, and
  `setUnlockedDeviceRequired(false)`. The fallback is not described as TEE: AndroidKeyStore may report
  software, trusted-environment, or StrongBox security depending on the device, and the actual
  `KeyInfo` security level remains part of on-device validation;
  partial/corrupt stored envelopes fail closed, first creation requires a durable `SharedPreferences.commit()`,
  and the committed envelope is re-read as a round-trip self-test before Rust injection through
  `FFI.setMobileAtRestStorageKey`. iOS startup
  (`flutter/ios/Runner/AppDelegate.swift`) loads or creates the same 32-byte random storage key as a
  Keychain generic-password item using `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and
  `kSecUseDataProtectionKeychain`, re-reads it before adoption, and injects it into Rust through
  `rustdesk_set_mobile_at_rest_storage_key` declared in the bridging header. `derive_cpace_prs` output bytes
  are unchanged; only the storage wrapper's key source changes. The `#[no_mangle]` C entry point is intentionally
  private in the Rust namespace: Rust still exports the C symbol, while pinned FRB 1.80.1 ignores non-public
  functions instead of trying to expose its raw pointer through the Dart bridge. Existing mobile ciphertext encrypted under
  the legacy config keypair is accepted only after the OS key was installed and tried, as a read-only decrypt fallback through
  `Config::get_existing_key_pair()`; OS-key unavailability returns an error before that read. When the authorized fallback succeeds, `decrypt_str_or_original` /
  `decrypt_vec_or_original` mark the value for re-store so the next write rewraps under the OS key. The Android packaging/native-linkage
  half is artifact-validated; the overall mobile item remains open. The Android release path keeps `MainApplication` and
  `MobileAtRestStorageKey` structurally auditable through R8 and runs
  `scripts/verify-android-mobile-key-artifact.py` against the final certificate-verified APK. The bounded
  verifier rejects duplicate/noncontiguous DEX entries, proves the ordered
  `Application.onCreate` → `getOrCreate` → JNI setter → `FFI.onAppStart` bootstrap, asserts the packaged
  KeyStore/AES-GCM/durable-commit/reread method references, and requires the AArch64
  `Java_ffi_FFI_setMobileAtRestStorageKey` dynamic export from the packaged `librustdesk.so`. It is wired
  into both normal signing and `build-android.sh --verify-apk`; source gates keep that wiring and its
  negative self-test mandatory. At exact clean commit `6efe41f45a01da1d8b4d39dee3cbb208d6a05308`, the default
  target-local two-pass Android build used pinned image
  `sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121`, private immutable online closure
  `a7581f0ffa4fa924d4eacfe6c2bef9dec37a2ce2d06740c04037489341d904ac`, and signing certificate SHA-256
  `1091322BA0425AFA1EB50DEEAE439A5FFFE2B1DD82C82B04515D9290A0CEEFA9`. Both clean target-local
  passes produced the same v2/v3-signed APK SHA-256
  `b506c67080ee86e6171ce3fed436bf8dd7e31dfa7d48f418158aaca2b10e46b3`; the manifest and mobile-key artifact
  verifiers passed during each signing pass and in the final direct artifact verification. This same-workspace
  target-local A/B check is not the full top-level R-B2 transaction with independent source snapshots, so R-B2 and
  R-B10 release closure remain open. The artifact gate proves packaging and native linkage, not live
  Keystore/Keychain behavior: the round trips have not run on an Android emulator/device or iOS build host in this
  loop. The Documents directory this wrapper
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
  review are recorded in the report. **AUDITOR HANDOFF PREPARED 2026-07-18 — R-V3 remains
  OUTSTANDING.** `docs/CRYPTO-AUDIT-SCOPE.md` now defines the exact-clean-public-commit review
  object, whole-repository follow-the-call-graph rule, current mandatory roots from password/NFC/
  Argon2id PRS derivation through CPace, wire choreography, the authorization edge, and the
  two-key secretbox frame lifecycle, primary draft-21/RFC 8265/libsodium references, required
  external deliverable, and the explicit non-sign-off boundary. The prior PAKE/transport entry
  points had drifted to stale line numbers and, after the bounded custom NFC implementation grew,
  materially understated the trust surface as approximately 600 lines of byte-shuffling. They now
  use symbol anchors and expose the custom normalization code as mandatory audit scope.
  `scripts/verify-crypto-audit-scope.py --self-test`, wired into `scripts/verify.sh`, rejects a
  missing root/current symbol, a brittle line citation, a false independent-sign-off claim, or a
  removed R-V3 limitation; its mutation suite proves those representative regressions fail. This
  prepares an accurate external handoff. It does not perform the independent review, assess the
  cryptography, or remove the pre-audit release blocker. **R-A10 PARTIAL-FRAME EVIDENCE GAP CLOSED
  AT PROJECT-TEST LEVEL 2026-07-18.**
  `partial_prekey_frame_times_out_without_key_or_guess_charge` now drives a raw loopback peer that
  declares a valid 64-byte pre-key frame, delivers one byte, and remains open. Under Tokio's paused
  clock it proves the exact 5-second WAIT_1 deadline returns `HandshakeError::Io`, no cipher is
  engaged, and the connection is dropped. Limiter mutation now has one typed production choke,
  `record_handshake_failure`: after nine confirmation failures the partial-frame `Io` leaves the
  source allowed, while the companion wrong-password `Confirmation` consumes the tenth slot and
  blocks it. The oversize, out-of-order, duplicate, and malformed wire negatives also assert no
  key engagement and no limiter charge. `scripts/verify-crypto-audit-scope.py --self-test` anchors
  the behavioral test and the typed accounting symbol so this evidence cannot disappear while the
  handoff still claims it. This closes only the recorded R-A10 project-test gap; it is not external
  audit evidence, does not satisfy R-V3, and does not remove the pre-audit production blocker.
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
- **R-R3 dependency-advisory gates** — `scripts/audit.sh` now separates image acquisition from verdict execution,
  uses only one exact local image content ID, verifies its acquisition metadata, scanner bytes, toolchain, and exact
  RustSec checkout, enforces an unoverrideable 90-day database-age ceiling, and runs both `cargo-audit` and
  locked/offline `cargo-deny check advisories` nonroot with no pull/network/capabilities, read-only inputs, bounded
  resources, strict structured finality, and a canonical-hashed Cargo vendor closure. The exact 2026-07-17 RustSec
  snapshot and policy were reviewed on 2026-07-22; both scanner verdicts are green for the recorded lockfile, policy,
  vendor closure, image, and snapshot, while freshness is reevaluated on every invocation. Independently archived
  and provenance-verified image distribution plus exact R-B2/R-B10 artifacts remain open. `scripts/dart-audit.sh`
  runs pinned offline OSV for `flutter/pubspec.lock` and requires reason-bearing future accepts. `scripts/verify.sh`
  mutation-binds both advisory authority models; `scripts/native-codec-watch.sh` covers the vcpkg native-codec watch
  separately.
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
  review enumerated confirmed-inert residue retained at that completion boundary: orphaned uncompiled
  `libs/scrap/src/wayland.rs` + `libs/scrap/src/common/wayland.rs` (the `mod` is
  excised, the files linger beside cfg-gated `common/linux.rs` WAYLAND arms);
  dead `--quick_support` plumbing in `libs/portable`;
  and, at the time of this earlier note, `enable_trusted_devices` viewer plumbing plus
  `Dialog2FaField`/`kUseTemporaryPassword` Dart stubs. The trusted-device/2FA cluster was
  subsequently excised and is closed/gated by I-11 below; it is no longer retained residue.
  The account-assignment residue was subsequently deleted and is closed/gated by R-SV6a above. The two orphaned
  Wayland capture files were subsequently deleted and are closed/gated by R-X12a below. The portable
  `--quick_support` plumbing was subsequently deleted and is closed/gated by the R-X9 source-completeness record
  below; it had no application receiver and the exact released setup name returned through the MSI installer path
  before that legacy classifier. No item in this earlier sampled residue list remains open.
  **⤷ NOTE: this bullet sampled ~5 items; it is SUPERSEDED by the `## Incomplete`
  section immediately below (2026-07-03 full sweep = ~80 sites, incl. 7 user-visible
  defects + 1 live race this earlier note missed).**
- **R-X12a — orphaned Wayland capture source files deleted — CLOSED/GATED 2026-07-21.** The June 22 R-X12
  change removed the root and common `mod wayland` declarations, the Cargo feature, every active consumer, and
  the seven-file `libs/scrap/src/wayland/` implementation, but two upstream-imported alternate module files
  remained uncompiled at `libs/scrap/src/wayland.rs` and `libs/scrap/src/common/wayland.rs`. Rust's module
  contract confirms an external source file enters a crate only through a module item, so neither file was
  reachable; Cargo likewise had no feature capable of selecting them. This was therefore source-coherence and
  future-reactivation debt, not a runtime Wayland/PipeWire capture path, listener, credential exposure,
  privilege escalation, exploitation incident, host mutation, or evidence of compromise. Both files are now
  deleted. The R-X12 gate rejects the old directory and both exact file paths (including dangling symlinks), and
  the independent workspace validator interprets the Cargo/module/path boundary and rejects deliberate feature,
  module, path, gate, requirement, disposition, or ledger mutations. The live X11 capture implementation and the
  separately compiled platform/session compatibility code are unchanged; exact packaged-artifact proof remains
  R-B2/R-B10.
- **R-X9 — portable-packer Quick Support residue excised — CLOSED/GATED 2026-07-21.** The June 24 R-X9
  change deleted the Windows application's portable controlled-side service, its Quick Support receiver and
  elevation machinery, `set_quick_support`, the `--quick_support` argument arm, and the application's executable-
  name classifier. It missed the duplicate classifier in `libs/portable/src/main.rs`, which still recognized
  `-qs-`/`-qs.exe`/`_qs.exe` names and replaced an empty forwarded argument list with `--quick_support`. History and
  current build tracing establish that `libs/portable` is now the live setup bootstrapper, not a dead crate:
  `scripts/build-windows.ps1` generates it from a one-file `rustdesk-installer.msi` payload and publishes it only as
  `rustdesk-setup.exe`. That exact name enters the closed protected-installer parser and returns before the legacy
  classifier, while the embedded RustDesk application no longer has any Quick Support receiving mode. The residue
  was therefore inert in the exact release flow and did not expose a second controlled-side mode, elevation path,
  listener, credential, privilege escalation, exploitation incident, host mutation, or evidence of compromise.
  It nevertheless contradicted R-X9's explicit compiled-out requirement and preserved misleading executable-name-
  selected reactivation logic. The duplicate classifier, state, and synthesized argument are now deleted; the live
  MSI filename classification, protected elevation ceremony, exact closed installer argv parser, extraction, and
  ordinary argument forwarding are unchanged. The shared R-X9 source gate now rejects `quick_support` in any active
  Rust source, and the independent workspace validator plus deliberate mutations bind the portable source absence,
  gate, existing R-X9 requirement, Appendix C #193, and this ledger. Focused portable-crate tests and a locked,
  offline nonroot Linux check provide source/build evidence; native Windows and exact setup-artifact execution remain
  part of R-B2/R-B10.
- **R-R2c — alternate mobile build authorities deleted — SOURCE CLOSED/GATED 2026-07-21; EXACT CURRENT-COMMIT
  APK EVIDENCE REMAINS R-B2/R-B10.** History and current caller tracing establish two different layers. The ten
  top-level Flutter scripts imported with the upstream tree were standalone entry points: `flutter/run.sh` fetched
  tools and ran a generic host build; `flutter/build_android.sh` emitted multi-ABI APKs and an AAB;
  `flutter/build_android_deps.sh` offered a second vcpkg acquisition model; `flutter/build_fdroid.sh` fetched and
  built four Android ABIs; the iOS pair plus generic iOS builder emitted Apple artifacts; and the armv7/x86/x86_64
  NDK helpers compiled unshipped Android targets. None had a live caller in the fork's release scripts. Commit
  `e323e09` had already marked the F-Droid, iOS arm64, and Android armv7 scripts for deletion with target pruning,
  but the imported executable files remained.

  The actual authority was already singular: `scripts/online-fetch.sh` authenticates and stages the complete pinned
  Android closure, including classic-mode `arm64-android` vcpkg natives; `scripts/build-android.sh` starts the
  networkless nonroot build/signing containers; `scripts/android-apk-build.sh` invokes exactly
  `flutter/ndk_arm64.sh` and one `flutter build apk --target-platform android-arm64 --split-per-abi`; and only the
  exact arm64 helper is consumed from the Flutter directory. The upstream full matrix exists only at the
  non-workflow `.github/workflows/flutter-build.yml.disabled` path. Its marker now makes that historical role
  explicit, its top-level trigger/job keys are schema-demoted to `historical_on`/`historical_jobs`, and its
  references to deleted helpers intentionally remain dangling. Renaming the file alone therefore cannot activate
  the reference, let alone silently revive an alternate build. Apple compilation remains source-conformance-only
  through the separate checker required by R-R2.

  All ten obsolete scripts are deleted. R-R2c makes the exact negative inventory, sole top-level Flutter shell,
  arm64 command chain, cache-staging authority, and inert-workflow boundary normative. The shared verifier rejects
  every deleted path including dangling symlinks, rejects any second top-level Flutter shell, checks the retained
  helper's regular executable type, and runs `scripts/verify-mobile-build-authority.py --self-test`. The focused
  semantic validator independently checks the exact helper bytes, one caller, one arm64 split-APK command,
  networkless/nonroot outer harness, arm64-only native staging, absent enabled workflow, schema-demoted inert
  reference, requirement, Appendix C #194, and this ledger, with a deliberate mutation for every deleted path and
  each positive authority edge. This closes conflicting source/build authority and future-reactivation debt; it is
  not evidence that any obsolete script ran, the host was mutated, a listener existed, a non-arm64 artifact shipped,
  privilege escalation occurred, or a system was compromised. A clean cold exact-commit Android double build,
  signed-APK verification on the release artifact, and device behavior remain owned by R-B2/R-B10 and are not
  inferred from this source closure.

  Focused verification used the already-present immutable Apple/Rust/Python image
  `sha256:612145fabd0c603417ab5e689e84d5b5a619f4edf31efceb3ecbe2813da2199c` as numeric UID/GID
  1000:1000 with networking disabled, a read-only root/source mount, all capabilities dropped,
  no-new-privileges, bounded CPU/memory/PIDs, no published ports, no Docker socket, and disposable tmpfs. The mobile
  validator passed its baseline and rejected all 32 deliberate mutations. The complete workspace source-mutation
  matrix, the 103-case dependency-inventory self-test and current inventory, the 63-case main-verifier authority
  suite, native-codec/hash normal and mutation gates, Python parsing, edited-shell Bash parsing, and diff hygiene
  passed. The inventory check also found and corrected a pre-existing stale post-R-X12a expectation: deleting the
  two orphaned Wayland Rust modules had reduced the tracked Rust source count from 249 to 247 and changed its
  per-file identity digest, while the measured 855 lexical unsafe blocks/74 matching files remained unchanged.
  No project build, APK build/sign, Android/device execution, full `scripts/verify.sh`, whole Apple checker, or R-B2
  release was run for this source-only slice. The complete verifier still lacks its exact pinned dev-check image,
  and the whole Apple checker would build images in preflight; neither boundary was bypassed or represented green.
- **R-R2d — retained GitHub Actions references made schema-inert — SOURCE CLOSED/GATED 2026-07-21; EXACT
  CURRENT-COMMIT ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Commit `16252a9` disabled GitHub-hosted CI/CD by
  suffix-renaming seven upstream definitions under `.github/workflows/` to `*.disabled`. Current history and
  source inspection found that only the later `flutter-build` reference had also lost executable workflow schema.
  The other six still carried top-level `on` and `jobs`: `ci`, `flutter-ci`, `flutter-tag`, and `wf-cliprdr-ci`
  retained manual plus push/PR/tag triggers, while `bridge` and `third-party-RustDeskTempTopMostWindow` retained
  reusable `workflow_call` entry. Their historical bodies include package installation, build/test execution,
  artifact upload, and a tag caller that inherits secrets into the release matrix. GitHub did not recognize these
  non-`.yml`/`.yaml` files in their current names, so this was accidental rename/copy reactivation authority and
  misleading re-enable documentation, not evidence that any job ran, a secret was disclosed, an artifact shipped,
  the host was modified, a listener existed, privilege escalation occurred, or a system was compromised.

  All seven retained references now carry exactly one schema-demoted `historical_on` and `historical_jobs`, no
  top-level `on` or `jobs`, and an explicit inert/rename-resistant marker. Historical bodies remain available for
  review, but renaming any one file cannot create a trigger, callable workflow, or executable job graph. The exact
  directory inventory remains zero enabled definitions, seven regular disabled references, and `DISABLED.md`;
  symlinks, extra entries, missing references, active extensions, and wrong types fail closed. The documentation no
  longer presents rename as an enable ceremony: restoring both schema keys and reviewing reusable dependencies is
  an explicit R-R2/R-R2d release-authority change. Local repository scripts remain the only build, verification,
  and release transaction authority.

  `scripts/verify-github-automation-authority.py` checks that complete inventory and every file's regular type,
  marker, top-level-key absence, and demoted-key cardinality, then binds R-R2d, Appendix C #195, documentation, the
  shared verifier, and this ledger. Its self-test applies separate trigger and jobs reactivation mutations to every
  retained reference, quoted/space-delimited YAML key variants, and inventory, enabled-definition, documentation,
  requirement, disposition, ledger, and gate mutations. The independent workspace verifier statically binds the
  focused validator's rejection semantics and wiring and mutation-tests the validator, documentation, normative
  records, and shared invocation. This is a
  source-authority closure only; cold exact-commit artifacts and release execution remain R-B2/R-B10.

  Focused verification used the already-present immutable Apple/Rust/Python image
  `sha256:612145fabd0c603417ab5e689e84d5b5a619f4edf31efceb3ecbe2813da2199c` as numeric UID/GID
  1000:1000 with networking disabled, a read-only root/source mount, all capabilities dropped,
  no-new-privileges, bounded CPU/memory/PIDs, no published ports, no Docker socket, and disposable tmpfs. The
  focused validator passed its baseline and rejected all 23 deliberate mutations, including alternate YAML key
  spellings; the exact extracted shared-verifier block passed. The existing 32-mutation mobile authority gate,
  complete independent workspace source-mutation sweep, 103-case dependency inventory/current inventory,
  63-mutation main-verifier authority suite, native-codec/hash normal and self-test gates, in-memory Python parsing,
  edited-shell Bash parsing, and diff hygiene passed. The broader workspace behavioral self-test reached its
  intentional live-systemd-user-bus prerequisite inside the isolated container; the host bus was not mounted, and
  that incomplete run is not represented as a pass. Verification and publication evidence for this loop are
  recorded in `/tmp/privilege_securiry_deep_audit.md`. No project build, artifact build/signing, Android/device
  execution, full `scripts/verify.sh`, whole Apple checker, or R-B2 release is claimed by this source-only change.
- **R-R1a — obsolete Dependabot submodule updater deleted — SOURCE CLOSED/GATED 2026-07-21; REPOSITORY-SETTING
  STATE REMAINS SEPARATE EXTERNAL EVIDENCE.** Commit `16252a9` suffix-renamed the imported
  `.github/dependabot.yml` while disabling GitHub-hosted CI/CD. Unlike the seven workflow bodies retained for build
  provenance, this file configured only the supported `gitsubmodule` ecosystem: daily version checks and update
  pull requests targeting `master`. R-R1 had already absorbed the sole `hbb_common` submodule in-tree; current
  source and index inspection found no `.gitmodules` and no gitlink. GitHub ignored the `.disabled` filename, so
  no version-update configuration was active and there was no current dependency for it to update. This was
  obsolete supply-chain automation plus rename/copy reactivation debt, not evidence that Dependabot ran, changed a
  pin, opened or merged a pull request, executed a workflow, modified the host, exposed a listener, crossed a
  privilege boundary, or compromised a system.

  The obsolete file is deleted rather than schema-wrapped. R-R1a makes the recognized `.github/dependabot.yml` and
  `.yaml` names plus both suffix-hidden variants source-forbidden. Dependency changes remain deliberate reviewed
  transactions that update the applicable lockfile/manifest, authenticated acquisition pins, provenance, advisory
  policy, and reproducibility evidence together. `DISABLED.md` no longer claims that a Dependabot reference is
  retained and distinguishes source configuration from GitHub's repository-level vulnerability-alert and security-
  update settings. A read-only live API check during this audit reported Dependabot security updates
  `enabled=false, paused=false` and vulnerability alerts disabled; that observation is time-bound external evidence,
  not a source invariant. The repository Actions setting remained enabled while the R-R2d source inventory had zero
  recognized workflow definitions; no repository setting was changed in this source slice.

  The R-R2d checker is renamed to `scripts/verify-github-automation-authority.py` because its authority contract now
  covers both workflow execution and dependency-rewrite automation. It rejects all four Dependabot path spellings,
  a restored `.gitmodules`, the retired narrow-verifier path, enabled/extra/nonregular workflows, every active or
  alternate trigger/job spelling, and normative/gate drift. Its full self-test applies 32 deliberate mutations.
  The shared verifier and independent workspace meta-gate bind the generalized name, absence semantics, R-R1a,
  Appendix C #196, the existing R-R2d contract, documentation, and both hardening ledgers. This closes tracked
  source automation only; it does not claim external settings immutability, current dependency-advisory evidence,
  or exact artifact/release proof.
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
  legacy `key_pair` is now device-id metadata plus decrypt-only migration fallback after the OS-key
  mobile at-rest wrapper source slice.

### Tier 3 — "live-looking dead" code ✅ DONE (deleted — it had lied to the next auditor)

- **[I-9] Post-key password re-prompt UI — CLOSED/GATED 2026-07-18.** The live pre-keying
  credential path is `connect-password-prompt`; the old post-key `enterPasswordDialog` /
  `wrongPasswordDialog` Flutter dialogs are absent, and Rust no longer emits `input-password`,
  `re-input-password`, or `input-2fa` msgboxes from the login-error path. `src/client.rs`
  routes password prompting to pre-keying establishment failures, while keyed login errors are
  non-credential errors. `scripts/verify.sh` gates the deleted Flutter dialog names and the
  absence of Rust msgbox senders for the retired prompt types. The remaining literal strings in
  generic Dart msgbox color/icon classification are inert display taxonomy, not an authentication
  sender or dialog construction path.

- **[I-10] Connection-manager `SwitchPermission` receiver — CLOSED/GATED 2026-07-18.** The CM
  receive loop in `src/ui_cm_interface.rs` contains no `Data::SwitchPermission` arm or stale
  "backend sends SwitchPermission back to CM" comment. `src/ipc.rs` contains no
  `SwitchPermission` data variant, and `src/server/connection.rs` has no runtime permission-widener
  handler. The desktop permission chips are read-only status indicators. `scripts/verify.sh` now
  gates the CM receiver/IPC variant absence in addition to the existing connection-side
  `ipc::Data::SwitchPermission` widener gate.

- **[I-11] Trusted-devices/2FA pipe — CLOSED/GATED 2026-07-18.** `LoginResponse` no longer carries
  the old trusted-devices bit; tag 3 is reserved in `libs/hbb_common/protos/message.proto`.
  `LoginConfigHandler` has no trusted-device field, the viewer has no 2FA login-response reader or
  `input-2fa` sender, the 2FA/trusted-device Dart widgets are gone, and the broader R-X7 gate keeps
  the responder 2FA machinery absent. `scripts/verify.sh` now also asserts the reserved proto tag and
  the absence of the retired constants/widgets/senders.

- **[I-12] `IdPk` + `decode_id_pk` rendezvous crypto — CLOSED/GATED 2026-07-18.** The direct-IP fork
  has no rendezvous id→public-key binding message: `libs/hbb_common/protos/message.proto` contains no
  `message IdPk`, and `src/common.rs` contains no `decode_id_pk` helper. `scripts/verify.sh` gates
  both source absences so the dead rendezvous crypto cannot silently return.

### Tier 4 — inert dead scaffolding (itemized dispositions; no blanket completion claim)

Safe at runtime, but each is R-G1 debt a from-scratch direct-IP fork would never contain:

- **Rendezvous peer-presence/status cluster — CLOSED/GATED (R-SV6c):** the latency map, generic IPC/
  FFI status payload, peer query/backend/runner, Dart state/callback/sort/dot/visibility/polling pipeline, and
  compatibility names are absent. The separately retained typed main-status synchronizer is native-desktop-only;
  the local status widget is explicitly direct-listener reachability and is gated to the real listener-bound fact.
  Exact artifact evidence remains R-B2/R-B10.
- **Public/custom-server predicate — CLOSED/GATED (R-SV6d):** `using_public_server`, its Rust FFI,
  generated/authored/web/JavaScript spellings, and both caller dependencies are absent. Direct pre-login custom
  quality/FPS has no public/relay cap; custom-quality presentation is peer-version-only; and the saved-peer
  rendezvous-presence cadence loop is absent. Exact artifact evidence remains R-B2/R-B10.
- **Viewer `direct`/relay residue — CLOSED/GATED 2026-07-20 (R-SV4a):** the keyed connection
  constructor returns only its stream and fixed `TCP` label; login state and interfaces carry no
  direct/relay discriminator; custom quality/FPS is unconditionally direct before login; FPS control
  has one direct policy; first-message retry is named for receiver evidence; and session add/reconnect,
  FRB, authored Dart, and the web bridge carry no relay-choice parameter. Focused Rust regressions and
  Rust/Dart source gates bind the behavior and API absence. Exact artifact evidence remains R-B2/R-B10.
- **Dead FFI exports — CLOSED/GATED:** `main_test_if_valid_server`, `main_get_proxy_status`,
  `main_handle_relay_id`, and `main_resolve_avatar_url` were already absent on re-audit; R-SV6a additionally deletes
  the account deployment FFI and generated/authored bridge surface.
- **Dead Rust backends named by this row — CLOSED/GATED:** the structured proxy store, alternate proxy/TLS connector,
  proxy-only validator, and their package records are deleted by R-S11b-3j. R-SV6a deletes the account
  API/audit/avatar builder cluster. The numeric-ID change backend/export and IPC rendezvous-server query are absent on
  current-source re-audit; R-SV6b additionally deletes the independently surviving Config resolver, cross-server
  client grammar, and persisted rendezvous/NAT/serial state. The separately listed Dart constants and address-display
  formatting are not covered by this Rust-backend closure.
- **Dead Dart policy-option aliases — CLOSED/GATED (R-G1):** `kOptionHideServerSetting`,
  `kOptionHideProxySetting`, `kOptionDisableChangeId`, and `kOptionAllowDeepLinkServerSettings` were
  deleted from `flutter/lib/consts.dart` by `d5aec5b`; no authored Dart file retains those names or
  the corresponding `hide-server-settings`, `hide-proxy-settings`, `disable-change-id`, or
  `allow-deep-link-server-settings` string vocabulary. The native built-in-key inventory is a
  separate stale-value/config-input boundary and is not represented as a Flutter control. The shared,
  Dart, and Apple source gates reject both the retired aliases and raw Dart string replacements; the
  independent verifier binds those gates and deliberately regrows an alias to prove rejection.
- **The attended-accept IPC pipeline (8 sites, A1–A8) — CLOSED/GATED 2026-07-18:** because
  `approve-mode` is pinned to `"password"` (`config.rs` `PINNED_SETTINGS`), every connection is
  authorized before the CM sees it. `buildUnAuthorized`, `showLoginDialog`, `cmLoginRes`, the CM
  `authorize()` accept path, and the `Data::Authorize` IPC variant are absent; `scripts/verify.sh`
  gates the deleted UI/IPC senders and enum variant. The generic local function name
  `authorize()` in unrelated IPC helpers is not this CM accept authority.
- **The runtime permission-widener IPC pipeline (5 sites, B1–B5) — CLOSED/GATED 2026-07-18:** the
  CM permission chips are read-only and the runtime widener surface is deleted. `src/ipc.rs` has no
  `Data::SwitchPermission` variant, `src/ui_cm_interface.rs` has no receiver arm, and
  `src/server/connection.rs` has no handler that can reassign connection capabilities mid-session;
  `scripts/verify.sh` gates those absences.
- **Numeric-ID query CLI — CLOSED/GATED 2026-07-20 (R-SV5a):** `--get-id` no longer has a desktop handler and
  cannot select the installed-root Unix `UserMainIpcScope`; focused/source/mutation gates bind both absences.
  Internal side-effect-free stored-ID reads remain separately audited compatibility metadata, not a supported CLI
  identity capability. Exact packaged-artifact evidence remains R-B2.
- **Numeric-ID address formatter/controller — CLOSED/GATED (R-G2/R-SV5):** the obsolete
  `id_formatter.dart`, `formatID`, `trimID`, `IDTextEditingController`, and the desktop/mobile
  numeric-only autocomplete normalization are deleted. The replacement `direct_address.dart` API
  trims only surrounding whitespace, preserves malformed interior whitespace for fail-closed
  validation, and names its controller/accessor for the direct-address authority. The shared
  `connect()` choke point normalizes once and validates the same exact target; peer cards,
  autocomplete, and delete confirmation render the persisted address verbatim instead of
  space-grouping numeric-looking values. The already-deleted `server_model.dart` `_serverId`/
  `fetchID` machinery leaves no stale formatter import. Focused Flutter tests cover normalization,
  malformed interior whitespace, controller semantics, bare-ID rejection, and the valid address
  forms; shared, Dart, Apple, semantic, and deliberate-mutation gates bind the source closure.
- **Serialized-but-unread presentation fields — CLOSED/GATED (R-G9):** `sameServer`/`same_server` and the
  CM-only copies of `recording`/`block_input`/`restart` are deleted after exact producer/consumer history and source
  proof; the real connection capability fields and viewer permission protocol remain. `forceAlwaysRelay` was
  already deleted and gated by R-G6 and was stale in this row.
- **Miscellaneous named residue — CLOSED/GATED:** `logOut(apiServer)` is closed by R-SV6a-1 after history proved
  that its callers, network sink, stub, and containing account model were already deleted; the later API-server IPC
  presentation arm and the dead localization key are now deleted and gated as the actual surviving residue. The
  stale `switch_sides()` entry is closed by R-G4a after source/history proof expanded it to, and deleted, the complete
  residual role-swap state chain. This closes only this itemized Tier 4 row, not the independent release/artifact,
  device, advisory, Apple-toolchain, or external-audit residuals above.

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
dd7d7cff62ef3affa5352b9b9eda85f3a0046562516bcc25a1b68eb7e4628f3e  requirements.html
```

This hash binds the current normative requirements text, including R-B9, R-B13, R-S11n through R-S11ch, R-SV4a,
R-SV5a, R-SV6a, R-SV6b, R-SV6c, R-SV6d, R-G9, R-G4a, R-X12a, R-X9, R-R1a, R-R2c, R-R2d, R-T4, and Appendix C #192–#227. It is a source-ledger identity; exact-commit artifact evidence is carried separately
by the R-B2 manifest.
