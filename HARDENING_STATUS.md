# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Superseded work-log material (intermediate `PARTIAL`/`TODO`/deferred
notes, and — as of 2026-06-28 — the reverted native-worker-sandbox slices) is
removed from this live ledger because it is misleading as current status. Git
history remains the traceability record for that intermediate work.

The approximate 400,000-token size budget is measured reproducibly by
`scripts/hardening-status-size.sh` as `ceil(UTF-8 bytes / 3)`, alongside exact
byte and word counts. This intentionally conservative, tokenizer-independent
estimate is the project metric; `--check` fails while the ledger exceeds it.

Current normative specification identity:

```text
3804ef5e68e9887d14edfc73449f6018f7b6393f46c53a511dae4fbb9d141af3  requirements.html
```

## Current Verdict

**STOP-SHIP: the source topology is substantially hardened, but native and release evidence is incomplete.**
The authoritative work is the release-blocking matrix below and the global
[`Open residuals`](#open-residuals-tracked-not-regressions) table; source and confined checks do not prove
target-native, installed-service, performance, or later-tree behavior.

Source has one mandatory CPace-keyed direct TCP transport; rendezvous, relay, KCP, LAN discovery, and downgrade
paths are absent. Controlled-side policy is compile-time pinned, session
capabilities derive from `AuthConnType`, and privileged IPC is receiver-authorized rather than
whole-config or ambient same-UID authority. Connection, media,
presentation, file, and helper work has bounded exact-owner source lifetimes. These are source dispositions,
not a claim that every target OS has executed them.

| Retained evidence | What it establishes—and does not establish |
| --- | --- |
| Portable Linux server transaction (`250e775b9a88a62a980937e1f278ad053f2d9d58`) | Real nonroot parked/listening, CPace, Remote/FileTransfer admission, capacity/refusal, and joined-shutdown behavior in confinement. It is not an installed root service or current release artifact. |
| Exact-current Linux full-peer presentation (`76d8a32c2775f0d13c0c05a9fbc8d82939ad866e`) | Real password-prompt authentication, capture-to-X11-pixel delivery, a bounded focus-loss cycle, stable-connection recovery, and joined teardown on Linux software rendering. It is not Windows/Android/Apple, repeated reconnect/soak, or installed-service evidence. |
| Exact-current Linux filesystem regressions (`76cc2fefc6470aeaeb76b50d34b4dc377b39ba49`) | A zero-NIC VM and networkless guest-only container executed all 57 `hbb_common::fs` tests on pinned Rust 1.75, including retained-directory, symlink-parent, path-swap, bounded-depth, create, remove, and rename authority cases. This is Linux library behavior, not Windows junction/handle, installed peer, end-to-end transfer, or release-artifact evidence. |
| Exact clean Flutter model transaction (`5c2fbfc9f78c8953a945283ef3c0cbef7f981064`) | A zero-NIC VM and networkless guest-only container freshly generated the Rust/Dart bridges and passed all 12 focused suites and 103 tests on sealed Flutter 3.24.5, Rust 1.75.0, LLVM 15.0.6, FRB, Cargo-vendor, Pub-cache, and builder inputs. This is exact Dart/model and generated-bridge evidence, not native renderer, focus/background, device/service lifecycle, installed artifact, latency, soak, or cross-version evidence. |
| Named Windows native/installed transactions | The recorded native-suite/package pass, installed LocalSystem CM transaction, and SCM credential transaction establish only their exact commits and scenarios. No current full RustDesk peer, native focus/minimize recovery, cold A==B build, or sustained resource/latency result exists. |
| Named Android package transactions | Real JNI/APK assembly and stable-signature byte equality were demonstrated for the named older source parents. No current APK installation, Activity/foreground-service lifecycle, task swipe/reopen/Force Stop, real peer, presentation, or device result exists. |
| Apple and iOS checks | Source/portable checks only. No signed installed macOS or current iOS package/device result exists. |

Release still requires exact current artifacts and target-native execution: installed Linux across supported
supervisors/desktops; Windows full-peer focus/minimize/background/reconnect and installed negative-principal
coverage; legitimate signed macOS installation/helper/launchd behavior; Android/iOS package lifecycle and
presentation; complete CM/file finality; cross-version interoperability; monotonic capture-to-actual-present
latency and freshness; bounded CPU/memory/thread/handle/queue use; repeated replacement/reconnect/soak and
cleanup; cold R-B2/R-B10 equality; independent reproduction; and external review. Android's persistent service
is intentional: recovery must come from exact generation retirement, not killing it. The reported Android
persistent-process hang and Windows display-only focus delay therefore remain open until reproduced or falsified
with current native artifacts. Focused fast verification is the development default; broader verification is a
deliberate integration/release checkpoint.

## Documentation and verification architecture

`requirements.html` is the timeless normative specification. This file records only current implementation,
retained evidence, and open obligations. Git history and `/tmp/privilege_securiry_deep_audit.md` retain change
history, failed attempts, run identities, and detailed receipts; they are not copied into either live document.

A source/model check is supplementary unless it executes the behavior it claims to establish. Gates must not treat
exact requirement, ledger, README, comment, test-name, other-verifier, or historical-receipt wording as product
correctness. Retain small source invariants where they protect a real topology, and retain executable tests where
they distinguish required behavior from the dangerous behavior. Delete duplicate verifier-of-verifier catalogs,
self-loading mutation machinery, stale fixtures, and ceremonial tests that establish neither. Native, installed,
artifact, performance, resource, lifecycle, and reproducibility claims require the isolated runtime evidence named
by their requirements and the STOP-SHIP matrices below.

| Current documentation-sensitive item | Current disposition |
| --- | --- |
| Normative identity and ledger budget | The exact `requirements.html` identity is recorded above. `scripts/hardening-status-size.sh --check` is the reproducible approximately 400,000-token ledger limit; satisfying the size limit is not release completion. |
| Appendix C #185–206, #234–241, #259–260, #262, #264–268, #349–353, and #363–370 | The vulnerability findings and their timeless disposition-to-requirement mappings remain normative. Implementation, gate, historical-causation, and artifact-status narration is absent; current source and evidence limits remain in the named requirement sections of this ledger. |
| Dependency advisories (R-A7/R-R3) | Timeless freshness and fail-closed policy remains normative; machine-readable accepts remain in `deny.toml`. The exact current Dart/Pub and RustSec snapshots have real no-NIC VM verdicts recorded in R-S11df and R-S11dg below; future snapshot refresh, independent reproduction, cold release artifacts, and the other explicitly listed release gaps remain open. Documentation or mutation counts are not scanner evidence. |
| Windows selected-token environment (R-S11ay) | The retained source contract uses the selected token's environment, fail-closed construction, case-insensitive launcher-owned overlays, exact Unicode-block construction, and cleanup. Exact-artifact principal, collision, failure, child-observation, and cleanup execution remains open in the Windows matrix. |
| Android packaging and cache publication (R-S11fu/R-S11fv/R-S11fz/R-S11cq/R-S11cn/R-S11fy) | The source-side packaging, immutable-cache, extraction, replacement, and recovery contracts remain requirement-owned. All six current Android, Debian, and Windows-helper bootstrap/certified builder archives are locally present and pin-bound, but the complete canonical input closure, stable Android signing material, a current APK/AAB, installation, lifecycle, peer, presentation, and device evidence are absent or open. |

Completed documentation cleanup has no live progress log here. Requirement-specific current dispositions remain in
their dedicated ledger entries or the table above; the Current Verdict and open matrices are authoritative for
missing evidence.

Further cleanup must classify remaining prose and purported tests by the current requirement or real behavior they
protect, preserve load-bearing contracts and executable coverage, and delete obsolete history or make-believe proof.

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

**Resolved source topology — excision and direct-only presentation backlog.** The obsolete host-pin,
2FA/trusted-device, attended-accept, permission-widener, rendezvous-presence, relay-choice, account, numeric-ID,
proxy, and dead presentation surfaces are absent. R-S17 is retired: R-P1/R-P5 define password-only CPace with no
host identity, host proof, known-hosts store, fingerprint UI, or pin CLI. The compact current disposition is in
`## Closed excision and direct-only presentation backlog`; commits `5a371ae`, `d5aec5b`, `6e9086d`, and
`02320c1` retain the implementation history. Source closure does not satisfy the exact-current packaged/native,
cold R-B2/R-B10, independent-reproduction, or external-review obligations.

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

**R-S19 — `AuthConnType` capability confinement (CWE-863).**

**Source disposition: implemented; exact-current native/product evidence remains open.** After CPace
authentication, the connection's validated `AuthConnType`—not broad `self.authorized` state or an
independent permission Boolean—is the authority for every peer-triggerable capability. The server derives
capability state from that type before applying peer login options. Its dispatcher admits desktop input and
host mutation, including physical resolution changes, only for `Remote`; capture/display metadata and
per-video QoS feedback are admitted only for the appropriate `Remote` or `ViewCamera` source. Sink checks separately
confine clipboard text, audio and voice-call state,
cursor/window capture, whiteboard, Windows session behavior, and file clipboard. `FileTransfer` retains only
its connection-owned filesystem and file-clipboard authority. This is the required structural disposition
for CVE-2026-58056 and the broader R-S19 class; the §2 trusted-password-holder model does not remove this
defense-in-depth requirement.

Exact-owner adjuncts keep authority from crossing otherwise valid sessions: screenshot requests are keyed by
connection, capture source, and display; viewer clipboard application is limited to the default remote-control
session; Android MediaProjection demand comes from the typed Remote owner set; and Windows CLIPRDR forwarding
requires the confined file/clipboard authority. Voice-call accept, close, and teardown admit only an owning
`Remote`/`ViewCamera` connection with pending or active call state. On Linux, each FUSE file-content read uses
a fresh bounded `(connection_id, stream_id)` route and rejects wrong-connection, wrong-stream, stale, or
duplicate responses.

Focused source gates in `scripts/verify.sh` bind derivation-before-options, dispatcher and sink allowlists,
exact screenshot ownership, viewer/mobile confinement, voice-call ownership, and the Linux response router;
`libs/clipboard` tests exercise the route state machine and request/response behavior. Those checks establish
source/model disposition only. The global OPEN tables remain authoritative for exact-current native packages,
cross-platform peer behavior, focus/background freshness, latency, reconnect, concurrency, soak, resource
bounds, cleanup, cold artifacts, independent reproduction, and external review.

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
former standalone Android-free Kotlin transition model was compiled only in the dated checkpoint below and is
now deleted. Current shared checks inspect the production carry-through and policy topology without claiming
Kotlin behavior.
The persistent service is deliberately unchanged: Android documents that a started service has a lifecycle
independent of its creating Activity
(<https://developer.android.com/develop/background-work/services>), while MediaProjection separately requires
callback registration before `createVirtualDisplay()` and exact resource cleanup on `onStop()`
(<https://developer.android.com/reference/android/media/projection/MediaProjection.html>). The design
implication is persistent listener/service ownership plus exact per-connection capture demand—not killing the
service to recover incoherent state.

Prior exact-type follow-up verification (2026-07-23): the now-deleted Android-free Kotlin decoder/policy driver compiled with
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
delayed old Service cannot clear a replacement. The then-current standalone Kotlin driver covered unauthorized and non-Remote
exclusion, concurrent Remote aggregation, remove→add and add→remove convergence, same-ID type replacement, and full
clear. Then-current focused/shared/independent mutation gates inspected the serialized owner update, reconciliation, stale-stop
absence, teardown admission latch, exact JNI object release, R-S14, Appendix C #205, and this ledger. Exact
APK validation is recorded below; physical-device reproduction and the full R-B2/R-B10 release remain open.

The same service/listener generation now continues through every accepted Android `Connection`, its independent
connection-manager callback thread, and controlled input JNI call. Native dispatch holds the exact callback-context
read guard and refuses a zero, stopped, or replaced generation before entering Java, so an old connection's delayed
add/remove/voice/input event cannot mutate a replacement Service even if the server has restarted and eventually
reuses the same positive connection ID. `startServer(this, ...)` returns that exact generation only after JNI proves
the caller is the currently retained `MainService` object; an overlapping obsolete Service therefore cannot bind
its generation to a replacement callback owner. `stopServer(generation)` serializes with begin and rebuild,
deactivates only the active matching generation, and does not consume a generation ID, so delayed destruction of
an obsolete Service cannot stop the replacement listener.
Exact object identity, exact listener generation, and the service-owned connection-ID set are therefore one closed
lifecycle boundary rather than three independently timed best-effort facts.

Final confined verification (2026-07-23): the now-deleted Android-free Kotlin driver compiled with pinned Kotlin 2.1.21
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
spawn. Owner replacement and exact generation+UUID retirement hold the opposing write lock through UUID-scoped
table removal and bounded transfer to the process-owned exact drain coordinator; the replacement generation records
that completion ticket, and its off-UI mobile-add transaction waits and revalidates it before insertion under
R-S11eq. Thus neither a delayed obsolete Activity/task callback nor a check/use race can retire, insert, start, or
close the replacement owner's sessions, while Android's component thread no longer waits for native worker finality.
Starting a replacement generation proactively retires the superseded UUID; task removal consumes only owner pairs
recorded by stopped Activities. An invalid/missing/stale binding fails closed, while `MainService` remains
persistent and continues owning only incoming controlled-side service state.
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
through that worker slot, request close, join the old round, and only then admit replacement. R-S11eq subsequently
moved Activity/service lifecycle initiation of that exact drain off Android's component thread without weakening
this finality: the component removes and transfers ownership, while a retained native worker performs the join and
the replacement add waits its exact completion ticket. The I/O worker in turn owns its exact video/audio decoder
and voice-capture workers, closes their channels/signals, and transfers their exact handles to a bounded fixed
completion pool before awaiting them and marking the round disconnected. Explicit route close and test cleanup
retain their exact completion sinks. The incoming `MainService`, controlled listener, projection grant, and capture
resources are deliberately unchanged.
**Shared controlled-audio and hard-drop completion ownership — SOURCE IMPLEMENTED; CURRENT NATIVE
LIFECYCLE EVIDENCE OPEN.** `start_audio_thread()` returns the sole `OwnedMediaThread`, which owns mailbox admission
and the exact decoder worker. The controlled connection combines accepted format and decoder in one
`ControlledAudioThread`, refuses overlap, clears voice authority, and closes/awaits that exact owner on call close,
audio disable, format-start failure, and connection close. Graceful viewer and controlled teardown transfer joins
to the fixed bounded completion pool before awaiting; hard `Drop` closes admission and hands off without blocking.
Voice-input ownership is installed before the first suspension and disabled before release. Completion-capacity or
authority loss aborts rather than detaching. The stale source-slicing recognizer and its documentation-prose
oracles are deleted; compact checks retain only the owning constructor, combined lifetime, completion authority,
graceful sink, and forbidden detached-constructor boundaries. The focused Rust regressions are authored but have
not been rebuilt from current source in the presently incomplete offline closure. This shared source disposition
is not an Android device reproduction or a causation claim for the reported display-only symptom; exact
native/package lifecycle, resource, reconnect, and device evidence remains open.
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

**OPEN — cross-platform focus-loss display latency and end-to-end connection correctness/performance audit.**

**Observed behavior and evidence boundary.** An older Windows outgoing viewer was reported to develop up to roughly
ten seconds of display delay after losing focus while remote input remained responsive; reconnect cleared the delay.
An older Android outgoing viewer could similarly retain a bad screen-control state across task swipe/reopen until
Android Force Stop destroyed the persistent process, while file transfer still worked. The Windows viewer and Debian
controlled-side artifacts predate the long hardening loop, and no exact commit or artifact manifest has been identified.
These reports prove neither a current-`master` regression nor one cause. They show that control and display planes can
diverge and that wholesale state replacement masks the fault; they do not implicate Android's intentionally persistent
controlled-side `MainService`, prove exploitation, or establish any host/service/network modification.

**Exact-current Linux boundary evidence (2026-09-22; still failing).** The extended no-NIC full-peer transaction at
commit `6c48ddf` built the exact release core and 77-file Flutter 3.24.5 bundle, authenticated the real prompt, and
presented four current 640x480 source states with initial maximum age 250 ms. Its first two-second external-focus-loss
cycle stayed fresh (`maximum_gap_ms=253`, `maximum_age_ms=295`) and recovered under a real pointer event in 0 ms on the
same authenticated TCP connection. The second six-second cycle then failed at an actual X11 presentation gap of
1012 ms, after only four distinct states; reconnect and replacement phases were therefore not reached. Initial resource
sampling was 314752 KiB RSS, 47 threads, and 46 descriptors, but the early failure is not a resource-bound or soak pass.

Environment-gated native trace at that exact failure narrows, but does not close, the defect. Every fresh decoded RGBA
state through sequence 30 was accepted by the production Linux texture registrar (`marked=1`), and Flutter invoked the
plugin's `copy_pixels` callback for every sequence, normally 2--18 ms after submission. Sequence 30 was copied at
monotonic 788013584 us; X11 declared the stale-presentation failure at 788239 ms, about 225 ms later. Sampled source
bytes changed with the controlled palette. Thus this Linux failure is downstream of transport, decode, plugin
submission, and external-texture consumption: the remaining unobserved boundary is Flutter backing-store render,
GTK redraw/composition, and actual X11 presentation. The trace disproves a permanently lost texture-notification
hypothesis for this run; a texture callback is still not proof that the corresponding pixels were presented.

This boundary has a strong, Linux-specific upstream match. Flutter PR
<https://github.com/flutter/flutter/pull/192094> records that an engine OpenGL frame can be consumed from a different
presentation context before rendering completes; PR <https://github.com/flutter/flutter/pull/192098> replaced a
correct-but-blocking `glFinish` handoff with fences and a GTK-main-thread wait; and PR
<https://github.com/flutter/flutter/pull/192150> later removed an unreachable shared-frame path on modern X11 while
retaining separate Wayland synchronization. The current Flutter Linux tracking issue
<https://github.com/flutter/flutter/issues/191245> still distinguishes requested/delivered frames from compositor
presentation and says X11 and Wayland need separate strategies. This repository's pinned Flutter 3.24.5 engine
(`a18df97ca57a249df5d8d68cd0820600223ce262`) predates those September 2026 changes. That is a strong mechanism match,
not proof that a current Flutter upgrade is sufficient or safe, and not evidence that Windows or Android shares the
same native cause. The next Linux correction must bind an audited engine/toolchain choice to the exact remaining
handoff and rerun the full actual-pixel schedule; reconnect, relaxed freshness limits, or synchronization before the
engine renders the backing store are not valid substitutes. The failed evidence remains retained and this item stays
OPEN / STOP-SHIP.

The binding product requirement is broader than either report: the complete connection flow must be correct and
performant across every supported viewer and controlled platform. Focus, visibility, foreground/background, task,
display-topology, congestion, network, reconnect, replacement, and teardown transitions must preserve exact authority,
fresh presentation, bounded resources, and final ownership without requiring reconnect as a recovery mechanism.

### Current source disposition — not native closure

Normative behavior and detailed mechanics live in the named requirements and Appendix C rows; dedicated status entries
hold any still-useful implementation detail. The following is current source disposition, not evidence that a packaged
client presented timely pixels on a target OS.

| Requirement | Current source disposition |
| --- | --- |
| R-S11ev/R-S11e-183 | The split 120-frame store/eight-token decoder protocol is replaced by one directly consumable capacity-eight, generation/GOP-aware mailbox. A later audit found that its one-second freshness clock began only at mailbox admission, after receipt acknowledgement and other awaitable work; the network loop now captures the receive instant as soon as the keyed stream yields bytes and carries it unchanged through admission and completed decode. R-S11fn and R-S11fo close decoder-control and endpoint-loss continuation. These source corrections remain causal candidates, not artifact-specific causal proof. |
| R-S11eb/R-S11e-146, Appendix C #281 | Mobile Activity/isolate ownership is distinct from a fresh exact outgoing-connection UUID. Replacement drains prior mobile connections; route, event, frame, cursor, file, timer, input, and delayed cleanup work is exact-session guarded. The persistent Android controlled service is intentionally unchanged. |
| R-S11ec/R-S11e-147, Appendix C #282 | Outgoing clipboard lifetime is owned by exact network-round leases and one retained worker handle, independent of UI-registry presence; replacement waits for predecessor drain. |
| R-S11ed/R-S11e-148, Appendix C #283 | Delayed OS-password input is an exact-round owned async task using only the admitting round's sender; every replacement/exit aborts and awaits it before round completion. |
| R-S11ee/R-S11e-149, Appendix C #284 | Viewer screenshot bytes and monotonic request IDs are exact session/request owned; the process-global cache and stale-response selection are absent. |
| R-S11ef/R-S11e-150, Appendix C #285 | Controlled screenshot requests are exact connection/channel owned and bounded; one retained bounded encoder replaces detached per-response threads. |
| R-S11eg/R-S11e-151, Appendix C #286 | Controlled video completion is exact source/display/generation/connection state without a shared unbounded acknowledgement queue or per-wait runtime. R-S11fb owns bounded local egress and writer finality; R-S11fk owns authenticated peer progress. |
| R-S11eh/R-S11e-152, Appendix C #287 | Each exact real-time audio subscriber has a constant-size format/latest-frame/wake mailbox consumed by the connection writer; unbounded intermediate audio queues are absent. |
| R-S11ei/R-S11e-153, Appendix C #288 | Android controlled input carries exact service-generation/Remote-connection ownership through JNI, uses bounded retained drains, and retires exact work without killing the persistent service. This is the controlled-Android path, not the reported outgoing-viewer path. |

The later dedicated entries R-S11eu through R-S11fc, R-S11ff, R-S11fk through R-S11fp, and R-S11fr through
R-S11fs cover Android video-generation ownership, viewer and controlled video flow, Flutter software/native
presentation, resume/re-notification, exact peer receipts, shared capture pacing, decoder control/finality, and pointer-
evidenced recovery. Their source/model gates do not replace the native matrix below; R-S11fk and R-S11fl remain
explicitly PARTIAL / RELEASE-BLOCKING.

The Windows first-video path now avoids the decoder worker's former nested Tokio runtime, second OS thread, synchronous
join, and ignored IPC result. Remote and View Camera connections share a process-wide Tokio `OnceCell` initialization
from the existing async connection owner, concurrent with connection establishment, with one outer 50-ms main-IPC
deadline and visible fallback logging. The checked-in connection-type regression covers all six connection types.
Current native Windows IPC success/failure/concurrency, thread/handle, first-presented-frame, and focus/minimize evidence
remains open; this source debt is not claimed as the delay's cause.

The R-S11cr/R-S11e-110 archive-specific PID mutation authority is subsumed by the canonical R-S11cr Android SDK
acquisition/publication entry; corrected disposable acquisition, cold release, device evidence, independent
reproduction, and external review remain open.

### Release-blocking behavioral evidence

| Evidence | Required closure |
| --- | --- |
| Artifact identity and comparison | Identify the exact operational Windows/Android viewer and Debian controlled-side artifacts. Bind every old/current executable or package to its source, manifest, and digest, and hold the isolated environment constant for controlled A/B comparison. |
| Windows viewer / Debian controlled side | In disposable native Windows and Linux environments, run exact current artifacts through sustained focus loss/recovery, minimize/restore, occlusion, repeated transitions, display changes, congestion, reconnect, and teardown. Demonstrate timely display recovery without reconnect while input remains responsive. Include the relevant old/current and supported cross-version combinations. |
| Android | Install the exact current APK in a disposable emulator and, where platform behavior requires it, a physical device. Exercise outgoing viewing across background, task swipe, reopen, process persistence, network transition, reconnect, and Force Stop as a destructive baseline. Separately exercise controlled-side persistent-service generation/replacement and capture/input cleanup. The service must remain persistent by design; correctness must come from exact retirement, not service death. |
| End-to-end observability | Record monotonic timestamps and queue depths for capture, encode, enqueue/write, authenticated peer receipt, decode, publication, renderer/compositor commit, and actual presentation, alongside control-message latency. Define explicit freshness/latency and CPU/memory/thread/handle bounds before execution. Frame receipt or callback invocation alone is not presentation. |
| Stress and finality | Cover decoder/renderer stalls, simultaneous healthy and suspended viewers, backpressure, keyframe recovery, topology change, network interruption, stale/duplicate work, replacement, abrupt peer loss, error publication, repeated reconnect, and soak. Prove bounded queues/resources and complete process/worker cleanup. |
| Release evidence | Run the exact clean committed cold R-B2/R-B10 artifacts, repeat independently, and obtain external review. Preserve commands, topology, artifact identities, logs, timing, and cleanup proof. |

Confined compilation, deterministic state-machine tests, source assertions, semantic checks, and mutation rejection remain
useful supplementary evidence for exact invariants. They do not prove focus/background recovery, Android lifecycle
behavior, native renderer scheduling, actual presented-frame latency, installed-service behavior, cross-version
interoperability, performance budgets, or final release correctness. This mandate therefore remains OPEN.

**Verifier and fixture alignment follow-ups — CURRENT SOURCE DISPOSITION; NOT PRODUCT
RUNTIME EVIDENCE.** These entries correct stale or operationally invalid verifier assumptions after stronger
source/build transactions replaced earlier shapes. Normative behavior remains in the named requirements; the
table records only the durable current alignment. Per-run failures, mutation matrices, commands, counts,
timings, hashes, and confinement narration remain in Git history.

| Disposition | Durable correction |
| --- | --- |
| R-S11cu/R-S11e-113 retained-identity systemd image consumer authority | The systemd image consumer retains the nonzero host UID/GID selected through absolute `/usr/bin/id` before repository use and admits only the retained-owner 0400/0444 metadata profile before publisher SHA-512 and `qemu-img` checks. |
| R-S11cl/R-S11e-104 umask-independent Gradle SDK fixture authority | The synthetic SDK self-test uses and restores a private construction umask; the production SDK validator continues to reject group/world-writable input rather than normalizing it. |
| R-S11cv/R-S11e-114 umask-independent libvpx self-test source authority | The synthetic committed-source fixture is explicitly mode 0700 before nested creation; production source-root ownership and write-bit refusal are unchanged. |
| R-S11e-155 current same-user connection-manager launch-gate authority | The gate follows the unconditional Linux parent-death-bound CM launch, the macOS/Windows same-principal launch with exact proof environment, and transfer of the child into retained ownership. |
| R-S11e-156 recursive Windows Amyuni absence-scan authority | The complete `res/msi` absence scan is recursive and preserves the distinction between clean no-match and scanner operational failure. |
| R-S11e-157 Windows custom-action ignore-surface excision | The three inert `CustomActions` ignore rules left after deletion of the authored MSI custom-action project are absent; active package-output ignores remain. |
| R-S11e-158 current olefile fixed-archive gate authority | Olefile is checked as its exact closed fixed-archive manifest entry, including name, URL, size, digest, and admitted redirect host, rather than through the deleted standalone fetch call. |
| R-S11e-159 scoped Linux protected-service permit mutation authority | The focused negative fixture targets the exact password-sensitive transaction call, not an ambiguous argument fragment shared by another protected transaction. |
| R-S11e-160 current mobile at-rest and signed-artifact gate authority | The shared gate delegates legacy-decrypt policy to its semantic verifier and requires the exact signing/verify-only mobile-key checker mounts and invocations. |
| R-S11e-161 current Linux service-child executable-object gate authority | The gate inspects the dedicated executable-object helper: the running image and byte-identical installed fallback are opened close-on-exec, and the installed path is also no-follow, before credential-changing launch. |
| R-S11e-162 current outgoing screenshot and controlled-audio owner-gate authority | Screenshot checks reject only the retired process-global cache/setter path, while media checks select the exact owning constructor, controlled-audio owner, connection fields, and read-before-install order. |
| R-S11e-163 current R-S19 controlled screenshot and Android capture-type gate authority | The shared edge gate follows the bounded connection/channel-owned screenshot registry and the typed, authorized Remote-only Android desktop-capture owner set; the deleted `isViewCamera` Boolean is not authority. |
| R-S11e-164 exact software-codec build-path verifier scope | The build-path scan has no verifier-specific exemption; the deleted global source/mutation catalog no longer stores inert forbidden-token fixtures, and all build-capable scripts are scanned by default. |
| R-S11e-166 current shared Apple companion-gate authority | The shared gate binds the fixed selected Apple target matrix, rejects target overrides, and checks the exact reproducibility-epoch transfer plus two private read-only source mounts. |
| R-S11e-167 current shared Android serialization-gate authority | An exact adjacency predicate requires `@Synchronized` immediately before `rustSetByName`; the broken quiet-grep pipeline and broad annotation-presence surrogate are absent. |
| R-S11e-168 current Pub-cache lock-postcondition gate authority | Networked production and offline replay retain exact read-only project-lock preimages and require equality after enforced resolution, with Flutter tool lock protection remaining separate. |

This table is source/verifier disposition only. Except for the inert R-S11e-157 repository-policy deletion, these
corrections did not alter product, acquisition, build, package, runtime, service, device, or artifact behavior.
They do not prove current cold acquisition/build results, installed/native execution, Android or Apple behavior,
presentation/performance/resource properties, independent reproduction, or external review. Those obligations
remain OPEN in the release-blocking table and the named normative requirements.

**Android persistent-service generation and mobile-session preparation — CURRENT SOURCE DISPOSITION;
TARGET PACKAGE/DEVICE/RELEASE EVIDENCE OPEN.** Android intentionally keeps its controlled foreground
`MainService` and process-wide resources alive across ordinary task removal. Correctness therefore comes
from exact generation ownership and terminal retirement, not from killing the service. Force Stop remains a
destructive diagnostic baseline: it clears process state but is not the intended recovery mechanism. The
controlled-side service resources below are distinct from Android/iOS outgoing-viewer sessions; neither
domain may clear, replace, or infer authority from the other.

**R-S11ek/R-S11e-169 exact MainService-generation Android controlled voice/playback ownership —
SOURCE IMPLEMENTED; DEVICE EVIDENCE OPEN.** Controlled admission begins closed. The positive native
server generation returned for the exact retained `MainService` object is installed in the process-wide
audio coordinator before callbacks are admitted. The coordinator accepts only monotonic generations;
same-generation begin is idempotent, replacement retires only predecessor controlled voice/playback
state, and a retired or stale generation—including same-number connection-ID ABA—cannot mutate the
replacement. Every controlled register/update/remove/clear and playback-projection operation carries
that exact generation. Outgoing viewer voice remains a separate exact session/generation domain.
R-S11ek and Appendix C #290 own the complete contract.

**R-S11el/R-S11e-172 exact MainService-generation Android listener and worker ownership — SOURCE
IMPLEMENTED; DEVICE EVIDENCE OPEN.** `AndroidListenerOwner` serializes one explicit
`Inactive → Reserved → Starting → Active → StopRequested → Exited → Inactive` lifecycle with the
checked generation/rebuild epoch and the exact native worker `JoinHandle` plus cancellation token.
Activation is not released until the worker is registered; stop cancels only the matching worker;
replacement is refused until exit and convergence; and zero, stale, wrong-phase, or exhausted rebuilds
cannot alter replacement state. Kotlin publishes the exact positive generation cross-thread, JNI proves
the exact retained `MainService` object, and the listener observes only an active exact-generation epoch
snapshot. The three executable Rust state-machine tests cover stale replacement callbacks, registration
and convergence ordering, invalid/exhausted edges, and thread-start failure. These tests prove the pure
native owner model only—not JNI/Android lifecycle, socket cleanup, reconnect, or device behavior. Current
APK installation and network-change/Stop/task-swipe/Force-Stop/reopen/replacement/resource testing remain
open under the global matrix. R-S11el and Appendix C #293 own the product contract.

**R-S11em/R-S11e-174 exact MainService-generation Android raw-video ownership — SOURCE
IMPLEMENTED; DEVICE EVIDENCE OPEN.** One serialized monotonic owner binds the process-global raw-video
buffer to the exact retained service generation. Binding the JNI callback owner begins that same
generation before publication; exact-object replacement/release retires only its own generation.
Typed video enable/disable and every `ImageReader` frame callback carry the generation, while audio uses
a separate typed operation rather than the deleted ambient video/audio selector. Each service has its
own cross-thread-visible `captureActive`: start commits it only after non-null display creation and
checked raw admission; stop disables exact raw state before retiring local display/reader/surface/
playback objects. Stale local teardown may free its own Android objects but cannot clear replacement
raw-video state. The pure owner regressions and focused source gate are supplementary; current installed
APK capture/replacement/task-swipe/Force-Stop/reconnect/presentation and bounded-resource evidence remains
open. R-S11em owns the complete contract.

**R-S11en/R-S11e-175 exact MainService status and explicit-stop lifecycle ownership — SOURCE IMPLEMENTED;
TARGET/PACKAGE/DEVICE EVIDENCE OPEN.** One private serialized status owner publishes only the exact active
service generation and MediaProjection readiness. Current begin is idempotent, replacement resets
readiness, stale updates/retirement cannot affect a replacement, and Activity-visible status remains
observation rather than capture/listener/connection authority. Passive attachment to an existing
service binds with flags `0`; `BIND_AUTO_CREATE` is used only for explicit initialization when no status
is published. Dart Start/Stop requests have one bounded in-flight latch and never overwrite observed status;
current native snapshots and lifecycle publications alone change that observation, identical observations do
not rebuild, and MediaProjection status cannot re-enter Start. Explicit Stop contains the framework request and
always attempts Activity unbinding even if `Context.stopService` throws; absent, removed, and uncertain bindings
remain distinct, uncertain bookkeeping is retained for retry, and failure stays visible. The sole resource
teardown remains `MainService.onDestroy`. The duplicate callable `destroy()`/plain `stopSelf()` path,
generationless companion booleans, and dead clipboard capture-status replica are absent; the internal exact-
failed-start `stopSelfResult(startId)` path remains intentional. One historical confined run compiled and executed
the exact production status owner with the now-deleted standalone driver; no retained Kotlin unit or instrumentation
regression currently covers it. The focused Flutter regression is authored and wired but unexecuted here;
current `MainActivity`/Flutter target compilation and installed start/status/Stop/binding/task-swipe/reopen/
Force-Stop/replacement/failure/resource scenarios remain open in the global matrix. R-S11en owns the complete
contract.

**R-S11eo/R-S11e-176 mobile outgoing-session preparation finality and failure visibility — SOURCE
IMPLEMENTED; ANDROID/iOS PACKAGE AND DEVICE EVIDENCE OPEN.** Android and iOS mobile add use one typed
asynchronous bridge operation on the existing bounded worker pool; the required predecessor
`close_and_join` remains terminal and serialized off Flutter's UI isolate. Dart retains at most one
running start and one replaceable latest pending successor. Exact close cancels its pending request or
awaits its admitted preparation before native close, and a stale completion closes only its captured
UUID. Initial worker failure rolls back the exact handler/session and joins its worker; unexpected
stream error/end is exact-session-bound, retires that session, dismisses loading state, and produces a
bounded nonsecret error rather than a successful-looking UUID or indefinite `Connecting...` state.
R-S11eo owns the complete contract.

**Retained evidence and boundary.** Executable Rust/Dart listener-epoch, raw-frame, status/Stop,
bounded-start, exact-cancellation, rollback/join, and stream-finality tests exist, and historical
networkless nonroot Android Rust/Kotlin plus shared Dart/Flutter compilation exercised named corrected
source. The connection/capture driver and four additional standalone Kotlin owner `main()` programs were not
Gradle unit/instrumentation tests; the current gate never compiled or executed them, and they are deleted instead
of being grepped as behavioral evidence. The connection/capture and status-owner drivers retain their explicitly
bounded historical execution records only. Those prior
results were source/compile evidence only. Mutation counts, repeated catalog runs, cache
workarounds, failed wrapper attempts, per-run timings, log hashes, and publication narration remain in
Git history rather than the current ledger. An older disposable APK compile predates these corrections
and is not evidence for them.

Current target evidence remains release-blocking: build and bind the exact current Android APK and iOS
artifact to source; install them in disposable target environments; exercise service start, passive
attach, explicit Stop, task swipe, reopen, Force Stop, service replacement, connectivity changes,
projection replacement, stale callbacks, same-ID ABA, slow outgoing predecessor drain, route
replacement/close, stream failure, reconnect, and file-transfer/display coexistence; observe actual
capture/decode/presentation freshness plus CPU/memory/thread/handle/queue bounds and complete cleanup.
Cold R-B2/R-B10 artifacts, independent reproduction, and external review also remain open. These source
corrections are plausible defenses against persistent-process incoherence but are not a device-level
causal reproduction of the user's older outgoing screen-control hang, and they do not establish an
authorization bypass, exploitation, host modification, or public exposure.

### Supporting connection-flow source disposition

The 36 entries formerly below this point were implementation diaries, not 36 independent claims of native
closure. Git history through parent `03260cd22395d9f08e8b5a398d35db2914a46623` retains their source
discoveries, intermediate designs, failed wrappers, image and artifact hashes, mutation counts, and exact run
transcripts. The current tree retains the following source disposition. Except where explicitly marked
**PARTIAL / RELEASE-BLOCKING**, “source closed” means only that the named source topology and focused checks
exist; it does not upgrade those checks into target-native, package, latency, soak, or release evidence.

- **R-X6/R-S14 Android final APK manifest authority** — Source/build gate closed. The signed-APK path verifies
  the merged manifest, approved permissions and component inventory, explicit non-exported service/activity
  boundaries, `allowBackup=false`, and the single exported launcher/deep-link activity. A current APK build,
  install, and device run remain part of the open mobile/release matrix.
- **R-X6/R-S14 Android legacy JAR-signature META-INF authority** — Source/build gate closed. API 24 is the
  intentional support floor; v1 signing is disabled, v2/v3 are required, and `apksigner -Werr` plus final-
  manifest inspection precede artifact hashing. Android 5/6 compatibility is intentionally absent.
- **R-S15 — viewer PeerConfig write authority** — Source closed. Peer strings and service IDs are bounded;
  unsolicited privacy-mode status cannot persist policy; and peer platform/version metadata affects only
  runtime keyboard compatibility, never the operator-owned saved keyboard mode.
- **R-S9 permanent-password PRS read-state authority** — Source closed. CPace and listener readiness consume
  the typed `Available`, `Empty`, or `UndecryptableStorage` state directly; no stale password, preset, storage,
  or prior-runtime fallback converts an unavailable durable credential into authentication authority.
- **R-S11ep/R-S11e-177 macOS runtime PRS raw credential authority** — Source closed. The exact service-owned
  server obtains only the canonical PRS-or-empty value over raw `_service_credential`, after connected-peer
  code/launchd proof and under bounded owned work. No storage envelope, salt, serde/JSON value, or generic
  `_service` credential response crosses the boundary. Signed installed-macOS behavior remains open.
- **R-S11eq/R-S11e-178 Android component-thread outgoing-owner retirement** — Source closed. Activity/service
  callbacks advance exact owner authority and remove live admission without joining I/O on Android’s component
  thread; one bounded process-lifetime coordinator owns the transferred tree, and replacement admission waits
  for its exact drain ticket off-thread. APK/device lifecycle behavior remains open.
- **R-S11er/R-S11e-179 desktop lock-screen mechanism authority** — Source closed. Linux and macOS use their one
  connection-owned physical key chord; the external-helper and generic-fallback surfaces are absent. Windows uses
  the fallible native `LockWorkStation` request and treats success only as initiation. Installed Linux, Windows,
  and macOS outcome, refusal, reconnect, and cleanup evidence remains open.
- **R-S11es/R-S11e-180 Windows viewer keyboard interception authority** — Source topology closed. The sole
  view-focus route now carries the typed full window `SessionID` into an owner of the same type; the dead
  `Session::enter`/`Session::leave` narrow connection-ID route is deleted. The dormant Sciter low-level hook,
  HWND relay, process-global Win-key state, FFI, and Flutter calls remain absent. The focused source invariant
  protects this one-route shape; exact multi-window native Windows behavior and resource evidence remain open.
- **R-S11et/R-S11e-181 Windows ambient native diagnostic-file authority** — Source closed by deletion. The
  unsupported `flog` helper, fixed `C:\\Windows\\temp\\test_rustdesk.log` append path, and commented call have
  no replacement, alias, or alternate ambient sink; the live `CONOUT$` console redirect is distinct. One direct
  source guard remains. Exact candidate PE symbol/string and native file-access evidence remains open.
- **R-S11eu/R-S11e-182 exact-generation Android video-worker and screen-state ownership** — Source implemented;
  installed evidence open. Controlled workers, displays, capturers, raw-frame consumption, screen geometry/scale,
  and half-scale mutation carry the exact nonzero `MainService` generation. Each `ImageReader` callback also
  captures that generation and, under the service monitor, admits only its exact still-current reader; image
  acquisition, JNI copy, and image close finish before teardown can close the reader. The former mutable-generation
  callback and its silent exception sink are absent. Exact APK/device stop/replacement races and presentation remain
  in the mobile and product-behavior OPEN rows.
- **R-S11ev/R-S11e-183 directly reachable, bounded, receive-time-fresh outgoing-viewer video mailbox** — Source
  closed. One capacity-eight generation/GOP-aware mailbox makes every retained frame directly reachable. The
  network owner captures the monotonic receive instant before parsing, acknowledgement writes, UI work, worker
  construction, or later awaits; the mailbox API requires that instant and cannot relabel pre-admission delay as
  fresh. Pre- and post-decode checks enforce the one-second budget, and endpoint loss is terminal rather than a
  healthy empty queue. The executable Rust regressions remain; the source-wording/mutation verifier and its
  duplicate workspace validator are deleted because they missed this semantic mismatch and observed no runtime.
  Current compilation/execution is not claimed for this correction: the fixed rootless Docker socket was absent,
  and no host or rootful fallback was used. Target-native focus/background/presentation evidence remains open.
- **R-S11ew/R-S11e-184 exact, bounded, latest-wins Flutter software-RGBA publication** — Source implementation
  and five directly wired executable Rust regressions remain. Each `(session, display)` owns one immutable
  published frame plus at most one latest pending frame and exact event generation; stale consumers or
  acknowledgements cannot publish or retain another session's pixels. Offer results now distinguish a bounded
  pending replacement from publication-token exhaustion, so exhaustion before an initial publication retires
  the just-created exact mailbox instead of leaving an empty map entry. The exhaustion regression exercises the
  real multi-consumer owner facade, but current compilation/execution is not claimed because the fixed rootless
  Docker socket is absent and no host or rootful fallback was used. Generated-bridge and native presentation,
  lifecycle, performance, and artifact evidence remain open.
- **R-S11ex/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration** — Source closed.
  Native texture pointer creation, publication, replacement, view transfer, and retirement are tied to the exact
  asynchronous UI owner. Failed Rust-pointer unpublication retains native storage; failed native release remains
  one visible terminal predecessor and cannot admit a replacement. Linux now also retains its exact retired
  `GObject` and reserved renderer key when the fallible Flutter registrar rejects unregistration, rather than
  finalizing potentially callback-reachable storage. Only successful unregister—including the final retry during
  outer plugin teardown—releases it; continued refusal retains the storage until process teardown. The production-
  translation-unit regression covers refusal, terminal no-retry, retained storage, successful close, and teardown
  finality, but current execution is not claimed while the fixed rootless Docker socket is absent. Callback cleanup
  cannot use or retire a replacement owner.
- **R-S11ey/R-S11e-186 software-RGBA-only desktop presentation** — Source/build topology closed. The unsupported
  GPU/VRAM texture plugin and its registration/packaging path are absent; supported desktop presentation uses the
  repository-owned software-RGBA plugin. Native renderer and packaged-plugin execution remain open.
- **R-S11ez/R-S11e-187 pending desktop frame retirement finality** — Source closed. Retirement prevents queued or
  subsequent native frame publication before registrar teardown while preserving storage already owned by the
  registrar until unregister finality. Native ABI/engine and sanitizer evidence remains open.
- **R-S11fa/R-S11e-188 exact viewer presentation-resume recovery** — Source closed. Mobile resume, desktop
  focus/restore/maximize, and tab reselection coalesce recovery for the exact live UI/session owner before the
  exact refresh path. A failed visible refresh stays pending, and the exact peer/display-ready transition retries
  it without a timer or another lifecycle event; readiness alone creates no refresh. The callback registration is
  exact-session/generation retired, so delayed mobile-route cleanup cannot clear or invoke its replacement. The
  persistent Android controlled service is intentionally not killed as recovery. Current Android/Windows native
  focus/background/presentation evidence remains open under the release-blocking matrix.
- **R-S11fb/R-S11e-189 controlled-video bounded local egress** — Source closed for local egress ownership. Each
  controlled connection has constant-space GOP-aware video state and at most one transmitted frame awaiting the
  exact sole-writer/peer-receipt conjunction. Local writer completion is neither capture progress nor presentation.
- **R-S11fc/R-S11e-190 exact desktop first-image admission** — Source closed. The fallible native RGBA bridge and
  exact UI event must both accept the first frame before the session records its one-time image notification.
  The obsolete void frame-admission export is absent on Windows, Linux, and macOS; the package contract permits
  only the canonical result-bearing ABI. Callback acceptance is not proof that pixels reached the compositor or
  display.
- **R-S11fd/R-S11e-191 exact macOS launchd service-record authority** — Source closed. Textual launchd
  corroboration is admitted only after socket audit-token, installed-code generation, exact argv, and trusted
  root-owned LaunchAgent-plist proofs. One strict top-level canonical PID/path tuple must match those identities;
  ambiguity fails closed. One focused source checker and a shared isolated Rust gate over the executable parser
  regressions remain; the workspace verifier does not duplicate their source/test-name or documentation-wording
  assertions. Signed native macOS execution remains open under the release-blocking matrix.
- **R-S11fe/R-S11e-192 bounded macOS launchd proof-child resources** — Source closed. The fixed `launchctl print`
  child has null input, byte-bounded nonblocking output, an absolute deadline, exact process ownership, and joined
  termination on every outcome. The shared isolated Rust gate executes exact-output, overflow, and deadline behavior;
  one focused checker retains the production-call and no-fallback invariants, while the Apple and workspace checkers
  do not duplicate them. This remains portable child/source evidence, not signed macOS execution.
- **R-S11ff/R-S11e-193 exact viewer refresh admission** — Source closed. Refresh is bounded, coalesced, exact-
  round and exact-UI owned, invalidates the local decoder generation before the network request, and poisons the
  round on invalidation or send failure. The shared isolated Rust lane executes mailbox ordering/capacity/closure,
  wake, exact-owner/range, and pre-start retirement behavior; the generated-bridge lane executes exact-owner display
  derivation. No deleted standalone wording/mutation verifier is claimed as evidence. The protocol has no presentation
  acknowledgement; exact target-native lifecycle, peer, pixels, latency, resource, and cleanup evidence remains open.
- **Outgoing viewer generic command admission** — Source closed. Each viewer round owns a capacity- and byte-
  bounded command FIFO plus an out-of-band terminal state. Oversize, exhaustion, accounting failure, receiver
  loss, or writer rejection poisons the round instead of silently dropping ordered UI/file/control work.
- **R-S11fg/R-S11e-194 outgoing viewer file-command admission and exact local writer finality** — Source closed.
  Flutter file operations await fallible exact-round admission; file actions use their typed path; and one bounded
  receipt tracker owns the exact local encrypted-frame write. Peer operation completion remains a separate
  authenticated `FileResponse`, not a cosmetic acknowledgement.
- **R-S11fh/R-S11e-195 controlled-side file-response exact local writer finality** — Source closed. Directory,
  digest, block, done, and error responses from direct and CM paths retain bounded exact writer receipts through
  the controlled connection, with writer failure/timeout terminal for that round.
- **R-S11fi/R-S11e-196 receive-file failure and cleanup finality** — **SOURCE CORRECTED; EXACT-CURRENT EXECUTION
  OPEN.** A block, confirmation, finalization, peer error, skip, or cancellation retires exact current-file state
  through one fallible operation. Cleanup uncertainty is terminal and visible; an identity-mismatched replacement
  survives, and CM cancellation retains its exact generation until cleanup finality instead of manufacturing `Done`.
- **R-S11fj/R-S11e-197 viewer download digest inspection failure** — **SOURCE CORRECTED; EXACT-CURRENT EXECUTION
  OPEN.** Signed file identity is validated before lookup. Leased handle-based destination/resume inspection now
  distinguishes only true absence from explicit parse, authority, object-type, metadata, timestamp, and cleanup
  failure; mutation follows success, and failure remains bound to the exact terminal viewer/CM operation.
- **R-S11fk/R-S11e-198 controlled-video exact peer receipt** — **PARTIAL / RELEASE-BLOCKING.** Versioned video
  generations and authenticated peer parse receipts replace local-writer completion as capture progress; the
  viewer returns a receipt after frame validation and before decode/publication. Exact serialized-byte assertions
  pin the frame, receipt, and negotiation field numbers instead of trusting a same-schema round trip; focused Rust
  tests cover both completion orders, identity refusal, reconnect reset, capability selection, and generation
  monotonicity. A real kernel-TCP regression proves local acceptance can precede any peer read, but none of this is
  decode, render, presentation, focus/background recovery, or exact-current packaged-platform evidence.
- **R-S11fl/R-S11e-199 controlled-video shared capture pacing** — **PARTIAL / RELEASE-BLOCKING.** Per-generation
  target state permits the first valid exact peer receipt to advance shared capture without allowing local
  supersession to manufacture progress; one stalled viewer cannot impose the inherited all-viewer barrier. The
  focused Rust state regressions cover real blocked-wait wakeup, acknowledging-peer retirement, all-disconnected
  release, refresh interruption, retired-receipt refusal, and successor progress. The global source-name,
  documentation-wiring, and mutation duplicates are deleted while both focused Rust execution lanes remain. A
  historical portable Linux two-viewer run reached RGBA publication without reconnect while a second viewer
  withheld receipt, but it did not exercise Flutter/compositor presentation or current packaged artifacts.
- **R-S11fm/R-S11e-200 desktop texture activation finality** — Source closed. A display slot publishes a new
  current texture only after that exact candidate’s asynchronous native activation/pointer acquisition succeeds;
  failure retires the candidate without displacing the prior live texture.
- **R-S11fn/R-S11e-201 semantic, non-dropping viewer decoder-control finality** — Source closed. Reset and
  recording transitions use semantic mailbox state rather than a droppable generic counter; accepted control
  either reaches its exact decoder generation or terminates the round.
- **R-S11fo/R-S11e-202 exact viewer decoder-endpoint finality** — Source closed. Receiver loss closes the exact
  mailbox; frame, refresh, queue-depth, FPS, and backlog operations observe terminal endpoint loss and cannot keep
  the same network round alive as a healthy empty queue.
- **R-S11fp/R-S11e-203 exact desktop pending-texture re-notification** — Source closed. Exact focus/resume/tab
  recovery first re-arms an already-pending frame on the published texture, then requests fresh peer video;
  idle/pre-first-frame state remains valid and stale pointer/UI owners are refused.
- **R-S11fq/R-S11e-204 Linux service-child terminal authority** — Source closed. The privileged supervisor selects
  one fixed literal `TERM` from service-owned platform policy after `env_clear`; it does not enumerate user
  processes, ingest their environment, or parse an ambient-selected terminfo database. Installed-service execution
  remains open.
- **R-S11fr/R-S11e-205 exact software-RGBA presentation recovery and asynchronous commit order** — Source
  implementation, three directly wired executable Rust regressions, and six directly wired pure-Dart ordering
  regressions remain. Recovery rotates and redelivers the exact bounded software publication before native
  re-notification and peer refresh; only the newest still-current asynchronous Dart decode may replace the
  displayed `ui.Image`. Generated-bridge and native lifecycle/presentation/performance evidence remain open.
- **R-S11fs/R-S11e-206 pointer-evidenced desktop presentation recovery** — Source closed. A pointer event delivered
  to the exact Windows remote canvas always consults the same coalesced exact-owner presentation recovery used by a
  real focus event. A stale blur flag is still cleared, but recovery no longer depends on that second flag: a pending
  minimize suspension also survives a missed restore/focus callback. The recovery owner is a no-op when no exact
  suspension is pending, so ordinary pointer input cannot create refresh traffic or restore control alone while
  display remains suspended.
- **R-S11ft/R-S11e-207 Linux selected-session observation authority** — Source closed. Each stable service-loop
  iteration builds one bounded selected-user process snapshot with capped proc records and coherent selector
  fields; privileged X11/Wayland/Xwayland/D-Bus selection does not repeatedly reread attacker-mutable proc state.
  Exact installed-service desktop/performance evidence remains open.

### Evidence retained and release boundary

The narrow native/runtime facts still worth carrying are deliberately few. R-S11fk’s networkless container
regression used a real kernel TCP connection and demonstrated that a successful local writer receipt can precede
the peer’s first read; this justifies the distinct authenticated peer-receipt state but proves nothing about
presentation. R-S11fl’s historical 2026-08-11 portable Linux run exercised a real server plus two keyed viewers,
withheld one viewer’s exact receipt, and allowed the healthy viewer to recover at the RGBA callback without
reconnect; it was based on an unpushed candidate, stopped before Flutter/compositor presentation, and is not
current-master or release evidence. The later tracked R-S11gc full-peer Linux receipt is retained in its dedicated
entry and is the stronger presentation result. Historical Linux/Android compilation, deterministic behavior tests,
portable Windows callback-core tests, and macOS cfg/parser/child checks establish only the layers they actually ran.

Presentation evidence consists of executable Dart/Rust state-machine tests and isolated Windows/Linux native runners.
No standalone source-wording verifier is a gate or release artifact, and source/model results do not upgrade the
still-open native-artifact evidence above.

The release-blocking matrix above and the global OPEN table remain authoritative. Current Android APK/device
lifecycle, native Windows focus/minimize/background and full-peer presentation, signed installed macOS, installed
Debian service/session behavior, iOS, cross-version operation, peer semantic file completion, capture-to-actual-
presentation timestamps, latency and queue budgets, simultaneous control/file/audio/video stress, repeated
reconnect/replacement, soak and resource cleanup, cold R-B2/R-B10 artifacts, independent reproduction, and external
review are all still open. Source gates, compilation, callback receipt, and historical named runs do not close
those obligations.

## R-S11b/R-S11c/R-S11i — service-owned IPC authority

**Verdict: source topology implemented; native and release evidence remains incomplete.** The ordinary
desktop IPC protocol has no password request, whole-configuration transfer, generic privileged mutation,
or fallback into user storage. Installed Linux, Windows, and macOS service state is owned by the
root/LocalSystem/LaunchDaemon authority that enforces it. Local path, UID/session, and executable checks are
prerequisites only; each privileged receiver validates the exact typed action and its live authority.

This is a current-state ledger, not the implementation diary. Detailed intermediate failures, dated mutation
counts, per-run hashes, and superseded designs remain in Git history beginning with
`57bcb529e0fa7477bb8a5ed542e013dfbb7bb56f`. Normative behavior is in R-S11, R-S11a, R-S11b, R-S11c,
R-S11i, R-S16, R-S19, and Appendix C #25-#29 of `requirements.html`. The index below is retained for
requirement and verifier traceability; it does not upgrade source evidence into native behavior.

### Current authority and source closure

| Surface | Platforms, endpoint/action, boundary, and current closure |
| --- | --- |
| Unattended credential ownership | Linux/macOS raw `_password` and `_service_password`, Windows first-instance local-only password pipes, and the read-only runtime-PRS replica channels are typed and bounded. Peer proof precedes secret-body read. The root/LocalSystem/LaunchDaemon receiver performs OS authorization and the final durable commit; ordinary UI/main IPC cannot write or mirror the credential. Operation IDs, bounded values, process-keyed replay fingerprints, explicit final status, wiping, admission closure, and joined drain prevent generic config or detached-work fallbacks. |
| Machine policy and configuration | Main IPC carries one allowlisted nonsecret option at a time and returns the receiver-derived effective value. Whole Config/Config2 synchronization, GUI import, generic option maps, standalone salt readers, automatic password generation, preset credential compatibility, structured SOCKS/proxy state, and service-side ordinary option writes are absent. Salt reads are side-effect-free and service identity is not created by a read path. |
| Privileged service control | Generic `_service` is a closed directional liveness/control protocol. Windows session selection is removed; RDP sharing and SAS use distinct typed receiver-owned actions. Protected service channels have separate capacities, transaction ownership, shutdown admission latches, and result finality. Windows impersonation is disposable-thread confined and requires successful RevertToSelf before a result. |
| CM, file, clipboard, audio, whiteboard, and terminal helpers | Authority is connection/generation scoped rather than ambient same-UID trust. CM admission binds the exact launched helper generation and a connection nonce to AuthConnType. Login is published before AuthorizedFS, all filesystem sends recheck live file authority, ordinary CM publication is bounded and terminal-first, and pre-login or stale/wrong-generation work is rejected rather than buffered. Linux audio, whiteboard, Windows clipboard, and terminal helper paths use purpose-specific capabilities and exact process identity. |
| Service and child process lifetime | Linux supervisor/child selection, environment, working directory, descriptors, helper provenance, pidfd records, shutdown, and installed init templates are source-owned. Windows uses exact process/token/session identity, suspended creation where required, kill-on-close jobs, fixed installed paths, protected registry/file authorities, and capacity-independent SCM stop; once Windows accepts cancellation, the caller stops issuing cancellation requests and waits for the owned worker result. macOS service/client proof uses audit-token code identity, exact launchd records, retained child ownership, bounded proof workers, and root-owned fixed support/log/helper paths. |
| Packaging, loaders, and OS commands | Privileged helpers and libraries resolve from fixed verified roots; PATH/current-directory search, root shell interpolation, caller-selected registry paths, stale updater/IDD/runtime-cleanup compatibility paths, world-writable staging, and generated Docker helper residue are deleted or fail closed. macOS LaunchDaemon installation uses the fixed signed helper rather than root execution from the app bundle. |
| Credential-bearing files | Unix writes and corruption backups are owner-only and no-follow hardened. Windows config directories/files use a protected DACL limited to LocalSystem and the process user and fail closed on insecure existing files. This is filesystem hardening, not a claim that machine-UUID wrapping protects against a local reader. |
| Verification/build authority | R-S11dh's authenticated ordinary-user, zero-NIC VM and R-S11cj's distinct outbound-only acquisition VM are the sole execution authorities. Focused runs establish their isolation, guest-only Docker/BuildKit ownership, exact input admission, listener invariance, root/foreign refusal, bounded cleanup, and finality; source/model gates remain supplementary. Every Unix fresh-SDK path that invokes Flutter after an offline Flutter-tools resolve—Android, Debian, Dart/FRB, full-peer staging, the focused Flutter model transaction, and Pub-cache semantic replay—now uses one exact finalizer. It admits only the pinned Flutter version and lock digest, single-link inputs, current-principal Pub output, lock/package-config timestamp freshness, an exact mode-0644 version marker, and a bounded package configuration whose every file-URI root contains `pubspec.yaml`, covering both Flutter bootstrap freshness and Flutter 3.24.5's running `PubDependencies.isUpToDate()` predicate before claiming that implicit Pub is prevented. The exact clean transaction at `5c2fbfc9f78c8953a945283ef3c0cbef7f981064` freshly generated the bridges and passed all 12 focused suites and 103 tests in 326 seconds with VM and container networking absent, read-only Landlocked inputs, unchanged host listeners, joined guest-only Docker/QEMU/virtiofsd cleanup, and automatic run-root retirement. Windows-golden freshness correction/reprovisioning remains open. All six current Android, Debian, and Windows-helper bootstrap/certified builder archives and the current devcheck verifier archive are locally present and pin-bound, but they establish builder/verifier distribution and runtime identity only. The complete canonical offline-input closure, stable Android signing-key files, Windows golden/operator inputs, current product artifacts, installed/native lifecycle evidence, cold A==B reproduction, independent reproduction, and external review are absent or open. |

The six current Android, Debian, and Windows-helper bootstrap/certified builder archives are present under
`online/inputs/build-images`; the current devcheck verifier archive is present under
`online/inputs/verifier-images`. Their pin-bound acquisition, certification or reconstruction, and promotion
evidence remains in the bounded receipts and audit. They prove builder/verifier distribution and runtime identity
only. The complete canonical
`online/inputs` closure, `.harness-state/win11-golden.qcow2`, and
`.harness-state/android-keystore/{rustdesk-fork.jks,pass}` are not locally present. The required Android signing
certificate remains pinned to SHA-256 `1091322BA0425AFA1EB50DEEAE439A5FFFE2B1DD82C82B04515D9290A0CEEFA9`;
a new key is not a valid substitute. Consequently, an exact-current cold product/release build and its native or
installed lifecycle evidence cannot presently be completed from the retained local inputs. Restoring or reacquiring
those inputs must preserve R-B2 and R-B10's single complete canonical closure and must not introduce a partial-cache
fallback.

Pub-cache and Gradle replacement cleanup is now one recoverable, acquisition-identity-owned transaction. A
replacement refuses an existing root unless it is owned by the acquisition UID/GID and sealed mode 0500; the old
root is made writable only for the cross-parent directory move required by `renameat2(2)`, is immediately resealed,
and is revalidated by exact identity, content digest, and metadata digest. Recovery reseals and completes both the
pre-move and post-move crash states. The old output and transaction record leave no consumer-namespace sibling after
success, completed archives are exactly retired, and an interrupted archive is reclaimed on the next serialized
online-output transaction. Actual Pub and Gradle state machines passed as UID/GID 4000 in the no-NIC verifier VM;
this is output-publication/finality evidence only, not a complete canonical input closure, product build, package,
installed lifecycle, native presentation, cold R-B2/R-B10, or independent-reproduction result.

### Authoritative native/runtime evidence retained

- The R-S11b/R-B4 portable Linux transaction at clean pushed commit
  `250e775b9a88a62a980937e1f278ad053f2d9d58` built and executed the real server as numeric nonroot
  against sealed offline inputs. It proved parked/no-listener startup, container-loopback-only direct
  listening, correct/wrong CPace keying, authenticated Remote and FileTransfer admission, capacity and
  forged-frame refusal, and joined shutdown. It did not exercise an installed root service, a real display,
  a renderer, another native OS, soak, or release artifacts.
- The Windows transaction at clean pushed commit
  `f0ff7532721da0ccccf3ba186274db5ade8cdb8e` compiled the native authority-critical suites and completed
  one package build in a zero-interface VM with loopback-only VNC and listener/process cleanup. It is a
  single-pass named-commit result, not cold A==B release evidence or proof for later source changes.
- The installed LocalSystem CM transaction at clean pushed commit
  `032c2f622b324f92b183a1ae37fb13f65523ada0` passed package install, six authenticated CM directory
  round trips, generation reuse/replacement, abrupt owner cleanup, SCM stop, and SCM restart. It does not
  cover macOS CM behavior, concurrent race/soak, graphical remote control, focus/background latency, or
  current cold release artifacts.
- R-S11gj's installed SCM credential transaction is green at
  `0a12ed407e63129cac4065f4418911ab71adf3ca`: the installed CLI/LocalSystem service path exercised
  authorization refusal, credential mutation, live replica convergence, service restart, store reload, and
  stop finality for those package bytes. It remains a named single-build result, not current-master R-B2.
- The R-S11dh authority smoke executed its real nonroot-host KVM/QEMU, networkless Debian guest, guest-only
  Docker daemon, and confined numeric-nonroot container lifecycle. Its exact kernel/initramfs are independently
  derived from the authenticated base, digest-pinned, retained by descriptor, and direct-booted; the guest proves
  the exact kernel command line and runtime unit masks. Expanded twelve-entry passes complete in about 20–49 seconds and
  pass
  AppArmor/seccomp/resource/namespace, no-bridge/no-forward/no-firewall-mutation, private-channel,
  listener-invariance, complete-bounded-capture, joined-process, and successful-run residue-free cleanup assertions.
  Controlled cancellation joined the exact processes and left no listener while retaining only exact private
  diagnostics, which were then explicitly reconciled. It executed the minimal read-only repository subset needed
  for the real `verify.sh --self-test-workspace`, which drives the descriptor-owned private-tree fixtures,
  and `dart-verify.sh --self-test-vm-authority`,
  `frb-codegen.sh --self-test-vm-authority`, `smoke-server.sh --self-test-vm-authority`, and
  `dart-audit.sh --self-test-vm-authority`, `audit.sh --self-test-vm-authority`, the identity-access-free
  `gen-android-keystore.sh --self-test-vm-authority`, the source/signing/output-access-free
  `build-android.sh --self-test-vm-authority`, the private-fixture-only
  `build-debian.sh --self-test-vm-authority`, the source/online-access-free
  `android-rust-check.sh --self-test-vm-authority`, and the source/online-access-free two-profile
  `test-android-gradle-cache.sh --self-test-vm-authority`, and source/input-free
  `apple-conform-check.sh --self-test-vm-authority` entries. Each performs an actual fixed-client Docker request with
  client/daemon pre/post generation replay; the applicable entries reject root and a foreign principal, and the Dart
  verifier proves its nested FRB child. The retained Dart/FRB focused checker runs inside the guest; the Dart-advisory
  checker was reduced from a 958-line cross-subsystem mutation catalog to a compact no-fallback/launch-shape check;
  the Rust-advisory checker was similarly reduced from a 1,053-line cross-subsystem mutation catalog; the Android
  signing checker was reduced from 718 to 318 lines and its duplicate 362-line workspace meta-check was deleted; the Android
  builder checker was reduced from 2,196 to 376 lines and its duplicate 912-line workspace block was deleted; and the guest
  runs the separate 31-decision Dart and 20-decision Rust scanner-result behavioral tests. The Android image-distribution
  checker is now a compact Android-specific pin/Dockerfile/loader/certification/promotion invariant rather than a
  cross-document mutation catalog, and its duplicate workspace validator is absent. The Debian image-distribution checker
  is likewise a compact Debian-specific invariant rather than a cross-document mutation catalog; its reciprocal workspace
  validator is absent. The Debian compiler-authority checker was reduced from a 1,093-line cross-document mutation catalog
  to a focused launch/VM-funnel invariant, and its duplicate 292-line workspace verifier block is absent. The same admitted
  UID/GID-4000 guest executes the generic archive/OCI provenance self-test, including
  40 Android, nine certified-Debian, and 22 Windows role/archive/direct-normalization decisions. The default classic-store
  profile rejects use of a certified builder's OCI-index digest as Docker's runtime reference and accepts only the
  separately pinned config digest. The fixed online-acquisition VM instead authenticates Docker's containerd image store
  and uses the explicit publication-index runtime mode, which binds the separately pinned OCI-index digest that this store
  resolves after loading the same archive; that exception is restricted to certified builders and is not an ambient
  fallback. At exact clean commit `dce876543d80b6f5e71aa2dce4d09dfc83e1fa8e`, the 48-second authority smoke also
  executed the production Windows-helper runtime's `small` profile against the real guest daemon: root and UID/GID-4001
  were refused, UID/GID-4000 completed, seven hostile mount shapes were refused, resource/security/read-only/network
  properties were observed in the container, and exact cleanup joined without residue. The Android Gradle entry likewise
  executes both exact production profiles against a minimal probe,
  observes their resource/security/read-only/network properties, and proves the guest container inventory is unchanged;
  it does not execute Gradle. The Debian entry executes its exact production compiler envelope, including private source,
  hidden Git, read-only online, security, namespace, and resource controls, while truthfully leaving the compiler workload
  unexecuted. Complete authority runs finished in 28–71 seconds with host listeners unchanged. It did not execute RustDesk,
  the verifier image, FRB code generation, a Gradle or Rust build, a Debian compiler/toolchain workload, an OSV or RustSec scan, the certified
  Windows helper archive/kernel/KVM/Windows workloads, the complete source/input transaction, an artifact, or an
  output-publication transaction.
- The focused R-S11dh filesystem transaction at clean pushed commit
  `76cc2fefc6470aeaeb76b50d34b4dc377b39ba49` and tree
  `f6297534ce3cf8f4460df324d31abf4d031b304d` executed the exact archived source in a direct-booted
  Debian VM with `-nic none` and a fresh guest-only Docker daemon configured with no bridge, forwarding,
  firewall mutation, or container network. A read-only, no-device/no-setuid/no-exec virtiofs mount exposed
  the sealed Rust 1.75 archive, 2.3-GiB Cargo vendor closure
  `b1c746659a19393c8f38e5b36ab76f357d4f7089c53cf45ffca8a45ec7a4f1d6`, and certified Debian-builder
  archive through a nonroot Landlock-confined `virtiofsd`; TCP bind/connect were denied and every serving
  thread entered seccomp filtering after QEMU attached. The fresh daemon proved that the certified OCI index
  `sha256:48596720e13492e8a511b35ad88932f23f19dd9271b9eb3da3c12c016698dabb` recovers the runnable immutable
  config identity `sha256:304b251e77fafe03192e035cc22479e0909d688035fbd30b1ac685e878ae9646` rather than relying on a
  pre-existing build image. All 57 `fs::tests` passed under numeric UID/GID 1000, a read-only container root,
  no capabilities, no-new-privileges, `docker-default`, and bounded resources. The 137-second outer receipt
  proved unchanged host listeners and sealed inputs plus joined VM, container, Docker, capture, and virtiofs
  cleanup. Windows-only junction/exact-handle tests did not execute, and this result does not exercise an
  end-to-end peer file transfer or installed/release artifact.
- R-S11bg's current devcheck reconstruction uses the exact Rust 1.75 base digest, fixed signed Debian/security
  snapshots, a fixed source epoch, an exact installed-package manifest, a Dockerfile-only private context, and
  BuildKit provenance that binds the base, arguments, source bytes, and `default` then `none` RUN network modes.
  Repeated real builds exposed and then removed four nondeterministic generated artifacts: two machine-ID files,
  the ldconfig auxiliary cache, and the alternatives log. Acquisition receipt `run.wcNY41uIe8` then completed two
  no-cache builds with the same runnable manifest
  `sha256:286817b35058612e5ff25790d3c30bc77274b2337aef79df8d24bf8e4f6f2466` and config
  `sha256:5bf549eb60a88e1039a751ffb37de390b655895c20009db97fb48f54e09415fa`, verified both captures, and atomically
  published the second private candidate. Fresh promotion receipt `run.LjHqqPoRtu` verified the exact
  681,163,937-byte archive at SHA-256
  `7fdb435c7fd6323fef3e5b54d410c4c5df85ea6a3636aa836359a18deec0abd7`, promoted it without clobbering, loaded it
  into an empty guest containerd image store, and passed its networkless/nonroot runtime contract. Both receipts
  report `hostfwd=absent`, unchanged host listeners, guest-only Docker/BuildKit, and joined cleanup. This is one-VM
  two-build runtime reproducibility plus a separate fresh-VM load check, not a separately administered independent
  rebuild, a full verifier/product run, an artifact build, native behavior, or release evidence. A final 70-second
  no-NIC authority smoke on the completed worktree passed the affected image-provenance decisions and the real guest
  authority/runtime fixtures with unchanged host listeners and joined cleanup; its unexecuted product-workload
  entries remain only authority checks, not product evidence.
- No evidence above used host RustDesk, Haggai, a host firewall/network change, a published container port,
  a VM NIC, root/sudo on the host, or a non-loopback host listener.

### Open / STOP-SHIP evidence

| Platform or boundary | Evidence still required |
| --- | --- |
| CM/file finality (R-S11c-4c/4d) | Exact-current Rust 1.75 Linux regressions now execute all 57 `hbb_common::fs` tests, including the retained-authority create/rename/file/directory mutations and Unix symlink/path-swap/depth-bound cases. Earlier current-source regressions also execute receive commit, incomplete/stale terminal refusal, peer-error cleanup, resume refusal, job identity, duplicate confirmation, malformed compression, and overflow boundaries through the shared job and CM dispatcher. Windows junction/exact-handle regressions remain unexecuted. Still exercise complete read/write/digest/cancel/error operations after Login, bounded saturation, terminal-first disconnect, fixed-sidecar collision, abrupt owner loss, and reconnect on installed desktop targets and Android. The existing installed Windows result predates this strengthening. |
| Linux installed service | Execute the exact final Debian artifact under the supported systemd, SysV, OpenRC, runit, and manual supervisors across X11/Xwayland and the required desktop/login transitions. Include unauthorized local actors, restart/identity races, liveness, bounded CPU/memory/handles, and cleanup. Portable rootless smoke is not installed-service proof. |
| Windows | Repeat affected native suites from the eventual release commit, perform the cold two-pass build/equality transaction, and retain installed credential/CM negative-principal results. Exercise a real peer, native capture/decode/presentation, focus/minimize/background/reconnect, concurrency races, session changes, and resource/latency soak. |
| macOS | Compile, sign, install, and run the exact app/helper/LaunchDaemon/LaunchAgent artifacts on legitimate Apple hardware or an acceptable isolated Apple environment. Exercise audit-token identity, Authorization Services, helper replacement/refusal, launchd restart, abrupt parent/child exit, CM generation races, filesystem modes/ACLs, and cleanup. Source conformance is not native Apple evidence. |
| Android and iOS | Android has no root IPC boundary and its exported service/component source shape is contained, while iOS has no controlled-side root IPC surface. This does not prove mobile behavior: exact current packages must be installed and exercised for persistent-service/task-swipe/Force-Stop/reopen, reconnect, capture/decode/presentation, background/focus, stale generation refusal, and bounded resource cleanup. |
| Artifacts and reproducibility | Run the clean committed cold R-B2/R-B10 Debian/Android/Windows transaction from authenticated pinned inputs; require A==B and exact manifest binding. Reproduce independently and obtain external review. No named historical build closes this current-release obligation. |
| Full verification infrastructure | R-S11bg now has a pin-bound recoverable verifier image: two no-cache builds in one acquisition VM produced the same runnable manifest/config, and a separate fresh acquisition VM verified, promoted, loaded, and ran the final archive. A current confined full product/source gate and a fresh independent-environment rebuild remain required; this infrastructure result supplies no product or native evidence. |
| Build/test execution authority (R-S11dh) | **STOP-SHIP; FAST NO-NIC AUTHORITY SMOKES, THE EXACT-CURRENT LINUX FILESYSTEM SUITE, ONLINE ACQUISITION, CURRENT DART/RUST ADVISORY VERDICTS, AND THE CURRENT ANDROID, DEBIAN, AND WINDOWS-HELPER CERTIFICATION TRANSACTIONS ARE GREEN, BUT PRODUCT AND RELEASE WORKLOADS REMAIN OPEN.** R-S11dh admits only authenticated ordinary-user QEMU/direct-boot/guest-Docker authority and has no host-Docker fallback; focused entries refuse applicable root/foreign callers and execute bounded guest containers. The `76cc2fe` focused transaction executed 57 real Rust tests in 137 seconds and, in a fresh daemon, distinguished the certified OCI-index identity from Docker's runnable config identity before use. R-S11cj separately executes acquisition in ordinary-user QEMU with rootless exact virtiofs exports, TCP-only guest/container egress, no host forwarding, unchanged host listeners, and joined finality. `run.dODxMdeH1n` built and captured the real Android bootstrap; `run.wn6nrHxpyi` reviewed and no-clobber promoted it. Current `run.61vb0nCRcV` then completed exact networkless certification, normalization, guest-only load, and runtime verification in 99 seconds, and pin-bound `run.phE39wA0oN` repeated full candidate verification, no-clobber promotion, and final load/runtime verification in 38 seconds. Their receipts bind the exact source, guest-only Docker/BuildKit, no host forwarding, listener invariance, and joined cleanup. Current `run.52py3CWymM` executed the real Android Rust, Gradle/Kotlin, warm-APK, and Gradle-seed publication path at `a73040d`, while its outer verdict was invalidated solely by disappearance of a pre-existing listener; clean `run.hutLn5juYg` then passed exact seed reuse, unchanged listeners, and joined finality. Android signing and retained release artifacts, installation/device lifecycle, future advisory refreshes, Apple source work, full-peer presentation, Debian/Windows product workloads, cold artifacts, complete prepared verifier inputs, fresh independent reproduction, and external review remain open. A library test run, entry gates, and a builder runtime fingerprint are not product, artifact, scanner, native-platform, or full-release evidence. |
| Product-level behavior | Real capture-to-present latency, display freshness during focus/background transitions, cross-version interoperability, reconnect finality, sustained performance/soak, and process/resource cleanup remain open across applicable platforms. These are not inferred from compile, model, source-string, frame-receipt, or protocol-only evidence. |

**R-S11ap–R-S11as/R-S11e-56–59 desktop lifecycle ownership — SOURCE IMPLEMENTED; CURRENT INSTALLED
NATIVE EVIDENCE OPEN.** `src/server.rs`, `src/direct_service.rs`, and `src/ipc.rs` perform startup
invariant and signal setup before admission, create one fallible named native IPC worker, wait for all
required local-listener readiness before starting the public listener, observe cancellation/signal/public-
listener/IPC completion in one owner, and join the exact listener and IPC thread before the sole non-returning
desktop finalizer. Protected Linux/macOS service IPC instead drains and returns its outcome to its foreground
owner. The focused source invariant guards that topology and R-S11e-58 has a pure returned-outcome regression;
neither proves the installed setup/failure/stop/restart/drain/exit/resource scenarios required by the OPEN
matrix.

### Source closure and supersession index

Unless an item is called out in the OPEN table, its source path is implemented, deleted, or superseded by the
current design. The exact behavior and acceptance criteria live in `requirements.html`; this compact index
exists only to make the current source disposition discoverable.

- R-S11b/R-B4 exact-owner rootless controlled-runtime smoke
- R-S11b-1 — Linux/macOS generic `_service` boundary
- R-S11b-2a/R-S11c-1a — ordinary main IPC cannot mutate passwords
- R-S11b-2b/R-S11c-1b — user-owned raw password mutation
- R-S11b-2c/R-S11c-1d — Linux service-owned unattended password provisioning
- R-S11b-2d/R-S11c-1e — Windows service-owned unattended password authority
- R-S11b-2e/R-S11c-1f — macOS service-owned unattended password provisioning
- R-S11fd/R-S11e-191 — macOS launchd service-record authority
- R-S11fe/R-S11e-192 — macOS launchd proof-child resource ownership
- R-S11b-3a — service-marked server rejects ordinary options IPC
- R-S11b-3b/R-S11c-1c — whole-config main IPC and GUI import deleted
- R-S11b-3c — generic config/proxy IPC write shape deleted
- R-S11b-3d — Windows service-owned RDP session-sharing policy
- R-S11b-3e — service identity/salt reads are side-effect-free
- R-S11b-3f — desktop at-rest wrapper no longer creates service identity/key material
- R-S11b-3g — trust-anchor/proxy-shaped option writes are pinned empty
- R-S11b-3h — main IPC mutation policy has no permissive fallback
- R-S11b-3i — hardware-codec probe IPC write surface deleted
- R-S11b-3j — structured SOCKS/proxy transport and credential store deleted
- R-S11b-3k — obsolete whole-config and standalone-salt authority APIs excised
- R-S11b-3l/R-X7b — generic automatic-password generator excised
- R-S11b-3m — typed permanent-password PRS authority reaches CPace admission
- R-S11c-13 — service-owned process close has dedicated receiver authority
- R-S11c-14 — service-owned voice-call input IPC mutation gate
- R-S11b-4d — local credential-bearing store file hardening
- R-S11b-4e — ordinary main IPC credential mirror excised
- R-S11b-3n — ordinary main IPC option mutation is single-key and receiver-effective
- R-S11b-3o — production-dead whole-options config writer excised
- R-S11b-3p — production-dead effective and standalone salt readers excised
- R-S11b-3q — preset-password credential/status compatibility excised
- R-S11c-2a/R-S11c-3a — Windows session selection removed; SAS is a dedicated service capability
- R-S11c-4a/R-S11c-4b — `_cm` file authority bound to a server-validated connection
- R-S11c-4c — CM login publication precedes every file operation
- R-S11c-4d — bounded exact-owner CM command publication
- R-S11c-22 — Windows CM non-file clipboard authority
- R-S11c-23 — Windows Flutter runner Rust core DLL load provenance
- R-S11c-24 — Desktop Dart FFI Rust core library provenance
- R-S11c-25 — Windows terminal service principal authority
- R-S11c-26 — protected service IPC resource boundary
- R-S11c-5 — macOS privileged service packaging
- R-S11c-17 — macOS runtime filesystem ACL authority
- R-S11c-18 — macOS privileged installer ACL finality
- R-S11c-19 — macOS LaunchAgent live argv authority
- R-S11c-20 — Unix terminal shell executable provenance
- R-S11c-21 — macOS privileged service template identity input
- R-S11c-16 — Desktop service lifecycle completion authority
- R-S11c-10a — Linux root-context desktop discovery shell interpolation
- R-S11c-10b — Linux helper/tray process cleanup shell pipelines
- R-S11c-10c — Linux xrandr resolution discovery shell pipeline
- R-S11c-10d — Linux process-discovery `pgrep` shell probes
- R-S11c-10g — Linux SELinux status shell probes
- R-S11c-10h — Linux config-home correction shell probes
- R-S11c-10i — Linux service lifecycle `systemctl` command construction
- R-S11c-10j — Debian package lifecycle and systemd stop semantics
- R-S11c-7 — Linux `_pa` audio helper capability
- R-S11c-11 — Desktop `_cm` endpoint-selection identity
- R-S11gi/R-S11e-221 — macOS/Windows exact connection-manager process ownership
- R-S11gj/R-S11e-222 — exact installed Windows SCM credential authority
- R-S11c-8 — `_whiteboard` helper ambient same-UID trust
- R-S11c-12 — Windows terminal helper pipe binding
- R-S11d-1 — Windows Amyuni IDD helper launch provenance
- R-S11d-2 — Windows Amyuni IDD cleanup completion authority
- R-S11d-3 — Windows runtime process command provenance
- R-S11d-4 — Windows MSI runtime-generated executable cleanup completion authority
- R-S11d-8 — Windows RDP viewer credential handling and command provenance
- R-S11d-9 — Windows terminal default-shell command provenance
- R-S11d-10 — Windows portable RuntimeBroker cleanup command provenance
- R-S11d-11 — Windows unsupported 32-bit WMIC process-probe deletion
- R-S11d-12 — Windows privacy broker and user shortcut process provenance
- R-S11d-13 — Windows service and session-token process launch provenance
- R-S11d-14 — Windows service/session token source provenance
- R-S11d-37 — Windows service-owned server child executable provenance
- R-S11d-38 — Windows inactive RustDesk IDD loader excision
- R-S11d-39 — Windows obsolete updater authority excision
- R-S11d-25 — Windows Amyuni SetupAPI install reboot-required completion
- R-S11d-26 — Windows app-name identity contract
- R-S11d-27 — Windows custom-client configuration provenance
- R-S11d-29 — Windows service-adjacent path known-folder authority
- R-S11d-31 — Windows privacy broker served-session authority
- R-S11d-16 — Windows Installer service and administrator-owned SAS-policy authority
- R-S11b-2 — installed-service unattended password ownership.
- Appendix C #61 — Linux polkit action and package authority. Source XML and each real Debian
  archive are checked by `scripts/verify-debian-package-authority.py`; exact package inventory
  excludes application-supplied `.rules`. Installed authorization behavior remains OPEN above.
- R-S11e-1 — Linux pkcheck image, requester, and lifetime authority
- R-S11e-2 — macOS privileged-service endpoint identity
- R-S11e-3 — Linux privileged-helper executable provenance
- R-S11e-4 — macOS service proof ownership and bounded admission
- R-S11e-5 — Linux service credential receiver and replica authority
- R-S11e-6 — Linux service-password server endpoint authority
- R-S11e-7 — user-owned permanent-password receiver authentication
- R-S11e-8 — macOS service-owned password right normalization before authorization
- R-S11e-9 — macOS service audit-token peer code identity
- R-S11e-10 — macOS residual process launch provenance
- R-S11e-11 — Windows service-owned password receiver proof
- R-S11e-12 — macOS clipboard-file paste no-follow finalize
- R-S11e-13 — macOS clipboard-file paste placeholder temp authority
- R-S11e-14 — Linux root/headless FileTransfer owner authority
- R-S11e-15 — Linux pkcheck request-time peer identity binding
- R-S11e-16 — permanent-password provisioning ingress
- R-S11e-17 — typed connection-manager file response authority
- R-S11e-18 — Windows named-pipe impersonation restoration
- R-S11e-19 — Windows service-owned child tree supervision
- R-S11e-20 — Windows Installer sole machine-state authority
- R-S11e-21 — raw password transaction finality and service-owned SAS
- R-S19a — connection-owned controlled-input execution
- R-S11e-22 — Windows machine credential store and former local-authority/LPE class
- R-S11e-23 — Windows current-package registry authority
- R-S11e-24 — Windows privacy-display registry recovery authority
- R-S11e-25 — Linux service-owned config-root authority
- R-S11e-26 — Linux service-child environment authority
- R-S11e-27 — Linux service-owned working-directory authority
- R-S11e-28 — Linux service-owned inherited descriptor authority
- R-S11e-29 — Linux service-originated helper inherited descriptor authority
- R-S11e-30 — Linux service-owned pkcheck inherited descriptor authority
- R-S11e-31 — Linux same-executable child inherited descriptor authority
- R-S11e-32 — Linux external-helper descriptor allowlist authority
- R-S11e-33 — desktop fatal-signal default disposition
- R-S11e-34 — macOS child inherited descriptor authority
- R-S11e-35 — Windows dormant generic process-launch authority
- R-S11e-36 — Windows privacy-broker process and window authority
- R-S11e-37 — Windows residual process-state authority
- R-S11e-38 — cross-platform root-to-user helper launch authority
- R-S11e-39 — Linux service-owned pkcheck inherited environment authority
- R-S11e-40 — Linux loginctl session-query authority
- R-S11e-41 — Linux systemctl service-lifecycle authority
- R-S11e-42 — Linux selected X11 session display authority
- R-S11e-43 — Linux obsolete Xorg process authority
- R-S11e-44 — Linux headless connection-manager parent authority
- R-S11e-45 — Linux remaining current-image process-table lifecycle authority
- R-S11e-46 — Linux privileged service-to-tray boundary
- R-S11e-47 — macOS numeric service-principal authority
- R-S11e-48 — Linux numeric selected-session service-child authority
- R-S11e-49 — exact service-owned server process role
- R-S11e-50 — exact desktop service-supervisor process role
- R-S11e-51 — Windows SCM-owned service entry authority
- R-S11e-52 — macOS service-owned configuration/log root
- R-S11e-53 — authority-bearing IPC listener failure outcome
- R-S11e-54 — Linux protected service IPC lifecycle ownership
- R-S11e-55 — macOS LaunchDaemon protected IPC signal drain
- R-S11e-56 — desktop controlled-server signal/listener lifecycle ownership
- R-S11e-57 — non-returning graceful-shutdown finalizer ownership
- R-S11e-58 — protected Unix service IPC foreground lifecycle ownership
- R-S11e-59 — desktop local-IPC readiness and retained native-worker ownership
- R-S11e-60 — Linux protected-service admission owns active-session identity work
- R-S11e-61 — macOS privileged helper current-build binding
- R-S11e-62 — macOS variadic file-creation ABI
- R-S11e-63 — complete Windows production-listener DACL coverage
- R-S11e-64 — smoke container image, network, and dependency authority
- R-S11e-65 — Windows token-switched child environment finality
- R-S11e-66 — macOS administrator-script environment finality
- R-S11e-67 — Linux clipboard fusermount process-context finality
- R-S11bb/R-S11e-68 — IPC lifecycle-split checker coverage
- R-S11bc/R-S11e-69 — Dart/FRB verifier container authority
- R-S11bd/R-S11e-70 — one confined owner for Flutter-side Rust verification
- R-S11be/R-S11e-71 — Dart advisory result and scanner authority
- R-S11bf/R-S11e-72 — Rust advisory freshness, result finality, and scanner authority
- R-S11bg/R-S11e-73 — main verifier all-nonroot container and recoverable image authority
- R-SV4a — direct-only viewer transport and state finality
- R-SV5a — obsolete numeric-ID query command and user-main-IPC scope
- R-SV6a — account/control-plane compatibility surface deleted
- R-SV6a-1 — logout and API-server presentation residue
- R-SV6b — dormant rendezvous/NAT compatibility authority deleted
- R-SV6c — rendezvous peer-presence and compatibility status plane deleted
- R-SV6d — public/custom-rendezvous selection state deleted
- R-G9 — minimal presentation and compatibility serialization contracts
- R-G4a — switch-sides role-swap compatibility state excision
- R-X6/R-S11c-9b — desktop URL IPC handoff canonicalization
- R-S11b-3 — service-owned remote-access policy, identity, and trust material.
- R-S11c-6 — Windows named-pipe endpoint hardening.
- R-S11c-9 — Windows URL forwarding via unauthenticated window messages
- R-S11c-10 — Linux root-context shell interpolation.
- R-S11b-4 — config secrecy statement after IPC closure

Additional Linux command/provenance closures whose earlier entries were prose rather than headings:

- R-S11c-10e closes Linux distro metadata parsing.
- R-S11c-10f closes linux_desktop_manager headless probing.
- R-S11c-10k closes Linux root/service helper command provenance.
- R-S11c-10l closes Linux server tray cleanup process selection.
- R-S11c-10m closes the shared Linux helper command-provenance residue.
- R-S11c-10n closes the Linux headless CM uid lookup.
- R-S11c-10o closes the Linux clipboard FUSE stale-unmount provenance path.
- R-S11c-10p closes the Linux self-relaunch AppImage fallback.
- R-S11c-10q closes the Linux clipboard FUSE root-process path.
- R-S11c-10r closes the Linux clipboard FUSE direct-mount/PATH-helper abstraction.
- R-S11c-10s closes the Linux Flutter runner Rust core library load provenance.
- R-S11c-10t closes the Linux Debian package tree authority.
- R-S11c-10u closes the Linux XDO libxdo dynamic-library provenance path.
- R-S11c-10v — obsolete generated Docker build helper excision.
- R-S11c-10w — verifier private scratch workspace authority.
- R-S11c-10x — Apple checker private verifier-VM scratch authority.
- R-S11c-10y closes the Linux Debian shipped ELF runtime-library provenance class.

### Adjacent findings not reopened here

Android exported components and iOS root-IPC absence are described above without claiming device behavior.
Unix socket parent/mode checks remain prerequisites, not privileged-action authority. File-transfer symlink
TOCTOU, port-forward plaintext, decompression amplification, OS-login removal, deep links, and native codec
advisories retain their separate requirements/status entries. Appendix C #2b remains the native-decoder residual.
The source topology is implemented; native, artifact, reproducibility, independent-reproduction, and
external-review claims remain bounded by the OPEN table and R-B2/R-B10.
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

**R-S11c-10w verifier scratch authority — SOURCE IMPLEMENTED; FOCUSED NO-NIC VM RUNTIME GREEN.**
`scripts/verify.sh` owns one authenticated private workspace and runs only the fast semantic baseline in the ordinary
loop. Its explicit VM self-test opens that exact initially empty mode-0700 root once and passes only the inherited
descriptor plus its recorded creation identity to `verify-private-tree-closure.py`. The helper rejects a descriptor
whose device/inode differs before allocating unpredictable descriptor-relative fixture
children and exercises cleanup-error preservation, authority bounds, acquisition failures, normalization,
external-hardlink refusal, retained-inode authority, root removal, and final emptiness. Any path, mount, identity,
inventory, cleanup, or finality ambiguity is fatal and preserves ambiguous state. The authenticated no-NIC verifier
VM refuses root and UID/GID 4001, admits only UID/GID 4000, rejects a deliberately mismatched creation identity before
the scratch root gains any entry, executes the real positive fixtures, and defers its success marker until descriptor-safe
workspace removal proves absence. The prior current-user-systemd prerequisite belonged to the
deleted global source/mutation catalog; no live verifier operation uses or requires that deleted managed-command
framework. This closes the focused workspace-fixture execution gap only, not the full verifier image/product gate,
release artifacts, native product behavior, independent reproduction, or external review.

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
agree with the exact runtime mount's `/proc/self/mountinfo` type, and ext4 must return a nonzero `f_fsid` derived from
its superblock UUID. The canonical 64-bit `f_fsid` and opaque persistent parent handle are recorded and must match
together across restart; the runtime mount ID remains live-process authority only. This avoids the newer-only
`FS_IOC_GETFSUUID` dependency that the pinned Debian 12 Linux 6.1 verifier VM correctly rejected. New journals are v4;
legacy v3 full-UUID records recover only when that UUID folds to the current ext4 `f_fsid` and the parent handle matches.

Every untrusted file edge is acquired first with `O_PATH|O_NOFOLLOW`, rejected unless it is a stable regular file, then
reopened nonblocking through its retained `/proc/self/fd/N` authority and re-proved. FIFO or other special-file
substitution therefore cannot block record, source, release, or cleanup inspection before type rejection. The exact
five files remain current-UID/current-GID, mode 0444, single-linked, xattr-free, bounded, synchronized, and manifest-bound.
The same-parent payload root is mode 0700 while staging and explicitly finalized and synchronized at mode 0555 only
after exact content and security proof.

The canonical mode-0400 v4 journal is linked and parent-synchronized in `initializing` state before payload creation.
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

`docs/RELEASE-VERIFICATION.md` makes the manifest itself an independently authenticated input and rejects
same-host package/checksum substitution, partial sets, identity mismatch, or any unsigned override.
`docs/ANDROID-SIGNING-RECOVERY.md` closes the Android break-glass obligation: verified offline backup is the
only loss recovery for the existing identity; suspected compromise retires that package identity and requires
a new package name, new key/pin, clean build, authenticated notice, and data-wiping uninstall/reinstall. The
current pipeline has no ad hoc certificate-lineage or pin-bypass path.

No current-master R-B2/R-B10 Debian, Android, and Windows artifact set or A==B manifest exists. Historical
successful and failed build transcripts, intermediate artifact hashes, temporary-log identities, and superseded
QA narratives remain available in Git and the external audit; they are not current release evidence.

The required sequence is: settle source and normative documentation, update inventory and codec/status hashes,
bump `FORK_VERSION` last, verify, commit, push the exact clean HEAD, then run the full cold build. This tracked
source does not substitute for the generated exact-commit artifact manifest, and no `.6` publication is claimed.

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

- **UPCOMING RELEASES — Linux service-child lifecycle ownership — OPEN.** Historical ledger
  disposition: SOURCE/RUNTIME/RELEASE-GATE IMPLEMENTED THROUGH R-S11c-27s; EXACT COLD
  ARTIFACT EXECUTION PENDING. The current source uses one init-independent ownership protocol:
  the installed `--service` supervisor owns the exact `--server --service-owned-server` child
  it launched; no process-name, path-text, argv-text, or current-image sweep is lifecycle
  authority. This remains explicitly **not authorization to inspect, signal, stop, restart,
  replace, upgrade, or otherwise use the deployed host RustDesk service or Haggai as a test
  dependency**.

  Current source contract:

  - `OwnedServiceChild` retains the Rust `Child` and a strict durable identity. Routine
    replacement and shutdown use only that retained child, bound both graceful and forced phases,
    remove the record only after reap, and preserve authority plus the record on uncertainty.
  - `ServiceRuntime` exclusively leases a root-owned mode-0700 runtime directory and publishes
    a bounded mode-0600 no-follow record containing PID, start time, boot ID, executable
    device/inode, UID, generation, and exact service role. Publication is durable and
    no-replace; malformed, linked, mis-owned, mis-moded, or ambiguous state is not adopted.
  - Crash recovery opens a pidfd and completely revalidates identity before each pidfd-bound
    signal. When pidfds are unavailable, only an exited or absent record may be removed; a live,
    mismatched, or unverifiable record is preserved and startup fails before IPC or replacement
    authority. The historical numeric-PID fallback is deleted.
  - Launch derives the principal from the selected numeric UID, opens the exact executable before
    a non-root credential transition, clears ambient environment and descriptors, supplies only
    the passwd-derived principal plus selected-desktop state, sets no-new-privileges, binds parent
    death across exec, and publishes the record before the child is resumed.
  - The package's systemd, SysV, OpenRC, runit, and manual integrations all start the same
    foreground `/usr/bin/rustdesk --service` supervisor. Manager containment is additional;
    child selection, crash recovery, and drain stay inside the Rust supervisor protocol.
  - The final-debian-artifact lifecycle gate is wired after cold A==B comparison and before
    publication. Wiring is not execution evidence.

  Evidence boundary:

  - Git history retains the detailed 2026-07-16 through 2026-07-23 development diary, fixture
    transcripts, run identifiers, timings, hashes, mutation counts, and superseded designs
    formerly copied here. Those receipts are provenance, not current-release proof.
  - Historical isolated runs exercised the actual debug binary or constructed package
    transactions for manual, SysV, systemd, OpenRC, and runit lifecycle; parent death; hostile
    records; executable replacement/deletion; cross-namespace identity; actual numeric-PID reuse;
    and unrelated portable/container survival. They establish that those fixtures once observed
    the intended behavior at their named source states.
  - Several historical service-manager runs used root or added capabilities inside containers.
    Under the current isolation policy they are diagnostic historical evidence only, not an
    acceptable current privilege-boundary rerun. Current root-required service testing must occur
    inside a disposable networkless VM; unprivileged containers remain rootless and
    capability-free.
  - The named systemd VM result and other historical runs predate current `master`; none proves
    the exact final `.deb`, all current source, cold reproducibility, independent reproduction,
    performance/resource bounds, or release readiness.

  Current closure index:

  - **R-S11c-27a — direct Linux service-child ownership and supervisor-death binding — SOURCE IMPLEMENTED.**
    The supervisor retains the final child; credential-drop exec carries kernel parent-death and
    no-new-privileges authority; global server sweeps are absent.
  - **R-S11c-27b — durable Linux service-child record and pidfd-first crash recovery — SOURCE IMPLEMENTED.**
    Root-only lease/record publication and full pidfd identity revalidation are the recovery
    authority.
  - **R-S11c-27c — bounded direct-child graceful/forced termination — SOURCE IMPLEMENTED.**
    TERM, KILL, and reap remain bound to the retained child with explicit deadlines and
    fail-closed uncertain-state preservation.
  - **R-S11c-27d — isolated Linux supervisor-crash/restart recovery behavior — HISTORICAL FOCUSED BEHAVIOR.**
    The fixture crossed parent death, lease release, stale-record removal, and exact live-record
    recovery; it is not current installed-artifact evidence.
  - **R-S11c-27e — executable-object replacement/deletion recovery behavior — HISTORICAL FOCUSED BEHAVIOR.**
    The fixture distinguished live executed inodes across rename and unlink rather than trusting
    path or argv text.
  - **R-S11c-27f — actual-binary manual/non-systemd supervisor lifecycle behavior — HISTORICAL RUNTIME.**
    The debug binary exercised graceful restart/stop, bounded forced reap, and unrelated portable
    survival; the old container run is not a current-policy installed-service proof.
  - **R-S11c-27g — actual-binary manual supervisor crash/restart recovery behavior — HISTORICAL RUNTIME.**
    The debug fixture observed parent-death exit, preserved crash evidence, and a fresh recovered
    generation.
  - **R-S11c-27h — actual-binary non-root active-desktop privilege-drop/exec behavior — SOURCE IMPLEMENTED;
    HISTORICAL RUNTIME.** The descriptor-bound active-seat launch was exercised with exact
    UID/GID/groups, bounded environment, empty live capabilities, and no-new-privileges. The old
    capability-added container is not an acceptable current rerun.
  - **R-S11c-27i — actual-binary hostile service-child record rejection behavior — HISTORICAL RUNTIME.**
    Seven malformed or ambiguous record classes were refused without granting signal or
    replacement authority.
  - **R-S11c-27j — concurrent separate-Docker service noninterference behavior — HISTORICAL RUNTIME.**
    An isolated sibling RustDesk process survived lifecycle operations until its own harness
    explicitly drained it.
  - **R-S11c-27k — pre-pidfd fallback recovery behavior — SUPERSEDED.** Its historical
    revalidate-then-numeric-signal design retained an irreducible PID-reuse race and was deleted
    by R-S11c-27u/R-S11ca; it is not a supported mode.
  - **R-S11c-27u — pidfd-unavailable live recovery refusal — SOURCE IMPLEMENTED; CURRENT RUNTIME OPEN.**
    Current source performs classification only and fails closed for live, mismatched, or
    unverifiable records. The updated exact-binary refusal fixture was not executed at that slice,
    and current installed-artifact behavior remains unproven.
  - **R-S11c-27l — installed Debian SysV lifecycle — SOURCE/PACKAGE IMPLEMENTED; HISTORICAL RUNTIME.**
    The package adapter and lifecycle fixture bind one exact supervisor and preserve unrelated
    processes. Its earlier constructed-package run predates current packaging and is not current
    artifact proof.
  - **R-S11c-27m — installed Debian systemd lifecycle — SOURCE/PACKAGE IMPLEMENTED; HISTORICAL NATIVE VM.**
    A networkless Debian VM once exercised installed restart, stop/start, supervisor crash,
    non-root child identity, cgroup ownership, portable survival, removal, and purge; it does not
    prove current `master` or the final artifact. The lifecycle now exists only as a release-only
    scenario of the common no-NIC verifier VM; its exact numeric-nonroot library-staging profile
    has current real-VM evidence, but the installed package transaction does not.
  - **R-S11c-27n — cross-container executable identity — HISTORICAL RUNTIME.** Distinct
    mount/PID namespaces using identical path and bytes remained distinct executable identities.
  - **R-S11c-27o — actual kernel numeric-PID reuse — HISTORICAL RUNTIME.** A private PID namespace
    forced reuse and recovery rejected the stale start identity without signaling the replacement.
    Its elevated container fixture is historical only under the current VM-only privilege policy.
  - **R-S11c-27p — packaged OpenRC/runit/manual supervisor templates — SOURCE/PACKAGE IMPLEMENTED.**
    Templates invoke only the foreground service supervisor and create no competing child or
    process-discovery authority.
  - **R-S11c-27q — native OpenRC lifecycle authority — SOURCE/PACKAGE IMPLEMENTED; HISTORICAL RUNTIME.**
    The old container transaction exercised native manager behavior and stale state, but requires
    current exact-artifact VM reproduction.
  - **R-S11c-27r — native runit lifecycle authority — SOURCE/PACKAGE IMPLEMENTED; HISTORICAL RUNTIME.**
    The old container transaction exercised exact runsvdir/runsv/supervisor/child ownership and
    recovery, but requires current exact-artifact VM reproduction.
  - **R-S11c-27s — final Debian artifact lifecycle gate — SOURCE/RELEASE-TRANSACTION IMPLEMENTED;
    EXECUTION OPEN.** The gate binds the cold A==B pass-A `.deb`, commit, package identity,
    authenticated devcheck archive, installed systemd lifecycle, post-run input identities, and
    pre-publication order through the common no-NIC verifier VM after its Docker daemon is joined.
    No current final `.deb` has passed it.
  - **R-S11c-27t/R-T4 — Linux headless CM bootstrap cancellation ownership — SOURCE IMPLEMENTED/GATED;
    NATIVE OPEN.** Owner loss is selectable throughout bootstrap and post-bootstrap work has
    bounded terminal-first completion. Current native/package/device lifecycle execution remains
    open.

  Required closure before this parent item may close:

  - Build the exact clean release commit twice from authenticated pinned inputs, prove A==B, and
    execute the resulting pass-A `.deb`—not a debug binary or reconstructed mini-package—in
    disposable networkless Linux VMs under systemd, SysV, OpenRC, runit, and the documented manual
    supervisor path.
  - Exercise root and active-user children across X11/Xwayland/login transitions; normal restart
    and stop; wedged-child escalation; supervisor crash; pidfd-unavailable refusal; stale,
    malformed, linked, mis-owned, and ambiguous records; PID reuse; executable
    replacement/deletion; and identical path/bytes/argv from a different executable identity.
  - Use realistic unauthorized local principals and concurrent unrelated RustDesk instances,
    prove they cannot acquire IPC/signal/lifecycle authority, and prove exact cleanup with bounded
    CPU, memory, file descriptors, processes, handles, and elapsed latency.
  - Bind all executed artifacts and VM bases to hashes, preserve compact reproducible evidence,
    reproduce independently, and obtain external security review. Until then, the source topology
    is implemented but installed current-release behavior and release readiness remain **OPEN**.

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
  CLOSED; TARGET-NATIVE FAILURE INJECTION AND CURRENT PACKAGE EVIDENCE OPEN.** Android/iOS authorize the
  decrypt-only config-keypair migration path only after a live OS-protected key was installed and failed to
  open an older payload. Missing or rejected OS-key state fails before legacy-key access, plaintext release,
  rewrap marking, or replacement storage; a genuine migration rewraps under the live key. Desktop read-only
  recovery remains separate. The focused source invariant and Rust policy regression cover this topology,
  but exact Android KeyStore/iOS Keychain failure and recovery, durable reload, current packages, and device
  behavior remain open in the mobile and release matrices.
- **R-S11bi/R-S11e-75 — macOS launchd lifecycle is domain-qualified and postcondition-checked — SOURCE
  IMPLEMENTED; NATIVE APPLE AND EXACT SIGNED-ARTIFACT EVIDENCE OPEN.** The privileged scripts address the
  exact `system/<label>` LaunchDaemon, and the Rust path derives the current graphical user's exact
  `gui/<effective-uid>/<label>` LaunchAgent. Both require the containing domain before classifying target absence;
  removal uses checked `bootout` plus an absence recheck, while install/restart uses checked `enable` and
  `bootstrap` plus a present-state recheck. Uninstall proves target absence before deleting privileged artifacts.
  The focused production-source invariant guards those command and ordering properties. It does not execute
  launchd. Exact signed installed artifacts still require the full present/absent/disabled/wrong-domain,
  partial-install, failure, retry, upgrade, logout/user-switch, restart, uninstall, abrupt-exit, state-agreement,
  and resource-cleanup matrix on supported macOS versions.
- **R-S11bj/R-S11e-76 — Android APK builder container and source authority — SOURCE CLOSED; CURRENT
  VM BUILD, RELEASE, AND DEVICE EVIDENCE OPEN.** `scripts/build-android.sh` rejects dirty overrides, binds one
  clean commit, creates a private immutable authority plus one fresh writable copy per pass, and proves committed
  inputs unchanged. Key inspection, compilation, signing, and verification use only the authenticated no-NIC
  verifier-VM guest-Docker funnel, immutable image ID, fixed nonroot/networkless/read-only confinement, bounded
  resources, and role-specific mounts. Live repository/output mounts, host Docker, image pull/build, Docker-socket,
  host-namespace, privileged, added-capability, and published-port fallbacks are absent. A sealed result must pass
  certificate, signature, manifest, mobile-key, checksum, source, and stable-publication checks; standalone A/B and
  release independent-snapshot equality remain required. Source and authority-entry checks are supplementary;
  current APK construction and R-B2/R-B10 remain open.
- **R-S11bk/R-S11e-77 — Android exact-commit snapshot mode authority — SOURCE CLOSED; CURRENT ARTIFACT
  EVIDENCE OPEN.** Git modes are normalized after every extraction: immutable roots/directories/executables are
  `0555`, immutable ordinary files `0444`, writable roots/directories/executables `0755`, and writable ordinary
  files `0644`. The descriptor-based comparator binds complete modes, ownership, types, link counts, stable
  identity, and content across both roots and refuses noncanonical input before compilation. The Gradle init-script
  gate remains independently strict.
- **R-S11bl/R-S11e-78 — Android bounded scratch lifecycle — SOURCE CLOSED; CURRENT BEHAVIORAL BUILD
  EVIDENCE OPEN.** The inner harness installs and retires Rust and Android cross-std payloads before expanding
  Flutter/LLVM, retains LLVM only through bridge/JNI production, retires LLVM and its environment before one
  Gradle projection, and retains Cargo through the final tracked metadata consumer. The 10-GiB executable tmpfs
  and 12-GiB no-swap ceiling remain fixed; no larger resource grant, host scratch, extra mount, or persistence
  fallback substitutes for phase ownership.
- **R-S11bm/R-S11e-79 — Android tool-preference scratch ownership — SOURCE CLOSED; CURRENT BEHAVIORAL
  BUILD EVIDENCE OPEN.** Before tool use, the inner harness clears competing Android home inputs, creates one fresh
  current-UID mode-0700 `ANDROID_PREFS_ROOT=/tmp/android-preferences-root` and `.android` child, and keeps legacy
  analytics plus current tool state inside that bounded private tree. Account-home, JVM-home/options, writable-root,
  host-mount, persistence, resource-widening, network, capability, and privilege fallbacks remain forbidden.
- **Retained named Android build evidence for R-S11bj–R-S11bm — OLDER COMMIT ONLY.** Clean commit
  `29915f0075f4d1464361f218e61dd7d7e7072b85` completed two fresh-source target-local passes and produced
  byte-identical, one-signer v2/v3-valid APKs at SHA-256
  `20af1c99178feb02e3a584a4148dbc5ce8129261361f7f37d0c09461d3e6f02e`. That result exercised the then-current
  inner source, mode, scratch, preference, signing, and artifact checks, but predates current master and the
  guest-only outer authority. It is not a current no-NIC VM build, independent-snapshot R-B2/R-B10 result, package
  installation, peer/presentation, lifecycle, resource-soak, or device result.
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
  SOURCE IMPLEMENTED/GATED 2026-07-22; FINAL DATA-PLANE SHAPE SUPERSEDED BY R-S11eh 2026-07-27;
  EXACT NATIVE/APK/DEVICE/ARTIFACT EVIDENCE REMAINS R-B2/R-B10.** Platforms: the shared non-iOS
  outgoing viewer (Android plus desktop; iOS has no local audio-service voice capture). Endpoint/action:
  an accepted outgoing voice call subscribes one synthetic `ConnInner` to the process-local audio
  service and sends its audio through that exact viewer round. The imported worker hot-polled separate
  stop and audio channels and did not own subscription revocation. The first R-S11bp closure made the
  worker block and gave it exact subscription/stop/handle ownership. R-S11eh's later end-to-end audit
  proved that the worker still drained into the viewer's unbounded general `Data` queue, so it moved
  rather than closed real-time resource accumulation.

  The final topology has no voice worker. `VoiceCallAudio` owns the exact synthetic subscription,
  non-cloneable input lease, and R-S11eh bounded receiver. The connection round's existing Tokio select
  waits on that receiver and its sole peer-stream writer sends the message directly. Normal stop,
  reconnect/final shutdown, and hard `Drop` all unsubscribe the exact synthetic connection before
  releasing the exact lease. No voice stop flag/channel, polling or blocking loop, nested runtime,
  intermediate `Data::Message` forwarding, detached handle, or voice-specific completion-pool handoff
  remains. This does not change Android's persistent `MainService` or incoming controlled-service
  lifetime.

  The updated `scripts/verify-viewer-voice-call-worker.py` binds the exact composite owner,
  unsubscribe-before-lease-release, event-driven direct-select consumption, sole-writer send,
  R-S11eh mailbox use, retired worker/stop/intermediate-queue absence, R-S11bp, Appendix C #209/#287,
  this row, and shared/Apple gate wiring while retaining its independent R-S11bq input-lease checks.
  The R-S11eh focused behavior and semantic gates supply the mailbox/resource proof. No current APK,
  native Android/desktop voice-call session, real device, exact release artifact, or R-B2/R-B10
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

  `VoiceCallAudio` now owns its lease alongside the exact subscription and R-S11eh bounded receiver.
  Stop removes the exact subscription and then drops only that lease; no intermediate worker has
  global-`None` cleanup authority, so lexical owner drop supplies exact rollback.
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

  The named source slice compiled exact Rust 1.75 locked/offline library tests against the pinned read-only
  Cargo-vendor closure and passed its two ownership regressions. That establishes only the Rust ownership model at
  that source state. Current packaged desktop/Android voice-call behavior, complete native lifecycles, and release
  artifacts remain open under the global matrix; deleted workspace-catalog results are not carried forward.
- **R-S11br/R-S11e-84 — Android native voice-call capture has exact process-wide owners — SOURCE
  IMPLEMENTED; EXACT-CURRENT PACKAGED NATIVE/DEVICE EVIDENCE OPEN.** One serialized
  `VoiceCallAudioCoordinator` owns the process-wide `AudioRecordHandle`. Controlled owners are
  registered and activated independently by exact service, connection, and registry generation; outgoing
  ownership uses the exact positive Activity generation and canonical isolate UUID. Stale updates,
  teardown, Activity callbacks, and service generations cannot alter their replacements, and neither owner
  domain clears the other.

  Recorder reconciliation selects active voice capture before exact-projection playback capture and otherwise
  stops. Construction and start prove permission, initialized/recording state, and bounded buffer arithmetic;
  failures release partial resources. Stop invalidates work, unblocks and joins the exact reader, restores
  interruption, and clears the recorder, reader, mode, projection, and raw-audio state. The outgoing Rust path
  constructs its subscription, lease, and bounded receiver before publishing native/UI started state.

  The deleted 5,638-line aggregate Android source verifier did not execute this lifecycle and no longer counts
  as evidence. The shared gate retains a narrow source backstop and relevant Rust behavior-test invocations.
  No standalone Android-free Kotlin owner fixture remains: the files were outside Gradle test source sets and the
  current gate only searched their prose rather than compiling them. Historical target-local APK
  assembly binds only its named older source. Exact-current package installation must still exercise concurrent
  controlled calls, controlled/outgoing overlap, Activity replacement, task swipe/reopen with the persistent
  service retained, Force Stop, projection replacement/revocation, injected permission/buffer/start/read
  failures, peer reconnect/presentation, and exact thread/audio/projection cleanup.
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
  listener state. The protected `_service` path additionally retains its bounded typed
  `ServiceIpcRequest::LivenessProbe` / `ServiceIpcResponse::Liveness` round trip;
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
  This is source-only coverage; it does not replace the native MSI and installed-artifact obligations below.

  Confined verification used the already-present immutable development image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` with UID/GID 1000, a read-only root
  filesystem and source mount, no network, all capabilities dropped, `no-new-privileges`, bounded PID/memory/CPU
  limits, and tmpfs-only scratch state. `bash -n` passed the edited shared gate and both modified WiX documents parsed
  as XML. A separate recursive package probe
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
  process absence, and typed status regression. Most confined checks used the already-present immutable development image
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
  tmpfs-only writable state. Bash syntax and Python byte-compilation passed.
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
  syntax and Python byte-compilation passed.

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
- **R-S11bx/R-S11e-90 — Windows runtime-broker cleanup is declarative — SOURCE IMPLEMENTED;
  NATIVE MSI TABLE, INSTALLED LIFECYCLE, AND CURRENT ARTIFACT EVIDENCE OPEN UNDER R-B2/R-B10.** The package-owned
  `App.exe` component contains exactly one non-wildcard
  `<RemoveFile Id="Remove.RuntimeBroker" Name="RuntimeBroker_rustdesk.exe" On="uninstall" />`. The standard
  Windows Installer `RemoveFiles` action therefore owns deletion of that exact sibling when the component is removed.
  `res/msi/CustomActions` and `Package/Fragments/CustomActions.wxs` are absent; source and build metadata contain no
  RustDesk-authored cleanup property, schedule, `CustomActionData`, native cleanup binary/export/project, preprocessing
  hook, project reference, or DUtil/WcaUtil dependency. The exact WiX 4.0.5 SDK, Firewall, Heat, Netfx, UI, and Util
  inputs are individually size/digest pinned in `scripts/pins.env` and acquired as one verified transaction.

  R-S11f, R-S11bx, and Appendix C #39 define the current authoring boundary. Focused shared and independent checks bind
  the exact row and component ownership, retired surface absence, and locked WiX inputs. These source checks do not
  establish the contents of a native MSI or installed behavior. R-B2/R-B10 still require native action/binary-table
  enumeration and attribution, install/repair/major-upgrade/uninstall execution, a clean exact-commit Windows build,
  and artifact identity. Typed pinned WiX extensions may contribute expected extension-owned actions; no final empty
  `CustomAction` table is claimed.
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
  `ok  Debian package tree is root-owned, exact-mode, exact-command-symlink-only, and source-gated`. Every
  project/test process ran as numeric
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
  1m30s with only the repository's existing warning set. Native-codec normal and negative self-tests passed against
  requirements SHA-256
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
  its self-tests, native-codec normal/negative checks, meta-verifier normal/source-mutation checks,
  Bash parsing, and private-tmpfs Python compilation passed. Two stale meta-verifier self-test literals for the
  corrected dedicated child/27-statement package constructor were rejected, updated to the actual contract, and the
  complete matrix was rerun successfully. Rustfmt found no drift in a newly touched hunk; the whole-file check remains
  non-clean only at explicitly untouched pre-existing locations in `src/ipc/auth.rs` and `src/platform/linux.rs`.

  One dependency-inventory invocation was mistakenly executed directly on the host as the ordinary user. It was
  read-only, used no root/network/service/device/port authority, changed no file, and is not counted; normal mode and
  its self-tests were rerun in the confined container. Separately, an incorrect formatter toolchain mount caused
  Docker to create one empty named volume, `rust1.75.0-x86_64-unknown-linux-gnu`. No project process used it, it
  contained no files and was initially left untouched rather than silently removed. The operator's later explicit
  residue-cleanup authorization removed that exact empty volume; see R-S11gl below. Neither deviation touched
  RustDesk, services, listeners, firewall state, or a device. No root container, host namespace, Docker socket
  mount, port publication, host RustDesk process/service/configuration, listener, firewall, network, or device path
  was used, inspected, or changed. The final exact-state review and publication identity are recorded in the
  external audit ledger after publication; the source slice does not claim native
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
  dependency-inventory normal/self-test, native-codec normal/self-test,
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
- **R-S11cg/R-S11e-99 — Android signing-identity generation authority — SOURCE
  CONTRACT RETAINED; CURRENT ONE-TIME EXECUTION AND RELEASE/DEVICE EVIDENCE OPEN.**
  `scripts/gen-android-keystore.sh` creates the permanent Android identity only at two distinct
  canonical absolute leaves in one current-UID mode-0700 directory. It refuses root, an alias other than
  `rustdesk-fork`, an existing keystore, insecure/symlinked inputs, mutable images, pulls, and broad mounts.
  The fixed immutable Android builder performs exactly three numeric-nonroot, no-pull, networkless,
  read-only-root, capability-free, no-new-privileges, resource-bounded operations: 33-byte CSPRNG password
  generation when needed, RSA-4096/SHA256withRSA fixed-alias key generation, and independent certificate
  inspection. Passwords enter only through read-only files, never argv or environment.

  The password and keystore are identity/metadata/digest checked around use. Same-filesystem hard links
  provide atomic no-clobber publication; a newly generated password is synchronized before its matching
  verified key, and final bytes/modes/link counts are reproved. The final signing directory is never mounted
  writable into a container.

  Historical disposable generation at clean commit `c89082124cff95a1c0a67ababcd4a5de57d5996f` exercised
  both password branches and an existing-key refusal, but it predates the current R-S11di VM-only authority
  and is not current-master release evidence. The current fast KVM pass exercises only the early
  identity-access-free authority branch. No established keystore/password was listed, opened, mounted,
  hashed, regenerated, replaced, or otherwise inspected. Current one-time execution, APK signing/upgrade,
  device behavior, cold R-B2/R-B10 artifacts, installed/native behavior, and external review remain open.
- **R-S11ch/R-S11e-100 — Windows helper container and KVM envelope — SOURCE
  IMPLEMENTED; ACTUAL SMALL-PROFILE VM EXECUTION GREEN; CERTIFIED HELPER/KVM/WINDOWS EVIDENCE OPEN.**
  `scripts/windows-helper-runtime.sh` remains the sole launch funnel for the Windows build, golden
  provisioner, and golden verifier. It verifies the exact certified helper image and captured archive,
  derives the independently pinned kernel through a snapshotted nonroot extractor, and applies one numeric-
  nonroot, no-pull, network-none, read-only-root, capability-free, no-new-privileges envelope with profile
  PID/memory/no-swap/CPU/tmpfs and finite ulimit bounds. Caller mounts are canonical explicit nonrecursive
  binds; only fresh exact outputs are writable. Ordinary operations receive no device; the two exact-golden
  inspection consumers alone may receive one `/dev/kvm:rw` grant and its proved nonroot group. Established
  and diagnostic goldens are hashed before inspection, and a new provision is accepted only after its final
  digest matches.

  The current R-S11do VM run executed the production shared runtime's `small` profile against a real
  guest-only Docker daemon and observed numeric UID/GID 4000, loopback-only container networking, read-only
  root and input, exact writable output, zero capabilities, no-new-privileges, seccomp filtering, and the
  expected PID/memory/no-swap/CPU/core/descriptor limits. It also behaviorally refused traversal, protected
  targets, duplicate targets, a FIFO, unsafe writable mode, writable hard links, and a terminal symlink.
  This is real envelope/mount/cleanup behavior, but the probe image is deliberately minimal and is not the
  certified Windows helper. Exact helper-archive provenance/runtime contents, kernel extraction, KVM/
  libguestfs, golden inspection, Windows provisioning/building, cold artifacts, native behavior,
  independent reproduction, and external review remain open.
- **R-S11ci/R-S11e-101 — Apple conformance verifier authority — VM-ONLY SOURCE PATH
  IMPLEMENTED; REAL AUTHORITY ENTRY GREEN; CURRENT APPLE WORKLOAD AND NATIVE APPLE EVIDENCE OPEN.**
  `scripts/apple-conform-check.sh` now refuses UID or primary GID 0 and authenticates R-S11dh before
  sourcing repository helpers or admitting product inputs. Caller Docker endpoint/context/configuration/TLS,
  target-matrix, and SDK-path state is rejected. The only Docker authority is the fixed guest client,
  principal-scoped Unix socket, root-owned empty configuration, and exact VM-root daemon generation; every
  image/provenance/container call uses an empty environment and replays that proof before and after. There is
  no direct host-root, host-rootless, TCP, or compatibility fallback.

  The normal path retains one immutable provenance-verified Apple image, the fixed macOS-arm64, macOS-x86_64,
  and iOS-arm64 matrix, private read-only source/vendor snapshots, one fresh private target, locked/offline
  serialized Cargo checks, deterministic SDK-boundary classification, nonroot no-pull/network-none/read-only-root
  containers, exact resource ceilings, and identity-bound private-tree cleanup. The gate no longer calls its
  guest scratch “host” state or treats self-greps and documentation wording as behavioral evidence. The focused
  checker is a compact architecture invariant; the duplicate Apple verifier-of-verifier block in
  `verify-verifier-workspace.py` is deleted.

  The current fast no-NIC QEMU run behaviorally refused VM root, UID/GID 4001, caller `DOCKER_HOST`, and caller
  `APPLE_TARGET`; admitted UID/GID 4000; and completed a real Docker 27.5.1 client/server request over the guest Unix channel with pre/post generation
  replay. The outer harness authenticated its qcow2, Docker bundle, kernel, and initramfs, observed no host
  listener change, and joined residue-free teardown in under 50 seconds. Its receipt deliberately says
  `workload=unexecuted`.

  The local `online/` closure is absent, including the pinned 1,122,604,778-byte Apple image archive and Cargo
  vendor tree, so the current complete three-target source transaction was not run. A historical full source
  pass predates this VM-only entry and is not current-tree evidence. Native macOS/iOS compilation, signing,
  installation, helper/launchd behavior, runtime, packages, cold release, independent reproduction, and
  external review remain open.
- **R-S11cj/R-S11e-102 — isolated online-acquisition VM and non-root producer authority — SOURCE,
  FOCUSED AUTHORITY, AND PRIVATE-WORKSPACE FAILURE FINALITY VERIFIED; FULL CACHE/PRODUCERS, COLD RELEASE,
  INDEPENDENT REPRODUCTION, AND EXTERNAL REVIEW OPEN.** Platform/boundary: one ordinary-user Linux
  orchestrator owns a disposable QEMU/KVM VM; VM-local root alone owns its outbound NIC, TCP resolver,
  Unix-only Docker daemon, private bridge/firewall/NAT, and sealed Git runtime. The exact admitted UID:GID
  owns each acquisition container and only its typed cache outputs. Host Docker, root, a live-source mount,
  host forwarding/TAP/bridge, a published port, and a non-loopback management listener are absent.

  Every non-bootstrap `online-fetch.sh` request enters that VM before Docker inspection. The host authenticates
  the Debian qcow2, direct-boot kernel/initramfs, static Docker archive, Debian Git package, and Ubuntu
  virtiofsd package, then transfers one clean committed Git bundle. Git is extracted only in the guest into
  a root-owned non-writable runtime and is limited to the local `file` protocol. Three separate ordinary-user
  virtiofsd processes each receive one retained export inode and one prebound private Unix socket: cache state,
  systemd-image cache, or the result root carrying the separately bounded transaction streams. Each launcher
  requires Landlock ABI 8, permits only
  its one export plus fixed runtime reads, denies TCP bind/connect, sets no-new-privileges, and requires
  virtiofsd's kill-action seccomp filter. The cache mount alone is executable and contains exactly the
  same-filesystem `inputs`/`retired` siblings; systemd and result mounts are `noexec`.

  VM-local root denies all outbound UDP before activating the acquisition NIC, configures DNS over TCP, and
  inserts the same UDP denial at the head of `DOCKER-USER` before a producer runs. The non-root entry replays
  the kernel, OS, NIC/address/route, filters, daemon generation/executable/socket, Git runtime, source
  commit/tree, mounts, and cache inventory before and after use. Root, foreign principal, stale generation,
  wrong source/mount, and forged environment fail closed. Producer containers retain immutable image IDs,
  no pull/publication, bridge-only acquisition egress or network-none semantic work, numeric non-root identity,
  read-only roots, zero capabilities, no-new-privileges, and finite resource bounds.

  The compact source invariant is supplementary. The focused run at exact source commit
  `c8817457dde6e874fbbe380f37022d4b77b40c4d` booted the authenticated topology and recorded a 16-second
  VM phase. It behaviorally refused VM root and a foreign principal; admitted UID/GID 1000; executed a
  capability-free, read-only-root, bounded bridge container; retrieved and SHA-256-verified the independently
  pinned 114,565-byte olefile wheel; proved cross-parent `RENAME_NOREPLACE`, occupied-destination no-clobber,
  and nonempty-directory `RENAME_EXCHANGE`; wrote both cache-state children and the systemd export; returned
  bounded results through the third export; observed no published port or host TCP/UDP listener change; and
  joined QEMU, Docker, serial capture, and all three virtiofsd processes with no retained successful-run root.
  At exact source commit `cd3891fae9c4b9f98b14aabc246d18f35af2d74b`, the guest transaction owner now
  establishes a soft and hard `RLIMIT_NOFILE` of 524,544 before dropping to the acquisition principal: the
  private-tree closer's 524,288-entry bound plus its 256-descriptor reserve. A compact source invariant derives
  and compares those constants so either side cannot drift silently. The successful authority transaction
  completed in 16 seconds and the outer owner accepted the exact descriptor-budget completion receipt.

  The behavioral failure test used the real `--maintenance-capture-android-builder-bootstrap-image` VM route.
  Before the correction, it reported both the genuine absent-image error and `retained-authority descriptor hard
  limit is below the tree bound`, leaving the private guest workspace unretired. Repeating the same transaction
  at `cd3891f` reported only the absent-image error: the private workspace closer completed, the before/during/
  after listener inventories were byte-identical, no owned QEMU or virtiofsd generation survived, and the exact
  bounded failure record was inspected before retirement. This closes the acquisition process's descriptor-
  budget/failure-cleanup defect, not the requested producer work.

  Same-generation build, validation, and private candidate capture now form one transaction. Successive real
  Android bootstrap attempts corrected obsolete final-pin use during discovery, mode-0600 embedded provenance,
  and classic-builder `Config.Image` bookkeeping without weakening runtime configuration or rootfs equality. At
  clean pushed commit `92b7a2bc75c37d661ee03e64045ac72d640d9b25`, the real discovery build, non-root
  provenance inspection, networkless metadata seal, and seal verification all passed. Archive capture then failed
  with `OSError: [Errno 27] File too large`: the guest's process-wide `ulimit -f 32768`, intended to constrain
  diagnostics, also constrained the deliberate cache artifact to 16 MiB. The before/during/after host listener
  inventories were byte-identical, no owned process survived, and no candidate was published.

  At clean pushed commit `53b16fe87de926a4281ccfd1c4e5449f95519798`, each transaction stdout/stderr stream is
  read through its own 16 MiB FIFO ceiling; the first excess byte is retained as an overflow verdict, and the real
  acquisition-VM authority smoke includes an exact 16 MiB-plus-one-byte fixture. OCI capture and certified OCI
  normalization independently refuse a compressed archive above 2,147,483,648 bytes before the excess write;
  that ceiling exceeds every currently pinned image archive (largest: 1,122,604,778 bytes). Docker-save stderr is
  inherited by the bounded transaction stream rather than held in an undrained pipe. The real authority smoke
  completed in 17 VM seconds, exercised the exact overflow fixture, observed unchanged host listeners, and joined
  all owned processes without retained successful-run state.

  The real Android candidate at the same commit then passed discovery, non-root provenance inspection, networkless
  metadata seal, seal verification, and the bounded archive write. It failed only when validation found legacy
  `repositories` metadata: private bootstrap capture had saved the image through a temporary tag, while the private
  content-addressed contract correctly forbids repository-name authority. The bounded stdout/stderr evidence in
  `.harness-state/verifier-vm/online-fetch-runs/run.L0Cywpd9Dp` was retained; before/during/after listener inventories
  were byte-identical, no owned process or candidate survived, and the failure did not touch host RustDesk.

  Current source deletes the private tag branch. Every private image, including an initially unpinned bootstrap
  candidate, is saved by immutable image ID and must have `RepoTags: null`, no image-name/ref root annotations, no
  `repositories` file, and one exact config/manifest/image identity. A real rerun at clean pushed commit
  `529836c18ec35b278549179816023c0b1e4b8c98` proved that exact-ID capture removed `repositories`, then stopped at
  `Docker archive root OCI descriptor does not bind the expected image identity`. Docker 27.5.1's classic image
  store emits an untagged root descriptor pointing directly to the synthesized image manifest; the Docker image ID
  remains the config digest. The prior fixture had modeled only the nested-index form emitted by the containerd
  image store. Run `run.Z8bhxmF7GV` retained bounded diagnostics, byte-identical before/during/after listener
  inventories, zero new listeners, no candidate, and no surviving owned VM process.

  Current source now gives the bootstrap candidate one exact classic-store shape: the unannotated root descriptor
  names the directly hashed manifest, that manifest names the exact Docker image-ID/config digest and every layer,
  and all referenced blobs remain the complete archive set. A real rerun at clean pushed commit
  `4dae85a25e95c50f27618b5520859eea30933206` passed those root/config checks and then stopped at
  `Docker archive image layer media type is unsupported`. The exact Moby 27.5.1 classic exporter writes local
  `TarStream()` bytes as uncompressed `application/vnd.oci.image.layer.v1.tar` descriptors, whose digests are the
  image config's diff IDs; the prior fixture used the containerd-store gzip media type. Run `run.WF3IzaAnjZ`
  retained bounded diagnostics, byte-identical before/during/after listener inventories, zero new listeners, no
  candidate, and no surviving owned VM process.

  At clean pushed commit `2984d5208fa7e7813b92aa8637851c3047f8c180`, `run.lPupE19cvt` passed the
  direct-manifest, image-ID/config, uncompressed-layer, and ordered diff-ID checks, then stopped at
  `Docker archive contains an absent, duplicate, or unreferenced OCI blob`. Exact Moby 27.5.1 source shows
  that the classic exporter also writes one content-addressed legacy v1 config for each layer; its modern loader
  selects `manifest.json` when present and reads only the named top config and layers, while those v1 configs are
  used only by the manifest-absent legacy loader. The failed run retained bounded diagnostics and byte-identical
  before/during/after listener inventories, published no candidate, and left no owned VM generation running.

  Current source therefore does not weaken the published archive contract. Private bootstrap capture first writes
  Docker's output to a bounded mode-0400 temporary, validates the complete reachable direct-manifest graph, and
  accepts discard-only blobs only when their paths exactly match their content hashes. A second bounded streaming
  pass emits deterministic metadata and only the reachable manifest/config/layers, replays the source hash and inode,
  strictly reverifies the resulting mode-0400 archive, materializes that closed graph, and removes the exact raw
  temporary before no-replace publication. Other private certified archives retain their existing nested-index
  contracts. The behavioral fixture proves strict rejection before normalization, removal and strict acceptance
  afterward, and rejection of a false discard-only content address. Focused provenance, online-authority, adjacent
  builder-authority, shared-workspace, and diff checks are green.

  Exact-current runtime evidence now exists for this capture path. At clean pushed commit
  `337753d692594531ca522d8927a8e6c606b819e8`, `run.dODxMdeH1n` used the authenticated ordinary-user
  acquisition VM and guest-only Docker 27.5.1 to build the Android discovery image, inspect its package manifest,
  build the networkless metadata-sealed candidate, verify discovery-to-candidate runtime/rootfs equality, normalize
  the exact-ID Docker save, strictly validate it, materialize its OCI layout, and publish by no-replace. The 325-second
  outer receipt reported `hostfwd=absent`, `listeners=unchanged`, and `cleanup=joined`; current exact-generation
  inspection found no QEMU, timeout, or virtiofsd process for the retired run. The success policy removed the run
  root after those checks, so raw listener snapshots/logs are not retained and this limitation is not laundered into
  stronger evidence.

  The subsequent `a81ffdf79afa87a75dfc5d692a33752bf305599b` harness correction requires exact equality of all three
  complete listener inventories and retains a compact success receipt only after exact run-root retirement. Real
  authority-smoke `run.iANlepal0v` completed in 16 seconds with no host forwarding, TCP-only guest acquisition,
  guest-only Docker, listener equality, and joined cleanup. Its current-user-owned mode-0400, one-link, 2,087-byte
  receipt binds the exact commit/tree/source bundle, request/mode, elapsed time, verified authority lines, listener
  inventory digest/size, and serial/result digests/sizes. The run root and exact process generation are absent. This
  is acquisition-authority/finality evidence only, not Android product, native-device, artifact, or release evidence.

  The promoted bootstrap at
  `online/inputs/build-images/android-builder-bootstrap.docker.tar.gz` is current-user-owned mode 0400,
  non-hardlinked, 468,001,119 bytes, and independently passes the strict persisted-bootstrap archive verifier. Its
  reviewed identities are image/config
  `sha256:309400e7e653f180aad33d92ba715e1d67c1320a684896c9d9a6a02936f38c6b`, manifest
  `sha256:0f71087843b2b06b30291ebdb370f29314872817d0bc67d31ae676b28495bfa2`, archive SHA-256
  `d67c950403691bb6db099e1fb19e8113a31a24366d8279b5b83a741c90fabdbc`, OCI-layout SHA-256
  `9bf7f6754f58c84e792851118fe0f6da57829d043592e59b0301cddcb93ef981`, Dockerfile SHA-256
  `d0935b5fd0849ad630f472c4d163c6eb9fd56d20955a0eeae3ff84c0c74977c1`, and dpkg-manifest SHA-256
  `747ebf6e4315ae9c71d7d130f68c2980dbf407a7d29403146e43e5161e6512a2`. Current source pins now name
  those reviewed bootstrap recipe/package/archive/OCI identities. At clean pushed pin commit
  `92693ea94804bfb6666b6bfb1ca2a52c5fca5062`, `run.wn6nrHxpyi` strictly reverified the candidate and materialized
  layout, atomically promoted it without replacement, strictly reverified the final, and completed in 39 seconds
  with exact listener equality and joined cleanup. Its mode-0400, one-link, 1,958-byte source-bound receipt remains;
  the candidate and run-root paths are absent. The certified Android builder was subsequently renewed from this
  exact bootstrap, pinned, and promoted through the distinct networkless transaction recorded under
  R-S11da/R-S11e-119. That closes this bootstrap-to-certified-image prerequisite only; product build and release
  authority remain separate.
  The complete cache, real producer workloads and
  output semantics, product builds, cold R-B2/R-B10 artifacts, independent reproduction, and external review
  remain open. No host RustDesk/service/configuration,
  Haggai environment, host Docker, firewall, route, interface, or sysctl was used or changed.
- **R-S11ck/R-S11e-103 — networked Gradle warmer source authority — CURRENT REAL SOURCE
  LIFECYCLE, PRODUCER, AND CLEAN REUSE EXECUTED; FAILURE NEGATIVES AND COLD RELEASE OPEN.** The sole supported entry crosses
  R-S11cj's authenticated acquisition VM. Inside that guest, one root-owned digest-pinned Git runtime
  closure admits a clean exact commit and rejects sparse/index/tracked divergence, nonignored untracked
  inputs, repository-local archive attributes, grafts, replacement refs, nonregular committed entries,
  and archive-transforming attributes. Ignored live residue cannot enter because the transaction archives
  the admitted commit into separate read-only authority and writable build trees.

  `stage_gradle` mounts only the private writable tree at `/src`, mounts and executes the Android program
  read-only from the authority tree, compares every committed input before and after the producer, accumulates
  live commit/tree/repository-metadata/rearchive failures, blocks publication on source failure, and retires
  the exact principal-, mount-, and inode-bound writable tree. The Gradle producer has no operator/guest
  working-repository mount or copy path.

  The focused checker remains supplementary. At exact source
  `a73040d8dda104f1493e1e3cb97c2a3855f379b1`, retained acquisition run `run.52py3CWymM`
  exercised `prepare_gradle_source`, the real Rust/Flutter/Gradle producer, committed-input pre/post comparison,
  source retirement, cache validation, and publication. It compiled the Android Rust release, completed
  `assembleRelease` in 291.1 seconds, built a 45.3 MiB warm APK, and published a verified 4.1 GiB Gradle seed.
  The outer harness deliberately invalidated that run because one pre-existing host listener
  (`0.0.0.0:21128`) disappeared only between its identical during-run and final inventories; both new-listener
  sets were empty. This therefore counts as real producer/source-lifecycle evidence but not as a clean outer
  listener-finality result, and the harness neither inspected nor repaired the unrelated service.

  The separate exact-source reuse run `run.hutLn5juYg` then revalidated the canonical cache and skipped warming,
  completing in 500 seconds with `hostfwd=absent`, guest-only Docker/BuildKit, and joined cleanup. Its unchanged
  605-byte listener inventory SHA-256 `d0657aea16dc017adc4cd7386e5fa8ef785e4b0bed418120923515aae425f809`
  exactly matches the first run's original pre-run inventory, so the missing incumbent had returned before this
  run without harness intervention. Still STOP-SHIP: producer-failure, committed-input-tampering, forbidden-Git-metadata, and
  publication-refusal runtime negatives; retained release-artifact identity, resource bounds/soak, cold
  R-B2/R-B10 equality, independent reproduction, and external review. R-S11cl and R-S11fv own the distinct
  cache-input/output transaction.
- **R-S11cl/R-S11e-104 — networked Gradle acquisition-output authority — CURRENT REAL PRODUCER AND
  PUBLICATION EXECUTED; CLEAN REUSE/FINALITY GREEN; FAILURE NEGATIVES AND EXACT COLD RELEASE OPEN.**
  Platform: the unprivileged Linux acquisition host and Android cache-warming container. Endpoint/action:
  `scripts/online-fetch.sh::stage_gradle` populating Gradle User Home while the complete Android SDK remains
  immutable. Boundary: network/dependency-controlled build execution ↔ the complete pinned offline-input
  closure and durable cache publication.

  Current source at `a73040d8dda104f1493e1e3cb97c2a3855f379b1` further narrows the historical topology below:
  dependency-controlled Gradle writes only one guest-local private producer tree, never the durable candidate;
  trusted transaction code validates and imports the quiescent tree after exit. JVM archive inputs that failed
  memory mapping over virtiofs are exact guest-local projections of the Android SDK and
  `rustls-platform-verifier-android` Maven repository, shadow-mounted read-only at their canonical paths and
  revalidated with the canonical sealed sources after the producer. R-S11fv records the current execution.

  Before this slice the producer still received `$ONLINE_DIR` read-write at `/online`. Its two
  legitimate outputs were `/online/gradle-home` and additions to `/online/android-sdk`, but the same
  mount gave it write/delete authority over every unrelated Cargo/Pub cache, NDK, vcpkg/native tree,
  toolchain archive, builder image archive, and Windows input. R-S11cj's numeric non-root container
  reduced that authority to the invoking user; it did not make the 25+ GB input closure an admissible
  output mount. This is source-proven build-input/output-publication authority, not evidence that a
  cached input changed, a container escaped, host root was acquired, a listener was exposed, host
  RustDesk/service/firewall/network state changed, exploitation occurred, or the host was compromised.

  `online-fetch.sh` now creates or normalizes the canonical online root to current-user-owned mode
  0700 and holds a nonblocking exclusive lock on that exact directory for the complete Gradle
  transaction. It reconciles every reserved stale transaction before treating an existing cache as
  complete. A cold run creates an unpredictable mode-0700 staging root on the online filesystem,
  stable-reads and privately clones the current-user-owned staged Android SDK, creates a distinct
  empty Gradle home, and records the exact online/staging/original-SDK/staged-SDK/staged-Gradle
  identities plus the SDK content digest in a bounded mode-0600 fsynced state record outside both
  container mounts. Historical complete root-owned SDK output is accepted only by the non-mutating
  legacy completeness check; a new transaction never adopts foreign-owned output that it could not
  later retire without privilege.

  The producer now receives the complete online root only as
  `readonly,bind-recursive=disabled`. Its only writable host mounts are the two exact private children
  at `/outputs/gradle-home` and `/outputs/android-sdk`. The shared Android build program accepts those
  exact paths only for `APK_MODE=warm`, rejects either internal environment variable in offline and
  rust-check modes, and directs `GRADLE_USER_HOME`, `ANDROID_HOME`, and `ANDROID_SDK_ROOT` to those
  mounts while all Pub, Cargo, NDK, vcpkg, toolchain, and other inputs remain under read-only
  `/online`. The wrapper now carries Gradle's publisher-listed SHA-256
  `fe696c020f241a5f69c30f763c5a7f38eec54b490db19cd2b0962dda420d7d12` for the complete
  7.6.4 distribution, and `pins.env` supplies the same independent validator input.

  `scripts/online-gradle-output.py` rehashes the live SDK after the producer stops and rejects a
  mismatch. It rejects a noncanonical or descendant-mounted tree, symlink, special file, multiply
  linked regular file, foreign owner, group/world-writable published state, excess depth/count/bytes,
  unstable read, or changed root identity. It normalizes only private output modes. Semantic
  postconditions require the Gradle dependency module cache, exactly one pinned wrapper ZIP with the
  publisher checksum and one extracted executable, plus the pinned Android build-tools revision,
  `aapt2`, `apksigner`, `zipalign`, compile-SDK `android.jar`, and `adb`. Producer, source,
  output, and publication verdicts remain independent; no candidate is published unless the first
  three are all green.

  Before publication every staged file and directory is fsynced. Descriptor-relative Linux
  `renameat2` first uses `RENAME_EXCHANGE` to atomically replace the nonempty SDK, then
  `RENAME_NOREPLACE` to install the absent Gradle home without clobbering a race; both namespace
  directories are fsynced after each step. A second-step or final identity/semantic failure moves the
  Gradle tree back and exchanges the SDK back. Restart recovery classifies only exact recorded/live
  inode arrangements: unpublished staging is retired, SDK-only publication is rolled back, and a
  complete two-name commit is retained. Unknown state is preserved and fails closed. Exact
  owner/mount-bound directory traversal restoration and the established external-inode-closure
  remover retire the reconciled private staging.

  The design follows the primary contracts rather than inferring publication behavior from a
  successful build. Docker documents that bind mounts are writable by default, that `readonly`
  removes write authority, and that recursive bind behavior is independently configurable:
  https://docs.docker.com/engine/storage/bind-mounts/. Gradle documents Gradle User Home as the
  location of caches and downloaded distributions, and separately documents the constraints on a
  shared read-only dependency cache:
  https://docs.gradle.org/current/userguide/directory_layout.html and
  https://docs.gradle.org/current/userguide/dependency_caching.html. Android documents both
  `sdkmanager` package installation and Android Gradle plugin auto-download of missing SDK
  packages:
  https://developer.android.com/tools/sdkmanager and
  https://developer.android.com/studio/intro/update.html. Gradle's publisher checksum page supplies
  the 7.6.4 all-distribution identity:
  https://gradle.org/release-checksums/. Linux documents `RENAME_EXCHANGE` and
  `RENAME_NOREPLACE` as atomic same-filesystem rename operations, while `fsync(2)` requires an
  explicit directory fsync for durable directory entries:
  https://man7.org/linux/man-pages/man2/renameat2.2.html and
  https://man7.org/linux/man-pages/man2/fsync.2.html.

  The executable transaction self-test in the immutable verifier image covers normal two-tree
  publication, completed-transaction recovery, SDK-only rollback, no-clobber destination racing,
  publisher-checksum rejection, and symlink rejection. The focused Gradle-output gate passes and
  rejects all 30 deliberate mutations; the adjacent exact-source gate rejects all 34; and the
  existing acquisition-container gate rejects all 29. The independent workspace verifier passes
  normally and with its complete in-memory source-mutation catalog after that catalog exposed and
  closed missing exact-operation and exact-mount-source bindings. Dependency inventory normal/self-test passes.
  Offline image
  provenance and the Android source comparator self-tests, native-codec normal/mutation checks,
  Bash/Python syntax, requirements-hash equality at
  `6a7246105673a29b1ce698fd7c6de607c0dd83ae9d0faacc68481d77466c1819`, and diff hygiene pass.
  A disposable exact-mount-topology negative probe also proved that the non-root producer cannot
  hardlink a read-only input into either separately mounted writable output: `link(2)` failed with
  `EXDEV`, the input link count remained one, and no output edge appeared.

  Executable checks used immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as UID/GID 1000:1000 with no pull or network, read-only root/source, all capabilities dropped,
  no-new-privileges, bounded resources, no Docker socket, no port, and no host namespace. The full
  shared verifier was not run because it includes out-of-scope privileged/runtime fixtures; a real
  networked Gradle acquisition was also not run, so this is source, transaction, negative-fixture,
  and authority-boundary evidence rather than cold acquisition-output reproduction. No networked
  acquisition, image pull/build/tag, release build, or host
  RustDesk/service/listener/firewall/network operation was executed for this source slice. R-S11cm/
  R-S11e-105 immediately following closes the two Cargo-installed tool outputs. The Pub output is
  closed by R-S11cn/R-S11e-106 below, and the libyuv single-file archive is closed by
  R-S11co/R-S11e-107 below, and both x64-linux/arm64-android vcpkg native outputs are closed by
  R-S11cp/R-S11e-108 below. The SDK producer and the Gradle SDK-write/publication path are
  superseded and closed by R-S11cr/R-S11e-110 below; other archive producers and host-side acquisition
  and maintenance candidate-image publication, exact cold R-B2 artifacts, native/device evidence,
  and external R-V3 review remain open.
- **R-S11cm/R-S11e-105 — networked Cargo-tool acquisition-output authority — CURRENT
  NUMERIC-NONROOT FILESYSTEM TRANSACTION GREEN 2026-09-12; COLD ACQUISITION AND RELEASE EVIDENCE
  OPEN.** The closed FRB/cargo-ndk producer funnel still gives each pinned builder read-only access to
  `online` and exactly one private writable Cargo-install root. Exact package, version, feature,
  binary, target, profile, Rust-archive, pre/post-input, and independent publication-verdict bindings
  remain in force.

  A follow-up audit found that the first publication helper did not implement the recovery promise it
  documented. Its v1 state was durable before producer bytes existed but contained no verified digest
  or publication-selection phase. `recover()` then classified the recorded inode as published solely
  because it appeared under `frb-tool` or `cargo-ndk-tool`; it neither validated the tree nor proved
  that publication had been selected. `online-fetch.sh` subsequently ran `check-complete`, so malformed
  bytes still failed closed, but recovery had already discarded the transaction distinction and could
  accept a manually moved, semantically valid yet unselected tree. New current-user-owned outputs also
  remained owner-writable after publication. This was transaction finality, durability, and immutable-
  input correctness debt—not evidence of exploitation, host root, a container escape, a listener,
  host RustDesk/service/firewall/network mutation, or compromise.

  The v2 state now starts explicitly `unselected` with no digest. Post-producer verification normalizes
  the current-user-owned tree to a private mode-0700 root, mode-0500 descendants/executable, and
  mode-0400 Cargo metadata; rejects foreign ownership, mounts, links, special files, xattrs, unsafe
  modes, unstable reads, excess bounds, noncanonical metadata, or a wrong ELF; and computes a domain-
  separated path/type/mode/content digest. Every file and directory is fsynced and the candidate is
  revalidated before a replacement state record durably selects that digest. Only that selection may
  precede `renameat2(RENAME_NOREPLACE)`. Publication changes the root to mode 0500, fsyncs the output and
  both namespaces, and revalidates the exact identity, digest, modes, and semantics. Rollback returns
  only that inode to private mode without clobbering.

  Recovery now distinguishes authority from topology. A selected private tree is accepted only after
  exact digest/semantic validation; a selected tree interrupted after rename is validated in mode 0700,
  sealed to 0500, fsynced, and validated again. A changed selected tree, ambiguous topology, moved
  unselected tree, or moved legacy-v1 tree is preserved and rejected. A preparation interrupted before
  a state record may retire only its still-private output. Existing root-owned complete tools remain
  non-mutatingly checkable; new current-user-owned tools have one exact sealed form.

  The current executable self-test passed for both tool kinds in a networkless, read-only-root,
  capability-free, no-new-privileges container as numeric UID/GID 1000:1000. It performs real temporary-
  filesystem writes, fsyncs, renames, mode transitions, rollback cleanup, and tampering, covering normal
  publication; selected pre-rename and post-rename recovery; moved-unselected and moved-v1 refusal with
  preservation; selected digest change; exact final modes; occupied destination; wrong metadata;
  symlink, external hardlink, xattr, and set-id rejection; and interrupted preparation. The compact
  focused source contract also passed, binding only the producer envelope and validate-sync-select-
  rename-seal-postcheck order. The obsolete 36-string mutation catalog and 289-line duplicate workspace
  verifier were deleted; they did not observe the transaction behavior and had missed this defect.
  Host listening sockets were identical before and after each confined run.

  No networked Cargo installation, online-cache mutation, image pull/build/tag, release build, root
  command, or host RustDesk process/service/config/listener/firewall/network operation was performed.
  Cold acquisition with the exact pinned builders, reproducible tool-binary provenance, exact release
  artifacts, native/device evidence, and external R-V3 review remain open.
- **R-S11cn/R-S11e-106 — networked Pub-cache acquisition-output authority — SOURCE AND
  CURRENT NUMERIC-NONROOT FILESYSTEM SELF-TEST GREEN; CURRENT SEALED CACHE/OFFLINE-REPLAY
  EVIDENCE RETAINED; COLD ACQUISITION, CANONICAL REPLACEMENT, AND RELEASE EVIDENCE OPEN.**
  Platform: the unprivileged Linux acquisition transaction and its immutable networked/offline
  builders. Endpoint: `scripts/online-fetch.sh::stage_pub_cache` and
  `scripts/online-pub-cache-output.py`. Boundary: networked Pub archive/Git processing ↔ exact
  committed source and pinned Flutter inputs ↔ one durable structurally and semantically closed
  `online/pub-cache`.

  The transaction exclusively locks the current-user-private online root and reconciles reserved
  staging before reuse or production. The producer sees the exact source and complete online closure
  read-only and receives one writable durable path: a same-filesystem private candidate mounted at
  canonical `/online/pub-cache`. It runs as numeric nonroot in the bounded no-port/no-host-namespace
  acquisition profile, enforces both committed lockfiles, proves them unchanged, and removes only the
  declared ephemeral Pub entries. Existing and new caches undergo the same bounded stable no-follow
  owner/mount/link/symlink/type/mode/xattr/path checks, exact hosted/hash/advisory inventory, and
  current three-checkout/three-bare-cache shape.

  A separate networkless immutable-builder pass mounts cache and source read-only, resolves both
  lockfiles offline with enforcement, and binds all three Git package/ref/path/URL mappings, clean
  trees, allowed modes, package identities, locked commits, and full checkout/bare object closure.
  The normalized candidate and staging parent are synchronized before state v3 durably selects
  publication. New publication uses descriptor-relative `RENAME_NOREPLACE`, seals only the exact
  candidate root, synchronizes the namespace, and revalidates identity, digest, and shape. Recovery
  accepts an unselected candidate only while it remains private, validates and seals an exact
  journal-selected post-rename candidate, and preserves incoherent or moved-unselected state.
  Occupied stale replacement follows the additional R-S11fy preservation contract.

  Exact-current execution in immutable local Python image
  `sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`
  as UID:GID 1000:1000 passed the production filesystem self-test and focused baseline. The same
  networkless, read-only-root/repository, capability-free, no-new-privileges, bounded profile then
  rejected all 65 focused deliberate mutations. Both runs used private noexec tmpfs, no port,
  device, Docker socket, privileged flag, or host namespace, and left the host listener inventory
  unchanged. The duplicate workspace Pub validator/mutation copy was deleted; it provided wording
  redundancy, not an additional behavioral layer.

  Retained operational evidence remains narrower than cold acquisition: the current sealed
  three-Git cache digest `fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4`
  passed both exact offline enforced-lockfile resolutions and three Git checks in R-S11gc, and the
  named R-B10 acquisition reaccepted it rather than rebuilding or replacing it. No current cold
  network acquisition, root-owned displaced-tree metadata-drift VM case, real canonical Pub-cache
  replacement, clean release artifact, Android/Windows/macOS device behavior, cross-version run,
  sustained performance/resource soak, independent reproduction, or external review is established.
- **R-S11co/R-S11e-107 — networked libyuv distfile output authority — SOURCE AND
  TRANSACTION SELF-TEST, EXACT-CACHE COMPATIBILITY, AND FOCUSED/INDEPENDENT MUTATION
  EVIDENCE VERIFIED 2026-07-24; COLD NETWORK ACQUISITION AND RELEASE EVIDENCE REMAIN OPEN.**
  Platform: the unprivileged Linux acquisition host and immutable Debian-builder container. Endpoint/action:
  `scripts/online-fetch.sh::stage_vcpkg_distfiles`, which fetches one pinned libyuv Git commit and
  publishes its deterministic tar/gzip distfile. Boundary: remote Git/archive processing ↔ the
  complete offline-input closure and durable `online/libyuv-<commit>.tar.gz` name.

  Before this slice the networked producer bind-mounted the complete `ONLINE_DIR` read-write solely
  to write one final archive. Its Git fetch/clone/archive/gzip process therefore inherited the
  invoking user's write/delete authority over every unrelated Cargo, Pub, SDK, NDK, vcpkg, native,
  Windows, toolchain, and builder input. It wrote the permanent name directly and performed only an
  in-container SHA-512 check afterward. R-S11cj's immutable numeric-nonroot execution removed
  container-root authority but did not make that broad writable bind or direct final-name
  publication admissible. This is source-proven acquisition-output/publication authority debt, not
  evidence that a cached input changed, a container escaped, host root was acquired, a listener was
  exposed, host RustDesk/service/config/firewall/network state changed, exploitation occurred, or
  the host was compromised.

  The libyuv stage now holds a nonblocking exclusive lock over the canonical current-user-private
  online root and reconciles every reserved `.rustdesk-libyuv-distfile.*` transaction before
  inspecting the final name. A cold run creates unpredictable mode-0700 same-filesystem staging.
  `scripts/online-libyuv-distfile-output.py` pre-creates one mode-0600 regular output file and writes
  a bounded, mode-0600, fsynced state record that binds the exact online/staging/output identities,
  UID/GID, full lowercase commit, lowercase SHA-512, and final destination. The networked container
  receives no online-root, source-tree, directory, or final-name mount. Its only writable host
  object is that pre-created inode at `/outputs/libyuv.tar.gz`.

  The producer retains the immutable Debian builder and the R-S11cj no-pull/nonroot/read-only-root/
  capability-free/no-new-privileges/resource-bounded acquisition floor. It fixes the HTTPS libyuv
  origin, excludes system/global Git configuration and replacement objects, disables hooks and
  external attributes, proves the exact named object is a commit, archives that full commit, uses
  `gzip -n`, and verifies the pinned SHA-512 before exit. The host independently validates the
  recorded output inode even if the producer fails: same filesystem, current ownership, exact mode,
  regular type, single link, no extended attributes, nonempty bounded stable read, and exact
  SHA-512. Success seals the candidate mode 0400.

  Producer and output verdicts remain independent. Only both green permit publication. The file and
  staging namespace are fsynced before descriptor-relative `renameat2(RENAME_NOREPLACE)` installs
  the still-absent exact final name; both directories are fsynced and the live identity, mode, and
  digest are rechecked. A later failure moves that exact inode back without clobber. Restart
  recovery accepts only bounded unprepared, unpublished, occupied-destination, or exact-published
  arrangements; every incoherent arrangement is preserved. Exact owner/mount-bound directory-mode
  restoration and external-inode-closure removal retire reconciled staging. An existing output is
  not presence-trusted: it receives the same complete validation. Historical root-owned mode-0644
  output is accepted only with root:root ownership, one link, no xattrs, same filesystem, bounded
  stable bytes, and the exact digest; new output is necessarily current-user-owned mode 0400.

  The current cached archive was inspected read-only: it is a 566,889-byte root:root mode-0644
  single-link regular file with SHA-512
  `be6b343ab6c62e8f2d1571fedf25f5facbf7cd7fe8e1cc4949dab7549ad15f962c91ea43bf567785e54382d7689514f6b66d61bd56b3f38ba54ef51c5fd0da9b`.
  It was not chmodded, copied, replaced, removed, or otherwise changed. The executable transaction
  self-test passed in immutable verifier image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as UID/GID 1000:1000 with no pull/network, read-only root/script, zero capabilities,
  no-new-privileges, and bounded resources. It covers successful publication/recovery,
  wrong-digest rejection, occupied-destination no-clobber behavior, symlink, external-hardlink,
  extended-attribute rejection where supported, empty pre-state preparation, and a process
  interruption while the temporary state record is being written. A separate disposable
  production-shaped probe prepared the recorded candidate through the helper container, gave exact
  Debian-builder image
  `sha256:6766564c65b0daead7d7031fcf0ff9ec8becab6ef9e3f9a7efd9f02f1b893776`
  only that pre-created file under the full nonroot/networkless/read-only-root runtime floor, and
  then used the helper container to validate, seal, publish, and recheck it. The result was the exact
  current-user-owned mode-0400 final file; the complete disposable host fixture was removed.

  Exact historical-cache compatibility was then exercised without modifying the real archive. The
  first disposable probe mounted the real file below a private tmpfs online root; the helper
  correctly rejected that artificial cross-filesystem topology before digest acceptance. A second
  disposable current-user-owned mode-0700 online root was created on the same host filesystem, with
  an empty same-name placeholder overlaid read-only by the real archive at the exact final path.
  `check-complete` accepted the real root:root mode-0644 inode and exact digest. The disposable
  fixture and placeholder were removed; the real archive remained read-only throughout.

  `scripts/verify-online-fetch-libyuv-output-authority.py` binds the fixed image/pins/origin,
  complete transaction and no-online-mount topology, Git object/archive/gzip/digest command,
  independent verdict barrier, helper metadata/durability/recovery invariants, shared gate,
  R-S11co, Appendix C #242, this ledger, and independent workspace ownership through deliberate
  mutations. It passes and rejects all 27 focused mutations; the workspace validator passes
  normally and its complete source-mutation matrix rejects the independent libyuv mutations.
  Adjacent online-container, Gradle-source, Gradle-output, Cargo-output, and Pub-output gates reject
  30, 38, 30, 36, and 40 mutations respectively. The dependency inventory normal/self-test passes.
  Native-codec normal/self-test,
  Bash/Python syntax, requirements HTML parsing, requirements hash
  `db631b7b58f70c331c1dab21d0219afbaeab094e90559735f27c13c83bb760ce`, and diff hygiene pass.

  No real networked Git acquisition was run, so this is source and negative transaction evidence
  rather than cold acquisition reproduction. Both x64-linux and arm64-android vcpkg native
  producers are closed by R-S11cp/R-S11e-108 immediately below, and Android NDK extraction is
  closed by R-S11cq/R-S11e-109 after that. Host-side downloads, Android SDK extraction, Windows
  archive packagers, maintenance
  candidate-image publication, exact cold R-B2 artifacts, native/device evidence, and external
  R-V3 review remain open. No online acquisition, image pull/build/tag, release build, root command,
  or host RustDesk process/service/config/listener/firewall/network operation was executed for this
  slice.
- **R-S11cp/R-S11e-108 — networked vcpkg native output authority — SOURCE AND REAL
  FILESYSTEM TRANSACTION HARDENING IMPLEMENTED 2026-09-12; COLD NETWORK REBUILD, RELEASE
  ARTIFACTS, NATIVE/DEVICE EVIDENCE, AND EXTERNAL REVIEW REMAIN OPEN.** Platform: the
  unprivileged Linux acquisition host and immutable Debian/Android builder containers.
  Boundary: networked vcpkg execution ↔ pinned offline inputs and durable
  `online/vcpkg/installed/{x64-linux,arm64-android}` consumer trees.

  The original builders mounted the complete online cache read-write, could replace either
  architecture's final tree, presence-trusted a libvpx-only marker, and retained unconsumed vcpkg
  output. The hardened lifecycle instead keys the complete triplet/port/builder/vcpkg/libvpx/
  libyuv/overlay/NDK input closure; reverifies the archives; locks and reconciles kind-scoped
  staging; and gives each immutable numeric-nonroot producer read-only nonrecursive online/overlay
  mounts plus exactly one private writable `/outputs/native` tree. Disposable source, build,
  download, home, and binary-cache state stays in bounded container scratch. Publication contains
  only the exact consumed headers, five x86-64 archives or six AArch64 archives, and both receipts.

  The host helper independently enforces canonical same-filesystem mount-closed bounded traversal,
  current ownership, stable full reads, portable paths, exact inventories/receipts, and refusal of
  symlinks, special files, external hardlinks, set-id/sticky bits, xattrs, or group/world writes.
  Every archive is parsed with bounded framing and must contain canonical 64-bit little-endian
  relocatable ELF objects for exactly x86-64 or AArch64. Files and directories are sealed 0400/0500
  and synchronized.

  The prior v1 journal recorded the candidate inode and input recipe but not whether validated
  output had been selected or what bytes were selected. Recovery could therefore accept a
  changed-but-still-structurally-valid tree after its inode reached the final path. The v2 journal
  starts explicitly `unselected` with no digest. After sealing and synchronization, the helper
  derives and revalidates a domain-separated, path/type/content-framed full-tree SHA-256, atomically
  records `selected` plus that digest, reloads the durable state, and revalidates the same inode
  and digest before descriptor-relative `renameat2(RENAME_NOREPLACE)`. An identity-bound directory
  descriptor changes only the exact root from private 0700 to final 0500; output and both namespace
  directories are synchronized and the exact bytes, identity, shape, ownership, modes, receipts,
  archive framing, and ABI are postchecked. Later failure restores the exact root to 0700 and
  rolls that inode back without clobber.

  Recovery safely retires still-private legacy/unselected candidates but refuses and preserves a
  moved v1 or unselected inode because neither state selected produced bytes. A selected private
  candidate must match its recorded digest. A selected inode moved before its root was sealed must
  match the digest while still mode 0700, is then descriptor-sealed to 0500 and synchronized, and
  must match again before classification as published. Changed, ambiguous, wrong-mode, or
  wrong-topology state is preserved. A bounded interrupted state replacement beside an unchanged
  unselected private candidate is classified for safe retirement. The helper rejects UID or GID 0.

  Historical root-owned final trees remain non-mutatingly admissible only through the exact legacy
  owner/mode/mount/link/xattr/type/path/size/archive checks and a frozen pair of current output key
  plus legacy full-tree digest. The allowlist remains empty. The observed x64 and Android trees
  carry stale libvpx receipt
  `2f1a0d9ec38bec3b32c2154a752119c3240c9944ab0ce1c4dfaf91e6a4bfac23`; their measured legacy
  digests `4fbb47ef3e8cdd79f96697e9650fc3a31e368dd38a54aa3af372bb5e59b0fa46` and
  `913588e8746761275c3115279789e1590bff9af614072882c09e5fc827e4ad55` remain denial evidence,
  not provenance. Acquisition rejects them without chmod, deletion, or replacement.

  The executable helper self-test and the 282-line focused source-contract gate pass in immutable
  image `sha256:e064e6c140869235533eb855191f9ac0f4be112e690012a15d4e80413589c518` under
  `--network=none`, no ports, numeric nonroot, read-only root/repository, zero capabilities,
  no-new-privileges, bounded CPU/PIDs/memory, and private noexec scratch. Actual filesystem cases
  cover both triplets, exact 0400/0500 publication, owner-writable refusal, wrong ABI/malformed ELF,
  inventory/symlink/hardlink/xattr refusal, no-clobber, unprepared and interrupted-state recovery,
  moved-unselected and moved-v1 preservation, selected pre/post-rename recovery, semantically
  admissible byte change after selection at the final path, and injected postpublication failure
  with exact rollback.
  The redundant 895-line focused mutation harness and 405 lines of duplicated workspace
  vcpkg checks/mutations/loaders were deleted; the real filesystem test remains primary and the
  focused gate retains only load-bearing source wiring. The ordinary workspace gate correctly
  rejected the intentionally stale requirements hash after the normative edit, then passed after
  the new hash was synchronized. Python AST, Bash syntax, requirements HTML parsing, exact hash
  binding, `git diff --check`, and the status-size gate pass below its 400,000-token budget.

  No cold/networked vcpkg build, image pull/build/tag, release build, root command, host RustDesk
  process/service/config/listener/firewall/network action, or cache mutation occurred. Android NDK
  extraction is tracked by R-S11cq immediately below. Other acquisition producers, exact cold
  R-B2 artifacts, native/device evidence, and external R-V3 review remain open.
- **R-S11cq/R-S11e-109 — Android NDK extraction and output authority — SOURCE AND
  ADVERSARIAL FILESYSTEM TRANSACTION IMPLEMENTED; EXACT-CURRENT FULL PINNED-ARCHIVE, COLD
  ACQUISITION, RELEASE, AND DEVICE EVIDENCE OPEN.** Platform: the unprivileged Linux acquisition
  host and immutable Android-builder container. Endpoint: `stage_android_ndk` publishing the exact
  r28c archive tree to `online/android-ndk`. The transaction refuses root ownership, verifies the
  archive and immutable builder, serializes on the private online root, reconciles reserved state,
  and fully validates rather than presence-trusts an existing final tree.

  A cold producer receives only the exact archive and extraction helper read-only plus one private
  writable output. It is networkless, non-root, read-only-root, capability-free,
  no-new-privileges, resource-bounded, and has no repository/online/final-name/host-root/socket/
  device/port or host-namespace authority. The helper enforces the closed r28c ZIP root, revision,
  type/mode/compression/path/count/size and internal-symlink graph; extracts with explicit parents
  and exclusive no-follow files; then independently proves exact inventory, ownership, mount/link/
  xattr closure, symlink targets, and every regular-file byte. Only a sealed, synchronized candidate
  whose inode and archive-derived tree digest were durably marked verified may be published by
  descriptor-relative no-clobber rename.

  Current recovery also covers the actual rename/root-seal crash window. A verified tree moved to
  the final name at private root mode 0700 is first revalidated against its journaled inode, exact
  archive bytes, sealed inner modes, and tree digest; only then is that same open directory changed
  descriptor-wise to 0555, synchronized, and fully revalidated. Publication uses the same
  descriptor-bound transition. Failure restores only that exact inode to private mode before
  no-clobber rollback; unverified, changed, substituted, ambiguously placed, or wrongly moded state
  remains preserved. The real filesystem self-test covers ordinary publication, occupied
  destination, prepublication validation failures, archive/path/symlink/type/inventory/byte/
  hardlink/xattr failures, interrupted state writes, the post-rename/pre-seal recovery, and refusal
  of a changed moved tree. A confined same-fixture A/B against parent
  `94a2143958bcb6a9f3500eb0897ae6c4deaa8788` left the old helper refused at mode 0700 while the
  current helper returned `published-after-root-seal` for the same crash point and committed the
  exact inode at mode 0555.

  Historical commit `6449cd777baac08f0480fffe7229d769e3722c5a` ran the then-current complete
  722,261,334-byte pinned archive through disposable non-root/networkless extraction and publication
  and found the established writable cache tree stale due to 27 generated Python-cache entries.
  That named result does not validate this later recovery correction or current release source. The
  exact pinned images and sealed `online/` inputs are absent now, so no exact-current full-archive
  run, cold fetch, package build, or Android installation/lifecycle result is claimed.

  R-S11cq and Appendix C #244 now contain only the timeless contract and risk disposition; their
  failure diary, `FIX` badge, mutation count, and run receipt were removed. The focused checker is a
  small load-bearing source contract, while its mutation catalog, documentation coupling, and the
  workspace verifier's duplicate validator/loaders/mutations were deleted. The executable
  filesystem transaction self-test remains authoritative for the behavior it actually exercises.
  Android SDK acquisition, maintenance-image publication, exact cold R-B2/R-B10 artifacts, native
  device behavior, independent reproduction, and external R-V3 review remain open.
- **R-S11cr/R-S11e-110 — exact Android SDK acquisition and publication authority — SOURCE
  CORRECTION IN PROGRESS 2026-08-04; ADVERSARIAL TRANSACTION AND EARLIER CLOSURE EVIDENCE RECORDED;
  CORRECTED DISPOSABLE ACQUISITION, EXACT CLEAN RELEASE, AND DEVICE EVIDENCE REMAIN OPEN.** Platform: the
  unprivileged Linux acquisition host and immutable Android-builder container. Endpoint/action:
  `scripts/online-fetch.sh::stage_android_sdk` and the downstream `stage_gradle` warm-cache
  transaction. Boundary: remote Android repository resolution and dependency-controlled Gradle
  execution ↔ the complete offline-input cache and the durable exact SDK name.

  Before this slice, `stage_android_sdk` treated `sdkmanager` package paths as content pins. It
  requested moving `platform-tools`, `build-tools;34.0.0`, and `platforms;android-34`, ignored a
  license-command failure, gave the networked resolver a writable mount of all `online`, recursively
  removed the prior SDK, and copied the resolver's broad mutable tree into the final name.
  Repository inspection proved that `platforms;android-34` currently occurs under multiple extension
  revisions, so the alias is not a stable byte identity. `stage_gradle` then cloned the SDK into a
  writable output and atomically exchanged that clone back into the final SDK. File transfer versus
  screen-control behavior in the Android runtime is unrelated to this build-harness finding; this
  slice changes no host or mobile RustDesk process, service, configuration, listener, firewall, or
  network state.

  `scripts/pins.env` now records exact SHA-256 values for seven fixed Google repository archives:
  `platform-tools_r37.0.1-linux.zip`, `build-tools_r30.0.3-linux.zip`,
  `build-tools_r34-linux.zip`, `platform-31_r01.zip`,
  `platform-32_r01.zip`, `platform-33-ext3_r03.zip`, and `platform-34-ext7_r03.zip`. Each record
  also carries the exact byte length and independently checked official repository XML SHA-1 in its
  provenance comment. The existing command-line-tools revision-21 archive remains the seventh exact
  input. The final closure intentionally omits the moving `platform-tools` alias, resolver licenses,
  `.temp`, `.knownPackages`, and generated `package.xml` files; it includes only the fixed exact
  platform-tools 37.0.1 archive.

  `stage_android_sdk` now exclusively locks the canonical current-user-private online root,
  reconciles every `.rustdesk-android-sdk.*` transaction, and fully checks a present final tree
  rather than presence-trusting or deleting it. A cold run creates unpredictable mode-0700
  same-filesystem staging with separate `downloads` and `output` children. The bounded fsynced
  transaction record binds the exact online/staging/container/archive identities, UID/GID, complete
  pin map, immutable builder, destination, verification phase, candidate inode, and tree digest.
  Every command rejects UID or GID 0.

  The new networked archive-acquisition funnel keeps the fixed Docker client, fixed local socket,
  and private empty Docker configuration. It uses the already loaded immutable Android builder with
  `--pull=never`, isolated bridge egress, read-only root, numeric UID:GID, zero capabilities,
  no-new-privileges, fixed PID/memory/no-swap/CPU ceilings, and bounded non-executable scratch. The
  producer receives exactly four mounts: the command-line ZIP and exact helper read-only, plus only
  the private downloads and SDK-output directories writable. It receives no online root, final
  name, repository, Docker socket, device, published port, or host network/PID/IPC/UTS namespace.

  `scripts/online-android-sdk-output.py` downloads only the seven fixed filenames from
  `https://dl.google.com/android/repository/`. It rejects redirects, non-200 status, transformed
  content, absent or wrong lengths, per-file/aggregate excess, and SHA-256 mismatch; creates every
  file exclusively; synchronizes it; and never executes an archive. Its ZIP contract binds each
  exact length, digest, entry count, root, destination, Unix mode set, and observed general-purpose
  flag set. It rejects comments, unsupported flags/compression, NUL truncation, non-ASCII or
  absolute/traversing/deep/long names, duplicates, special/set-id/sticky members, size/count
  overflow, and cross-package collisions. Extraction creates explicit directories and
  `O_EXCL|O_NOFOLLOW` regular files and normalizes only the archive-derived executable bit.

  After the producer stops, the host reopens and rehashes all eight archives, requires exact output
  inventory and same-filesystem/mount closure, current ownership, raw modes, no symlink, special
  object, xattr, or external hardlink, and equality of every regular-file byte with a fresh archive
  stream. Consumer semantics require command-line tools revision 21 and executable `sdkmanager`,
  fixed platform-tools revision 37.0.1 with executable nonempty `adb`, both exact build-tools
  revisions with `aapt2`, `apksigner`, and `zipalign`, and platforms 31–34 with their exact API-level
  property and `android.jar`. The normalized complete tree is independently
  bound at SHA-256
  `f7fa90b41ea168fc385f46e9c5f48f3cee28bddddd44abd5036d97d17a72fd2b`,
  43,480 files, 11,295 directories, and 898,205,722 regular-file bytes. Every file and inner
  directory is sealed 0444/0555 and synchronized before descriptor-relative publication. The
  candidate root stays private mode 0700 because Linux must update its `..` entry during a
  cross-parent directory rename. `renameat2(RENAME_NOREPLACE)` installs the absent final name, then a
  descriptor-bound exact-identity transition seals that root 0555 and synchronizes it before
  postcheck. Restart recovery independently revalidates every archive and output byte before
  completing only the exact recorded post-rename/pre-root-seal arrangement; postcheck, rollback, and
  exact private retirement bind every other inode arrangement.

  The established live `online/android-sdk` was inspected read-only and is intentionally not
  accepted: it is root-owned resolver output and contains moving/resolver state outside the exact
  archive closure. The new flow fails closed on it and tells the operator to retire it explicitly;
  it does not delete, replace, or chmod it. This is the same deliberate legacy-state rule used for
  the stale Android NDK output.

  The corrected Gradle warmer no longer clones or mounts an SDK output. Its sole writable durable
  mount is private `/outputs/gradle-home`; the exact SDK remains at read-only
  `/online/android-sdk`, and `RUSTDESK_ANDROID_SDK_HOME` is rejected in warm mode. The transaction
  records and rehashes the live SDK before warming, after the producer, after Gradle-home
  publication, and during recovery. Only Gradle home is synchronized and installed with
  `RENAME_NOREPLACE`; there is no `RENAME_EXCHANGE`, SDK rollback, SDK-only recovery, `adb`
  requirement, or SDK publication authority. This explicitly supersedes the writable-SDK-clone and
  two-name-publication portion of R-S11cl/R-S11e-104 while retaining its lock, wrapper checksum,
  structural/semantic, no-clobber Gradle, recovery, and private-retirement protections.

  Both transaction helpers pass their adversarial self-tests in the immutable Android builder as
  numeric non-root with no pull/network, read-only root/source, zero capabilities,
  no-new-privileges, and bounded resources. SDK fixtures cover exact publication/recovery, byte
  tampering, extra entries, external hardlinks, occupied destination, wrong archive digest,
  traversal, and exact post-rename/pre-root-seal recovery. Gradle fixtures cover one-name
  publication/recovery, SDK mutation, occupied destination, wrong publisher checksum, and symlink
  rejection.

  The earlier disposable networked proof used immutable Android-builder image
  `sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121`
  as UID:GID 1000:1000 with no pull, read-only root and exact input binds, no capabilities or
  privilege gain, no port/device/socket/host namespace, fixed resources, and container-only tmpfs
  outputs. It fetched the then-six exact network archives, verified their lengths and hashes,
  expanded the then-seven-package closure, compared all 43,468 files to those archives, and
  independently produced the former whole-tree digest. The tmpfs vanished with the container; no
  archive or SDK output was published to the host. The 2026-08-04 correction below supersedes that
  closure, so this earlier run is not acquisition or build evidence for the current eight-package SDK.

  `scripts/verify-online-fetch-android-sdk-output-authority.py` and the corrected Gradle focused
  verifier bind the exact pins, archive names/lengths, four-mount producer topology, runtime floor,
  network response checks, closed ZIP and byte/inventory/resource contract, independent tree
  closure, durable transaction, no-clobber publication, read-only Gradle SDK, shared gates,
  R-S11cr, Appendix C #245, this ledger, and independent workspace ownership through deliberate
  mutations. The adjacent container gate now treats the archive funnel as its own fourth Docker
  primitive and passes with 36 mutations rejected.

  No root command, image pull/build/tag, release build, host RustDesk process/service/config/
  listener/firewall/network operation, or live online SDK mutation occurred. The networked action
  was limited to the disposable container proof above. This is source, negative-fixture, exact
  archive, and complete temporary acquisition evidence—not exact clean R-B2/R-B10 release output or
  installed Android device evidence.

  Follow-up correction (2026-07-29), **R-S11cr/R-S11e-110 umask-independent raw SDK root authority**:
  the exact-output contract requires the producer's raw SDK root and every descendant
  directory to be mode 0755 before the verified tree is sealed. Descendant directories were
  explicitly normalized after creation, but the root used only `Path.mkdir(mode=0o755)`. Python
  applies the process umask to that requested creation mode, so an otherwise valid extraction under
  ambient umask 0077 created the root as 0700 and the helper's own raw-profile comparison correctly
  rejected it. This was a fail-closed availability and reproducibility defect in the build
  transaction, not a relaxation of validation, an SDK-content change, root execution, a container
  escape, a public listener, or a host RustDesk/service/firewall/network mutation.

  Extraction now no-follow normalizes the newly and exclusively created root to 0755 immediately
  after creation, matching the existing explicit normalization of every inner directory and file.
  The transaction self-test scopes umask 0077 around the real extraction call and restores the
  caller's previous mask in `finally`; it therefore exercises the production path rather than a
  mode-only surrogate. The focused verifier binds the exact normalization order, restrictive-mask
  fixture, and restoration through deliberate mutations. The shared R-S11cr gate executes both that
  behavioral self-test and the focused matrix, while the independent workspace verifier binds and
  source-mutates the helper, focused verifier, and this ledger. The normative R-S11cr text and
  Appendix C #245 already require exact raw modes independent of archive/extractor authority, so
  their existing requirements hash remains unchanged.

  Confined verification used cached immutable development image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as numeric UID:GID 1000:1000 with no pull or network, read-only root and repository, all
  capabilities dropped, no-new-privileges, bounded resources and non-executable scratch, and no
  port, device, socket, or host namespace. Under explicit umask 0077, the real transaction self-test
  passed, the focused authority verifier rejected all 42 deliberate mutations, the independent
  workspace baseline passed, and the complete unsliced independent source-mutation matrix passed.
  Two preceding full-matrix attempts correctly failed on new meta-verifier debt: first, the
  independent gate did not bind the focused verifier's exact 0755 assertion; second, its deliberate
  mutation expected the old diagnostic label. The independent assertion and mutation classification
  were corrected before the successful full rerun. No acquisition, release build, live SDK
  publication, or host/mobile runtime action was part of this evidence.

  Follow-up correction (2026-08-04), **R-S11cr/R-S11e-110 fixed platform-tools/Flutter SDK-recognition
  closure — SOURCE AUTHORED; CORRECTED ACQUISITION AND REAL-JNI APK BUILD PENDING**: the first
  real-JNI candidate build against the newly acquired exact SDK generated the Flutter bridge and
  completed the optimized ARM64 Rust library, then stopped before Gradle with `No Android SDK found`.
  Exact inspection of the independently SHA-256-pinned Flutter 3.24.5 source established the cause:
  `AndroidSdk.validSdkDirectory` accepts an SDK root only when it contains `licenses/` or
  `platform-tools/`, and the closure deliberately omits resolver license state. The dummy-JNI
  build-graph diagnostic had used the historical broad SDK, which contained platform-tools, and
  therefore concealed this acquisition defect. This is a build-input completeness failure, not an
  Android product-runtime failure and not evidence of host RustDesk/service/configuration/listener/
  firewall/network mutation.

  The corrected closure pins Google's stable `platform-tools_r37.0.1-linux.zip` by its official
  repository2-1.xml length 9,054,187 and SHA-1
  `477254aa5f903c15cf51001717bdf347fb6b53e0`, plus independently streamed SHA-256
  `d230f13842f60f782a8645f9c813f8f845bf36089ea7289f28c48f17979313f1`. Its exact twelve regular
  entries, root, modes, flags, compression, and 22,198,160 expanded bytes enter the existing closed
  archive contract; no moving package alias or resolver is reintroduced. Consumer semantics require
  `Pkg.Revision=37.0.1` and an executable nonempty `platform-tools/adb`. An independent virtual-tree
  calculation first reproduced the former sealed candidate identity exactly, then added only the
  fixed archive and derived the new normative closure:
  `f7fa90b41ea168fc385f46e9c5f48f3cee28bddddd44abd5036d97d17a72fd2b`, 43,480 files, 11,295
  directories, and 898,205,722 regular-file bytes. The transaction self-test fixture, focused pin/
  archive/consumer mutations, independent workspace bindings, R-S11cr, and Appendix C #245 are
  updated with the same requirement. The fresh exact acquisition, source comparison, real-JNI
  Gradle warm, networkless APK build, artifact inspection, and pinned-epoch payload comparison are
  recorded immediately below. Stable-key signed A/B release reproduction and device execution
  remain open.
- **R-S11fv/R-S11e-208 — Gradle publication/offline-seed mode closure — CURRENT CANONICAL FIRST
  PUBLICATION EXECUTED; CLEAN REUSE/FINALITY GREEN; COLD-RELEASE AND DEVICE EVIDENCE OPEN.** Platform: the unprivileged
  Linux acquisition transaction and immutable Android builder. Endpoint/action:
  `scripts/online-gradle-output.py::{verify_staged,publish,recover,check_complete}` and
  `scripts/android-gradle-cache.py::materialize`. Boundary: writable networked Gradle output ↔ one
  immutable networkless build seed.

  `verify_staged` admits only a private, bounded, mount/link/type/path/owner-closed candidate whose
  pinned wrapper, dependency cache, and read-only Android SDK semantics pass. `publish` seals every
  descendant to the consumer's exact 0500-directory and 0400/0500-file profile, rechecks content and
  semantics, synchronizes the tree before journal selection, and uses descriptor-relative
  `RENAME_NOREPLACE`. The exact root alone remains 0700 for the cross-parent rename; it is then
  identity-checked, descriptor-sealed 0500, synchronized, and completely rewalked. Recovery and
  rollback act only on the recorded inode topology; `check_complete` and the offline projector reject
  writable, permissive, or mixed seeds.

  The dependency-controlled JVM no longer executes against a virtiofs-backed writable output or directly
  memory-maps its SDK/Maven classpath archives through virtiofs. The transaction makes independently validated
  guest-local projections of the exact Android SDK closure (including the pinned command-line-tools archive for
  closure validation) and the `rustls-platform-verifier-android` Maven repository, then shadow-mounts only the
  SDK and Maven subtrees read-only at their canonical `/online` paths. The canonical inputs remain read-only.
  Gradle writes one different-filesystem guest-local producer root; only after exit does trusted code revalidate
  canonical and projected inputs, normalize and digest the quiescent output, import it into the still-unmounted
  durable candidate, require producer-before/import/producer-after/durable digests to agree, and publish.

  The current executable helper self-test creates real temporary filesystem transactions and covers
  successful publication and final modes, writable-root/file refusal, destination races, SDK/content
  mutation, symlink and checksum rejection, exact post-rename/pre-root-seal recovery, rollback, and
  sealed-old replacement crash boundaries. The focused static gate remains supplementary and protects
  the shell/helper/projector/pin ordering and absence of destructive or writable-input fallbacks. It no
  longer parses requirements/ledger prose, meta-checks test error strings, or requires a duplicate
  workspace validator; that duplicate validator, source loader, and mutation layer are deleted.

  Exact-source retained run `run.52py3CWymM` exercised this first-construction path at
  `a73040d8dda104f1493e1e3cb97c2a3855f379b1`: Android Rust release compilation finished in 4m31s,
  Gradle/Kotlin completed without either former `FileChannelImpl.map0`/`No such device` failure,
  `assembleRelease` built a 45.3 MiB ARM64 warm APK in 291.1 seconds, every projection retired, and the
  validated 4.1 GiB cache published. Its overall outer verdict remains invalid because the final inventory was
  missing one pre-existing `0.0.0.0:21128` listener that was present both before and during; it created no new
  listener. Separate run `run.hutLn5juYg` then revalidated the exact cache and completed the reuse path in 500
  seconds with joined cleanup and an unchanged 605-byte listener inventory whose hash exactly matches the first
  run's original baseline. These are current canonical warm-publication/reuse
  results, not a retained signed release artifact, cold R-B2/R-B10 A==B, replacement-path run, APK installation,
  Activity/persistent-service/task-swipe/Force-Stop/reconnect/presentation evidence, latency/resource soak,
  independent reproduction, or external review; all of those remain STOP-SHIP.

- **R-S11fw/R-S11e-209 — Linux X11 capture shared-memory authority — SOURCE IMPLEMENTED;
  RETAINED CONFINED KERNEL TEST EVIDENCE; REAL X SERVER AND RELEASE EVIDENCE OPEN.** The current
  `SharedMemory` owner rejects empty/overflowing sizes, creates an exact 0600 `IPC_PRIVATE` segment,
  establishes cleanup before its read-only local mapping, checks XCB attach acceptance, and marks the
  segment deletion-pending only after acceptance. Construction and drop retain exact detach/removal
  ownership and make failures visible. The checked bindings and the two serialized SysV behavior tests
  remain in the shared gate.

  Commit `b068ffcf` records the implementation and a clean Rust 1.75 numeric-nonroot, networkless
  container run proving effective-user ownership, exact 0600 mode, one local attachment, `SHM_DEST`,
  and final disappearance. The focused source checker remains a supplement; its documentation coupling,
  mutation catalog, and stale workspace reimplementation are deleted. A current isolated real-X run must
  still exercise acceptance/rejection/cleanup, actual capture-to-render, unauthorized-principal attempts,
  installed cross-user service behavior, current artifacts, cold reproduction, and independent review.

- **R-S11fx/R-S11e-210 — Linux X11 capture GetImage frame finality — SOURCE IMPLEMENTED;
  RETAINED PURE-BRANCH TEST EVIDENCE; REAL X SERVER, FRESHNESS, AND RELEASE EVIDENCE OPEN.**
  `get_image` uses the checked request and non-null protocol-error output, snapshots diagnostics before
  freeing both allocations, and rejects protocol errors, connection failure, missing replies, and any
  reply byte count other than the exact capture buffer. `frame()` propagates failure before reading or
  comparing shared bytes. The two pure result tests remain in the shared gate.

  Commit `e314d2b2` records the implementation and a clean Rust 1.75 numeric-nonroot, networkless
  container run covering exact success, size mismatch, preserved protocol diagnostics, connection
  failure, and missing reply. The focused source checker is supplemental and no longer treats prose or
  checker mutation strings as product evidence. A current isolated real-X run must still exercise the
  request/reply ABI, rejection and no-reply behavior, actual capture-to-codec-to-render, focus/background
  freshness and latency, reconnect, cross-version behavior, current artifacts, cold reproduction, and
  independent review.

  Current verification cleanup removed 468 checker lines: prose assertions and mutations from the focused checker,
  its self-mutation catalog, and the complete duplicate workspace implementation/load/dispatch path. The
  focused source check, workspace normal check, Python AST parse, Bash parse, HTML parse, requirements
  identity check, and diff hygiene are green. The workspace check now passes instead of failing on its stale
  blank-line parser assumption. No current Rust or X-server behavior was executed in this source-only cleanup;
  the retained confined runs above are historical, and every real-X/native obligation remains open.

- **R-S11fy/R-S11e-211 — stale canonical Pub-cache replacement authority — SOURCE
  CORRECTED; CURRENT NUMERIC-NONROOT FILESYSTEM CRASH/ROLLBACK TESTS AND 72-MUTATION FOCUSED
  GATE GREEN; ROOT-OWNED METADATA-DRIFT VM AND REAL CANONICAL REPLACEMENT OPEN.** Platform:
  the unprivileged Linux acquisition transaction. Endpoint:
  `scripts/online-fetch.sh::{stage_pub_cache,retire_pub_cache_output_staging}` and
  `scripts/online-pub-cache-output.py`. Boundary: an occupied immutable or root-owned stale cache
  ↔ one independently verified candidate, without destructive authority over the displaced tree.

  An occupied cache is reused unchanged only after complete structural and offline semantic
  validation. Otherwise the helper validates it without chmod, chown, normalization, deletion, or
  cross-parent movement. The normalized candidate and staging parent are synchronized before state
  v3 selects replacement. The durable record binds candidate and displaced identities/content
  digests, the displaced tree's exact UID/GID/mode digest, provenance, namespace-root identities,
  and deterministic reserved names. Legacy-v2 replacement state is preserved and rejected because
  it lacks that metadata commitment; safe legacy nonreplacement state is accepted only through the
  same exact candidate validation.

  The candidate is promoted with descriptor-relative `RENAME_NOREPLACE` to a reserved sibling under
  the locked online parent and then installed by same-parent `RENAME_EXCHANGE`. Only the candidate
  root transitions from 0700 to 0500. The displaced tree stays at the recorded sibling and is checked
  by inode, content, links, ownership, and modes before completion and around journal-only archival.
  Recovery accepts only exact prepared, promoted, exchanged-unsealed, or completed replacement
  topology. Nonreplacement recovery refuses a moved unselected inode; for selected new state it
  validates the exact private candidate or validates, seals, synchronizes, and revalidates the exact
  live post-rename inode. Rollback restores the old live name first and demotes only the candidate.

  The current real temporary-filesystem self-test passed ordinary new publication and replacement,
  selected pre-rename and post-rename/pre-seal recovery, moved-unselected refusal, promoted and
  exchanged recovery, rollback, safe legacy-v2 new recovery, legacy-v2 replacement refusal,
  mismatched displaced-metadata refusal, identity/content/metadata preservation, finality, and
  journal archival. The focused verifier rejected all 65 retained mutations. The confined profile
  and listener result are recorded in R-S11cn above. These results do not exercise a genuinely
  root-owned displaced tree, power-cut storage behavior, the live canonical cache, cold acquisition,
  release artifacts, target devices/VMs, cross-version behavior, sustained resource/performance
  bounds, independent reproduction, or external review; all remain open where applicable.
- **R-S11fz/R-S11e-212 — stale occupied canonical Gradle-cache replacement — SOURCE IMPLEMENTED;
  CURRENT NUMERIC-NONROOT FILESYSTEM SELF-TEST GREEN; OLDER REAL APK AND V3 CANONICAL
  EVIDENCE RETAINED; CURRENT V4, COLD-RELEASE, AND DEVICE EVIDENCE OPEN.** Platform: the unprivileged Linux
  acquisition transaction and immutable Android builder. Endpoint/action:
  `scripts/online-fetch.sh::{stage_gradle,retire_gradle_output_staging}` and
  `scripts/online-gradle-output.py::{validate_displaced_output,replace,finish_promoted_replacement,
  rollback_replacement,recover,archive_replaced}`. Boundary: one independently verified private
  current candidate ↔ an occupied canonical cache that may be immutable or root-owned.

  `stage_gradle` reuses an occupied cache unchanged only after its complete immutable-tree and current
  wrapper/dependency/SDK semantics pass. A stale result receives no deletion, chmod, chown,
  normalization, elevation, or cross-parent-move authority. Replacement starts only after producer
  exit, source and SDK postconditions, independent candidate verification, publisher checksum,
  semantic validation, and an exact full-tree digest receipt. The occupied tree must be nonempty,
  bounded, mount/link/type closed, non-group/world-writable, wholly root- or acquisition-owned, and
  readable without permission changes; an unreadable tree fails closed for explicit operator
  retirement.

  The helper seals candidate descendants while retaining the exact candidate root at 0700, rechecks
  digest and semantics, and synchronizes the tree and staging parent before the v4 journal durably
  selects replacement. That record binds semantic pins, original SDK identity/digest, candidate and
  displaced identities/content digests, the displaced tree's exact ownership/mode digest,
  online/staging/retired-root identities, and deterministic no-clobber names. Legacy-v3 replacement
  state is preserved and rejected because it lacks that metadata commitment; legacy-v2 state cannot
  authorize replacement. The SDK and displaced tree are revalidated before promotion.
  `RENAME_NOREPLACE` promotes the candidate to a reserved sibling under the locked
  online parent; one same-parent `RENAME_EXCHANGE` installs it without changing the old directory's
  parent. Only the candidate root is sealed to 0500. The live candidate, SDK, and displaced tree are
  revalidated before success. Recovery accepts only the recorded prepared, promoted, or exchanged
  topology; incoherent state is preserved. Failure restores the old live name first and demotes only
  the candidate. Archival no-clobber moves only the user-owned staging/journal envelope outside
  `online`; the displaced tree stays at its reserved sibling with unchanged inode, ownership, modes,
  and full-content digest.

  The helper's real-filesystem self-test runs as numeric UID:GID 1000:1000 and covers ordinary
  publication and replacement, post-selection prepared recovery, promotion recovery,
  exchange-before-root-seal recovery, sealed-candidate rollback, destination and SDK races, checksum
  and writable-seed rejection, old-tree identity/content/ownership/mode preservation, displaced-mode
  drift refusal, legacy-v3 replacement refusal, candidate finality, and record archival. The focused
  source gate is supplementary and checks the transaction wiring; it has no
  requirements/status/workspace-document coupling. No duplicate workspace implementation remains.

  Retained evidence is deliberately bounded. A read-only compatibility validation of the then-live
  stale cache recorded a 4,590,447,012-byte closed tree at SHA-256
  `074cbfdc08dd721fb93e3413481d50ab7a5e4e626a4d7addf0477595d97132df`; it did not mutate or
  replace the cache. A later canonical R-B10 acquisition at source commit
  `66c53ba3286c1636bf76b6a4ac3f5943036722ee` did run the former v3 same-parent exchange:
  candidate digest `46291a99308d1c8992d22d0bdd6f1c050b51dccbedc18ae46f567e0e7150f8b6`
  became live, the exact displaced-root inode and the same
  `074cbfdc08dd721fb93e3413481d50ab7a5e4e626a4d7addf0477595d97132df` content digest
  remained at the reserved sibling, the SDK digest was rechecked, and the journal was archived.
  That is real canonical replacement evidence for root identity/content under v3, but cannot prove
  the ownership/mode commitment that only v4 records. At source commit
  `226ce5bcb1421cebe76cdf3b66b27ed22589bebc` using retained
  private inputs from `7c29f39a829b39de558a39d0ee7b575ac42e4ce9`, a real ARM64 JNI/APK build
  produced stable-key APK SHA-256
  `031a1f31c74d123b9121b3bb1d8e94aa025373403bb05fc023536ebc079e39b5`, byte-equal to two
  independently built retained APKs; signature, manifest, mobile-key, and native-inventory checks
  passed. That artifact neither exercised canonical replacement nor represents current master, and
  its retained log contained an unresolved severe bridge diagnostic and warnings, so it is not clean
  release evidence.

  Still open: a safe real v4 replacement/recovery transaction bound to current source; fresh
  current-source Gradle/JNI/APK artifacts; cold R-B2/R-B10 A/B equality; installed Android
  Activity/foreground-service/task-swipe/reopen/Force-Stop behavior; real peer capture/decode/present
  and reconnect/focus latency; bounded performance/soak/cleanup; independent reproduction; and
  external review. This documentation slice ran no producer, canonical mutation, APK install, device,
  VM, service, peer, presentation, or host operation.

- **R-S11ga/R-S11e-213 — canonical Dart-handle ownership and fail-closed Android bridge diagnostics —
  SOURCE IMPLEMENTED; FRESH PRODUCTION BRIDGE GENERATION AND LOCKED ARM64 RUST CHECK GREEN;
  APK/DEVICE/NATIVE PRESENTATION EVIDENCE OPEN.** Platform: every Flutter-feature Rust build, with
  executable evidence on the Android ARM64 target. Endpoint/action: `src/flutter_ffi.rs` type ownership,
  the root Cargo feature/dependency graph, and `scripts/android-apk-build.sh` bridge-generation verdict.
  Boundary: the Dart C API's opaque handle ABI and ffigen diagnostics ↔ generated Rust/Dart bridge code
  admitted to later Cargo/JNI/Gradle consumers.

  The prior workaround stated that the pointee was immaterial and declared
  `pub type Dart_Handle = *const std::ffi::c_void`. That claim was false as a source contract. The locked
  `dart-sys 4.1.5` source defines `Dart_Handle = *mut _Dart_Handle`, and the locked
  Flutter-Rust-Bridge `dart_api.h` expresses the same owner as `typedef struct _Dart_Handle*
  Dart_Handle`. Flutter-Rust-Bridge already selected that exact package transitively but did not re-export
  the name at its crate root. Its temporary generated stubs resolved the name through
  `crate::flutter_ffi::*`, so the local alias caused ffigen to diagnose two different C typedefs. Pointer
  representation happened to be the same, but that does not authorize a contradictory declaration or a
  severe diagnostic in release evidence.

  `dart-sys = { version = "=4.1.5", optional = true }` is now a direct optional dependency activated by
  the `flutter` feature, the root lock record carries the direct edge, and `flutter_ffi.rs` re-exports
  `dart_sys::Dart_Handle`. No second handle type remains and no new package entered the 898-record lock.
  Android bridge generation writes its complete combined output through `tee` to a fresh private tmpfs log,
  emits that output to the enclosing build log, rejects any `[SEVERE]` marker before Cargo or Gradle even
  when the outer generator exits zero, and retires the log on success while an exit trap owns other exits.
  The focused Android authority verifier rejected all 178 deliberate mutations, including the exact manifest
  feature and package pin, root lock edge, canonical re-export, second-type absence, private output capture,
  severe verdict, and consumer order; the shared verifier, normative requirement, Appendix disposition, and
  independent workspace gate bind that focused contract.

  Counted executable evidence used a fresh archive of HEAD overlaid with every edited tracked file inside
  pre-existing immutable Android-builder image
  `sha256:fc9adbc23c769c604de4ff046dbb95a6d8bb240377a67f6a070a9db94c7f50f2`. It ran as numeric UID:GID
  1000:1000 with no network, pull, published port, device, Docker socket, or host namespace; a read-only
  root, source, and exact private Android input snapshot; all capabilities dropped; no-new-privileges; finite
  PIDs/memory/no-swap/CPU/descriptors/file size; and fresh private tmpfs work. Production bridge generation
  completed without `[SEVERE]`. It retained the already-visible unresolvable-module warnings plus ffigen
  warnings that intentionally opaque `_Dart_Handle`, `DartCObject`, and `Display` declarations have no
  definition; those warnings were neither hidden nor relabeled as clean. The exact command
  `cargo ndk --platform 21 --target aarch64-linux-android check --locked --release --features flutter
  --lib` exited zero in 1m09s with five `scrap` and 87 root-library warnings.

  Two setup attempts are explicitly uncounted. The first stopped before project code because UID 1000 could
  not create a child in a root-owned mode-0700 `/work` tmpfs mount. The second stopped during pinned Rust
  archive extraction because an intended 32-GiB file-size ceiling had been supplied as 8,388,608 bytes. The
  counted attempt used a standard 1777 tmpfs mount boundary with an immediate UID-owned mode-0700 work child
  and the correctly expressed finite file ceiling. No root, capability, writable host input, or other
  bypass was granted.

  No full APK was assembled, signed, retained, installed, or launched. No Activity, foreground service,
  task swipe/reopen/Force Stop, actual peer, display/control/file transfer, capture/decode/render, Windows
  focus/minimize, device/emulator/VM, cross-version interoperability, latency budget, sustained soak,
  canonical cache replacement, clean exact-commit R-B2/R-B10 release, independent reproduction, or external
  review ran. This closes one source/bridge-verdict defect and one target compile-integration check only; the
  user's accumulated-change risk assessment and every native/end-to-end stop-ship gap remain in force.

- **R-S11gb/R-S11gg/R-S11gh; R-S11e-215/219/220 — Windows presentation and window
  lifetime: SOURCE IMPLEMENTED; HISTORICAL NARROW NATIVE EVIDENCE; CURRENT FULL-PEER/RELEASE
  EVIDENCE OPEN.** The current plugin resolves main-window ID 0 from the valid registrar view's live
  post-parenting `GA_ROOT`. Secondary close is idempotent and response-bound: the exact HWND,
  engine, channel, and manager owner survive until Dart cleanup completes; `WM_NCDESTROY` clears
  the exact `GWLP_USERDATA`; and only the returning private-message turn retires the manager entry.

  Commit `fd1d6d8f2d06f42f8c421d08a25f89185db0cf9c` historically passed the narrow
  production-window presentation transaction: real minimize/restore and focus-loss/pointer-return,
  two 128-frame queues, 312-ms and 172-ms composed-pixel observations, pointer delivery, typed-zero
  exit, guest shutdown, and cleanup in an unprivileged zero-interface Windows VM with loopback-only
  VNC. Commit `7ad3e34f2eed70711a31e7880302b4047524dac3` held the secondary Dart destruction
  response for 1013 ms, observed a new frame in 139 ms while its production HWND/engine remained
  live, and then observed cleanup before native/manager retirement. The ignored raw receipts are no
  longer local, so these are named historical results, not exact-current reruns or release artifacts.

  Current verification must additionally exercise R-S11gh's repeated-close and non-success result
  paths. R-S11gk remains the release-blocking real-peer transaction: exact current artifacts,
  uninterrupted focus/minimize freshness without reconnect, capture-to-compositor timestamps,
  queue/resource bounds, cross-version behavior, sustained soak, cold R-B2/R-B10 equality,
  independent reproduction, and external review remain open. Focused source checks are
  supplementary and cannot promote either historical transaction to current native evidence.

- **R-S11gd/R-S11e-217 Linux Flutter handled-command exit contract — SOURCE FIX, EXACT
  RELEASE-BUNDLE EXECUTION, AND LATER FULL-PEER EVIDENCE RECORDED.** Platform: shipped
  Linux Flutter runner. Endpoint/action:
  dynamic core loading and the `rustdesk_core_main` UI-continuation decision for CLI commands.

  The Rust FFI boolean means only “continue into Flutter UI.” A successfully handled command such
  as `--password-stdin` returns false after printing `Done!`; actual command errors exit nonzero in
  Rust before returning. `flutter/linux/main.cc` previously treated that false UI decision exactly
  like `dlopen`/`dlsym` failure and returned 1. The fifth full-peer run reproduced the contradiction
  with the actual release bundle, not a mock: the credential transaction completed, but the shipped
  runner reported failure.

  The runner now separates invocation success from the UI decision with an explicit output
  parameter. A null decision output, missing bundled core, or missing symbol still returns
  `EXIT_FAILURE`; a successful false decision returns `EXIT_SUCCESS`; and only a true decision
  enters `g_application_run`. Rust's existing nonzero exits for validation, authorization, and
  command failures are unchanged. The fast full-peer harness source-contract check binds both
  branches in the actual Linux runner. The
  sixth exact committed release-bundle transaction made the shipped authenticated
  `--password-stdin` command print `Done!` and exit zero, after which the same process reached typed
  `user-server` state. The run then stopped at the separate literal-loopback harness contradiction
  before viewer start, so this executable evidence closes only the handled-command exit contract
  and does not close R-S11gc.

  This narrow correction does not by itself prove password persistence, listening, peer
  authentication, pixels, focus recovery, Android/Windows lifecycle behavior, release packaging,
  cross-version operation, soak, independent reproduction, or external review. The later exact
  transaction closes R-S11gc's narrow Linux evidence; those broader claims remain with the other
  explicit stop-ship boundaries.

- **R-S11gf/R-S11e-218 Linux Flutter texture-plugin load authority — SOURCE IMPLEMENTED;
  EXACT-CURRENT FULL-PEER, PACKAGED-ARTIFACT, AND CROSS-PLATFORM EVIDENCE PENDING.** Platform:
  Linux outgoing Flutter viewer. Endpoint/action: lazy Rust loading of the repository-owned software
  RGBA renderer before native texture registration. Boundary: exact application-bundle code identity
  versus ambient ELF dynamic-loader search.

  Read-only source tracing found that Linux alone initialized `TEXTURE_RGBA_RENDERER_PLUGIN` with
  `Library::open("libtexture_rgba_renderer_plugin.so")`. The `dlopen(3)` contract treats a name with
  no slash as a search request: calling-object RPATH/RUNPATH, `LD_LIBRARY_PATH`, the loader cache,
  and default directories can participate. This contradicted the existing Debian package authority,
  which admits exactly one renderer member at
  `/usr/share/rustdesk/lib/libtexture_rgba_renderer_plugin.so`, while Windows already constructs an
  application-relative DLL path and macOS opens the current image. The renderer is outgoing-viewer
  presentation code; the installed Linux root service ordinarily controls a separate user-owned
  server role and no root-service reachability, exploit, host mutation, or compromise was
  demonstrated. This is nevertheless concrete ambient-library authority and a future-reactivation
  risk, not a merely stylistic path choice.

  Linux now obtains the current executable, rejects anything other than a clean absolute file path,
  derives exactly `<executable-parent>/lib/libtexture_rgba_renderer_plugin.so`, and passes that
  slash-containing pathname to `Library::open`. A missing executable identity, malformed path,
  absent plugin, or loader error leaves the renderer unavailable. There is no bare-soname,
  environment-selected, current-working-directory, system-library, or compatibility fallback.
  Focused path regressions bind the installed `/usr/share/rustdesk` and ordinary portable/bundle
  layouts and reject relative, parent-traversing, and fileless roots. The desktop-texture verifier
  binds the fixed basename, path derivation, exact loader call, tests, shared/fresh-bridge gate
  wiring, R-S11gf, Appendix C #341, and this ledger; the independent workspace verifier binds those
  same source families and mutations separately.

  The counted compile transaction ran as numeric UID/GID 1000:1000 in the pinned Debian-builder
  image `sha256:607278bc16cf12eadaa41f8fa63a5a160a34b1a980be8cb2a772c4c3b7d3fdb2` with
  no network, a read-only root and offline inputs, all capabilities dropped, no-new-privileges, no
  Docker socket or host namespace, no port publication, one disposable tmpfs source, and one fresh
  private compiler target. It hash-checked the individually required Rust 1.75.0, Flutter 3.24.5,
  LLVM 15.0.6, and FRB 1.80.1 archives; generated all four bridge outputs from an exact tracked
  source archive plus this pending `src/flutter.rs`; rejected any `[SEVERE]` generator diagnostic;
  passed exact Rust 1.75 rustfmt; compiled the production library with
  `flutter,unix-file-copy-paste`; and passed both selected regressions (`2 passed`, `0 failed`, 483
  filtered). The warning-only generator output and existing compiler warnings are retained as
  warnings, not promoted to failures or hidden. An earlier direct compile against the checkout's
  ignored stale bridge failed on its older FFI signatures; a fresh-generation attempt then failed
  rustfmt; and a second attempt reused an output whose dependency-owned copied headers were mode
  0400. None count as success. The counted transaction used a new target rather than changing those
  permissions.

  This narrow transaction verified the four individually required archive hashes and exercised the
  current Cargo vendor/Pub-cache contents offline; it does not certify the canonical full-online
  closure. That closure's current manifest identity still differs from the pinned expected identity,
  so the full-peer harness remains fail-closed and no runtime result is claimed from it.

  On the tracked verifier bytes, the focused desktop-texture verifier, Python AST parsing, and the three shell-gate
  parses passed. This remains source-only evidence and did not start a RustDesk process or listener.

  This source correction does not inherit R-S11gc's earlier exact commit `38ad03e` runtime result:
  that artifact predates the changed loader bytes. An exact-current full-peer run must prove the
  release bundle actually resolves the new path, authenticates, presents current pixels through
  focus loss, and exits cleanly. Exact Debian-artifact execution, Windows/Android/macOS/iOS behavior,
  focus/background/reconnect/resource soak, current cold R-B2/R-B10 artifacts, independent
  reproduction, and external review remain explicit release blockers. No host RustDesk process,
  service, binary, configuration, listener, display, firewall/UFW/nftables/iptables state, or host
  network state was inspected or changed for this source slice.

- **R-S11gc/R-S11e-216 Linux full-peer presentation — EXACT-CURRENT PRODUCT RUNTIME GREEN;
  CURRENT ARTIFACT, INSTALLED, CROSS-PLATFORM, AND SOAK EVIDENCE OPEN.**

  **What the current runtime establishes.** No-NIC verifier-VM transaction `run.e47T6SGHQP` built
  clean pushed product commit `76d8a32c2775f0d13c0c05a9fbc8d82939ad866e`, tree
  `92e483393489c82b85d82017526013b1a25ae0af`, and canonical source archive SHA-256
  `340cd5787d5a403667d643b87b9c896185c4dca0ba1225f4f1c5952d00b497c5` into the release Rust
  core and actual 77-file Linux Flutter bundle from the exact pinned offline inputs. The shipped
  nonroot server started credential-empty and parked, accepted the test password only through
  redirected `--password-stdin` and authenticated same-user IPC, and then became the same typed
  listening process. The real viewer entered all 22 password characters through XTest; a count-only
  AT-SPI observation proved the field complete without reading its value, the prompt retired, and no
  password appeared in argv or environment.

  A changing 256-state X11 source traversed actual capture, software encode, keyed TCP, viewer VP9
  decode, Rust-to-Dart texture publication, the production Linux texture plugin, Flutter, and
  observed X11 pixels. First fresh pixels arrived in 83 ms; four distinct current frames were
  observed; the initial observation's maximum age was 671 ms; blurred age during 2,000 ms of
  external focus loss was 83 ms; pointer-return recovery was 0 ms; and the focus round's maximum age
  was 252 ms. The authenticated TCP tuple and inode stayed identical, so reconnect could not explain
  recovery. Viewer, server, source, both Xvfb owners, listener, guest Docker, QEMU, and virtiofsd
  reached joined terminal receipts. The transaction completed in 762 seconds. One
  `dbus-run-session` unknown-child diagnostic occurred during teardown, so this is not claimed as a
  diagnostic-clean or sustained-performance run.

  **Confinement and claim boundary.** Controlled peer and viewer had separate process, IPC,
  home/configuration, and X11 state. The controlled peer used `--network=none` with only `lo`; the
  viewer shared only that exact namespace; no port was published and zero UDP sockets were present.
  The server-only manifested evidence shim narrowed the product’s intentional wildcard port-21118
  bind to `127.0.0.1`; therefore the transaction proves the media/session path under literal
  container-loopback confinement, not native product bind-address behavior. It did not inspect or
  change the host RustDesk service, binary, configuration, listener, display, firewall, route, or
  network state. A green transaction does not establish the broader R-B10 online closure.

  The maintained fast checker now validates only this harness source contract. It does not replay
  the runtime and cannot renew or extend the named-commit evidence. The former self-mutation catalog,
  requirements/status prose checks, and independent verifier-of-verifier copies were deleted because
  they measured source wording rather than presentation behavior. The real full-peer harness remains
  the authoritative executable test.

  The obsolete five-file synthetic Flutter texture/X11 smoke was also deleted. It acquired direct
  host-Docker authority and could not establish an authenticated capture-to-present product path,
  while its useful pending-frame/direct-ABI behavior remains covered by the native C++ plugin test
  invoked from the VM-only Dart verifier. R-S11gc's real full-peer harness is now the sole maintained
  Linux pixel-presentation transaction. The deleted synthetic result remains available in Git history;
  deleting it removes one host-Docker consumer but adds no new native, product, or current-commit
  runtime evidence.

  **VM-only full-peer authority (2026-09-15).** The maintained full-peer entry now refuses root, a
  root primary group, caller-selected Docker state, and any environment without the authenticated
  no-NIC verifier-VM preflight before admitting source, offline inputs, images, outputs, or scratch.
  Every image query, container launch, inspection, log read, and cleanup uses the fixed guest client,
  private guest Unix socket, and root-owned read-only configuration with daemon-generation replay
  before and after the operation; the shared host-Docker helper and host fallback are absent. The
  ordinary-user QEMU transaction behaviorally refused VM root, foreign UID/GID 4001, and caller
  `DOCKER_HOST`, then admitted UID/GID 4000 for a real Docker 27.5.1 client/server request. It booted
  with no NIC, created no host-listener delta, joined QEMU/Docker/private-tree cleanup, and completed
  in 49 seconds. Its exact receipt says `workload=unexecuted`: the sparse authority payload contains
  no product source/offline closure or builder images and therefore supplies no new full-peer,
  capture, pixel, focus, latency, artifact, or current-commit runtime evidence.

  **Fresh-texture startup defect and correction (2026-09-22).** The immediately preceding real run
  `run.1UMgis8X1F` authenticated successfully, negotiated and decoded VP9, and kept the server video
  service active, but displayed no pixels. A fresh desktop `FFI.start` had requested display-0 texture
  publication while its exact native handler still had an empty display set. Native ownership checks
  correctly refused the pointer, but `LatestDesktopTextureSlot` correctly treated that stable demand's
  failed activation as terminal; later peer-info display admission could not resurrect it. This was a
  real presentation-only failure, not a password, transport, server-capture, or decoder failure. Fresh
  peers now wait for Rust's initial-display commit and subsequent `peer_info` event; the existing
  `pi.isSet` view boundary then creates the texture. Existing-window routes retain early creation only
  after `sessionAddExistedSync` has synchronously committed their display owner. No timer, polling,
  reconnect, permissive native publication, or blind retry was added. `run.e47T6SGHQP` is the exact
  runtime confirmation of that corrected ordering.

  **Open / STOP-SHIP.** Release still requires an exact-current artifact run plus installed Linux
  coverage; Android persistent-service,
  task-swipe/reopen/Force-Stop, real-peer presentation, and resource-finality testing; native Windows
  focus/minimize/background/reconnect and display-latency testing; macOS/iOS; cross-version
  interoperability; concurrent control/file/audio operation; repeated reconnect and sustained
  capture-to-present latency, freshness, queue, CPU, memory, thread, handle, and cleanup soak; cold
  R-B2/R-B10 equality; independent reproduction; and external review.

- **R-B10 exact-current canonical online-input reconciliation — OPERATIONAL ACQUISITION AND
  COMPLETE CLOSURE VERIFICATION GREEN FOR THE NAMED V3 TRANSACTION 2026-08-08; CURRENT V4
  REPLACEMENT, COLD RELEASE/DOUBLE-BUILD, AND NATIVE DEVICE/VM EVIDENCE OPEN.** Exact source authority:
  clean pushed commit `66c53ba3286c1636bf76b6a4ac3f5943036722ee`, tree
  `a34b81db605c31cf1c4352d621dfd01e346a03a4`, and canonical Git-archive SHA-256
  `1a235e8267bc0d574f6055286bc3b269b656907cec856b55601ad813d1283dae`.
  Boundary: the intentionally stale but preserved canonical Android/native/Windows-helper inputs
  plus an obsolete whole-tree receipt -> one current, individually checked, self-recorded
  `online/` closure usable by the networkless build gates. This is input-maintenance evidence, not
  a claim that a clean R-B2 release was built twice or that an installed Android/Windows client ran.

  The first real `scripts/online-fetch.sh` execution reverified the immutable builder/verifier
  images, fixed archives, exact Cargo vendor, FRB tool, and current three-Git Pub cache, then stopped
  before Gradle at the occupied `vcpkg-distfiles/libvpx-native-key.txt`: the exact security patch
  still matched source and its SHA-512 pin, but the 65-byte receipt contained historical key
  `8e936f7953fa1065cf276106b54bc3ad93208e6854557143c5e42a66802dac6e`
  instead of committed-overlay key
  `afa7f36e0104d94645cbd9d8c08e9701b406ac1bc3e5f7f533e5b241f7a6551f`.
  Both occupied native-codec trees separately carried still older receipt
  `2f1a0d9ec38bec3b32c2154a752119c3240c9944ab0ce1c4dfaf91e6a4bfac23`;
  the live NDK contained 28 build-created `__pycache__`/`.pyc` entries outside the exact archive;
  and the root-owned SDK retained the obsolete resolver-shaped output. Updating only a marker would
  have falsely blessed old binaries, while deleting or permission-normalizing those trees would
  have violated their source contracts.

  One explicit operator-retirement transaction therefore ran in the immutable devcheck image as
  numeric UID:GID 1000:1000 with `--network=none`, read-only root, all capabilities dropped,
  `no-new-privileges`, bounded resources, no port/device/socket/host namespace, and exactly one
  writable `online/` bind. It used descriptor-relative same-parent
  `renameat2(RENAME_NOREPLACE)` only. The old libvpx key, complete root-owned vcpkg tree, dirty NDK,
  and root-owned SDK retained their exact device/inode/owner/mode under distinct
  `.rustdesk-retired-*` names; no content was removed, chmodded, chowned, overwritten, or moved
  across parents. Their identities remain respectively `66306:117742238`, `66306:103977791`,
  `66306:115118913`, and `66306:125997901`.

  The next canonical acquisition published the current libvpx receipt, built both native-codec
  consumer projections from the pinned baseline and overlay, and independently admitted their
  exact header/static-library/ELF inventories. The x64 and ARM64 output keys are
  `05ba4d6d9009ff1a01cc7ab5c7ecd50bdcc8ea75e7cd3de9ca7a8367719bf7f7`
  and `4c3f9f263a5d6c87db34f2fc6645c3ac768eb686ae4037db0dae556c5fa35698`;
  both carry the current libvpx key. The NDK was re-extracted and compared entry-for-entry with the
  pinned r28c ZIP before publication. The SDK producer acquired its eight fixed filenames and
  passed exact length, digest, archive-inventory, semantic, byte-comparison, and sealed-tree checks
  before publishing current-owner mode-0555 NDK and SDK roots.

  Gradle warming then performed a real clean ARM64 Rust/JNI release compilation from the exact
  commit in 2m30s, with the existing 87 library warnings plus one service warning, followed by a
  successful 236.8-second `assembleRelease` of a 45.0-MB transient APK. That APK was only the cache
  warmer's disposable output: it was neither stable-signed, retained, installed, launched, nor
  counted as R-B2/device evidence. The independently verified Gradle 8.7 candidate had full-content
  digest `46291a99308d1c8992d22d0bdd6f1c050b51dccbedc18ae46f567e0e7150f8b6`.
  The state-v3 same-parent exchange installed exact inode `66306:113814497`, preserved displaced
  digest `074cbfdc08dd721fb93e3413481d50ab7a5e4e626a4d7addf0477595d97132df`
  at exact inode `66306:127308720`, revalidated SDK digest
  `60f888eb0a836b5e58fb58a05a3a0823b15b9da57fe72adff70de7cccd067ee5`
  around publication, and archived its durable journal under
  `.harness-state/retired-online-inputs`.
  That v3 record bound the displaced Gradle root identity and content digest but not its exact
  ownership/mode profile; it therefore does not establish the current v4 preservation contract.

  That invocation next stopped on the preserved root-owned 198,126,354-byte historical
  `flutter-pub-cache.tar.gz` (`2e17bac34a6a3229c91f4786f78d23ff10dbee1c49b2053b84838202d99d805c`)
  rather than overwriting it with the current narrow contract. A second exact same-parent,
  no-clobber retirement preserved inode `66306:103715841`. The following acquisition rerun
  reaccepted every new native/NDK/SDK/Gradle final, then networklessly projected and independently
  replayed the exact 95-package Flutter-tools cache. The published current-owner mode-0400 archive
  is exactly 18,771,131 bytes at SHA-256
  `69db14598f59440d4c2b16e017b2266f3b011cd1cc6854c65b6caaea8db946ae`.
  WiX, Windows engine/toolchain, fixed archives, and every individually pinned SHA-256/SHA-512 input
  reverified before the expected obsolete whole-tree pin stopped the run.

  Two fresh independent devcheck-container launches then hashed the complete read-only tree and
  agreed exactly on canonical closure
  `eacb4d0fadb044f2f38520ad5263470a89c286bed69927ce2c32babcbc01ab24`:
  266,866 files, 80,019 directories, 76 symlinks, 38,967,060,125 regular-file bytes,
  30 hardlink groups, and 17 explicitly represented case-collision groups. A separate
  numeric-nonroot, networkless container atomically wrote the self-excluded record and immediately
  reverified it. After the tracked pin was updated,
  `scripts/online-fetch.sh --verify-offline-inputs` reverified every archive/image and the complete
  canonical closure and
  exited zero. Preservation-bound historical inputs remain included by exact bytes but are not
  canonical consumer names or inferred-valid build outputs.

  Before this result was recorded, the focused container-authority, Gradle-output,
  Flutter-tools-cache-output, and Cargo-vendor-output verifiers passed. Those focused source checks are
  supplementary to the executable acquisition and publication transaction above.

  The monolithic `scripts/verify.sh` shared gate was deliberately not invoked: its current IPC
  fixture starts isolated containers as UID:GID 0:0 with `CAP_CHOWN` and `CAP_FOWNER`. Although that
  is a documented narrow fixture, invoking it would violate the operator's explicit no-root rule.
  The successful nonroot gates above do not relabel the omitted shared Cargo/test stages as green.

  The networked acquisition containers used only the source-owned outbound bridge profiles:
  numeric nonroot, `--pull=never`, read-only root, dropped capabilities, no privilege gain,
  bounded PID/memory/no-swap/CPU/tmpfs, and no published port, device, Docker-socket mount, or host
  namespace. No RustDesk runtime, host service, host configuration, host listener, host display,
  UFW/nftables/iptables state, route, or host-network state was inspected or changed. Exact clean
  Android and Windows release artifacts, installed Activity/foreground-service/task-swipe/
  Force-Stop and focus/minimize/restore behavior, real presentation/control/file-transfer
  coexistence, repeated reconnect/resource soak, cross-version behavior, cold double-build byte
  equality, independent reproduction, and external review remain stop-ship gaps.

- **R-S11cs/R-S11e-111 — fixed SHA-256 toolchain and installer archive acquisition authority —
  SOURCE IMPLEMENTED 2026-07-24; ADVERSARIAL TRANSACTION/MUTATION AND COMPLETE LIVE
  FOURTEEN-ARCHIVE ACQUISITION EVIDENCE RECORDED; BROADER RELEASE EVIDENCE OPEN.** Platform: the unprivileged Linux
  acquisition host and immutable Android-builder container. Endpoint/action: the former generic
  `fetch_verify` family used by Rust, Flutter, Android, LLVM, Python, FRB, vcpkg, and Windows archive
  acquisition. Boundary: remote HTTPS response/redirect behavior and network-client execution ↔ the durable
  exact offline-input namespace and every later offline release consumer.

  Before this slice, host `curl -L` wrote predictable `<final>.part` names directly under `online` and
  an overwrite-capable `mv` installed the final name. A final SHA-256 caught a completed wrong response,
  but the host network client had no reviewed final-host set, response-length ceiling, content-encoding
  contract, private output namespace, durable state, independent output verdict, or no-clobber publication.
  The generic helper served fourteen release inputs and three wrapper families. This was build-host
  network-execution, acquisition-output/publication, stale-state, and denial-of-service authority debt—not
  evidence that a cached archive was malicious or changed, host root was acquired, a container escaped, a
  port/listener was exposed, host RustDesk/service/configuration/firewall/network state changed,
  exploitation occurred, or the host was compromised.

  Source closure: `scripts/pins.env` now binds the exact byte length next to the established digest for
  every fixed archive. One sorted fourteen-entry manifest names Android command-line tools and NDK;
  Linux and Windows Flutter; FRB; Linux and Windows LLVM; olefile and Windows Python; Linux Rust and the Android
  standard library; vcpkg; Git for Windows; and the Windows Rust MSI. Each entry carries one exact
  credential-free HTTPS URL, length, SHA-256, and a bounded reviewed initial/final redirect-host set.
  `fetch_verify`, `fetch_toolchains`, `fetch_windows_toolchains`, and `fetch_vcpkg` are deleted; the main
  path calls the fixed transaction once, so the inherited redundant vcpkg fetch cannot recur. The moving,
  operator-captured `rustup-init.exe` remains outside this manifest and is still digest-verified before
  Windows use.

  `scripts/online-fixed-archive-output.py` rejects root UID/GID, mutable image identity, malformed or
  pending pins, noncanonical destinations/URLs/hosts, duplicates, and any manifest count/order other than
  the exact fourteen. The host exclusively locks the current-user-private mode-0700 online root,
  reconciles every reserved same-filesystem transaction, and fully validates present output by stable
  no-follow descriptor reads. Reuse requires exact type, same filesystem/mount, closed ownership/mode
  profile, single link, no xattrs, length, and SHA-256. Historical current-user 0644/0664 and root
  0444/0644 files are accepted only below that private root after the same byte check; new output is
  current-owner mode 0400. A wrong occupied final fails without deletion, replacement, chmod, or download.

  A cold transaction creates unpredictable mode-0700 staging with one private output and a bounded
  single-link mode-0600 fsynced state record. That record binds the online/staging/output identities,
  UID/GID, complete manifest digest and records, immutable Android-builder content ID, exact helper digest,
  missing set, phase, and per-file publication progress. The producer runs through the established archive
  funnel by exact image ID with `--pull=never`, isolated bridge egress, a read-only root, numeric non-root
  identity, all capabilities dropped, no-new-privileges, fixed PID/memory/no-swap/CPU ceilings, and bounded
  non-executable scratch. Its only mounts are the exact helper and state read-only and the private output
  writable. It receives no online root, final path, live repository, Docker socket, device, published port,
  other writable host path, or host network/PID/IPC/UTS namespace.

  Python proxy discovery is disabled. Every request begins at the exact HTTPS URL; at most five redirects
  may remain credential-free HTTPS within that entry's host set. Status must be 200, the final host remains
  allowed, and content encoding is absent or identity. A present decimal `Content-Length` must equal the
  pin before streaming; an absent length is admitted only with explicit chunked transfer framing.
  The producer creates each candidate exclusively with no-follow semantics and, under either framing, stops at the exact byte
  ceiling, requires final length and SHA-256, synchronizes it, and seals it 0400 without executing or
  extracting it. After producer exit, the host independently checks exact inventory, recorded inode,
  ownership/modes, filesystem/mount, type/link/xattr closure, and stable complete bytes. Producer and host
  verdicts remain independent.

  Only a verified transaction may publish. Each archive uses descriptor-relative
  `renameat2(RENAME_NOREPLACE)` and synchronizes both namespaces. An exact destination race is independently
  revalidated before the identical staged duplicate is removed; a different destination is fatal. State is
  synchronized after each archive, and all fourteen finals are rechecked before completion. Recovery
  accepts prepared discard, verified-unpublished, exact interrupted per-file publication, and complete
  arrangements; incoherent state is preserved. Coherent staging is removed only through the shared
  identity-bound, same-filesystem, no-follow private-tree closure.

  Verification recorded so far: the helper adversarial self-test passes as numeric UID/GID 1000 in the
  immutable Android builder with no pull/network, read-only root/source, all capabilities dropped,
  no-new-privileges, bounded resources, no port/socket/device/host namespace, and disposable tmpfs. It
  proves exact fourteen-file and nested `win/` publication, idempotent completion, an interruption after
  no-clobber rename but before state advancement, wrong length/digest cleanup, redirect-host refusal,
  bounded chunked delivery, unframed-response refusal, symlink rejection, unsafe nested-parent refusal,
  and wrong occupied-destination refusal. The focused source verifier binds the exact
  manifest/pins, three-mount producer, root/network/redirect/response/file/output/recovery/publication
  contracts, shared-gate wiring, R-S11cs, Appendix C #246, and this ledger through 36 deliberate
  mutations.

  Complete live acquisition proof: one disposable immutable Android-builder container ran as numeric
  UID:GID 1000:1000 with `--pull=never`, isolated bridge egress, read-only root, all capabilities dropped,
  no-new-privileges, fixed PID/8-GiB-memory/no-swap/two-CPU ceilings, and bounded non-executable `/tmp` and
  `/proof` tmpfs. The exact helper was its only read-only host bind; it received no writable host path,
  source tree, online cache, final host name, Docker socket, device, port, or host namespace. It downloaded
  all 14 exact responses (4,233,346,963 bytes), exercised Google/Python/static-Rust/GitHub redirect and
  fixed-length/chunked delivery, checked every streaming ceiling and SHA-256, independently verified the
  complete candidate, and passed durable no-clobber publication plus reconciliation entirely inside
  `/proof`. The container exited green with `fixed archive complete live network lifecycle: PASS
  (14 archives)`; its tmpfs and every downloaded byte then vanished. Two preceding fail-closed attempts
  exposed and corrected the source manifest's `frb`/`flutter` ordering and GitHub codeload's explicit
  chunked/no-`Content-Length` response contract; neither attempt published persistent output.

  Evidence boundary: this is complete disposable cold acquisition evidence for the fixed fourteen-archive
  transaction, not a run against or mutation of the live online cache and not a release build. R-S11cu
  subsequently closes the separate Debian systemd-image path. Host Cargo vendoring and Windows Flutter
  engine and Pub-cache archive producers, WiX capture, maintenance-image acquisition/publication, exact
  cold R-B2/R-B10 artifacts, native/device behavior, and R-V3 external review remain open. No root command
  or root container, image pull/build/tag, release build, host RustDesk process/service/configuration/
  listener/firewall/network operation, or live online archive mutation was performed.
- **R-S11ct/R-S11e-112 — fixed libvpx source and Windows-tool archive acquisition authority —
  SOURCE IMPLEMENTED 2026-07-24; ADVERSARIAL TRANSACTION/MUTATION AND COMPLETE DISPOSABLE
  33-ARCHIVE LIVE ACQUISITION EVIDENCE RECORDED.** Platform: the unprivileged Linux acquisition host and
  immutable Android-builder container. Endpoint/action: the former `fetch_verify_sha512` path for the
  libvpx source archive and the 32 archives in `res/vcpkg/libvpx/windows-tools.sha512`. Boundary: remote
  HTTPS response/redirect behavior and network-client execution ↔ the durable `online/vcpkg-distfiles`
  namespace consumed by the native codec and Windows release pipelines.

  Before this slice, host `curl -L` wrote predictable `<final>.part` names directly below that durable
  namespace and an overwrite-capable `mv` installed each final. A final SHA-512 caught wrong completed
  bytes, but delivery had no exact length, response ceiling, content-encoding, reviewed final-host,
  private-output, independent-verdict, durable-state, or no-clobber contract. The MSYS2 branch began at
  `mirror.msys2.org`, which currently redirects to a geographically selected third-party mirror. This
  was build-host network-execution, acquisition-output/publication, stale-state, and denial-of-service
  authority debt—not evidence that a cached input changed, host root was acquired, a container escaped,
  a port/listener was exposed, host RustDesk/service/configuration/firewall/network state changed,
  exploitation occurred, or the host was compromised.

  Source closure: `fetch_verify_sha512` and the per-tool URL/download loop are absent. The tracked
  `res/vcpkg/libvpx/fixed-archive-acquisition-v1.txt`, pinned by SHA-256
  `c90310083a22b9da7cebb9412275f3a551dd03f146fcf7f25fed84ab633b5a8f`, contains exactly 33 sorted
  five-field records totaling 181,392,489 bytes. It binds one libvpx source and the exact 32 downstream
  Windows-tool names to fixed credential-free HTTPS URLs, byte lengths, acquisition SHA-256 values, and
  reviewed redirect-host sets. MSYS2 inputs use the stable direct `repo.msys2.org` repository rather than
  the moving mirror redirector. The shell loader checks the acquisition-manifest pin before and after
  parsing, requires one source plus the complete unique canonical tool-name set, and cross-checks that set
  against the independently SHA-512-pinned consumer manifest before network use.

  The existing R-S11cs transaction engine is shared rather than copied. At this slice it had two closed profiles:
  exactly 14 toolchain/installer entries with only optional `win/` nesting, or exactly 33 vcpkg entries
  comprising one `vcpkg-distfiles/libvpx-*.tar.gz` child and 32
  `vcpkg-distfiles/windows-tools/*` children. Its candidate-inventory and recovery checks derive the
  complete ancestor-directory set, so the deeper profile cannot smuggle an adjacent entry. Both profiles
  retain the current-user-private online-root lock, stable no-follow existing-output verdict, recorded
  manifest/helper/image identities, same-filesystem private state/output, exact three-mount immutable
  numeric-nonroot acquisition container, disabled proxy discovery, bounded HTTPS redirect/status/
  encoding/framing/length processing, exclusive no-follow creation, independent host byte/metadata
  verification, mode-0400 sealing, descriptor-relative `RENAME_NOREPLACE`, per-file state/fsync,
  restart reconciliation, and exact-identity retirement. R-S11cu subsequently adds one exact Debian-image
  profile without admitting arbitrary one-entry input. The producer receives no online root, final
  destination, live repository, Docker socket, device, port, host namespace, or other writable host path.
  Existing historical current-user mode-0664 files remain reusable only after their exact size and
  acquisition SHA-256 pass; downstream `require_libvpx_distfiles` and Windows build gates still enforce
  every established SHA-512 independently.

  Verification recorded so far: the shared executable self-test passes as numeric UID:GID 1000 with no
  network, read-only source/root, all capabilities dropped, no-new-privileges, and bounded resources. It
  now exercises a complete 33-entry three-level prepare/download/independent-verify/no-clobber-publish
  lifecycle and rejects an unsafe nested `windows-tools` parent. The focused authority verifier binds the
  exact acquisition-manifest bytes/pin/shape, SHA-512 consumer-name equality, shell loader, legacy path
  absence, dual closed profiles, narrow producer, response/file/publication/recovery rules, R-S11ct,
  Appendix C #247, and this ledger through 44 deliberate mutations. Bash/Python parsing, the normal
  independent workspace verifier, its complete semantic source-mutation matrix, and the native-codec
  normal/mutation gates are green.

  Complete live acquisition proof: one disposable immutable Android-builder container ran as numeric
  UID:GID 1000:1000 with `--pull=never`, isolated bridge egress, read-only root, all capabilities dropped,
  no-new-privileges, fixed PID/2-GiB-memory/no-swap/two-CPU ceilings, and bounded non-executable `/tmp` and
  `/proof` tmpfs. Its only host mounts were the exact helper, acquisition manifest, and SHA-512 consumer
  manifest, all read-only. It received no source tree, online cache, final host name, writable host path,
  Docker socket, device, port, or host namespace. The transaction downloaded all 33 exact responses
  totaling 181,392,489 bytes, checked HTTPS status/host/encoding/framing/length and acquisition SHA-256,
  independently verified the complete three-level candidate, passed durable no-clobber publication and
  reconciliation, then rechecked the libvpx source and all 32 tools against their established downstream
  SHA-512 pins. It exited green with `vcpkg fixed archive live lifecycle: PASS`; its tmpfs and every
  downloaded byte then vanished. The first disposable attempt failed before network use because the
  shared path grammar omitted the `~` present in the canonical MinGW pkgconf name. The grammar and
  behavioral/mutation fixtures were corrected before the successful attempt; the failed attempt
  downloaded and published nothing.

  Evidence boundary: the current live cache was also inspected read-only inside a numeric-nonroot,
  networkless, capability-free container: all 32 tool files and the libvpx source matched their
  established SHA-512 pins, and their measured acquisition SHA-256/length values produced the tracked
  manifest. No live cache byte or metadata was changed. This live proof is a disposable cold acquisition
  transaction, not a release build or a mutation of the persistent online closure. R-S11cu separately closes
  Debian systemd-image acquisition. Committed local security-patch/native-key publication, host Cargo
  vendoring, Windows Flutter engine/Pub-cache/WiX
  producers, maintenance-image acquisition/publication, exact cold R-B2/R-B10 artifacts, native/device
  behavior, and R-V3 external review remain open. No root command/container, image pull/build/tag,
  release build, host RustDesk process/service/configuration/listener/firewall/network operation, or live
  online-cache mutation was performed.
- **R-S11cu/R-S11e-113 — Debian systemd VM image acquisition authority —
  SOURCE IMPLEMENTED 2026-07-24; ADVERSARIAL TRANSACTION/MUTATION AND COMPLETE
  DISPOSABLE COLD ACQUISITION EVIDENCE RECORDED.**
  Platform: the unprivileged Linux acquisition host and immutable Android-builder container.
  Endpoint/action: `scripts/online-fetch.sh --debian-systemd-smoke-image`, which stages the dated Debian 12
  genericcloud QCOW2 consumed by the networkless installed-systemd lifecycle gate. Boundary: remote HTTPS
  response/network-client execution ↔ the durable private
  `.harness-state/debian-systemd-smoke/debian-12-genericcloud-amd64-20260712-2537.qcow2` base.

  Before this slice, host `curl -L` streamed remote delivery into the predictable durable sibling
  `<image>.part`; failure removed that pathname, and a successful final SHA-512 was followed by chmod and
  overwrite-capable `mv`. The dated Debian URL and publisher hash constrained completed bytes but not response
  length, redirect host, content transformation, direct durable-namespace write authority, interrupted state,
  or no-clobber publication. This was build-host network-execution, acquisition-output/publication, stale-state,
  and denial-of-service authority debt—not evidence that the cached image changed, host root was acquired,
  Docker escaped, a public listener/port was created, host RustDesk/service/configuration/firewall/network state
  changed, exploitation occurred, or the host was compromised.

  Source closure: the dated filename remains derived only from
  `DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD=20260712-2537`. Debian's dated directory publishes one matching
  `SHA512SUMS` record; the existing cache matches it exactly. The new acquisition pins bind the same
  publisher-exact bytes to length 346,882,048 and SHA-256
  `b49303d83f5f69ff55fdf8c16b883b5714bc5332d37a6f6b8a94da42ad5b0999`, while the established publisher
  SHA-512 remains independent and mandatory at acquisition completion and again before QEMU consumption.
  The one-entry source manifest fixes the credential-free dated HTTPS origin and admits exactly
  `cloud.debian.org` plus the currently reviewed Debian-selected final host
  `laotzu.ftp.acc.umu.se`. A different redirect target fails closed and requires an explicit manifest
  review; there is no ambient Debian-mirror allowlist. A confined one-byte diagnostic observed that exact
  final URL and the exact 346,882,048-byte object size. Because this Debian path has exceeded the shared
  120-second I/O wait during failed-closed diagnostics, only the large systemd-image profile receives a
  finite 300-second I/O timeout; the ordinary archive timeout remains 120 seconds.

  The R-S11cs/R-S11ct transaction engine is reused rather than copied. Its third closed profile is exactly one
  top-level `debian-12-genericcloud-amd64-YYYYMMDD-HHMM.qcow2`; every other one-entry name and every other
  cardinality remains rejected. Generic transaction orchestration now takes an explicit publication root.
  Toolchain/vcpkg calls retain the private canonical online root; the systemd call uses only its separately
  proved current-UID/current-GID mode-0700 harness/state directories, so the explicit systemd mode no longer
  prepares or locks unrelated `online`. Existing image reuse accepts only current-owner modes 0400 or
  historical read-only 0444, one link, no xattrs, same mount, exact length, and SHA-256. It does not chmod,
  delete, or replace an occupied image; new publication is mode 0400.

  Cold acquisition uses the same durable same-filesystem private state/output transaction, exact immutable
  Android-builder/helper binding, numeric-nonroot three-mount producer, disabled proxy discovery, bounded HTTPS
  redirect/status/encoding/framing/length processing, exclusive no-follow creation, exact SHA-256, fsync and
  mode-0400 sealing, independent host metadata/byte verdict, descriptor-relative `RENAME_NOREPLACE`, namespace
  synchronization, restart reconciliation, and exact-identity retirement. The producer receives the helper and
  state read-only plus only the private output writable. It receives no harness/publication root, final name,
  canonical online cache, repository, Docker socket, device, port, host namespace, or other writable host path.
  The networkless consumer independently accepts only the 0400/0444 current-owner profile and retains the
  publisher SHA-512, `qemu-img check`, standalone-QCOW2/no-backing-file, no-network, and throwaway-CoW-overlay
  checks.

  Verification recorded: Bash parsing and Python in-memory compilation pass. The shared executable transaction
  self-test exercises exact one-entry prepare/acquire/independent-verify/no-clobber-publish, historical-mode reuse,
  and writable-output rejection. The focused authority verifier binds the exact size, SHA-256, publisher
  SHA-512, two-host origin/redirect set, ordinary-versus-large-image I/O timeouts, closed manifest shape,
  publication-root separation, narrow producer, consumer metadata/SHA-512 checks, R-S11cu, Appendix C #248,
  and this ledger through 59 deliberate mutations. The adjacent online-fetch container-authority gate rejects
  36 mutations. The independent workspace validator is green normally and across its complete semantic
  source-mutation matrix after the systemd-image metadata, timeout, and redirect-host checks were made
  unambiguous. The native-codec ledger normal and mutation gates remain green against the updated requirements
  hash.

  Complete live acquisition proof: one disposable transaction used a current-user-owned mode-0700 private
  `/dev/shm` tree and the immutable Android-builder image. Preparation, independent verification, publication,
  reconciliation, reuse, and final digest inspection ran networkless. The sole networked producer ran as numeric
  UID:GID 1000:1000 with `--pull=never`, read-only root, all capabilities dropped, no-new-privileges, fixed
  PID/2-GiB-memory/no-swap/two-CPU ceilings, and bounded non-executable `/tmp`. It received exactly three mounts:
  the helper and state read-only and the private output directory writable. It received no source tree, harness
  publication root, online cache, Docker socket, device, port, or host namespace. The producer downloaded all
  346,882,048 bytes, enforced the exact HTTPS host/response/length/SHA-256 contract, and sealed the candidate
  mode 0400. A separate networkless invocation independently verified it, descriptor-relative no-clobber
  publication and reconciliation completed, publisher SHA-512 matched, the final current-owner/current-group
  mode-0400 single-link file was exact, and a second prepare returned `complete` with no missing output. The run
  exited green with `Debian systemd image cold lifecycle: PASS
  size=346882048 mode=0400 sha256+publisher-sha512=exact reuse=complete`; the identity-checked trap then removed
  the complete RAM-backed tree.

  Failed-closed diagnostics are part of the evidence: two earlier 120-second full-download attempts reached no
  publication; a one-byte probe proved that the canonical Debian origin currently selects
  `laotzu.ftp.acc.umu.se`, motivating the exact second host and systemd-only 300-second I/O timeout. The first
  post-change full transaction completed download/verification/publication/reuse but its final read-only
  validator was invoked with Docker environment flags after the image name and failed before digest assertions;
  its trap removed the temporary tree, and only the corrected fully green rerun is counted. Attempts to run the
  workspace verifier's broader executable self-test in the pinned Android and Debian builders failed before
  applicable fixtures because the former lacks `systemd-run` and the latter lacks Python `tomllib`; neither is
  claimed. The normal validator and complete semantic source-mutation matrix are the recorded workspace evidence.

  Evidence boundary: this is a source and disposable acquisition closure, not a release build or a mutation of
  the persistent image cache. It does not close the exact clean R-B2/R-B10 transaction, committed local
  security-patch/native-key publication, host Cargo vendoring, Windows Flutter/Pub/WiX producers,
  maintenance-image acquisition/distribution, native/device behavior, independent image distribution, or R-V3
  external review. No root command/container, image pull/build/tag, release build, host RustDesk
  process/service/configuration/listener/firewall/network operation, or persistent cache mutation was performed.
- **R-S11cv/R-S11e-114 — committed libvpx patch and native-key publication authority —
  SOURCE/GATES COMPLETE 2026-07-24; EXACT CLEAN RELEASE EVIDENCE REMAINS OPEN.** Platform: the unprivileged Linux
  acquisition host. Endpoint/action: `scripts/online-fetch.sh::stage_libvpx_distfiles`, which
  publishes the repository-owned CVE patch and the complete libvpx overlay/source key beside the
  network-acquired vcpkg distfiles. Boundary: the exact committed source identity and two
  deterministic local bytes ↔ the durable `online/vcpkg-distfiles` consumer namespace.

  Before this slice, the shell hashed the live patch pathname, copied it into the predictable
  `libvpx-<fix>.patch.part`, and used overwrite-capable `mv`. It then regenerated
  `libvpx-native-key.txt.part` unconditionally and overwrote the final receipt. A symlinked
  temporary could redirect the path write; wrong occupied state was replaced rather than rejected;
  the hash and copy were separate pathname operations; and an interruption left ambiguous shared
  residue. This was source-proven current-user build-input publication, namespace, and stale-state
  authority debt. It is not evidence that either cached file changed, host root was acquired,
  Docker escaped, a listener or port was exposed, host RustDesk/service/configuration/firewall/
  network state changed, exploitation occurred, or the host was compromised.

  `online-fetch.sh` now resolves and retains one exact Git commit and tree, requires the canonical
  clean live checkout, explicitly refuses Git graft or replacement-ref state, and proves the fixed
  patch is one mode-100644 tracked blob whose no-filter live object equals the committed blob. The native-input key is computed from the established pin
  fields plus every ordinary committed blob below `res/vcpkg/libvpx`; a symlink, submodule, or
  special committed entry is fatal. The independently retained live-tree calculation must equal
  that committed key. Commit/tree/blob/clean-state/live-key equality is reproved after local
  publication and after each x64-linux or arm64-Android networked vcpkg producer, and either native
  output may publish only when that source postcondition and its independent output verdict pass.

  The dedicated `scripts/online-libvpx-local-output.py` refuses UID or primary GID zero and accepts
  only the canonical patch path below a current-user, non-group/world-writable source root. The
  shell holds the existing nonblocking exclusive online-root lock around publication. The helper
  stably reads the patch through a no-follow single-link descriptor, rejects xattrs and mutable
  metadata, and independently enforces `SHA512_LIBVPX_PATCH`. It opens only the exact current-user
  same-filesystem/same-mount/no-xattr `vcpkg-distfiles` parent. An occupied final must be a stable
  same-mount single-link regular file in one closed current-user or historical root-owned mode
  profile and match the exact patch or newline-terminated native-key bytes. Wrong or unsafe state
  fails before candidate creation and is not deleted, replaced, or chmodded.

  Missing output is created exclusively under an unpredictable same-filesystem mode-0700 staging
  directory. A bounded fsynced mode-0600 state record binds online/distfile/staging identities,
  owner, source commit/tree/blob, exactly two ordered outputs, candidate identities, lengths,
  SHA-256 values, patch SHA-512, and key bytes. Candidates are exclusive no-follow current-owner
  files, stably rechecked, synchronized, and sealed 0400. Patch publication deliberately precedes
  receipt publication. Each uses descriptor-relative `renameat2(RENAME_NOREPLACE)` and fsyncs both
  namespaces; an exact concurrently occupied final consumes only its identical staged duplicate,
  while a different final fails. Both finals are rechecked before exact staging retirement.

  Restart reconciliation accepts only bounded ordinary current-owner partial files in an
  unprepared reserved directory, or a recorded arrangement whose exact source/byte authority still
  equals the current transaction and in which each candidate identity is still staged or is the
  exact final, or the candidate is absent only while the independently revalidated exact occupied
  final remains. This last topology is required when an existing exact patch consumes its staged
  duplicate while the same transaction publishes a previously missing receipt. State is stably
  reread before retirement. A symlink, special file,
  external hardlink, descendant mount, xattr, unexpected entry, changed parent, missing candidate
  identity, or mismatched recorded authority is preserved and rejected. The read-only consumer
  command refuses and preserves any unreconciled reserved transaction and applies the same
  descriptor/metadata/byte verdict. The old patch/key `.part`, `cp`, overwrite `mv`, direct path-hash
  consumer, and refresh-in-place receipt semantics are absent.

  Verification: the helper self-test passes in immutable Android-builder
  image `sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121`
  as numeric UID:GID 1000:1000 with `--pull=never`, no network, read-only root/source, all
  capabilities dropped, no-new-privileges, fixed PID/memory/no-swap/CPU ceilings, and bounded
  non-executable scratch. It exercised cold two-file publication, exact occupied inode reuse,
  mixed exact-patch/missing-receipt publication without replacing the occupied patch,
  historical-mode reuse, wrong occupied output refusal without overwrite, interrupted unprepared
  reconciliation, successful read-only validation, preservation of unresolved read-only state,
  preservation of a recorded transaction from a different source authority, and symlinked
  source/staging, external-hardlink staging, and xattr refusal. The focused deliberate-mutation
  verifier passes. The independent workspace verifier passes both its normal source contract and
  complete source-mutation-only matrix. The adjacent vcpkg native-output verifier passes with all
  48 mutations rejected; fixed-archive authority passes with all 59 mutations rejected; online
  container authority passes with all 36 mutations rejected; and native-codec watch passes both
  normal and mutation-self-test modes. A separate confined calculation proves the live and exact
  committed libvpx native-key algorithms agree at
  `afa7f36e0104d94645cbd9d8c08e9701b406ac1bc3e5f7f533e5b241f7a6551f`. Python AST parsing, `online-fetch.sh`/`verify.sh` Bash
  parsing, requirements HTML parsing, synchronized requirements SHA-256
  `e91c445b89284741bbf8e781bb5fc755bbfd1b7d6c670ee805daf05818d085a2`, and `git diff --check`
  pass in the final confined source state. These are source/helper fixture verdicts, not a claim
  that the persistent cache was published or that an exact release artifact was built.

  Evidence boundary: this source slice runs no network producer, image operation, compiler,
  archive extractor, or release build for the two deterministic local files. The persistent online
  cache was not mutated. Host Cargo vendoring, Windows Flutter/Pub/WiX producers, maintenance-image
  acquisition/distribution, exact clean R-B2/R-B10 artifacts, native/device behavior, independent
  image distribution, and R-V3 external review remain open. No root command/container, image
  pull/build/tag, host RustDesk process/service/configuration/listener/firewall/network operation,
  or native device was used.
- **R-S11cw/R-S11e-115 — exact Cargo vendor acquisition-output authority —
  SOURCE, TRANSACTION, OFFLINE SEMANTIC, AND MUTATION VERIFIED 2026-07-24; EXACT CLEAN
  RELEASE EVIDENCE REMAINS OPEN.** Platform: the unprivileged Linux acquisition host and the
  immutable Debian builder. Endpoint/action: `scripts/online-fetch.sh::vendor_cargo`, which
  materializes the complete Cargo registry/Git source closure and source-replacement map consumed
  by every offline Rust build. Boundary: networked Cargo archive/Git processing ↔ one exact
  committed source, the pinned Rust toolchain, sealed build inputs, and the durable online cache.

  Before this slice, `vendor_cargo` called ambient host `cargo` against the live checkout with host
  network/Cargo/Git state, directed it into permanent `online/cargo-vendor`, and truncated the
  permanent `online/cargo-vendor-config.toml` pathname. An occupied tree was updated instead of
  proved, a failure could leave a partial tree/config pair, and no independent Cargo process showed
  that the resulting bytes resolved the committed lockfile offline. This was build-host execution,
  acquisition-input/output, namespace, stale-state, and denial-of-service authority debt. It is not
  evidence that the existing vendor bytes changed, any dependency was malicious, host root was
  acquired, Docker escaped, a listener or public port was exposed, host RustDesk/service/config/
  firewall/network state changed, exploitation occurred, or the host was compromised.

  `online-fetch.sh` now stages and verifies the pinned Rust 1.75 archive before Cargo vendoring and
  contains no host-Cargo path. It requires the already-loaded immutable Debian builder and constructs
  the same exact clean commit/tree/archive authority used by the Gradle and Pub paths. The authority
  rejects sparse checkout, replacement refs, grafts, noncanonical index flags, staged/tracked/
  untracked drift, archive-transforming attributes, and committed symlink/special entries. Its
  read-only extraction is independently compared with a private writable extraction, after which
  the writable copy is retired before Cargo starts. After producer and semantic runs, a fresh
  extraction re-proves commit/tree/clean/archive/source equality and is again retired.

  The current-user mode-0700 online root is exclusively locked. Every reserved transaction is
  reconciled before reuse or staging. A present final is accepted only when both the vendor
  directory and config exist and the same complete non-mutating validators accept them; partial,
  wrong, linked, mounted, foreign, mutable, or otherwise unsafe occupied state fails without
  deletion, replacement, chmod, or producer execution. A cold run creates an unpredictable
  same-filesystem mode-0700 transaction directory plus a hidden sibling vendor candidate. The
  candidate is deliberately a sibling of the permanent vendor name: Linux permits the fully sealed
  directory to move between names under the same parent without granting write permission to the
  directory to update a cross-parent `..` relationship.

  `scripts/online-cargo-vendor-output.py` refuses UID or primary GID zero and records online,
  transaction, candidate, raw-config, canonical-config, source commit/tree/archive, builder, Rust,
  output pins, owners, inode identities, exact counts, phase, and dispositions in a bounded
  mode-0600 append-only fsynced JSON-lines journal. The only admitted forward sequence is
  `prepared → verified → authorized → publishing → vendor-published → complete`, with exact
  phase/disposition combinations. Pre-journal recovery accepts only the exact empty files/tree
  created by preparation. Prepared or structurally verified state is discardable and cannot
  publish; only authorized-or-later exact state can resume publication.

  The producer uses intentional isolated bridge egress but no pull, a read-only root, the invoking
  numeric UID:GID, all capabilities dropped, no-new-privileges, fixed PID/memory/no-swap/CPU bounds,
  and bounded executable scratch. It receives exactly four host mounts: exact committed source and
  the pinned Rust archive read-only, plus the private hidden vendor directory and exact raw-config
  inode writable. It receives no online root, permanent output name, live checkout, Docker socket,
  device, port, other writable host path, or host namespace. HOME, Cargo home/target, Git config, and
  the installed Rust toolchain live only in tmpfs. Exact Rust 1.75 runs
  `cargo vendor --locked --versioned-dirs --manifest-path /source/Cargo.toml /outputs/vendor` and
  emits its map only to `/outputs/raw-config.toml`.

  Independent host validation bounds paths, depth, per-file size, total files/directories/bytes,
  journal/config sizes, and mountinfo. It rejects noncanonical roots, descendant mounts, filesystem
  crossings, symlinks, special objects, foreign ownership, set-id/sticky bits, extended attributes,
  external hardlinks, unsupported modes, and unstable reads. The exact accepted closure is 50,926
  files, 12,144 directories, 2,299,420,401 regular-file bytes, and canonical provenance SHA-256
  `fb63f7daefc2c26fb73c04a7d77e9cb8a7658e3c899352e851bb1ebbacdc8c04`.
  Producer file executability is retained while all files/directories are normalized to 0400/0500,
  synchronized, and then completely revalidated. The bounded raw config must have one unambiguous
  terminal `/outputs/vendor` declaration. Only that declaration is transformed to the established
  final path; the resulting 4,393-byte config must equal SHA-256
  `18a946aa319d64fa07e9616801981b1794c01764f9d870090de593cec412d62f`, and is
  synchronized and sealed 0400.

  Structural validation does not authorize publication. A second immutable numeric-nonroot
  container runs with `--network=none`, no pull, read-only root, zero capabilities,
  no-new-privileges, fixed resource ceilings, and bounded executable tmpfs. It receives only exact
  source, Rust archive, sealed vendor tree, and canonical config read-only. It creates a disposable
  empty Cargo home, changes only that copy's sole directory declaration to `/vendor`, and requires
  exact Rust 1.75 `cargo fetch --offline --locked --manifest-path /source/Cargo.toml` to succeed.
  Producer, source, Rust input, structural output, semantic, and publication statuses remain
  independent. The helper records authorization only when every preceding verdict is green.

  Publication moves the sealed tree first through descriptor-relative same-parent
  `renameat2(RENAME_NOREPLACE)`, synchronizes the online namespace, and records
  `vendor-published`; only then may the sealed config enter its final name through the same
  no-clobber primitive. Exact concurrent output is independently revalidated, while different
  output fails. Every journal and namespace transition is synchronized and complete output is
  rechecked. Recovery accepts only exact recorded inode arrangements; malformed/partial journals,
  contradictory dispositions, symlink/special/hardlink/mount/xattr state, changed parents or
  identities, and unexpected inventory are preserved. Reconciled private state is retired through
  the established exact-identity mode restorer and external-inode closure remover. Consumers refuse
  any surviving reserved transaction.

  The disposable cold producer exposed a pre-existing reproducibility mismatch instead of being
  forced to reproduce it: the historical vendor/config pins retained the unversioned
  `https://github.com/rustdesk-org/tokio-socks` source and its `tokio-socks-0.5.2-3` tree even
  though the current committed `Cargo.lock` no longer contains that source. Exact Rust 1.75
  vendoring therefore emits 25 rather than 26 source-map entries and removes precisely 96 files,
  27 directories, and 685,019 content bytes. Keeping the historical superset would make the new
  producer permanently fail its own lockfile-exact contract. The source pins now bind the measured
  current output: vendor root
  `fb63f7daefc2c26fb73c04a7d77e9cb8a7658e3c899352e851bb1ebbacdc8c04`,
  config `18a946aa319d64fa07e9616801981b1794c01764f9d870090de593cec412d62f`,
  and full online closure
  `ab9d1b9e467dbc7723f809eb7d7e905ca5b9285fe00f8572e96c2490fe0ffc66`
  over 145,614 files, 42,828 directories, 41 symlinks, and 25,722,811,491 content
  bytes. The full closure was derived in disposable reflink storage by replacing only those two
  measured artifacts and running the canonical whole-tree algorithm. The persistent historical
  cache was not edited or chmodded. Because silent cache replacement would violate this boundary,
  its now-stale exact occupied pair intentionally fails until an operator explicitly retires it and
  reruns acquisition; the transaction does not delete it merely because source pins advanced.

  A disposable cold-output proof also exercised the real producer and publication path against
  the corrected closure. The producer used immutable Debian builder
  `sha256:6766564c65b0daead7d7031fcf0ff9ec8becab6ef9e3f9a7efd9f02f1b893776`
  as numeric UID:GID 1000:1000 with an isolated bridge, no pull, read-only root, all capabilities
  dropped, no-new-privileges, explicit resource ceilings, no port or host namespace, the exact
  pinned Rust archive read-only, the current source read-only, and only its candidate tree and
  raw-config inode writable. The first attempt used the historical pins and correctly stopped at
  the independently checked config digest before authorization or publication, exposing the stale
  `tokio-socks` surplus described above. With the corrected pins, the producer completed; the
  helper admitted, normalized, synchronized, and revalidated all 50,926 files; a separate
  `--network=none` exact Rust 1.75 `cargo fetch --offline --locked` completed from an otherwise
  empty Cargo home; and authorization, tree-before-config no-clobber publication, recovery, and
  final complete validation all passed. The disposable final and its whole-online reflink proof
  were then mode-restored where necessary and completely removed. The persistent online cache was
  never mounted writable by those proofs.

  That cold proof intentionally is not promoted to exact clean release evidence: it mounted the
  current read-only working tree while this source slice was uncommitted and used synthetic
  source/journal identities for the disposable helper transaction. `Cargo.toml` and `Cargo.lock`
  had no working-tree diff, so it validates the measured Cargo output, offline resolution, sealing,
  recovery, and publication mechanics, but not the exact clean commit/archive precondition or an
  R-B2 release artifact. The committed `online-fetch.sh` path enforces that precondition before a
  real persistent acquisition.

  Source-fixture verification uses immutable image
  `sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121`
  as numeric UID:GID 1000:1000 with no network, read-only root/source, all capabilities dropped,
  no-new-privileges, fixed PID/memory/no-swap/CPU ceilings, and bounded non-executable scratch for
  source fixtures. The helper self-test covers cold publication, verified-but-unauthorized recovery,
  authorized complete recovery, interruption after tree-before-config publication, exact final
  checking, writable occupied root/file/config refusal, wrong occupied output preservation, and
  external-hardlink refusal. The focused
  structural verifier rejected all 22 deliberate authority mutations; the adjacent container,
  exact-source, fixed-archive, and Rust-audit gates rejected 39, 38, 59, and 53 mutations
  respectively. The independent workspace passed normally and across its complete source-mutation
  matrix. That matrix exposed and closed two source-verifier gaps before publication: shared Rust
  archive-check literals are now scoped to the exact Cargo-tool lifecycle, and main acquisition
  order independently requires fixed Rust inputs before Cargo vendoring. During the 2026-07-25
  whole-closure refresh, the focused Cargo semantic-profile extractor was also found to span the
  following Pub semantic profile; a missing Cargo `--cap-drop=ALL` therefore borrowed the Pub copy
  and escaped its capability-widening mutation. The extractor now ends at the immediate Pub-profile
  boundary, the focused 22-mutation suite rejects that removal, and the independent workspace
  extracts the same exact function and carries its own capability-drop mutation. This is an
  assurance repair; the already capability-free producer/semantic runtime profiles did not change.
  The native-codec watch
  passed normally and in mutation-self-test mode. Bash/Python/HTML parsing, synchronized
  requirements SHA-256
  `f785be15c36ac3e0b9d31b83a761a6d5480a62e706be7161c32274aa22e3b862`,
  unchanged Cargo manifests/lockfile, and diff hygiene passed in the final source state; final
  index, commit, and remote-publication evidence follows after it exists.

  Evidence boundary: no root command/container, host Cargo, host-network listener, published port,
  host namespace, image pull/build/tag, persistent online-cache mutation, release build, native
  device, or host RustDesk process/service/configuration/listener/firewall/network operation is part
  of this source slice. A disposable producer/offline-resolver transaction is separate evidence and
  is not an exact clean R-B2 release artifact. Windows Flutter/Pub/WiX producers,
  maintenance-image acquisition/distribution, native/device behavior, independent image
  distribution, and R-V3 external review remain open.
- **R-S11cx/R-S11e-116 — exact Windows Flutter-engine acquisition-output authority —
  SOURCE, TRANSACTION, COLD PRODUCER, ARCHIVE SEMANTIC, AND MUTATION VERIFIED 2026-07-24;
  EXACT CLEAN RELEASE EVIDENCE REMAINS OPEN.** Platform: the unprivileged Linux acquisition
  host and immutable Android-builder. Endpoint/action:
  `scripts/online-fetch.sh::stage_windows_engine`, which uses the exact Flutter 3.24.5 Linux
  SDK to acquire the Windows x64 debug/profile/release engine cache shipped into the offline
  Windows guest. Boundary: networked Flutter/CDN archive processing ↔ one exact SDK input,
  one bounded candidate inode, and the durable offline cache.

  Before this slice, the networked producer received the complete 25+ GiB `online` directory
  read-write, extracted a wildcard `flutter-*.tar.xz`, installed global
  `safe.directory = *`, and streamed directly into the permanent
  `flutter-windows-engine.tar.gz` pathname. Any occupied regular file skipped without a
  digest, length, metadata, or archive-semantic verdict. Remote engine content and archive
  generation therefore inherited current-user write/delete authority over every unrelated
  offline release input, and interruption could leave a partial final that presence checks
  trusted. This was acquisition-input/output, namespace, stale-state, and denial-of-service
  authority debt. It is not evidence that the pinned historical engine bytes changed, that
  Flutter or its engine was malicious, that host root was acquired, Docker escaped, a
  listener or public port was exposed, host RustDesk/service/configuration/firewall/network
  state changed, exploitation occurred, or the host was compromised.

  The transaction now requires the already-loaded immutable Android-builder content ID and
  the exact 693,186,548-byte Flutter 3.24.5 Linux archive. It rechecks that real nonsymlink
  input's SHA-256 and size before the transaction, after the producer, and after semantic
  replay. The current-user mode-0700 online root is exclusively locked; every reserved
  `.rustdesk-windows-engine.*` directory is reconciled first. An occupied final is accepted
  only after complete nonmutating stable no-follow metadata, single-link, xattr, exact
  207,343,264-byte length, SHA-256, and tar-semantic validation. New output must be
  current-owner mode 0400. The sole compatibility profile is exact root:root mode 0644, which
  preserves the historical archive without chmod, replacement, or deletion.

  A cold run creates an unpredictable current-owner mode-0700 same-filesystem transaction
  directory and one pre-created mode-0600 output inode. A bounded fsynced mode-0600 state
  record binds online/staging/output identities, UID/GID, Flutter version, immutable builder,
  source SHA-256, output SHA-256/length, and fixed destination. The producer uses intentional
  isolated bridge egress, no pull, a read-only root, numeric UID:GID, all capabilities dropped,
  no-new-privileges, fixed PID/memory/no-swap/CPU ceilings, and bounded executable tmpfs. It
  receives exactly two host mounts: the exact SDK archive read-only and candidate inode
  writable. It receives no online root, final name, live checkout, Docker socket, device,
  published port, other writable host path, or host namespace. HOME is private; the executable
  path is the exact extracted Flutter/Dart toolchain plus `/usr/bin:/bin`; system/global Git
  and attribute configuration, replacement objects, optional locks, and wildcard repository
  trust are absent.

  Exact `flutter precache --windows` output is selected only from the three fixed
  `artifacts/engine/windows-x64{,-profile,-release}` regular-file trees and the exact
  `windows-sdk`, `libimobiledevice`, and `usbmuxd` stamps. The list must have exactly 73 unique
  names; cache-wide added/newer timestamp inference and the transient lock have no output
  authority. Only those disposable scratch files are explicitly normalized to mode 0666, except
  the three `gen_snapshot.exe` files and three stamps at 0644; extraction umask therefore cannot
  change tar headers. It is encoded with sorted names, numeric zero owner/group, epoch 1700000000,
  and `gzip -n -9`.
  A streaming writer refuses to write any byte beyond the exact compressed size and rejects a
  shorter result; the producer verifies the SHA-256 before exit. The networked process never
  knows or writes the permanent name.

  `scripts/online-windows-engine-output.py` independently binds the recorded inode, rejects
  linked, xattr-bearing, foreign, changed, noncanonical, mounted, or unexpected state, and
  parses the gzip tar without extraction. The exact archive has 73 unique positive-size
  regular members and 817,399,293 uncompressed bytes: 48 debug, 11 profile, 11 release files,
  plus exactly the `windows-sdk`, `libimobiledevice`, and `usbmuxd` stamps. Paths are exact
  bounded relative ASCII; links, directories, devices, FIFOs, sparse/extension types,
  traversal, duplicates, PAX metadata, names, device fields, and unexpected entries are
  rejected. Every member has numeric zero owner/group, empty user/group/link names, fixed
  mtime, and exact mode 0644 only for the three stamps and three `gen_snapshot.exe` members,
  0666 otherwise. The candidate is synchronized, sealed 0400, and completely revalidated.
  A second immutable numeric-nonroot container receives only the validator and candidate
  read-only under `--network=none`, no pull, read-only root, no capabilities,
  no-new-privileges, resource ceilings, and bounded non-executable scratch, and repeats exact
  byte and semantic validation. Producer, source, host-output, networkless-semantic, and
  publication verdicts remain independent.

  Only all-green prior verdicts permit descriptor-relative same-parent
  `renameat2(RENAME_NOREPLACE)` publication. Candidate and both namespaces are synchronized;
  the exact live inode and full contract are rechecked. Later failure attempts an exact
  no-clobber rollback and preserves both errors. Recovery accepts only exact empty/interrupted,
  recorded unpublished, destination-raced, or exact published arrangements. Malformed state,
  symlink/special/hardlink/mount/xattr state, foreign ownership, changed identities, and
  contradictory inventory are preserved. Exact-identity traversal restoration and
  external-inode-closure removal retire reconciled staging.

  The immutable Android-builder source-fixture run uses numeric UID:GID 1000:1000 with no
  network, read-only root/source, all capabilities dropped, no-new-privileges, fixed resource
  ceilings, and bounded non-executable scratch. Transaction fixtures cover cold publication,
  published recovery, wrong digest, independently pinned-but-semantically-wrong archive,
  occupied destination preservation, interrupted state, symlink, external hardlink, and xattr
  refusal. The focused verifier rejects deliberate source/helper/requirement/ledger mutations,
  and the independent workspace binds the same contract and its own mutation set. The exact
  historical root-owned archive was separately copied only into disposable container tmpfs and
  passed the full closed 73-member semantic contract; the persistent archive was mounted
  read-only and was not modified, chmodded, renamed, or replaced.

  The first cold attempt correctly failed at the exact output ceiling before validation or
  publication: the inherited cache-wide “new or newer than marker” heuristic captured unrelated
  Flutter cache churn. Replacing that heuristic with the source-derived 73-name projection exposed
  a second fail-closed mismatch: all 73 payloads and all 817,399,293 content bytes matched the
  historical archive, but private extraction umask narrowed ordinary scratch-file modes and changed
  raw tar headers. The resulting diagnostic gzip was 207,343,576 bytes at SHA-256
  `5fb8e63233ed1a1a7588aad74b8cc1bf56deccc90db83feb469d0df56fff6fed`; it was
  never authorized or published and was removed. A separate networkless proof applied the explicit
  0666/0644 name-scoped normalization to the historical payloads and reproduced both raw-tar
  SHA-256 `cd5e90fa10bf4865bd8a7132577a6c6fd6c1f48e51e85d48b549f51dcbdc1f29`
  and final 207,343,264-byte SHA-256
  `413c7117cc60545629367f73545aa5b3720687eddc77d7d48f93477e4f05440e`.
  These failures are why the final producer binds exact paths, exact count, and exact header modes
  rather than widening the output pin or treating logical payload equality as publication authority.

  Complete disposable producer evidence uses the same immutable image, exact SDK read-only,
  isolated bridge, no port/host namespace, and only a private disposable candidate writable.
  It reproduces the exact 207,343,264-byte SHA-256-pinned archive; separate networkless replay,
  sealing, no-clobber publication, recovery, and complete final validation pass before the
  disposable state is removed. This cold producer proof is not an exact clean R-B2 release
  build and does not publish into the persistent online cache.

  Evidence boundary: no root command/container, image pull/build/tag, persistent online-cache
  mutation, release build, native device, listener, published port, firewall/network
  configuration change, or host RustDesk service/configuration operation is part of this
  slice. The Windows flutter_tools Pub-cache producer is closed separately by R-S11cy; WiX
  acquisition, maintenance-image acquisition/distribution, exact clean R-B2/R-B10 artifacts,
  native/device behavior, independent image distribution, and R-V3 external review remain open.
- **R-S11cy/R-S11e-117 — exact Windows flutter_tools Pub-cache acquisition-output authority —
  SOURCE, TRANSACTION/PROJECTION FIXTURE, TWO DISPOSABLE REPRODUCTIONS, ARCHIVE SEMANTIC,
  OFFLINE RESOLUTION, AND FOCUSED/BROAD MUTATION VERIFIED 2026-08-06; EXACT CLEAN RELEASE
  EVIDENCE REMAINS OPEN.** Platform:
  the unprivileged Linux acquisition host, immutable Android-builder, and offline Windows
  `flutter_tools` provision input. Endpoint/action:
  `scripts/online-fetch.sh::stage_flutter_pub_cache`, which projects the already complete
  R-S11cn hosted cache into `flutter-pub-cache.tar.gz`. Boundary: a validated immutable
  Pub-cache source and pinned Flutter SDK/lock ↔ one bounded candidate inode and the durable
  Windows toolchain cache.

  Before this slice, any occupied regular final skipped without size, digest, metadata,
  structure, or actual offline-resolution validation. A cold packager selected the immutable
  Debian builder, mounted the complete 25+ GiB `online` root read-write, and truncated
  `/online/flutter-pub-cache.tar.gz` directly. Its only archive postcondition grepped one
  `test-1.25.7` member. The packager therefore held current-user write/delete authority over
  every unrelated offline release input, interruption could leave a partial durable final,
  and presence plus one name could authorize stale or incoherent bytes. Direct reproduction
  also proved that the current Debian builder's tar 1.29/gzip 1.6 produces a different
  198,142,789-byte archive at SHA-256
  `3293010dacbc9f41915a0fbb0eaa8391fca1f9e5993b9598ea88c57aa70bd0d0`;
  the already pinned Android builder's tar 1.35/gzip 1.12 reproduces the reviewed bytes.
  This was acquisition-input/output, namespace, stale-state, reproducibility, and
  denial-of-service authority debt. It is not evidence that the historical archive or source
  cache changed, Flutter/Pub was malicious, host root was acquired, Docker escaped, a listener
  or public port was exposed, host RustDesk/service/configuration/firewall/network state
  changed, exploitation occurred, or the host was compromised.

  The transaction now uses the retained clean exact-commit source authority and calls the
  R-S11cn stable no-follow/mount-closed `check-complete` validator over `online/pub-cache`.
  Its exact tree receipt is recorded in the transaction and rechecked after both packaging and
  semantic replay. The exact 693,186,548-byte Flutter 3.24.5 source archive is verified by
  SHA-256 and size before, between, and after those processes. The extracted
  `packages/flutter_tools/pubspec.lock` is independently pinned at SHA-256
  `66955192347d2d4eb24476745462c80a11d9bbf19a461f3504bbbd86e366ee8e`.
  Exact cold reconstruction exposed a later conceptual defect in the 2026-07-25 contract:
  it tarred the whole R-S11cn app-plus-tools union cache even though the durable Windows input
  was described as a 95-package `flutter_tools` closure. The preserved historical archive had
  24,807 members, while the current exact union produced 23,731; the member comparison found
  1,690 historical-only paths, 614 current-only paths, and 240 changed paths. Most changed
  payloads were Pub's time-varying `.cache/*-versions.json` responses, and package trees also
  followed app-lock changes. Repinning that whole-union output would therefore retain a
  fundamentally nondeterministic and overbroad boundary.

  The producer now treats R-S11cn only as authenticated acquisition source. It parses the
  pinned Flutter lock into exactly 95 hosted name/version/content-SHA records, requires every
  corresponding source hash record to equal the lock, and selects only those 95 package trees
  and 95 hash files. App-only packages and the complete hosted metadata cache are absent. The
  output is the 18,771,131-byte archive at SHA-256
  `69db14598f59440d4c2b16e017b2266f3b011cd1cc6854c65b6caaea8db946ae`.

  UID or primary GID zero is refused. The canonical current-user mode-0700 online root is
  exclusively locked before reconciliation, occupied-output validation, staging, or
  publication. Every reserved `.rustdesk-flutter-pub-cache.*` transaction is reconciled
  first. An occupied final passes the same stable no-follow, real-regular-file,
  same-filesystem, single-link, xattr-free, exact-size, exact-SHA-256, and full semantic
  parser as a new candidate, then the same separate offline resolution. A new final is
  current-owner mode 0400; only the exact historical root:root mode-0644 metadata profile is
  admitted after the identical byte and semantic verdict. Wrong occupied state is preserved
  without chmod, deletion, replacement, or reacquisition.

  A cold transaction creates one unpredictable current-owner mode-0700 same-filesystem
  directory and one pre-created mode-0600 output inode. Its bounded fsynced mode-0600 state
  binds online/staging/output identities, UID/GID, source-tree digest, Flutter version,
  source and lock digests, immutable Android-builder ID, output length/SHA-256, and fixed
  destination. Packaging uses `--pull=never`, `--network=none`, a read-only root, numeric
  UID:GID, all capabilities dropped, no-new-privileges, fixed PID/memory/no-swap/CPU limits,
  and bounded non-executable tmpfs. It receives exactly four host mounts: `pub-cache` and the
  exact Flutter source archive read-only with recursive submount inclusion disabled, the exact
  committed helper read-only, and the one recorded candidate inode writable. It receives no
  online root, final name, live checkout, Docker socket, device, port, other writable host
  path, or host namespace.

  The C-locale producer extracts only the exact `flutter_tools` lock from the pinned Flutter
  archive and reproves its SHA-256. The helper's bounded canonical parser emits a sorted
  NUL-delimited manifest for the 95 selected package trees, 95 exact hash records, and four
  required parent directories. GNU tar consumes only those explicitly enumerated paths with
  literal NUL framing, recursion disabled, and hardlinks dereferenced, then applies name
  sorting, numeric owner/group zero, epoch 1700000000, and `u+rwX,go+rX,go-w` before
  `gzip -n -9`. That general normalization would collapse the
  historical source's two mode-0754 files to 0755. The helper therefore operates as a
  streaming raw-tar normalizer: it validates each header checksum and complete padded
  payload, changes exactly the two reviewed short-name regular headers from 0755 to 0754,
  recomputes each checksum, requires both exactly once, preserves GNU LongLink records and
  all other bytes, and rejects partial records, wrong input modes/types, too few terminal
  zero blocks, or later nonzero data. Its bounded writer opens only the existing no-follow
  empty single-link mode-0600 inode, checks current ownership and no xattrs, refuses the first
  byte beyond the exact compressed length, rejects a short or wrong-digest stream, and fsyncs.

  `scripts/online-flutter-pub-cache-output.py` then independently performs stable
  no-follow hashing and parses rather than extracts the gzip tar. The logical contract is
  exactly 7,778 members: 1,054 directories, 6,724 regular files, and 86,925,556 regular
  bytes. It binds 7,681 hosted members, 97 hosted-hash members, exactly 95 direct package
  directories, 95 direct `.sha256` records, zero metadata-cache records, one exact empty file,
  and required `test-1.25.7`. Every
  name is unique bounded relative ASCII rooted in one of the two admitted trees with maximum
  path length 181 and depth 16. Links, link targets, devices, FIFOs, sparse/special entries,
  traversal, backslashes, PAX metadata, names, device fields, wrong ownership/time/mode, and
  duplicates are rejected. All directories are 0755; regular modes are exactly 6,712 at
  0644, 10 at 0755, and the two named files at 0754. Exact ordered metadata SHA-256
  `fa1189aa532a4444dcd2c0643030e7a41dae0421968843fa2ee48c258ac69c80`,
  concatenated payload SHA-256
  `a57b1bf257350624e3cd5610121f0ce84a601cfb090f7490fa9073be086f7478`,
  and name-bound per-file SHA-256
  `d9b7aa737bea93d62fb46cfa1e2a49339040f8f594c8ac1d61459b3e895106e8`
  make the full ordering/name/mode/size/content claim executable. The candidate is fsynced,
  sealed mode 0400, and completely revalidated.

  A separate immutable numeric-nonroot Android-builder process uses no pull, no network,
  read-only root, no capabilities, no-new-privileges, fixed resource ceilings, and bounded
  executable tmpfs. It receives only the pinned Flutter archive, sealed candidate, and exact
  helper read-only. It copies the archive into disposable scratch, checks the complete byte
  and logical contract there, and only then extracts both reviewed archives into scratch
  without restoring owner or permission authority. It asserts the complete metadata-free
  logical contract, closes HOME/Pub/Git/PATH configuration, proves the exact lock digest, runs
  `dart pub get --offline --enforce-lockfile`, and proves the lock unchanged. Producer,
  Pub-source, Flutter-input, structural-output, offline-semantic, and publication statuses are
  independent.

  Only all-green verdicts permit fsynced descriptor-relative
  `renameat2(RENAME_NOREPLACE)` publication. Both namespaces and the published inode are
  synchronized and revalidated. Later failure attempts exact no-clobber rollback and preserves
  both errors. Recovery accepts only exact bounded unprepared, unpublished,
  destination-raced, or published arrangements. Malformed state, links, mounts, xattrs,
  foreign ownership, unexpected entries, changed identities, and contradictions are
  preserved. Exact-identity traversal restoration and external-inode-closure removal retire
  only reconciled staging. The broad writable online mount, Debian-builder choice,
  direct-final truncation, presence-only skip, single-member grep, and unchecked shell
  publication path are absent.

  Confined source-fixture verification used immutable image
  `sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121`
  as numeric UID:GID 1000:1000, with no network, read-only roots/inputs, all capabilities
  dropped, no-new-privileges, and fixed resource/tmpfs ceilings. The transaction self-test
  covers cold publication/recovery, wrong digest, independently pinned but semantically wrong
  archive, occupied destination preservation, interrupted state, symlink, external hardlink,
  xattr, exact 95-record lock parsing, exact projection inventory, wrong source-hash rejection,
  wrong lock-digest rejection, both special-mode header rewrites, and a missing-special
  rejection. Two independent numeric-nonroot networkless productions from the same exact
  read-only source emitted byte-identical 18,771,131-byte archives at SHA-256
  `69db14598f59440d4c2b16e017b2266f3b011cd1cc6854c65b6caaea8db946ae`.
  The independent full semantic parser accepted the exact logical contract. A separate fresh
  no-network process extracted only into tmpfs, confirmed exactly 95 package directories and
  95 hash records with no `.cache`, and completed the exact flutter_tools offline enforced-lock
  replay with the lock digest unchanged. The focused verifier rejected all 30 deliberate
  mutations and the independent workspace structural binding passed. The persistent source
  cache and historical archive remained read-only and were not modified, chmodded, renamed,
  replaced, or deleted; only disposable evidence copies were quarantined or regenerated.

  The focused mutation verifier and independent workspace mutation matrix bind the helper,
  producer topology, pins, shared gate, R-S11cy, Appendix C #252, and this ledger. Exact test
  counts and synchronized requirements identity are recorded in the audit ledger after the
  final staged source state passes. This source/acquisition compatibility proof is not the
  clean exact-commit R-B2 release transaction. WiX acquisition, maintenance-image
  distribution, exact release artifacts, installed/native/device behavior, independent image
  distribution, and R-V3 external review remain open.
- **R-S11cz/R-S11e-118 — exact signed WiX package acquisition and locked offline restore
  authority — SOURCE, TRANSACTION, SCOPED COLD ACQUISITION, LEGACY RETIREMENT, SIGNATURE,
  LOCKED-RESTORE, MUTATION, AND NETWORKLESS NATIVE MSI BUILD VERIFIED; CLEAN DOUBLE-BUILD,
  NATIVE MSI TABLE, AND INSTALLED LIFECYCLE EVIDENCE REMAIN OPEN.** Platform: the unprivileged Linux
  acquisition host, manifest-bound offline UDF media, and networkless ephemeral Windows build
  guest. Endpoint/action: `scripts/online-fetch.sh::stage_windows_wix_nuget`, Linux-side
  `build_offline_media`, and the WiX restore in `scripts/build-windows.ps1`. Boundary:
  publisher-signed NuGet package bytes ↔ durable offline input, derived global-package cache,
  and the Windows MSI build.

  Before this slice, `online/wix-nuget.tar.gz` was an opaque archived NuGet global-packages
  tree. Its retired producer selected mutable `mcr.microsoft.com/dotnet/sdk:8.0`; the Linux
  harness extracted the tar into writable run state, mapped the expanded tree into UDF media,
  and the Windows guest copied it to `C:\wix-nuget` before an unlocked restore. The extant
  71,249,853-byte historical archive at SHA-256
  `0f76c469cd2171f3bf7913828851a2cb22c10a7e0be8bf73ef99a791a6cd1190`
  contained eight package roots, including the already removed DUtil and WcaUtil native custom-
  action build dependencies. A separately derived six-root archive at exact size 54,038,393 and
  SHA-256 `62afa1543d52461ee0b80334c4c3a1d6bf1b54d94f3cd745869102ed613f3b58`
  removed those two roots, but it still made mutable derived package-manager state—including
  extraction results and completion metadata—the durable authority. This was acquisition,
  cache-state, package-signature, lock, and stale-lifecycle authority debt. It is not evidence
  that the historical package bytes changed, WiX/NuGet was malicious, host root was acquired,
  Docker escaped, a listener or public port was exposed, host RustDesk/service/configuration/
  firewall/network state changed, exploitation occurred, or the host was compromised.

  The durable authority is now exactly six publisher `.nupkg` files at version 4.0.5:
  Firewall 330,923 bytes / SHA-256
  `d722cd6d5d262736fc9220fa1d287147c244fd5c2b21065bf192935d8e45d8e3`;
  Heat 5,018,595 /
  `6c137c6a7d6b724169ff47832d080bf75009f24cda656d5644585031ebbe66d8`;
  Netfx 1,577,895 /
  `e09e0e121c482cba3e77521f83f9820f232dd0ab65199f66398efdef3f7b2e46`;
  SDK 18,626,823 /
  `917009bef10f430ee72c4401f70ffcb36562a53f41ea027b8dcacba5e9886a6f`;
  UI 793,813 /
  `313cc0a9b2c2e90661a6ab56f46a08ce551ed64673cbef95ceab6508690147a1`;
  and Util 891,963 /
  `b63e40584d3b5ceb23607586ad720ae0288bad2c8699a0a07cd3260591d1292e`.
  The exact lower-case flat-container URLs admit only `api.nuget.org`. Independent signature
  verification binds WiX author certificate SHA-256
  `0DB368BC1A5A9E19CC9E036B490B7C4A4D3DFB941C0781B4F22F218BE0B54986`
  and NuGet.org repository certificate SHA-256
  `5A2901D6ADA3D18260B9C6DFE2133C95D74B9EEF6AE0E5DC334C8454D1477DF4`.

  Acquisition reuses the R-S11cs fixed-archive helper under its new exact six-entry profile.
  The already verified immutable Android builder runs with numeric UID:GID, `--pull=never`,
  isolated bridge egress, read-only root, all capabilities dropped, no-new-privileges, bounded
  resources, and only exact helper/state read-only mounts plus one private output writable. It
  receives no online root or final name. Independent host validation proves exact response
  framing, length/digest, ownership, mode, link count, mount, xattr, and six-file inventory
  before descriptor-relative no-clobber publication. The explicit
  `--wix-nuget-packages` mode invokes only this transaction and retirement. No .NET SDK image,
  host `dotnet`, cache producer, compatibility tag, broad writable online bind, or direct final
  writer remains.

  `scripts/online-wix-nuget-retire.py` runs only after all six exact finals are durable. It
  refuses UID/GID zero, exclusively locks and revalidates the current-owner mode-0700 xattr-free
  online root, revalidates the mode-0700 six-package directory and every mode-0400 single-link
  current-owner package through stable no-follow descriptors, proves same filesystem/mount and
  no xattrs, and recognizes only a current-owner mode-0644 archive with one of the two exact
  historical size/digest identities above. An unknown or unsafe archive is preserved. A
  recognized archive moves by descriptor-relative
  `renameat2(RENAME_NOREPLACE)` into unpredictable same-parent private staging; both namespaces
  are synchronized, the staged exact bytes are revalidated, and only that exact leaf is
  unlinked. Restart recovery admits only empty private staging or one exact known archive.
  Adversarial self-tests cover exact retirement, idempotent absence, unknown-input
  preservation, and interrupted exact-staging recovery. A separate disposable replay used the
  real historical 71,249,853-byte archive plus all six source-identical package files and
  returned `retired`, then idempotent `absent`, without changing any mounted source.

  The Linux Windows harness no longer defines `WIX_NUGET_ROOT`, extracts the archive, or gives
  a helper writable WiX output. Preflight proves the exact six names, sizes, and hashes.
  `windows-offline-manifest.py` records the direct `wix-nuget-packages` mapping; the complete
  online tree is read-only to media creation; genisoimage grafts that directory directly; and
  before/after manifest equality proves input stability. The Windows guest revalidates all six
  source files, validates its ephemeral temporary directory, requires the run-ID-scoped cache
  and configuration names to be absent, atomically creates both without deleting or overwriting
  occupied state, and never copies expanded source state. `NUGET_PACKAGES` points at that fresh
  directory; the no-clobber configuration is synchronized and hashed across restore; and the
  guest disables online revocation lookup, requires signature verification, clears ambient
  sources, maps only `WixToolset.*` to the read-only UDF source, and names both pinned signer
  fingerprints.

  `Package.wixproj` now pins `WixToolset.Sdk/4.0.5`, expresses every direct extension as exact
  `[4.0.5]`, and requires locked restore. The committed `packages.lock.json` binds exactly the
  five direct PackageReferences and their signed-package content hashes; the SDK remains exact
  in the project SDK declaration and in the six-file source inventory. MSBuild restore passes
  `RestoreLockedMode=true`, `RestorePackagesWithLockFile=true`, `RestoreNoCache=true`, and
  `NuGetAudit=false`. It must leave source package, temporary configuration, and lock bytes
  unchanged and produce exactly six `4.0.5` global-package roots with nonempty
  `.nupkg.metadata`, nuspec, `.nupkg.sha512`, and source-identical cached `.nupkg` bytes before
  MSI compilation.

  The scoped real acquisition used exact Android-builder image
  `sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121`
  as numeric non-root with bridge egress and no port/host namespace. It acquired, independently
  verified, and no-clobber published all six packages, then retired the exact eight-package
  archive. Persistent postconditions are current-user mode 0700 for the package directory and
  mode 0400, one link, exact length/digest for every file. The canonical self-excluding online
  closure was deliberately regenerated to SHA-256
  `29dc7e958ef7d78c02723d15601fcfe360915d8328cc319a20484513187ecad3`:
  145,715 files, 42,856 directories, 41 symlinks, 25,679,486,815 content bytes, 16 hardlink
  groups, and nine case collisions.

  A separate no-network semantic replay used the already present exact .NET 8.0.422 SDK image
  `sha256:d80fdd84f7e18eea12f8e45c52914f1353395009c95c41197178ea19944e6d48`
  as UID:GID 1000 with read-only root/source, zero capabilities, no-new-privileges, bounded
  resources, and tmpfs-only writes. Starting from a blank global cache, it independently
  verified every exact package SHA-256, both signatures on all six packages, the same cleared
  local-source/package-mapping/trusted-signer configuration used by Windows, and the actual
  updated project plus committed lock. `dotnet restore --locked-mode --no-cache` completed in
  217 ms with the lock unchanged and exactly six complete cache roots. The certificate validity
  dates printed by verification are historical, but the packages carry signed timestamp
  evidence and the offline restore under the pinned exact bytes/signers passed; no live network
  or moving publisher state participated.

  Native Windows diagnosis and correction (2026-08-11) remained fail-closed across successive fresh guest
  attempts. One run established that bare `cmake` was absent from the Windows PATH; the build now resolves the exact
  Visual Studio CMake executable. A second run showed that building the isolated callback target still traversed a
  phony Flutter assembly dependency; the native target now explicitly disables project-reference rebuilding. A
  third run passed the callback test but proved a temporary-directory `NuGet.Config` was not SDK-resolver authority:
  restore attempted `nuget.org` and was rejected. Moving the already locked, signer-pinned configuration to the
  solution directory made source discovery exact. The next networkless guest used only the offline UDF feed but
  correctly failed locked restore with `NU1004`: the evaluated project requested `win`, `win-arm64`, `win-x64`, and
  `win-x86`, while the lock had no runtime target graphs. The project now names that exact `RuntimeIdentifiers` set,
  and the lock adds exactly four empty `native,Version=v0.0/<rid>` graphs. All five direct package identities and
  content hashes are unchanged. A network-disabled, numeric-UID, read-only-root .NET SDK replay independently
  generated and then restored that exact lock with only the pre-existing signed local packages. The focused WiX
  verifier passes and rejects all 27 deliberate mutations, including project/lock runtime-graph and SDK-resolver
  configuration mutations; the independent workspace binding passes.

  The final fresh Windows guest at tree `58c3125332b13a00950cee990d4f16be5d9d4a24` had zero network interfaces and
  restored with only `C:\rustdesk-build\source\res\msi\NuGet.Config` and feed `F:\wix-nuget-packages`.
  The log records all five direct 4.0.5 packages installed from that feed, restore success with zero warnings/errors,
  the native MSI build succeeding with ten documented WiX/ICE warnings and zero errors, canonical MSI package code
  `{6D52FC07-14FE-543E-A63D-6A6449DD7FA8}`, and successful setup packaging. The finally published MSI is
  18,308,615 bytes at SHA-256 `6692c36a11489d1ba1c79f87044970b3926a3067b09f9bbdb28226b3b9ec4b39`.
  This is real networkless WiX restore/compile/package evidence, but it is one worktree build rather than the exact
  committed R-B2 double build. It does not inspect every native MSI table against policy or exercise
  install/repair/upgrade/uninstall and service lifecycle; those remain open.

  Confined Bash/Python checks, the fixed-archive and retirement executable fixtures, offline
  manifest fixture, fixed-archive 63-mutation gate, online-container 39-mutation gate, Windows
  helper 42-mutation gate, Windows harness contract plus 139 mutations and four bounded
  behavioral suites, focused WiX 24-mutation gate, shared source gate, and independent workspace
  mutation matrix bind the producer, consumer, lock, signer, legacy retirement, requirements,
  Appendix C #253, and this ledger. The synchronized requirements identity is recorded below.
  No root process,
  privilege escalation, image pull/build/tag, port, Docker-socket mount, host namespace/device,
  host firewall/network mutation, or host RustDesk process/service/listener/configuration
  inspection or change occurred. This slice does not build an MSI or Windows release artifact,
  inspect native MSI tables, exercise install/repair/major-upgrade/uninstall, complete cross-
  target R-B2 double-builds, close maintenance-image distribution, prove installed/native/device
  behavior, independently distribute build images, or complete R-V3 external review.
- **R-S11da/R-S11db/R-S11dc bootstrap-candidate refresh — ANDROID REAL ACQUISITION-VM
  CANDIDATE, REVIEWED PROMOTION, AND NETWORKLESS CERTIFICATION COMPLETE; DEBIAN/WINDOWS REFRESH
  AND PRODUCT PRODUCERS OPEN.** The corrected transaction installs packages once inside one disposable
  acquisition-VM generation, derives the canonical package inventory from the installed result, embeds the
  recipe/package contract, and applies only a metadata seal before exact capture. Discovery or candidate state
  cannot enter an ordinary loader; final bootstrap pins remain a separately reviewed no-clobber authority.

  At clean pushed commit `337753d692594531ca522d8927a8e6c606b819e8`, `run.dODxMdeH1n`
  completed the real Android package build, nonroot contract inspection, metadata seal, strict canonical archive
  capture, OCI materialization, and private candidate publication in 325 seconds. Its terminal receipt reported
  unchanged host listeners and joined cleanup. The successful run root was retired by policy; the candidate was
  independently reverified at UID/GID 1000, mode 0400, one link, 468,001,119 bytes, and SHA-256
  `d67c950403691bb6db099e1fb19e8113a31a24366d8279b5b83a741c90fabdbc`. After deliberate pin review,
  `run.wn6nrHxpyi` at `92693ea94804bfb6666b6bfb1ca2a52c5fca5062` strictly reverified and
  no-clobber promoted that bootstrap in 39 seconds, with listeners unchanged and cleanup joined.

  The distinct networkless certification and final-image promotion are recorded immediately below. This closes
  the Android bootstrap refresh prerequisite, not the real Gradle/Rust/signing/APK producer, release, device,
  independent-reproduction, or external-review obligations. Equivalent current Debian-builder and Windows-
  helper bootstrap refresh/certification remains open.
- **R-S11da/R-S11e-119 — authenticated Android builder image distribution authority —
  SOURCE, DIRECT-OCI DISTRIBUTION, PROVENANCE SELF-TEST, CURRENT REAL ARCHIVE/RUNTIME,
  PIN-BOUND PROMOTION, COMPACT SOURCE, ISOLATED EXECUTABLE-FIXTURE, AND ONLINE-CLOSURE EVIDENCE
  RENEWED 2026-09-16; CLEAN EXACT-COMMIT R-B2/R-B10 RELEASE, DEVICE/NATIVE, OTHER
  IMAGE-DISTRIBUTION, AND EXTERNAL-REVIEW EVIDENCE REMAIN OPEN.** Platform:
  the unprivileged Linux acquisition/build host, its local Docker/BuildKit engine, and every
  offline Android release consumer. Endpoint/action: `scripts/online-fetch.sh` maintenance
  acquisition, direct certification export/canonicalization, exact-pin promotion, plus ordinary `load_builder_images` and
  `require_pinned_builder_image android-builder`. Boundary: a network/root package-installing
  historical image build and its incomplete source metadata ↔ the exact independently archived
  builder executable authority trusted by release builds.

  Before this slice, `online/build-images/android-builder.docker.tar.gz` was a
  467,527,003-byte archive at SHA-256
  `8103ee08edb4fd40d5d7d86f825f374692fa3d58f549a47ce05a64beecf2e304`.
  Its root image/index ID was
  `sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121`,
  runtime manifest
  `sha256:8eebca9c54a246acfa16bec3ac9768cf7e1cb0e8687ab17c0438b573bd821259`,
  and config
  `sha256:7e3a21f7335f4ab15eec150c07df242424ef626718a110f5b504174fd3217103`.
  Its embedded builder Dockerfile SHA-256
  `a1c2bc0e3475eefc9b16810035013d023b93a2e4db575eaa2cab9f99826bcfed`
  and live/stored package-manifest SHA-256
  `89c22fc379536a5279456a7a1e7f841af90034d7ef47a9f8a508516d4d1e1ee4`
  are exact and internally coherent. Its default mode-min BuildKit statement nevertheless
  supplied local-worktree VCS revision `ef8b…`, while the Dockerfile at that committed revision
  hashes to `7639…`, not the embedded `a1c2…` recipe. Docker's primary SLSA-definition
  documentation explicitly says local-context `vcs` values are client-supplied, unverified
  metadata hints. The mismatch therefore made the attestation insufficient source/build
  authority; it is not evidence that the exact archive or package set changed, that Docker
  escaped, that host root was acquired, that a listener or public port was exposed, that host
  RustDesk/service/configuration/firewall/network state changed, that exploitation occurred,
  or that the host was compromised.

  The historical object is now named and accepted only as
  `android-builder-bootstrap.docker.tar.gz`. Its archive bytes, length, index/config/manifest
  IDs, embedded recipe/package contract, and deterministic materialized OCI-layout SHA-256
  `5c7d43a27ac02e28ae22d6d37d5a566e09a8a8c22937c33609a2ce1a20cfbf75`
  are all separately pinned. The exact-bootstrap role requires current-user ownership, one
  link, mode 0400, exact size, and the modern content-addressed OCI archive form; it cannot use
  a legacy Docker tar layout. `materialize-oci-layout` stably no-follow opens and twice hashes
  that archive, reruns its complete semantic verdict, bounds 4,096 members, 16-MiB metadata,
  and 8-GiB expanded content, admits only the exact OCI root files/directories and hash-named
  blobs, and creates every output through descriptor-relative no-follow `O_EXCL`. Every blob
  must match its name. Files are synchronized and sealed 0400, blob directories 0500, the
  namespace is synchronized, and a fresh inventory/metadata/blob pass derives the independently
  pinned complete-layout digest. The digest is reproved immediately before and after BuildKit
  executes.

  `scripts/Dockerfile.android-builder-certify` is the sole 51-line certification recipe, exact
  SHA-256
  `b665c4007b9a24cc7987e42db64e062c824ef737d03462d5df593c5e572c8bcb`.
  It names only `FROM android-builder-bootstrap`, sets `USER 1000:1000`, and has one
  `RUN --network=none`. That operation verifies live UID/GID, the embedded original recipe,
  both live and stored package-manifest identities, the exact original contract, and every
  required tool. It installs, downloads, copies, and repairs nothing. Certification fixes a
  private empty Docker configuration/client endpoint, clears the environment, sets
  `BUILDX_GIT_INFO=false`, supplies the bootstrap only as
  `oci-layout://<private-layout>@<exact-index-id>`, and invokes BuildKit with no network, pull,
  cache, secret, SSH agent, privileged entitlement, registry context, load, tag, or push. Linux/amd64,
  `SOURCE_DATE_EPOCH=1700000000`, timestamp rewriting, no unpack, and mode-max provenance are
  explicit.

  Certification now writes only
  `type=oci,name=rd-android-builder-certified:authenticated-v1,dest=<private-file>,tar=true`
  with OCI media types, gzip-compressed layers, and timestamp rewriting. The fixed name creates
  the exact exporter annotations and attested subject; it is never installed as a tag or used as
  image-selection authority. The raw outer tar must be current-user-owned, one link, mode 0600,
  and beneath a current-user mode-0700 private parent. Its scanner rejects more than 4,096
  members or 8 GiB, noncanonical inventory/order/header metadata, links/specials/PAX, blob-name
  disagreement, nonzero termination data, and source mutation. The outer index must contain
  exactly one descriptor with the exact name/ref/epoch annotations. Candidate normalization derives
  the candidate index, runtime manifest, and runtime config from the completely validated direct export
  rather than requiring not-yet-reviewed final pins. It rejects an extra root referrer, compatibility
  manifest, unreferenced object, or missing object, strips exporter-only outer annotations, and synthesizes
  one `RepoTags: null` compatibility manifest. It streams a deterministic gzip/USTAR candidate through
  exclusive no-follow creation, seals it mode 0400, and applies the complete semantic verdict before and
  after descriptor-relative no-clobber publication. Only the later promotion path accepts deliberately
  reviewed final archive/index/manifest/config pins.

  The final validator rejects every VCS-shaped field recursively and requires exactly one in-toto
  Statement/v0.1 attestation with a SLSA v0.2 predicate. It exact-matches the subject; the sole
  `oci-layout://<opaque-store>:latest@<digest>` bootstrap dependency; complete external request and five
  build arguments; embedded certification Dockerfile bytes/source map; the exact three-operation LLB graph;
  sole UID/GID-1000 execution with BuildKit network mode 2 and only the root mount; builder/result platform;
  and request-completeness metadata. The provenance layer map must use the exact original uncompressed
  descriptors from the independently rehashed pinned bootstrap OCI layout: step zero is its three layers,
  and step one is those same layers plus the new certification layer. The runtime output separately requires
  four rewritten gzip layers, 21 history entries with the final eight at the fixed epoch, exact Docker 27.5.1
  loaded-config representation, no root descriptor annotation, no archive tag, and no unreferenced
  blob/member.
  Runtime verification launches only the final content ID with no pull/network, a read-only
  root, UID/GID 1000, all capabilities dropped, no-new-privileges, PID/memory/no-swap/CPU
  ceilings, and bounded non-executable tmpfs, then rechecks live UID/GID, recipe/package
  contract, and tool resolution.

  The current canonical certified archive is 474,623,832 bytes, current-user-owned, single-link,
  mode 0400, with SHA-256
  `918c3b696270bbb9a5ff70ea8cabd19f5a5d353503af3268ab2951a0ec66cd06`. Its root image/index ID is
  `sha256:420530ff412c240c70ed510d019c27cfb9cce99c9dc9e669beb9fda818999b43`, exact runtime
  manifest `sha256:38b072fca23d9bebb5f817cf9cc4519544b0435bb3144cd92cfa547f1f0289ac`, and config
  `sha256:66059635c06f8e003312d8e897d3ed664fca790ce6cafc5a6b531992b5063119`.

  At clean pushed commit `bc3bfe9cc6ceb4dd928cd89906ae542bf0f62928`, real
  `run.61vb0nCRcV` completed exact-bootstrap materialization, BuildKit v0.18.2 networkless
  certification, bounded direct-OCI normalization, complete semantic verification, guest-only Docker load, and
  confined runtime fingerprint in 99 seconds. After deliberate pin review at
  `b5d39e1dafd0fe534fac02f4cff78750a4a0453b`, real `run.phE39wA0oN` reverified the complete
  candidate against those pins, no-clobber promoted the same inode, and repeated the complete final load/runtime
  verdict in 38 seconds. Both source-bound receipts require no host forwarding, unchanged host listeners,
  guest-only Docker/BuildKit, and joined cleanup. The candidate path and successful run roots are absent; the
  final archive above is present and independently rehashed from the host as an ordinary file read.

  BuildKit records dynamic invocation/session data in the attestation, so a subsequent outer index/archive need
  not be byte-identical even when the runtime manifest/config are reproduced. The current image has not yet had
  a second independent current-source certification or cold R-B2/R-B10 product build, and no such claim is made.
  Failed diagnostic candidates remain confined beneath their exact failed-run evidence rather than entering the
  fixed candidate or final namespace.

  Ordinary `load_builder_images` now accepts only the certified archive with exact byte size and
  full certified spec, then revalidates the exact loaded ID/runtime. Five Android release
  consumers retain `ANDROID_BUILDER_IMAGE_ID`, which now names only the certified content.
  The bootstrap archive and `android-builder-bootstrap-candidate` role cannot enter ordinary
  runtime verification. Networked package installation remains an explicit maintenance
  `build_android_builder_bootstrap_image` operation; exact bootstrap capture is separate; and the
  bootstrap becomes eligible material only after the networkless certification transaction.
  The prior self-authorizing `build_android_builder_image` surface and Android Docker-store
  capture function are absent; generic builder capture now covers only the Windows helper
  image. New archive publication uses a current-user mode-0700 parent, current-user mode-0400
  one-link source, and descriptor-relative `renameat2(RENAME_NOREPLACE)` with namespace
  synchronization and inode postcondition; occupied state is preserved.

  The complete provenance self-test passes 39 Android-builder decisions: the positive
  archive/runtime baseline; archive hash/size; all image/config/manifest/bootstrap/recipe/
  package/epoch pins; runtime user; archive mode/hardlink; and adversarial tag, VCS, embedded
  source, execution network/user, registry context, material, layer map, runtime user, root
  annotation, layer epoch, subject, missing-attestation, and extra-operation fixtures, followed
  by a final positive replay. The added decisions cover successful direct-export normalization,
  wrong raw mode, raw hardlink, wrong exporter name, extra outer referrer, unexpected
  compatibility manifest, occupied normalized output, and byte-identical normalization replay.
  The former 1,282-line focused mutation catalog and its duplicate 237-line workspace validator
  are deleted. Neither executed an archive, canonicalizer, loader, or certification operation;
  they mutated source and documentation wording and made unrelated verifier structure part of
  the verdict. A compact Android-specific source invariant now binds the reviewed pins and
  certification Dockerfile, final-only loader, local-OCI networkless build, verify-before-no-clobber
  promotion, and absence of the retired self-authorizing/Docker-store paths. The authenticated
  no-NIC verifier VM runs that compact invariant and the executable provenance self-test as
  UID/GID 4000; the latter executes the 39 Android archive/direct-OCI decisions, including
  referrer, metadata, no-clobber, and deterministic-normalization failures. The focused authority
  pass completed in 25 seconds with unchanged host listeners and joined residue-free cleanup. That historical
  pass remains fixture behavior; the distinct current 474,623,832-byte archive build, load/runtime verdict, and
  pin-bound promotion are the real acquisition-VM runs recorded above. The final confined proportional rerun
  also passed online-fetch
  container authority's 44 mutations; Apple image authority's 56; Dart image authority's 85;
  Rust image authority's 95; Bash syntax, Python byte-compilation, HTML parsing, native-codec
  normal/mutation checks, and diff hygiene. Dart/Rust focused gates now bind the centralized
  five-image private-archive classifier and exact candidate functions rather than source-order-
  dependent legacy tuples. The self-excluding complete ignored online tree was regenerated and
  independently verified at
  `1e7e9a813e2ee2b3325205f9db29c335086133a6a900ee585639125bcf4ee70e`:
  145,627 files, 42,831 directories, 41 symlinks, 29,224,673,274 content bytes,
  16 hardlink groups, and 9 case collisions.

  One diagnostic attempt used a `docker-image://sha256:…` additional context while determining
  BuildKit's accepted context syntax. BuildKit attempted outbound registry resolution and failed
  before any Dockerfile operation, image publication, or archive change. That approach was
  abandoned; the implemented path is the documented local
  `oci-layout://…@sha256:…` form and the final attestation rejects a registry context. An earlier
  corrected maintenance attempt exported through Docker's shared image store and then saved the
  captured content ID. Because that store already retained the canonical archive's attestation
  referrer for the identical runtime manifest, the saved outer index contained an unrelated
  second descriptor. The validator rejected it as anything other than exactly one captured
  image; no candidate/final was published or changed. This engine-state-dependent capture is
  the reason the Android store/tag/save path was deleted in favor of direct OCI output, not
  evidence of compromise. No root
  command or root container, privileged flag, added capability, host namespace/device, Docker
  socket passed into a container, published port, release build, or host RustDesk
  process/service/configuration/listener/firewall/network inspection or mutation occurred.
  This slice does not complete the clean independent-snapshot R-B2/R-B10 transaction, build or
  sign an APK, test Android devices or the original swipe/relaunch sequence, prove native
  installed-platform behavior, authenticate/distribute other maintenance images,
  or complete R-V3 external review.
- **R-S11db/R-S11e-120 — authenticated Debian builder image distribution authority —
  SOURCE, DIRECT-OCI DISTRIBUTION, REAL ARCHIVE/RUNTIME, INDEPENDENT RUNTIME-GRAPH
  REPRODUCTION, AND COMPACT SOURCE/NO-NIC FIXTURE EVIDENCE PRESENT; CLEAN
  EXACT-COMMIT R-B2/R-B10 RELEASE, INSTALLED DEBIAN LIFECYCLE, OTHER MAINTENANCE-IMAGE
  DISTRIBUTION, DEVICE/NATIVE, AND EXTERNAL-REVIEW EVIDENCE REMAIN OPEN.** Platform: the unprivileged Linux
  acquisition/build host, its local Docker/BuildKit engine, and each offline Debian release
  consumer. Endpoint/action: the Debian image maintenance acquisition, direct certification,
  canonicalization, exact-pin promotion, ordinary `load_builder_images`, and
  `require_pinned_builder_image deb-builder`. Boundary: a historical network/root
  package-installing build with incomplete source metadata ↔ the exact independently archived
  builder executable authority admitted to release compilation.

  Before this slice, `online/build-images/deb-builder.docker.tar.gz` was a 462,069,452-byte
  archive at SHA-256
  `361e04156023e286e4c0014753e379a2aef1e63c4f3a56ea7dafa316ecb15d6f`.
  Its image/index ID was
  `sha256:6766564c65b0daead7d7031fcf0ff9ec8becab6ef9e3f9a7efd9f02f1b893776`,
  its runtime manifest was
  `sha256:9fa4f01154f278ecf285bad9e59940ebb181d6464489dbd9473f40320e2482f6`,
  and its config was
  `sha256:ff9c506bb404f079cf37d36396d25d4a53fb6b57aeff258f7764b1900c62c738`.
  The embedded Debian recipe SHA-256
  `3f50a91a679138318c5cc0f7151fd4cf1d3ec55e6fa6736b67b88919eab8d9b6`
  and live/stored package-manifest SHA-256
  `e5003404717eea27ffb2cb6cf1aaac72b89b5ea6e70d11c16c605a15129760ae`
  are internally coherent. Its only mode-min BuildKit provenance nevertheless supplied
  local-worktree VCS revision `ef8b8226…`; the Debian builder Dockerfile committed at that
  revision hashes to
  `dc2109a073bca71de0fb481c537a2f8e264ce0f678292385d8a5f01f7f43fa9c`,
  not the embedded recipe. Docker's primary SLSA-definition documentation says those
  local-context VCS values are client-supplied, unverified metadata hints. That mismatch made
  the old attestation insufficient build/source authority. It is not evidence that the exact
  archive or package set changed, Docker escaped, host root was acquired, a listener or public
  port was exposed, host RustDesk/service/configuration/firewall/network state changed,
  exploitation occurred, or the host was compromised.

  The renewed bootstrap-only `deb-builder-bootstrap.docker.tar.gz` is 453,785,262 bytes at
  SHA-256 `ca955262563bfe5b0190dc0b6127a55c0986502bb0430ca754511d835f51e83e`, image/config
  `sha256:7fcb86e05617e2b70fc645d24205d3cd8cab13e31f4c172c43d610cfa52ed919`, manifest
  `sha256:4b6d5df1dee2b8ee1d132d51ab29e99ad697e69e37a8c0b44ddda39617fff4a5`, and complete
  materialized OCI-layout SHA-256 `17f64d3dbf1ce147971b5692e6fff58b03a0649bee7267711fcd6a66bf84e089`.
  Its current recipe/package contract is separately pinned. The bootstrap verifier requires a current-user-owned,
  one-link mode-0400 modern content-addressed archive and cannot accept it as the final role. The common
  materializer stably no-follow reads and twice hashes it, applies bounded exact-member and
  expanded-byte rules, creates every member descriptor-relatively with no-follow exclusive
  creation, validates blob bytes against names, synchronizes and seals the layout, and proves
  that independent complete-layout identity immediately before and after certification.

  `scripts/Dockerfile.deb-builder-certify` is the sole 51-line certification recipe at SHA-256
  `d5f22c0adbec24e9f95a51ad5f40ce32d5fea59c7d840bdbf7f15caca6af0283`.
  It names only `FROM deb-builder-bootstrap`, sets `USER 1000:1000`, and has one
  `RUN --network=none`. That operation proves live UID/GID, the embedded original Debian
  recipe, live and stored package manifests, exact `deb-builder` provenance contract, and all
  required build tools. It installs, fetches, copies, and repairs nothing. The maintenance
  build fixes an empty private Docker configuration/client endpoint, clears client Git
  metadata with `BUILDX_GIT_INFO=false`, supplies only
  `oci-layout://<private-layout>@<exact-index-id>`, and invokes BuildKit for Linux/amd64 with
  no network, pull, cache, secret, SSH agent, privileged entitlement, registry context, load,
  tag, or push. Mode-max provenance, `SOURCE_DATE_EPOCH=1700000000`, OCI media types, gzip
  layer compression, and timestamp rewriting are explicit.

  BuildKit writes only the fixed private direct OCI export
  `rd-deb-builder-certified:authenticated-v1`; it never loads or tags that result. The common
  raw-export scanner requires a current-user-owned one-link mode-0600 tar under a
  current-user mode-0700 directory and rejects more than 4,096 members, more than 8 GiB of
  expanded content, malformed inventory/order/headers/modes/timestamps, links/specials/PAX,
  blob-name disagreement, nonzero trailing data, extra outer descriptors/referrers,
  unexpected compatibility metadata, unreferenced objects, and missing reachable objects. The
  canonicalizer derives the candidate index from the sole named descriptor, exact-matches the
  pinned runtime manifest/config and reachable graph, strips exporter annotations, synthesizes
  `RepoTags: null`, and streams deterministic gzip/USTAR bytes through no-follow exclusive
  creation. It reproves the raw source, seals the result mode 0400, and applies the semantic
  verdict before and after descriptor-relative no-clobber publication.

  The final certified archive is current-user-owned, single-link mode 0400, exactly
  463,321,996 bytes, and SHA-256
  `a1426f726639c5d7b62ea5bf6515b514e99ebde95feccf468e7c081f1080b0e5`.
  Its image/index ID is
  `sha256:48596720e13492e8a511b35ad88932f23f19dd9271b9eb3da3c12c016698dabb`,
  runtime manifest
  `sha256:b7eab9b6c0fedadd213116e58f99826648bdb27c58e1bda6c9cc321b862cea5e`,
  and config
  `sha256:304b251e77fafe03192e035cc22479e0909d688035fbd30b1ac685e878ae9646`.
  It has the exact three inherited layers plus one certification layer, 22 normalized history
  entries, numeric-nonroot runtime config, exact labels, no tag/outer annotation or
  unreachable member, and one in-toto provenance statement. The generalized verifier rejects
  every VCS-shaped field and exact-matches the subject; sole bootstrap material; request and
  five build arguments; embedded certification Dockerfile and source map; complete
  three-operation LLB; local OCI store/session; sole UID/GID-1000 execution with BuildKit
  network mode 2 and only the root mount; layer mapping; platform; metadata; and
  request-completeness state.

  The reviewed production candidate was semantically verified before promotion, renamed as the
  same inode through descriptor-relative `RENAME_NOREPLACE` only after every final pin matched,
  and then loaded and runtime-verified from its stable descriptor at the final name. The
  confined runtime uses no pull/network, a read-only root, UID/GID 1000, all capabilities
  dropped, no-new-privileges, PID/memory/no-swap/CPU ceilings, and bounded non-executable tmpfs,
  then rechecks live identity, embedded/live package contract, and tools. Failed-closed real build
  `run.zHiuvMH6SF` and corrected real build `run.w9S8gnkc6K` independently reproduced the exact
  runtime manifest and config above; the former stopped before candidate publication only because the verifier's
  then-stale history count expected 21 rather than the proven 22. Their dynamic outer indexes differ
  because mode-max provenance records invocation/session/timestamp metadata; no byte-identical
  attestation-archive claim is made.

  Ordinary loading now admits only the exact final `deb-builder.docker.tar.gz`. The
  bootstrap and fixed `deb-builder-certified-candidate.docker.tar.gz` cannot enter that path.
  Networked acquisition can emit only `deb-builder-bootstrap-candidate`; Debian capture can
  archive only the bootstrap role; and generic final capture is absent. The old
  self-authorizing `build_deb_builder_image`, shared `capture_builder_image`, generic
  `maintenance_capture_builder_images`, and its CLI entry point are absent. The compact
  Debian-specific gate now checks only exact pins/recipe, bootstrap-only acquisition and capture,
  final-only loading, the local-OCI networkless certification transaction, verify-before-no-clobber
  promotion, runtime-verifier arguments, and retired fallback absence. Common archive, attestation,
  and canonicalization semantics remain owned by the executable provenance fixtures rather than a
  reciprocal source verifier.

  The sole no-NIC verifier VM runs that compact gate as UID/GID 4000 and runs the generic
  provenance self-test with a certified Debian archive/direct-OCI fixture. The Debian fixture
  validates the role-specific Ubuntu 18.04 base, 22-entry history, runtime/tool/cat contract,
  attestation source, and direct normalization, and refuses wrong role, base, and embedded
  certification source. The shared Android fixture continues to exercise the larger common
  archive/attestation/ownership/graph/contamination/no-clobber matrix. This generated fixture is
  not the 463,321,996-byte release archive, a real BuildKit certification, or a loaded-container
  fingerprint. The exact current real-archive/runtime and repeated runtime-graph results are recorded above.
  Current cold exact-commit R-B2/R-B10 determinism,
  installed Debian lifecycle, other maintenance images, native/device behavior, independent
  reproduction, and external review remain open.
- **R-S11dc/R-S11e-121 — authenticated Windows helper image distribution authority —
  RENEWED BOOTSTRAP AND CERTIFIED FINAL BUILT, REVIEWED, PINNED, AND PROMOTED;
  COLD RELEASE, WINDOWS GUEST LIFECYCLE, INDEPENDENT REPRODUCTION,
  AND EXTERNAL REVIEW REMAIN OPEN.** Platform/boundary: the unprivileged acquisition host,
  local Docker/BuildKit certification transaction, and every offline Windows-release helper
  consumer must admit one authenticated final helper without treating a mutable image tag,
  network response, or self-asserted historical capture as authority.

  The current bootstrap is the reviewed 995,301,648-byte archive at SHA-256
  `541abfbed8600324a89d7e77acb7b1782682dab52ca97f039abd4622347a2e69`, image/config
  `sha256:d87ce47b24a9c71a9053d163043c0e64d70a80c342b2c6a7e4c9824f1ce40c13`, manifest
  `sha256:40c34d0ec4ce22ead7c57f194fe98b0c4e8b6b397d5c5252ba6a63319a643320`, and OCI-layout
  SHA-256 `2383c9c3405e937568b62a5eee85237d0874d28c45bf41e671b5dd69bb257644`.
  It binds the current recipe/package contract, remains bootstrap-only, and cannot enter the
  ordinary loader. Acquisition and pin-bound promotion are the separate reviewed transactions
  recorded above; no mutable tag, registry lookup, or unreviewed network response authorizes use.

  Final authority is one networkless UID/GID-1000 certification from that descriptor-verified
  local OCI layout. The exact `Dockerfile.win-helper-certify` proves the embedded recipe,
  live/stored package inventory, helper tools, `olefile`, and role contract without acquiring
  or repairing anything. BuildKit receives no registry/tag context, pull, cache, secret, SSH
  agent, privileged entitlement, load, tag, save, or push authority and directly exports one
  private mode-max OCI result. The bounded shared canonicalizer produces the deterministic
  null-tag mode-0400 archive and promotion verifies every final pin before descriptor-relative
  `RENAME_NOREPLACE`.

  The final archive pins are image
  `sha256:5fe6b794695afc69c32d037f1e6e24224f2925c2e48e98d82c35a23b584ee256`,
  manifest
  `sha256:72e72381f5402ae5ab495b99b9a4ff4ce9c7d08aea2a679ab8760cc2de6bc030`,
  config
  `sha256:a5a8ff785ebe749eabc4bb4aaf8e438bbf12a6551663148d6ac60f94c02a9ea3`,
  998,725,383 bytes, and SHA-256
  `e7dae7a080fda65778ef7ed3c05bcb31b98830f56f514b2f01c084f055b66995`.
  Ordinary loading, all three Windows helper consumers, and kernel derivation select only that
  final archive; the runtime repeats full archive verification before and after derivation and
  requires the exact loaded fingerprint. Networked acquisition and capture are bootstrap-only,
  and generic/tag/save/final-capture fallbacks are absent.

  Verification is split by observable property. The shared executable provenance suite owns a
  distinct 21-decision Windows-helper archive/inspect/attestation/direct-OCI branch: it validates
  the exact role contract and rejects identity, recipe, package, epoch, root, network, VCS,
  source, exporter-name, and layer-map drift. The compact Windows-specific source gate owns only
  pins, Dockerfile and shell transaction shape, final-only runtime selection, downstream
  consumers, and retired-fallback absence; the former 49-mutation catalog, documentation checks,
  provenance implementation scan, and reciprocal whole-workspace validator are deleted. Both
  gates execute as UID/GID 4000 in the sole no-NIC verifier VM, which uses private Unix
  management channels and proves host-listener invariance and joined residue-free cleanup.

  The current certification, independent archive review, pin transition, and separate final
  promotion are recorded above. They prove the real networkless graph, exact loaded-runtime
  fingerprint, final archive identity, no-clobber publication, candidate retirement, and cleanup.
  This builder prerequisite is not Windows product or release evidence. Historical evidence also
  records device-free derivation of the pinned 15,042,952-byte
  `vmlinuz-6.8.0-134-generic` at SHA-256
  `72526aac4c8c3f63d30fe0741f0c3b1923e700585750cb135815d5c2f831b691`.
  The generated executable fixture is not the real bootstrap or certified archive, a current loaded
  container, or a Windows artifact. Current clean exact-commit R-B2/R-B10 output, Windows guest
  build/install/upgrade/uninstall and native
  behavior, other maintenance images, independent reproduction, and R-V3 review remain open.
- **R-S11dd/R-S11e-122 — runtime-smoke host, Docker-client, build-user, and checkout-write
  authority — SOURCE MIGRATED TO THE SOLE VERIFIER VM; REAL VM ENTRY/DOCKER REQUEST, ROOT/FOREIGN
  REFUSAL, LISTENER INVARIANCE, AND JOINED CLEANUP GREEN 2026-09-15; FULL PRODUCT SMOKE, EXACT R-B2
  ARTIFACT, NATIVE TARGETS, AND EXTERNAL REVIEW REMAIN OPEN.** Platform: the unprivileged
  Linux orchestration host, networkless verifier VM, and guest-container Linux
  runtime-smoke fixtures. Endpoint/action: `scripts/smoke-server.sh` Docker resolution,
  compilation, ordinary runtime, service lifecycle, PID-reuse, and sibling orchestration;
  `scripts/smoke-process-guard.py` process-identity proof. Boundary: the invoking user and
  live repository ↔ Docker-client/daemon selection, host `/proc`, build-container identity,
  dependency caches, and container runtime fixtures.

  Before this slice, the harness invoked `docker` through `PATH` and inherited the caller's
  Docker context, host, TLS, configuration, and related client environment. Docker documents
  that `DOCKER_CONTEXT` overrides `DOCKER_HOST` and that client configuration participates in
  daemon selection (https://docs.docker.com/reference/cli/docker/). The harness also executed
  `scripts/smoke-process-guard.py` directly on the host before and throughout the smoke; its
  `record` and `monitor` modes enumerated the complete host `/proc` process set to reject new
  command lines matching a historical RustDesk selector. Finally, `BUILD_RUN` accepted the
  image's default UID 0 and mounted the live checkout read-write. Docker documents both that
  the default container user is root
  (https://docs.docker.com/engine/containers/run/#user) and that a writable bind mount lets a
  container create, change, or delete host files
  (https://docs.docker.com/engine/storage/bind-mounts/#considerations-and-constraints). These
  were unnecessary daemon-selection, host-process-inspection, and source/build authorities.
  They are not evidence that a remote daemon was actually selected, any host process was
  signaled, the checkout was changed, Docker escaped, host root was acquired, a listener or
  public port was exposed, host RustDesk/service/configuration/firewall/network state changed,
  exploitation occurred, or the host was compromised.

  The current orchestrator refuses UID or primary GID 0 before reading product inputs and
  admits only the authenticated R-S11dh verifier-VM entry. It uses the fixed guest-private
  Docker Unix socket, root-owned mode-0555 client, and root-owned canonical-empty read-only
  configuration in an otherwise empty environment; the common entry preflight re-proves the
  exact client/daemon bytes, daemon PID/start generation, socket metadata and root peer before
  and after every operation. There is no `/var/run/docker.sock`, host-root Docker, rootless-host
  Docker, network API, or second authority fallback. Private source/target identities remain
  independently rechecked and identity-safe cleanup still preserves ambiguous state.

  `BUILD_RUN` is now the invoking numeric non-root UID:GID with all capabilities dropped,
  no-new-privileges, a read-only container root, no network or pull, and explicit PID,
  memory/no-swap, CPU, and executable scratch ceilings. A 2026-08-04 source-authority
  follow-up removed the complete live-checkout bind, including ignored residue, from every
  container. The orchestrator now requires a clean tracked/nonignored tree, resolves one full
  `HEAD` commit, creates a private `git archive`, extracts it with canonical read-only modes,
  records independent archive and complete-tree SHA-256 values, and verifies source object
  identity and tree content after compilation and again after all runtime stages. The only
  Cargo output bind is a new private mode-0700 target owned by the invoking user. It is mounted
  at the disjoint top-level `/smoke-target`, never below the read-only `/work` source mount. The
  build alone receives the canonical offline-input root read-only; every ordinary, lifecycle,
  PID-reuse, and sibling fixture receives only the exact source snapshot and private target
  read-only. The root/capability-requiring service and
  PID-reuse fixtures remain container-only with network none, no published port, Docker
  socket, device, host namespace, writable source, or writable build output. Their root and
  capability semantics are intentionally not described as non-root because they exercise
  installed-service behavior; reducing those per-fixture capabilities remains separate from
  this host/build-authority closure.

  The host-wide selector, baseline, monitor, stop-control, and record modes and every host
  call site are deleted. `scripts/smoke-process-guard.py` now has only `wait-server`,
  `wait-service-server`, and a pure self-test. Its `/proc` reads are PID-specific exact
  executable/start-time/closed-argv authority proofs invoked only from isolated smoke
  containers. The prior host-monitor evidence recorded under R-S11c-27j and related
  historical runtime entries is historical only and no longer describes a current execution
  path. R-S11dd and Appendix C #257 make this closure normative.

  The trigger for that follow-up was an evidence review, not an observed product failure: two
  ignored generated Rust bridge files existed beside the clean checkout and the prior smoke
  mounted that checkout wholesale. The smoke build uses default `use_dasp` plus
  `linux-pkg-config`, not the optional `flutter` feature; `src/lib.rs` therefore compile-time
  excludes `bridge_generated.rs` and `bridge_generated.io.rs` from this server build. The
  earlier green portable run remains real working-tree Linux behavior, but is deliberately not
  promoted to new exact-commit evidence until the corrected committed harness is replayed. No
  source-generation transaction is added to this non-Flutter smoke, and no ignored output is
  silently treated as committed authority.

  The first replay of committed exact-source correction
  `e5ec1105e0b18ee512060632b99ff7ed759a8cfc` on 2026-08-04 failed closed before any
  container command or RustDesk product code started: Docker could not create the requested
  nested `/work/target` mountpoint beneath the read-only exact-source mount. The transcript had
  already bound source archive SHA-256
  `17c52eae53782d9b8e48c852dec174610787285ca77c462aff5eb83d066aa690` and tree SHA-256
  `7eb9c258ec3ba5fec97d7bfc7f29165ada67a1aa4fd1b274d727b349ae7aca08`.
  Cleanup removed the private smoke workspace and test container state; the attempt opened no
  listener and exercised no product behavior. This was a harness mount-topology defect, not a
  RustDesk runtime failure. The source correction now uses disjoint `/work` and
  `/smoke-target` mounts. Bash/Python syntax, the independent normal semantic contract, the
  native-codec normal/self-test gates, and one uninterrupted complete source-mutation catalog
  passed in the same pinned non-root, networkless, read-only verifier image. The correction
  remains unpromoted to runtime evidence until that exact committed topology passes the complete
  confined product replay.

  The first exact-commit replay of the disjoint topology at
  `12ebd52614e969134a31c10cc26600879374c3ac` bound source archive SHA-256
  `185896ccfbe94b99f2d7ef8f33f02f4452f98c366e06ba97bd756521b3c6e321` and tree
  SHA-256 `e53532644da30a688b458edd9c4f414466409f1a3ed69a42b2c845ebc3c6803d`.
  Compilation and every later portable stage completed, including loopback-only/zero-UDP listener
  proof, graceful drain, correct/wrong CPace, capacity shed, authenticated Remote admission to the
  exact headless result, port-forward echo, FileTransfer admission, forged-frame rejection,
  different-source limiter safety, and real 60-second limiter decay. The run nevertheless ended
  red because the initial no-password parked stage's readiness checker compared a live log's byte
  size before and after opening its pinned descriptor. A legitimate append in that interval changed
  size and produced `log changed while being pinned` before the stage emitted its complete
  alive/socket/diagnostic result. Typed IPC subsequently reported `state=parked`, but that alone is
  not promoted to no-listener proof. The orchestrator then emitted three unsupported derivative
  failure claims from the absent result lines. Source review proves this as an evidence-harness race:
  immutable probe identity correctly retains size, while an append-growing log must be pinned by
  stable object/type/ownership/mode/link identity without size. The correction separates those
  identities, adds a deterministic growing-log self-test, and evaluates parked product assertions
  only after a zero-exit isolated stage. No RustDesk product source or policy changes in this
  follow-up. The failed replay published no port, touched no host RustDesk/service/firewall/network
  state, and cleaned all private smoke/container state; its successful later stages remain truthful
  partial behavior, not a green transaction.

  The evidence-only correction was committed and pushed as
  `c2004d46c2d5026ec74e997c5b12a4530196c9c6`; local `HEAD`, `origin/master`, the
  fetched branch, and an independent remote-head query matched before the replay. Its fresh
  exact-commit portable-rootless replay bound source archive SHA-256
  `362a413dd43fcc068bd43a6e9f963437c6e337b07e428f205ba3124362fad03d` and tree
  SHA-256 `1b3d060c0a332388b883ac9fbd3705c3f3f06801fbc3ea0bc02d9d086185ae86`,
  rebuilt the server and probes in a new private target, and exited zero. The runtime proved the
  readiness helper, VP9 MDWE, no-password alive/parked/no-listener state, exactly one
  container-local `127.0.0.1:21118` TCP listener with zero UDP, graceful drain, correct/wrong
  CPace, capacity shedding, keyed Remote admission to the exact expected headless-display refusal,
  sealed port-forward echo, FileTransfer admission, forged-frame AEAD rejection, different-source
  limiter safety, and a real 64-second hold followed by recovery after the 60-second limiter
  window. The entire run used the exact numeric non-root executable, no published port, no host
  network/namespace/device/Docker-socket mount, and no host RustDesk/service/firewall/network
  inspection or mutation. Scoped cleanup found a clean Git tree, no current-user
  `/tmp/rustdesk-smoke.*` workspace, and no `rd-smoke-` container.

  This green result is server/protocol evidence, not end-to-end evidence for the reported stale
  display/focus lifecycle fault. Portable-rootless mode did not enter root/service/init-system/
  user-creation/installed-layout/packet-capture stages, and the replay had no Flutter engine,
  Android persistent-service lifecycle, Windows focus transition, native graphical session,
  physical device, real peer screen stream, background/suspend transition, performance/soak, or
  release artifact. Those native cross-platform connection/display lifecycle obligations remain
  open and must not be inferred from this smoke.

  No project application binary, root fixture, host-process scan, listener, firewall/network
  query, or host RustDesk process/service/configuration inspection or mutation was performed
  while implementing or verifying the original source slice. The later failed exact-source
  replay entered Docker only far enough to encounter the pre-command mount error described
  above; it did not start the application. The full root-containing runtime smoke was
  intentionally not run; its current-source runtime behavior and exact artifact remain R-B2
  evidence, and external expert review remains R-V3.

  Current correction: `smoke-server.sh` now authenticates the R-S11dh entry before reading
  product inputs or creating scratch, refuses UID/GID 0, binds the guest marker to pinned Docker
  27.5.1, and wraps the fixed guest socket/client/read-only configuration with pre/post entry
  replay. The VM harness carries the actual entry on read-only media and behaviorally refused VM
  root and UID/GID 4001, admitted only UID/GID 4000, and completed a real Docker client/server
  version operation. Repeated complete KVM executions finished in 16–17 seconds with `-nic none`,
  unchanged host listener sets, and joined cleanup. Xvfb preparation now uses `--network none`,
  a read-only `/xvfb-inputs` mount, exact package metadata/digests, and no Curl/Wget path; this
  source correction was not runtime-exercised because its authenticated package closure is not
  present. The exact development image and complete source/vendor/Xvfb input medium are likewise
  absent, so no RustDesk build, listener, protocol, display, video, root fixture, installed-service,
  artifact, native-platform, or performance/soak claim is made.
- **R-S11df/R-S11e-124 — Dart advisory execution authority — CURRENT NO-NIC OSV
  SCAN PASS 2026-09-22; RELEASE EVIDENCE OPEN.** `scripts/dart-audit.sh` refuses UID/GID
  zero and authenticates R-S11dh before reading the lockfile/policy or creating scratch.
  Image inspection and both bounded scanner launches use only the fixed guest client,
  guest-private socket, and root-owned read-only configuration in an empty environment,
  with VM preflight replay before and after every operation. Its former host
  `/var/run/docker.sock` authority and private host-client configuration lifecycle are
  deleted. The KVM harness carries the actual entry on read-only media, rejects VM root
  and UID/GID 4001, admits only UID/GID 4000, and completes a real Docker client/server
  request without a VM NIC or host listener; repeated current runs finished in 19–20
  seconds with joined cleanup. The old 958-line cross-subsystem mutation
  catalog is replaced by a compact no-fallback and launch-shape source check; the same
  guest executes the separate 31-decision scanner-result behavioral test, while
  acquisition/OCI provenance retain their own focused gates.
  Focused fixed-archive acquisition owns authenticated loading of its exact certified builder into each
  fresh guest containerd store instead of relying on caller preload order; the WiX entry no longer loads
  unrelated builders. The July Pub generation's clean HTTP-404 refusal established that a GCS generation
  is immutable only while retained. Maintenance discovery at `3b0e50a` therefore queries one fixed GCS
  object, binds an exact generation and metageneration, validates the publisher and independent checksums
  plus bounded ZIP/OSV structure, rechecks latest metadata for replacement, and emits review-only pins
  without publication authority. Run `run.xpZPC90COW` discovered generation `1789013095985302`, updated
  `2026-09-10T04:04:56.119Z`, at SHA-256
  `6d103d73cb21483dfb0f1c04f3a37e1485e8d37b568d084f772dc9cfb28e9716`.
  Commit `55dc913` deliberately promotes that reviewed revision once in `pins.env`; the fixed-archive
  verifier now checks canonical bounded pin shape, timestamp/epoch and size relationships, and exact
  manifest consumption instead of duplicating a stale database version. Exact ordinary acquisition run
  `run.rAYEcZNjXU` then loaded and verified the certified Android builder, requested only that generation,
  independently validated the 19,142-byte/13-record/47,157-expanded-byte database and the 56,676,514-byte
  scanner, and no-clobber published both mode-0400 inputs. Its 49-second receipt binds exact source,
  QEMU user-only egress, UDP denial, absent host forwarding, unchanged 605-byte host listener inventories,
  guest-only Docker/BuildKit, and joined cleanup.

  Repository-local Dart audit-image reconstruction and archive distribution are now closed for this
  snapshot. Commits `22b5c339`, `fed5eaa0`, `d8b1fe3a`, `21a5704f`, `4bcf4450`, and `fdcb194a` make
  reconstruction recoverable, bind deterministic created/layer epochs, model the exact native SLSA v0.2
  statement and LLB graph emitted by pinned BuildKit 0.18.2, and retain useful fail-closed graph diagnostics.
  The intermediate VM runs stopped before publication on a misplaced spec property, an incorrect v1
  provenance assumption, and a newer-builder-only source attribute; their retained evidence was used to
  correct the exact model rather than weaken it or fabricate a fixture pass.

  Fresh acquisition run `run.n4FnJ8P0Uq` at `fdcb194a` performed two no-cache, `--network=none` builds in
  one disposable guest. Both produced runtime manifest
  `sha256:cfddb726527d6434eaf6e652f0c404d6115aa879fcc02a71645446f0bac5baf6` and config
  `sha256:0a4213605273bbe7272cde29fa6376cd6391aa3d1797add39121822131879443`; the reviewed second
  provenance index is `sha256:f44a8c8c2cdbb7269dbcc6a3a726acfe35f94d2a183ec62ef821d94ff57d5f2b`.
  Its private candidate archive was 45,818,990 bytes at SHA-256
  `8ccf86653e1a1de16ddf9dc6657daad49b29c51d58771ad70fa779a038272a0c`. Commit `f6ff9b38`
  records those reviewed pins. Separate fresh-VM run `run.xzqruM0OmH` then reverified the candidate against
  that commit, no-clobber promoted it to the final mode-0400 archive, loaded it into the empty guest store,
  and verified the exact image. The 69- and 27-second receipts bind guest-only Docker/BuildKit, QEMU
  user-only networking with no host forwarding, UDP denial, byte-identical 605-byte host listener
  inventories, and joined cleanup.

  Commit `4ca6c2f` adds the actual focused transaction rather than promoting an entry/source check into verdict
  evidence. Three retained VM failures then corrected real integration faults: unreadable root-extracted source
  (`run.JQqIXQMRLV`, fixed by `f115da6`), confusion between the OCI publication index and classic-Docker runtime
  config identity (`run.AFpgN5nwWg`, fixed for Dart by `be5f6b4`), and a focused-path descriptor ceiling below the
  descriptor-bound cleanup requirement (`run.CImYjMHdDD`, fixed globally by `a82aaba`). Their listener inventories
  were unchanged; none is counted as a pass.

  Exact clean pushed-source run `run.EDeOJHBrIT` at
  `a82aaba7fd8b4d89df2280f3ab1afb9d26e512da`, tree
  `61ed3e89d224d417fb7f5613ab31c7d48ac3abcd`, completed the real offline OSV scan in 28 seconds. It binds image
  publication index `sha256:f44a8c8c2cdbb7269dbcc6a3a726acfe35f94d2a183ec62ef821d94ff57d5f2b`, runtime config
  `sha256:0a4213605273bbe7272cde29fa6376cd6391aa3d1797add39121822131879443`, lock SHA-256
  `cc7da12d2a7033bd76f5d19926ee39242ff1cd19f55223d2d9ad12d530329eae`, and empty-policy SHA-256
  `c60870472e03eaa1cda0b1cd0b2c74591c6255d1c8ab1dde13e7b7392938e143`. The exact R-R3/R-S11be green verdict
  was present once; root and UID/GID 4001 were refused; UID/GID 4000 ran with exact soft/hard `nofile=524544`;
  QEMU and the scanner container had no network; source/image inputs stayed read-only; Docker remained guest-only;
  host listeners were unchanged; and cleanup joined. Separate default no-NIC run `run.MU5pT3LVL3` completed in 82
  seconds and exercised the 31-decision result gate plus offline-image provenance fixtures. This closes the current
  Dart verdict only for that exact 2026-09-10 Pub snapshot, lockfile, policy, image, and source.

  A separately administered independent reconstruction, analogous publication/runtime identity assumptions in
  other Docker consumers, complete canonical closure/current cold artifacts, release and
  signed artifacts, native/device behavior, display/session lifecycle, performance/soak, and external review remain
  open. Neither run used host/root Docker, host RustDesk or Haggai state, a published port, or host firewall/network
  mutation.
- **R-S11dg/R-S11e-125 — Rust advisory execution authority — CURRENT NO-NIC
  RUSTSEC SCAN PASS 2026-09-22; RELEASE EVIDENCE OPEN.** `scripts/audit.sh`
  refuses UID/GID zero and authenticates R-S11dh before reading repository audit
  inputs or creating scratch. Both immutable-image inspections and all three
  bounded preflight/scanner launches use only the fixed guest client,
  guest-private socket, and root-owned canonical-empty read-only configuration in
  an empty environment, with VM authority replay before and after every operation.
  The former host `/var/run/docker.sock` route and host-Docker fallbacks remain
  absent. Mutable source-tree paths are masked only when they exist, so the gate
  now works from an exact archive without requiring `.git`, `target`, harness, or
  Flutter output residue; Cargo target state is guest-private tmpfs state.

  Commits `836bd57` and `48bc65e` add the real focused transaction. It admits one
  exact clean pushed `master` archive, the authenticated Rust-audit image on
  read-only ISO media, and the sealed Cargo vendor closure through nonroot
  Landlocked read-only `virtiofsd`; QEMU has `-nic none`. Root and UID/GID 4001 are
  refused, while the authenticated UID/GID 1000 principal loads the exact classic-
  store runtime config and executes the unchanged production audit entry. The
  compact source gate remains supplementary; the separate 20-decision policy,
  freshness, and result test plus acquisition/OCI provenance retain their own
  focused coverage.

  Exact clean pushed-source run `run.UXY7Iyvbty` at
  `48bc65eb9324ae7871d5ac43ab393b211247dd5c`, tree
  `858bdc5758d6ec61ba1987874475c5a4b83c2b8e`, completed both real offline
  scanners in 125 seconds and emitted the one exact green R-R3/R-S11bf verdict.
  The emitted receipts bind publication index
  `sha256:5e2a167b67cc0692974757bb4752583a57458e4c7f70693e0ba2b1ca2bf6cfbe`,
  runtime config
  `sha256:c7f8e0132b340dc41899b4dd25a342962f7ed97b0ea80814c4641539b67111a0`,
  lock SHA-256 `077491c2f2588c6073bfd59988f63cfa354b69435f340194288cdb0c636ea3ab`,
  policy SHA-256 `48c580d6c00024eb4de975bb557c81f94fd89db76a376e9662e1b92482fb40fa`,
  and vendor closure
  `b1c746659a19393c8f38e5b36ab76f357d4f7089c53cf45ffca8a45ec7a4f1d6`.
  Scanner containers had no network, read-only roots, no capabilities, and
  no-new-privileges; source/image/vendor inputs remained read-only; host listeners
  were unchanged; and image, containers, daemon, mounts, VM, capture, channels, and
  the successful private run root were joined or retired.

  This closes the current RustSec verdict only for the exact Cargo lock, reasoned
  policy, vendor closure, audit image, RustSec commit
  `b5fc89b8be99e96f79194d8a6f11e9b4143b99f0`, and source above while that database
  remains inside the fixed 90-day freshness window. A separately administered
  independent reconstruction, future snapshot refresh, remaining Docker consumers,
  complete canonical closure/current cold artifacts, release/signed artifacts,
  native/device and display/session behavior, performance/soak, independent release
  reproduction, and external review remain open. No RustDesk product ran; no host
  Docker/root/sudo, host or Haggai RustDesk state, published port, firewall, or host
  network mutation was used.
- **R-S11di/R-S11e-127 — Android signing-identity Docker authority — REAL VM
  AUTHORITY PASS 2026-09-15; ONE-TIME GENERATOR/IDENTITY, APK/DEVICE, COLD RELEASE,
  NATIVE, AND EXTERNAL-REVIEW EVIDENCE OPEN.**
  The prior generator used `/var/run/docker.sock`. Strong inner-container flags did not remove the
  root-equivalent host daemon's authority over host mounts and container interpretation. This was real
  build-execution debt, not evidence that the established identity changed, Docker escaped, a listener was
  exposed, host RustDesk or firewall/network state changed, or the host was compromised.

  `scripts/gen-android-keystore.sh` now refuses numeric UID/GID zero, then authenticates R-S11dh before
  repository shell/pins or default signing-path resolution. Image provenance and all three R-S11cg launches
  use only the fixed guest client, principal-scoped guest Unix socket, root-read-only canonical configuration,
  and live VM-root daemon generation. Each operation gets an empty client environment and pre/post authority
  replay. Host/rootless/TCP Docker, ambient routing/configuration, and fallback paths are absent.

  `--self-test-vm-authority` exits before worker validation, a default signing path, scratch, or signing-input
  access and makes one real guest client/server version request. The real no-NIC KVM run completed in 22
  seconds: VM root and UID/GID 4001 were refused; UID/GID 4000 passed; the identity-untouched receipt and
  compact source gate passed; host listeners were invariant; and QEMU, capture, sockets, overlay, payload, and
  private run state were joined and removed. The earlier 718-line mutation catalog and 362-line independent
  verifier-of-verifier block were deleted; the retained 318-line checker binds the no-host-fallback, fixed
  provenance, launch shapes, secret flow, and harness wiring directly.

  The established keystore/password and the normal one-time generator were not invoked, listed, opened,
  hashed, mounted, inspected, rotated, regenerated, or mutated. No APK/device, current cold release, or native
  app behavior was exercised. No host Docker/root, VM NIC, published port, non-loopback listener, host process
  scan, RustDesk service/configuration, Haggai, firewall, or network-state mutation was used.
- **R-S11dj/R-S11e-128 — Android artifact-builder Docker authority —
  REAL NETWORKLESS KVM ENTRY VERIFIED 2026-09-15; NORMAL VM BUILD TRANSPORT,
  CURRENT APK, COLD RELEASE, DEVICE, AND EXTERNAL-REVIEW EVIDENCE REMAIN OPEN.**
  Platform/boundary: unprivileged Linux release orchestration ↔ the Docker
  authority that performs Android builder provenance, key inspection,
  compilation, signing, and signed-artifact verification.

  The former script used a rootful daemon on the orchestration host. Its inner
  containers were non-root, offline, read-only-root, capability-free, and
  resource-bounded, but a Docker daemon controller can request arbitrary host
  bind mounts. That was real build-host/local-privilege-escalation authority,
  regardless of the inner flags. It is not evidence that this authority was
  abused, Docker escaped, signing/source/artifact bytes changed, a listener was
  exposed, or host RustDesk, service, configuration, firewall, or network state
  changed.

  `scripts/build-android.sh` now refuses UID or primary GID zero before
  repository shell/pin sourcing and requires the R-S11dh verifier-VM admission
  before evaluating source, online, output, keystore, or password defaults.
  `--self-test-vm-authority` performs one real guest client/server version
  exchange and exits before provenance, scratch, source, signing, output, or
  container work. Normal provenance and the four operation shapes use only the
  fixed guest client, VM-local root daemon's permissioned Unix socket, and
  root-owned read-only canonical-empty configuration. Their wrappers have an
  empty environment, explicit endpoint/configuration arguments, and admission
  replay before and after every operation. There is no host/rootless/TCP/context
  fallback, host Docker-socket mount, direct host Docker launch, or host-authority
  cleanup path. Existing exact-source, private-online, read-only-signing,
  independent-pass, inner-container confinement, APK validation, A==B, and
  terminal no-clobber publication semantics remain in place.

  Authoritative runtime evidence: the unprivileged
  `scripts/smoke-verifier-vm-authority.sh` completed in 24.63 wall seconds
  (22 guest seconds) using the pinned Debian bookworm qcow2, direct pinned
  kernel/initramfs, `-nic none`, Docker 27.5.1, and private Unix-only
  serial/QMP channels. VM root was refused with the exact early diagnostic;
  UID/GID 4001 was refused by the guest socket authority; UID/GID 4000 completed
  the real builder authority entry and live client/server request with pre/post
  replay. The receipt records `source=untouched signing=untouched
  output=untouched`. Host listener snapshots were identical, the guest retained
  only `lo`, Docker created no bridge/forwarding/firewall/listener change, and
  QEMU/capture/channel/run cleanup joined without residue.

  Verification cleanup is material, not cosmetic. The Android builder checker
  was reduced from 2,196 lines / 104,147 bytes to 410 lines / 17,297 bytes and
  now checks only this authority, the four operation shapes, retained source/A-B/
  publication invariants, and the real VM-harness wiring. Its 115-string
  cross-subsystem mutation catalog and requirements/status coupling were
  deleted. The duplicate 912-line workspace verifier-of-verifier block, its
  dispatch, and its source loading were deleted outright. The same workspace
  oracle's combined Debian/Android fake-host-Docker target fixture is now entirely absent; current
  Debian and Android entry evidence comes from their real no-NIC VM envelopes, not a fake client.
  The independent Android-builder image gate remains separate and passes its normal contract and
  all 54 focused provenance mutations. Shell syntax, isolated Python
  compilation, the compact Android gate, and HTML parsing are targeted checks
  for this slice; none substitutes for the runtime result above.

  Crucial open boundary: the authority-only VM payload does not contain the
  certified Android builder image or the complete source/online/signing/output
  transaction. Consequently, a normal direct or release-child build deliberately
  fails closed outside the admitted VM, and the release transaction is not yet
  operational through this new boundary. Implement one unprivileged outer flow
  that imports the exact OCI image into a disposable no-NIC guest, supplies
  exact source/online and stable signing inputs with least authority, returns
  one bounded identity-bound private result, independently validates it, and
  leaves no signing or VM residue. Then run a fresh exact-commit signed APK A==B
  build, cold R-B2/R-B10 release, device behavior, independent reproduction, and
  external review. No APK was built and no established signing file was opened,
  listed, hashed, mounted, or modified in this slice.

- **R-S11dk/R-S11dh/R-S11e-129 — Debian artifact-builder Docker execution authority —
  VM AUTHORITY AND REAL PRODUCTION PROFILE GREEN; CERTIFIED TOOLCHAIN WORKLOAD OPEN.**
  `scripts/build-debian.sh` no longer initializes, asserts, cleans, or calls the
  shared `local_docker` host-daemon API, and contains no
  `/var/run/docker.sock`, rootless-daemon, context, TCP, or direct-client
  fallback. UID/GID-zero refusal and the fixed R-S11dh entry preflight occur
  before repository helpers, pins, source, online input, output, or release
  state are read. Immutable-image provenance and the sole compiler operation
  use only the fixed guest client, VM-private Unix socket, root-owned
  canonical-empty read-only configuration, and pre/post daemon-generation
  replay.

  The one `debian_compiler_run` operation preserves R-S11cf's private
  exact-commit source and read-only online input while adding
  `bind-recursive=disabled` to both mounts. Its immutable no-pull container
  has no network, a read-only root, the admitted numeric nonroot principal,
  zero capabilities, no-new-privileges, default seccomp, explicit
  `docker-default` AppArmor, private cgroup/IPC namespaces, and explicit
  PID, 16-GiB/no-added-swap, four-CPU, core, descriptor, file-size, and
  executable-tmpfs bounds. The source tree is its only writable durable input;
  a read-only no-exec tmpfs hides `.git`. Publication replays VM admission
  immediately before the existing private pending-result and exact
  workspace-retirement transaction.

  Authoritative runtime evidence: the focused R-S11dh harness booted its
  digest-pinned Debian 12 guest with four vCPUs, `-nic none`, private
  Unix-only serial/QMP, and guest-only Docker 27.5.1. VM root and UID/GID 4001
  were refused; UID/GID 4000 invoked the real production launch function
  against a minimal immutable probe image. The container observed PID 1,
  UID/GID 4000, the exact cgroup limits, zero added swap, zero capabilities,
  no-new-privileges, seccomp filtering, `docker-default` AppArmor, loopback
  only, read-only root/online/Git mounts, and the expected private-source
  write. The online fixture and hidden Git file were unchanged, guest
  container inventory matched before/after, host listeners matched
  before/during/after, and QEMU/Docker/channel/overlay/private-fixture cleanup
  joined. The complete authority run finished in 40 seconds.

  The prior 1,093-line mutation/documentation/publisher checker was deleted
  and replaced by a focused Debian compiler-authority invariant. The duplicate
  292-line workspace verifier block, dispatch, and source loader were deleted;
  the shared publisher's separate executable behavior test remains. The stale
  second Appendix C row numbered 264, which still prescribed the retired host
  Docker authority, was deleted rather than retained as progress history. The
  runtime receipt truthfully records `workload=unexecuted`: the certified
  Debian-builder OCI archive and complete source/online input/result transport
  were not supplied to this smoke, so no compiler, RustDesk binary, package,
  release transaction, or installed service ran. Exact workload transport,
  cold A==B R-B2/R-B10 artifacts, installed/native behavior, independent
  reproduction, and R-V3 external review remain open.
- **R-S11dl/R-S11e-130 — installed Debian systemd lifecycle is VM-only;
  REAL STAGING PROFILE VERIFIED 2026-09-15; CURRENT FINAL ARTIFACT LIFECYCLE,
  COLD RELEASE, NATIVE/DEVICE, REPRODUCTION, AND EXTERNAL REVIEW REMAIN OPEN.**
  Platform/boundary: unprivileged release host → common disposable Debian
  verifier VM with no NIC and private Unix-only channels → VM-root Docker used
  only for exact offline image verification and library staging → real systemd
  PID 1 after Docker has terminated.

  The separate 459-line
  `scripts/smoke-debian-systemd-lifecycle.sh` host orchestrator is deleted.
  It no longer connects to host Docker, selects a lifecycle image/tag, stages
  dependencies on the host daemon, maintains separate VM state, or builds a
  synthetic source-mode package. The only installed lifecycle entry is
  `scripts/smoke-verifier-vm-authority.sh --debian-systemd-lifecycle`.
  `scripts/verify-release.sh` does not pretend this final-artifact operation is
  a source gate; `scripts/build-release.sh` invokes it after A==B and before
  manifest construction/publication.

  The common host harness requires distinct canonical current-principal
  mode-0700 immutable-input and run roots. It verifies the pinned base,
  direct-boot kernel/initramfs, Docker bundle, exact mode-0400 devcheck archive,
  exact mode-0400 final `.deb`, artifact hash/package/architecture, detached
  clean source commit, current and provenance-commit devcheck recipe bytes,
  provenance ancestry, and independent package authority. Package and archive
  enter read-only ISO media owned as numeric UID/GID 4000. QEMU has exactly
  `-nic none`, read-only media, bounded overlay/time/result output, private
  Unix serial/QMP, and host-listener snapshots before/during/after; all inputs
  are identity/hash checked after execution.

  In the guest, root owns one fixed Docker 27.5.1 daemon on a guest-private Unix
  socket and authenticates the exact devcheck archive. The new
  `scripts/stage-debian-systemd-runtime-libs.sh` refuses UID or primary GID
  zero before repository loading, refuses foreign UID/GID 4001 through the
  common preflight, and admits only UID/GID 4000. Its sole production launch
  uses the immutable image ID, `--pull=never`, no network, a read-only root,
  explicit entrypoint, zero capabilities, no-new-privileges, seccomp filtering,
  `docker-default` AppArmor, private cgroup/IPC namespaces, 64 PIDs, 1 GiB
  memory with no added swap, one CPU, zero core, 4096 descriptors, 256 MiB file
  size, and 32 MiB private no-exec scratch. Docker receives exactly one
  root-owned RustDesk executable read-only and one empty private output
  directory writable, both nonrecursive. The flat library output is
  collision-checked and bounded to 60..256 nonempty single-link files and
  1 GiB.

  The guest seals the staged library set, then signals and joins the exact
  Docker daemon and proves its socket/bridge/network effects absent before
  installing or starting RustDesk. It remounts the libraries
  read-only/nodev/nosuid/noexec and dispatches only the exact release
  `.deb` lifecycle. That real-systemd transaction retains the existing
  production-unit/package verification, direct non-root service-child
  cgroup/identity/capability/no-new-privileges/argv/environment/executable
  proofs, normal restart, stop/start, KILL recovery, portable-sibling survival,
  removal, purge, and cleanup requirements.

  Current behavioral evidence is deliberately narrow and exact. On 2026-09-15
  the ordinary common harness booted the SHA-512-pinned Debian base with direct
  authenticated boot assets and `-nic none`; started the VM-root Docker
  daemon; refused root and foreign staging entries; and ran the real production
  staging launch function against a private minimal executable fixture. The
  container observed PID 1, UID/GID 4000, zero capabilities,
  no-new-privileges, seccomp mode 2, `docker-default`, exact cgroup resource
  limits, loopback only, read-only root/input, sole private writable output,
  and unchanged input/container inventory. Docker, QEMU, Unix channels,
  overlay, and private fixtures joined cleanly; host listeners were unchanged.
  The complete common authority run finished in **46 seconds** and emitted:
  `VERIFIER_VM_SYSTEMD_LIBS_ENTRY=pass ... runtime=real
  input=private-fixture-only workload=unexecuted cleanup=joined`.

  That receipt is not an installed RustDesk claim. The devcheck prerequisite is now locally restored as the exact
  681,163,937-byte pin-bound archive described in R-S11bg above, but a current final A==B `.deb` remains unavailable
  and the final-artifact scenario has not been rerun.
  Installed current-`master` behavior therefore remains open, as do cold
  R-B2/R-B10 outputs, the other Linux supervisors, cross-version/native/device
  performance and soak, independent reproduction, and R-V3 review. The former
  916-line/44-mutation lifecycle checker was replaced with a compact
  architectural invariant, and the duplicate workspace-verifier block was
  compressed to the current VM topology; neither is counted as runtime evidence.

- **R-S11dm/R-S11e-131 — release-parent host-Docker removal, verifier-VM
  admission, and descriptor-bound workspace lifecycle — SOURCE CORRECTED;
  REAL CLEANUP, VM-ENTRY, AND RELEASE-WORKSPACE FIXTURES GREEN 2026-09-20; FULL COLD RELEASE,
  NATIVE/DEVICE, INDEPENDENT, AND EXTERNAL EVIDENCE PENDING.**
  Platform: ordinary-user Linux orchestration host and the authenticated
  no-NIC Debian verifier VM. Endpoint/action: <code>scripts/build-release.sh</code>
  production admission, builder content-ID handoff, private snapshot reset,
  transaction cleanup, and release publication. Boundary: orchestration host ↔
  admitted UID/GID 4000 verifier-VM transaction ↔ VM-only build children, plus
  the exact current-principal release workspace.

  The prior parent used the orchestration host's fixed rootful Docker socket for
  three duplicate builder-image provenance checks and five invocations covering
  mode normalization, descriptor capacity, cleanup-fixture construction, reset
  fixture construction, and terminal removal. Later hardening made those
  containers numeric-nonroot and capability-free, but this did not cure the
  outer authority: a rootful daemon still interprets bind mounts against the
  host, and a container running the same UID gave the descriptor helper no
  permission unavailable to the caller. This was real release-verdict,
  host-filesystem, cleanup, and local-privilege authority debt. It is not
  evidence that the path was exploited, a container escaped, root was acquired,
  a listener or port was exposed, or host RustDesk, Haggai, firewall, routing,
  interface, service, configuration, or artifact state changed.

  The release parent now refuses UID or primary GID zero and closes inherited
  Docker/build state before repository shell or pins. Normal production and its
  authority probe require the common verifier-VM preflight before those
  repository helpers. A direct orchestration-host production invocation fails
  before workspace creation because the authenticated VM marker, fixed guest
  client/configuration/socket, daemon generation, Unix peer, and zero-NIC
  topology are absent. There is no host-rootful, rootless-host, TCP/context,
  Podman, privilege, or ambient fallback.

  All parent Docker configuration, socket checks, daemon requests, image
  provenance, container launches, and fake Docker fixtures are deleted.
  <code>assert_release_builder_image_ids</code> validates only the three exact
  <code>sha256:</code> content-ID strings loaded from the commit-bound pins.
  The parent passes the relevant string through its empty child environment;
  each Android, Debian, Windows-helper, verification, advisory, and lifecycle
  child retains its own guest-only admission and provenance proof. Parent state
  cannot substitute for a child's image proof.

  Workspace normalization and terminal removal now invoke the committed
  <code>verify-private-tree-closure.py</code> bytes directly through the already
  open, identity- and SHA-256-bound descriptor in isolated Python. The helper
  retains the exact tree root, mount ID, bounded complete inventory, uniform
  current-principal ownership, every inode edge, and internal hardlink closure
  before changing a mode or unlinking an entry. The cleanup preflight creates
  real current-owner mode-0000 files and a mode-0500 directory, then removes
  them through the production helper and retires the exact empty fixture root.
  Snapshot reset similarly proves external-hardlink refusal before normalizing
  owner access and running Git cleanup. Foreign ownership, mount crossings,
  special objects, external hardlinks, changed identities, or incomplete
  cleanup remain preservation-first failures with the exact retained path.

  Executable evidence is primary for this slice. The ordinary release
  transaction fixture completed both A/B Debian, Android, and Windows target
  paths, final Debian-lifecycle dispatch, manifest/publication/recovery
  behavior, and terminal workspace removal in about twelve seconds with no
  Docker executable or socket. The clean-commit reset fixture exercised the
  actual inaccessible-mode, internal-hardlink, external-hardlink, normalization,
  Git cleanup, and final exact-tree proof. The cleanup-missing fixture retained
  the visible fail-closed result. The common real VM authority run refused the
  release entry as VM root and UID/GID 4001, admitted UID/GID 4000, and emitted
  <code>VERIFIER_VM_RELEASE_PARENT_ENTRY=pass ... parent_docker=absent
  cleanup=descriptor-bound children=vm-only</code> while QEMU had
  <code>-nic none</code>, Unix-only channels, unchanged host listeners, bounded
  output, and joined residue-free teardown. This is entry and cleanup evidence,
  not an artifact build.

  The former 950-line, 27-mutation checker tied to the retired host socket is
  deleted. <code>scripts/verify-release-parent-authority.py</code> is a compact
  architecture invariant with no mutation-catalog pretense. The separate
  35,217-line <code>scripts/verify-verifier-workspace.py</code> global
  source/document/mutation catalog is also deleted in full, along with its
  ordinary-gate call, its software-codec scan exemption, and reciprocal
  source/dispatch assertions in focused checkers. It did not execute the
  release workspace and was not behavioral evidence. A bounded
  <code>verify-release-workspace-runtime.sh</code> entry is instead wired into
  the authenticated no-NIC VM authority run to execute the actual release,
  reset, publisher, and descriptor-helper fixtures as UID/GID 4000 while
  refusing VM root and UID/GID 4001. The first real run exposed absent Git; the
  second, after exact pinned-package provisioning in the disposable guest,
  exposed the finalizer's Linux-6.8-only filesystem-UUID ioctl on pinned Debian
  12 Linux 6.1. After replacing that dependency with the kernel-defined ext4
  `f_fsid` plus persistent parent-handle authority, the 67-second no-NIC run
  emitted <code>VERIFIER_VM_RELEASE_WORKSPACE_RUNTIME=pass uid=4000 gid=4000
  root=refused foreign=refused network=none release=actual reset=actual
  publisher=actual closure=actual cleanup=joined</code> and the outer exact
  unchanged-listener/joined-cleanup receipt. Old catalog passes are not carried
  forward as a substitute.

  Remaining STOP-SHIP work is explicit: the outer common VM does not yet carry
  the complete release source/online/image/signing/Windows-golden input set or
  return the full bounded artifact set. Therefore a direct host release fails
  closed and a complete cold current-commit R-B2/R-B10 transaction has not run.
  The present VM entry probe does not compile RustDesk, execute certified
  builder images, launch the nested Windows guest, produce A==B artifacts,
  install a package, exercise a peer, prove native/device lifecycle or
  display/focus/reconnect latency, reproduce independently, or supply R-V3
  external review. The broader Ralph goal remains active.
- **R-S11dn/R-S11e-132 — mandatory Android release-gate source,
  resource, cleanup, and Docker authority — BOTH OUTER AUTHORITIES MIGRATED;
  BOTH GRADLE PRODUCTION PROFILES GREEN; ACTUAL GRADLE/RUST WORKLOADS OPEN.**
  Platform/boundary: `scripts/test-android-gradle-cache.sh` outer mode and
  `scripts/android-rust-check.sh`, required by `scripts/verify-release.sh`,
  bridge release source/online inputs to Android-builder containers.

  Their source staging and inner operation shapes remain intentionally strict:
  numeric non-root, immutable image, no pull/network, read-only root, no
  capabilities or privilege gain, bounded resources, recursively excluded
  mounts, private Gradle fixtures, and an immutable reference plus disposable
  writable Rust source candidate with before/after comparison. Neither child
  writes the live checkout.

  Both children now refuse UID/GID zero and fail through the common verifier-VM
  admission before repository helpers, source, online inputs, fixtures, or
  scratch. Their only Docker/provenance functions use the fixed guest client,
  permissioned Unix channel, root-owned empty configuration, otherwise-empty
  environment, explicit host/configuration arguments, and pre/post admission
  replay. The former `local_docker` initialization, host daemon, configuration
  cleanup, ambient provenance call, and fallback surface are deleted.

  The Gradle child has two closed launch functions: the descendant-mount
  rejection profile retains its exact read-only projector/init/seed/overlay
  mounts and smaller bounds; the semantic profile retains its exact read-only
  projector/init/mode-contract/test/Gradle-distribution mounts and larger
  bounds. Both use immutable IDs, no pull or network, a read-only root,
  numeric-nonroot execution, no capabilities or privilege gain, explicit
  AppArmor, bounded PID/memory/no-swap/CPU/core/descriptor/file-size/tmpfs
  resources, and nonrecursive mounts. `--inside` is a PID-1, nonroot container
  payload and cannot become a host-side test mode. The Rust child retains its
  immutable reference/disposable candidate, read-only operation/online inputs,
  nonrecursive mounts, stable-source comparisons, and confined launch contract.

  The real zero-NIC KVM smoke executed the Gradle entry under VM root, foreign
  UID/GID 4001, and authorized UID/GID 4000. Root and foreign callers were
  refused. The authorized caller used the real fixed Docker client/server and
  executed both production profile launch functions against a minimal immutable
  probe image. From inside each container it observed the exact PID, memory,
  zero-swap, CPU and descriptor bounds plus PID 1, UID/GID 4000, read-only root,
  loopback-only network namespace, zero effective capabilities, no-new-
  privileges, filtered seccomp, and `docker-default` AppArmor state. The guest
  container inventory was identical before and after. The outer transaction
  retained bounded output, unchanged host listeners, and joined removal of
  QEMU, Docker, channels, overlay, and private run state. The compact focused
  source checker ran inside that same guest; the unused global-workspace source
  loader for this child was deleted.

  This is real daemon and production-profile evidence, not a Gradle result. The
  probe deliberately accessed neither the projector inputs nor the pinned Gradle
  distribution and reports `gradle=unexecuted`; the Android Rust authority-only
  path likewise reports `workload=unexecuted`. The renewed 474,623,832-byte
  Android-builder archive is now present and has passed its distinct guest-only load/runtime transaction, but
  this authority-only profile still did not transport or execute the complete offline Gradle/Rust toolchain
  closure. A workload-capable exact-input transport and actual Gradle and Rust executions therefore remain
  STOP-SHIP. No Gradle build, Android Rust check,
  APK, release transaction, installed/device behavior, independent reproduction,
  or external review is claimed.

- **R-S11do/R-S11e-133 — Windows-helper verifier-VM, mount, resource, KVM, and cleanup authority —
  SOURCE IMPLEMENTED; ACTUAL SMALL-PROFILE GUEST-DOCKER BEHAVIOR GREEN; CERTIFIED HELPER/KVM/WINDOWS
  EVIDENCE OPEN.** Platform/boundary: the unprivileged Windows release and diagnostic caller ↔ the sole
  authenticated no-NIC verifier VM, its guest-only Docker daemon, immutable helper inputs, exact mounts,
  process limits, `/dev/kvm`, and terminal cleanup.

  The removed path initialized `/var/run/docker.sock` from all three Windows callers, giving their helper
  launches and provenance checks root-equivalent host-daemon authority. Admission occurred only after repository
  shell was sourced, and `require_pinned_builder_image` could select its ambient provenance fallback. That was
  daemon-selection and host-build authority debt; it was not evidence that the authority was exploited or that
  any host service, RustDesk process, firewall, network state, listener, input, or artifact was changed.

  `build-windows-vm.sh`, `provision-windows-vm.sh`, and `verify-windows-golden.sh` now refuse UID/GID zero and
  authenticate the exact verifier-VM generation before sourcing repository libraries or reading product inputs.
  `windows-helper-runtime.sh` has one Docker mode: fixed `/usr/bin/docker`, fixed guest Unix socket, fixed
  root-owned canonical-empty guest configuration, empty environment, redundant explicit routing, and pre/post
  generation replay around every client and provenance operation. No host/rootless-host socket or ambient fallback
  remains. `require_pinned_builder_image` accepts a caller-proved executor so the Windows funnel cannot escape that
  authority. Mount, profile, KVM `rw`-only, archive/kernel/program, and descriptor-bound cleanup rules from R-S11ch
  remain source-enforced.

  The fast no-NIC VM smoke behaviorally refuses root and UID/GID-4001, then runs the production runtime as
  UID/GID-4000 against the real guest daemon. It refuses traversal, protected and duplicate targets, FIFO,
  unsafe-writable, writable-hard-link, and terminal-symlink mounts. Its successful `small` launch observes zero
  capabilities, no-new-privileges, seccomp filtering, the exact PID/memory/no-swap/CPU/core/descriptor ceilings,
  loopback as the only interface, read-only root/input, exact writable output, and residue-free joined cleanup.
  Complete outer runs passed in 28–29 seconds with host listeners unchanged. A deliberately synthetic kernel and
  minimal probe image exercise only this envelope; they are not certified helper or kernel evidence.

  The former 78-mutation checker and duplicate workspace validator were deleted. The remaining compact source
  invariant protects the sole funnel, no-fallback wiring, caller admission, mount/KVM/cleanup envelope, and real
  behavioral-test connection; it is supplementary to the VM result. Exact certified helper archive/image
  provenance, kernel extraction, KVM/libguestfs, golden inspection, Windows provisioning/building, cold artifacts,
  native behavior, independent reproduction, and external review remain open. The broader Ralph-loop goal remains
  active.
- **R-S11dp/R-S11e-134 — generic cleanup has no daemon-global Docker
  enumeration or prefix-deletion authority — SOURCE IMPLEMENTED AND
  CONFINED SOURCE/MUTATION VERIFIED 2026-07-26.**
  Platform: the unprivileged Linux build/maintenance host. Endpoint/action:
  default `scripts/cleanup.sh::clean_ephemeral` container and image discovery
  plus force removal. Boundary: a generic reversible VM/host cleanup request ↔
  every container and image name visible through whichever Docker daemon and
  client configuration the caller selected.

  Proven old path and history: the default cleanup PATH-selected `docker`,
  inherited its complete routing/configuration environment, called
  `docker ps -aq --filter name=${HARNESS_PREFIX}`, suppressed enumeration
  failure, and passed every whitespace-split result to `docker rm -f`. It then
  listed every top-level image repository/tag, selected textual prefix matches,
  and piped those mutable names to `xargs docker rmi -f`. Docker's official
  container-list documentation states that the `name` filter matches all or
  part of a name; its image-list documentation states that one image may have
  multiple repository names/tags. The container and image removal commands are
  destructive daemon operations. A shared prefix therefore did not prove the
  creating transaction, exact immutable object, or absence of another owner.
  `git blame` attributes this branch to the original R-B11 cleanup import
  `34b4921f`, not the recent fixed local-Docker hardening.

  This was daemon-global availability, mutable-name, daemon/configuration-
  selection, and destructive-cleanup authority debt. It is not evidence that
  this cleanup was run against another daemon, that an unrelated container or
  image was actually removed, Docker escaped, host root was acquired, a
  listener or port was exposed, host RustDesk/service/configuration/firewall/
  network state changed, exploitation occurred, or the host was compromised.

  Authority model and source closure: generic cleanup owns only resources whose
  exact identity was retained by the transaction that created them. It has no
  such Docker object identity, and a name, label, repository/tag, or prefix is
  not a substitute. The complete Docker availability check, global container
  and image enumerations, suppressed-error branches, force removals, word
  splitting, and `xargs` pipeline are deleted. `scripts/cleanup.sh` contains no
  Docker token or client/daemon operation. Existing container-producing
  transactions retain their own exact terminal cleanup; deliberately retained
  acquisition/certification candidates remain explicit maintenance state
  rather than implicit default-cleanup targets. The README states that split
  directly. The separate R-B11/R-B11a direct-QEMU, session-libvirt, overlay,
  manifest-gated old system-network, and recorded-package reversal surfaces
  remain independently auditable; this slice does not declare them safe.

  Primary contracts:
  https://docs.docker.com/reference/cli/docker/container/ls/,
  https://docs.docker.com/reference/cli/docker/image/ls/,
  https://docs.docker.com/reference/cli/docker/container/rm/, and
  https://docs.docker.com/reference/cli/docker/image/rm/.
  R-S11dp and Appendix C #269 make the deletion normative. The independent
  workspace validator and its complete deliberate-mutation catalog bind
  cleanup-source Docker absence, preserved default VM/host-cleanup entry,
  operator documentation, requirement, Appendix disposition, this row, and
  the synchronized requirements-hash scope without invoking cleanup or
  inspecting the live daemon.

  Confined verification on 2026-07-26 used immutable verifier image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as the caller's numeric non-root UID/GID with no network, a read-only root
  and recursively-disabled read-only repository bind, dropped capabilities,
  no-new-privileges, finite PID/memory/no-swap/CPU/descriptor/core/file-size
  limits, a bounded noexec tmpfs, and no Docker socket, device, port, or host
  namespace mount. Python compilation, Bash syntax, HTML parsing, exact
  requirements-hash equality, cleanup-source Docker-token absence, and
  `git diff --check` passed. The independent workspace validator passed
  normally and rejected all 2,379 deliberate source mutations from mutation
  one. Adjacent source contracts rejected all 27 release-parent, 44 Debian
  systemd-lifecycle, and 78 Windows-helper mutations; native-codec-watch passed
  its normal and negative self-test gates. The validator had no Docker
  client/socket and invoked no cleanup, daemon inventory/deletion, build,
  Android/Gradle, KVM, Windows, root fixture, release workload, or host
  RustDesk/service/firewall/network operation. The outer verifier transaction
  created and terminally removed only its own exact disposable container.

  Exact cold R-B2/R-B10 artifacts, remaining native/installed/device evidence,
  fresh independent image reproduction where separately named, and R-V3
  external review remain open. The broader Ralph-loop goal remains active.
- **R-S11dq/R-S11e-135 — generic cleanup has no PID-file, session-domain-name, or pathname-derived destructive ownership —
  SOURCE IMPLEMENTED AND CONFINED SOURCE/MUTATION VERIFIED 2026-07-26.**
  Platform: the unprivileged Linux build/maintenance host. Endpoint/action:
  no-argument `scripts/cleanup.sh` legacy direct-QEMU, session-libvirt, and
  overlay cleanup. Boundary: caller-writable repository state and mutable
  process/domain/path names ↔ host process signals, the complete libvirt
  session daemon, and filesystem deletion.

  Proven old path and history: the default branch read every
  `.harness-state/winvm/*.pid` file, treated its decimal contents as a live QEMU
  identity, sent TERM, waited two seconds, sent KILL, and then deleted guessed
  PID/socket names. A user-writable PID file contains neither process start time
  nor executable/role identity, and a stale PID can be reused. The same branch
  listed every session-libvirt domain and destroyed/undefined each mutable name
  beginning with the shared harness prefix while suppressing discovery/control
  errors. Its overlay branch used `-d` on a caller-writable directory edge,
  which follows a symlink, and then pathname-globbed `rm -f` beneath that edge.
  Current source contains no producer for the legacy `winvm` PID/socket layout
  or generic `overlays` directory. The current per-build Windows transaction
  already retains a direct-child start identity, kernel-random domain UUID,
  pass-private root, and exact terminal cleanup. `git blame` attributes the
  PID branch to `d329a696` and the prefix-domain/overlay branches to the original
  R-B11 cleanup import `34b4921f`.

  This was arbitrary-process availability, daemon-global session-domain
  availability, pathname-substitution deletion, suppressed-error, and
  destructive-cleanup authority debt. It is not evidence that cleanup ran,
  an unrelated process/domain/file was removed, root was acquired, a listener
  or port was exposed, host RustDesk/service/configuration/firewall/network
  state changed, exploitation occurred, or the host was compromised.

  Authority model and source closure: the no-argument mode performs exactly one
  report and no mutation. `clean_ephemeral`, its prefix, PID/socket namespace,
  process signals, session-libvirt enumeration/control, and overlay/path
  deletion are absent. Ephemeral lifecycle belongs to the exact transaction
  that retained the creating process/domain/state identity. A legacy leftover
  without that identity requires explicit operator reconciliation rather than
  a destructive guess. The separately selected manifest-backed old
  system-network and package-reversal modes remain unchanged. The golden-image
  provisioner's formerly name-owned pre-creation collision handling is
  independently closed by R-S11dr below; that transaction-owned lifecycle does
  not broaden generic cleanup authority.

  R-S11dq and Appendix C #270 make this source boundary normative.
  `scripts/verify-cleanup-authority.py` independently binds the source,
  documentation, requirement, Appendix row, ledger, shared-gate wiring, and
  workspace-verifier wiring with deliberate mutations. The repository-wide
  workspace validator independently binds the same runtime absence and focused
  checker shape through its complete source-mutation catalog. Neither gate
  invokes cleanup, signals a process, queries libvirt, deletes a file, or
  inspects/mutates live host state.

  Confined source evidence on 2026-07-26 is green. The focused cleanup
  authority verifier rejects all 16 deliberate mutations. The independent
  workspace baseline passes, and its complete catalog rejects all 2,390
  deliberate source mutations from mutation one. The adjacent release-parent,
  Debian systemd-lifecycle, and Windows-helper gates reject 27, 44, and 78
  mutations respectively. Native-codec normal and negative self-test modes,
  Bash/Python syntax, requirements HTML parsing, exact synchronized
  requirements SHA-256
  `fcfbc395e0e61eb5eb8fb1f09afbbc8e8dc219556435b5d2eeb36ca61afbcf2a`,
  and diff hygiene pass.

  Every project gate ran in immutable verifier image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as the caller's numeric non-root UID/GID with no pull or network, read-only
  root/repository with recursive bind inclusion disabled, all capabilities
  dropped, no-new-privileges, finite PID/memory/no-swap/CPU/descriptor/core/
  file-size limits, bounded noexec tmpfs, and no Docker socket, device, port, or
  host namespace mount. Each outer Docker call used a fresh mode-0700 private
  client directory containing only canonical-empty mode-0600 configuration;
  that file and directory were exactly unlinked/removed after the call. The
  outer verifier removed only its own disposable container.

  Three preliminary checker attempts are retained rather than hidden. The first
  focused self-test exposed an ineffective workspace-name mutation because an
  unchanged call site still satisfied a substring assertion; the assertion now
  binds the exact function definition, and the complete 16-case focused set
  restarted. The first workspace baseline used a finite 256-KiB file-size
  ceiling that was too small for this verifier and stopped with `EFBIG` before
  validation; it was rerun under the repository's established finite 128-GiB
  ceiling. The next baseline exposed one new checker call to a nonexistent
  generic `require` helper; the checker now uses the verifier's native explicit
  failure form, after which baseline and the complete catalog restarted from
  mutation one. These were verifier-development/confinement defects, not
  cleanup, process, libvirt, filesystem, Windows, host, or service execution.

  No cleanup mode, process signal, libvirt query/control, pathname deletion,
  helper workload, KVM/Windows operation, package/artifact builder, root
  fixture, release transaction, installed/native/device test, or external
  review is claimed here.

  Exact cold R-B2/R-B10 artifacts, remaining native/installed/device evidence,
  fresh independent reproduction where separately named, and R-V3 external
  review remain open. The broader Ralph-loop goal remains active.
- **R-S11dr/R-S11e-136 — Windows golden exact libvirt-domain lifecycle — SOURCE
  IMPLEMENTED; CURRENT NATIVE SESSION-LIBVIRT/WINDOWS-VM EVIDENCE OPEN.**
  `scripts/provision-windows-vm.sh` validates its fixed name and kernel-random
  version-4 UUID, proves both absent by complete enumeration before media creation
  and again before launch, and never mutates a pre-existing name. It retains and
  admits the exact `setsid --wait virt-install --uuid` PID/start/process-group/session
  identity before observing domain creation. Guest reads and control select only
  that UUID; errors and unexpected identity preserve ambiguity, while successful
  marker/hash acceptance and every conclusive cleanup path retire the exact UUID
  without deleting the golden disk. Control uses the private session URI, a fresh
  no-stdin bounded control session, C locale, and no version-specific
  `--no-pkttyagent`; VNC is explicitly loopback-only.

  Review in this slice found that the golden path lacked the per-build launcher's
  explicit pre-commit/committed domain state. It now preserves any UUID that appears
  after creation intent but before exact launcher admission and UUID/name creation
  proof, exact disk set, transaction-owned storage, single user-mode interface
  without host forwarding, loopback-only VNC, and no host device; only that
  complete proof commits destructive domain authority. This closes the
  signal/error window in which an unadmitted launch could previously reach the
  name-and-UUID cleanup branch.

  The retained focused checker is a fast source-topology guard only. Its in-memory
  mutation catalog and the workspace verifier's duplicate golden-domain validator
  were deleted because neither executed libvirt or observed a VM lifecycle. In the
  confined utility image, the exact embedded XML parser accepted one confined-domain
  fixture and rejected six wrong-disk/network/forwarding/VNC/passthrough/raw-QEMU
  variants; Bash/AST, focused, and normal workspace checks also pass. This is parser
  behavior and source integration, not libvirt or Windows execution.
  Current native evidence still requires the real malformed/collision/control,
  admission, ambiguity, client-result, marker/hash, signal/timeout/success teardown,
  listener-finality, storage-preservation, and terminal-absence scenarios in a
  disposable private session-libvirt/Windows VM environment. No exact current
  golden reprovision or cold R-B2/R-B10 Windows artifact closes this item. Detailed
  implementation history remains in Git at `f6771b03`.
- **R-S11ds/R-S11e-137 — exact per-build libvirt UUID ownership — SOURCE
  IMPLEMENTED; CURRENT NATIVE SESSION-LIBVIRT/VM EVIDENCE OPEN.**
  `scripts/build-windows-vm.sh` proves the generated name and kernel-random
  UUID absent by complete fail-closed enumeration, records creation intent
  immediately before the retained `setsid --wait virt-install --uuid` client,
  and grants no destructive authority until that exact client is admitted,
  completes successfully, and UUID-addressed name/XML/storage proof passes.
  All post-commit state, destroy, and undefine operations select the UUID;
  pre-commit UUID appearance, an unexpected name, process-identity uncertainty,
  and control uncertainty preserve the domain. Teardown never requests storage
  deletion and clears authority only after UUID absence. The guest remains
  networkless with VNC explicitly loopback-only. R-S11e-170 and R-S11e-214
  retain the distinct process-group admission and version-compatible control
  evidence below. On 2026-09-14 the focused Windows and independent workspace
  normal validators passed in the exact available confined utility image. That
  image lacks `qemu-img`, `virsh`, and `virt-install`, and the exact development
  image is absent; no substitute was used. No exact current native libvirt/VM
  transaction or cold R-B2/R-B10 Windows artifact closes this item.
- **R-S11dr/R-S11ds/R-S11e-214 — noninteractive session-libvirt control —
  SOURCE IMPLEMENTED; CURRENT VM/NATIVE-WINDOWS/ARTIFACT EVIDENCE OPEN.**
  Both Windows VM transactions delegate every `virsh` query and control to the
  shared `windows_libvirt_run_bounded_control`: an absolute `setsid --wait`, a
  finite `timeout`, exact `qemu:///session`, and closed standard input under the
  caller's private libvirt environment. The source contains no version-specific
  `--no-pkttyagent`, interactive/privileged fallback, alternate URI, or direct
  launcher bypass. Focused and independent checks guard that source topology;
  they do not execute libvirt. Exact current private-daemon/domain control,
  timeout/error/finality, terminal-interaction refusal, VM teardown, Windows
  guest behavior, cold R-B2/R-B10 artifacts, independent reproduction, and
  external review remain open.
- **R-S11dr/R-S11ds/R-S11e-170 — exact `setsid` process-group admission — SOURCE
  IMPLEMENTED; EXECUTABLE LIBVIRT/VM AND COLD RELEASE EVIDENCE OPEN.** Golden
  provisioning and per-build launch retain `$!` plus its start time only as a
  candidate identity. A monotonic admission interval requires that same live,
  non-zombie PID to reach `PGID == SID == PID` before any group scan, negative-
  PGID signal, domain observation, or cleanup authority. Exit, identity change,
  conditional-fork wrapper behavior, or timeout preserves any domain as
  ambiguous. Cleanup revalidates and drains the complete admitted group before
  reaping its leader. The per-build executable shell fixture forces a delayed
  pre-admission state, rejects it, admits the unchanged leader, and exercises
  bounded TERM/KILL drain; a confined util-linux process experiment also
  confirms that a job-control wrapper with a distinct session-leader child is
  rejected. These checks do not execute libvirt or a VM. Exact isolated
  libvirt/VM behavior, cold R-B2/R-B10 artifacts, installed/device evidence,
  independent reproduction, and external review remain open.
- **R-S11dt/R-S11e-138 — Windows build run-state cleanup — SOURCE IMPLEMENTED;
  CURRENT NATIVE WINDOWS-BUILD/LIBVIRT/VM EVIDENCE OPEN.**
  `scripts/build-windows-vm.sh` records each private run root's device/inode
  before population and orders exact process-group, UUID-domain, transient-
  libvirt, and helper-authority retirement before descriptor-relative removal.
  R-S11gl supersedes the original whole-run preservation policy: after
  conclusive external-authority retirement, success, failure, timeout, and
  signal paths independently retire the exact bulk root and build snapshot;
  a failed run may first retain only its bounded diagnostic envelope. Only
  inconclusive external authority or exact-object removal preserves bulk state
  and the lease. The closer rejects replacement edges, mount/device crossings,
  special nodes, and external hardlinks, retains inode authority through
  unlink, removes the authenticated root last, and proves absence. On
  2026-09-14 its complete behavior self-test passed in the exact available
  unprivileged, network-disabled utility image with the required finite
  524,544-descriptor bound; the focused Windows and independent workspace
  normal validators also passed. No builder main path, libvirt, VM, native
  Windows artifact, cold R-B2/R-B10 transaction, or host product state ran.
- **R-S11du/R-S11e-139 — Windows result publication is exact-object and authority-terminal —
  SOURCE/MUTATION/FILESYSTEM VERIFIED; FRESH NATIVE SINGLE-PASS PUBLICATION GREEN 2026-08-11;
  EXACT-COMMIT COLD DOUBLE-BUILD EVIDENCE PENDING.**
  Platform: the unprivileged Linux Windows-build host. Endpoint/action:
  `scripts/build-windows-vm.sh::publish_result` moving the validated pass-A
  `.exe`/`.msi`, checksum records, and optional diagnostics from private build
  state into the caller-selected absent output leaf. Boundary: private
  run/result identity plus the selected output-parent namespace ↔ the
  irreversible public multi-artifact result and the terminal build verdict.

  Proven old path and history: preflight canonicalized the output-parent
  pathname but retained no object identity or write-authority proof.
  `publish_result` then created `.windows-publish.XXXXXXXX` directly under
  that pathname, copied each file through shell paths, checked hashes by
  pathname, and invoked `mv -T --no-clobber "$staging" "$OUT_DIR"`. `git
  blame` and `git log -S` trace the block to `57bcb529` (`Harden privileged
  IPC and release authority`). The GNU Coreutils `mv` specification states
  that a failed rename caused by different filesystems falls back to
  copy-then-remove; `--no-clobber` also skips an occupied destination rather
  than making the rename primitive itself authoritative. The path therefore
  did not prove one same-filesystem atomic edge change, retained neither
  parent nor candidate identity, synchronized neither directory namespace,
  and could publish before `windows_helper_authority_close` decided whether
  the build still owned unreconciled Docker/configuration state. The builder
  refuses UID and primary GID zero. This was non-root artifact-publication
  integrity, pathname-substitution, cross-filesystem atomicity, durability,
  and transaction-finality debt—not evidence that publication ran, artifacts
  changed, Docker escaped, root was acquired, a VM/domain/listener/network
  started, or host RustDesk/service/firewall/network state changed.

  Authority model and source closure: preflight now proves the canonical
  output parent is owned by the invoking UID/GID, has owner read/write/search,
  and grants no special, group-write, or world-write authority, then retains
  its device/inode. The isolated `scripts/publish-windows-result.py` opens
  that exact identity and R-S11dt's exact mode-0700 run-root identity with
  `O_DIRECTORY|O_NOFOLLOW`, rejects POSIX access ACLs, and requires one
  filesystem. It descends only through current-principal mode-0700
  `pass-A/result` directories from the retained run-root descriptor.

  The admitted source inventory is exactly two nonempty artifacts, their two
  canonical lowercase SHA-256 records, and at most the bounded build log and
  progress transcript. Every file must be current-UID/current-GID, mode 0644,
  single-link, regular, size-bounded, opened no-follow, and stable through
  read/copy. The helper creates the fixed exclusive candidate inside the
  authenticated private run root, copies through descriptors into new files,
  independently hashes artifacts against the records, synchronizes every
  file, rechecks the closed inventory and content, and synchronizes the
  candidate directory plus run-root namespace. Pre-publication failure or
  interruption therefore leaves evidence only inside the exact retained
  private transaction rather than beside the public output.

  The main path closes the Windows-helper Docker/configuration authority
  before entering publication. The preparation helper re-proves both path
  edges, then invokes libc `renameat2(RENAME_NOREPLACE)` descriptor-relative
  from the retained run root to one kernel-random hidden pending name in the
  retained output parent. It synchronizes both namespaces, proves the
  run-root candidate edge absent, proves the pending edge is the exact
  still-open mode-0700 candidate, revalidates it, and returns only its strict
  name plus device/inode authority. The pending directory is never populated
  through the output parent and is not the requested result.

  While the requested output remains absent, the shell parses that exact
  authority and retires the remaining run-root identity with R-S11dt's
  descriptor-relative private-tree closer. Cleanup failure therefore
  preserves a private pending candidate and fails before apparent
  publication. Only after exact run-state retirement does a separate
  isolated commit invocation re-open the retained output-parent and pending
  identities, revalidate their inventory and checksums, re-prove the parent,
  and use same-parent `renameat2(RENAME_NOREPLACE)` to install the requested
  final name. It synchronizes that namespace and proves pending-edge absence
  plus exact final identity/content. Destination presence, pending or parent
  substitution, `EXDEV`, missing no-replace support, or uncertainty fails
  without copy, overwrite, deletion, or fallback. No fallible material
  action remains after final publication. The former pathname-populated
  output-parent staging, shell copy/hash loop, GNU `mv`, and
  post-publication offline-media deletion are absent. R-S11du and Appendix C
  #274 make this exact boundary normative.

  Verification is intentionally confined to source/mutation checks and the
  new helper's bounded ordinary-filesystem fixture. That fixture proves a
  successful exact prepare/commit, occupied-destination preservation with
  the pending candidate retained, output-parent and pending-object
  substitution refusal, externally hard-linked source refusal, and
  unexpected-inventory refusal. It uses disposable files only and does not
  run the Windows builder main path, Docker/helper workloads, `virt-install`,
  `virsh`, libvirt, KVM, a Windows VM, root fixtures, cleanup against host
  state, or any host service/network operation.

  Confined verification: the focused Windows harness baseline and complete
  self-test pass from mutation one, rejecting all 226 deliberate source
  weakenings and passing five bounded behavioral suites. The separate
  workspace semantic baseline passes and its complete 2,466-entry in-memory
  source-mutation catalog passes from mutation one. The shared private-tree
  closer's complete behavioral self-test passes. Adjacent golden-domain,
  generic-cleanup, Windows-helper, release-parent, and Debian
  systemd-lifecycle gates reject 32, 16, 78, 27, and 44 mutations
  respectively. Bash syntax, in-memory Python AST parsing, the publisher
  prepare/commit self-test, exact requirements digest, native-codec normal
  gate, and native-codec negative self-test pass. The exact synchronized
  requirements SHA-256 is
  `9bde87af77e4c815c8ba91714f248d64e559a0b1cb661562a690577485ca2637`.
  The MSI behavioral suite imports only the existing local SHA-256-pinned
  `olefile` wheel; nothing is installed and network remains disabled.

  The final source audit rejected the first one-phase implementation before
  commit: the requested result could already exist when a later EXIT-trap
  run-root cleanup failed and changed the transaction verdict. That finding
  caused the two-phase pending-object/final-commit correction above and a
  complete restart of focused and independent mutation verification.
  Preliminary verifier failures are retained as evidence: source-checksum,
  final-edge, normative-requirement, and pre-publication-order mutations
  initially exposed incomplete or stale focused bindings; independent
  no-clobber and expected-identity mutations were correctly rejected under
  mismatched expected diagnostic labels; and every applicable complete suite
  restarted after correction. Container setup also exposed a UID-wide
  `RLIMIT_NPROC` that was too low, a root-owned private tmpfs, an insufficient
  descriptor ceiling for exact tree closure, an undersized file-size ceiling,
  and the verifier image's absent per-user systemd bus. The executable
  workspace `--self-test` was not misrepresented or granted that host socket;
  the isolated semantic baseline and complete source catalog were run
  instead, while the relevant bounded executable gates ran separately. An
  attempted `py_compile` correctly failed against the read-only repository
  before being replaced by in-memory AST parsing.

  One process-boundary error is also recorded: a read-only Python occurrence
  counter was accidentally run on the host once. It read four repository
  files and performed no write, privilege use, socket access, service action,
  or network operation, but it violated the container-only execution rule and
  its result was not used as verification. The count was independently
  reproduced inside the confined image. Every counted executable gate ran in
  immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as numeric UID/GID 1000:1000 with no pull or network, read-only root and
  repository, recursive bind inclusion disabled, all capabilities dropped,
  no-new-privileges, finite PID/memory/no-swap/CPU/descriptor/core/file-size/
  tmpfs limits, and no Docker/libvirt/service-manager socket, host namespace,
  device, port, or host-configuration mount. Each outer Docker call used a
  fresh mode-0700 private client configuration whose mode-0600 file and
  directory were exactly removed.

  No Windows builder main path, Docker/helper workload inside the verifier,
  `virt-install`, `virsh`, libvirt query/control, KVM/VM operation, cold
  R-B2/R-B10 transaction, root fixture, installed/native/device behavior,
  independent reproduction, or R-V3 external review is claimed by this
  source slice. No host RustDesk/service/configuration/firewall/network state
  was inspected or mutated. Those obligations and the broader Ralph-loop
  goal remain open.

  Native publication evidence (2026-08-11) includes the failure that made the final run meaningful. The preceding
  fresh Windows guest had already returned `build-windows.ps1 exit=0`, passed native tests, restored and built WiX,
  and produced both artifacts, but the publisher refused its result with
  `source checksum rustdesk-setup.exe.sha256 metadata is invalid`. Read-only inspection proved both freshly emitted
  checksum records were mode 0600: `extract_and_validate` inherited the harness's private `umask 077`, while the
  publisher correctly required every source file to be mode 0644. No result was published. The smallest correction
  explicitly sets only those two new checksum records to 0644 after creation. The focused verifier binds their
  creation-before-normalization order and rejects a deliberate 0600 regression; its normal path, all 226 mutations,
  and five bounded behavioral suites pass in a non-root, read-only, network-disabled container. The independent
  workspace binding also passes.

  A completely fresh run then captured exact tree `58c3125332b13a00950cee990d4f16be5d9d4a24`, reverified private offline
  closure `eacb4d0fadb044f2f38520ad5263470a89c286bed69927ce2c32babcbc01ab24` before and after the guest,
  completed the native Windows build, canonical-form validation, helper retirement, publication preparation,
  exact run-root retirement, and final no-clobber commit. It reported `publish-windows-result: committed` and
  `Windows artifacts complete`. The destination `/home/user/rustdesk-windows-cm-publish-20260811-result` is mode
  0700 and contains only the two mode-0644, single-link artifacts, their mode-0644 checksum records, and the two
  bounded mode-0644 diagnostics. Independent checksum verification passes. `rustdesk-setup.exe` is 18,528,256 bytes
  at SHA-256 `2d59e6c668c0e6add53c50588544b0823fc33653319888bf63543c24a73d3572`; `rustdesk.msi` is
  18,308,615 bytes at SHA-256 `6692c36a11489d1ba1c79f87044970b3926a3067b09f9bbdb28226b3b9ec4b39`.
  The exact private run root is absent after publication.

  The transaction used current-user `qemu:///session`, never root or sudo. Its exact domain had zero network
  interfaces and only a temporary QEMU listener on `127.0.0.1:5900`; after completion the domain, QEMU process,
  harness process, and 5900 listener were all absent. No host RustDesk process, service, configuration, firewall,
  UFW/nftables/iptables, route, or host network setting was inspected or changed. This closes the native
  single-pass publication boundary only. `DOUBLE_BUILD=0`, a dirty captured worktree rather than a final commit,
  lack of independent reproduction, lack of installation/runtime service exercise, and lack of cross-target cold
  R-B2/R-B10 publication keep the release obligation open.
- **R-S11dv/R-S11e-140 — Debian result publication is private-until-verified,
  exact-object, no-clobber, and authority-terminal — SOURCE AND CONFINED
  SOURCE/MUTATION/FILESYSTEM VERIFICATION COMPLETE 2026-07-26; COLD RELEASE,
  INSTALLED LIFECYCLE, AND EXTERNAL-REVIEW EVIDENCE REMAIN OPEN.**
  Platform: the unprivileged Linux Debian-build host. Endpoint/action:
  `scripts/build-debian.sh::build_one` selecting and validating each generated
  package plus `publish_result` moving the validated pass-A package and its
  canonical checksum into the caller-selected absent output leaf. Boundary:
  private exact-commit build/package objects and child-owned Docker/workspace
  authority plus the selected output-parent namespace ↔ the irreversible
  public two-file Debian result and terminal child verdict.

  Proven old path and history: after each compiler container,
  `build_one` ran `mkdir -p "$OUT_DIR"`, selected the first globbed package,
  copied it to `"$OUT_DIR/rustdesk-${profile}.deb"` with overwrite authority,
  then ran the package-authority, polkit-policy, and maintainer-script
  validators against that caller-visible copy. It wrote the checksum through
  overwrite-capable `tee`. Direct reproducibility then read the public pass-A
  checksum, published pass B beneath public `"$OUT_DIR/_rebuild"`, and only
  afterward compared the two hashes. A verifier failure, failed second pass,
  or A/B mismatch could therefore leave one or two apparently complete
  caller-visible artifacts from a failed transaction; a rerun could replace
  prior output. The EXIT path later removed child Docker configuration and
  private build state, so a cleanup failure could also change the verdict
  after public files existed. `git blame` and `git log -S` trace the output
  creation/copy/checksum and `_rebuild` shape to the original
  `cd09dcc5` Debian-builder commit, with later package checks added around the
  same publication model.

  The builder refuses numeric UID and primary GID zero and its sole compiler
  remains the already-confined pinned no-pull/networkless/read-only-root,
  numeric-nonroot, capability-free/no-new-privileges, resource-bounded
  container. This finding was non-root package-output integrity,
  intermediate-result exposure, overwrite, pathname-substitution, durability,
  cleanup-order, and terminal-verdict debt. It is not evidence that the
  builder was run, a package was modified or replaced, another Docker daemon
  was selected, Docker escaped, host root was acquired, a listener or port was
  exposed, or host RustDesk/service/configuration/firewall/network state
  changed or was compromised.

  Source correction: preflight now requires the requested output to be one
  absent absolute canonical leaf beneath an already-existing canonical,
  current-principal non-root parent with owner read/write/search and no
  special, group-write, or world-write authority. It retains the parent's
  device/inode before any build. Existing output, unsafe parent, symlinked or
  noncanonical topology, and malformed destination names fail without
  inspection, adoption, deletion, or overwrite.

  Each compiler still writes only into its private exact-commit source. The
  post-container gate now admits exactly one constrained `rustdesk-*.deb`
  basename and requires a bounded current-principal, non-symlink,
  non-executable, non-group/world-writable, single-link regular file. It
  records the package device/inode, metadata, and SHA-256; runs the complete
  package-authority, polkit-policy, control-script/lifecycle, source, and
  online-snapshot checks against that private object; then requires metadata
  and digest stability. Direct pass A and independent pass B retain only
  private artifact identities/digests and compare those digests. The release
  child still uses `DOUBLE_BUILD=0` only because the enclosing release
  transaction owns two independent exact snapshots. There is no public pass
  copy, `_rebuild`, or checksum before every required check and equality
  decision succeeds. The control-script/package extraction scratch is now
  created as a private subtree of the recorded build workspace and retained
  for its one exact descriptor-relative closer; the former unrelated `/tmp`
  allocation and recursive `rm -rf` deletion path are absent.

  Publication first re-proves and terminally removes the fixed local-Docker
  configuration authority. The isolated
  `scripts/publish-artifact-result.py` opens the exact validated package and
  retained output parent no-follow; rechecks current-principal ownership,
  safe mode, single-link, size, device/inode, and source digest authority; and
  rejects POSIX access/default ACLs where applicable. While the requested name
  is absent, it exclusively creates one kernel-random
  `.debian-output-pending-<64hex>` mode-0700 directory under the authenticated
  parent. Through retained descriptors it creates exactly a mode-0400
  single-link nonempty `rustdesk-x86_64.deb` plus its mode-0400 canonical
  lowercase SHA-256 line, hashes the copy against the already-validated
  digest, synchronizes both files and the pending directory, revalidates the
  closed inventory/content, synchronizes the parent namespace, and returns
  only the strict pending name plus device/inode.

  With the requested output still absent, the shell invokes the shared
  descriptor-relative private-tree closer against the child workspace's
  device/inode recorded immediately after `mktemp`. The old recursive
  `chmod -R`/`rm -rf` cleanup is absent. Substituted, cross-mount, special,
  externally linked, descriptor-budget, or otherwise ambiguous state is
  preserved and fails before final publication. This removes the direct
  private source(s), online snapshot where child-owned, and all remaining
  child scratch only after the package has been independently copied into the
  authenticated private pending object. Release-parent-owned source/online
  snapshots remain under their outer transaction rather than being adopted by
  this child.

  A second isolated publisher invocation then reopens the exact parent and
  pending identities, revalidates the exact modes, links, inventory, checksum,
  and bytes, synchronizes and reproves the parent, and performs one
  descriptor-relative same-parent `renameat2(RENAME_NOREPLACE)` to the
  requested absent destination. It synchronizes the changed namespace, proves
  pending absence and exact final-object identity/content, and reproves the
  pending edge and final identity a second time after the potentially long
  final content hash before reproving the parent. Collision,
  source/parent/pending substitution, unsupported no-replace semantics, or
  uncertainty has no copy, overwrite, deletion, cross-filesystem fallback, or
  compatibility path at the requested name. Only namespace synchronization
  and exact proof follow the final edge change; no build,
  Docker/configuration cleanup, private-workspace deletion, or output write
  remains afterward. R-S11dv and Appendix C #275 make this boundary normative.

  Confined verification used immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as numeric UID/GID 1000:1000 with no pull or network, read-only root and
  repository, recursive bind inclusion disabled, all capabilities dropped,
  no-new-privileges, finite PID/memory/no-swap/CPU/descriptor/core/file-size/
  tmpfs limits, and no Docker/libvirt/service-manager socket, host namespace,
  device, port, or host-configuration mount. Each outer Docker call used a
  fresh mode-0700 private client configuration whose mode-0600 file and
  directory were exactly removed. The focused Debian authority verifier
  passes all 90 mutations. The bounded publisher fixture proves successful
  prepare/commit and mode-0400 exact inventory; occupied-destination
  preservation with pending state retained; source/output-parent/pending
  substitution refusal; source-hardlink refusal; and extra-inventory refusal.
  The independent workspace semantic baseline and its complete catalog of
  2,491 deliberate source mutations pass from mutation one. Adjacent exact
  reruns pass the
  release-parent 27-mutation, Debian systemd-lifecycle 44-mutation, and Android
  builder 145-mutation authority catalogs; the Debian package-authority
  synthetic fixture, source polkit verifier, private-tree closer behavior
  fixture, and native-codec normal/negative gate are green. Bash syntax,
  in-memory Python compilation, requirements HTML parsing, active-hash
  synchronization, and diff hygiene pass. The active requirements SHA-256 is
  `ce7e3a94dc28f59cd64b00b0184655c15c091c517b957c66a8884021fcf25a36`.

  Preliminary failures are retained as verifier-hardening evidence. The
  focused checker initially confused the pre-rename and post-rename parent
  `fsync` while checking final order; an output-preflight-order mutation
  survived; and a source-hardlink mutation survived a generic link-count
  token. Those checks were made phase/object-specific and restarted. Three
  later complete-catalog attempts rejected production mutations correctly
  but expected older diagnostic labels for Docker-before-workspace cleanup,
  the shared Debian disposition, and final no-clobber rename; each label was
  corrected and the complete catalog restarted from mutation one. The final
  destination-edge tightening then made an older focused pending-edge mutation
  target occur twice; the checker now requires and separately mutates both
  pre-content and post-content pending-retirement proofs. The first complete
  rerun rejected each split mutation correctly but expected phase-specific
  diagnostic labels rather than the validator's combined two-proof invariant;
  those expected labels were corrected and the complete catalog restarted
  from mutation one. A subsequent meta-mutation changed the focused
  post-content final-edge enforcement label but survived because the
  independent checker's generic text also occurred in the focused mutation
  catalog; the independent binding now requires the exact enforcement tuple
  and the complete catalog was again restarted from mutation one. No accepted
  mutation or bookkeeping failure is represented as a pass.

  This evidence intentionally does not invoke the Debian builder main path,
  Docker/compiler workload inside the verifier, a release transaction, actual
  package installation, root fixture, systemd/service manager, or any host
  service/network action. The behavioral fixtures use only bounded disposable
  ordinary filesystems inside the confined verifier container.

  One process-boundary error during this slice is retained rather
  than hidden: a host inspection command accidentally included
  `python3 -c 'print()'` with its empty output redirected away. It read no
  project file, wrote no file, used no privilege or socket, and performed no
  service or network operation, but executing even that no-op interpreter on
  the host violated the container-only rule. It is not used as verification;
  every project syntax, behavior, or mutation check runs in the confined
  verifier container.

  Exact cold committed R-B2/R-B10 Debian/release artifacts, executable package
  installation and service lifecycle, installed/native/device behavior,
  independent reproduction where separately required, and R-V3 external
  review remain open. No host RustDesk/service/configuration/firewall/network
  state was inspected or mutated, and the broader Ralph-loop goal remains
  active.
- **R-S11dw/R-S11e-141 — Android pass isolation, private result validation,
  exact cleanup, and publication are one no-clobber authority-terminal
  transaction — SOURCE AND CONFINED FOCUSED SOURCE/MUTATION/FILESYSTEM
  VERIFICATION COMPLETE 2026-07-26; COLD RELEASE, INSTALLED/DEVICE, AND
  EXTERNAL-REVIEW EVIDENCE REMAIN OPEN.**
  Platform: the unprivileged Linux Android-build host. Endpoint/action:
  `scripts/build-android.sh::build_apk` and `sign_apk` creating each private
  pass, `validate_private_result` proving its signed result, and
  `publish_result` exposing only authenticated pass A after private A/B
  equality. Boundary: independent exact-commit writable pass trees, signed
  APK/checksum objects, and child-owned Docker/workspace authority plus the
  selected output-parent namespace ↔ the irreversible caller-visible
  two-file Android result and terminal child verdict.

  Proven old path and history: the Android builder gave both passes the fixed
  `"$OWNED_WORKSPACE/source-build"` pathname. After extracting and compiling
  pass A it recursively changed that tree's permissions and removed it with
  `rm -rf`, then constructed pass B at the same name. Publication ran
  `mkdir -p "$OUT_DIR"` and overwrite-capable `install` for the APK and
  checksum, compared private and public pathnames only after those writes,
  checked the public checksum, and then launched another fallible
  certificate/manifest/mobile-key verifier container against the public APK.
  Docker/configuration and the private workspace remained live until EXIT,
  whose fallback recursively changed and removed the workspace by pathname.
  A verifier, collision, substitution, interruption, or cleanup failure could
  therefore leave apparently complete caller-visible state from a failed
  transaction or replace a prior result, while pass independence relied on
  recursive deletion rather than coexisting object ownership. `git blame`
  and `git log -S` trace this publication/source-reuse shape to
  `d8d9ddaf` (`Confine Android artifact builds`) by Ronen Zyroff.

  The builder has always refused numeric UID and primary GID zero, and its
  build/sign/verification containers remain pinned, no-pull, networkless,
  read-only-root, numeric-nonroot, capability-free/no-new-privileges, and
  resource-bounded. This finding was non-root APK-output integrity,
  pass-isolation, intermediate-result exposure, overwrite,
  pathname-substitution, durability, cleanup-order, and terminal-verdict debt.
  It is not evidence that the builder ran, an APK was modified or replaced,
  another Docker daemon was selected, Docker escaped, host root was acquired,
  a listener or port was exposed, or host
  RustDesk/service/configuration/firewall/network state changed or was
  compromised.

  Source correction: preflight now requires one absent absolute canonical
  output leaf under an already-existing canonical, current-principal non-root
  parent with owner read/write/search and no special, group-write, or
  world-write authority, and retains that parent's exact device/inode before
  creating build authority. Existing output, unsafe/noncanonical/symlinked
  parent topology, or malformed destination fails without adoption,
  inspection, deletion, or overwrite. The private workspace is itself proved
  canonical current-principal mode 0700 and retained by exact device/inode.

  Pass A and pass B now receive distinct freshly absent
  `source-pass-a`/`source-pass-b` exact-commit writable trees. They coexist
  until the one whole-workspace close, so no between-pass recursive
  permission rewrite or deletion establishes independence. Each unsigned APK
  stays inside its pass source and is mounted read-only into signing; only the
  signed APK is created in that pass's private result directory. After
  signing, the result is sealed to exactly mode-0400
  `rustdesk-arm64.apk` and its mode-0400 canonical lowercase SHA-256 record.
  `validate_private_result` rejects extra entries, symlinks, hardlinks,
  wrong ownership/group/mode, empty/oversized APKs, wrong checksum size/text,
  and digest mismatch; runs the existing pinned-certificate,
  v2/v3-signature, manifest, mobile-key, online-snapshot, and source checks
  against that private APK; then requires APK/checksum metadata, checksum
  bytes, and APK digest stability. It retains only validated pass-A
  path/device/inode/digest and pass-B digest authority. Direct A/B equality is
  private. `DOUBLE_BUILD=0` remains release-internal/diagnostic behavior; the
  release transaction independently owns the two exact snapshots.

  Publication re-proves and terminally removes the fixed local-Docker
  configuration authority before any output candidate is prepared. The
  former Debian-only descriptor publisher is now the deliberately closed
  two-profile `scripts/publish-artifact-result.py`; it accepts only
  `debian-x86_64` or `android-arm64`, never caller-selected artifact names.
  The Android profile opens the exact validated pass-A APK and retained output
  parent no-follow, rechecks current-principal ownership, safe mode,
  single-link/size/device/inode and digest authority, rejects widening POSIX
  ACLs, and exclusively creates one kernel-random
  `.android-output-pending-<64hex>` mode-0700 directory beneath the
  authenticated parent while the requested name is absent. Through retained
  descriptors it creates exactly mode-0400 `rustdesk-arm64.apk` and
  `rustdesk-arm64.apk.sha256`, hashes and synchronizes both, revalidates the
  closed inventory/checksum/content, synchronizes the pending and parent, and
  returns only the strict pending name plus device/inode.

  The builder next invokes the shared descriptor-relative private-tree closer
  against the exact recorded workspace while the requested destination
  remains absent. Both pass sources/results, the child-owned online snapshot,
  and all scratch retire together. The old builder-level recursive
  `chmod -R`/`rm -rf` path and between-pass deletion are absent. Root-edge
  substitution, mount/device crossing, special nodes, external links,
  descriptor-budget exhaustion, or any ambiguity preserves state and fails
  before final publication.

  A second isolated publisher invocation reopens the exact parent/pending
  identities, revalidates the exact profile inventory, modes, links,
  checksum, bytes and parent authority, and performs one descriptor-relative
  same-parent `renameat2(RENAME_NOREPLACE)` to the requested absent leaf. It
  synchronizes the parent, proves the pending edge absent and final edge equal
  to the still-open object, revalidates content, and reproves the parent.
  Collision, source/parent/pending substitution, unsupported semantics, or
  uncertainty has no public copy, overwrite, deletion, cross-filesystem
  fallback, or compatibility path. No build, Docker operation, workspace
  cleanup, public verification container, output mutation, or fallible
  completion log follows the terminal publisher call. Verify-only mode does
  not prepare or publish output and uses the same exact workspace closer.
  R-S11dw and Appendix C #276 make this boundary normative.

  Confined verification used immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as numeric UID/GID 1000:1000 with no pull or network, read-only root and
  repository, recursive bind inclusion disabled, all capabilities dropped,
  no-new-privileges, finite PID/memory/no-swap/CPU/descriptor/file-size/tmpfs
  limits, and no Docker/libvirt/service-manager socket, host namespace,
  device, port, or host-configuration mount. The focused Android authority
  verifier passes all 166 deliberate mutations. The shared bounded publisher
  fixture passes independently for both closed profiles, including successful
  prepare/commit, exact mode-0400 inventory, occupied-destination
  preservation, source/output-parent/pending substitution refusal, source
  hardlink refusal, and extra-inventory refusal. Bash syntax, in-memory Python
  compilation, the focused Debian 90-mutation regression, Android exact-source
  comparator fixture, and the independent workspace semantic baseline are
  green. One uninterrupted complete independent catalog rejects all 2,510
  deliberate source mutations from mutation one. Adjacent exact reruns pass
  the release-parent 27-mutation and Debian systemd-lifecycle 44-mutation
  authority catalogs. The native-codec normal and negative fixtures,
  requirements HTML parse, active-hash synchronization, and final Bash/Python
  syntax gates are green. The active requirements SHA-256 is
  `90e6c414eb90986568b603030ce8cd70c0d5b4e802fd89bb6beeca46f5b152dd`.

  Preliminary failures are retained as verifier-hardening evidence. The first
  complete-catalog attempt showed that replacing the recorded Android
  workspace device/inode with a constant survived the independent checker;
  the checker now requires that exact stat-derived assignment. The second
  attempt showed that deleting the output-contract call while leaving its
  function defined survived; the independent checker now binds its order
  before execution/build authority. A third attempt rejected that deletion
  correctly but expected the older diagnostic label. A fourth rejected the
  shared no-clobber mutation correctly but expected an Android-specific label
  even though the Debian profile checker encountered the shared helper first.
  A fifth rejected the migrated Debian exact-inventory mutation correctly but
  expected its pre-profile label. Those expected diagnostics were corrected
  and every complete run restarted from mutation one. Final review then added
  a second exact two-file inventory enumeration after signed-artifact
  verification, with shell-option state preservation and new focused and
  independent mutations; the final 2,510-mutation run passed uninterrupted.
  No accepted mutation or diagnostic bookkeeping failure is represented as a
  pass.

  This source slice intentionally does not invoke the Android builder main
  path, an Android build/signing/verifier workload, keystore, release
  transaction, APK installation, emulator/device, root fixture, systemd or
  any host service/network action. Exact cold committed R-B2/R-B10
  Android/release artifacts, installed/native/device behavior (including the
  separately tracked Android lifecycle/session correction), independent
  reproduction where separately required, and R-V3 external review remain
  open. No host RustDesk/service/configuration/firewall/network state was
  inspected or mutated, and the broader Ralph-loop goal remains active.
- **R-S11dx/R-S11e-142 — privileged service-control and SAS protocol type
  authority — SOURCE CLOSED/GATED 2026-07-27; PLATFORM-WIRE REGRESSION
  COVERAGE STRENGTHENED 2026-08-16; CURRENT CONFINED SOURCE/4,404-MUTATION
  VERIFIED; CURRENT RUST COMPILE UNAVAILABLE BECAUSE THE PINNED IMAGE IS
  ABSENT; PRIOR 2026-07-27 LINUX RUST EVIDENCE RETAINED;
  COLD INSTALLED/NATIVE/DEVICE/EXTERNAL EVIDENCE PENDING.** A fresh
  endpoint-to-action trace covered the Unix and Windows `_service` listener,
  its incumbent-liveness probe, macOS authorization-right readiness and
  Windows service-owned share-RDP mutation, the independently raw macOS
  `_service_credential` runtime PRS snapshot, and the separate Windows
  `_service_sas` listener and `SendSAS` dispatch. Existing kernel
  peer-credential/role checks, Windows
  SYSTEM-only DACLs, deadlines, frame and capacity bounds, transaction
  ownership, receiver-side policy, macOS raw credential protocol, and final
  native-action checks were present and remain unchanged.

  The trace found no present credential or action bypass: each old receiver
  rejected unrelated `Data` variants after deserialization. It did find a
  conceptual protocol-authority and future-reactivation gap: both privileged
  endpoints still compiled and parsed the full cross-purpose CM/file/
  clipboard/URL/whiteboard/audio/process-control `Data` union before their
  allowlists ran. The source correction gives `_service` closed directional
  `ServiceIpcRequest` and `ServiceIpcResponse` enums, gives `_service_sas`
  separate one-operation `WindowsServiceSasIpcRequest` and
  `WindowsServiceSasIpcResponse` enums, and routes all callers, receivers,
  and incumbent-liveness probes through the corresponding typed
  serialization methods. Distinct request/result variant names make
  opposite-direction frames fail deserialization. The old service
  liveness, macOS credential-control, Windows RDP-policy, and SAS variants
  are removed from `Data`.

  R-S11dx and Appendix C #277 make the independent protocol boundaries
  normative. The desktop-wide directional serialization regression covers
  the exact tag-only liveness wire shapes, accepted request/response frames,
  unknown-field refusal, opposite-direction refusal, and cross-purpose
  `Data::Close` refusal. Platform-cfg cases in that same regression now cover
  exact accepted request/result bytes, unknown-field refusal, and
  opposite-direction refusal for macOS authorization-right readiness and
  Windows service-owned share-RDP mutation. This closes a 2026-08-16
  evidence gap found by re-deriving every generic `_service` producer,
  admission gate, receiver authorization check, and native sink: the runtime
  authority remained closed, but the Rust regression had been cfg-excluded
  from Windows and exercised only liveness on macOS. The shared verifier and
  Apple source checker bind
  the exact enum inventories, typed Unix/Windows dispatch, every macOS
  snapshot/readiness and Windows RDP/SAS caller, old-union absence, and
  the desktop-wide/platform-specific wire regressions in addition to the
  deliberate shape/dispatch/caller/residue mutations. The independent
  workspace catalog binds the same source and documentary contract, including
  mutations that restore the old Linux/macOS-only test scope or weaken any
  platform-specific accepted-wire, unknown-field, or direction assertion.

  Current 2026-08-16 verification used the already-present immutable generic
  image as numeric UID/GID 1000:1000 with no pull/network, read-only root and
  repository, dropped capabilities, no-new-privileges, finite resource limits,
  and no Docker/libvirt/service-manager socket, host namespace, device, port,
  or host-configuration mount. Shell/Python syntax, the independent semantic
  baseline, and the Apple structural checker all pass; the Apple checker
  rejects all 40 embedded mutations with empty findings. The first complete
  independent-catalog attempt correctly rejected the first new macOS
  exact-wire weakening but stopped because its new fixture label did not match
  the validator's actual diagnostic. After correcting every new label to the
  emitted contract diagnostic, a fresh uninterrupted run from mutation one
  rejected all 4,404 source mutations and exited zero.

  Current focused Rust compilation/execution was attempted only with
  `--pull=never` against the exact pinned devcheck image and could not start
  because that image is absent locally. No image was pulled, built, tagged, or
  substituted, and no host Rust execution was used. Therefore the new
  macOS/Windows cfg branches have current source/mutation evidence but still
  require native compilation/execution in the future; the prior Linux Rust
  evidence is retained rather than silently promoted to this change.

  The retained 2026-07-27 confined Linux compilation and focused execution
  used immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as numeric UID/GID 1000:1000 with no pull/network, read-only root and
  repository, recursive bind inclusion disabled, capabilities dropped,
  no-new-privileges, finite process/memory/CPU/descriptor/core/file-size
  limits, and no Docker/libvirt/service-manager socket, host namespace,
  device, port, or host-configuration mount. The two directional Rust tests
  pass; the protected/main bounded-codec regression passes; the shared
  service-password value-limit regression passes; and all eight
  Linux-runnable macOS LaunchAgent plist regressions pass. The focused Unix
  incumbent checker rejects all 19 mutations. The embedded Apple checker
  rejects all 30 mutations with empty `r_s11b`, `r_s11b2`, and `r_s11e16`
  findings. The independent semantic baseline passes and one uninterrupted
  complete run rejects all 2,531 in-memory source mutations from mutation
  one. The range-coupled Debian lifecycle and release-parent checkers reject
  44 and 27 mutations. The shared R-S11b/R-S11dx source-only gate, Bash
  syntax, in-memory Python compilation, requirements HTML parsing, exact
  active-hash synchronization, and native-codec normal/negative gates pass.
  Requirements SHA-256 is
  `925919dbedaac48308ab4c1e271a2dcf90e6a48bc110c40eaee3216a02da093a`.

  Preliminary verification is retained rather than promoted: a
  content-bearing internally tagged representation admitted `c: null`, and
  tag-only unit variants still ignored an unknown outer field. Empty struct
  variants were therefore selected and the focused regression now proves
  exact tag-only bytes plus rejection. The first complete workspace-catalog
  attempt correctly rejected the renamed liveness variant but stopped because
  its new fixture expected a descriptive label rather than the validator's
  actual diagnostic. All new diagnostics and caller bindings were audited,
  and the complete 2,531-entry run restarted from mutation one. The pinned
  image lacks the `rustfmt` component, so `cargo fmt --all -- --check` could
  not execute; no formatting pass is claimed, and manual Rust review plus
  `git diff --check` is used instead. The full verifier is not run as a
  monolith because it would require nested container authority that is not
  granted; its exact focused Rust tests and source-only R-S11dx block are run
  separately without a Docker socket.

  This slice invokes no service, listener, endpoint, native privileged
  action, root fixture, Docker socket inside a verifier, or host
  service/network operation. Exact cold installed Unix/Windows/macOS
  behavior, native SAS/RDP/Authorization Services action evidence,
  device/reproduction evidence where separately required, and R-V3 external
  review remain open. The broader Ralph-loop goal remains active.
- **R-S11dy/R-S11e-143 — Linux PulseAudio helper protocol and resource finality
  — SOURCE CLOSED/GATED 2026-07-27; CONFINED LINUX
  RUST/SOURCE/MUTATION VERIFIED; COLD INSTALLED/NATIVE/DEVICE/EXTERNAL
  EVIDENCE PENDING.** A fresh endpoint-to-action trace covered `_pa` listener
  admission, the audio service's client, subscriber-bound token creation,
  owner-main-IPC validation, source selection, PulseAudio capture, raw-frame
  transport, cancellation, and the surrounding `GenericService` retry path.
  The existing authority chain was strong and remains unchanged: the audio
  service proves the connected `_pa` process before disclosing its token; the
  helper accepts only the current process or exact live direct-child CM owner
  identity; the owner main endpoint is UID-routed and identity-authenticated;
  and the token is minted from and retained only for the active subscriber
  set. Source resolution and PulseAudio open still occur only after those
  checks. The trace found no source evidence that an unauthenticated local
  process could start capture.

  It did find a narrower independent protocol/resource/finality gap. The
  first unauthenticated `_pa` frame was `Data::PulseAudioStart` on the default
  `BytesCodec` ceiling of `usize::MAX`, so a same-UID client could accumulate
  an unbounded JSON frame before token validation and the endpoint compiled
  every unrelated `Data` parser. After admission, the helper ignored a
  PulseAudio read error and could spin, its raw write had no deadline, the
  audio service ignored failure to send the token-bearing request, and its
  `if let Ok(next_raw())` loop both hid transport reset and waited forever on
  a stalled helper instead of rechecking subscriber/restart cancellation.
  These were local denial-of-service, lifecycle, and future-reactivation
  defects—not an authorization bypass, root acquisition, public listener, or
  evidence of host/service/firewall/network mutation.

  The source correction moves the exact
  `StartCapture { owner, token, source }` request into the one-variant,
  unknown-field-denying `LinuxPulseAudioIpcRequest` protocol and removes
  `PulseAudioStart` from `Data`. Accepted and connecting `_pa` streams install
  a purpose-specific 8-KiB codec cap before request processing; the typed
  request read and write use a one-second deadline; and request-send failure
  terminates the audio-service run. After authority validation, the helper
  emits only an empty zero-audio sentinel or one exact 3,840-byte frame, checks
  outbound shape and codec size, and gives each write a one-second deadline.
  A PulseAudio read error or transport/write failure terminates that capture
  transaction. The audio-service reader wakes once per second to re-evaluate
  `sp.ok()` and `RESTARTING`; timeout alone is a wake, while peer reset, codec
  failure, or invalid nonempty frame shape propagates to the existing bounded
  `GenericService` retry/backoff instead of being ignored or hot-looped.

  R-S11dy and Appendix C #278 make the closed protocol and terminal resource
  behavior normative. The focused regression covers the exact wire bytes,
  unknown-field and `Data::Close` rejection, typed duplex exchange, codec
  ceiling, exact frame shape, oversize rejection, periodic timeout wake, and
  terminal peer reset. The focused Linux nondumpable CM/PA/whiteboard checker,
  shared R-S11c-7 source gate, and independent workspace mutation catalog bind
  the enum inventory, old-union absence, accepted/client cap, authority-before-
  source order, typed request flow, capture-read termination, bounded write,
  cancellable read, transport error propagation, requirement, Appendix row,
  and this ledger.

  Confined Linux compilation and focused execution used immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as numeric UID/GID 1000:1000 with no pull/network, read-only root and
  repository, recursive bind inclusion disabled, capabilities dropped,
  no-new-privileges, finite PID/memory/CPU/descriptor/core/file-size limits,
  and no Docker/libvirt/service-manager socket, host namespace, device, port,
  or host-configuration mount. Rust 1.75 compiled against the exact committed
  read-only Cargo vendor closure. The closed `_pa` protocol test passes, and
  both pre-existing subscriber/token authority tests pass. The focused Linux
  nondumpable CM/PA/whiteboard checker rejects all 44 deliberate mutations.
  The shared R-S11c-7/R-S11dy source-only block, Bash syntax, in-memory Python
  parsing, requirements HTML/hash synchronization, and native-codec normal/
  negative gate pass. The independent workspace semantic baseline passes,
  and one uninterrupted complete run rejects all 2,556 in-memory source
  mutations from mutation one. The range-coupled Debian lifecycle and
  release-parent checkers reject all 44 and 27 mutations. Requirements
  SHA-256 is
  `51ea30a8cc8fa9a10599d82ffa881e6aafcb0fd5c6f092de549bc1aab415f7fe`.

  Preliminary non-passes remain explicit. The first focused-checker run found
  that its `pub enum Data` prefix selected `DataKeyboard`; the exact
  `pub enum Data {` anchor replaced it, and the then-complete 39-mutation
  suite restarted from mutation one; the final 44-mutation suite also
  restarted from mutation one after the bounded-retry and exact writer-body
  gates were added. Two Rust invocations stopped before
  compilation because a read-only Rustup update path and then a stale split
  registry cache could not satisfy the current lock; a third stopped because
  an old target volume was root-owned. No ownership was changed and no root
  was used. The counted compile instead fixed the installed toolchain,
  consumed the committed read-only vendor source map, and wrote only to a
  fresh UID-owned private `/tmp` target. The pinned image lacks the `rustfmt`
  component, so no formatting pass is claimed; manual Rust review and
  `git diff --check` are used. The full verifier is not run as a monolith
  because it would require nested container authority that is not granted;
  its exact affected Rust and source/mutation components were run separately
  without a Docker socket.

  This source slice does not start `_pa`, open PulseAudio, connect any live IPC
  endpoint, invoke a service, run a root fixture, or inspect/mutate host
  RustDesk/service/configuration/firewall/network state. Exact cold committed
  release-artifact, installed/native behavior, device/reproduction evidence
  where separately required, and R-V3 external review remain open. The broader
  Ralph-loop goal remains active.
- **R-S11dz/R-S11e-144 — whiteboard helper protocol and resource finality
  — SOURCE CLOSED/GATED 2026-07-27; CONFINED LINUX
  RUST/SOURCE/MUTATION VERIFIED; COLD
  INSTALLED/NATIVE/DEVICE/EXTERNAL EVIDENCE PENDING.** A fresh desktop trace
  covered Remote-only `show_my_cursor` registration, per-connection token
  creation, helper launch, token-derived endpoint selection, kernel/process
  parent admission, mutual role-bound HMAC, command transport, renderer state,
  client teardown, helper event-loop cancellation, and transport failure.
  Existing authority remains conjunctive and unchanged: each launch uses a
  fresh 32-byte token-derived endpoint; the helper requires its recorded direct
  parent under the platform-specific kernel/process policy; both directions
  prove the exact `--whiteboard` role and launch token; and only a
  Remote-authenticated connection can mint a token accepted for that
  connection's cursor state. The trace found no source evidence that an
  ambient same-UID process could issue an authorized overlay command.

  It did find an independent parser/resource/finality gap. The four proof
  messages and four post-proof commands were variants of the cross-purpose
  `Data` union over the default unlimited `BytesCodec`. The client fed an
  unbounded command channel and ignored every stream-send error. The helper
  accepted each proved stream into a detached task, continued listening for
  more streams in the same launch generation, retained an unbounded
  connection-token map, parsed unrelated `Data` variants, and decided whether
  disconnect should exit the overlay from the handler's incidental active
  state. These were bounded-local denial-of-service, parser coupling,
  lifecycle, and future-reactivation defects—not an authorization bypass,
  exploitation, root acquisition, public listener, or evidence of
  host/service/configuration/firewall/network mutation.

  The source correction creates three distinct, unknown-field-denying
  protocols outside `Data`: owner `ServerProof`/`EndpointChallenge`, helper
  `ServerChallenge`/`EndpointProof`, and owner-to-helper
  `Bind`/`Event`/`Close`/`Shutdown`. Both accepted and connecting streams
  install the 64-KiB whiteboard codec before proof. Proof reads/writes and
  command writes use one-second deadlines; strict reset, codec, UTF-8, and
  schema errors are terminal. A post-proof command-read timeout is only a
  one-second cancellation wake. The owner retains at most 16 positive IDs
  with fresh exact 32-byte tokens and publishes a 64-slot bounded sender;
  enqueue is nonblocking, lossy cursor/event overflow is diagnosed, critical
  bind/close/shutdown overflow retires the stream owner, and the extra local
  sender is dropped so retirement wakes the receiver. Every transport write
  propagates failure. The helper independently validates the exact token shape
  and 16-entry ceiling, directly awaits exactly one authenticated stream
  instead of detaching it, stops listener admission, checks event-loop
  cancellation on each deadline wake, and emits terminal overlay `Exit` after
  shutdown, cancellation, reset, malformed traffic, or transport failure.

  R-S11dz and Appendix C #279 make the directional wire, resource budgets, and
  terminal ownership normative. The focused Linux Rust 1.75 diagnostic passes
  all seven whiteboard-filtered regressions: exact directional wire and
  cross-purpose/unknown-field rejection, codec/oversize/deadline/reset
  behavior, endpoint token/role proof, exact Linux parent authority,
  per-connection command authority, malformed/token-count rejection, and
  queue capacity. The focused Linux CM/PA/whiteboard checker rejects all 71
  deliberate mutations, and the updated Windows production-listener checker
  rejects all 17 while proving that the DACL path delegates to the same exact
  token-derived postfix classifier used for codec selection. The shared and
  extracted Apple R-S11c-8/R-S11dz source blocks pass. The independent
  workspace semantic baseline passes, and one uninterrupted complete run
  rejects all 2,588 in-memory source mutations from mutation one. The
  range-coupled Debian lifecycle and release-parent checkers reject all 44 and
  27 mutations. Bash syntax, in-memory Python parsing, requirements HTML
  parsing, native-codec normal/negative gates, and exact active requirements
  hash synchronization pass. Requirements SHA-256 is
  `d8c49669e1600f740f6d64404996e8a96e6eae3da2e149fe21f0959fb48c302d`.

  Preliminary non-passes remain explicit. The prior compile session result was
  unavailable after its process handle expired, so no result was inferred; the
  exact focused Rust command was rerun and passed. The first complete workspace
  catalog run exposed a stale `_pa` mutation anchor after the whiteboard
  connector gained another nesting level. The next two complete runs correctly
  rejected the new owner-schema and typed-write mutations but refused to count
  them because the catalog labels did not match the independent validator's
  more precise diagnostics. Each meta-verifier defect was corrected without
  weakening the product contract, the baseline was rerun, and the complete
  2,588-entry catalog restarted from mutation one; only the final uninterrupted
  pass is counted. The pinned image lacks the `rustfmt` component, so no
  formatting pass is claimed; manual Rust review and `git diff --check` are
  used. The full verifier is not run as a monolith because it would require
  nested Docker authority that is not granted; its affected Rust, source,
  semantic, mutation, hash, and range-coupled components run separately
  without a Docker socket. A final combined checker invocation also stopped
  when Python byte-compilation attempted to create `scripts/__pycache__`
  beneath the deliberately read-only repository mount; the source was not
  made writable, and syntax was rechecked by in-memory AST compilation.
  During cleanup preparation, one host-side
  `verify-private-tree-closure.py --help` invocation mistakenly initialized
  only the argument parser and printed usage. It did not inspect or mutate a
  tree, use elevated authority, or run a product/verifier check, but it still
  violated the project-execution-in-container rule and is not counted as
  confined evidence. The actual authenticated target cleanup remains confined.

  Counted project tests, semantic checks, mutation checks, and cleanup used
  immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as numeric UID/GID 1000:1000 with no pull/network, a read-only root and
  repository, recursive bind inclusion disabled, all capabilities dropped,
  no-new-privileges, finite PID/memory/CPU/descriptor/core/file-size limits,
  and no Docker/libvirt/service-manager socket, host namespace, device, port,
  or host-configuration mount. No overlay, listener, host IPC endpoint,
  service, root fixture, or host RustDesk/service/configuration/firewall/
  network operation was invoked. Exact cold committed release artifacts,
  installed/native behavior, device/reproduction evidence where separately
  required, and R-V3 external review remain open. The broader Ralph-loop goal
  remains active.
- **R-S11ea/R-S11e-145 — desktop URL/instance handoff closed protocol and resource budget
  — SOURCE CLOSED/GATED 2026-07-27; CONFINED LINUX
  RUST/SOURCE/MUTATION VERIFIED; COLD
  INSTALLED/NATIVE/DEVICE/EXTERNAL EVIDENCE PENDING.** The Windows/macOS
  `_url` path was traced from OS/CLI and Flutter
  canonicalization through the Rust sender, platform listener/DACL, receiver
  peer authorization, global Flutter event, and Dart window/session dispatch.
  Existing authority was already conjunctive: Windows used the restricted
  named-pipe DACL plus same-session/current-executable proof, and macOS used the
  service-scoped installed-app proof. The reviewed source did not show an
  ambient unauthorized URL-injection path.

  The post-authentication wire was nevertheless the wrong abstraction.
  `Data::UrlLink(String)` made `_url` compile and parse the complete
  cross-purpose local union over the default unlimited `BytesCodec`. The
  sequential receiver had a one-second read timeout but no pre-read frame
  ceiling. The same string carried three operations: a canonical URL opened a
  session, an empty string activated the main window, and the magic value
  `"close"` closed every window. This was bounded-local parser/resource,
  operation-typing, and future-reactivation debt—not evidence of exploitation,
  root acquisition, public listener exposure, host mutation, or compromise.

  `src/ipc.rs` now defines an unknown-field-denying
  `DesktopUrlIpcRequest` outside `Data`, with exactly `OpenUrl { url }`,
  `Activate`, and `CloseAll`. The old union variant, empty-string activation
  caller, close constant, and Dart close sentinel are deleted. Both connecting
  and accepted `_url` streams install an 8-KiB codec before the first frame;
  connect, write, and strict read use one-second deadlines. The existing
  sequential listener owns one request at a time and does not detach work.
  After existing platform sender proof and typed deserialization, the receiver
  independently validates `OpenUrl`: at most 1,024 bytes overall, at most 512
  bytes for the address, the current application scheme, one exact
  connect/play/file-transfer/view-camera/port-forward/RDP/terminal operation,
  and the same direct IPv4/IPv6 or domain-with-port accept set used by the
  connection choke point. Wrong-scheme, noncanonical, query/credential/config,
  relay-shaped, indirect-ID, malformed, unknown-field, cross-purpose,
  oversized, reset, and deadline-expired requests fail before Flutter.
  `src/server.rs` emits distinct open, activate, and close event names;
  `flutter/lib/models/model.dart` handles them in separate branches, so an
  invalid URL event neither activates nor closes a window. macOS Finder
  activation now requests typed `Activate` directly.

  R-S11ea and Appendix C #280 make this protocol, semantic limit, resource
  budget, receiver ordering, and sentinel deletion normative. The final exact
  focused regression was compiled from the
  repository's authenticated vendored Cargo closure in immutable image
  `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c`
  as numeric UID/GID 1000:1000, with no pull/network, a read-only root and
  repository, recursive bind inclusion disabled, all capabilities dropped,
  no-new-privileges, finite resources, and only an isolated user-owned target
  writable. It passed exact wire, unknown-field/cross-purpose rejection,
  valid direct IP and domain/port admission, wrong-scheme/indirect-ID/
  relay-shaped/missing-port/query/config/oversize rejection, receiver
  revalidation, codec/oversize/deadline/reset behavior, and typed transport
  (`1 passed`, `0 failed`, `354 filtered`). The extended Windows
  production-listener/desktop-URL semantic checker passes and rejects all 35
  deliberate source, protocol, constructor, receiver-order, event,
  sentinel, documentation, and gate mutations. The shared and extracted
  Apple R-S11ea source blocks pass. The independent workspace baseline passes,
  and one uninterrupted final exact-tree run rejects all 2,605 in-memory
  source mutations from mutation one. Native-codec normal/negative gates and
  exact requirements hash synchronization pass; the range-coupled Debian
  lifecycle and release-parent checkers reject all 44 and 27 mutations.

  Preliminary non-passes remain explicit. Two initial compile setups stopped
  before repository compilation because the immutable Rustup shim attempted a
  forbidden toolchain sync and then an older split Cargo cache lacked the
  current pinned `crossbeam-epoch`; the vendored closure was used without
  relaxing confinement. A later final focused rerun reached repository
  compilation but a newly specified 4-MiB per-file container limit killed
  `rustc` with `SIGXFSZ`; no test result was inferred, the limit was corrected
  to a still-finite 2 GiB, and the exact test passed. The first extracted Apple
  source block printed an unmatched-parenthesis grep error caused by a
  double-escaped new expression; that extraction is not counted, the
  expression was corrected, and both Apple and shared blocks passed. The first
  two complete workspace catalog attempts correctly rejected the extra
  operation and uncapped connecting-constructor mutations but refused to
  count them because their new catalog labels did not match the validator's
  broader diagnostics. The labels—not the product checks—were aligned, the
  catalog restarted from mutation one, and a complete pass followed. After
  additional adversarial Rust assertions were added, the complete 2,605-entry
  catalog was restarted once more; only that final uninterrupted exact-source
  pass is counted. The pinned image lacks `rustfmt`, so no formatting pass is
  claimed; manual Rust review and `git diff --check` are used. The full
  verifier is not run as a monolith because it would require nested Docker
  authority that is not granted; the affected Rust, source, semantic,
  mutation, hash, and range-coupled components run separately without a
  Docker socket.

  This slice starts no listener, connects no host endpoint, opens no window,
  invokes no service or root fixture, and inspects/mutates no host
  RustDesk/service/configuration/firewall/network state. Exact cold committed
  release artifacts, installed/native behavior, device/reproduction evidence
  where separately required, and R-V3 external review remain open. The broader
  Ralph-loop goal remains active.
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
  runs pinned offline OSV for `flutter/pubspec.lock` and requires reason-bearing future accepts. Exact no-NIC VM
  run `run.EDeOJHBrIT` is green for the 2026-09-10 Pub snapshot, current lockfile, empty policy, and pinned audit
  image at source commit `a82aaba`; its precise scope and remaining gaps are recorded in R-S11df. `scripts/verify.sh`
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
- **R-R2c — alternate mobile build authorities deleted — SOURCE CLOSED; CURRENT APK/DEVICE EVIDENCE OPEN.**
  `scripts/online-fetch.sh`, `scripts/build-android.sh`, and `scripts/android-apk-build.sh` are the sole Android
  release path. The ten imported generic, multi-ABI, F-Droid, iOS, and non-aarch64 top-level Flutter scripts remain
  absent, including as symlinks; `flutter/ndk_arm64.sh` is the only top-level Flutter shell and contains the exact
  locked arm64 command consumed once by the one arm64 split-APK build. The retained Flutter workflow text is
  schema-inert and is checked separately by the GitHub-automation gate. The shared verifier directly checks this
  small source topology, while the Android builder checker binds the authenticated verifier-VM funnel and forbids
  host-Docker, root, host-network, published-port, and live-worktree fallbacks. The obsolete standalone 32-mutation
  mobile verifier and its duplicate workspace verifier-of-verifier block are deleted; they had become false after
  the builder correctly replaced `local_docker` with guest-only `verifier_vm_docker` and established no product or
  artifact behavior. A clean cold exact-commit double build, signed current APK, installation, device lifecycle,
  peer, presentation, and resource evidence remain required by R-B2/R-B10 and are not inferred from source checks.
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

## Closed excision and direct-only presentation backlog

**State: current source topology closed; exact-current artifact evidence remains open.** Normative behavior is in
R-P1, R-P5, R-G1, R-G2, R-G4a, R-G6, R-G9, R-S12, R-S17, R-S19, R-X7, R-X9, R-SV4a, R-SV5, R-SV5a, and
R-SV6a through R-SV6d. Git history retains the original findings, implementation sequence, source counts, and
per-run gate receipts; this section retains only present disposition and evidence limits.

| Finding / requirement | Current source disposition |
| --- | --- |
| I-1/I-2/I-3/I-8; R-S17/R-P1/R-P5 | Host-key/fingerprint/pin behavior was retired rather than repaired. CPace derives its PRS from the password and fixed domain-separation salt. `HostIdentity`, host proof, known-hosts/pin storage, fingerprint boards/dialogs, and `--get-fingerprint`/`--pin-host`/`--forget-host` are absent. Mobile legacy `key_pair` is device metadata plus decrypt-only migration input, not a host identity. |
| I-4/I-5/I-6/I-7; R-G1/R-G2/R-SV5/R-SV6c | Rendezvous-presence sorting is absent; the viewer labels and controllers use direct addresses; recent/favorite peer cards query the real per-address saved PRS; and the excised QR scanner leaves no iOS camera/photo-library usage declarations. The controlled-side status is direct-listener state, not rendezvous presence. |
| I-9/I-10/I-11/I-12; R-X7/R-S19 | Credential prompting occurs before CPace keying. The post-key password/2FA dialogs and senders, attended `Data::Authorize`, runtime `Data::SwitchPermission`, trusted-device/2FA field and widgets, `IdPk`, and `decode_id_pk` are absent. Permission chips are presentation only; live capabilities derive from the authenticated `AuthConnType`. |
| R-SV4a/R-SV5a/R-SV6a/R-SV6b/R-SV6c/R-SV6d | Viewer/session/bridge APIs carry no relay discriminator or public/custom-server predicate. Numeric-ID query/routing, account deployment/logout/audit/avatar control plane, proxy/rendezvous/NAT resolver and persistence, cross-server grammar, online map/query/polling, and their compatibility aliases are absent. The one initiation model is exact direct address over keyed TCP. |
| Dead Dart policy-option aliases — CLOSED/GATED (R-G1) | The retired server/proxy/change-ID/deep-link option aliases and their raw authored-Dart vocabulary are absent. Pinned native stale-value masks are not Flutter controls. |
| Numeric-ID address formatter/controller — CLOSED/GATED (R-G2/R-SV5) | `id_formatter.dart`, numeric-ID formatter/controller APIs, numeric-only autocomplete normalization, relay suffix handling, and bare-ID admission are absent. `direct_address.dart` trims only outer whitespace; the shared connect choke point validates the same exact address; persisted peer addresses render without numeric grouping. |
| R-G4a/R-G6/R-G9 | Role-swap fields/events/FFI/serialization, relay/WOL fallback UI, `forceAlwaysRelay`, unread CM copies of controlled capability flags, and account provenance fields are absent. Direct-only errors point to address/port reachability; live capability refusal is distinct; authenticated connection capability state and the post-key viewer permission protocol remain. |
| Other protocol/config closure | `LoginRequest` carries only the retained session metadata; obsolete host-key, OS-login, elevation, role-swap, and legacy hash authentication messages are absent. The baked rendezvous trust constant cannot be overridden by config; deep links cannot write config/password state; settings expose no deleted identity/relay/key/proxy/whitelist authority; voice-call audio remains AuthConnType-gated; remember/forget password handles both legacy and PRS fields coherently. |

**Evidence boundary.** Focused source, serialization, and Flutter behavior gates protect the named invariants, but their
presence is supplementary and does not prove exact packaged bytes or native behavior. The clean committed cold
Debian/Android/Windows R-B2/R-B10 transaction, native Apple/device coverage where applicable, independent
reproduction, and external review remain governed by their open ledger rows. A regression or contrary runtime result
reopens the affected claim; the removed historical “do not re-open” instruction carried no authority.

### R-S11gk/R-S11e-223 — real Windows full-peer focus/presentation transaction

**OPEN / STOP-SHIP: no valid exact-current Windows full-peer runtime result exists.** The source harness is
designed to run a real Flutter viewer and controlled `--server` inside one zero-interface Windows VM, require
continuous and minimized color changes, post-focus/restore freshness within 2500 ms, mapped remote input, one
exact loopback TCP session without reconnect, unchanged release artifacts, and complete process, listener, and
domain cleanup. The repository-local state contains no Windows golden or complete Windows input closure, so an
exact-current native transaction cannot start from the present inputs. Source conformance, narrow compositor
tests, result-verifier fixtures, and Linux peer evidence cannot substitute. The reported display-only delay after
Windows focus loss while control remains responsive, reconnect recovery, capture-to-present queue behavior,
cross-version behavior, soak, and current release artifacts all remain open.

### R-S11gl/R-S11e-224 — bounded Windows harness storage lifecycle

**Source implemented; current native VM execution remains open.** The current harness uses one nonroot build
lease, a sealed canonical golden as a zero-copy backing edge, one build-scoped snapshot transaction, admission
based on fixed allowance plus a 32-GiB emergency reserve, and identity-bound cleanup on every conclusive
outcome. Failure evidence is allowlisted and bounded to 16 MiB per file and 64 MiB total; bulk disks, overlays,
media, artifacts, and snapshots cannot be retained as diagnostics. Inconclusive identity, process, domain, or
helper cleanup preserves state and blocks another run rather than guessing. The repository-local state has no
Windows golden or complete Windows input closure, so no exact-current real builder transaction ran for this
source. Success, failure, timeout, signal, substitution, cleanup-failure, and residue behavior around the native
Windows VM therefore remain mandatory runtime evidence; source and focused non-VM fixtures do not close it.

### R-S11gm/R-S11e-225 release-parent workspace principal closure (2026-09-15)

**Source closed; real reset/terminal-cleanup fixtures pass; cold release remains
open.** The release parent has no container launches, Docker socket, image
provenance request, capability grant, root fixture, or ownership-conversion
path. Every persistent release-workspace object must remain owned by the
admitted numeric nonroot principal. The commit-bound in-memory helper directly
performs mode normalization and cleanup only after exact root identity, same
mount, bounded inventory, uniform current-principal ownership, retained inode
edges, and complete internal hardlink closure. Foreign ownership,
non-traversable or changed state, external hardlinks, special objects, and
descendant mounts are preserved for explicit reconciliation.

The current ordinary-user reset fixture behaviorally rejected an external
hardlink without changing its target, handled internal hardlinks plus
current-owner mode-0000 files and mode-0500 directories, stripped unsafe mode
bits, removed only ignored generated state, and restored the exact source
snapshot. The terminal-removal fixture exercised the same production helper and
exact empty-root retirement. These runs used no Docker. The pinned complete
offline closure and full release transport are absent, so no current cold
release proves that every real builder returns only current-principal-owned
state.

### R-S11gn/R-S11e-226 — Windows harness transient libvirt storage ownership (2026-08-13)

**Source closed; real QEMU/VM execution remains open.** The old unmanaged absolute disk paths allowed
user-session libvirt to create persistent autostart pools and logs outside the harness's owned backing tree.
The current launchers create a private nonroot foreground `libvirtd` with private HOME/XDG/runtime state and
no listening transport, then create one exact transient, nonpersistent, non-autostart directory pool for each
disk parent before domain creation. Receipts bind pool name/UUID/XML/target inode and QEMU log identity;
domain-first teardown visits every pool, retires exact poolstate/log objects, joins the private daemon and
auxiliaries, and only then retires backing storage. Ambiguous or changed identity preserves state and fails
closed. Historical fake-libvirt fixtures and one private-daemon/transient-pool lifecycle ran without QEMU;
they are not product or VM evidence. Current inventory finds no owned session domain or private harness state.
Exact-current zero-interface QEMU execution, Windows peer/service behavior, and release evidence remain open.

### R-S11go/R-S11e-227 — ordered exact-owner display-selection finality (2026-08-13)

- **SOURCE IMPLEMENTED; FOCUSED 70-MUTATION AND INDEPENDENT 4,129-MUTATION SOURCE EVIDENCE PASS; NATIVE/RELEASE EVIDENCE OPEN.**
  The audit proved several shared connection-flow defects. Native Flutter display switching exposed a void FFI carrying
  only the connection UUID; Dart cleared or changed visible state without awaiting native admission. Signed display IDs
  were cast before validation, missing/closed rounds were silently consumed, and local handler/RGBA state could change
  before an operation was accepted. Switch/capture and refresh were independently schedulable, while the controlled
  side logged invalid switch/capture/exact-refresh requests and continued the connection. A caller-supplied desktop flag
  decided whether displays owned by other live UI sessions survived, although that ownership fact exists only in the
  native handler inventory. Normal generated Flutter bridge calls execute on a four-worker pool, so separately awaited
  UI/event callbacks could still enter native display selection out of order. Dart also copied the mutable selection only
  inside that delayed worker call and could narrow a non-`i32` value before Rust validation. Controlled switch, capture,
  and refresh helpers silently reported success when their weak server owner had already retired.
- Two subtler defects remained after the first ordered-command draft and were corrected in this slice. First,
  `ViewerCommandSender::try_send` could publish the typed command to the network receiver before local handler/RGBA
  ownership committed. A fast peer's first refreshed keyframe could therefore outrun its local owner and be discarded,
  plausibly leaving display presentation waiting for a later keyframe while input remained immediate. Second,
  existing-window startup inserted/replaced a same-session handler before capture admission and removed the entry on
  refusal, destroying the valid predecessor it had just replaced. These are source-level mechanisms consistent with
  the reported Android persistent-service recovery symptom and Windows focus-loss display-only delay; they do not prove
  causation for the weeks-old deployed binaries.
- The correction snapshots an exactly `i32`-representable selection at Dart invocation and feeds generated normal-worker
  calls through one per-live-session/UI-owner latest-wins sequencer bounded to one running and one pending request; a superseded pending
  request completes false without native submission or UI commit. It carries the exact connection-session UUID and
  current UI-owner UUID through a fallible bridge. Under the exact handler-owner lock it validates one nonempty,
  distinct set against current bounded peer inventory. Native code on every platform derives the capture set as that
  selection plus the union retained by every other live UI owner; the Dart/web/native `isDesktop` policy flag is gone.
  One `DisplaySelectionCommand` contains only an optional minimal typed switch, one mandatory boxed capture set, and
  either one legacy refresh-all plan or one boxed exact refresh set. Construction validates capture/switch/refresh
  coherence, dimensions, indices, duplicates, cardinality, retained heap, and serialized work before admission.
- Admission is now an explicit reserve/commit/publish transaction. The sender first reserves the exact bounded MPSC
  slot and checked byte semaphore budget. While that slot remains invisible to the sole network loop, an infallible
  callback commits the new handler/display ownership and retires only obsolete exact RGBA mailboxes. Only then is the
  command published. The network loop performs optional switch, mandatory capture set, decoder refresh, and peer
  refresh in order. Thus the first refreshed keyframe cannot outrun local display ownership. Generic display-control or
  refresh messages terminate the round. The bounded Dart admission sequencer adds no isolate or native/background task;
  no additional transport queue, runtime, timer, polling loop, retry, reconnect fallback, unbounded queue, or
  generic-message bypass exists.
- Existing-window startup now performs the same synchronous reservation and commits the replacement handler only in the
  invisible-slot callback. Refusal leaves a same-session predecessor exactly intact; the former staged insert/rollback,
  `sessionStartWithDisplays`, second capture FFI, and stream-time capture are deleted. Dart awaits native admission and
  rechecks the same connection/UI owner before clearing an image, changing `currentDisplay`, moving a window, dismissing
  the mobile selector, or reporting success. Invalid controlled-side switch/capture/exact-refresh requests terminate
  their authenticated connection instead of preserving silent viewer/controlled divergence. A controlled server-owner
  disappearance during switch/capture/refresh and a later viewer transport failure likewise terminate the exact round.
  Local admission and ordered transport remain distinct from peer-operation acknowledgement, which the current wire
  protocol does not provide.
- The source regressions now cover command shape/byte bounds; queue invisibility during local commit; stale UI owner;
  negative, duplicate, and out-of-inventory displays; missing round; old handler/RGBA preservation on refusal; ordered
  typed selection; exact and legacy refresh plans; cross-owner capture union; failed same-session replacement preserving
  its predecessor; valid startup replacement; the one-running/one-latest-pending Dart sequencer; exact typed-list
  representation; existing-window selected-display/set coherence and exact typed snapshot; and controlled-side
  exact-or-terminal execution. `verify.sh`, `dart-verify.sh`, and `apple-conform-check.sh` invoke the focused
  self-test; the generated Dart gate selects the sequencer behavior test; shared and generated-bridge Rust gates select
  all `r_s11go_` regressions.
- This slice changes no OS-privilege boundary, host service/configuration, listener, firewall, network namespace, or
  unrelated project. No root/sudo/privileged container, image pull/build/tag, published port, product process, VM, or
  full release ran. A confined exact-lock targeted Rust test attempt verified 36 clean exact-commit Git packages and 845
  registry archives against their lockfile SHA-256 values, then stopped offline before compilation because the cleaned
  cache lacks `crossbeam-epoch 0.9.20`, `memmap2 0.9.11`, and `rustls-pki-types 1.12.0`; no substitute version was used.
  Exact generated-bridge/Rust/Dart compilation and test execution, peer-operation acknowledgement, physical Android
  persistent-service task-swipe/reopen/Force-Stop recovery, native Windows focus/minimize behavior, installed
  Linux/macOS/iOS, cross-version behavior, capture-through-presentation timestamps and budgets, sustained
  reconnect/focus/resource soak, cold R-B2/R-B10 equality, independent reproduction, and external review remain open.
  The user's explicit requirement that the whole connection flow—not only complained-about paths—be correct and
  performant on every supported platform remains binding and guides later slices.

### R-S11gp/R-S11e-228 — exact-session display-selection queue lifetime (2026-08-14)

- **SOURCE IMPLEMENTED; FOCUSED 84-MUTATION, ADJACENT ANDROID 532-MUTATION, AND INDEPENDENT 4,320-MUTATION SOURCE EVIDENCE PASS; NATIVE/RELEASE EVIDENCE OPEN.** Review of the immediately preceding
  R-S11go implementation found that its bounded Dart display-selection queue was actually one field on each `FFI`, not
  one queue per exact live `(session UUID, UI-owner UUID)` pair as the requirement stated. This distinction is material
  on Android: `gFFI` is intentionally permanent for the app process and keeps one stable UI-owner UUID, while `start()`
  rotates the connection UUID. An old display operation that remained inside the generated normal-worker/native call
  could therefore retain `_running` and prevent every display selection for the replacement session from reaching
  native code. Activity task-swipe/reopen preserves the process and persistent service, whereas Force Stop destroys
  them; that is a concrete source mechanism matching the user's recovery shape. It does not prove causation for the
  older Android or Windows binaries currently deployed, which predate this new queue implementation.
- The queue now has immutable exact owner value `(sessionId, clientOwnerId)` and a terminal retired state. Submission
  with a mismatched owner or after retirement returns false before invoking the operation. Retirement is exact-owner
  checked and idempotent, immediately resolves the running caller and retained pending caller false, discards the
  pending operation, and prevents a late value or error from reviving the queue or surfacing into replacement-session
  UI. Any already-entered native call still carries only its captured old session and owner. The reusable mobile model
  retires its predecessor queue before reset, rotates its session UUID, and installs a fresh independently draining
  queue before native insertion. Explicit current-session close, stream failure, and expected stream close all retire
  the current queue before asynchronous cleanup; a stale old close cannot retire the replacement session.
- This is deliberately a lifecycle correction to the existing bounded sequencer, not a second recovery system. It adds
  no timer, polling loop, task, isolate, runtime, native/background worker, transport queue, retry, or reconnect fallback.
  It neither stops nor weakens Android's persistent `MainService`; task-swipe may continue to leave that service alive.
  The behavioral regression holds an old operation open, retires its exact queue, proves both old callers are refused,
  proves stale-owner submission and retirement are refused, and proves a fresh replacement queue completes without
  waiting for the old operation. The focused verifier binds exact owner admission, retirement finality, mobile rotation,
  explicit/stream terminal paths, test selection, requirements, and ledger. The adjacent Android lifecycle and
  voice-call ownership checks remain focused source evidence rather than native lifecycle evidence.
- This source slice changes no host service, process, listener, firewall, network namespace, persistent Android service,
  or OS privilege boundary. No root/sudo/privileged container, image pull/build/tag, port publication, RustDesk process,
  VM, or release build is part of this evidence. Exact generated-bridge and Dart compilation/test execution, exact-current
  physical Android task-swipe/reopen/Force-Stop recovery, Windows focus/minimize behavior, Linux/macOS/iOS lifecycle,
  deployed/cross-version behavior, capture-through-presentation timestamps and latency budgets, sustained reconnect/
  focus/resource soak, cold R-B2/R-B10 equality, independent reproduction, and external review all remain open. The
  user's broader requirement that the whole connection flow be correct and performant on every supported platform is
  unchanged.

### R-S11gq/R-S11e-229 — exact-session topology and presentation ordering (2026-08-14)

- **SOURCE IMPLEMENTED; FOCUSED 121-MUTATION, ADJACENT RGBA 55-MUTATION, ADJACENT ANDROID 532-MUTATION, AND COMPLETE
  INDEPENDENT SOURCE EVIDENCE PASS; EXACT DART/NATIVE/RELEASE EVIDENCE OPEN.** The audit found that the
  ordered native session stream was consumed by a synchronous `Stream.listen` callback which started and discarded one
  asynchronous closure for every message. Any awaited `peer_info`, `sync_peer_info`, display switch/follow, cached
  window-transfer, cursor, file, or privacy handler could therefore overlap later messages and complete out of wire
  order. In the display path specifically, `handleSwitchDisplay`, `handlePeerInfo`, `handleSyncPeerInfo`, and
  `switchToNewDisplay` also discarded `updateCurDisplay` futures. Native software-RGBA publication ordering prevented
  one older publication from replacing a newer publication for the same display, but it did not bind decoded pixels or
  first-image/canvas work to the peer/display topology from which their dimensions were read. A later topology event
  could therefore complete while an earlier frame decode or geometry update was still in flight. This is a concrete
  shared Flutter source defect consistent with display-only incoherence or delay while input remains responsive; it is
  not proof that the weeks-old deployed Android, Windows, or Debian binaries exercised this exact mechanism.
- The local authority model is now one immutable `(session UUID, UI-owner UUID)` shared by both bounded Dart lanes.
  Cached window-transfer state and the closed low-rate topology set (`peer_info`, `sync_peer_info`, platform additions,
  switch/follow display, and texture-render mode) enter one FIFO with one running operation and at most 32 pending
  operations. Exact owner mismatch or retirement refuses work before invocation. Overflow or task failure retires the
  running/pending callers and becomes a visible terminal connection error. Expected close, stream error/done, explicit
  close, and reusable-mobile predecessor replacement retire the exact topology and display-selection lanes together.
  Local UI display state commits enter this same topology lane only after the existing ordered native display-selection
  admission returns; code already executing in the topology lane applies its captured revision directly and does not
  recursively enqueue. Revision-sensitive geometry work in the lane is awaited through its commit. The existing 300 ms
  scroll-settle callback remains outside the FIFO so it cannot add topology head-of-line delay; it consumes no lane
  capacity and rechecks the captured exact session/topology revision immediately before mutation.
- Media decode deliberately remains outside that FIFO. Each software RGBA, native texture, or web RGBA notification
  captures a non-enqueuing checkpoint for all topology work observed before it. Checkpoints consume no pending capacity;
  if later topology is accepted before the continuation resumes, the earlier checkpoint is stale and the frame is
  refused. A checkpoint that remains current captures the exact display-topology revision. That session/revision is
  checked before dimensions are read, after asynchronous pixel decode, after canvas/cursor initialization awaits, and
  immediately before image commit. A later topology mutation therefore prevents an old decode or canvas continuation
  from publishing into new state. Software RGBA acknowledges the exact native publication on stale, missing-copy,
  decode, success, and pre-handoff failure paths. First-image preparation is shared through at most one exact in-flight
  future; only a still-current session/revision marks it complete or runs callbacks. Malformed session-stream JSON is a
  visible terminal inconsistency rather than log-and-continue behavior. High-rate cursor/file work is not added to the
  topology FIFO, and frame decode never occupies it.
- This is an ordering/lifetime correction, not a recovery mechanism. It adds no reconnect, retry, timer, polling loop,
  isolate, worker, runtime, Android service restart, native transport queue, or decode head-of-line wait. Deterministic
  Dart queue tests cover FIFO behavior, capacity-free checkpoints, later-state invalidation, overflow retirement, task
  failure, exact retirement, and replacement-session independence. The focused display/session finality verifier binds
  the queue, exact owner lifecycle, topology event set, cached-state ordering, malformed-event finality, local-commit
  serialization, checkpoint/revision guards, first-image finality, requirements, ledger, and generated Dart gate wiring.
- This source slice changes no host service, process, listener, firewall, network namespace, persistent Android service,
  or OS privilege boundary. Exact Dart formatting/analyzer/test and generated-bridge execution have not yet been run in
  this slice. Physical Android task-swipe/reopen/Force-Stop recovery; native Windows focus/minimize behavior;
  Linux/macOS/iOS lifecycle; deployed and cross-version behavior; concurrent-feature interaction;
  capture-through-compositor timestamps and explicit latency/queue budgets; sustained reconnect/focus/resource soak;
  clean committed cold Debian/Android/Windows R-B2/R-B10 artifact equality; installed-service/release-child proofs;
  independent reproduction; external review; and the user's broader requirement that the whole connection flow be
  correct and performant on every supported platform all remain open release obligations.

### R-S11gr/R-S11e-230 — bounded exact-session web frame ownership (2026-08-14)

- **SOURCE IMPLEMENTED; FOCUSED AND COMPLETE INDEPENDENT SOURCE/MUTATION VERIFICATION GREEN; EXACT
  DART/WEB/NATIVE/RELEASE EVIDENCE OPEN.** Follow-up review of R-S11gq's media checkpoint path found that the live web
  RGBA callback handed its
  caller-owned `Uint8List` directly to an asynchronous handler which awaited topology completion before reading it.
  The old, unused `ImageModel.webOnRgba` helper explicitly recorded that a browser callback buffer can be detached after
  callback return and therefore deep-copied it, but the live callback never used that helper. The helper's growable list
  was not a valid resource bound either. Every live web frame also created and detached a separate checkpoint/decode
  continuation, so delayed topology or decode could retain an unbounded number of futures and full-frame buffers before
  resuming them together. Rust's native software-RGBA path is not this defect: its exact session/display mailbox already
  owns at most one active and one latest pending frame, and exact acknowledgement promotes the pending publication.
  This is web buffer-lifetime and presentation-resource debt, not proof of the reported older Android/Windows delay, a
  native mailbox failure, network exposure, privilege escalation, host mutation, exploitation, or compromise.
- The live web callback now takes one synchronous `Uint8List.fromList` copy before any await and submits that owned frame
  to a queue owned by the immutable `(session UUID, UI-owner UUID)`. Each display has an independent lane containing one
  running frame and at most its latest pending successor; supersession resolves and releases the older pending frame
  without invoking it. The queue admits at most 32 active display keys. Owner mismatch or retirement refuses work before
  presentation. Capacity exhaustion and unexpected presentation failure retire every retained lane and are routed to
  the existing visible exact-session failure path. Installation and fail-closed retirement occur with the topology and
  display-selection queues, so task-swipe/reusable-mobile replacement, explicit close, expected close, stream failure,
  and later replacement cannot share a frame queue. Running old work remains unable to commit because the existing
  session/topology checks surround decode, first-image work, and image publication. The obsolete growable web backlog,
  alternate helper, and frame wrapper are deleted.
- This is a bounded ownership correction, not a recovery system. It adds no timer, retry, reconnect, poll, worker,
  isolate, runtime, Android service restart, native transport queue, or cross-display head-of-line wait, and it does not
  change or duplicate Rust's software-RGBA mailbox. Deterministic tests cover one-running/one-latest behavior,
  cross-display independence, terminal task failure, owner/capacity refusal, exact retirement, and replacement-session
  independence. R-S11gr and Appendix C #353 make the contract normative; the focused display/session verifier binds
  the production topology and behavior gates.
- No host service, process, listener, firewall, network namespace, persistent Android service, unrelated image, or OS
  privilege boundary is changed by this source slice. Exact Flutter formatting/tests/analyzer, generated bridge, browser
  execution, physical Android task-swipe/reopen/Force-Stop recovery, native Windows focus/minimize behavior,
  Linux/macOS/iOS lifecycle, deployed/cross-version behavior, concurrent-feature interaction, capture-through-compositor
  timestamps and budgets, sustained reconnect/focus/resource soak, cold R-B2/R-B10 equality, installed-service proof,
  independent reproduction, and external review remain open.

### R-S11gs/R-S11e-231 — exact-owner presentation-refresh display authority

**SOURCE IMPLEMENTED; ONE EXECUTABLE RUST REGRESSION RETAINED AND DIRECTLY WIRED;
SOURCE/MUTATION THEATER DELETED; EXACT GENERATED-BRIDGE, TARGET-RUNTIME,
PRESENTATION, PERFORMANCE, ARTIFACT, AND REVIEW EVIDENCE OPEN.**

The production refresh surface carries only the immutable connection-session and UI-owner UUIDs.
Under the exact handler-owner guard, native code rejects a stale owner or empty display set, derives
the bounded display inventory solely from that handler, re-arms each owned software-RGBA mailbox,
re-notifies each applicable pending desktop texture, and admits peer refresh for the same displays
before releasing the guard. Dart cannot enumerate or choose the native refresh display, and no
retry, reconnect, timer, worker, queue, service transition, or privilege surface was added.

The executable Rust regression
`r_s11ff_r_s11gs_video_refresh_derives_the_current_exact_ui_owner_displays` exercises exact-owner
and empty-set refusal, invalid owned inventory, and canonical multi-display derivation; the shared
verifier invokes the `r_s11ff_` family directly. The deleted 1,339-line
`scripts/verify-viewer-rgba-mailbox.py` only matched source and test names and applied 137 textual
substitutions while conflating R-S11ew, R-S11fr, R-S11gs, R-S11gt, and R-S11iw. Its 2,028 lines of
workspace validator, mutations, source binding, dispatch, and documentation/wiring coupling were
also deleted. No product source or executable regression changed.

Fresh generated Rust/Dart bridges and exact-current target execution remain STOP-SHIP. Android
task-swipe/reopen/Force-Stop, Windows focus/minimize, other-platform and cross-version behavior,
capture-through-presentation timestamps, explicit latency/queue/CPU/memory budgets, sustained
reconnect/resource soak, cold R-B2/R-B10 equality, independent reproduction, and external review
remain open.

### R-S11gt/R-S11e-232 — explicit initial and ongoing native display ownership

**SOURCE IMPLEMENTED; SIX EXECUTABLE RUST REGRESSIONS RETAINED AND DIRECTLY WIRED;
SOURCE/MUTATION THEATER DELETED; EXACT GENERATED-BRIDGE, TARGET-RUNTIME,
PRESENTATION, PERFORMANCE, ARTIFACT, AND REVIEW EVIDENCE OPEN.**

Only the first fresh, streamless, unselected video UI handler may start peer I/O and await initial
display ownership. The initial login response preserves the raw peer display before generic
normalization and either binds exactly one valid marked handler once or preserves a completely
explicit reconnect selection. Missing, ambiguous, stale, conflicting, unowned, or out-of-inventory
state is terminal before peer metadata is consumed. The worker slot is acquired before and retained
with the handler-owner guard through stream installation and peer start, and failed start rolls back
only the same exact UI owner.

Software-RGBA and desktop-texture delivery require the handler's exact display membership. Renderer
resources never create capture authority; texture selection is display-keyed; renderer sizing
carries and rechecks the exact UI-owner UUID, is awaited in the existing topology lane, and cannot
add display ownership. Established noncached reconnects restore their prior bounded selection
through the existing ordered display transaction. No alternate owner, compatibility presentation
path, reconnect mechanism, queue, task, worker, timer, or privilege transition was added.

The directly wired `r_s11gt_` Rust family covers one-time binding, invalid and ambiguous refusal,
reconnect preservation, session-start admission, renderer-resource exclusion, and exact-owner
sizing. The `r_s11ff_` family covers exact-owner refresh. These tests execute deterministic Rust
state and ownership transitions; the deleted Python parser executed none of the Rust, Dart,
generated bridge, renderer, focus, lifecycle, or peer behavior.

Fresh bridge generation and exact-current Rust/Dart/Flutter execution remain STOP-SHIP, including
physical Android task-swipe/reopen/Force-Stop and Windows focus/minimize/window-transfer; all
supported platform and cross-version behavior; capture-through-compositor timing; sustained
reconnect/focus/resource soak; cold R-B2/R-B10 equality; independent reproduction; and external
review.

### R-S11gu/R-S11e-233 — bounded exact-owner native-to-Dart cursor publication

**SOURCE IMPLEMENTED; THREE EXECUTABLE RUST REGRESSIONS RETAINED AND DIRECTLY WIRED;
SOURCE/MUTATION THEATER DELETED; EXECUTABLE DART, GENERATED-BRIDGE, TARGET-RUNTIME,
PRESENTATION, LIFECYCLE, PERFORMANCE, ARTIFACT, AND REVIEW EVIDENCE OPEN.**

Each exact native UI handler owns one `CursorPositionMailbox`: one typed published coordinate/token
and one latest current coordinate. New positions replace only the current value while a publication
is outstanding. Exact session, UI-owner, coordinates, and checked positive token gate acknowledgement;
acknowledgement drains or promotes exactly one latest successor. Failed delivery retains only current
state and blocks another post until exact stream replacement rotates to a fresh token. A topology
barrier retires only pre-barrier pending state under the same handler lock; later movement may promote
after the already-published predecessor is acknowledged. Handler retirement drops the mailbox.

Dart awaits the exact session/topology checkpoint and then attempts the exact native take even if a
later topology transition invalidates coordinate commit; this prevents the unchanged publication from
stranding a post-topology successor. A synchronous commit still requires the captured topology revision.
Web does not impersonate the native typed stream: signed-32-bit coordinates enter the existing exact-owner
one-running/one-latest lane and commit only after its topology checkpoint. No retry, reconnect, timer,
worker, isolate, service restart, transport queue, listener, or persistent-service change is introduced.

The three directly wired `r_s11gu_` Rust regressions exercise one-published/one-latest promotion,
wrong-coordinate and wrong-token refusal, topology-barrier retirement, post-barrier promotion, stream
re-arm, stale predecessor refusal, drain, and allocation exhaustion. The shared verifier invokes the
family directly; the generated-bridge verifier invokes both the enclosing lifecycle module and the exact
family. These are executable Rust state-machine tests, not Dart, generated-bridge, lifecycle, renderer,
or target-runtime evidence.

The deleted 779-line `scripts/verify-viewer-cursor-mailbox.py` only parsed source strings and applied
61 textual substitutions. Its 1,276 lines of duplicated workspace validator, source mutations, source
binding, dispatch, and cross-verifier wiring were also deleted, including the display-selection mutation
that merely asserted the cursor verifier's position in an arbitrary dispatch sequence. The parser never
executed Rust or Dart, generated a bridge, drove a cursor event through a target runtime, presented pixels,
or measured latency/resources. No product source or executable regression changed.

The bounded-before-port requirement remains grounded in the official Dart contracts: [`SendPort.send`](https://api.dart.dev/dart-isolate/SendPort/send.html)
is asynchronous and does not wait for receipt, while [`ReceivePort`](https://api.dart.dev/dart-isolate/ReceivePort-class.html)
buffers before listener registration. Flutter also warns that lifecycle notifications may be skipped and
that mobile [`paused`](https://api.flutter.dev/flutter/dart-ui/AppLifecycleState.html) stops begin/draw-frame
callbacks. Those platform contracts justify the bounded owner; they do not prove this implementation on a device.

Exact executable Dart tests for checkpoint/take/invalidation and the web lane, fresh generated Rust/Dart
bridges, and exact-current target scenarios remain STOP-SHIP. Required scenarios include Android
task-swipe/reopen/Force-Stop, Windows focus/minimize/window transfer, other supported platforms and
cross-version operation, actual cursor/display presentation ordering, capture-through-presentation timing,
bounded CPU/memory/tasks/handles/queues, sustained reconnect/focus/resource soak, cold R-B2/R-B10 equality,
independent reproduction, causation, and external review.

### R-S11gv/R-S11e-234 — exact bounded cursor-shape identity, publication, presentation, and retirement

**SOURCE MODEL UPDATED; EXACT FLUTTER UNIT STATE-MACHINE COVERAGE PASSES; TARGET-NATIVE, DEVICE,
PERFORMANCE, AND RELEASE EVIDENCE OPEN.**

- The exact pinned Flutter 3.24.5 source exposes a framework lifetime hole:
  `MouseCursorManager.handleDeviceCursorUpdate` removes `_lastSession[device]` and returns for
  `PointerRemovedEvent` without calling `MouseCursorSession.dispose`. `RendererBinding` updates
  `MouseTracker` before `GestureBinding` routes the same non-hit-tested removal event through
  `PointerRouter`. Dart's `Finalizer` contract does not guarantee that a callback runs. The former
  finalizer-only compensation therefore could not establish deterministic pointer-device retirement.
- `flutter/lib/models/custom_cursor_registry.dart` now gives each live presentation one exact
  `CustomCursorPresentationSession` keyed by UI owner and pointer device. Claiming a replacement first
  installs the new exact device owner and synchronously revokes the predecessor; exact session retirement
  removes only an identity-equal mapping. Device and UI-owner retirement synchronously make every affected
  session unable to present before their serialized fallback/deletion futures run. The presentation token
  independently rechecks retirement after asynchronous registration readiness. An in-flight platform
  presentation remains conservatively leased until serialized fallback or a successful replacement proves
  displacement.
- The native and web adapters install one process-lifetime global `PointerRouter` route when their first
  custom session is created. A real `PointerRemovedEvent` retires the current exact device owner. Normal
  Flutter disposal detaches and retires the same finalizer-safe session object idempotently, UI teardown
  retires every device owned by that exact cursor owner, and a stale dispose or later finalizer cannot remove
  or reset its replacement. The finalizer token has no `MouseCursorSession` back-reference and remains only
  a best-effort last resort; correctness no longer depends on garbage collection.
- The existing checked capture, content identity, typed acknowledgement, bounded controller/subscriber/Dart
  caches, exact decompression, and 64-entry/16 MiB process-global platform registry remain governed by
  R-S11gv. Direct Rust `r_s11gv_` tests remain in `scripts/verify.sh`. The direct Dart
  `custom_cursor_registry_test.dart` gate remains in `scripts/dart-verify.sh` and now covers pending
  device removal, Flutter's exact `MouseCursorManager` replacement order, real `PointerRouter`
  classification of `PointerRemovedEvent`, stale and unactivated same-device replacement chains, exact
  UI-owner retirement, and retirement during an in-flight platform presentation in addition to its prior
  ordering, uncertainty, resource-bound, and diagnostic-finality cases.
- The 769-line `verify-viewer-cursor-resources.py` source-wording/mutation catalog and 387 lines of its
  independent workspace verifier, mutation fixtures, source loading, and shell/Apple wiring are deleted.
  They parsed selected strings and meta-tested 73 mutations but did not execute Flutter, a platform cursor
  manager, pointer delivery, native capture, or presentation; retaining them would misstate evidence. No
  skipped placeholder or compatibility wrapper replaces them.
- A confined exact Flutter 3.24.5/Dart 3.5.4 run mounted the current registry/route sources and repository
  test read-only into a disposable minimal Flutter package and passed all 24 tests. Its first run correctly exposed
  four stale test setups: three requested eviction before asynchronous registration finality despite the
  non-evictable pending-entry contract, and one acquired a failed handle only after it had retired. The tests
  now acquire before asynchronous failure and await successful registration before inactive eviction. The
  final suite additionally prevents old-session disposal from reclaiming a handoff after its unactivated
  successor retires. A separate exact-Dart harness covers the lower-level pending-device, stale-replacement,
  all-device UI-owner, and in-flight-presentation cases. A second networkless run used a byte-matched current
  Flutter source snapshot and the unchanged committed lockfile to analyze the four touched production files
  against the application's actual dependency closure and rerun all 24 tests. This proves the pure Dart
  owner/coordinator state machine, shared production `PointerRouter` adapter, and touched-file type integration;
  it does not analyze the whole app, generate the bridge, execute the native cursor plugin, or drive engine-to-
  `RendererBinding` pointer delivery.
- Engine/OS `PointerRemovedEvent` delivery, native plugin registration/presentation, physical Android task
  swipe/reopen/Force Stop, Windows focus/minimize/reconnect, other target platforms, cross-version behavior,
  capture-through-compositor latency, sustained resource/performance soak, cold artifact equality, installed
  packages/services, independent reproduction, external review, and causation of the reported display delay
  remain open. The broader requirement that the complete connection flow be correct and performant is not
  narrowed by this slice.
- Source extraction, formatting, structural checks, and product/test execution use disposable unprivileged
  containers with no published ports. Product/test execution is networkless and uses a private snapshot or
  read-only exact repository files; one formatter-only invocation made only its two exact source/test mounts
  writable. Acquisition-only containers with no repository mount used outbound HTTPS to resolve the minimal test
  and unchanged committed application lockfiles; all analysis/tests then ran offline. Nothing runs RustDesk or
  inspects/changes host RustDesk, `haggai_computer`, host services, firewall/routing, or listener state.

### R-S11gw/R-S11e-235 — bounded controlled-side service-to-connection egress (2026-08-16)

**SOURCE IMPLEMENTED; FIVE EXECUTABLE RUST REGRESSIONS RETAINED AND WIRED; SOURCE/MUTATION
THEATER DELETED; EXACT CURRENT NATIVE, PERFORMANCE, ARTIFACT, AND EXTERNAL EVIDENCE OPEN.**
Platforms: shared Android, iOS, Windows, Linux, and macOS controlled-side transport. Surface:
synchronous service producers -> exact connection-owned `ControlEgressState` -> connection loop ->
keyed writer.

The inherited defect was real. Audio and video already had semantic bounded mailboxes, but every
other synchronous service message entered an unbounded Tokio channel. This included 33 ms cursor
positions, exact cursor-shape, clipboard and topology messages, stop-service intent, and potentially
large screenshot responses. A busy connection loop or back-pressured writer could retain arbitrary
count and bytes and later deliver stale positions. Reconnect destroyed the old queue; that is a
cleanup-mediated recovery mechanism, not evidence that an unidentified deployed artifact exercised
it or that it caused a reported display delay.

The current design gives each exact controlled connection one short-mutex state owner and a one-slot
wake. It admits at most 256 messages and two maximum session packets plus checked entry accounting;
each protobuf must fit the keyed-session payload ceiling. Only the FIFO-tail `CursorPosition` may be
replaced. Every exact message is an ordering barrier, and all other messages remain FIFO. Audio and
video classes are refused from this control mailbox. Wrong class, oversize, count or byte exhaustion,
or accounting failure clears retained work, stores one typed terminal cause, wakes the receiver, and
terminates the exact connection. Receiver retirement closes admission and releases retained state
even while stale producer clones exist. This adds no retry, reconnect, timer, task, runtime, listener,
dependency, privilege transition, service restart, or Android persistent-service change.

Five executable Rust regressions remain in `src/server/connection.rs`:

- `r_s11gw_cursor_positions_replace_only_the_trailing_cursor`
- `r_s11gw_count_saturation_is_terminal_and_releases_exact_messages`
- `r_s11gw_byte_and_wire_bounds_fail_the_exact_round_closed`
- `r_s11gw_media_bypass_and_receiver_retirement_are_visible`
- `r_s11gw_async_receiver_waits_without_polling_and_closes`

The shared gate retains the direct command
`cargo test --lib --features linux-pkg-config,flutter r_s11gw_ --color never`. Its actual execution,
not its presence in a shell script, is the relevant regression evidence.

The deleted `scripts/verify-controlled-control-egress.py` was a 518-line source parser with 51
textual mutations. It never invoked Cargo or Tokio, drove a producer, blocked a connection loop,
created socket backpressure, or observed ordering, freshness, latency, memory, task, or handle
finality. Its duplicate workspace validator, mutation catalog, dispatch, source-map entry, and
adjacency fixtures were removed; shared and Apple invocations were removed, and the two surviving
neighbor fixtures now name only surviving dispatches. R-S11gw and Appendix C #358 now say explicitly
that source matching, source mutation, script wiring, and workspace parsing are not behavioral proof.
No product source changed in this cleanup slice.

In immutable local inspection image
`sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`, mounted read-only as
numeric UID/GID 1000 with no network or ports, all capabilities dropped, no-new-privileges, and
bounded resources, all 124 Python scripts parsed, requirements HTML and the affected shell gates
parsed, the reduced independent workspace baseline passed, both changed neighboring adjacency
mutations were present and rejected, native-codec synchronization and the status-size gate passed,
and host `git diff --check` passed. One initial targeted mutation exposed that the shortened CM
fixture matched an earlier quoted occurrence rather than the real dispatch; it was anchored to the
actual three-call sequence and then rejected. Exact pre/post host listener bytes matched at SHA-256
`e5c30f61cd0c6495b4719f10dc914ddb2feab91f06f611097f032292f97fa2a4`. The exact pinned devcheck
image `sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` is absent and the
inspection image has no Cargo. No image was pulled or built, no host Rust command ran, and no Rust,
native, or product behavior is claimed.

Remaining STOP-SHIP evidence includes exact-current native execution on every supported target;
real synchronous cursor, clipboard, topology, stop-service, input-response, and screenshot producers
through mailbox and connection-loop backpressure; refusal, disconnect, replacement, FIFO, freshness,
latency, and retained-resource observation; physical Android task-swipe/reopen/Force-Stop and Windows
focus/minimize reproduction; Linux/macOS/iOS and cross-version behavior; sustained reconnect/focus/
resource/performance soak; cold R-B2/R-B10 equality and installed behavior; independent reproduction;
R-V3 external review; causation; and complete connection-flow correctness and performance.

### R-S11gx/R-S11e-236 — exact keyed-writer count-and-byte ownership (2026-08-17)

**SOURCE IMPLEMENTED; FOUR EXECUTABLE RUST REGRESSIONS RETAINED AND WIRED; SOURCE/MUTATION
THEATER DELETED; EXACT CURRENT NATIVE, PERFORMANCE, ARTIFACT, AND EXTERNAL EVIDENCE OPEN.**
Platforms: shared Android, iOS, Windows, Linux, and macOS viewer/controlled transport. Surface:
ordinary and receipt-bearing post-CPace sends through `FramedStream`, its bounded `WriterCommand`
FIFO, and the sole split-sink writer task.

The inherited defect was real: the 512-command Tokio channel returned capacity when the writer
dequeued a frame, before `sink.send` completed, leaving the active ciphertext outside its stated
count. There was no retained-byte budget, and both keyed send paths sealed and advanced their nonce
before discovering backpressure or enforcing the engaged 32 MiB session ceiling. This shared path
carries media, file, clipboard, tunnel, screenshot, and control traffic. The mechanism is consistent
with cleanup-mediated recovery, but source review does not establish that an unidentified deployed
artifact exercised it or that it caused the reported display delay.

The current design creates one `WriterAdmission` from the exact codec ceiling at keying. Before
sealing, both keyed send paths checked-add secretbox `MACBYTES`, reject overflow and oversize, and
nonblockingly reserve one of 512 active-plus-queued frame permits plus exact ciphertext bytes from
a two-maximum-packet budget. Those owned permits travel in `WriterFrameReservation` through the
sole sink await. Sink failure drops encoded sink state before releasing the reservation; all fatal
send, drain, receive, admission, and hard-drop paths close admission before aborting the exact
writer. No retry, reconnect, alternate writer, queue, timer, task, runtime, listener, dependency,
privilege transition, or Android persistent-service change is part of this design.

Four executable Rust regressions remain in `libs/hbb_common/src/tcp.rs`:

- `r_s11gx_writer_admission_checks_size_count_and_bytes_before_ownership`
- `r_s11gx_active_and_queued_frames_share_one_exact_budget_until_abort`
- `r_s11gx_failed_drain_retires_writer_admission`
- `r_s11gx_oversized_plaintext_is_rejected_before_peer_delivery`

The shared gate retains the direct command
`cargo test -p hbb_common --lib r_s11gx_ --color never`. This is the relevant executable regression
entry point; its actual execution remains an evidence obligation and is not inferred from source.

The deleted `scripts/verify-keyed-writer-budget.py` was a 456-line source parser with 25 textual
mutations. It never invoked Cargo or Tokio, opened a socket, created backpressure, exercised a sink,
or observed nonce, delivery, latency, memory, task, or handle finality. The duplicate keyed-writer
parser, mutation catalog, dispatch, source-map entry, and adjacency fixtures were removed from
`scripts/verify-verifier-workspace.py`; shared and Apple calls to the deleted focused parser were
removed, and adjacent verifier fixtures were made exact. R-T18, R-S11gx, and Appendix C #359 now
state that these source/mutation/script-wiring checks are not behavioral evidence.

No product source changed in this cleanup slice. On the final pre-commit bytes, the immutable local
inspection image `sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`
ran as numeric non-root with no network, no capabilities, no-new-privileges, a read-only repository,
and bounded CPU, memory, PIDs, and tmpfs. All 125 Python scripts passed AST parsing;
`requirements.html` and the three changed/shared shell entry points parsed; the independent
workspace baseline passed; and the exact changed adjacency mutation in each surviving CM egress,
controlled egress, and display-selection verifier was rejected. Native-codec binding passed, the
ledger measured 1,117,479 UTF-8 bytes / 372,493 estimated tokens, `git diff --check` passed, and the
host listener snapshot remained byte-identical at
`e5c30f61cd0c6495b4719f10dc914ddb2feab91f06f611097f032292f97fa2a4` before and after. The
inspection image has no Cargo, and the exact pinned dev-check image
`sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c` is absent. No image was
pulled or built, no host Rust command ran, and no Rust/native or product behavior is claimed.

Remaining STOP-SHIP evidence includes exact-current native execution on every supported target;
real `FramedStream` socket backpressure, sink-failure, drain, abort, nonce/non-delivery, latency, and
retained-resource observation; physical Android task-swipe/reopen/Force-Stop and Windows focus/
minimize reproduction; Linux/macOS/iOS and cross-version behavior; sustained reconnect/focus/
backpressure/resource/performance soak; cold R-B2/R-B10 artifact equality and installed behavior;
independent reproduction; R-V3 external review; causation; and proof that the complete connection
flow is correct and performant.

### R-S11gy/R-S11e-237 — bounded connection-manager result ownership (2026-08-17)

**SOURCE IMPLEMENTED; FIVE EXECUTABLE RUST REGRESSIONS RETAINED AND WIRED;
SOURCE/MUTATION THEATER DELETED; CURRENT INSTALLED/NATIVE CM EVIDENCE OPEN.**
Platforms: Windows, Linux, and macOS desktop CM result hops plus Android's direct in-process hop.
Surface: synchronous UI, clipboard, voice, and file-result producers -> bounded CM egress -> exact
connection owner.

The inherited problem was two consecutive unbounded desktop `Data` queues and the same unbounded
connection-facing shape on Android. The live traffic includes chat, privacy, voice, Windows file
clipboard, and typed CM file responses; raw read blocks carry bytes outside their JSON envelope.
A blocked CM writer or connection loop could retain arbitrary count and bytes until reconnect/drop
destroyed the queue. The unused click-time request/response, server-side CM timestamps, FFI exports,
and CM global replica are deleted rather than consuming a result variant. This is a cleanup-mediated
recovery mechanism, not proof about an unidentified deployed artifact or causation for a reported
display delay.

The current `CmEgressSender`/`CmEgressReceiver` owner has one wake token, at most 256 entries, a
128 MiB structured ceiling, a separately enforced 256 KiB raw-block ceiling, and a checked aggregate
budget of two maximum complete messages plus fixed entry accounting. Its closed vocabulary excludes
ambient filesystem data. Wrong class, encoding failure, individual or aggregate oversize, count or
accounting failure atomically clears retained work, records one typed terminal cause, wakes the
owner, and terminates the exact bridge/connection. Receiver retirement closes admission and releases
payloads despite stale senders. No coalescing, retry, reconnect, alternate route, task, runtime,
listener, privilege transition, service restart, or Android persistent-service weakening was added.

Five executable Tokio regressions remain in `src/ui_cm_interface.rs`:

- `r_s11gy_cm_egress_is_fifo_and_releases_capacity_on_receive`
- `r_s11gy_cm_egress_capacity_and_wrong_class_are_terminal`
- `r_s11gy_cm_egress_encoded_byte_limits_are_terminal`
- `r_s11gy_cm_egress_accounts_serde_skipped_raw_blocks_and_receiver_retirement`
- `r_s11gy_cm_egress_wakes_without_polling_and_sender_retirement_closes`

The shared verifier retains the direct command
`cargo test --lib --features linux-pkg-config,flutter r_s11gy_ --color never`. Its execution—not its
presence—is the relevant regression evidence.

The deleted `scripts/verify-cm-egress-budget.py` was an 824-line source parser with textual mutation.
It opened no CM stream or socket, ran no Cargo/Tokio/native process, and observed no filesystem,
ordering, terminal cause, latency, memory, task, or handle outcome. Its duplicate workspace parser,
mutation inventory, dispatch, source-map entry, and adjacency coupling were deleted; shared/Apple
calls were removed and the surviving display-selection fixture now names only surviving dispatches.
The same deletion removes its non-behavioral R-S11ha and R-S11is source assertions. No product source
changed in this cleanup slice.

In immutable inspection image
`sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`, run as numeric nonroot
with no network or ports, read-only root/repository, dropped capabilities, no-new-privileges, and
bounded resources, all 123 Python scripts parsed; requirements HTML and the affected shell gates
parsed; the reduced independent workspace baseline passed; the exact surviving display-verifier
adjacency mutation was present and rejected; native-codec synchronization and the status-size gate
passed; and host `git diff --check` passed. Exact pre/post host listener bytes matched at SHA-256
`e5c30f61cd0c6495b4719f10dc914ddb2feab91f06f611097f032292f97fa2a4`. The exact pinned devcheck
image, authenticated `online/` closure, repository Windows golden, and Android harness state are
absent, so none of the retained Rust or installed/native scenarios can run from current authoritative
assets. No substitute or unrelated image was used; no image was pulled or built, no host Rust command
ran, and no product/native behavior is claimed.

Remaining STOP-SHIP evidence is the current installed/native transaction itself: complete desktop
and Android CM/file operations after Login, both hops, saturation and terminal-first refusal, stale
generation, abrupt owner loss, reconnect, ordering, latency, memory, task/handle finality, and cleanup;
plus platform lifecycle/presentation/soak, cold R-B2/R-B10 equality, independent reproduction, and
external review.

### R-S11gz/R-S11e-238 — exact bounded file-clipboard route ownership (2026-08-17)

**SOURCE IMPLEMENTED; FIVE EXECUTABLE RUST REGRESSIONS RETAINED AND WIRED;
SOURCE/MUTATION THEATER DELETED; EXACT CURRENT NATIVE, PERFORMANCE, ARTIFACT,
AND RELEASE EVIDENCE OPEN.** The inherited registry retained receivers across viewer
rounds, used overlapping positive viewer/controlled IDs, removed routes without a
generation, admitted payloads through unbounded channels, and could create competing
Windows controlled consumers. Those are source-proven ownership, resource, and finality
defects consistent with cleanup-mediated recovery—not proof about the weeks-old deployed
artifacts or causation for the reported display-only delay.

The current registry retains only clonable senders. Every viewer round owns a fresh
receiver, checked negative ID, and exact generation lease; controlled IDs are unique and
positive, with zero reserved for Unix broadcast. Windows preserves the opaque ID bit
pattern, has only the CM-owned controlled consumer, and Unix alone owns the direct
controlled route. Each route uses one nonblocking wake token, a 256-message FIFO ceiling,
an individual heap ceiling of `MAX_SESSION_PACKET`, a two-maximum-payload aggregate
budget plus fixed entry accounting, and checked capacity-based nested allocation sizing.
Admission/accounting failure is terminal and clears payloads; receiver and final-producer
retirement are visible; point/broadcast sends snapshot senders before admission.

Five Rust tests exercise FIFO recovery, terminal count/byte failure and payload release,
allocation-capacity accounting, wake and receiver/producer finality, fresh role-disjoint
routes, duplicate controlled-route refusal, generation-safe cleanup, and exact delivery.
Existing FUSE tests exercise exact controlled-route acquisition. The shared runner retains
`cargo test -p clipboard --features unix-file-copy-paste --lib r_s11gz_ --color never`.
These are executable in-process state-machine tests, not native clipboard, Windows ABI,
viewer/CM/FUSE lifecycle, or installed-artifact evidence.

The 1,463-line `verify-clipboard-route-budget.py` and 1,450 lines of duplicated workspace
loading, source matching, mutation catalog, dispatch, and adjacency coupling were deleted.
The script only searched and rewrote source text while claiming R-S11gz, R-S11it, and
R-S11iu coverage; it never ran Rust, Dart, Kotlin, Flutter, Windows, Android, IPC, or a
clipboard route. Shared and Apple invocations were removed and four neighboring mutation
fixtures were retargeted to the surviving dispatch sequence. Requirements and Appendix C
now treat executable state transitions and current target observation as evidence and
explicitly reject source matching, deliberate mutation, script wiring, and workspace
parsing as behavioral proof.

A confined structural pass in immutable image
`sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`
passed Python AST and requirements HTML parsing, shared/Apple/Dart shell syntax, the
reduced workspace baseline, all four changed adjacency mutations, native-codec
synchronization, the status-size gate, and `git diff --check`. It used no network,
ports, capabilities, writable repository/root, elevated user, or unbounded resources;
the exact host listener inventory was unchanged. No product/native test ran. The
repository `online/` closure, pinned devcheck image, and repository-owned Windows
golden VM are absent, so the retained Rust/Dart/Kotlin/native scenarios receive no new
behavior verdict.

Exact current Windows/Linux/macOS execution must still cover native ABI identity, viewer,
Unix-controlled, Windows-CM, and FUSE routes through connection/reconnect, refusal,
replacement, and cleanup, with file correctness, latency, backpressure, CPU, memory,
handles, and thread finality. Physical Android/Windows symptom reproduction,
cross-version/platform behavior, capture-to-present timing, sustained coexistence soak,
cold R-B2/R-B10 equality, installed artifacts/services, independent reproduction, R-V3
external review, causation, and the complete connection flow remaining correct and
performant are open. No product source or Android persistent-service behavior changed.

### R-S11ha/R-S11e-239 — exact-command CM file-job log ownership (2026-08-20)

**SOURCE IMPLEMENTED; TWO EXECUTABLE RUST REGRESSIONS RETAINED AND WIRED;
SOURCE/MUTATION THEATER DELETED; CURRENT DESKTOP/ANDROID RUNTIME EVIDENCE OPEN.**

The inherited CM task sent terminal file-job logs through an unbounded `String` self-queue even
though the same task awaited the producer and consumed the result. The current `handle_fs` returns at
most one owned terminal log directly after removing the exact connection/generation job. Desktop
consumes it before later file work; Android requests no log construction without retaining the job.
There is no log channel, detached producer, retry, alternate presentation path, or service change.

The executable Tokio regressions
`r_s11ha_cm_file_job_log_is_returned_to_the_exact_command_owner` and
`r_s11ha_cm_file_job_log_can_be_omitted_without_retaining_the_job` remain, with direct shared command
`cargo test --lib --features linux-pkg-config,flutter r_s11ha_ --color never`. The deleted combined
CM source verifier did not execute them or observe logs/jobs/resources. Exact desktop and Android
cancellation, completion, failure, next-command ordering, abrupt loss, and cleanup remain required,
as do current artifacts, performance/soak, independent reproduction, and external review.

### R-S11hb/R-S11e-240 — exact bounded native clipboard-listener ownership (2026-08-20)

**SOURCE IMPLEMENTED; FOUR EXECUTABLE RUST REGRESSIONS RETAINED AND WIRED;
SOURCE/MUTATION THEATER DELETED; EXACT CURRENT NATIVE, DEVICE, PERFORMANCE,
ARTIFACT, AND RELEASE EVIDENCE OPEN.** This is the shared native clipboard-master
path compiled on Windows, Linux, and macOS. Android does not compile it; Android's
persistent `MainService` and separately owned outgoing clipboard poller are unchanged.

The inherited callback sent one payloadless notification per native change into an
unbounded queue for every subscriber even though consumers reread current clipboard
state after waking. Startup failure could retain the inserted subscriber, a controlled
error could bypass manual unsubscribe, name-only cleanup admitted stale-owner ABA, and
post-start master exit did not wake consumers. Those are source-proven desktop resource,
ABA, and finality defects consistent with cleanup-mediated recovery—not proof about the
weeks-old deployed artifacts or causation for the reported display-only delay.

The listener now owns one coalescing readiness bit, one terminal stop/error slot that
outranks readiness, receiver liveness, and a condition wake. Each subscription has a
checked monotonic generation; duplicate live names are refused. The retained
`ClipboardSubscription` and sole `CallbackReceiver` perform exact generation-bound RAII
cleanup, startup failures remove the exact insertion and join the startup thread,
post-start master exit publishes a terminal result, and exact last retirement signals and
joins the sole listener thread. Viewer and controlled scopes retain the exact owner. No
retry, reconnect, timer, poller, additional worker/thread/runtime/listener, payload queue,
dependency, privilege transition, service restart, port, alternate clipboard path, or
Android service change was introduced.

Four deterministic Rust tests exercise 1,024 changes collapsing to one delivery, terminal
error superseding pending readiness, receiver retirement refusing later admission, and a
stale generation preserving its replacement. The shared runner retains
`cargo test --lib --features linux-pkg-config,flutter clipboard_listener::tests:: --color
never`. These are executable state-machine tests; they do not by themselves observe an OS
clipboard callback or target lifecycle.

The 429-line `verify-clipboard-listener-ownership.py` and 426 lines of duplicated workspace
loading, source matching, mutation catalog, dispatch, and adjacency coupling were deleted.
They only searched and deliberately rewrote source text; they never executed Rust, the
native clipboard master, viewer or controlled workers, an Apple target, or a target OS.
Shared and Apple invocations of that script were removed, while neighboring verifier
fixtures were retargeted to the surviving dispatch sequence. R-S11hb and Appendix C #363
now explicitly reject source matching, deliberate mutation, and script wiring as
behavioral proof and require direct target-runtime lifecycle, correctness, latency, and
resource evidence.

In the existing immutable inspection image
`sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`,
with no network, a read-only repository/root, numeric non-root identity, no capabilities,
`no-new-privileges`, and bounded CPU/memory/PIDs/private tmpfs, Python AST and requirements
HTML parsing, shared/Apple/Dart shell syntax, the reduced independent workspace baseline,
native-codec watch, status-size gate, and each of the five changed neighboring adjacency
mutations passed. A stable final targeted run left the exact host listener inventory
unchanged. The container executed no Rust or native product/test code.

The exact pinned devcheck/target builder inputs and authenticated repository `online/`
closure remain unavailable locally, so the retained Rust tests were not compiled or run
in this slice and receive no new result. Required evidence remains exact current Windows,
Linux, and macOS execution of master startup/callback delivery, viewer and controlled
subscriptions, focus/background/reconnect/replacement, every error/retirement edge,
native clipboard correctness, latency and retained thread/handle/memory finality;
physical Android and Windows symptom reproduction; cross-version and cross-platform
behavior; capture-through-compositor timing; sustained coexistence/resource/performance
soak; cold R-B2/R-B10 equality; installed artifacts/services; independent reproduction;
R-V3 external review; causation; and the complete connection flow being correct and
performant. This slice touches no host/Haggai RustDesk process, service, configuration,
listener, firewall/network state, VM/device, image/cache, unrelated workload, or OS
privilege boundary.

### R-S11hc/R-S11e-241 — latest-state Windows tray session-count ownership (2026-08-20)

**SOURCE IMPLEMENTED; FOUR EXECUTABLE RUST REGRESSIONS AUTHORED AND WIRED; EXACT
CURRENT WINDOWS TRAY/PERFORMANCE/ARTIFACT EVIDENCE OPEN.** The inherited one-second tray
poller sent each changed controlled-session count through an unbounded standard-library
channel, while the Tao loop consumed at most one queued value per callback. A stalled UI
could therefore retain obsolete history. Publication discarded receiver failure and the
poller did not observe receiver retirement. This was Windows source-proven resource,
stale-presentation, and finality debt—not a privileged-service bypass, proof that deployed
artifacts exercised it, or a causation claim for the reported display delay.

The tray now owns one Tokio watch cell initialized to zero. The existing poller receives the
sole sender, publishes only changed state after releasing its read guard, and exits before
the next IPC query or after publication when the UI receiver is closed. Arbitrarily many
changes before observation collapse to the newest count. The Tao event-loop scope owns the
sole receiver, acknowledges each observed revision once, and retires it after publisher
closure. The typed main-IPC request, one-second interval, IPC timeout, polling thread/runtime,
tooltip semantics, service authority, network topology, and Android persistent service are
unchanged; no alternate queue, retry, reconnect, listener, port, dependency, or privilege
path was added.

Four Rust regressions exercise latest-state collapse, unchanged-state silence,
receiver-retirement refusal, and publisher-retirement observation. The shared runner keeps
its exact `cargo test --lib --features linux-pkg-config,flutter tray::tests:: --color never`
invocation. The 310-line `verify-tray-session-count-mailbox.py` and 390 lines of duplicated
workspace coupling were deleted because they only matched and deliberately mutated source
strings; they never executed Tokio, the IPC poller, Tao, or Windows. R-S11hc and Appendix C
#364 now require the executable state-machine regressions plus exact Windows main-IPC,
tooltip, focus/session, latency, poller-retirement, and bounded-resource observation.

Confined Python AST/HTML parsing, shared/Apple/Dart shell syntax, the reduced independent
workspace baseline, requirements-digest synchronization, native-codec watch, status-size
gate, and `git diff --check` passed. The non-networked container left the exact host listener
inventory unchanged (`e5c30f61cd0c6495b4719f10dc914ddb2feab91f06f611097f032292f97fa2a4`).

Exact current Windows compilation and tray execution remain open. The authenticated
repository `online/` closure, pinned devcheck/Windows helper inputs, and repository-owned
golden QCOW2 are absent; unrelated local Android emulator images are not RustDesk evidence
or test authority. The retained Rust tests were therefore not compiled or executed and
receive no new behavior verdict. Required evidence still includes an exact candidate in a
disposable zero-interface Windows VM, installed-service and real tray behavior,
focus/minimize/session transitions, sustained thread/handle/memory and latency soak, cold
R-B2/R-B10 equality, independent reproduction, R-V3 external review, and the complete
connection flow remaining correct and performant. This slice touches no host/Haggai RustDesk process, service,
configuration, listener, firewall/network state, VM/device, image/cache, unrelated workload,
or OS privilege boundary.

### R-S11hd/R-S11e-242 — coherent latest-state wakelock snapshot ownership (2026-08-21)

**SOURCE IMPLEMENTED; FOUR EXECUTABLE RUST REGRESSIONS AUTHORED AND WIRED; EXACT
CURRENT NATIVE/DEVICE/PERFORMANCE/ARTIFACT EVIDENCE OPEN.** The inherited controlled-side
path sent every `(connection_count, remote_count)` reevaluation through an unbounded
standard-library channel, assembled the counts under two separate `AUTHED_CONNS` locks,
ignored publication failure, and detached the worker handle. Blame attributes that old path
to inherited commit `c2abd3b3` (2026-06-19), not this correction. This was source-proven
resource, coherence, ordering, and finality debt, not proof that an unidentified deployed
artifact exercised it or that it caused the reported display-only delay.

The process now owns one retained named `rustdesk-wakelock` worker and one mutex/condition-
variable latest-state cell: one zero-initialized typed snapshot, one pending bit, and explicit
publisher/receiver liveness. Each reevaluation derives both counts under one connection
guard, publishes the full snapshot before releasing the guard, and coalesces arbitrary
intermediate revisions. Identical snapshots still wake the worker so a keep-awake setting
change is observed. Publisher/receiver retirement and worker-start/publication failure are
visible. Existing platform wakelock/display behavior is preserved; no queue, retry,
reconnect, timer, poller, additional worker/thread/runtime, listener, port, dependency,
privilege transition, service restart, network route, or Android persistent-service change
was introduced.

Four Rust regressions exercise newest-snapshot collapse, identical-snapshot option
reevaluation, receiver-retirement refusal, and publisher-retirement observation. The shared
runner retains its focused
`cargo test --lib --features linux-pkg-config,flutter server::connection::wakelock_snapshot_tests:: --color never`
invocation. The 510-line `verify-wakelock-snapshot-mailbox.py` and 691 lines of duplicated
workspace coupling were deleted: they only matched and deliberately mutated source strings,
never executed Rust or a platform wakelock, and therefore supplied no behavioral evidence.
R-S11hd and Appendix C #365 now require the executable state-machine regressions plus exact
target-runtime lifecycle, latency, power-state, and bounded-resource observation.

Confined Python AST/HTML parsing, shared and Apple shell syntax, the reduced independent
workspace baseline, the synchronized requirements digest, native-codec watch, status-size
gate, and `git diff --check` passed. The non-networked container left the exact host listener
inventory unchanged (`e5c30f61cd0c6495b4719f10dc914ddb2feab91f06f611097f032292f97fa2a4`).
The exact pinned devcheck image and repository `online/` closure are absent, so the four Rust
regressions were not compiled or executed and no native verdict is inferred. Physical Android
task-swipe/reopen/Force-Stop and Windows focus/minimize/reconnect behavior; Linux/macOS/iOS and cross-version
behavior; weeks-old deployed artifacts; capture-through-compositor timestamps and explicit
latency/queue budgets; sustained connection/reconnect/focus/background/file/control/
resource/power/performance soak; clean cold R-B2/R-B10 equality; installed artifacts and
service behavior; independent reproduction; R-V3 external review; causation; and proof that
the complete connection flow is correct and performant remain release obligations. This
slice touches no host RustDesk process, configuration, service, listener, firewall/network
state, VM, Android device/service, unrelated workload, or OS privilege boundary.

### R-S11he/R-S11e-243 — serialized controlled-side status refresh ownership

**SOURCE IMPLEMENTED; SIX FOCUSED REGRESSIONS AND THE CLEAN COMBINED 12-SUITE/103-TEST
NO-NIC AUTHORITY PASS; EXACT CURRENT NATIVE/PACKAGE EVIDENCE OPEN.** The process-owned `ServerModel` uses one
`ServerStatusRefreshLoop`: one one-shot timer, at most one active complete turn, no queue or
catch-up path, and a terminal close that cancels pending time and awaits the active turn. The
next 500-millisecond interval starts only after client-count/snapshot/window reconciliation and
password-status reads settle. Failure is visible and does not wedge the next interval; the
initial readiness check occurs once; duplicate start and start-after-close are refused. This
owner intentionally survives individual viewer-session retirement and does not weaken Android's
persistent foreground service.

`flutter/test/server_status_refresh_loop_test.dart` exercises slow-turn nonoverlap and the full
post-completion interval, one-time readiness, visible failure with later progress, close/drain/
no-rearm finality, cancellation before the deferred first turn, and duplicate/restart refusal.
Its real `flutter test --no-pub` invocation remains in `scripts/dart-verify.sh`. The former focused
Python verifier, duplicated workspace validator/mutation catalog, and shared/Apple invocations were
deleted because they only parsed source and documentation wording and did not execute the Dart
scheduler.

Flutter's tool bootstrap regards `packages/flutter_tools` as stale unless `.dart_tool/version`
byte-equals the SDK `version` file and the lock/package configuration are newer than
`pubspec.yaml`; Flutter 3.24.5's running `PubDependencies.isUpToDate()` check also requires every
package root to contain `pubspec.yaml`. One shared finalizer therefore checks the exact pinned SDK
version and lock digest, current-principal ownership, non-symlink/single-link inputs, timestamp
freshness, a bounded version-2 package configuration with 1–4096 unique file-URI package roots and
one `pubspec.yaml` at every root, and exact marker metadata/content before publishing the marker.
It uses shell-owned canonical-path and exact-file reads rather than assuming a merged `/usr`, so
the pinned Ubuntu 18.04 builder and current Debian guests execute the same contract. Android,
Debian, Dart/FRB, full-peer staging, focused model execution, and Pub-cache semantic replay all
call it before their first relevant Flutter operation. The focused model transaction also consumes
Flutter's supported `config --no-analytics` first-run action into bounded diagnostics before
requesting JSON, so the validator never strips or tolerates non-JSON banners.

At clean pushed commit `5c2fbfc9f78c8953a945283ef3c0cbef7f981064` (tree
`008431690aaeeab277f6a81e013f532daab50d67`), the authority created a fresh source archive and
QCOW2 child, generated all Rust and Dart bridge outputs, compiled the Flutter workload, and passed
all 12 named suites and all 103 visible tests: global-event dispatch, status refresh, display
selection, session events, latest-frame ownership, session-stream finality, mobile-session start,
desktop-texture lifecycle, desktop-tab retirement, presentation recovery, RGBA publication order,
and custom-cursor registry. Inputs were
the sealed Flutter 3.24.5, Rust 1.75.0, LLVM 15.0.6, FRB generator
`5f8b26a0aadbe8a14aa7cb3ba5ca55e7d1a6d5c751381d3119e73cfc686c2ad0`, Cargo-vendor closure
`b1c746659a19393c8f38e5b36ab76f357d4f7089c53cf45ffca8a45ec7a4f1d6`, Pub-cache closure
`e3e364cd012f19a374655ade92fc49e5c1aa631de367575ad9c5368908264c12`, and the separately pinned
Debian-builder OCI-index/runtime-config identities. The outer run completed in 326 seconds with
QEMU `-nic none`, container `--network=none`, a read-only container root, numeric UID/GID 1000,
all capabilities dropped, no-new-privileges, AppArmor, read-only Landlocked inputs, unchanged host
INET listeners, exact receipts, joined guest-only Docker/QEMU/virtiofsd cleanup, and automatic
private-run-root retirement.

This closes the clean combined Dart/model and fresh generated-bridge execution gap only. The
Windows golden-image provisioning path has the same conceptual freshness obligation; correcting it
still requires a new golden receipt, reprovisioning, inspection, and repinning. Exact native
renderer/compositor behavior and the platform/device/package evidence below also remain open.

Exact Android task-swipe/reopen/Force-Stop and Windows focus/minimize behavior, other platforms and
cross-version operation, capture-through-presentation latency, sustained connection/resource soak,
cold R-B2/R-B10 equality, installed artifacts, independent reproduction, and external review remain
STOP-SHIP.

### R-S11hf/R-S11e-244 — bounded exact-generation global event dispatch

**SOURCE IMPLEMENTED; EXACT CLEAN FLUTTER MODEL REGRESSIONS PASS WITH FRESH BRIDGES;
NATIVE/WEB/PACKAGE EVIDENCE OPEN.** One process-owned `GlobalEventDispatcher`
synchronously selects an exact registered-handler binding or fallback generation before admission.
Registered/control work has one serial drain, one running entry, at most 64 pending entries, a
16,777,216-code-unit message bound, a 67,108,864-byte retained bound, and at most 256 registered
handlers. Replacement retires only predecessor pending work; active predecessor work settles
before replacement work and cannot migrate. Malformed input, exhaustion, handler failure, and
stream termination are visible to the exact route and cannot fail a later generation.

High-rate web cursor events remain outside that FIFO: after exact fallback capture and synchronous
validation they enter the existing exact-owner one-running/one-latest cursor lanes without one
future per event. Native registered-first/fallback routing and web registered-only/fallback-only
routing remain distinct. Exact session teardown retires its fallback capability without stopping
the persistent process or Android foreground service.

`flutter/test/global_event_dispatcher_test.dart` exercises FIFO/nonoverlap, replacement and active
settlement, exact retirement, count/byte bounds, registered-route ownership, native/web route
separation, synchronous cursor handoff, malformed input, visible failure, and recovery.
`flutter/test/latest_frame_queue_test.dart` separately covers observed one-running/one-latest
submission and exact failure retirement. Their real `flutter test --no-pub` invocations remain in
`scripts/dart-verify.sh` and both passed in the exact clean 12-suite transaction recorded above.
The former focused Python verifier, duplicated workspace validator/mutation catalog, and
shared/Apple invocations were deleted because they only parsed source and documentation strings
and did not execute either Dart owner. Exact Android task-swipe/reopen/Force-Stop, native
desktop and web routing, Windows focus/minimize/reconnect, other-platform/cross-version behavior,
capture-through-presentation latency, sustained resource soak, cold R-B2/R-B10 equality, installed
artifacts, independent reproduction, causation, and external review remain STOP-SHIP.

### R-S11hg/R-S11e-245 — endpoint-specific Windows service credential/control protocols

**SOURCE IMPLEMENTED; ONE EXECUTABLE CROSS-PLATFORM WIRE REGRESSION RETAINED AND
DIRECTLY WIRED; SOURCE/MUTATION THEATER DELETED; EXACT CURRENT INSTALLED WINDOWS
AUTHORITY, LIFECYCLE, RESOURCE, ARTIFACT, AND REVIEW EVIDENCE OPEN.**

The inherited `_service_credential` and `_service_main_control` listeners authenticated distinct
protected endpoints but deserialized one shared request/response union before a later discriminator
rejected the wrong operation. The current source instead defines four closed, disjoint,
unknown-field-rejecting types: credential requests/responses and control requests/responses. Each
listener owns its own budget, requester capability, typed reader, handler, writer, and client
endpoint. Credential operations, port-forward count, and shutdown remain reachable only through
their endpoint-specific capability; shutdown retains control authority across acknowledgement and
revalidates before its latch. No listener, operation, retry, runtime, service transition, or network
surface was added.

The platform-neutral Rust regression
`ipc::test::windows_service_credential_and_control_channels_use_closed_directional_protocols`
serializes the exact credential/control request and response forms and rejects opposite-direction,
cross-endpoint, unknown-field, nested-unknown-field, and generic-`Data` inputs. The shared verifier
now invokes that test directly. Its execution is wire/parser evidence only: it does not exercise a
Windows named pipe, LocalSystem, a retained supervisor process, protected action, acknowledgement,
restart, or cleanup.

The deleted `scripts/verify-windows-service-channel-protocols.py` was a 1,538-line source parser
that conflated R-S11hg, R-S11ib, R-S11ic, R-S11iq, and R-S11ir and attacked them only by replacing
source strings. Its duplicate workspace validator, mutation inventory, source-map entry, and
dispatch were deleted, and its shared/Apple calls were removed. No product source changed.

STOP-SHIP evidence remains exact current installed Windows credential/control transactions with the
intended LocalSystem supervisor and unauthorized or wrong-generation actors; malformed and
cross-endpoint frames; PID/creation-time/token/image/argv changes; request and acknowledgement
failure; restart; bounded CPU/memory/handles/tasks; and cleanup. Cold R-B2/R-B10 equality,
independent reproduction, and external review remain open.

### R-S11hi/R-S11e-246 — bounded format-first peer-audio decoder mailbox (2026-08-22)

**SOURCE IMPLEMENTED; CONFINED SOURCE AND DELIBERATE-MUTATION VERIFICATION RECORDED
BELOW; EXACT RUST/NATIVE EXECUTION, PHYSICAL/CROSS-PLATFORM AUDIO AND LIFECYCLE
BEHAVIOR, COLD RELEASE, INDEPENDENT REPRODUCTION, CAUSATION, AND EXTERNAL REVIEW
EVIDENCE OPEN.** Platform: the shared outgoing viewer on Android, iOS, Windows, Linux,
and macOS, plus the shared accepted-call peer-audio playback path on the controlled side.
Endpoint/action: post-transport `AudioFormat`/`AudioFrame` admission into one exact native
Opus decoder/playback worker. This slice does not change audio capture or output-device
selection, voice-call authorization, the connection protocol, Android's foreground
service, any controlled listener, or any video/input/file path.

Read-only current-source and history tracing found one remaining real-time admission
defect adjacent to, but distinct from, the previously corrected R-S11ev video mailbox.
Commit `edc8a3b9` (2026-06-27) replaced the inherited unbounded generic `MediaData`
channel with `mpsc::sync_channel` capacity eight. R-S11ev later removed video frames and
lossy video wake tokens from that union, but deliberately left audio on the generic
FIFO. Both outgoing-viewer and accepted controlled peer-audio callers used nonblocking
`try_send`. A full queue discarded the newly arriving packet, so a decoder/output stall
could retain the oldest eight frames. If production and consumption later resumed at
the same rate, each newly opened slot could accept one new packet while the old
eight-packet offset remained; bounded memory alone therefore did not guarantee real-time
freshness or convergence.

The generic queue also admitted frames before it had any codec authority. On the
outgoing viewer, the audio worker is created with the connection, so an out-of-order or
hostile peer could fill all eight slots with `AudioFrame` messages and make the first
valid `AudioFormat` the dropped ninth item. The decoder would consume and ignore the
pre-format frames, never receive a usable format, and remain silent for that connection.
The controlled accepted-call path creates its decoder only on first format and was not
reachable through that exact pre-format sequence, but it shared the newest-drop FIFO and
freshness defect. `AudioHandler` already and intentionally pins the first valid Opus
sample-rate/channel pair and rejects later changes; changing codecs in place or blindly
recreating native playback was therefore not the correct repair.

The corrected authority model is explicit. The network/authorization task owns
synchronous admission but never decoder execution. One `AudioMailboxState` owns at most
one pending first format, its immutable `(sample_rate, channels)` identity, eight
timestamped frames, and terminal state under one short standard-library mutex. Its
condition variable owns only event-driven wakeup, not payload or history. The sole
`AudioMailboxReceiver` owns dequeue and native decoder invocation. `OwnedMediaThread`
alone owns the non-cloneable sender plus exact decoder `JoinHandle`; the existing bounded
media completion pool alone may own a handle after graceful close or hard `Drop`.

First valid format admission commits its identity and pending payload before wake and
clears impossible pre-generation frame state. A frame is refused until that identity is
present. Duplicate formats create no replay work; a different format remains a protocol
refusal instead of mutating live native state. Receive always takes the pending format
before a frame. Frame admission retains at most eight packets and, at the exact bound,
retires the oldest before appending the newest. Dequeue skips any packet older than one
second without expiring the format. Sender or receiver close marks terminal, releases
the retained format and every frame, and wakes the exact worker. There is no polling
sleep, timeout loop, retry, asynchronous task, nested runtime, secondary queue, or
per-message worker.

Outgoing-viewer and controlled callers still enforce the existing native Opus packet,
sample-rate, and channel limits before mailbox admission and exhaustively handle every
typed outcome. Controlled playback still requires the accepted-call input lease and
pins its separate `ControlledAudioThread.format` identity before installation. A fresh
controlled decoder refusing its validated first format is drained through the exact
existing close-and-join path rather than installed partially. Close, call termination,
audio disable, connection retirement, hard-drop behavior, and the bounded worker-reaper
topology are otherwise unchanged.

Four deterministic Rust regressions cover pre-format refusal plus format-first order,
duplicate/change coalescing, capacity-eight oldest-frame replacement with exact FIFO
order among retained frames, and stale-frame refusal before delivery. Existing owner
regressions continue to cover close-before-join and nonblocking hard-drop handoff. The
focused `scripts/verify-viewer-audio-mailbox.py` gate independently parses the exact
state, typed outcomes, admission/receive order, owner/worker topology, both caller
classes, tests, requirements, ledger, and shared/Apple/independent wiring, then attacks
those obligations with deliberate mutations. The independent workspace validator
separately binds the source behavior and focused verifier structure rather than trusting
the focused gate's verdict.

Final verification uses only the authorized immutable local inspection image with
network disabled, the repository bind-mounted read-only, UID/GID 1000, all capabilities
dropped, `no-new-privileges`, a read-only root filesystem, bounded PIDs/memory/CPU, and
no Docker socket, device, host namespace, or published port. The image contains Python
and shell but no Rust/Cargo, Flutter/Dart, native audio stack, or platform target
toolchain. Exact Rust unit execution, native playback, and compilation are therefore not
claimed; no substitute image, network pull, dependency acquisition, listener, host
process, or long release build is used. The focused peer-audio mailbox verifier passed
all 22 deliberate mutations. The adjacent Android voice-call ownership verifier rejected all 535
mutations. The independent workspace validator passed in normal mode, and its complete
unfiltered 4,832-entry semantic source-mutation catalog passed; every fixture had to be
rejected at every reachable source occurrence. Earlier exhaustive construction runs
correctly rejected the mutated product bytes but exposed one missing focused-fixture
binding and diagnostic-label mismatches in the new independent coverage. Those verifier
defects were corrected, the audio-specific mutation preflight passed, and the final
unfiltered catalog then passed unchanged. Both native-codec watch modes passed. The
three modified Python verifiers parsed through Python's AST without writing bytecode;
the modified shared and Apple shell gates passed `bash -n`; `requirements.html` passed
the standard-library HTML parser; and its independently computed SHA-256 was
`cf622bd47a8d5b0b27c6a171f8e1db34ada551a6b44708fadfd98ab947b45188`.
The exact R-S11hi Rust regressions and their shared Cargo gate are present and
source-bound, but the gate was not executed because the authorized image has no Rust or
Cargo toolchain.

This is source proof of a shared audio resource/order/freshness defect and its bounded
correction. It is not evidence that an unidentified weeks-old Android, Windows, or
Debian artifact contained or exercised the defect, not proof that it caused the reported
display-only delay, and not evidence of exploitation, privilege escalation, compromise,
public exposure, container escape, or a host RustDesk/service/firewall/listener/network
change. This slice does not inspect, stop, restart, modify, or connect to a host RustDesk
process or service; does not inspect or change host firewall/network/listener state; does
not touch an Android device, VM, Haggai/Desktop_Haggai_computer workload, or unrelated
container/image; and does not request or acquire root.

Physical Android task-swipe/reopen/Force-Stop and Windows focus/minimize/reconnect
behavior; Linux/macOS/iOS and cross-version audio behavior; exact weeks-old deployed
artifacts; capture-through-encode/transport/receive/decode/publication/Dart/compositor
timestamps and explicit latency/queue/CPU/memory budgets; sustained
connection/reconnect/focus/background/file/control/audio/resource/power/performance soak;
clean cold R-B2/R-B10 equality; installed process/service/package behavior; independent
reproduction; R-V3 external review; causation; and proof that the complete connection
flow is correct and performant all remain explicit release obligations and explicit user
requests.

### R-S11hj/R-S11e-247 — complete account storage and presentation authority excision

**SOURCE IMPLEMENTED; EXACT COMPILATION, GENERATED-BRIDGE, PACKAGE, AND INSTALLED-ARTIFACT
EVIDENCE OPEN.** The direct-only fork has no live account/address-book/group UI or control plane, so
the inherited record types, encrypted raw stores, FFI/web save/load/clear surface, account options,
password-provenance flag, main-status variants, recursive asset packaging, and retired icon-font
families were deleted instead of acquiring a replacement worker or migration protocol. Existing
`*_ab` and `*_group` files remain untouched inert bytes. Live peer TOML persistence and direct-session
display-name/avatar, CPace, password, and connection-token state are separate and remain governed by
their own requirements.

The former focused Python verifier, its duplicated workspace validator and mutation catalog, and the
shared/Apple invocations were deleted because they only searched exact source and documentation text;
they did not compile the current tree, regenerate a bridge, inspect a package, load dormant user data,
or execute an installed client. Closure now requires exact-current compilation, fresh generated-bridge
inspection, built-package asset and symbol inventories, cold R-B2/R-B10 equality, installed-platform
checks, independent reproduction, and external review. The broader cross-platform connection-flow,
latency, resource, background/focus, reconnect, and cleanup obligations remain open.

### R-S11hk/R-S11e-248 — bounded exact-session file-confirm ownership

**Status: SOURCE IMPLEMENTED; CURRENT EXECUTABLE DART/FLUTTER/NATIVE AND
TARGET-PLATFORM EVIDENCE OPEN.**

Current source admits each required overwrite/skip decision as one immutable canonical
payload: positive signed-32-bit job ID, nonnegative signed-32-bit file number, exact
lowercase booleans, and a nonempty NUL-free read path capped at 32,768 UTF-16 code
units. One exact session generation owns an event-driven FIFO capped at 64
running-plus-pending confirmations. Close retires the generation, pending work, and
remembered policy before replacement. Malformed or refused admission, missing job,
and callback failure use the visible exact-session terminal path; stale failures
cannot close a replacement. Required work is never silently dropped, coalesced, or
overwritten, and the idle owner has no timer or polling wakeup.

The executable `flutter/test/file_dialog_event_loop_test.dart` regression suite is
authored for FIFO, capacity, closed admission, replacement serialization, callback
failure, typed parsing, and path bounds, and remains wired into `scripts/dart-verify.sh`.
The former 610-line Python source recognizer, its second workspace implementation,
and shared/Apple invocations were deleted: those programs only parsed current source,
test names, gate wiring, and documentation, so their passing result was not behavioral
or independent evidence. No Dart, Flutter, native, package, or target runtime executed
in this cleanup slice. Exact-current Dart execution and installed target-native
file-transfer, replacement, Android task-swipe/reopen/Force-Stop, cross-version,
latency/resource, and cleanup evidence remain open under the global STOP-SHIP matrix.
Historical implementation and run details remain in Git at
11402b7ba925a283b8284a14a194c59af9d98e3f.

### R-S11hl/R-S11e-249 — reserve-before-dispatch file-response ownership

**Status: SOURCE CORRECTED; CURRENT EXECUTABLE DART/FLUTTER/NATIVE AND
TARGET-PLATFORM EVIDENCE OPEN.**

Current source reserves one exact session/operation/key/side response owner before
each normal-directory, empty-directory, or recursive-directory native dispatch.
Active, dispatch-draining, and timed-out owners share a capacity of 64. The response
deadline remains live while dispatch is suspended; completion requires every
correlation dimension; recursive errors select only their exact positive action
owner. Wrong, malformed, negative-ID, unsolicited, and stale responses consume no
authority. Because path-only wire responses have no request nonce, timeout retains
a bounded tombstone and refuses same-key retry until an owned late response is
discarded or the session retires. Exact close/replacement clears ownership before
settling waiters, and the native producer preserves the actual local/remote side.
Recursive admission now rejects zero, negative, and out-of-signed-32-bit action IDs
before reserving capacity, starting a timer, or dispatching. Recursive error events
consume an owner only when their ID is a canonical positive signed-32-bit string and
their error is a string; the former event-handler coercion of arbitrary values through
`toString()` is absent.

The executable `flutter/test/mobile_file_session_lifecycle_test.dart` suite now covers
all three response maps before blocked dispatch settlement, shared retained capacity,
strict recursive action/error identity, correlation refusal, retirement/replacement,
dispatch failure, tombstones, late-response consumption, and timer cancellation. It
remains wired into `scripts/dart-verify.sh`. The former 834-line Python recognizer,
its duplicated workspace implementation, and shared/Apple invocations were deleted:
their 36 mutations altered source, test names, gate wiring, and documentation strings
without running Dart, Flutter, a native bridge, or a target. No Dart, Flutter, native,
product, package, or target executable ran in this slice because no user-owned
container/VM runtime or host-independent Dart toolchain was available; no rootful
fallback was used. Exact Dart/native execution, installed cross-
platform bridge behavior, fast/late responses, timeouts, reconnect, cross-version
operation, latency/resource soak, and cleanup remain open under the global STOP-SHIP
matrix. Historical implementation details remain in Git at
7595f363961c3a15b718e99848c63e440ac73718.

### R-S11hm/R-S11e-250 — exact-session file-command and job-result ownership

**Status: SOURCE IMPLEMENTED; DART MODEL REGRESSIONS PASS IN A NO-NIC LINUX VM;
FRESH GENERATED-BRIDGE, NATIVE, AND TARGET-PLATFORM EVIDENCE OPEN.**

Current source captures exact sessions and immutable command inputs before asynchronous
boundaries. Delete-file events settle only their bounded exact session/action/file owner;
they cannot independently mutate a display job. The caller applies progress or error only
after response-and-dispatch finality. Remote empty-directory removal uses a fresh operation
ID and exact `(session, operation, 0)` result owner instead of reusing the display ID/file-0
identity; local removal uses its direct fallible result. The former recursive sink re-resolved
every child and final root by pathname after one advisory metadata check. Current file,
nonrecursive-directory, and recursive empty-directory deletion instead acquire every parent
component no-follow and retain the admitted parent/directory authority. Unix enumeration and
recursion use directory descriptors plus `fdopendir`/`fstatat(AT_SYMLINK_NOFOLLOW)`/
`openat(O_NOFOLLOW)`/`unlinkat`; Windows enumeration and recursion use parent-relative no-follow
NT handles and `FileDispositionInformationEx` POSIX disposition on the exact admitted handle.
Directory enumeration classifies NTFS junctions and every other reparse point as links rather
than ordinary directories, so Flutter cannot recursively enumerate their targets. Nested links
and reparse points are deleted as leaves, a stable link/reparse root is refused,
observable replacement or uncertain absence is an error, and recursion is capped at 64 levels,
10,000 directories, and 10,000 total entries. POSIX has no portable unlink-by-open-inode
primitive: the final `unlinkat` remains a name operation after immediate retained-parent identity
revalidation, so a principal already able to mutate that exact parent can still exchange the
name in that syscall window; it cannot redirect traversal through a substitute or another parent.
Only successful sink finality may complete the separate display job; deletion history removes
only the exact deleted subtree rather than unrelated substring matches. Directory links enter
the leaf-unlink command path and cannot trigger recursive target enumeration. Native
create-directory no longer uses `create_dir_all` on a re-resolved path: it validates the complete
path before mutation, then creates and no-follow-opens every component through the retained Unix
descriptor or Windows NT-handle walk. Native rename rejects anything other than one nonempty
normal basename and stays relative to the retained no-follow source parent. Windows opens the
exact source with DELETE authority, renames that handle with parent-relative
`FileRenameInformation`, and re-proves that the destination names the same volume/file identity.
Unix immediately revalidates the admitted no-follow source identity, calls retained-parent
`renameat`, re-proves the destination identity and required old-name absence, and synchronizes the
parent; every post-rename failure reports that the visible/durable outcome is uncertain. As with
unlink, POSIX has no atomic rename-by-previously-open-inode primitive, so a principal already able
to mutate that exact parent retains the final identity-check/rename syscall window but cannot
redirect the operation through another parent or destination link target. Create-directory and
rename reserve exact file-0 result owners before dispatch and return only after local or remote operation finality;
the local native producer emits that same canonical identity. Invalid or unowned cancel IDs fail before
dispatch. Desktop/mobile create dialogs and the rename dialog capture their admitted directory,
entry/name set, path style, direction, and session before their dialog awaits. Replacement still
synchronously retires admissions, waiters, job/dialog policy,
and page-owned wakelocks before awaited cleanup. Web file commands invoke the global JavaScript
bridge in the caller's checked event-loop turn rather than deferring dispatch into a later `Future`.

The executable Dart suite now drives unmatched and exact delete events through the real
job controller, response-before-dispatch finality, invalid cancel refusal, immutable rename
dialog state, create-error finality, directory-link leaf removal, component-exact history cleanup,
and remote empty-directory display-ID/result-ID separation,
in addition to its existing send, correlation, timeout, retirement, and persisted-job cases.
Focused Rust regressions are authored for complete and nonrecursive empty-directory removal,
nonempty-tree error propagation, depth exhaustion, stable symlink/junction-root refusal, nested
symlink/junction leaf removal without target traversal, swapped-root identity/refusal, and
file-removal refusal through a symlink/junction parent. Windows coverage also requires an NTFS
junction to enumerate as `DirLink` and its leaf command to delete the exact junction without
touching the target. The Windows swapped-root case retains the
admitted handle, renames its object, plants a replacement junction, and requires disposition to
remove only the acquired object; the Unix counterpart requires the changed root edge to fail
without touching or traversing the replacement. Additional native regressions cover legitimate
and idempotent nested creation, complete validation before creation, symlink/junction-parent
refusal, exact/same-name rename, destination-symlink replacement without target mutation, Unix
source-generation mismatch and retained-parent path swap, and Windows exact-source-handle rename
after its original name is replaced.
The Dart suite remains wired into `scripts/dart-verify.sh`. The 859-line source-wording recognizer,
its 572-line workspace duplicate, and shared/Apple invocations were deleted because they ran no
Dart, bridge, filesystem command, target, or application behavior. The inherited
`flutter/test/cm_test.dart` manual GUI launcher was also deleted: it contained no `test` or
`testWidgets` case and no assertion, had no live caller, no longer compiled against `Client`, and
made the real Flutter test inventory fail before behavioral execution.

The exact tracked candidate source subsequently ran under the retained Flutter 3.24.5 toolchain in
an ordinary-user, snapshot-on QEMU guest with `-nic none`, no route, and only guest loopback enabled
for Flutter's private test-runner socket. Offline package resolution left `pubspec.lock` unchanged.
The ownership file passed all 15 visible cases in 4 seconds; the complete remaining 22-file Flutter
inventory passed all 165 visible cases with zero runner errors in 17 seconds at concurrency one.
The `FileController` translation dependency is now explicit at every construction site, so these
model tests do not initialize native FFI merely to label a dialog. The empty-directory case uses
`tester.pump()` instead of awaiting a fake-async zero-duration timer that can never advance itself.
This was an exact-source Dart/Flutter model run, not fresh FRB generation: it reused the retained
generated Dart bridge (`33db9d840bdfe2081f187b61f88436515d58c8482a6c49626901702d259ef813` /
`07607702bac08dd620102cda04ef86759902ba04f256e469e2f567b9f5b5a686`). It ran no Rust native
deletion implementation or RustDesk product process. Fresh bridge generation and exact isolated
execution on Android, iOS, Windows, Linux, macOS, and applicable web targets—including task
swipe/reopen/Force Stop, desktop replacement, reordered results, cross-version transfer,
performance/resource soak, and cleanup—remain OPEN under the global STOP-SHIP matrix.

### R-S11hn/R-S11e-251 — lossless whiteboard IPC/event-loop lifecycle ownership

**Status:** SOURCE IMPLEMENTED / EXACT PRODUCTION LIFECYCLE MODULE EXECUTED
UNDER RUST 1.75 / CONFINED SOURCE AND MUTATION EVIDENCE COMPLETE / FULL ROOT
CARGO AND NATIVE PLATFORM EXECUTION EVIDENCE OPEN.

This continuation selected one residual helper-lifecycle slice under the
binding R-S11b/R-S11c loop. The prior R-S11c-8/R-S11dz correction gave the
dedicated whiteboard helper a token-derived endpoint, exact launch-parent and
role proof, bounded directional protocol, and one authenticated stream owner.
Its process lifecycle was nevertheless incomplete. `start_ipc` could return
while resolving missing or invalid launch environment, creating the listener,
observing listener end, or handling comparable early terminal outcomes. The
only overlay `CustomEvent::Exit` publication lived after
`handle_new_stream`, so those pre-stream returns could strand the transparent
overlay event loop. Windows and macOS started the IPC thread before their
event-loop constructors published `EVENT_PROXY`; a direct early event would
therefore also have been lossy. A single terminal edge used an unbounded
channel, each launcher used a raw detached `std::thread::spawn`, and the thread
handle was discarded. This is source-proven local helper finality and orphan
process debt. It is not proof of compromise, exploitation, public exposure,
privilege escalation, host RustDesk/service/firewall/network modification, or
causation for the separately reported Android/Windows display-only delay.

The corrected authority model treats this dedicated helper process as one IPC
generation with one locked level-triggered `(event-loop proxy, terminal
latch)` owner. Termination before proxy installation latches the edge; the
later platform install immediately consumes its supplied proxy to emit exactly
one Exit and does not retain it. Proxy installation before termination retains
that exact proxy; the first terminal finalizer takes it and emits exactly one
Exit, while repeated finalization is inert. Event-loop retirement clears only
the retained proxy and cannot reset terminal history. Lock ownership is
released before synchronous event delivery. A synchronous worker entrypoint
installs its function-scoped terminal guard as its first action, before invoking
the runtime-backed `start_ipc` function and therefore before runtime
construction, launch-environment, parent, listener, proof, transport, or
command work. Runtime-construction panic and every later return path now
converge on the same terminal publication owner. The authenticated stream
handler observes cancellation but no longer owns or emits process termination.

`WhiteboardIpcWorker` now retains one Tokio one-shot stop sender and the exact
thread handle. Its fallible `std::thread::Builder` gives the worker a diagnostic
name and makes spawn failure visible. Returning event-loop owners request stop
and join that exact thread; join panic is caller-visible. Linux performs the
join both when application construction fails and after `run_app` returns.
The shared Windows/macOS owner performs the join whenever its platform event
loop returns or fails. An already-finished receiver is diagnosed at debug level
before the same exact join, rather than silently discarding that outcome. The
unbounded lifecycle channel, raw detached spawn, inner-handler terminal event,
direct platform-global proxy mutation, and obsolete cleanup callback are
deleted. No retry, reconnect, polling loop, new listener/runtime/worker,
service/activity kill, Android foreground-service weakening, port, network
behavior, dependency, privilege transition, or alternate command route is
added.

The generic `WhiteboardEventLifecycle` is now a small production module imported
by `server.rs`, rather than test logic duplicated beside the server. That exact
production module can be compiled directly without first building unrelated
capture/codec dependencies. Three deterministic state-machine regressions prove
termination-before-proxy delivery once, proxy-before-termination exact take
and repeated-finalization refusal, and event-loop retirement followed by
preserved latched delivery. The shared verifier runs that fast behavior gate
before retaining the complete root-crate Cargo gate; it does not replace,
disable, or weaken the latter. The focused
`scripts/verify-whiteboard-ipc-lifecycle.py` validator binds the state machine,
terminal guards, one-shot named worker, exact join sites, all three platform
proxy owners, absence of obsolete semantics, focused Rust tests,
requirements/Appendix/ledger identity, shared and Apple wiring, independent
workspace dispatch, and requirements hashes. Its self-test deliberately
mutates those boundaries. The workspace verifier independently derives the
product contract and carries separate product, platform, regression,
focused-verifier, wiring, requirement, ledger, and dispatch mutations. The
older R-S11dz shared, Apple, Linux-focused, and independent checks were updated
to require startup-wide finality instead of incorrectly requiring termination
inside the post-authenticated stream handler.

The exact normative requirements input for this disposition is
`9d79e12d9011d0f226c00b40fbc503ee3ce3b13fb23920aa967f954f89030e09  requirements.html`.

One preflight command mistakenly invoked Python bytecode compilation directly
on the host while checking the newly edited verifier scripts. It read only
repository scripts, used no networking or privilege, and did not inspect or
touch RustDesk, a service, listener, firewall, device, VM, or unrelated
workload. Its result is discarded as validation evidence and its generated
`scripts/__pycache__` residue is removed. All reported parser and verifier
evidence for this slice must come from the sole approved networkless,
read-only, capability-dropped verifier container.

Earlier confined source evidence used the approved verifier image identity
`sha256:2d178f2785b96dfbf62a416ca2e40f50e30150b4ff3320d706f0d96e90600eb3`
with no network, a read-only repository mount, all capabilities dropped,
`no-new-privileges`, non-root UID/GID 1000, bounded PIDs/memory/CPU, and only a
bounded private `/tmp`. The focused lifecycle verifier passed its complete
focused self-test; a targeted preflight of the new lifecycle fixtures and the
affected legacy whiteboard fixtures passed. The updated Linux
nondumpable/CM/PA/whiteboard focused verifier also passed. Python AST parsing of the three edited
verifiers, requirements HTML parsing, and Bash syntax parsing of both edited
gate scripts passed under that confinement. That earlier image contains no
Rust/Cargo, Dart/Flutter, or native platform toolchain.

A subsequent exact-candidate run executed the independently compilable
production lifecycle module with pinned `rustc 1.75.0` and `cargo 1.75.0` in
builder image
`sha256:304b251e77fafe03192e035cc22479e0909d688035fbd30b1ac685e878ae9646`.
The snapshot-on QEMU guest had `-nic none`; before, during, and after the run it
had only `lo`, only loopback routes, and zero listening TCP/UDP sockets. The
guest mounted the candidate read-only with `nosuid,nodev,noexec`. Its nested
container used `--network=none`, a read-only root and source mount, UID/GID
1000, no effective capabilities, `no-new-privileges`, seccomp mode 2, no port
bindings, bounded PIDs/memory/CPU, and private bounded tmpfs work areas. The
focused verifier passed all 39 deliberate mutations; the exact production
module passed all three Rust state tests with zero failures. The complete
focused container took 800,367,522 ns. Candidate hashes were byte-identical
before and after, the guest Docker container and daemon were removed/stopped,
both virtiofs helpers exited, the guest powered off, no QEMU/virtiofs process
remained, host listening endpoints were unchanged, and the retained child
overlay passed `qemu-img check` at 133,111,808 allocated bytes.

An attempted complete root-crate Cargo run reached dependency discovery before
test execution and stopped because this Debian builder has no `libyuv.pc`.
That is verifier-infrastructure incompleteness, not a product-test failure and
not passing evidence. No dependency was downloaded or fabricated to conceal
it. Full root-crate compilation therefore remains open alongside the target-
native platform runs below.

Exact Rust/native compilation and tests, Windows/macOS/Linux platform
execution, physical helper startup/failure/exit reproduction, orphan-process
observation, cold committed R-B2/R-B10 equality, installed artifacts/service
behavior, independent reproduction, R-V3 external review, connection-flow
causation, and sustained correctness/performance/resource evidence remain
explicitly open. The broader user-requested Android task-swipe/reopen/Force-Stop
and Windows focus/minimize/reconnect display-latency reproduction,
capture-through-compositor timestamps, explicit end-to-end
latency/queue/CPU/memory budgets, cross-version behavior, and proof that the
complete connection flow is correct and performant also remain open release
obligations.

### R-S11ho/R-S11e-252 — exact-generation whiteboard client worker ownership

**Status:** SOURCE IMPLEMENTED / CONFINED SOURCE AND MUTATION EVIDENCE
COMPLETE / FOCUSED RUST TESTS AUTHORED BUT UNEXECUTED / EXACT RUST/NATIVE,
PLATFORM, DEVICE, PERFORMANCE, ARTIFACT, AND RELEASE EVIDENCE OPEN.

Read-only continuation review of the adjacent controlled-side whiteboard
launcher found a second, independent lifecycle defect after R-S11hn corrected
the helper process. Every call to `register_whiteboard`, including a duplicate
`show_my_cursor=Yes` for an already-registered authenticated Remote connection,
performed a raw detached `std::thread::spawn`. That thread constructed a nested
current-thread Tokio runtime before discovering that a sender or
`STARTING_WHITEBOARD` flag already existed. An authenticated peer could
therefore drive redundant OS-thread/runtime construction without creating new
whiteboard authority.

The startup flag also covered the worker's complete lifetime, not merely
startup. Once the live worker observed an empty connection map, took the
separately locked global sender, and committed to shutdown, a new registration
could arrive before the old worker returned. Its newly spawned thread observed
the lifetime-wide flag, exited as “already starting,” and discarded its handle;
the old worker then cleared the flag and exited. The new registration remained
in the separate global map with no command sender or worker. Reapplying the
option later could recover it, which is source-level cleanup-mediated recovery
debt. This is shared Windows/macOS/Linux local resource and connection-flow
lifecycle debt. It is not evidence of compromise, exploitation, public
exposure, privilege escalation, host RustDesk/service/firewall/network
modification, or proof that unidentified deployed artifacts exercised the
defect or that it caused the separately reported Android/Windows display-only
delay.

The correction replaces `STARTING_WHITEBOARD`, `TX_WHITEBOARD`, and `CONNS`
with one mutex-owned `WhiteboardClientState`. It holds the registration map,
one exact-generation bounded sender, one retained Tokio task handle, and a
closed `Idle`/`Starting`/`Running`/`Stopping` phase. Idle demand reserves one
checked monotonically increasing generation. Duplicate Starting demand is
included in the eventual atomic registration snapshot; duplicate Running
demand does not launch or bind again; a new Running registration publishes its
exact Bind through that generation's sender. One task runs on the existing
Tokio runtime. The raw OS thread, nested `#[tokio::main]` runtime, detached
handle, lifetime-wide atomic flag, split connection/sender locks, and ad-hoc
cleanup callbacks are deleted.

The runtime-owned task retains its generation and installs
`WhiteboardClientWorkerGuard` as its first action. Returned errors and caught
panics are diagnosed before that finalizer consumes the exact retained task
handle and clears only its exact sender. Sender publication and the initial
registration snapshot occur under the same lifecycle lock. A stale finalizer
cannot mutate another generation. Runtime acquisition or task installation
failure cancels only the exact reserved generation and is visible; it does not
create a fallback thread/runtime.

Idle shutdown now proves the same locked registration map is empty, moves the
exact Running generation to Stopping with no restart request, and takes only
its sender. A registration arriving after that commit latches one successor
request. Finalization rechecks that demand is still live and reserves at most
one successor; removal of the intervening demand cancels that restart. Demand
arriving earlier during Starting or Running remains on the current generation.
Unexpected startup, transport, sender, task, or helper failure moves the
generation to Idle without self-retry. If a new Bind itself observes the
sender closing or saturated, that same explicit registration latches the
single successor edge; background failure or retained registrations alone do
not create a retry/reconnect loop. A later explicit option registration may
reserve a new generation.

The existing 64-command nonblocking queue, 16-registration authority cap,
token-derived endpoint, launch/parent proof, parent-death behavior, typed
deadline writes, and event-only lossy overflow policy remain unchanged.
Required command refusal retires the sender and phase; it is never converted
to blocking admission. The high-frequency cursor path uses fixed two-slot
stack storage and a scoped sender borrow instead of adding a per-event heap
allocation or per-command sender clone. No listener, transport, protocol,
port, service/activity kill, Android foreground-service weakening, timer,
poller, reconnect loop, OS thread, nested runtime, dependency, privilege
transition, or alternate command route is added.

Four deterministic Rust state regressions bind duplicate demand to one
generation, demand crossing committed stop to one successor, startup and
sender failure to no self-retry, and stale-finalizer refusal. The focused
`scripts/verify-whiteboard-client-lifecycle.py` validator parses the exact
phase/generation state, unified owner, existing-runtime task and first-action
guard, failure-versus-demand distinction, fixed-allocation command path,
registration/shutdown/startup interleavings, regressions, shared and Apple
gates, adjacent Linux verifier, requirements/Appendix/ledger identity,
independent workspace binding, and exact requirements hashes. Its deliberate
mutations independently weaken those boundaries. The workspace verifier also
derives the product contract directly and carries separate product, phase,
task, hot-path, regression, gate, requirement, ledger, source-binding, and
dispatch mutations rather than trusting the focused verifier's verdict.

Confined source verification used only the approved immutable verifier image
`sha256:2d178f2785b96dfbf62a416ca2e40f50e30150b4ff3320d706f0d96e90600eb3`
with `--pull=never`, networking disabled, a read-only root and repository, all
capabilities dropped, `no-new-privileges`, numeric UID/GID 1000, bounded
PIDs/memory/swap/CPU, and a bounded private no-exec tmpfs. The focused
whiteboard-client lifecycle verifier rejected all 47 deliberate mutations;
the adjacent Linux nondumpable/CM/PA/whiteboard verifier rejected all 71; the
independent workspace baseline passed; and a narrowed execution through the
real `validate_sources` function rejected all 28 new R-S11ho catalog entries.
On those exact product, gate, verifier, requirement, and digest bytes, one
fresh complete unsliced `--source-mutations-only` execution then ran
uninterrupted from mutation one in exact container `be9dadd446d1`. Docker's
daemon event record reports `execDuration=9851`, `exitCode=0`, the approved
image digest above, and the subsequent expected `--rm` destroy. The unified
terminal handle expired after container exit before returning final stdout, so
no captured terminal-text receipt is claimed. Only that final complete
zero-exit execution is counted as the catalog pass.

Verification was allowed to fail loudly. One initial preflight attempt stopped
before product mutation because a focused-verifier fixture named a stale
string. Two later complete attempts are also uncounted: each correctly
rejected a weakened production owner, first the retained generation-bound task
and then the existing-runtime spawn, but the new catalog entry expected a
broader R-S11ho diagnostic than the earlier whiteboard protocol validator
emitted. The mutation expectations were aligned to those already-enforced,
narrower diagnostics; the same overlap audit also aligned the existing
first-action finalizer and hot-path allocation diagnostics. No production
code, invariant, validator requirement, or mutation was removed or weakened.
The complete 28-entry narrowed pass preceded the final full restart.

The approved verifier image contains Python, shell, and Node but no Rust,
Cargo, rustfmt, Dart, Flutter, or native platform toolchain. No image was
pulled, built, or tagged, and no host Rust command was run. The authored Rust
regressions therefore remain explicitly uncompiled and unexecuted; confined
source and mutation evidence is not represented as native behavior evidence.
No host RustDesk process, configuration, service, listener, port,
firewall/network state, VM, device, or privilege boundary was inspected or
changed by this slice. One broad read-only `docker ps` status query used to
locate the long-running verifier also returned container IDs, image IDs,
status, commands, and names for unrelated running containers, including
Haggai; no unrelated container was entered, signalled, stopped, restarted, or
changed, and no unrelated files, logs, sockets, namespaces, or internal
process state were inspected. Subsequent status queries were restricted to the
exact verifier container ID or approved image.

Exact Rust/native compilation and tests, Windows/macOS/Linux physical
multi-connection/duplicate-toggle/stop-window execution, helper-process
startup and orphan observation, sustained thread/task/queue/CPU/memory and
latency soak, clean committed cold R-B2/R-B10 equality, installed
artifacts/service behavior, fresh independent reproduction, R-V3 external
review, connection-flow causation, physical Android
task-swipe/reopen/Force-Stop and Windows focus/minimize/reconnect reproduction,
capture-through-compositor timestamps, cross-version behavior, and proof that
the complete connection flow is correct and performant remain explicitly open
release obligations and explicit user requests.

### R-S11hp/R-S11e-253 — exact-owner whiteboard presentation and redraw lifecycle

**Status:** SOURCE IMPLEMENTED / FOCUSED RUST TESTS AUTHORED BUT UNEXECUTED /
CONFINED SOURCE AND MUTATION EVIDENCE COMPLETE / EXACT RUST/NATIVE, PLATFORM,
DEVICE, PERFORMANCE, ARTIFACT, AND RELEASE EVIDENCE OPEN.

Read-only continuation review of the whiteboard flow after R-S11hn and
R-S11ho found a third, independent presentation-lifecycle defect. The
authenticated helper converted an authorized connection Close into
`CustomEvent::Clear`, but none of the Windows, macOS, or Linux renderers
handled Clear. If another connection kept the shared helper alive, the
retiring connection's last cursor could therefore remain visible. Click
ripples were stored by window or in one global vector rather than by their
connection owner, with no explicit per-owner admission ceiling, so they could
not be retired with that connection. macOS additionally retained text layouts
by historical `(text, color)` values instead of by the connection whose cursor
needed the layout.

All three renderer event loops also used continuous polling or an equivalent
redraw cycle while idle. macOS requested another display from inside each
draw, creating a self-perpetuating redraw edge. This was avoidable idle CPU/GPU
and presentation-resource debt in the dedicated helper, not remote-display
frame transport. The authenticated wire accepted a generic `CustomEvent`
payload even though Clear and Exit are helper-internal lifecycle decisions,
and each high-frequency cursor update formatted its numeric connection ID into
a heap string before event-loop publication.

Further exact review corrected an overly broad preliminary reading of the
option branch: the old supported disable path already called
`unregister_whiteboard`; it did not strand supported-disable demand. The
narrower option debt was that platform support was computed before both enable
and disable, and an unsupported enable transition did not explicitly retire a
possibly pre-existing registration. The correction moves support probing
inside the enable branch and makes authenticated Remote enable, non-Remote
refusal, unsupported refusal, and disable transitions explicit. No deployed
artifact was inspected, so this source review does not establish which version
or path ran on a user's device.

The corrected wire vocabulary now contains Bind, typed Cursor, Close, and
process Shutdown only. Cursor carries the positive numeric connection ID,
token, and cursor value. Renderer-internal Clear and Exit cannot be named on
the wire. The authenticated helper validates the cursor token before deriving
an internal numeric-owner Cursor action; authorized Close removes the exact
token before deriving internal Clear. A reserved owner value is used only for
terminal Exit. The former formatted cursor-key helper and generic client event
API are deleted. The two cursor producers publish typed Cursor values, use
fixed at-most-two-command storage, and periodically flush into fixed storage
bounded by the existing 16-connection authority rather than allocating a new
vector on each tick.

One shared generic `WhiteboardPresentationState` now owns cursors and click
ripples by positive numeric connection ID. It accepts no more than the
existing 16 active whiteboard owners. Each owner retains one current cursor
and at most 64 active ripples; when full, the oldest ripple is removed before
the next is accepted. Exact Clear removes that owner's cursor and complete
ripple queue and leaves all other owners unchanged. Expired ripple retention
also removes empty owner buckets. Windows, macOS, and Linux all consume this
same owner rather than parallel cursor/ripple containers. macOS keys its
derived text layout by connection ID, rebuilds it only when that owner's text
or color changes, and removes it on exact Clear.

Demand-driven macOS drawing also binds surface retirement across monitor
windows. Before replacing an owner's cursor, the renderer snapshots its prior
window ID. A move to another monitor requests redraw for both the new and
prior windows, so removing perpetual redraw cannot leave pixels on the former
surface. A cursor coordinate owned by no current monitor clears that owner's
cursor, ripples, and text layout and redraws any prior surface instead of
retaining an unmapped last position. Monitor ownership uses half-open logical
rectangles, so the first pixel on an adjacent display is not misassigned to
the preceding window's inclusive right or bottom edge.

Each platform now waits in its native event loop while no animation exists.
Initialization, accepted Cursor, and exact Clear request a redraw. While any
ripple remains, the event loop owns one 16-millisecond deadline. Its
ResumeTimeReached edge first retires expired ripple state, requests a final
clearing frame whenever a ripple existed, and rearms only while active ripples
remain. Drawing also prunes defensively. Suppressed or occluded painting is
therefore not required to stop the deadline after the 500-millisecond ripple
lifetime. Once no ripple remains, the control-flow choice is Wait. The
continuous Poll choices and macOS draw-triggered `setNeedsDisplay` call are
removed. This does not add a timer task, worker, thread, runtime, poller,
retry/reconnect path, alternate session reuse, service/activity kill, Android
foreground-service weakening, listener, transport, port, network behavior,
dependency, privilege transition, or alternate command route.

Two deterministic generic Rust state regressions prove that Clear is exact
and final for the named owner's cursor and all ripples while preserving another
owner, and that total owner admission plus oldest-first per-owner ripple
admission remain bounded. The focused
`scripts/verify-whiteboard-presentation-lifecycle.py` contract derives the
closed IPC vocabulary, option transitions, typed fixed-storage client path,
authenticated internal action derivation, shared state bounds, every platform
renderer, macOS derived-layout lifetime, demand-driven redraw, regressions,
shared and Apple gates, normative requirement, Appendix disposition,
independent workspace binding and dispatch, and exact requirements hashes. Its
self-test deliberately weakens those boundaries. The workspace verifier also
derives the product and platform contract directly and carries separate
product, renderer, behavior, gate, requirement, ledger, focused-verifier,
source-binding, and dispatch mutations rather than trusting the focused
verifier's verdict.

Accepted confined evidence used only the approved immutable image
`sha256:2d178f2785b96dfbf62a416ca2e40f50e30150b4ff3320d706f0d96e90600eb3`
as uid/gid 1000 with no network, a read-only repository bind, a read-only
container root, all capabilities dropped, no-new-privileges, no devices,
ports, host namespaces, Docker socket, image pull/build, root, or persistent
container. Python AST, requirements HTML, requirements-hash bindings, and
shell syntax passed. The whiteboard IPC, whiteboard client, whiteboard
presentation, and Linux nondumpable CM/PA/whiteboard focused suites rejected
their focused weakening cases. The sole approved verifier image has no Rust,
Cargo, rustfmt, Dart, Flutter, or native platform
toolchain, so native compilation and behavior cannot be substituted by that
source-verification environment.

This slice does not inspect, stop, restart, modify, or connect to a host
RustDesk process or service; inspect or change host firewall/network/listener
state; touch an Android device, VM, Haggai/Desktop_Haggai_computer workload, or
unrelated container/image; or request/acquire root. It is source-proven shared
Windows/macOS/Linux whiteboard presentation, resource, and idle-redraw debt.
It is not evidence of compromise, exploitation, public exposure, privilege
escalation, host/service/firewall/network modification, or proof that an
unidentified deployed artifact exercised the defect. Because the separately
reported Android task-swipe/reopen/Force-Stop and Windows focus/minimize delay
affects remote display frames while input control remains immediate, this
helper-overlay correction is not claimed as its cause or fix.

Exact Rust/native compilation and tests, Windows/macOS/Linux physical
multi-connection/toggle/close behavior, idle-versus-animation overlay CPU/GPU
and memory measurement, current physical Android
task-swipe/reopen/Force-Stop and Windows focus/minimize/reconnect reproduction,
capture-through-compositor timestamps, explicit end-to-end
latency/queue/CPU/memory budgets, sustained
connection/reconnect/focus/background/file/control/resource/performance soak,
cross-version behavior, clean committed cold R-B2/R-B10 equality, installed
artifacts/service behavior, fresh independent reproduction, R-V3 external
review, causation, and proof that the complete connection flow is correct and
performant remain explicit release obligations and explicit user requests.

### R-S11hq/R-S11e-254 — exact-generation Android MainService startup transaction

**State.** The exact-generation startup transaction, rollback, retained native
worker, and accepted-connection ownership are implemented in source. The first
2026-09-11 review found that deactivation collapsed “stop requested” and
“worker/runtime inactive” and discarded the worker handle. A follow-up found that
the retained worker still spawned every accepted socket into a detached Tokio
task, reloaded the process-global shutdown token inside `Connection`, and relied
on Android runtime destruction to abort those tasks. Port forwarding could also
ignore service-generation stop until its one-hour idle deadline. The source now
uses one exact worker-generation cancellation parent plus an owned `JoinSet`;
complete Android compilation and native behavior remain unexecuted and
unclaimed.

**Boundary and implementation.** `INACTIVE`, `RESERVED`, `STARTING`, `ACTIVE`,
`STOP_REQUESTED`, and `EXITED` are distinct exact-generation states. Activation
uses a start gate: the worker cannot enter `start_server` until its thread handle
and cancellation parent have transferred into the native owner. Deactivation
records `STOP_REQUESTED` and cancels only that worker's parent; it cannot
authorize generation retirement or replacement. The accept loop owns every
admitted task in one `JoinSet`, eagerly reaps completed tasks, and gives each
connection a child token so listener stop propagates downward while one
connection cannot cancel its listener or siblings. Shutdown leaves admission,
drops the listener, cancels the parent, and joins every admitted task before the
listener generation completes. Authentication, the established session loop,
and the sealed port-forward relay observe that scoped token; `Connection` no
longer reloads ambient process shutdown state. Desktop uses the same ownership
path with its process-scoped parent.

The worker's terminal guard runs only after synchronous `start_server` returns
and its `#[tokio::main]` runtime is destroyed, then publishes one
generation-bound JNI callback. Runtime destruction is the postcondition, not the
normal connection-cleanup mechanism. `MainService` posts reconciliation onto the
Android main looper, retires the retained Kotlin/native plan, and releases a
destroyed Service callback owner only after exact convergence. A later begin
refuses a still-running predecessor and reaps its retained completed handle
before allocating another generation. Reserved-start rollback without a worker
remains immediate. Stale callbacks cannot select a replacement.

The existing startup transaction still keeps the listener inactive until one
positive generation owns screen, status, voice, callback admission, and listener
activation. Failure retains the same Service object, generation, callback
authority, notification, and cleanup plan while blocking replacement; task
removal does not stop the foreground service and Force Stop is not a recovery
mechanism.

**Evidence.** The unchanged dependency-free production lifecycle module's three
Rust 1.75 regressions previously exercised start-before-registration refusal,
stop-request versus inactivity, terminal convergence before replacement, stale
generation refusal, rebuild exhaustion, and thread-creation rollback in a
numeric-nonroot networkless container. The new production `JoinSet` drain test
proves parent-to-child cancellation, child isolation, complete join, and empty
postcondition in code and is wired into `scripts/verify.sh`, but it has **not run**.
Pinned rustfmt 1.75 parsed every touched Rust file; `bash -n`, `git diff --check`,
and the focused Android startup source invariant passed for that historical source. The workspace verifier's five duplicate Android
focused validators, loaders, dispatches, and their uniquely owned mutation
catalog are deleted rather than preserving the retired stop helper and
runtime-abort listener shape. Nine orphaned tuples missed by that deletion are
also absent: three pre-extraction `reserved`/`active` representation mutations,
two obsolete focused-script `--self-test` wiring mutations, and four requirements/
Appendix wording mutations with no semantic consumer. The retained normal
workspace check still observes source structure rather than Android behavior and
is not a reason to restore any superseded lifecycle. The remaining 304-line focused startup checker and its two
shared-script invocations are now deleted: it only matched source strings and did not execute an Android Service,
JNI bridge, callback worker, listener, or cleanup path. The former global mutation catalog was
deleted after its last bounded run produced no verdict before exit 137; it never
supplied Android lifecycle, product, or native evidence.

Two bounded, network-disabled, numeric-nonroot compilation attempts used only
the read-only repository/toolchain/cache plus three ephemeral crates whose bytes
matched the exact `Cargo.lock` SHA-256 values. Linux stopped at the generic
image's missing `gdk-3.0` development metadata; Windows checking stopped at the
absent MSVC `lib.exe`. Neither reached the RustDesk crate, so neither is compile
or test evidence. The roughly 1 GB target and all three temporary archives were
removed. No current JNI, Android framework, emulator, device, or accepted-socket
runtime execution exists yet.

**Open evidence.** Build and install the exact current APK with the pinned
Kotlin/Gradle/NDK closure, inject every startup and retirement failure, and run
task-swipe/reopen/Service-recreation/Force-Stop, reconnect, file, display,
control, capture, port-forward, and audio cases on Android, including stop during
pre-key authentication and each authenticated mode. First run the new Rust test
and compile every affected target. Then prove listener/task/thread/handle/memory/
queue/CPU/latency finality—including stop with live blocking filesystem work—on
the real runtime. Sustained soak, desktop shutdown behavior, cross-version
behavior, signed artifacts, cold R-B2/R-B10 equality, independent reproduction,
and external review remain STOP-SHIP. This source change is not claimed to fix
the separately reported Android task-swipe or Windows focus/display-latency
symptoms, and complete connection-flow correctness and performance remain open.

### R-S11hr/R-S11e-255 — app-open health start and persistent-resource generation transfer

**State.** Source recovery is implemented. Reopening the app while the
foreground service persists now schedules one explicit
`ACT_ENSURE_CONTROLLED_SERVICE` start before passive binding. Scheduling
failure is returned to Flutter, and the health action cannot request or consume
screen-capture consent.

**Boundary and implementation.** An unhealthy committed generation is retired
while it still owns callback authority: controlled admission closes; exact
capture, input, demand, raw-video, reader/surface, and playback-audio state is
retired; and only then do native status/voice owners retire. A coherent
Service-owned `MediaProjection` and callback survive generation replacement.
Android 14+ preserves its policy-permitted `VirtualDisplay` by detaching its
surface; older policy releases it. Mismatched projection/callback state is
discarded. The replacement republishes retained readiness only to its new exact
generation. Each explicit transaction publishes its actual Boolean service
outcome, while `direct-listener-bound` remains the UI's socket truth.

**Evidence.** Source commit
`2fb7d4aaebf8899a347a2c7e7a27f68e9caaf98f` contains the Activity health edge
and transfer ordering. Focused status/listener/raw/voice validators and
the independent source gate bind the current product topology. This is source
evidence only; no current Kotlin/Gradle/JNI build, APK, emulator, or physical
device executed this transaction.

**Open evidence.** Run the exact installed APK through task swipe, reopen,
Service recreation, Force Stop, retained/revoked projection, Android 14 display
reuse, injected cleanup/activation failures, reconnect, and concurrent
file/display/control/audio work. Capture-to-present latency, queue/CPU/memory/
handle cleanup, sustained lifecycle soak, cross-version behavior, cold release
equality, independent reproduction, causation, and external review remain
STOP-SHIP.

### R-S11hs/R-S11e-256 — exact-session X11 empty-Display recovery

**State.** Source recovery is implemented, including the follow-up correction
for X servers that legitimately retain root. Exact native compilation,
installed GDM/Xorg execution, artifacts, independent reproduction, and external
review remain open.

**Boundary and implementation.** The exact selected logind session supplies one
typed `Display` plus canonical `session-<id>.scope`. A nonempty canonical local
display is final; malformed, remote, or unavailable nonempty data fails closed.
Only explicit emptiness admits a bounded `/tmp/.X11-unix` recovery. The
directory must be root-owned and sticky, names must be canonical `X<decimal>`,
the candidate set is capped at 64, each nonblocking connection receives at most
25 ms within one 500 ms total deadline, and exactly one validated display must
remain.

The X-server principal may be the selected UID or root. Supporting root is
required because the supported Xorg wrapper may retain privilege when hardware
access requires it. Pathname owner, `SO_PEERCRED` UID, and credential-PID
process owner must agree exactly. The connected peer must additionally yield a
live `SO_PEERPIDFD`; two bounded cgroup-v2 reads must be identical and terminate
at the selected session's exact scope; and the pathname device, inode, type, and
owner must survive revalidation. Missing kernel support, another UID, owner
mismatch, PID reuse, exit, malformed/changing/deleted/descendant/foreign scope,
timeout, overflow, no match, or ambiguity returns no display. Process-name or
environment endpoint discovery, `w`, Xorg argv, hostname rewriting,
cross-owner pathname trust, and invented `:0` remain absent.

A process-supplied Xauthority path is only a credential hint: it must be
absolute and control-free and come from the same admitted process record as a
display naming the selected X server. Otherwise Xlib uses the selected user's
standard home authority, with only the selected-UID GDM runtime authority file
retained as an explicit fallback.

**Evidence.** The original empty-`Display` implementation is at
`da827ab3ce59372a7fab7e8a6b96b516d77fbb38`. Subsequent review against GDM's
`-displayfd` launch and Xorg's supported root-retaining wrapper mode found and
removed its selected-UID-only availability assumption. Pure regressions cover
typed empty-display scope, canonical names, selected-user/root principal
admission, unrelated-UID refusal, exact terminal scope, and ambiguity. The
focused gate binds the ownership conjunction and legacy-fallback absence. These
checks do not execute Xorg or prove capture.

**Open evidence.** Compile and run the exact current source, then install the
exact Debian artifact in disposable Linux VMs covering both unprivileged Xorg
and root-retaining Xorg, with logind `Display` empty and populated. Admit only
the exact selected session; reject foreign scopes, every pathname/peer/process
ownership mismatch, unrelated UIDs, stale/replaced sockets, dead/reused
peers, unsupported pidfd, and multiple displays. Exercise service restart and
desktop replacement, actual capture and control, and bound discovery/CPU/
memory/descriptor cleanup. Cold R-B2/R-B10 equality, independent reproduction,
and external review remain STOP-SHIP.

`SO_PEERPIDFD` entered upstream Linux in 6.5, while the disposable Debian 12
base is from the 6.1 kernel family unless its package carries a backport. The
supported-kernel matrix must therefore prove the option before this recovery is
shippable. If it is absent, selecting and documenting a minimum kernel or
designing one equally race-free older-kernel authority remains an explicit
decision; numeric-PID inference is not an acceptable silent fallback.

### R-S11ht/R-S11e-257 Linux desktop-selector namespace authority

**State.** The source boundary is present. Exact-current compilation, installed
desktop and service behavior, hostile namespace coexistence, performance and
resource bounds, exact artifacts, independent reproduction, and external review
remain open.

**Boundary.** A selected desktop process may contribute `DISPLAY`,
`XAUTHORITY`, `WAYLAND_DISPLAY`, or `DBUS_SESSION_BUS_ADDRESS` only when
the already-opened process directory has the selected UID and its opened
`ns/mnt` and `ns/net` objects match the supervisor's retained namespace
objects by device and inode. The same UID and both namespace identities are
checked before classification and after the complete bounded environment read.
Missing, inaccessible, foreign, malformed, or changing identity discards the
record. Xwayland presence commits only after the final proof.

The mount namespace is required because filesystem-backed selector paths must
have the same meaning in the eventual child; the network namespace is required
because D-Bus may use abstract Unix sockets or network transports. The
implementation does not substitute process names, PID or namespace-link text,
pathname equality, cgroup membership, or one matching namespace for both.
It enters no namespace and grants no process-control authority.

**Evidence.** Current source retains one bounded process snapshot, descriptor-
relative process and namespace access, exact namespace-object comparison, and
pre/post admission. Rust regressions cover bounded/complete parsing, coherent
service-child identity, current-namespace admission, and independent mount or
network mismatch refusal. The implementation provenance is
`305515a5d0b3941fd564f48185cc8feb45c86162`.

The former 743-line Python verifier and its second mutation-heavy copy in the
workspace verifier were deleted: both inspected source strings and documentary
headings, and neither executed a foreign namespace, an installed service, or a
service child. The live tree retains the Rust regressions and one small
supplementary source guard for the load-bearing pre/post namespace shape. This
is source evidence only.

**Open evidence.** Build and install the exact current Debian artifact in
disposable networkless VMs. Exercise supported supervisors and X11, Xwayland,
and Wayland sessions with stable same-namespace selector processes plus
same-UID processes whose mount namespace, network namespace, both namespaces,
or identity during observation differ. Prove correct child environment and
desktop selection, Xwayland publication ordering, bounded scan time, CPU,
memory, and descriptors, service/child restart and cleanup, and noninterference
with unrelated instances. Cold R-B2/R-B10 equality, independent reproduction,
and external review remain STOP-SHIP.

### R-S11hu/R-S11e-258 — atomic exact-owner outgoing viewer-session registry

**State.** The source design is present. Exact-current generated-bridge/native execution, cross-platform concurrency, installed-artifact, performance/resource, independent-reproduction, and external-review evidence remain open.

**Boundary and current implementation.** `SESSIONS` is the process-wide outgoing viewer registry shared by Android, iOS, Linux, macOS, Windows, and the web-authored bridge. `sessions::insert_session` holds one global write guard from the global connection-UUID uniqueness check through vacant handler admission and returns the actual installed peer `Arc`; it does not publish ambient last-peer state before admission succeeds. `sessions::remove_session_by_exact_ui_owner` requires `(connection UUID, client-owner UUID)` and holds the same global write guard through handler removal and possible peer removal. For a nonempty surviving display union, exact and bulk retirement now reserve the bounded capture-shrink command and commit handler/RGBA removal while its slot is invisible. If derivation or command admission fails, the round is invalid or already terminal, so the same transaction evicts the peer and every handler; displaced-handler notification and peer `close_and_join` remain outside the registry lock. A successful non-last close preserves the peer, a last close returns the exact peer, and failed-start rollback uses the same primitive. Rust FFI, the three authored Dart close paths, and web parity carry both identities.

**Evidence.** Source inspection confirms the single-write-guard admission and retirement paths in `src/flutter.rs`, reserve-before-commit capture shrink through `src/ui_session_interface.rs`, exact-owner finality in `src/flutter_ffi.rs::session_close`, and dual-identity close propagation in `flutter/lib/models/model.dart` and `flutter/lib/web/bridge.dart`. The retained Rust regressions exercise installed-versus-candidate `Arc` identity, global duplicate refusal, wrong-owner refusal, admitted non-last capture shrink, last-peer return, and exact plus bulk terminal-round eviction. The standalone source-shape parser and its verifier-of-verifier coupling are deleted; compiled behavior regressions and the ordinary focused cross-language checks are the maintained evidence.

**Open evidence.** Run the exact-current compiled `r_s11hu_` regressions and generated bridge, then exercise concurrent same-peer attach/close and stale-callback races on each supported native client. Physical Android task-swipe/reopen/Force-Stop and Windows focus/minimize/reconnect reproduction, capture-through-presentation timestamps, latency/queue/CPU/memory/handle budgets, sustained connection/file/control/resource soak, signed installed artifacts, clean cold R-B2/R-B10 equality, independent reproduction, external review, field causation, and proof of the complete performant connection flow remain release obligations.

### R-S11hv/R-S11e-259 — orphaned viewer close-prediction surface excision

**State.** The non-authoritative close-prediction surface is absent from current source. Exact generated-bridge/native compilation and cross-platform close/concurrency execution remain open.

**Boundary and current implementation.** Viewer retirement has one authority: the R-S11hu exact-owner close transaction. Rust has no `would_remove_peer_by_exact_ui_owner`, native FFI has no `will_session_close_close_session`, and the web bridge has no `willSessionCloseCloseSession`. Current callers need no prediction; any future disposition must be returned atomically by the close transaction rather than read before it.

**Evidence.** Source inspection confirms the prediction symbols are absent while `remove_session_by_exact_ui_owner` still checks both identities and returns the last installed peer for finality outside the registry lock. The focused source gate and independent workspace check enforce that current source shape; they are supplementary to, not substitutes for, the retained Rust registry regressions and native execution.

**Open evidence.** Compile the exact generated bridge and execute close/attach races across Android, iOS, Linux, macOS, Windows, and web. Installed artifacts, sustained lifecycle/resource soak, cold release equality, independent reproduction, and external review remain open.

### R-S11hw/R-S11e-260 — exact Windows service-owned RDP-policy requester role

**State.** Source implementation is present and focused source checks cover the exact requester
role and retained-authority conjunction. Exact-current native Windows execution, installed-service
behavior, artifacts, independent reproduction, and external review remain open.

**Boundary and current implementation.** The LocalSystem service owns the installed-machine RDP
sharing policy. `authorize_windows_service_owned_share_rdp_requester` retains the pipe-reported
process handle and generation, immutable executable/argv identity, and a complete live token proof
that exactly matches the named-pipe impersonation token. It admits only an elevated current
canonical executable with no arguments. Its consuming commit repeats pipe PID, process liveness and
creation time, fresh identity, canonical executable, exact role, pipe/process token equality, and
elevation immediately before `set_service_owned_share_rdp`, which is the capability's final action.
Uncertain or changed evidence returns `ShareRdpSet { accepted: false }` without the HKLM write.

**Evidence.** Direct inspection confirms the handler cannot call the writer outside the retained
requester capability, the detached elevation-only helper is absent, and the Windows-only Rust role
regression accepts the no-argument UI while rejecting server, service, tray, connection-manager,
password, and unknown roles. Focused and independently implemented source checks preserve those
invariants. They are supplementary source evidence, not a native Windows or deployed-artifact result.

**Open evidence.** Run the exact candidate in a disposable Windows VM against an installed SCM
LocalSystem service and the real settings-page request. Exercise authorized UI, every rejected role,
non-elevated and mismatched tokens, client exit, PID/process-generation churn, pipe-owner change, and
the race immediately before commit; prove the HKLM value changes only for the authorized generation
and measure handle/process cleanup. No repository-owned Windows golden disk or live user-session
libvirt socket was available during this source-ledger cleanup, so no native verdict is claimed.
Clean R-B2/R-B10 artifact equality, independent reproduction, sustained performance/resource
evidence, and R-V3 external review also remain open.

### R-S11hx/R-S11e-261 — exact Linux service-owned password requester role

**State.** Source implementation is present and focused source checks cover the exact-role and
post-polkit replay invariants. Exact-current Linux native execution, installed-service behavior,
performance/resource evidence, release artifacts, independent reproduction, and external review
remain open.

**Boundary and current implementation.** The root `_service_password` listener derives PID and UID
from `SO_PEERCRED` before reading a secret, requires root or the freshly resolved active user and
the current canonical executable, and retains PID, UID, start time, complete argv, and applicable
launch ancestry. `PeerProcessIdentity` redacts argv contents from `Debug`. Admission permits only
the no-argument UI, `--password`, or `--password-stdin`; all other or malformed roles fail closed.
The listener replays the complete identity before dispatch. After the bounded fixed-action
`pkcheck` succeeds, the password admission path again requires the same live complete generation
and finite role before the service-owned credential ledger may accept the operation.

**Evidence.** Current source inspection finds the retained identity and role checks in
`src/ipc/auth.rs`, pre-body admission and retained dispatch in `src/ipc.rs`, and the final
post-polkit replay immediately before typed ledger admission. The focused Linux password verifier
and its finite-role Rust regression protect those source invariants; they are supplementary source
evidence, not native polkit or installed-service proof.

**Open evidence.** Compile and execute the exact current Linux tests; exercise real polkit allow,
deny, timeout, shutdown, PID reuse, argv change, role refusal, and all three admitted clients in an
installed disposable Linux VM; verify durable credential behavior across service restart; measure
latency, CPU, memory, handles, task bounds, and cleanup; prove clean cold R-B2/R-B10 artifact
identity; obtain independent reproduction and R-V3 external review.

### R-S11hy/R-S11e-262 — exact macOS service-owned password requester generation and role

**State.** Source implementation is present and focused/shared source checks cover retained
audit-token generation, complete-role admission, final replay, and the stated XNU limitation.
Signed native macOS, installed LaunchDaemon, race, resource/performance, release-artifact,
independent-reproduction, and external-review evidence remain open.

**Boundary and current implementation.** Before task transfer or secret read, the
`_service_password` listener snapshots socket UID, effective PID, and full `LOCAL_PEERTOKEN`;
the token's embedded effective UID and PID must exactly match the separate socket values and PID
must be nonzero. The full audit token, including PID-version, and complete argv are retained.
One bounded Security.framework proof requires root or the fresh console user, the exact signed
installed-app generation and trusted layout, and only no-argument UI, `--password`, or
`--password-stdin`. Audit-token generation proofs bracket PID-based argv capture.

After the complete request and Authorization Services capability succeed, the receiver re-proves
fresh UID authority, installed-app generation/layout, complete argv equality, finite role, and
generation finality, then requires a fresh stream UID/PID/full-token snapshot to equal the accepted
requester before transferring password ownership. That socket replay proves only current-last-owner
consistency: it rejects visible mismatches and a currently different accessor, but it does not prove
exclusive frame authorship or every descriptor handoff because ordinary XNU socket activity can
restore the retained process as last owner.

**Evidence.** Current source inspection finds fail-closed socket/token construction and exact-role
admission in `src/ipc/auth.rs`, retained pre-task dispatch and the post-capability requester replay
in `src/ipc.rs`. Focused, shared, and Apple structural checks cover these source relationships and
the limitation; none is a signed native macOS execution.

**Open evidence.** Compile and execute the exact signed candidate on macOS; run Authorization
Services allow/deny, audit-token/PID-reuse/argv, descriptor-sharing, and last-owner-restoration
races; exercise installed LaunchDaemon behavior for all three admitted callers and refused roles;
measure authorization latency, CPU, memory, handles, bounded work, and cleanup; prove cold
R-B2/R-B10 artifact identity; obtain independent reproduction and R-V3 external review.

### R-S11hz/R-S11e-263 — exact macOS password-right readiness requester authority

**State.** Source implementation is present and focused/shared source checks cover retained
requester authority and policy-write-last ordering. Signed native macOS, installed-service, race,
resource/performance, release-artifact, independent-reproduction, and external-review evidence
remain open.

**Boundary and current implementation.** `EnsurePasswordRightReady` is treated as privileged
because it invokes `AuthorizationRightSet`. Generic macOS `_service` admission retains the
accepted UID/effective-PID/full-token snapshot across task transfer. Only the readiness action adds
the exact endpoint, fresh console/root UID, signed installed-app generation/layout, and complete
no-argument UI, `--password`, or `--password-stdin` role proof. After request decode, a fresh
snapshot must exactly match the retained requester. One bounded proof then replays installed
identity, complete argv, finite role, and audit-token generation, with
`AuthorizationRightSet` as the final conjunct. Generic liveness, a stale role, a bare PID, or a
disjunction cannot authorize the write. The post-request snapshot has R-S11hy's current-last-owner
limitation and is not exclusive frame or descriptor-handoff proof.

**Evidence.** Current source inspection finds pre-task authorization retention and typed dispatch in
`src/ipc.rs`, exact action admission and snapshot equality in `src/ipc/auth.rs`, and the final
short-circuiting policy-write action in `MacosServiceOwnedPasswordRightAdmission::ensure_ready`.
Focused/shared/Apple checks protect those source relationships; they do not execute
Authorization Services on macOS.

**Open evidence.** Compile and run the exact signed candidate on macOS; exercise real
`AuthorizationRightSet`/`AuthorizationRightGet` allow-deny behavior, requester and descriptor
races, all admitted roles and refusals, installed LaunchDaemon policy state, repeated-operation
cleanup, latency, CPU, memory, and handles; prove cold R-B2/R-B10 artifact identity; obtain
independent reproduction and R-V3 external review.

### R-S11ia/R-S11e-264 — exact macOS service-owned credential requester generation and response finality

**State.** Source implementation is present and focused/shared source checks cover accepted
generation retention, launchd-bound role replay, and PRS-load ordering. Signed native macOS,
installed LaunchDaemon/LaunchAgent, race, resource/performance, release-artifact,
independent-reproduction, and external-review evidence remain open.

**Boundary and current implementation.** Before task transfer, the bodyless
`_service_credential` listener retains the accepted UID, effective PID, and full
`LOCAL_PEERTOKEN`; generic bounded proof returns that exact snapshot rather than a Boolean.
The action proof requires the exact endpoint, fresh root/current-console authority, the live signed
installed-app generation and trusted layout, exact `--server --service-owned-server` argv, and a
trusted LaunchAgent record whose top-level PID and plist path match the requester. Complete argv is
retained across the bounded `launchctl` query, then installed generation, process name/liveness,
argv equality, and finite role are replayed.

Immediately before PRS access, the handler requires a fresh exact endpoint/UID/effective-PID/full-
token snapshot to equal the retained requester. Only the resulting admission may load and send the
operation-bound runtime PRS replica. The final snapshot is current-last-owner consistency, not
exclusive request authorship or complete descriptor-handoff proof. The response remains deadline-
and-capacity-bounded, root-sourced, operation-bound, and nonpersistent at the child.

**Evidence.** Current source inspection finds the retained authorization in the macOS credential
listener, action-specific launchd proof and post-query replay in `src/ipc.rs` and
`src/ipc/auth.rs`, and PRS access only after `MacosServiceOwnedCredentialRequester::admit`.
The focused macOS credential verifier and shared/Apple checks protect these source relationships;
they are not installed macOS execution.

**Open evidence.** Compile and execute the exact signed candidate on macOS; exercise
audit-token/PID-reuse/argv/descriptor-sharing and launchd-state races, malformed/changed requesters,
installed LaunchDaemon-to-LaunchAgent replica exchange, operation binding, restart behavior,
latency, CPU, memory, handles, and cleanup; prove cold R-B2/R-B10 artifact identity; obtain
independent reproduction and R-V3 external review.

### R-S11ib/R-S11e-265 — retained Windows RDP-policy requester through final mutation

**State.** Source implementation is present and the Windows-only exact-role regression remains.
Dedicated requester-capability and installed policy-mutation evidence is missing; native Windows,
adversarial race, resource/performance, release-artifact, independent-reproduction, and
external-review evidence remain open for this action.

**Boundary and current implementation.** `authorize_windows_service_owned_share_rdp_requester`
returns `WindowsServiceOwnedShareRdpRequester`, not a Boolean. It owns the opened process handle,
creation-time generation, fresh executable/complete-argv identity, and equal accepted pipe/process
token proof for the elevated no-argument UI. Its consuming commit rechecks pipe PID, retained-handle
liveness and creation time, fresh identity/current executable/exact role, fresh equality of both
token sources to the accepted elevated proof, then repeats stable PID and liveness. The current-
product 64-bit HKLM writer is the final action while the process handle remains owned; the handler
cannot call it directly.

The Win32 evidence provides connected-process and last-message consistency, not proof that a pipe
handle was never inherited or duplicated or that one process authored every byte. Every visible
PID, generation, executable, argv, token, elevation, role, or liveness change still fails closed.

**Evidence.** Current source inspection finds the capability, retained process/token fields, full
admission and final replay in `src/ipc/auth.rs`, and capability-only dispatch in `src/ipc.rs`.
`ipc::ipc_auth::tests::windows_service_owned_share_rdp_client_role_is_exact_interactive_ui` executes
the finite role predicate only on Windows. It does not exercise process retention, revalidation,
named-pipe impersonation, or the final registry mutation. The deleted combined Python checker only
matched source text and was not an installed SCM transaction through the real settings page.

**Open evidence.** Compile and run the exact candidate in a disposable Windows VM; exercise the
real settings-page request against an installed LocalSystem SCM service with allowed/denied actors,
process exit and PID reuse, token/argv/image changes, pipe-handle inheritance/duplication, and
registry-write observation; measure latency, CPU, memory, handles, and cleanup; bind signed
artifacts, prove cold R-B2/R-B10 identity, and obtain independent reproduction and R-V3 external
review.

### R-S11ic/R-S11e-266 — retained Windows service-main supervisor authority through exact actions

**State.** Source implementation and the closed-protocol wire regression are present. Dedicated
current installed supervisor-authority and protected-action evidence is missing. Native Windows,
adversarial race, resource/performance, release-artifact, independent-reproduction, and
external-review evidence remain open.

**Boundary and current implementation.** The SYSTEM-only `_service_credential` and
`_service_main_control` listeners construct distinct `WindowsServiceCredentialRequester` and
`WindowsServiceControlRequester` capabilities around a private retained supervisor requester.
Admission owns the opened synchronized process handle and creation time, fresh executable/complete
argv, equal independent pipe and process LocalSystem token proofs, exact launch-bound supervisor
PID/generation, fixed service image, exact `--service` role, liveness, and stable pipe PID. The
endpoint capability moves into its bounded transaction and remains owned across request-read
`await`; cached identity, a post-read Boolean, or cross-endpoint authority is unavailable.

Immediately before credential quiesce/apply/query/resume or port-forward session count, the
consuming capability revalidates pipe PID, process liveness/generation, fresh executable/argv,
fixed-image role, and both live token proofs against the accepted LocalSystem proof, then repeats
PID and liveness with the protected operation last. Handlers do not name the protected replica,
connection registry, or shutdown latch. Shutdown first consumes control authority into a prepared
capability, retains it across the bounded `ShutdownAccepted` write, and repeats complete
revalidation before the latch; failed acknowledgement or replay performs no shutdown. These checks
provide connected-process and last-message consistency, not exclusive byte authorship or complete
pipe-handle-handoff detection.

**Evidence.** Current source inspection finds the distinct capability types, retained shared proof,
admission, and common revalidation in `src/ipc/auth.rs`; listener ownership across await and
capability-only action dispatch are in `src/ipc.rs`. The retained executable R-S11hg regression
proves closed wire deserialization only. It cannot prove LocalSystem authorization, launch-bound
supervisor identity, capability lifetime across `await`, protected-action ordering, or
post-acknowledgement replay. The deleted Python checker executed none of those properties.

**Open evidence.** Compile and run the exact candidate in a disposable Windows VM; exercise real
installed LocalSystem credential/control exchanges with authorized and wrong principals,
PID/process/token/argv/image changes, pipe-handle inheritance/duplication, request failure,
acknowledgement failure, shutdown replay failure, service restart, and replica state transitions;
measure latency, CPU, memory, handles, queues, and cleanup; bind signed artifacts, prove cold
R-B2/R-B10 identity, and obtain independent reproduction and R-V3 external review.

### R-S11id/R-S11e-267 — typed macOS service-owned password authority through ledger admission

**State.** The source implementation is present. Exact-current signed macOS, installed-service,
performance/resource, release-artifact, independent-reproduction, and external-review evidence remains
open.

**Boundary and current implementation.** The bounded Security.framework path grants one private,
non-cloneable `MacosServiceOwnedPasswordAdmission` only after the exact right, imported external
authorization, and installed-app requester generation/argv/role succeed. Its consuming preparation
revalidates the operation/value, requester, and post-request stream UID/effective PID/full audit token,
then calls the capability-typed coordinator. There is one capability construction and one
capability-owned coordinator call. Only an owned new `Prepared` transition retains the secret and
reaches the mutation handler; replay/status is a separate secret-free result. After `Prepared`, the
root service owns commit, recovery, replay, drain, and failure finality without depending on requester
survival. The stream replay proves current-last-owner and process-generation consistency, not exclusive
frame authorship or absence of descriptor sharing.

**Evidence.** The current call graph is anchored by
`grant_macos_service_owned_password_admission`,
`MacosServiceOwnedPasswordAdmission::prepare_mutation`, and
`PasswordMutationCoordinator::prepare_macos_service_owned` in `src/ipc.rs`. The focused password
IPC verifier, shared/Apple analyzers, and independent workspace validator contain guards for typed
grant, sole construction/call sites, exact replay ordering, secret-free status handling, and
Boolean/direct-handler bypass absence. R-S11id and Appendix C #389 specify the same boundary. These
source contracts do not constitute native macOS evidence.

**Open evidence.** Compile and execute the exact signed candidate on macOS; exercise Authorization
Services allow, deny, expiry, replay, and cleanup; attack audit-token/PID/argv/descriptor-sharing races;
run every legitimate and refused role against the installed LaunchDaemon; measure latency, CPU, memory,
handles, and cleanup; prove clean cold R-B2/R-B10 artifact equality; obtain independent reproduction and
R-V3 external review.

### R-S11ie/R-S11e-268 — typed Linux post-polkit password authority through ledger admission

**State.** The source implementation is present. Exact-current Linux native/unit, real-polkit,
installed-service, performance/resource, release-artifact, independent-reproduction, and external-review
evidence remains open.

**Boundary and current implementation.** Successful bounded `pkcheck` plus exact post-authorization
requester replay grants one private, non-cloneable `LinuxServiceOwnedPasswordAdmission` retaining the
complete socket-derived `PeerProcessIdentity`. Its consuming `admit_commit` validates operation and
value, freshly replays that requester, and is the sole caller of the coordinator transition requiring
the typed admission. The coordinator rederives the caller and exact-matches service-owned kind, keyed
fingerprint, caller, and `Authorizing` before `Committing`. Denial can cancel only the exact matching
pre-admission claim. `Committing`, `Recoverable`, and `Complete` work remains service-owned and is
never cancelled or reauthorized merely because the requester exits.

**Evidence.** Current `src/ipc.rs` contains
`grant_linux_service_owned_password_admission`,
`LinuxServiceOwnedPasswordAdmission::admit_commit`,
`LinuxPasswordAdmissionCoordinator::admit_authorized`, and exact pending-claim cancellation. The
focused password IPC verifier and shared/Apple/independent analyzers bind non-cloneability, sole
construction/call sites, operation/value/requester replay, exact transition/cancellation, detached
Boolean absence, and post-admission finality. R-S11ie and Appendix C #390 define the corresponding
contract. These source contracts do not establish native polkit or installed-service behavior.

**Open evidence.** Compile and run exact-current Linux tests; execute real polkit
allow/deny/timeout/shutdown paths; attack PID/UID/start-time/argv/generation races; run the installed
service with authorized and unauthorized local principals; measure latency, CPU, memory, handles, and
cleanup; prove clean cold R-B2/R-B10 artifact equality; obtain independent reproduction and R-V3
external review.

### R-S11if/R-S11e-269 — typed Windows named-pipe password authority through user/service admission

**State.** The source implementation is present. Exact-current Windows native/unit, installed
LocalSystem/user endpoint, UAC/race, performance/resource, release-artifact, independent-reproduction,
and external-review evidence remains open.

**Boundary and current implementation.** The raw message-mode named-pipe listener uses endpoint-specific
DACL/security and retains the complete process, immutable identity, process-token, impersonated-pipe-
token, endpoint, generation, liveness, and deadline proof through full frame validation. A private typed
sender derives the endpoint and consumes that proof into a non-cloneable user-owned or service-owned
admission carried through the bounded queue. The user entry and shutdown disposition consume user
admission and fix the action; receiver-derived local eligibility/policy may further deny it but is not
requester authority. Service replay/shutdown queries borrow service admission, while fresh keyed
`Active` insertion consumes it. After `Active`, LocalSystem owns persistence, child convergence,
replay, drain, and finality without retaining a stale process handle. There is no public generic
postfix/request pairing or cross-action fallback.

**Evidence.** The current typed transport and endpoint derivation are in
`src/platform/windows.rs` (`WindowsUserOwnedPasswordRequest`,
`WindowsServiceOwnedPasswordRequest`, and `WindowsSensitivePasswordRequestSender`); final consuming
mints are in `src/ipc/auth.rs`; admissions and ledger entry points are in `src/ipc.rs`. Focused,
shared, Apple, independent-workspace, and native-build gate definitions cover final proof replay,
endpoint/type pairing, queue retention, consumer signatures, fresh admission, and generic/direct bypass
absence. R-S11if and Appendix C #391 define the same boundary. These source contracts are not Windows
native or installed-service evidence.

**Open evidence.** Compile and execute the exact candidate in a disposable Windows VM; exercise
installed LocalSystem and user endpoints, UAC allow/deny, timeout/shutdown, wrong endpoint, wrong token,
PID/process-generation/identity/endpoint/process-exit races, retry, crash recovery, and cleanup; measure
latency, CPU, memory, handles, and queue bounds; prove clean cold R-B2/R-B10 artifact equality; obtain
independent reproduction and R-V3 external review.

### R-S11ig/R-S11e-270 — typed Linux service-owned credential authority through operation-bound PRS response

**State.** The source implementation is present. Exact-current Linux native/unit, installed-service,
adversarial identity-race, performance/resource, release-artifact, independent-reproduction, and
external-review evidence remains open.

**Boundary and current implementation.** The fixed `_service_credential` listener authenticates the
exact current `--server --service-owned-server` child into one private, non-cloneable requester
retaining complete `PeerProcessIdentity` before reading the bodyless request. Its consuming admission
repeats the fixed executable/argv/direct-parent/launch-parent/runtime-generation proof, requires complete
identity equality, and binds the wire UUID. Only the consuming admission may read
`service_owned_runtime_prs_replica("Linux")` and send it under that UUID. The handler cannot name the
generic proof, PRS reader, or raw writer; the postfix-selectable proof is parent-module-private.

**Evidence.** `LinuxServiceOwnedCredentialReplicaRequester::authenticate` and `::admit`, plus
`LinuxServiceOwnedCredentialReplicaAdmission::respond`, form the current sole path in `src/ipc.rs`.
The focused Linux password/credential gate and shared/Apple/independent validators bind fixed-endpoint
construction, non-cloneability, retained identity, consuming final replay, sole admission construction,
operation binding, protected read/write ownership, proof visibility, and handler-bypass absence.
R-S11ig and Appendix C #392 define the same action boundary. These source contracts are not
installed-service or native race evidence.

**Open evidence.** Compile and execute exact-current Linux tests; run installed-service exchanges and
adversarial PID/start-time/UID/executable/argv/direct-parent/launch-parent/runtime-generation/socket
races; test malformed/trailing requests, child exit, response failure, and cleanup; measure latency,
CPU, memory, handles, and bounded resources; prove clean cold R-B2/R-B10 artifact equality; obtain
independent reproduction and R-V3 external review.

### R-S11ih/R-S11e-271 — typed Linux root-to-child runtime PRS writer authority

**State.** The source implementation is present. Exact-current Linux native/unit, installed-service,
adversarial identity-race, performance/resource, release-artifact, independent-reproduction, and
external-review evidence remains open.

**Boundary and current implementation.** After durable service-owned password persistence, the root
service rereads a distinct non-cloneable `ServiceOwnedRuntimePrsReplica`; plaintext cannot be
reclassified as that type. A typed main-completion request selects user-owned behavior or Linux
service-owned convergence without a caller-supplied mode Boolean. Only root in the exact `--service`
supervisor role may mint a non-cloneable writer by selecting the current child UID, deriving that UID's
fixed `_password` endpoint, and retaining the connected stream plus complete proved child identity.
The consuming begin method freshly replays role and identity, accepts only the typed PRS, uses the same
operation UUID for request and response, and preserves `NotSent` versus `Uncertain`; admitted
uncertainty remains in bounded recovery/finality. The ordinary connector contains no service-owned
routing or proof.

**Evidence.** Current `src/ipc.rs` separates `ServiceOwnedRuntimePrsReplica`,
`MainPasswordMutationRequest`, `LinuxServiceOwnedPasswordReplicaWriter`, and
`LinuxServiceOwnedPasswordReplicaAttempt`; the only service convergence path consumes the typed writer
and borrows the typed PRS. Focused/shared/Apple/independent gate definitions cover exact root role, UID
and fixed path, retained child identity, final replay, same UUID, uncertainty, generic-route absence,
typed call sites, and plaintext separation. R-S11ih and Appendix C #393 carry the same contract. These
source contracts do not prove installed-service behavior or native resource bounds.

**Open evidence.** Compile and execute exact-current Linux tests; run the installed root
supervisor/active-user child and adversarial PID/start-time/UID/executable/argv/direct-parent/
launch-parent/runtime-generation/socket races; inject connect/pre-send/send/response uncertainty and
observe recovery/finality; measure latency, CPU, memory, handles, and cleanup; prove clean cold
R-B2/R-B10 artifact equality; obtain independent reproduction and R-V3 external review.

### R-S11ii/R-S11e-272 — typed Linux child-side runtime PRS receiver authority

**State.** The source implementation is present. Exact-current Linux native/unit, installed
root-service/active-user-child, adversarial parent-race, replay/finality, performance/resource,
release-artifact, independent-reproduction, and external-review evidence remains open.

**Boundary and current implementation.** Only the exact service-owned child role may create a
non-cloneable receiver for the fixed `_password` endpoint. It retains kernel socket PID/UID plus
`/proc/<pid>/stat` start time after requiring UID 0, socket/proc UID equality, and launch-parent/live
direct-parent equality. Ptrace-gated root executable/argv inspection is deliberately not substituted
for that kernel/direct-parent proof. A typed authority carries the receiver; its kind projection only
classifies capacity. After full canonical request validation, consuming admission freshly replays child
role and the complete root-parent generation. The ledger consumes that admission with a typed
`ServiceOwnedRuntimePrsReplica`; a dedicated bounded worker alone installs it through the runtime-only
sink. The generic password worker remains durable-store-only. Parent survival is required through
pre-ledger admission, while the child owns replay, completion, shutdown drain, and failure finality
after irreversible preparation.

**Evidence.** The current path is expressed by
`LinuxServiceOwnedPasswordReplicaReceiver`,
`SensitiveMainPasswordAuthority::ServiceOwnedRuntimePrs`,
`LinuxServiceOwnedRuntimePrsAdmission`,
`begin_linux_service_owned_runtime_prs_mutation`, and the dedicated runtime worker in `src/ipc.rs`.
Focused/shared/Apple/independent gates bind retained parent generation, initial/final role and endpoint,
consuming admission and ledger inputs, typed worker/sink, fixed action kind, and durable-worker
separation. R-S11ii and Appendix C #394 define the same boundary. These source contracts do not prove
native installed-service, race, or resource behavior.

**Open evidence.** Compile and execute exact-current Linux tests; run the installed root parent and
active-user child with authorized and unauthorized principals; attack parent exit, PID reuse, UID/PPID,
launch-parent, socket, malformed/trailing input, replay, shutdown, and error-finality cases; measure
latency, CPU, memory, handles, and cleanup; prove clean cold R-B2/R-B10 artifact equality; obtain
independent reproduction and R-V3 external review.

### R-S11iw/R-S11e-286 — exact software-RGBA event-stream replacement

**SOURCE IMPLEMENTED; TWO EXECUTABLE RUST REGRESSIONS RETAINED AND DIRECTLY WIRED;
SOURCE/MUTATION THEATER DELETED; EXACT GENERATED-BRIDGE, TARGET-RUNTIME,
PRESENTATION, PERFORMANCE, ARTIFACT, AND REVIEW EVIDENCE OPEN.**

One exact connection session, UI owner, replacement transaction, display, and checked publication
token own each handoff. `session_start_` retains the worker and exact handler-owner guards through
stream replacement. `rearm_rgba_for_stream_replacement` holds the mailbox write guard, rotates
every live exact-session publication to a fresh checked token, promotes only the newest pending
frame, bounds and canonically sorts at most 16 displays, and posts to the supplied stream before a
predecessor acknowledgement can interleave. Exhaustion, excess state, or post refusal retires only
that exact session and fails visibly; unrelated sessions remain intact.

The directly wired `r_s11iw_stream_replacement_*` Rust regressions exercise fresh-token rotation,
latest-pending promotion, predecessor copy/acknowledgement refusal, unrelated-session preservation,
and exact-session refusal cleanup. They do not execute a generated bridge, Flutter event stream,
target renderer, Android Activity/service lifecycle, Windows window transfer, or compositor.

Exact-current generated-bridge and target-artifact scenarios remain STOP-SHIP: replace a live stream,
delay predecessor completion, observe successor pixels and predecessor inactivity, and verify
bounded latency, CPU, memory, handles/tasks, and cleanup across Android task-swipe/reopen/Force-Stop,
Windows focus/minimize/window transfer, other supported platforms, and reconnect soak. Cross-version
behavior, cold R-B2/R-B10 equality, independent reproduction, causation, and external review remain
open.

### R-S11iz/R-S11e-289 — exact Linux headless CM readiness handshake finality

**State:** source implemented; native installed behavior and release evidence open.

**Boundary and current implementation.** One controlled-side Linux headless
connection and its exact connection-manager bootstrap task share one sampled
headless decision and two Linux-only Tokio one-shot channels. The desktop signal
is a nonblocking wake hint. After authenticated CM stream and exact peer
establishment, the bootstrap task must publish the positive result successfully.
The connection consumes that result once under its finite deadline; only the
positive result permits peer login success. Sender loss, timeout, a missing
endpoint, or repeated consumption fails the exact connection with the existing
desktop-session-not-ready result. Non-Linux builds own no dummy endpoint for this
protocol. No fallback, retry, reconnect path, second state replica, or unbounded
wait exists.

**Evidence.** Deterministic regressions in `src/server/connection.rs` cover wake,
owner closure, receiver preservation across the bounded state recheck, positive
readiness, sender loss, and timeout. `scripts/verify.sh` checks the production
topology and login ordering; `scripts/apple-conform-check.sh` checks non-Linux
exclusion; the workspace verifier independently checks the product topology and
ordering. Historical commands and raw receipts remain in Git history.

**Open evidence.** Exact Rust/native execution, installed Linux headless login and
CM-failure behavior, live desktop-transition races, complete file/control/display
transactions, cross-version behavior, explicit latency/queue/CPU/memory bounds,
sustained lifecycle/resource soak, signed artifacts, clean cold R-B2/R-B10
equality, independent reproduction, causation, external review, and proof that
the complete connection flow is correct and performant remain STOP-SHIP.

### R-S11ja/R-S11e-290 — exact Android MainService callback-thread finality

**State:** source corrected; Android compile, installed lifecycle behavior, and release evidence open.

**Old path and boundary.** The inherited `MainService` started one `HandlerThread` for `ImageReader` and
`MediaProjection` callbacks but retained only its `Looper`. Destruction called `quitSafely()` and immediately
discarded the handler/looper references. Android defines safe quit to process every already-due queued message,
and quit does not join the underlying thread. `onDestroy()` could therefore return and permit a replacement
Service generation while an exact predecessor callback was queued or still executing. This is a direct
resource-finality defect; it is not evidence that the deployed Android symptom followed this path.

**Current implementation.** The Service owns the exact `HandlerThread` and handler. Native generation
initialization fails before reservation if either is absent or the thread is dead. After controlled capture,
projection, raw-video, and audio state retires, teardown clears both publication references, requests immediate
queue termination with `quit()`, and joins that exact thread until it is dead. An interrupt is recorded rather
than escaping the join and is restored only after terminality. Native generation retirement and callback-owner
release occur afterward, so no replacement can overlap a predecessor callback worker through normal lifecycle
completion. A healthy Service-owned worker and projection remain across ordinary listener-generation repair. If
the worker is dead or incoherent, the health transaction instead releases projection state, joins the dead worker,
retires the native generation, and creates one replacement worker before reserving a replacement generation. No
timeout, retry worker, second queue, or process-kill recovery path was added.

**Evidence and open work.** No source-string checker was added for this framework behavior; the pre-existing
startup checker and both invocations were deleted because source matching cannot prove callback or thread finality.
This host has no Android SDK, emulator binary, AVD, or repository device-lifecycle harness. `adb` was not
invoked because it can start a host daemon/listener, and no Docker, VM, device, or host product was used as a
fallback. Adjacent Android ownership/source checks, the normal workspace check, Bash/HTML parsing, requirements
identity, the status budget, native-codec integrity, and diff hygiene pass, but none executes this Android path.
Exact current Kotlin/Gradle/JNI compilation and an installed APK must hold a callback in flight, queue a
second callback, destroy the Service, inject join interruption, prove queue and thread finality, and then prove a
clean replacement through ordinary Stop, task swipe, framework recreation, projection revocation, Force Stop, and
reopen/reconnect. Latency, ANR, CPU/memory/thread/handle cleanup, current artifacts, cold equality, independent
reproduction, causation, and external review remain STOP-SHIP.

### R-S11iy/R-S11e-288 — exact desktop CM bridge EOF and failure finality

**State:** Source implementation and focused source gates exist. Exact Rust and
native execution, installed desktop behavior, performance and resource evidence,
current artifacts, independent reproduction, and external review remain pending.

**Boundary and current implementation.** This is the controlled-side Linux,
macOS, and Windows connection-manager bridge owned by one authenticated network
`Connection`, its authenticated CM IPC stream, and its finite `CmEgressSender`.
In `src/server/connection.rs`, authenticated `Ok(None)` is a terminal error rather
than a repoll. `try_start_cm_ipc` retains an exact egress clone before transferring
the original into `start_ipc`; only `Some(Err(_))` from the owner wrapper publishes
`Data::CmErr`, normal owner cancellation publishes nothing, and refusal is handled.
The established pre-login suppression is Windows-only. Existing ordinary-session
and port-forward consumers remain the sole teardown authority, including the
terminal `CmEgressFailure` behavior of the bounded lane.

**Evidence.** Shared and Apple gates plus the independent workspace baseline bind
terminal EOF, exact sender ownership, cross-desktop failure publication, checked
refusal, normal cancellation, the Windows-only exception, and both consumers.
This is source-level evidence; no installed CM process was exercised by those
checks.

**Open evidence.** Execute EOF, transport failure, owner cancellation, pre-login,
queue-refusal, and connection teardown against exact current installed Linux,
macOS, and Windows artifacts. Exercise complete file/control/display transactions
and measure lifecycle latency, CPU, memory, handles, queues, and cleanup under
sustained reconnect/focus/background load. Cross-version behavior, current signed
artifacts, clean cold R-B2/R-B10 equality, independent reproduction, causation,
external review, and proof that the complete connection flow is correct and
performant remain open STOP-SHIP obligations.

### R-S11ix/R-S11e-287 — exact Dart event-stream consumer generation

**State:** Source implementation plus the exact clean Flutter model regression and
fresh bridge generation pass at `5c2fbfc9f78c8953a945283ef3c0cbef7f981064`.
Native execution, device lifecycle and performance evidence, current artifacts,
independent reproduction, and external review remain pending.

**Boundary and current implementation.** This is the Flutter session-event
consumer shared by Android, iOS, Windows, Linux, macOS, and the web parity path.
One exact connection session, UI owner, and process-local stream generation own
each listener. `SessionStreamGeneration` retains one strictly advancing integer
and one current identity-bearing binding. Mobile and desktop start paths reserve
the binding before native `sessionStart`. Listener installation, every message,
web RGBA, error, and done callback require that exact current binding before any
session, queue, presentation, failure, or native-close effect. Exact owner
retirement clears only its own binding. No stream history, subscription registry,
retry, queue, worker, service transition, or reconnect policy is added.

**Evidence.** `flutter/test/session_stream_finality_test.dart` covers same-owner
replacement, strict generation advance, different-owner retirement refusal, and
exact current-owner retirement. `scripts/verify-session-stream-generation.py`,
the shared Android ownership gate, Apple gate, and independent workspace baseline
bind pre-native reservation and exact-current callback/finality checks. The named
clean transaction generated the bridges and executed this suite under Flutter
3.24.5 in a networkless guest-only container. This is Dart/model and generated-
bridge evidence, not device or installed-artifact evidence.

**Open evidence.** Run the exact current bridge and artifact through physical
Android task-swipe/reopen/Force-Stop and native Windows focus/minimize/window-
transfer replacement scenarios, plus iOS, Linux, macOS, web, and cross-version
behavior. Measure capture-through-presentation latency and bounded resource
cleanup under sustained lifecycle/reconnect load. Current signed artifacts, clean
cold R-B2/R-B10 equality, independent reproduction, causation, external review,
and proof that the complete connection flow is correct and performant remain open
STOP-SHIP obligations.

### R-S11iv/R-S11e-285 — exact desktop texture withdrawal and native pointer publication

**State:** Source implementation plus the exact clean Dart model regression and
fresh bridge generation pass at `5c2fbfc9f78c8953a945283ef3c0cbef7f981064` and exact-current Linux native
full-peer execution at `76d8a32c2775f0d13c0c05a9fbc8d82939ad866e`. Exact-current Rust regression
execution, Windows/macOS native execution, installed-platform behavior, sustained performance and resource
evidence, current artifacts, independent reproduction, and external review remain pending.

**Boundary and current implementation.** This is the Windows, Linux, and macOS
outgoing-viewer texture lifecycle from Dart display demand through asynchronous
plugin creation, exact Rust publication, matching unpublication, and release.
`LatestDesktopTextureSlot` requests retirement synchronously on false demand or
disposal, retains one retirement future, and creates a successor only after exact
predecessor finality. Native publication is result-bearing and names the exact
session, UI owner, selected display, nonzero pointer, and operation. Registration
accepts only a vacant slot or the same pointer; unregistration removes one exact
matching pointer. Dart exposes the Flutter texture ID only after native success and
attempts one matching unpublication before plugin release. Android and iOS use the
separate bounded software-RGBA path.

Fresh connections do not create a desktop texture during `FFI.start`, when their native display set is
necessarily empty. Rust commits the bounded initial display owner before publishing `peer_info`; the
desktop view is guarded by the corresponding committed `pi.isSet` state and only then supplies texture
demand. Existing-window routes may bootstrap a texture before cached-state replay only after their
synchronous exact display-owner transaction succeeds. A refused publication remains terminal for that
unchanged demand; the correction does not weaken owner checks or introduce retries.

**Evidence.** `flutter/test/desktop_texture_lifecycle_test.dart` covers in-flight
retirement, false/true demand, predecessor finality, and single retirement. Rust
regression `r_s11iv_pixelbuffer_publication_is_display_and_pointer_exact` covers
selected-display, collision, wrong-pointer, exact-removal, and retired-owner cases.
`scripts/dart-verify.sh` and `scripts/verify.sh` retain those executable tests;
the independent workspace baseline supplies only supplementary source checks. The
named clean transaction generated the bridges and executed the Dart suite under
Flutter 3.24.5; it did not execute the Rust regression or a native plugin. The later
`run.e47T6SGHQP` transaction built the exact release bundle, authenticated a real viewer, and exercised
successful production Linux plugin publication through changing observed X11 pixels and focus loss with
joined cleanup. That is Linux native runtime evidence, not installed-package, Windows/macOS, sustained-soak,
or release-artifact evidence.

Candidate Flutter 3.47.5 runs identified and corrected a separate Linux secondary-engine regression. The
remote-desktop window is created by `desktop_multi_window` with its own `FlDartProject`; selecting the legacy
external-pixel-buffer renderer only on the primary project left that actual window on Impeller and reduced
texture consumption to roughly one copy per 1.1 seconds. Commit `61842d6c` applies one checked pre-engine
project policy to primary and secondary projects. Exact no-NIC run `run.38gNPF0izl` then had no Impeller
banner, presented initial current pixels, and copied every traced submission through its failure boundary.

Follow-up exact run `run.DuaU2EktAy` at `f243f46ef533e303d0416c6186edc7214df09da0` added a native GTK draw
observation. It built the exact 78-file candidate bundle, authenticated the real password prompt, presented
initial pixels in 253 ms with 291 ms maximum age, passed a two-second unfocused interval with eight distinct
states and 261 ms maximum age, and recovered focus without replacing the authenticated TCP connection. During
the next interval, every copied frame was followed by a mapped, visible, drawable `FlViewRenderer` draw. The
failure was therefore not a lost Flutter/GTK redraw. Decoded pixels instead showed `current low nibble + previous
high nibble` after the 255-to-0 source wrap. The verifier source painted those nibbles in separate X requests at
the same 250 ms cadence as capture, so capture phase after refresh could repeatedly observe the intentionally
torn intermediate state. The current verifier correction composes off-screen and publishes one whole state with
one X request. That correction requires a fresh VM run and is not evidence that the reported Android persistent-
process or Windows focus/display-only delay is fixed.

**Open evidence.** Run the exact current generated bridge and native Windows and
macOS plugins, plus installed Linux, through focus/minimize, display-switch, window-transfer,
deselection, disposal, and pointer-replacement stress. Measure capture-through-
compositor latency, queues, CPU, memory, and cleanup under sustained lifecycle
soak. Physical Android lifecycle behavior remains open under its separate path.
Rerun the corrected atomic-pixel-source transaction through all focus and reconnect cycles before drawing any
further Linux presentation conclusion; do not substitute texture callbacks, redraw callbacks, or relaxed pixel
freshness for actual presented-pixel evidence.
Cross-version behavior, current signed artifacts, clean cold R-B2/R-B10 equality,
independent reproduction, causation, external review, and proof that the complete
connection flow is correct and performant remain open STOP-SHIP obligations.

### R-S11ip/R-S11e-279 — orphaned generic desktop privilege-probe excision

**State.** The authored source implements the required excision. Current evidence is source-level;
fresh generated-bridge, native-platform, installed-artifact, performance, and release evidence is
still open.

**Boundary and current implementation.** The zero-caller generic privilege operation is absent from
`src/platform/macos.mm`, the macOS/Linux/Windows Rust platform layers, `src/ui_interface.rs`,
`src/flutter_ffi.rs`, and the authored web bridge. No compatibility alias or replacement generic UI
privilege API remains. Purpose-specific internal `is_root` and Windows `is_elevated` queries remain
available to their real callers. The distinct macOS service-owned unattended-password authorization
creator/verifier remains the only interactive typed authorization flow and retains its checked
external-form cleanup and conditional commit rules.

**Evidence.** `scripts/verify.sh` and `scripts/apple-conform-check.sh` bind authored-source absence,
fresh generated-output absence, and preservation of the typed macOS authorization path. The focused current-tree baseline passes;
it is static evidence only and does not show that a bridge was freshly generated, Authorization
Services ran, or a deployed binary ran.

**Open evidence.** Generate all Rust/Rust-IO/Dart/Freezed bridges from the exact candidate; compile
and execute native Windows and signed macOS paths; exercise installed artifacts and macOS
authorization release/failure cleanup; measure sustained resources; complete cold R-B2/R-B10,
independent reproduction, and external review.

### R-S11iq/R-S11e-280 — purpose-specific Windows RDP-sharing presentation authority

**State.** The purpose-specific source path is implemented and the fresh-bridge naming gate remains.
Exact-current generated bridge, native Windows, installed, performance, artifact,
independent-reproduction, and external-review evidence remains open.

**Boundary and current implementation.** The desktop control asks only
`main_can_request_share_rdp_change` / `mainCanRequestShareRdpChange`. On Windows,
`can_request_service_owned_share_rdp_change` returns true only for exact empty argv, the fixed
installed package executable matching the running non-reparse image, and an elevated current token;
proof errors propagate to the shared wrapper, are logged once, and fail closed. Other platforms
return false. This Boolean is presentation state only. The LocalSystem receiver remains the sole
mutation authority and retains `WindowsServiceOwnedShareRdpRequester` across handling through its
final generation-, image-, token-, role-, liveness-, and pipe-revalidated HKLM write.

**Evidence.** The full verifier retains fresh generated Rust/Dart checks for the removed generic
`main_is_root` / `mainIsRoot` bridge and the purpose-specific replacement. The deleted combined
Python parser did not execute the predicate, bridge, UI, UAC token, SCM service, or registry
mutation; source-string mutations are not evidence for those behaviors.

**Open evidence.** Freshly generate and compile the Rust/Dart bridge; run an installed native
Windows administrative UI through allow and deny cases; exercise real SCM mutations and adversarial
image/token/generation/pipe races; measure latency and resources; bind signed artifacts; complete
cold R-B2/R-B10, independent reproduction, and external review.

### R-S11ir/R-S11e-281 — bounded Windows RDP-sharing client transaction ownership

**State.** The bounded client-owner source design is implemented. Four Windows-target Rust owner
regressions and three pure-Dart UI-latch regressions are authored and wired into their target lanes,
but have not executed at the current commit. Fresh generated-bridge, native Windows, installed,
resource-soak, artifact, independent-reproduction, and external-review evidence remains open.

**Boundary and current implementation.** One lazy process-lifetime
`WindowsShareRdpClientOwner` owns one named OS thread, one fallibly built current-thread Tokio
runtime, and a one-slot request channel. Admission uses `try_send`; full and closed channels are
distinct failures. Startup failure, a finished worker, closed admission, or lost completion consumes
and joins the terminal thread generation. The sole runner executes requests serially without a
per-request spawn. Each service exchange retains separate one-second connect/send/receive bounds;
the bridge waits at most eight seconds for the exact result without cancelling or detaching admitted
work. Errors remain `Result<()>` through the shared and Flutter FFI surfaces. Dart uses one
synchronous mounted-lifetime latch, disables duplicate row/checkbox actions, surfaces errors, and
refreshes service-owned state only after latch release. The private worker-construction seam cannot
select a service operation or escape this module; production still supplies only the fixed typed
RDP-sharing transaction and the fixed eight-second result deadline.

**Evidence.** The `ipc::test::windows_share_rdp_client_tests::r_s11ir_` family drives reported
startup failure and panic, capacity-one waiting admission, serial exact success/error results,
normal/closed/disconnected/panicked worker joins, caller-deadline uncertainty, the dropped completion,
and subsequent work on the same serial owner. `share_rdp_change_lifecycle_test.dart` drives
synchronous duplicate refusal, error-before-latch-release ordering, and absence of late UI callbacks
after unmount. `build-windows.ps1` requires exactly four named Rust regressions and executes them;
`dart-verify.sh` formats, analyzes, and executes the Dart owner. The global shell gate retains only
exact former-helper absence, cross-layer result propagation, and real-lane wiring, while
Apple-specific checks no longer require Windows-only documentation prose. None of these new tests
has compiled or run at this commit because the authorized isolated Windows and Flutter environments
are unavailable.

**Open evidence.** Execute the focused Dart lane and exact-current Rust/Flutter build on native
Windows, then exercise allow, refusal, queue-full, timeout uncertainty, startup failure, worker panic,
concurrent taps, process exit, and real SCM completion in an installed artifact. Measure threads,
handles, CPU, memory, and latency under soak; bind signed artifacts; complete cold R-B2/R-B10,
independent reproduction, and external review.

### R-S11is/R-S11e-282 — exact-command CM file-response admission finality

**SOURCE IMPLEMENTED; TWO EXECUTABLE RUST REGRESSIONS RETAINED AND WIRED;
SOURCE/MUTATION THEATER DELETED; CURRENT INSTALLED DESKTOP/ANDROID FILE EVIDENCE OPEN.**

`CmFileResponder::send` returns the exact `CmEgressAdmissionError`; all response-producing helpers
and exhaustive `handle_fs` propagation make refusal terminal on desktop and Android. A read job is
committed only after `ReadJobInit` admission, digest/progress stops on refusal, and absent/malformed
raw write framing terminates the stream. Already-completed filesystem effects are not falsely rolled
back or reported unperformed; exact session closure is the only sound outcome after response loss.
There is no log-only success, retry, alternate route, inferred completion, service transition, or
persistent-service kill.

The executable Tokio regressions
`r_s11is_cm_file_response_refusal_is_returned_to_the_command_owner` and
`r_s11is_read_job_commits_only_after_initial_response_admission` remain, with direct shared command
`cargo test --lib --features linux-pkg-config,flutter r_s11is_ --color never`. The deleted source
verifier never drove the CM stream, filesystem, raw frame, or target process and is not evidence.

Exact installed desktop and Android transactions remain STOP-SHIP. They must exercise directory and
recursive listing, create/remove/rename, writes, digest, read blocks, completion, cancellation,
malformed raw framing, saturation, abrupt loss, stale generation, reconnect, filesystem outcomes,
protocol finality, jobs, latency, memory, tasks, handles, and cleanup. Current artifacts, cross-
platform behavior, performance/soak, cold equality, independent reproduction, and review remain open.

### R-S11c-4d — receive-file commit, resume, and failure finality

**SOURCE CORRECTED; PRIOR PINNED LINUX CROSS-PROCESS/PROCESS-DEATH AND SYSCALL-TRACED
DURABILITY EVIDENCE RETAINED; EXACT-CURRENT EXECUTION, NATIVE INSTALLED, AND PHYSICAL POWER-LOSS
EVIDENCE OPEN.**
A transfer job has one immutable send or receive role.
Only receive jobs may write, own receive sidecars, clean them, or commit them; only send jobs may
read. File-list admission rejects invalid initial indexes and aggregate-size overflow. Confirmation
requires the exact job and active file, refuses duplicates, and publishes a resumed stream only
after the correct source or receive sidecar is opened, its actual length admits the offset, the seek
succeeds, and byte accounting remains representable. Malformed or over-limit zstd input is an
explicit write failure rather than a successful empty block.

Receive blocks advance files monotonically. A terminal `Done` commits only the exact next index,
after the active stream and retained staged handle are synchronized and the staged file's time is set;
incomplete or stale terminal indexes fail. The admitted digest handle is removed before the exact
final rename. Publication is an irreversible in-memory state transition immediately after rename,
before any post-rename barrier. Unix then synchronizes the retained containing-directory handle;
failure is reported as **visible but commit-durability-uncertain**, never as an assertion that rename
did not occur. Error cleanup for that state retries the namespace barrier and synchronizes the exact
now-final handle, but can never delete or replace the published file. Direct viewer, controlled-side,
and CM call sites propagate confirmation/finalization failure and clean only a receive generation the
job admitted. CM terminal results remain bound to connection ID, generation, job, and phase; peer
error, pre-publication failure, and post-publication durability uncertainty remain distinct. Current-file
retirement is one fallible operation: it closes the stream, consumes only the admitted receive claim, and propagates
identity or durability cleanup failure instead of logging success. Viewer block failure carries that uncertainty
into the round-owned terminal error. CM cancellation enters a distinct exact-generation `Cancelling` phase and
awaits a typed cleanup result; success retires authority without a peer `Done`, while failure produces a bounded
authenticated file error.

Namespace durability is now part of admission and cleanup rather than only final publication. Unix
synchronizes the exact parent after creating the lock and staged sidecars, synchronizes each retained
ancestor immediately after a successful `mkdirat`, and synchronizes the parent after exact-handle
sidecar or lease removal. A cleanup attempt still persists removals that did succeed when another
artifact fails its identity check; the stable lock pathname is retired only after the relevant
cleanup barrier succeeds. A deterministic same-UID replacement therefore leaves the replacement and
displaced admitted payload untouched and retains a zero-byte lock marker rather than claiming a fully
retired transaction. The OS lock is released, so the marker does not block a later cooperative owner.

Each destination now acquires a nonblocking OS advisory lease on a stable owner-only
`<final>.download.lock` inode before any sidecar is opened or truncated. The opened lock pathname is
identity-revalidated after acquisition. A live contender fails without modifying the owner's data.
Kernel lock release on process death leaves the stable inode plus exact `.download`/`.digest` state
available for explicit resume; successful commit, exact cleanup, failed admission, and read-only
confirmation retire the lock inode. Resume and confirmation never create missing destination
directories. Resume reacquires the lease, requires the exact stored digest,
and retains the exact open download and digest handles. Cleanup checks that each Unix pathname still
names its admitted device/inode; Windows deletes the admitted handle. Unix validates effective-UID
ownership and one-link authority, and Windows validates one-link authority, before any truncation, so
a precreated hard link cannot redirect sidecar truncation.

The retained prior Linux-container run passed all 37 `fs::tests` and the complete 147-test `hbb_common` Rust 1.75
suite. It predates the current fallible-retirement and CM cancellation-finality correction. Its focused behaviors
include a real competing process, forced termination of the process
holding the lease with resume/commit by a third process, `.download` and `.digest` hard-link attacks,
deterministic staging-inode replacement, false-resume refusal, exact cleanup, confirmation-lease
retirement, ordinary post-rename durability, and a post-publication barrier failure that must preserve
the visible final file. Tests ran as numeric UID/GID 1000 in a capability-free,
no-new-privileges, network-disabled container with read-only source/caches and disposable tmpfs Cargo,
target, home, machine identity, and filesystem fixtures; no ports were published. This is prior Linux
container behavior, not current-source, installed, or native cross-platform evidence. The current source adds real
replacement-generation assertions at the shared job and direct-viewer layers plus typed CM cancellation success and
replacement-generation failure finality. A shared regression also covers publication failure after the exact digest
was already unlinked, requiring cleanup to remove the remaining staged file and lease without accepting a renamed or
linked object. Exact lease-marker removal/durability failure is now part of setup, inspection, commit, and cleanup
results instead of a successful return followed by destructor logging; rejected resume admission also retires its
idle marker without removing resumable sidecars. None has compiled or executed in this tree because the fixed
authorized rootless Docker socket is absent.

An exact-production-path `strace` run observed the successful Linux sequence
`fsync(download) -> unlinkat(digest) -> renameat(download, final) -> fsync(parent)`. Injecting `EIO`
into that final parent `fsync` made the finalizer return the explicit visible-but-uncertain error while
the test proved the final payload remained visible and both staging names were absent. A second trace
drove the real `ReceiveWriteClaim`: after injected post-rename parent-sync failure, cleanup retried the
same directory barrier, synchronized the exact published file handle, durably retired the lock, and
again left the final payload intact. These are kernel-observed Linux syscall and fault-injection
results, not source-string assertions. They are not a physical power-cut or filesystem-remount test.

Windows publication remains handle-relative through `NtSetInformationFile` and now flushes the exact
download handle both before and after it is renamed; post-rename failure uses the same irreversible
published state. This is conservative source design, not current Windows compile/runtime or native
namespace-durability evidence. On macOS/iOS, regular-file synchronization performs ordinary `fsync`
followed by mandatory `F_FULLFSYNC`, and namespace transactions place another exact-file full-sync
after the directory barrier. Apple documents `F_FULLFSYNC` as the stronger persistence request but a
best-effort guarantee; the source has not been compiled or exercised on the current native Apple
targets. Unix has no general rename-by-file-descriptor primitive: it revalidates the staged device/inode
immediately before `renameat`, so deterministic substitution fails closed, but a narrow hostile
same-UID pathname race between the last check and rename/unlink remains unproved. Advisory leases do
not constrain a noncooperating process with the receiver's own filesystem identity. Required follow-up
is exact installed Windows, Linux, macOS, Android, and iOS file transactions; native
contention/crash/reconnect and storage-failure injection; physical power-loss/remount testing where
practical; bounded resource/latency soak; current artifact binding; cold R-B2/R-B10 equality;
independent reproduction; and external review.

### R-S11it/R-S11e-283 — terminal CM stream and route-setup ownership

**PRE-LOGIN SOURCE DEFECT CORRECTED; SEVEN TARGETED EXECUTABLE REGRESSIONS AUTHORED
AND WIRED BUT NOT YET RUN; EXACT NATIVE INSTALLED CM/ROUTE EVIDENCE OPEN.** Review
disproved the former source-closure claim: before Login, `PrivacyModeState`,
`FileTransferLog`, and `ClipboardFileEnabled` could mutate UI state, and Windows
`ClipboardFile` could stop the global clipboard context before its late `conn_id` check.
The inherited unused `ClickTime` request/response and its process-global replica are now
deleted end to end instead of being retained behind an ownership guard. The first correction
also incorrectly treated the legitimate
Windows privacy teardown callback as an ordinary pre-Login client effect and therefore
made that callback unreachable. The runner now distinguishes one activated client stream
from independently authorized one-shot actions. Before activation it accepts only Login,
close/disconnect, Windows' server-validated non-file clipboard read, and the typed Windows
privacy callback. The callback carries the originating connection's CM token, fixes its
connection type to Remote at the receiver, repeats live connection validation, then under
the registry lock requires the same token on the exact current owner before it publishes
only the response form and terminates its auxiliary stream. The old bare-ID callback and
broadcast helper are absent. Response-only clipboard and privacy messages are terminal.
Production `ipc_task` still invokes the
same whole-stream runner exactly once and binds its private validation seam to
`validate_cm_connection_authority`; there is no retry or alternate authority path.

Six Windows Rust tests drive that runner through the real framed `ConnectionTmpl`
transport with an in-memory duplex endpoint. They cover inert pre-Login refusal,
malformed framing, first-Login activation and repeated-Login finality, route collision,
readiness-send failure, a token-validated one-shot privacy callback delivered to the exact
activated owner without auxiliary client admission, no client commit on refusal, and
observation that exact client removal occurs while the route remains occupied. A
clipboard-crate regression drives the real controlled-route registry with test-only mint
accounting and proves a
duplicate ID consumes neither a route generation nor a channel. The suites are wired to
the native Windows artifact lane, and the portable route-allocation test is wired to the
confined Linux verifier. The old clipboard-route source/mutation verifier remains
deleted; no replacement source-text R-S11it proof was added.

These tests were not compiled or executed for this source change: the fixed rootless
Docker socket is absent, session libvirt has no domain, and the repository-owned Windows
golden image is absent. Host execution, privileged Docker, and a long release build were
not used as fallbacks. Therefore even focused executable evidence remains open until the
isolated Windows lane runs this exact source.

Run the exact installed Windows candidate through those scenarios, EOF and abrupt-owner
loss, same-ID route races, SCM restart, and complete file/clipboard transactions. Retain
latency, CPU/memory/handle/thread cleanup, current artifact identity, cold R-B2/R-B10
equality, independent reproduction, and external review. Until that exists, the source
shape is not promoted to native or lifecycle proof.

### R-S11iu/R-S11e-284 — exact-generation CM client-registry ownership

**CORE REGISTRY, SNAPSHOT RECONCILIATION, CM FILE-LOG, AND FINAL-REMOTE CLEANUP SOURCE
IMPLEMENTED; OTHER SIDE-EFFECT LIFETIME WORK REMAINS; FOCUSED RUST AND DART REGRESSIONS
RETAINED OR AUTHORED;
ANDROID RUST FIXTURES ARE NOT EXECUTED; CURRENT DEVICE/NATIVE EVIDENCE OPEN.**
`CmClientRegistry` owns a checked process-lifetime
generation and exact `CmClientOwner`. Admission rejects nonpositive IDs, empty connection
authority tokens, stale source generations, active same-source collisions, and exhaustion
without partial mutation. The registry token is internal, serde-skipped authority state;
the UI-facing client representation omits it.
Disconnected owners may be replaced; only a newer Android MainService generation may
supersede an active predecessor, whose egress owner closes before replacement. Desktop
source generation zero cannot supersede an active collision. Registry mutation, chat,
voice, Android notification/input/capture mirrors, and generation-bearing
add/remove/chat/voice UI events carry or check the exact owner. This is not yet a blanket
claim for every CM side effect. CM file-log publication now carries the retained exact owner
through every desktop filesystem, forwarded-log, and read-tick site. Publication checks that
owner immediately before the Flutter handoff; stale ownership or an unknown action terminates
the stream path. The fixed event schema is `id`, `registry_generation`, `action`, and `log`, so
an action string cannot select or overwrite an authority field. Dart dispatch uses its receiving
`FFI`, requires the exact live `ServerModel` generation, rejects every embedded `connId` mismatch,
and stores jobs plus speed-sampling state under the exact owner. Full-state refresh, add,
replacement, remove, and close reconcile those tables; retirement deletes the predecessor table,
and deferred tab selection rechecks both its request generation and client owner before
publication. The former desktop length-only refresh gate is deleted: count is not state identity.
The desktop CM and live mobile UI now use the same non-overlapping 500 ms repair turn, which obtains
the complete native registry snapshot, validates the top-level list and every positive, unique
connection ID and process-lifetime registry generation before any mutation, and canonicalizes
admission order by generation. An asynchronous snapshot carries the
local observation revision from before its native call and cannot overwrite an intervening add,
remove, disconnect, or voice event. Reconciliation reuses only the exact `(id, generation)` Dart
owner, preserves its UI-local unread state, replaces a successor rather than inheriting predecessor
state, and rebuilds tabs only when owners or tab identity change; an unchanged snapshot causes no
client-list, file-table, tab, or listener notification mutation. Native serialization borrows the
registry entries and does not clone their egress senders on each repair turn. Consequently a missed
same-count replacement, disconnect, voice transition, or remove-plus-add is repaired by the next
refresh rather than persisting indefinitely. `closeAll` removes only the exact generations it
captured, preserving a concurrently admitted successor. Disconnected owners retain their table only
while that exact generation remains in the client registry. The unused
process-global desktop click-time request/response and FFI surface are deleted end to end. The
previously recorded Windows clipboard-cleanup gap is not reachable:
the exact controlled-route lease remains occupied through registry retirement and native emptying,
and a same-ID successor must acquire that route before it can enter the client registry.

Windows privacy mode now retains one typed connection owner containing the positive
connection ID and nonempty CM authority token for the physical privacy resource's full
lifetime. A same-ID request with a different token is not treated as the same owner.
Privacy activation does not acquire local-input suppression: the inherited global low-level
keyboard/mouse hook and its arbitrary physical-input filtering are deleted. Windows reserves only
the explicit Ctrl+P machine-local escape chord with `RegisterHotKey`. One owned queue thread creates
its message queue before publishing its ID, and its exact `JoinHandle` is retained from creation
through `UnregisterHotKey` and joined teardown; a second registration cannot start while that owner
exists, and cleanup uncertainty poisons reuse. `GetMessage` error and `WM_QUIT` are distinguished.
The queue handler performs no privacy, network, display, or runtime work: it only makes a bounded
nonblocking handoff to one retained process-lifetime control worker and resumes pumping. The queued
request carries the exact connection ID and CM token captured by that hotkey registration, so delayed
work cannot force off a same-ID replacement or another owner. That worker
reuses the Tokio runtime handle retained by the exact privacy owner; the former per-callback
`#[tokio::main]` runtime is absent, and the synchronous bridge fails closed on a Tokio runtime
thread. Teardown sends a distinct
`AuthorizedPrivacyModeState` one-shot request; the CM fixes Remote as the type, validates
the live token, and routes a token-free response only to a current registry entry retaining
that same token. A validator-approved stale
token therefore cannot cross a same-ID CM replacement. The old bare-ID
`PrivacyModeState` request and multi-client broadcast helper are deleted. Privacy activation
now has one blocking-worker path for every implementation instead of choosing whether to
block the Tokio worker from the previously selected implementation. A one-permit admission gate
allows only one activation thread through the complete registered-and-joined lifetime, while one
process-lifetime reaper retains and joins its exact handle. The worker cannot begin native work
until that handoff succeeds. Each physical implementation reaches a two-phase
prepare/commit gate before it publishes the owner; the 7.5-second response deadline sends a
cancel decision and then waits for the owned operation to roll back and drain rather than
returning while it can commit later. A connection-future drop also publishes cancellation through
a shared activation flag, and each implementation checks that flag before and between native
mutation stages; a worker already inside one opaque native call cannot be interrupted by this
source mechanism, but it must stop at the next checkpoint and roll back. Dropping the connection-
side future also closes the final commit gate, so a worker that reaches it afterward must roll back.
Connection-driven off, capture-validation rollback, `Connection::drop`, and the physical Ctrl+P
escape now require the exact ID and CM token; only the final-Remote machine reset retains explicitly
named force-off authority. Drop/activation-error retirement is idempotent when a different exact owner is current,
so routine cleanup neither revokes nor log-amplifies an incumbent connection. An activation
refusal no longer force-disables an incumbent connection's privacy resource. Unsupported nonempty
implementation names fail instead of silently selecting a
fallback. Virtual-display and window implementations attempt physical rollback before a
cancelled transaction reports completion, and teardown continues display/window restoration
even if escape-hotkey retirement fails. Virtual-display teardown now checks display staging,
display commit, monitor removal, and registry recovery instead of discarding their results; it
retains the relevant snapshots for retry until each class succeeds and aggregates simultaneous
failures. The inherited fallback that force-unplugged every pre-existing virtual display when this
activation had created none is removed. The Amyuni interface does not expose stable monitor
identities, so the former vector of fake zero-valued "indices" is replaced by an honest count that
is recorded immediately after this activation's plug-in succeeds; teardown requests exactly that
many removals and none when the activation created none. A returned rollback/hotkey-retirement failure retains
the pending exact owner instead of erasing cleanup authority; the activation-error path retries
teardown only for its own exact ID/token.
Switching implementations now refuses to replace the old implementation when its reported
teardown fails. The first-plug resolution workaround no longer launches an unretained child thread;
its bounded poll completes synchronously inside the same calling operation and logs each resolution
failure. Non-privacy virtual-display callers still need installed proof that this blocking work is
off their Tokio/UI execution paths.

This is source and model closure for activation publication and hotkey ownership, not native Windows
display evidence. The Windows-only regression performs two real `RegisterHotKey`/`UnregisterHotKey`
lifecycles, refuses a concurrent registration, and requires reuse only after exact joined teardown;
the pinned Windows lane invokes it, but that lane has not run for this source. Native hotkey,
display, and registry APIs may still have target-specific blocking and failure semantics. In
particular, Amyuni exposes count-based
plug/unplug rather than resource identities, so cross-process driver churn can make ownership
ambiguous and must be exercised/refused correctly in the installed race matrix. Disconnect-time
exact-owner privacy retirement now makes one nonblocking submission to a bounded 32-request queue.
A short independent lifecycle snapshot admits a queue entry only for the exact active owner or the
single admitted activation, preventing unauthenticated or unrelated connection churn from consuming
retirement capacity. The activation reaper retains that pending identity until its exact native
worker joins; final activation and every central teardown path refresh the active identity before
pending authority is released. One retained process-lifetime worker drains accepted ID/token
requests in order and performs the existing idempotent exact-owner teardown, so this step no longer
waits in `Connection::drop` for the global privacy mutex or native restore; submission or worker
failure is logged and never falls back to inline teardown. Unsupported platforms allocate no worker
or queue. The unused public `privacy_mode::init`, `clear`, and `switch` facades are deleted; the last
could replace an implementation through destructor cleanup while discarding its failure, outside the
one fallible activation-switch transaction. The trait's internal `clear` operation remains for that
transaction. Final-Remote cleanup no longer infers global finality from an unlocked connection count
or runs native display work in `AuthedConnID::drop`. Each desktop Remote owns an exact cleanup lease;
the last retirement coalesces one cleanup request on a retained process-lifetime worker. Admission
invalidates an unclaimed request or asynchronously waits for a claimed request, and a failed cleanup
permits one retry bound to that admission's exact retry revision. A failed or older waiter cannot
benefit from a later admission's retry. The authenticated registry assigns a checked generation,
refuses same-ID overlap, retains an unpublished capacity-counted reservation before the next await,
keeps its mutable entries private, and exposes only narrow read-only counts to shutdown, cursor, and
Windows service-control consumers. The final credential-current commit atomically publishes that
reservation; retirement marks the exact entry unavailable
before local capability validation can use it,
performs ID-keyed codec/QoS/mouse/whiteboard retirement while the ID remains reserved, and removes only
that generation. If exact registry retirement cannot be proved, the Remote cleanup lease is poisoned;
it cannot launch uncertain physical cleanup, and Remote admission plus graceful drain remain failed closed
until process restart. Because cleanup admission may wait, authorization now revalidates the exact credential
generation after cleanup and input-worker startup before committing `authorized = true`; mismatch drains
those exact owners and fails login. The worker waits for any admitted privacy activation to join, restores wallpaper,
resolution, privacy, virtual-display, and cursor state, aggregates fallible native results, and is
part of graceful-shutdown drain; a latched cleanup failure is not reported as drained. Resolution
restoration no longer holds its registry lock across a native call or clears failed work: a successful
unchanged snapshot is removed, while failure or a concurrent replacement fails the transaction and
remains retryable. Windows reset removes only the remaining process-counted virtual displays, treats
zero owned displays as successful finality, rejects negative-index global removal, and does not mutate
implementation-owned display state after a failed privacy teardown. Multi-display teardown decrements
the exact owner's remaining count after each success, so a partial failure cannot over-remove on retry.
When no Amyuni display remains observable, one successful exact cleanup step also retires one stale
process-owned count; contradictory enumeration remains a visible retryable failure.
The primary post-authentication type gate now reserves physical resolution changes and every other
host-display mutation for Remote sessions, the only sessions that own final-cleanup leases. ViewCamera
retains video observation, camera/display selection, refresh, query, and bounded video-feedback messages,
while FileTransfer, Terminal, and PortForward cannot reach those per-video QoS sinks.
Explicit peer-off and
capture-validation/activation-error
rollback remain synchronous and result-bearing. Real cancellation, disconnect, concurrent successor,
session-change, driver-delay/failure, restore-failure, queue/worker refusal, shutdown, and bounded
resource/latency behavior remain open for exact installed desktop artifacts.

The Android CM/file bridge now runs as one retained child future of the exact network
`Connection` on its existing Tokio runtime. The former unretained OS thread and hidden
current-thread runtime are absent. Unexpected child completion closes that connection;
ordinary connection close publishes the existing one-shot terminal and awaits the child.
`CmClientTaskOwner` owns the admitted registry generation, so dropping the child at any
await synchronously attempts exact-generation registry/UI retirement. Android-visible
imports used by this path are no longer incorrectly excluded by target configuration.

Android source carries service, connection, and registry generations through its resource
mirror, input, delayed pointer work, voice, capture reconciliation, notifications, native
events, and Dart state. A newer same-ID owner retires predecessor resources before
publication; stale callbacks are intended to be inert. The persistent foreground service
remains intentional, and cleanup correctness must not depend on task swipe or Force Stop.
The retained Android CM listener checks its exact registry owner before it processes each
event after Login. Once a newer service generation replaces it, the next observed command
is terminal before filesystem dispatch or any other command effect. Work admitted while
the owner was current may finish; supersession does not invent rollback or report an
already completed filesystem effect as unperformed.

Five Rust tests exercise stale-owner reuse, same-source/stale collision refusal,
disconnected replacement, generation-exhaustion no-commit, and exact-owner file-log publication
with stale/unknown refusal. Another focused unit regression proves that a privacy resource rejects
same-ID replacement with a different connection token. Three additional Tokio regressions execute
the activation worker/reaper rendezvous: successful prepare/commit, deadline cancellation that
cannot return before the held worker drains, and connection-future cancellation that makes a late
commit fail. A fourth executable regression stalls the retirement worker inside its first teardown
callback, proves a later exact-owner request is admitted without waiting on that callback, then
requires both accepted requests to execute in FIFO order before the worker joins. It exercises the
real bounded dispatcher loop but not Windows display APIs or a complete `Connection` destructor. The
callback regression first rejects a
stale token at the registry
egress edge, then drives the valid one-shot callback over the real framed runner. Three
additional focused Rust tests drive the actual Android CM future through one-shot terminal
completion, direct future cancellation after admission, and same-ID service-generation
supersession followed by a real `CreateDir` command. The last requires predecessor
termination with no directory effect, followed by exact successor cleanup.
Six additional Rust state regressions cover unclaimed-cleanup supersession, claimed-cleanup
admission blocking, last-live-lease finality, exact-revision retry isolation, stale cleanup-lease
retirement, and authenticated same-ID collision/stale-removal refusal. A focused resolution regression executes partial failure and
concurrent-record replacement against the real restoration transaction helper. They are selected by
the existing serial `r_s11iu_` target lanes but have not run for this source.
The shared runner uses
`cargo test --lib --features linux-pkg-config,flutter r_s11iu_ --color never -- --test-threads=1`
because these regressions intentionally exercise one process-global activation admission gate.
The pinned offline Windows artifact lane now runs the same filter serially before packaging, so the
Windows implementations must compile with the exact-owner API and the lifecycle regressions must
execute on that target; this wiring is not a claim that the lane has run for the current source.
That lane also runs the Windows-only native privacy escape regression serially; it is authored but
has not executed for this source because no disposable Windows VM is currently registered.
`flutter/test/server_model_test.dart` retains registry-generation JSON serialization and adds two
state regressions for same-count replacement/disconnect/voice repair, exact-owner UI-state retention,
unchanged-snapshot inertness, canonical generation order, and whole-snapshot duplicate owner refusal.
`flutter/test/cm_file_owner_test.dart`, now invoked by `scripts/dart-verify.sh`, adds two executable
Dart cases for the fixed envelope, closed action vocabulary, same-ID fresh-table replacement,
payload-ID refusal, selected-table retirement, and invalidation of a delayed predecessor selection.
These state tests do not exercise the complete rendered Flutter window or native event stream.
Android owner-state evidence is limited to supplementary checks of production Kotlin topology. No retained Kotlin
unit/instrumentation test or installed package currently executes `ControlledConnectionType`,
`ControlledCaptureOwnerState`, `ControlledInputOwner`, `ExactOwnerBoundedQueue`, `VoiceCallOwnerState`,
`MainServiceGenerationOwner`, or `MainServiceStatusOwner` through their replacement, retirement, stale-generation,
and cleanup cases. Five standalone owner `main()` programs outside Gradle test source sets are deleted rather than
retained as tests; the last four deletions removed six shell prose searches plus the workspace meta-verifier's
twelve repeated assertions and three source loads. The shared
source gate still checks the retained Android child future, exact generation transfer, terminal/connection finality,
RAII registry retirement, and selected production owner topology without treating model text as behavior.

The activation, child-future, registry, file-owner, and Dart cases have not been executed against the
current dependency closure: the fixed rootless Docker socket, repository Cargo vendor closure,
repository Flutter cache, and repository Windows image are absent. Host execution was not used as
a fallback, and static review is not their result. Required evidence remains exact Rust and Dart
execution, the complete native-to-rendered Flutter event path, an Android target
compile, plus current Android package execution for same-ID supersession, stale/duplicate
callbacks, input, queued/delayed
actions, voice/recorder demand, capture, notification, task swipe, reopen, Force Stop,
reconnect, and bounded cleanup without treating service death as recovery. Desktop and
installed Windows same-ID collisions, complete file transactions, latency/resource soak,
signed artifact binding, cold R-B2/R-B10 equality, independent reproduction, causation,
R-V3 external review, and correct/performant end-to-end connection behavior remain open.
This source correction is not evidence that it caused or resolves the user-reported
outgoing Android screen-control hang or the Windows focus/minimize display-only latency.

### R-S11io/R-S11e-278 — checked macOS password-authorization creator cleanup and output commit

**State.** The source implements checked creator-reference cleanup and output commit. Focused source
validation exists, but no exact-current signed macOS execution proves the native resource and failure
semantics. This item is source-supported and native-evidence-open.

**Boundary and current implementation.** The UI-side creator validates the exact administrator-only
right, clears the validated caller buffer before fallible work, keeps the external form in a zeroed
local object, and uses the existing interactive preauthorization flags. It releases exactly the
creator reference with `kAuthorizationFlagDefaults`, retains that status, publishes the form exactly
once only when externalization and release both succeed, wipes the local form, and returns their
conjunction. Creator-side rights destruction is forbidden because it would invalidate the transferable
authorization before helper import. The Rust wrapper owns the result in bounded, zeroizing
`SensitiveAuthorization` storage.

**Evidence.** `src/platform/macos.mm` contains the native transaction and distinct creator/verifier
cleanup flags; `src/platform/macos.rs` contains the bounded sensitive wrapper. The focused password
IPC, Apple conformance, independent workspace, and native-watch validators bind output preclear,
release cardinality/flag/status/order, conditional single publication, local wipe, conjunctive return,
and the R-S11io/Appendix C #400 documentation identity. This is source evidence only.

**Open evidence.** Run the exact signed candidate on macOS and inject authorization creation,
preauthorization, externalization, and creator-release failures; prove zero output on every failure,
successful later helper import, bounded handles/memory, prompt and retry behavior, installed
LaunchDaemon interaction, repeated-operation cleanup, artifact identity, cold R-B2/R-B10 equality,
independent reproduction, and external review.

### R-S11in/R-S11e-277 — read-only macOS password authorization verification

**State.** Verification is separated from policy creation in source and requires checked imported-right
cleanup. Focused source validation exists; exact-current native Authorization Services behavior remains
unproved.

**Boundary and current implementation.** `AuthorizationRightSet` is reachable only through the typed
readiness action. Password admission performs read-only external-form verification, then fresh complete
requester-generation replay, then constructs the typed admission. Native verification requires the
exact right definition before import, evaluates the named right without interaction, calls
`AuthorizationFree` exactly once with `kAuthorizationFlagDestroyRights`, requires its status, repeats
the exact definition read after cleanup, and accepts only the conjunction of evaluation, cleanup, and
final-policy success. Missing, malformed, denied, expired, cleanup-failed, or drifted state fails closed
and is never repaired by verification.

**Evidence.** `src/ipc.rs` contains the ordered Rust admission grant; `src/platform/macos.mm` contains
the read-only native verifier and sole policy writer. Focused password IPC, Apple conformance,
independent workspace, and native-watch validators bind writer cardinality and absence, the two policy
reads, noninteractive evaluation, checked destroy/free ordering, the three-result conjunction, and the
R-S11in/Appendix C #399 identity. These validators do not execute Authorization Services.

**Open evidence.** Run real allow, deny, malformed, expired, missing-definition, drift, cleanup-failure,
and privileged concurrent-policy-change cases on the exact signed macOS candidate. Measure rights and
handle cleanup, repeated prompt/recovery behavior, installed LaunchDaemon behavior, latency and resource
bounds, artifact identity, cold R-B2/R-B10 equality, independent reproduction, and external review.
The two policy reads provide last-observed consistency, not an atomic lock against another privileged
administrator.

### R-S11im/R-S11e-276 — typed macOS password-right policy-write authority

**State.** The source carries exact requester authority through a typed consuming policy-write action.
Focused source validation exists; exact-current signed macOS and installed Authorization Services
execution remain open.

**Boundary and current implementation.** A private, non-cloneable
`MacosServiceOwnedPasswordRightAdmission` retains the complete exact administrative requester. Its sole
grant consumes that requester and the fresh post-request service-socket authorization and requires the
fixed endpoint plus exact UID, effective PID, and audit-token equality. Only its consuming
`ensure_ready` action may replay installed-app identity, argv, finite administrative role, and process
generation, then invoke the fixed policy writer as the final conjunct. The response Boolean reports
only the completed operation and carries no authority.

**Evidence.** `src/ipc.rs` contains the admission, sole grant, consuming action, and closed
authenticate-to-grant-to-action flow. Focused password IPC, Apple conformance, independent workspace,
and native-watch validators bind type privacy/non-cloneability, consuming requester ownership, exact
post-request equality, sole construction, final live replay/write, direct-writer absence, and the
R-S11im/Appendix C #398 identity. This is source evidence, not a native policy-write result.

**Open evidence.** Exercise the exact signed macOS candidate against installed LaunchDaemon and
Authorization Services with authorized and unauthorized roles, requester exit, PID reuse, UID,
audit-token, argv, descriptor-handoff, and socket races. Measure prompt/failure finality, latency,
handles and memory, repeated operations, artifact identity, cold R-B2/R-B10 equality, independent
reproduction, and external review.

### R-S11il/R-S11e-275 — typed macOS credential-replica response authority

**State.** The source binds the password-equivalent PRS response to a consuming exact-requester
admission. Focused source validation exists; no exact-current signed macOS execution proves the
LaunchDaemon/LaunchAgent transaction.

**Boundary and current implementation.** The private non-cloneable
`MacosServiceOwnedCredentialRequester` retains the complete signed installed-app socket identity and
exact argv. After a canonical bodyless request, only its consuming `admit` method may take a fresh
fixed-`_service_credential` same-stream snapshot and require exact UID, effective-PID, and audit-token
continuity. The resulting private non-cloneable
`MacosServiceOwnedCredentialReplicaAdmission` retains the requester and wire UUID. Only its consuming
`respond` method may read the root runtime PRS and send it under that UUID while retaining the
requester. The handler has no Boolean-authority, generic-secret, raw-writer, or direct-read fallback.

**Evidence.** `src/ipc.rs` contains the requester, sole consuming admission, response owner, and
closed handler call graph. The focused macOS credential IPC, Apple conformance, independent workspace,
and native-watch validators bind the final snapshot/equality, sole construction, retained UUID and
requester, capability-owned PRS read/write, and the R-S11il/Appendix C #397 identity. This proves source
structure only and retains the documented last-owner limitation.

**Open evidence.** Run the exact signed installed macOS transaction with legitimate and adversarial
LaunchAgent/requester generations, exit, PID reuse, audit-token, descriptor-handoff, request/response,
timeout, shutdown, and socket races. Measure response finality, latency, memory and handle cleanup,
artifact identity, cold R-B2/R-B10 equality, independent reproduction, and external review. Darwin
last-owner continuity is not exclusive request-frame authorship or complete handoff detection.

### R-S11ik/R-S11e-274 — typed Linux initial credential runtime PRS receiver authority

**State.** The source retains the exact root-parent generation through typed runtime-only installation.
Focused source validation exists; exact-current installed Linux service execution remains open.

**Boundary and current implementation.** A private non-cloneable
`LinuxServiceOwnedCredentialReplicaReceiver` owns the fixed-`_service_credential` stream and accepted
PID/UID/start-time `LinuxProcessIdentity`. Connection requires the exact service-owned child role,
UID-0 endpoint, root launch/direct-parent proof, and deadline. Its consuming transaction uses one UUID,
validates the complete canonical response, reauthenticates the retained stream, rechecks the deadline,
and requires complete parent-generation equality. Only the resulting typed admission may consume the
runtime-only PRS sink. The normal wrapper is `connect -> receive_and_admit -> install`; the debug-only
unsupervised fixture receives no credential and may only clear runtime PRS.

**Evidence.** `src/ipc.rs` contains the receiver/admission graph and
`libs/hbb_common/src/config.rs` contains the canonical validating nonpersistent sink. The focused
Linux password IPC, shared, Apple, independent workspace, and native-watch validators bind fixed
endpoint and role, retained stream/generation, same-UUID exchange, final proof/deadline/equality,
consuming install, debug-fixture separation, and the R-S11ik/Appendix C #396 identity. This is source
evidence rather than an installed-service result.

**Open evidence.** Run the exact candidate as an installed root supervisor and active-user child
inside a disposable Linux VM across supported desktops and init systems. Test parent exit and restart,
PID reuse, UID/PPID/start-time, launch-parent, descriptor-handoff, timeout, malformed response, socket
race, replay, shutdown, and error finality. Measure latency, CPU, memory, descriptors and cleanup; bind
the Debian artifact; complete cold R-B2/R-B10 equality, independent reproduction, and external review.

### R-S11ij/R-S11e-273 — typed macOS child-side runtime PRS receiver authority

**State.** The source retains exact privileged-helper authority through typed runtime-only
installation. Focused source validation exists; exact-current signed macOS and installed helper
execution remain open.

**Boundary and current implementation.** `MacosServiceServerAuthorization` privately retains the
socket-derived UID, effective PID, and full audit token after UID-0 and exact signed-helper validation.
A private non-cloneable `MacosServiceOwnedCredentialReplicaReceiver` owns that authorization and the
fixed-`_service_credential` stream. Its consuming transaction freshly checks the exact child role,
uses one UUID for request and response, validates the complete canonical PRS, snapshots and reproves
the retained peer, and requires full UID/PID/audit-token equality. Only the resulting typed admission
may consume the validating nonpersistent runtime sink; the public wrapper has no raw, generic-secret,
proof, endpoint, config-sink, or Boolean fallback.

**Evidence.** `src/ipc/auth.rs` contains the opaque helper authorization and exact continuity
comparison; `src/ipc.rs` contains the receiver, admission, and closed wrapper; the shared sink is in
`libs/hbb_common/src/config.rs`. The focused macOS credential IPC, shared, Apple, independent
workspace, and native-watch validators bind the typed proof return, fixed role/path, retained stream
and full identity, same-UUID exchange, final proof/equality, consuming install, and the
R-S11ij/Appendix C #395 identity. This is source evidence only.

**Open evidence.** Run the exact signed installed macOS child/helper flow with authorized and
unauthorized peers, helper exit, PID reuse, changed audit token, descriptor handoff, malformed and
mismatched responses, timeout, shutdown, and socket races. Measure install/reconnect finality,
latency, CPU, memory and handles, bind exact artifacts, and complete cold R-B2/R-B10 equality,
independent reproduction, and external review. The source model proves connected-peer/last-owner
consistency, not exclusive frame authorship or complete descriptor-handoff detection.
