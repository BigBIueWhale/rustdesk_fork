# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Older work-log material was removed from this live ledger on
2026-06-26 because it contained superseded `PARTIAL`, `TODO`, and deferred-work
claims that were useful historically but misleading as current status. Git
history remains the traceability record for those intermediate notes.

## Current Verdict

**Status: file-transfer parent-walk, Windows/Android socket-surface,
native-codec advisory-watch, native media/clipboard handoff-bound and
CLIPRDR callback fail-closed follow-ups, the first desktop
native-video/native-Opus/native-zstd/native-clipboard worker slices, the
mobile media/zstd fail-closed behavior, bounded worker-I/O thread, Linux
child-confinement, Windows Job Object child lifetime/limit guards and process mitigations, non-mobile desktop-Unix worker RLIMIT/fd-cleanup
confinement, macOS worker NoNetwork Seatbelt confinement, Linux
x86_64/aarch64 post-exec syscall-filter/fd-cleanup follow-ups, and unsupported
Linux worker-architecture fail-closed behavior for those slices,
Unix/macOS file-copy descriptor-parser/FileContents worker isolation, Windows
CLIPRDR same-artifact worker isolation, desktop video capability-advertising
wrapper closure, and Apple SDK-free source-conformance are closed in source and
gates; responder-side port-forward latent-connect and file write-response
forwarding follow-ups remain closed. The full cross-platform native
decoder/parser sandbox remains open beyond those worker slices.**

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
are capped before native handoff, remote cursor RGBA payloads must match checked
positive dimensions before the Flutter image-decode handoff, CLIPRDR
format/data/file-content payloads are capped, Android clipboard handoff now uses
the same aggregate item/count caps as desktop before JNI/platform forwarding,
Unix file-copy descriptor PDUs reject excessive descriptor counts before
allocation, Unix file-content reads are admitted through a per-connection
sliding request/byte budget before local file I/O, the Windows CLIPRDR Rust<->C
bridge re-checks those caps on both inbound server calls and callback-generated
outbound messages, rejects null callback pointers and null-plus-nonzero payloads
before copying into Rust memory, bounds callback C-string and local-file UTF-16
scans before conversion, tracks native-originated CLIPRDR format-data and
file-content requests before forwarding them to the peer, drops unsolicited,
duplicate, expired, or overlong peer responses before calling into the C bridge,
clears that pending Windows CLIPRDR state when the per-connection clipboard
channel is removed,
and the Windows CLIPRDR mapping table grows before append with zeroed new slots.
The C bridge also initializes and guards request/response state before
fail-closed exits and event signaling. This is a DoS/resource-bound,
state-accounting, and FFI-boundary closure, not the Appendix C #2b sandbox.

A later focused read-only TCP audit found no permanent owner-lockout exposure in
the pre-key flood path: the pre-key semaphore is acquired before spawn, released
after CPace success or timeout/failure, and the online-guess limiter is
per-source and decaying. The honest residual is active availability saturation:
a sustained TCP flood can temporarily fill the 256 pre-key slots until the
bounded handshake deadlines release them, so legitimate owners may see transient
capacity shedding during an active flood. That is the intended R-T1/R-T12
bounded-degradation posture, not an unbounded resource leak or permanent
lockout. The same audit identified three smaller TCP conformance gaps, now
closed in this worktree: `CloseReason` now waits for an R-T9 writer-drain
acknowledgement before the stream can drop, accept errors are counted and
periodically summarized with their errno class instead of merely rate-limited,
and authenticated connection ids are allocated only after CPace succeeds with a
non-wrapping/collision-avoiding counter.

The first Appendix C #2b implementation slices now move desktop viewer
VP8/VP9/AV1 software video decode, Opus packet decode, and peer-controlled zstd
decompression, plus normal desktop clipboard protobuf-to-native conversion and
SET, behind hidden same-artifact worker roles: `--native-video-worker`,
`--native-opus-worker`, `--native-zstd-worker`, and
`--native-clipboard-worker`. The video parent length-bounds the serialized
`VideoFrame` request, refuses a silent in-process desktop fallback if the worker
is unavailable, and accepts only raw RGB data below the native decoded-byte
ceiling back from the child. The audio parent length-bounds Opus packets,
refuses a silent in-process desktop fallback if the worker is unavailable,
accepts only PCM output bounded by the negotiated sample rate/channel count, and
kills the child if a decode round-trip exceeds the fixed timeout. The zstd
parent length-bounds compressed peer input, routes file-block, clipboard,
cursor, and terminal peer decompression through the child on desktop, reports
invalid or over-cap worker decode as failure, and refuses a silent in-process
desktop fallback. On Android/iOS, video decode advertising now returns no
supported decoders, mobile video decoder construction returns an unavailable
backend, mobile Opus decoder construction fails closed, and peer zstd
decompression fails closed instead of invoking native zstd in-process until a
platform worker/service boundary exists. Local persisted config decompression
stays in-process by design. The clipboard parent now sanitizes peer
`MultiClipboards` before the
handoff, rejects more than 16 items, caps aggregate clipboard content at 64 MiB,
serializes the sanitized protobuf to the child, and refuses a silent in-process
desktop SET fallback if the worker fails or times out. The workers have no
listener or session state; the video worker owns `scrap::codec::Decoder` and
rejects H.264/H.265 plus process-local texture outputs, the audio worker owns
`magnum_opus::Decoder`, the zstd worker owns the hostile-peer decompression
operation, and the clipboard worker owns the protobuf-to-`arboard::ClipboardData`
conversion plus platform clipboard write. Desktop video capability advertising
now routes through `NativeVideoDecoder::supported_decodings()` everywhere in the
Rust UI/session source, so the wrapper's H.264/H.265 suppression cannot be
bypassed by a direct `scrap::codec::Decoder::supported_decodings()` call outside
the worker module; `scripts/verify.sh` source-gates that raw call as absent
outside `src/native_video_worker.rs`. The worker parents now use one
persistent, named I/O thread per child plus a one-slot command channel and
per-request reply timeout, instead of spawning a new OS thread for each decode,
decompress, or clipboard SET round trip. Shared singleton worker admission for
desktop peer zstd decompression, normal clipboard SET, Unix file-descriptor PDU
parsing, and Unix file-content/file-list requests now uses non-blocking
`try_lock()` and fails closed if the worker is already processing another
request, so a slow or wedged child round trip cannot park unrelated sessions
behind that worker's timeout. On Linux, those child processes are
also spawned through a shared `hbb_common::native_worker_sandbox` pre-exec hook
that sets no-new-privs, parent-death SIGKILL, non-dumpability, and hard
resource ceilings for file descriptors, address space, heap/data, stack,
memlock, file size, and core dumps before the worker role starts parsing
hostile-peer content. After the hidden worker role has execed, the desktop
worker roles also call a post-exec entry hook. That hook closes inherited fds
above stdio with Linux `close_range(3, UINT_MAX)` plus `/proc/self/fd` fallback,
or desktop-Unix `/dev/fd` enumeration where `close_range` is not available. On
Linux, the helper test now spawns a child with a deliberately inherited fd above
`WORKER_NOFILE_LIMIT` and asserts that the worker-entry cleanup closes it; this
would have failed against the earlier bounded `3..WORKER_NOFILE_LIMIT` loop. On
non-Linux desktop Unix excluding Android/iOS, the parent
pre-exec hook also applies the same file-descriptor, address-space, heap/data,
stack, memlock, file-size, and core-dump resource ceilings before the worker
role starts. On macOS, the worker entry hook additionally applies the named
Seatbelt `kSBXProfileNoNetwork` profile before reading hostile-peer parser
requests. On Linux
x86_64/aarch64, the entry hook additionally installs a seccomp-BPF deny filter
before reading hostile-peer requests. The filter blocks direct TCP/UDP-capable
socket families, listener/accept syscalls, process exec/fork/vfork/process-like
clone, clone3, ptrace/BPF/perf/keyring, module, mount/chroot/namespace,
io_uring, pidfd, cross-process memory, reboot, hostname, quota/accounting,
mknod, and outbound process-signal syscalls while leaving local AF_UNIX client
sockets available for desktop clipboard backends. Unix/macOS file-copy FILEDESCRIPTOR
PDUs now parse through `--native-filedesc-worker`, and Unix/macOS local
file-list state plus FileContents reads now cross `--native-filecontents-worker`,
before Linux FUSE or macOS paste-task state consumes peer-driven file-copy
requests. Those workers have the same no-listener stdio shape, one-slot parent
I/O channel, fixed timeout/kill behavior, and Linux worker sandbox entry hook as
the other desktop worker slices. On Windows, the same worker parents hide the
child console, immediately assign the spawned child to a Job Object with an
active-process limit of one, kill-on-job-close, and a 1536 MiB per-process memory
ceiling, and keep that Job Object handle alive for the worker lifetime before
sending hostile-peer bytes; if post-spawn assignment fails, the parent kills/waits
the child and refuses fallback. Once the worker role starts, the Windows entry
hook applies process mitigation policy before parsing hostile-peer requests:
dynamic code is prohibited, legacy extension points are disabled, strict handle
checks are enabled, and remote or low-integrity image loads are refused. Windows
CLIPRDR now follows the same
same-artifact worker shape: the parent constructs a proxy context, the child owns
the FreeRDP/COM CLIPRDR context, callback-generated `ClipboardFile` events cross
bounded stdio frames, a bounded child-output queue, and bounded parent
per-connection `ClipboardFile` queues, the worker response wait is clamped to the
fixed 30-second CLIPRDR wait plus a 3-second parent grace, the child drops its
global event sender before joining the output thread on stdin EOF, the
`conn_id == 0` callback broadcast uses the bounded proxy event path instead of
writing into the child's process-local message channels, disconnect cleanup
crosses the worker boundary through a bounded clear-pending command, and the raw
in-process native CLIPRDR initializer is no longer public. This is not yet the
full sandbox: mobile peer clipboard handling, mobile media/zstd platform-worker
support if those features are to be enabled on mobile, Android's process model,
iOS's no-child-process model, a broader
macOS/desktop-Unix syscall or Seatbelt allowlist beyond NoNetwork, equivalent
seccomp support before enabling parser workers on Linux architectures outside
x86_64/aarch64, and equivalent timeout/kill/restart semantics for any remaining
native parser surfaces remain tracked residuals.

The requirements snapshot reviewed in this pass was:

```text
d34aad84c44e8b919e72130eecb78e3f06e3f19a8d667a2219402e8225c90dc1  requirements.html
```

`requirements.html` is intentionally not edited by implementation work.

## Recent Closures

- **TCP close-drain, accept-error accounting, and pre-key id accounting are
  closed.**
  `libs/hbb_common/src/tcp.rs` now routes the keyed writer task through
  `WriterCommand::{Frame,Drain}`. `FramedStream::flush_writer` and
  `Stream::flush_writer` enqueue a bounded drain acknowledgement, and
  `Connection::send_close_reason_no_retry` waits for that acknowledgement after
  queuing `CloseReason`; dropping the stream can no longer abort the writer
  before the close frame has had a chance to flush. `src/server.rs` now records
  accept errors through `ACCEPT_ERR_COUNT` plus `ACCEPT_ERR_LOG_STATE`, emitting
  periodic `count=... last_class=...` summaries with the most recent errno
  class. `create_tcp_connection` now allocates `get_new_id()` only after CPace
  succeeds, so failed pre-key attempts do not mutate authenticated-session id
  accounting; `get_new_id()` avoids unchecked `i32` wrap and live-id collision.
  `src/direct_service.rs` also drops the production parse `unwrap()` in the
  startup whitelist self-test. `scripts/verify.sh` gates the writer drain and
  counted accept-error summary. Validation: `git diff --check`, shell syntax
  checks, `bash scripts/verify.sh` (green), and `bash scripts/smoke-server.sh`
  (green; loopback-only, one `127.0.0.1:21118` TCP listener, zero UDP).
- **Windows CLIPRDR pending state is now cleared on channel removal, not only
  on clipboard reset/start messages.**
  `libs/clipboard/src/lib.rs::remove_channel_by_conn_id` now clears
  `platform::windows::clear_pending_cliprdr_conn(conn_id)` after removing a
  Windows CLIPRDR message channel, with the channel lock released before the
  pending-state mutex is touched. This closes the small disconnect cleanup gap
  where a password-correct peer could leave bounded pending
  format-data/file-content response slots alive until TTL pruning. This bullet is
  only state cleanup for the CLIPRDR bridge; the later `--native-cliprdr-worker`
  slice is the process-boundary closure, and neither slice is a Windows syscall
  sandbox.
- **Shared native-worker admission no longer blocks unrelated sessions behind a busy singleton.**
  Desktop peer zstd decompression, normal clipboard SET, Unix file-descriptor
  PDU parsing, and Unix file-content/file-list worker requests now use
  non-blocking `worker.try_lock()` admission. If the singleton worker is already
  in a bounded child round trip, the caller gets a fail-closed "worker busy;
  refusing to queue ..." error instead of waiting behind the timeout. This is a
  post-key DoS/resource-bound closure for the current worker slices, not a
  replacement for mobile process isolation or a future syscall allowlist
  sandbox. The Windows CLIPRDR process boundary is covered by the dedicated
  `--native-cliprdr-worker` slice below.
- **Linux aarch64 worker seccomp parity is wired at the filter path, not only in constants.**
  `libs/hbb_common/src/native_worker_sandbox.rs` now builds and installs the
  post-exec seccomp-BPF worker filter on Linux x86_64 and Linux aarch64. The
  BPF arch guard uses the per-target native audit constant, aarch64 has its
  syscall table for socket/bind/listen/accept/exec/clone plus the dangerous
  syscall deny set, and the unsupported-Linux-architecture fallback now returns
  an explicit `Unsupported` error instead of silently taking the old `Ok(())`
  path without a seccomp table. That makes parser-worker startup fail closed on
  Linux architectures outside x86_64/aarch64 until an equivalent filter exists.
  `scripts/verify.sh` now gates the aarch64 audit marker, syscall numbers,
  combined cfg, fallback exclusion, fail-closed fallback string, no `Ok(())`
  fallback, and arch test name. The runtime AF_INET seccomp probe still executes
  on the current Linux x86_64 validation host; an aarch64 runner would execute
  the same test under the aarch64 cfg.
- **Windows native worker children now get fail-closed Job Object lifetime,
  resource guards, and process mitigations.**
  `libs/hbb_common/src/native_worker_sandbox.rs` now exposes
  `apply_to_spawned_child`, because Windows needs a process handle before Job
  Object limits can be applied. The hook returns a must-use
  `WorkerProcessGuard`; each same-artifact native worker parent stores that guard
  beside its `Child`, immediately after `spawn()` and before writing
  hostile-peer bytes to the child. On failure the parent kills/waits the child and
  refuses the in-process fallback. The Windows hook hides the worker console and
  assigns the child to a Job Object with active-process, per-process memory, and
  kill-on-job-close limits. The worker-entry hook then installs Windows process
  mitigations before hostile-peer parsing: dynamic-code prohibition, extension
  point disablement, strict invalid-handle checking, and remote/low-integrity
  image-load refusal. This is a Windows resource/lifetime/exploit-mitigation
  companion for the existing worker slices, not a Windows AppContainer,
  restricted-token, or syscall-allowlist sandbox. The CLIPRDR-specific
  process-boundary closure is tracked in its own worker bullet below.
- **Non-mobile desktop Unix worker children now get RLIMIT ceilings and inherited-fd cleanup.**
  `libs/hbb_common/src/native_worker_sandbox.rs` now routes macOS/other
  desktop-Unix worker spawns, explicitly excluding Android/iOS, through a
  pre-exec resource hook instead of the old no-op.
  The hook applies the same file-descriptor, address-space, data/heap, stack,
  memlock, file-size, and core-dump ceilings used by the Linux workers, and the
  worker-entry hook closes inherited fds above stdio before parsing
  hostile-peer requests. The cleanup is no longer limited to the low
  `3..WORKER_NOFILE_LIMIT` range: Linux uses `close_range(3, UINT_MAX)` with a
  `/proc/self/fd` fallback, and other desktop Unix targets use `/dev/fd`
  enumeration. This is a resource/fd confinement slice only; it does not claim a
  macOS seatbelt profile, a BSD pledge/capsicum equivalent, or a syscall
  allowlist.
- **macOS native worker children now apply the Seatbelt NoNetwork profile before parsing peer input.**
  The macOS worker entry path closes inherited fds and then calls
  `sandbox_init(kSBXProfileNoNetwork, SANDBOX_NAMED, ...)` before the hidden
  worker role reads hostile-peer parser requests. `scripts/verify.sh` and
  `scripts/apple-conform-check.sh` now gate the macOS Seatbelt markers. This
  is a no-network Seatbelt slice for the worker roles; it does not claim a
  full custom macOS allowlist, a BSD pledge/capsicum equivalent, or an iOS
  no-child-process model.
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
- **Desktop native video, Opus, peer zstd, and normal clipboard SET cross worker
  processes with bounded parent I/O threads, Linux child confinement, Windows Job
  Object child limits, and Linux x86_64/aarch64 post-exec syscall filtering.**
  `src/native_video_worker.rs` adds the hidden same-artifact
  `--native-video-worker` role, entered from `src/core_main.rs`, and
  `VideoHandler` now owns `NativeVideoDecoder` instead of
  `scrap::codec::Decoder` directly. On desktop targets, VP8/VP9/AV1 frames are
  serialized to a length-bounded stdio request, decoded by a child process using
  `scrap::codec::Decoder`, and returned as raw RGB. The parent refuses a silent
  in-process desktop fallback if the worker is unavailable, and the worker
  rejects H.264/H.265 or process-local texture outputs. Each parent request is
  timeout-bounded and kills the worker child on timeout or transport failure.
  `src/native_audio_worker.rs` adds the analogous hidden same-artifact
  `--native-opus-worker` role, and `AudioHandler` now owns
  `NativeOpusDecoder` instead of `magnum_opus::Decoder` directly. On desktop
  targets, Opus packets are serialized to a length-bounded stdio request,
  decoded by the child, and returned as bounded f32 PCM. The parent refuses a
  silent in-process desktop fallback and kills the child on decode timeout or
  transport failure. On Android/iOS, `NativeVideoDecoder::supported_decodings`
  returns an empty `SupportedDecoding`, mobile video decoder construction returns
  `Unavailable`, and `NativeOpusDecoder::new` returns an error; mobile media
  remains unavailable until a platform worker/service boundary exists rather than
  parsing hostile-peer media in-process. `libs/hbb_common/src/compress.rs` adds
  the analogous hidden `--native-zstd-worker` role. Peer-controlled receive decompression now
  uses `peer_decompress`: desktop routes file blocks, compressed clipboard
  payloads, cursor colors, and terminal output through a length-bounded stdio
  worker with a fixed timeout and no in-process fallback. Android/iOS now
  refuse peer zstd decompression rather than invoking native zstd in-process;
  those compressed peer features stay unavailable on mobile until a platform
  worker/service boundary exists. Local config decompression still uses
  `decompress` directly because it is persisted local state, not a peer parser
  path. `scripts/verify.sh` gates all three worker args, wrappers/core entries,
  no-fallback strings, the mobile video/Opus/zstd no-in-process fallbacks,
  timeout/kill markers, peer zstd call sites, and absence of direct native
  decoder ownership in
  `src/client.rs`.
  `src/native_clipboard_worker.rs` adds the hidden same-artifact
  `--native-clipboard-worker` role. The desktop parent now sanitizes inbound
  `MultiClipboards`, rejects more than 16 items, caps aggregate content at
  64 MiB, sends only a length-bounded sanitized protobuf to the child, and logs
  then refuses any in-process desktop fallback if the worker fails. The child
  parses the protobuf, performs the `proto::from_multi_clipboards` native
  conversion, appends the owner marker through the shared clipboard helper, and
  calls the platform clipboard SET behind a 3-second parent timeout. The same
  slice fixes uncompressed `ClipboardData::Special` serialization so the content
  bytes, not the special-name bytes, are sent. The video, Opus, zstd, and
  clipboard parents now keep child stdio on a single named I/O thread with a
  one-slot command channel; timeout enforcement waits on the per-request reply
  channel and kills the child on timeout, avoiding the earlier hot-path
  per-round-trip `std::thread::spawn` pattern. `scripts/verify.sh` now gates the
  worker args/core entries, parent worker calls, no-fallback strings,
  timeout/kill markers, item and aggregate caps, native conversion helper,
  absence of parent-side direct `proto::from_multi_clipboards` use in
  `update_clipboard_`, the bounded I/O-thread channels, and absence of direct
  per-request `std::thread::spawn` in the worker parent files. The same parent
  spawn paths now call the shared worker sandbox helper before `spawn()` and the
  post-spawn confinement hook immediately after `spawn()`. On Linux the pre-spawn
  helper applies no-new-privs, parent-death SIGKILL, non-dumpability, and RLIMIT
  ceilings for fds/address-space/data/stack/memlock, regular-file size, and core
  dumps. On Windows the post-spawn hook hides the worker console, assigns the
  child to a Job Object with active-process, kill-on-job-close, and per-process
  memory limits, and returns a guard that each worker parent stores for the child
  lifetime before any hostile-peer request is sent to the child. The worker-role
  entrypoints then call the post-exec sandbox hook before request parsing. On
  Windows that hook applies process mitigations for dynamic-code prohibition,
  extension-point disablement, strict invalid-handle checking, and
  remote/low-integrity image-load refusal. On Unix-like worker children, the hook
  closes inherited fds above stdio using the wide fd cleanup path and, on Linux
  x86_64/aarch64, also installs a seccomp-BPF deny filter. The filter blocks
  AF_INET/AF_INET6/AF_PACKET/AF_NETLINK/AF_BLUETOOTH/AF_VSOCK
  socket creation, bind/listen/accept, exec/fork/vfork/process-like clone,
  clone3, process-signal syscalls, ptrace/BPF/perf/keyring, module loading,
  mount/chroot/namespace pivots, io_uring, pidfd fd theft, cross-process memory,
  reboot/hostname/quota/accounting, and device-node creation syscalls. It
  intentionally allows thread clones and local AF_UNIX client sockets so native
  decoders and Linux clipboard backends can still function. `scripts/verify.sh`
  gates the helper module, the confinement primitives, the resource-limit
  markers, all four pre-spawn call sites, all four post-exec worker-entry call
  sites, the inherited-fd cleanup, the seccomp x86_64/aarch64 markers, and a focused
  `hbb_common` unit sanity/runtime-probe test set for the worker-limit
  constants, filter constants, and kernel-enforced AF_INET socket denial. A
  separate `scripts/verify.sh` gate now requires the Windows Job Object
  primitives, process mitigation policy markers, winapi feature flags, must-use
  guard, kill-on-job-close limit, guard drop path, and fail-closed post-spawn hook
  call plus stored guard field at every same-artifact worker spawn site.
- **Remote cursor image handoff is dimension- and byte-checked before Flutter decode.**
  Peer cursor colors already route through `peer_decompress`, which on desktop
  means the same-artifact zstd worker rather than in-process zstd. `src/flutter.rs`
  now additionally requires positive checked cursor dimensions, a 1-megapixel
  cursor ceiling, and an exact `width * height * 4` RGBA byte count before
  serializing cursor colors into the UI event. `flutter/lib/models/model.dart`
  keeps a defensive mirror of the same pixel/byte cap, rejects oversized JSON
  before decoding, rejects malformed JSON, enforces exact list length and byte
  values, and only then calls `decodeImageFromPixels`. `scripts/verify.sh` gates
  the Rust and Dart cursor cap markers so this downstream image-decode guard
  cannot silently regress while the larger mobile/process-boundary residuals
  remain tracked separately.
- **Android clipboard aggregate caps now match desktop before platform handoff.**
  The Android single-clipboard and multi-clipboard inbound paths now both call
  `sanitize_multi_clipboards_for_native_proto` before serializing
  `MultiClipboards` to the Android clipboard manager JNI/FFI boundary. This
  keeps the same 16-item and 64 MiB aggregate cap on Android that desktop already
  applies before its worker/native handoff. `scripts/verify.sh` gates both the
  single-item and multi-item Android sanitizer call sites. This is still not the
  Android process-model sandbox; it closes the missing aggregate-accounting gap
  inside the current in-process Android residual.
- **Unix/macOS file-copy descriptor PDUs have a cheap descriptor-count ceiling
  and now parse out-of-process.**
  `libs/clipboard/src/platform/unix/filetype.rs` now rejects more than 4096 file
  descriptors and uses checked descriptor-size multiplication before
  `Vec::with_capacity` and descriptor parsing. The existing 16 MiB CLIPRDR
  format-data byte cap remains, but a peer can no longer use that cap to expand
  into roughly 28k FUSE/macOS pasteboard file descriptors. The regression test
  `rejects_too_many_file_descriptors_before_allocation` proves the oversized
  count header is rejected without allocating the full PDU, and
  `scripts/verify.sh` gates the count cap, checked-length marker, and test name.
  The production Linux FUSE and macOS pasteboard consumers now call
  `FileDescription::parse_file_descriptors_isolated`, which routes peer
  FILEDESCRIPTOR PDUs through a hidden same-artifact `--native-filedesc-worker`
  before FUSE or paste-task state consumes the file list. The parent bounds the
  binary PDU before the worker handoff, uses a single named I/O thread with a
  one-slot channel, kills the worker on timeout or transport failure, and has no
  silent in-process production fallback. The worker enters the shared native
  worker sandbox before parsing. Focused protocol tests cover a valid PDU and a
  parse-error response, and `scripts/verify.sh` gates the worker arg, isolated
  API, Linux/macOS production call sites, core worker entry, timeout marker,
  one-slot I/O channel, named I/O thread, sandbox hooks, and absence of the old
  production direct parse call.
  `libs/clipboard/src/platform/unix/serv_files.rs` now also keeps a 10-second
  per-connection sliding window for file-content requests and requested bytes
  before local file I/O, rejects negative lengths before signed-to-unsigned
  casts, masks the offset low/high words explicitly, and uses checked
  `offset + length` arithmetic. Regression tests cover request-count,
  byte-window, and negative-length rejection. `scripts/verify.sh` gates those
  accounting constants, the pre-I/O admission call, checked range arithmetic,
  offset word masking, the negative-length guard, and the regression test names.
  The same file now owns a hidden `--native-filecontents-worker` role for the
  Unix/macOS file-list cache, generated file-list PDU, and local FileContents
  size/range reads. The public `clear_files`, `sync_files`, `get_file_list_pdu`,
  and `read_file_contents` APIs route through a persistent same-artifact child
  with a one-slot I/O channel, fixed timeout/kill behavior, Linux worker sandbox
  pre-spawn and post-exec entry hooks, and no silent in-process fallback. On
  worker failure the parent logs/refuses the fallback and returns an error or an
  empty PDU as the existing API shape requires. The worker response protocol is
  compact binary for file-list and file-content results, so file bytes are not
  JSON-expanded across the parent/child pipe. Focused protocol tests cover
  sync/PDU generation, a file-range read through the worker loop, and parent
  rejection of a malicious oversized result-count response without count-sized
  allocation. `scripts/verify.sh` gates the worker arg, wrapper/core entry,
  public worker routing, no-fallback strings, bounded channel, named I/O thread,
  sandbox hooks, response cap, binary response tags/no JSON response regression,
  protocol tests, parent response-count test, and absence of the old
  `CLIP_FILES` in-process global.
- **Windows CLIPRDR Rust<->C bridge caps and null-boundary guards mirror the
  app-level CLIPRDR caps.**
  `src/clipboard_file.rs` already rejects oversized peer CLIPRDR format lists,
  format-data responses, file-content requests, and file-content responses
  before converting protobuf into `ClipboardFile`.
  `libs/clipboard/src/platform/windows.rs` now repeats those caps at the FFI
  bridge into the C `wf_cliprdr` context and at the native callback boundary
  before callback data is copied into Rust `Vec`s and forwarded to the session
  channel. The callback side also fail-closes on null structure pointers, null
  format arrays, null non-empty payloads, invalid or unterminated bounded
  C-string fields, oversized format names, excessive local-file counts, and
  unterminated over-cap UTF-16 file paths. `libs/clipboard/src/windows/wf_cliprdr.c`
  caps native data/file responses, zeroes new mapping-table slots before append,
  clears stale hmem/file responses before overwrite, and initializes/guards
  clipboard request state before cleanup or event signaling. The Rust FFI bridge
  now also tracks pending native-originated `FormatDataRequest` and
  `FileContentsRequest` messages, caps outstanding requests per connection and
  across the process, expires stale entries, clears them on clipboard reset
  events, rejects duplicate pending `(conn_id, stream_id)` file-content requests,
  and drops unsolicited or overlong peer responses before calling the C
  server-response handlers. This
  prevents a future Rust caller from bypassing the app-level cap, keeps
  callback-generated messages bounded, and reduces repeated bounded-response
  state-confusion pressure. `scripts/verify.sh` gates the Windows bridge
  constants, null/fail-closed markers, bounded string helper, per-connection and
  process-wide pending request/response accounting markers, and C request/event
  guard markers. This was a fail-closed
  DoS/memory-pressure/state-accounting/FFI-boundary guard; the process-boundary
  closure is tracked separately below.
- **Windows CLIPRDR now crosses a same-artifact worker process boundary.**
  `libs/clipboard/src/platform/windows.rs::create_cliprdr_context` now returns a
  `CliprdrWorkerProxy` instead of constructing the FreeRDP/COM CLIPRDR context in
  the parent process. The hidden `--native-cliprdr-worker` role owns the native
  CLIPRDR context and forwards callback-generated events to the parent through
  bounded stdio frames, a bounded child-output queue, and bounded parent
  per-connection `ClipboardFile` queues. The same retained Windows Job Object
  process-count/memory/kill-on-close guard used by the other same-artifact
  workers is kept for the child lifetime. The parent kills the child on timeout
  or transport failure, clamps the CLIPRDR wait to the fixed 30-second constant
  plus a 3-second response grace, clears the child's global event sender before
  joining the output thread, and routes the `conn_id == 0` format-list broadcast
  through the proxy event path instead of a process-local `VEC_MSG_CHANNEL`
  write. Disconnect cleanup now enqueues a bounded `ClearPendingConn` worker
  command and `EmptyClipboard` also clears child-side pending request accounting,
  so cleanup targets the process that owns the pending map. The raw
  `CliprdrClientContext::create` initializer plus the direct server helper
  functions are no longer public Rust APIs; parent code is expected to enter
  through the worker proxy factory.
  `scripts/verify.sh` gates the proxy factory, child native-context ownership,
  worker entrypoint, bounded frames/queues on both sides of the worker boundary,
  callback event forwarding, fixed/clamped timeout markers, event-sender cleanup,
  child pending cleanup, absence of public native-context constructors/helpers,
  and absence of direct `VEC_MSG_CHANNEL` use in the Windows CLIPRDR module.
  This closes the tracked Windows CLIPRDR process-boundary residual; it is still
  not a Windows syscall allowlist sandbox.
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

The Debian, Android, and Windows artifacts below were rebuilt after commit
`898947b` (`Gate desktop video codec capability wrapper`) and before the later
harness/status-only cleanup notes in this ledger. Those later edits do not
change the Rust/Flutter application binary inputs. `scripts/build-debian.sh`
ran in the disposable `rustdesk-fork-harness-deb-builder` build container with
the compile stage offline (`--network=none`) and
`SOURCE_DATE_EPOCH=1700000000`, then performed its double-build determinism
check. `scripts/build-android.sh` ran in the disposable
`rustdesk-fork-harness-android-builder` container with the compile stage offline
(`--network=none`), signed with the stable local Android key, and
`apksigner verify` reported one signer with v1/v2/v3 verification true.
`WINDOWS_BUILD_SOURCE=worktree scripts/build-windows-vm.sh` ran through the
transient Windows KVM path from the pinned golden qcow2, booted the per-build
VM with `--network none`, used loopback-only VNC, extracted/canonicalized the
`.exe` and `.msi`, and passed the default Windows double-build A==B assertion.

```text
bc29f067458c0f3020cdec5c76e487d36d81e63a2b6aaf8ceac320038dcb0406  dist/rustdesk-x86_64.deb
add41e1ec9f096b2c5e9858c5d29de7a72deecbe38fde0a29abc9a73a9d28635  dist/rustdesk-arm64.apk
6b61d0466a2d631ea03515b794ef531dad94ede3b4d0e2380e831768985ca821  dist/rustdesk-setup.exe
291a5349a77a157f9b699586ac5a3f15d5e1d1c3e8157b6246e6a6b110d75dab  dist/rustdesk.msi
```

Build evidence:

- Debian `scripts/build-debian.sh` passed its offline Docker double-build A==B
  gate after the desktop video capability-wrapper change.
- Android `scripts/build-android.sh` passed from the current source, and
  `apksigner verify` reported one signer with v1/v2/v3 verification true.
- Windows `WINDOWS_BUILD_SOURCE=worktree scripts/build-windows-vm.sh` passed
  from the current application source in the transient KVM VM path. The guest
  `build-log.txt` contains pre-canonical hashes; the final release hashes are
  the host-canonicalized `dist/*.sha256` values above.

## Validation Matrix

The following full validation matrix passed before the current desktop
native-worker source changes and full artifact rebuilds:

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

After the desktop native-video/native-Opus/native-zstd/native-clipboard worker
source changes, these source, runtime, Flutter/Dart, and advisory gates have
been re-run successfully:

```text
bash scripts/verify.sh                 # GREEN: VERIFY: all gates green
bash scripts/dart-verify.sh            # GREEN: flutter analyze lib/ + Dart gates
bash scripts/smoke-server.sh           # GREEN: loopback runtime smoke incl. R-T1 flood-shed
bash scripts/flutter-verify.sh         # GREEN: cargo check --features flutter,linux-pkg-config
bash scripts/audit.sh                  # GREEN: no unignored Rust advisories
bash scripts/dart-audit.sh             # GREEN: no unignored Pub advisories
bash scripts/apple-conform-check.sh    # GREEN: SDK-free Apple source conformance
bash scripts/native-codec-watch.sh     # GREEN: native codec watch ledger in sync
git diff --check                       # GREEN
```

After the bounded native-worker I/O-thread, Linux child-confinement, and Linux
x86_64/aarch64 post-exec syscall-filter/fd-cleanup follow-ups, these focused gates have
been re-run successfully:

```text
docker run ... cargo test -p hbb_common --lib native_worker_sandbox::tests --color never  # GREEN: 8 tests incl. x86_64/aarch64 arch guard, high-fd inherited-cleanup child probe, and AF_INET seccomp EPERM runtime probe
rustfmt --edition 2021 --check libs/hbb_common/src/native_worker_sandbox.rs libs/hbb_common/src/compress.rs src/native_video_worker.rs src/native_audio_worker.rs src/native_clipboard_worker.rs  # GREEN
bash -n scripts/verify.sh             # GREEN
bash scripts/verify.sh                # GREEN: VERIFY: all gates green, incl. bounded worker I/O-thread channels, Linux worker confinement/seccomp/fd-cleanup markers and call-sites, x86_64/aarch64 seccomp source markers, runtime high-fd cleanup and seccomp probe gates, and no per-request std::thread::spawn in worker parent files
git diff --check                       # GREEN
```

An attempted Docker-only `cargo check -p hbb_common --lib --target
aarch64-unknown-linux-gnu` installed the Rust aarch64 stdlib in the throwaway
container but stopped before checking `hbb_common` because `libsodium-sys`
requires an aarch64 pkg-config/sysroot that the devcheck image does not carry.
No host toolchain was modified. The current aarch64 evidence is therefore the
source-level cfg/number/fallback gates plus the shared filter-builder tests that
run on the current x86_64 Linux validation host; an aarch64 runner should run the
same `native_worker_sandbox::tests` set.

After the Unix/macOS file-copy descriptor worker source changes, these focused
and full gates have been re-run successfully:

```text
docker run ... cargo test -p clipboard --features unix-file-copy-paste --lib file_descriptor_worker_loop --color never  # GREEN: 2 protocol tests
docker run ... cargo check --features linux-pkg-config,unix-file-copy-paste --color never  # GREEN
bash -n scripts/verify.sh             # GREEN
rustfmt --edition 2021 --check libs/clipboard/src/platform/unix/filetype.rs libs/clipboard/src/platform/unix/mod.rs libs/clipboard/src/platform/unix/fuse/mod.rs libs/clipboard/src/platform/unix/macos/pasteboard_context.rs src/native_file_descriptor_worker.rs src/core_main.rs src/lib.rs  # GREEN
bash scripts/verify.sh                # GREEN: VERIFY: all gates green, incl. Unix/macOS file-copy descriptor worker protocol and source gates
git diff --check                       # GREEN
```

After the Unix/macOS file-copy FileContents worker source changes, these
focused and full gates have been re-run successfully:

```text
docker run ... cargo test -p clipboard --features unix-file-copy-paste --lib file_content_worker_loop --color never  # GREEN: 2 worker protocol tests
docker run ... cargo test -p clipboard --features unix-file-copy-paste --lib file_content --color never  # GREEN: 6 tests incl. accounting, negative-length, worker sync/PDU, worker range read, and malicious response-count rejection
docker run ... cargo check --features linux-pkg-config,unix-file-copy-paste --color never  # GREEN
bash -n scripts/verify.sh             # GREEN
rustfmt --edition 2021 libs/clipboard/src/platform/unix/serv_files.rs libs/clipboard/src/platform/unix/mod.rs src/lib.rs src/core_main.rs src/native_file_contents_worker.rs  # GREEN
bash scripts/verify.sh                # GREEN: VERIFY: all gates green, incl. Unix/macOS file-copy FileContents worker protocol and source gates
git diff --check                       # GREEN
```

After the Windows CLIPRDR Rust<->C bridge cap/null/bounded-read/request-accounting
source changes, these focused source gates have been re-run successfully:

```text
bash scripts/verify.sh                 # GREEN: VERIFY: all gates green, incl. CLIPRDR FFI cap/null/bounded-read/pending-state gates
rustfmt --edition 2021 --check libs/clipboard/src/platform/windows.rs  # GREEN
git diff --check                       # GREEN
```

After the Windows CLIPRDR pending-state disconnect cleanup, these focused
Docker-only gates have been re-run successfully:

```text
docker run ... rustfmt --edition 2021 --check libs/clipboard/src/lib.rs libs/clipboard/src/platform/windows.rs  # GREEN after installing rustfmt inside the throwaway container
docker run ... bash -n scripts/verify.sh  # GREEN
docker run ... source-grep gate for platform::windows::clear_pending_cliprdr_conn(conn_id) in remove_channel_by_conn_id + verify.sh marker  # GREEN
docker run ... git diff --check           # GREEN
docker run ... cargo check -q -p clipboard --lib --color never  # GREEN; only an unrelated pre-existing hbb_common redundant secretbox-import warning
bash scripts/verify.sh                    # GREEN: VERIFY: all gates green, incl. the Windows CLIPRDR disconnect-pending-clear source gate
```

After the remote cursor UI image-handoff guard changes, these focused source and
Dart gates have been re-run successfully:

```text
bash scripts/verify.sh                 # GREEN: VERIFY: all gates green, incl. cursor RGBA exact-len gates
bash scripts/dart-verify.sh            # GREEN: flutter analyze lib/ + Dart gates
rustfmt --edition 2021 src/flutter.rs  # GREEN
git diff --check                       # GREEN
```

After the Android clipboard aggregate-cap parity and Unix file-copy descriptor
count-cap changes, these focused gates have been re-run successfully:

```text
docker run ... cargo test -p clipboard --features unix-file-copy-paste file_list_test::rejects_too_many_file_descriptors_before_allocation  # GREEN
docker run ... cargo test -p clipboard --features unix-file-copy-paste file_content_request  # GREEN: request-count, byte-window, negative-length guards
docker run ... cargo test -p clipboard --features unix-file-copy-paste 'platform::unix'  # GREEN: 7 Unix clipboard/FUSE/file-serving tests
bash scripts/verify.sh                 # GREEN: VERIFY: all gates green, incl. Android clipboard aggregate, Unix descriptor-count, and Unix file-content accounting gates
rustfmt --edition 2021 src/clipboard.rs libs/clipboard/src/platform/unix/filetype.rs libs/clipboard/src/platform/unix/local_file.rs libs/clipboard/src/platform/unix/serv_files.rs  # GREEN
git diff --check                       # GREEN
```

After the Windows native-worker process-mitigation entry hook and gate update,
these focused and full gates have been re-run successfully:

```text
docker run ... rustfmt --edition 2021 --check libs/hbb_common/src/native_worker_sandbox.rs  # GREEN in a disposable rust:1.75-slim container
docker run ... bash -n scripts/verify.sh  # GREEN in a disposable bash:5.2 container
docker run ... cargo check /tmp/rd-win-mitigation-check --target x86_64-pc-windows-msvc  # GREEN: cfg(windows) native_worker_sandbox.rs Job Object + process-mitigation branch typechecked without the full native dependency graph
bash scripts/verify.sh                    # GREEN: VERIFY: all gates green, incl. native-worker post-spawn confinement hook, stored guard, Windows Job Object, and Windows process-mitigation source gates
git diff --check                          # GREEN after this ledger update
```

After the mobile media fail-closed change, these focused and full gates have
been re-run successfully:

```text
docker run ... rustfmt --edition 2021 --check src/native_video_worker.rs src/native_audio_worker.rs  # GREEN in a disposable rust:1.75-slim container
docker run ... cargo check /tmp/rd-mobile-media-check --target aarch64-linux-android  # GREEN: cfg(android) mobile media wrappers typechecked with local stubs, no NDK/link step
docker run ... cargo check /tmp/rd-mobile-media-check --target aarch64-apple-ios      # GREEN: cfg(ios) mobile media wrappers typechecked with local stubs, no Apple SDK/link step
bash scripts/verify.sh                    # GREEN: VERIFY: all gates green, incl. mobile video/Opus no-in-process fallback and no-advertise source gates
git diff --check                          # GREEN after this ledger update
```

After the desktop-Unix Android/iOS cfg correction, macOS worker Seatbelt
NoNetwork entry hook, and unsupported-Linux-architecture fail-closed worker
entry fallback, these focused and full gates have been re-run successfully:

```text
docker run ... rustfmt --edition 2021 --check libs/hbb_common/src/native_worker_sandbox.rs  # GREEN
docker run ... bash -n scripts/verify.sh scripts/apple-conform-check.sh  # GREEN
docker run ... cargo test -p hbb_common --lib native_worker_sandbox::tests --color never  # GREEN: 8 Linux worker sandbox tests incl. high-fd cleanup and seccomp runtime probes
docker run ... cargo check temp include-harness --target x86_64-apple-darwin/aarch64-linux-android/x86_64-pc-windows-msvc  # GREEN: macOS/Android/Windows cfgs typecheck without the full native dependency graph
docker run ... cargo check temp include-harness --target armv7-unknown-linux-gnueabihf  # GREEN: unsupported Linux worker-arch fail-closed branch typechecks
bash scripts/apple-conform-check.sh       # GREEN: Apple source gate passes, incl. macOS worker Seatbelt NoNetwork assertion and SDK-free Rust-only boundary
bash scripts/verify.sh                    # GREEN: VERIFY: all gates green, incl. unsupported Linux worker-arch fail-closed, macOS Seatbelt NoNetwork, and desktop-Unix excluding Android/iOS platform hook gates
docker run ... git diff --check           # GREEN after this ledger update
```

After the mobile peer-zstd fail-closed change, these focused and full gates have
been re-run successfully:

```text
docker run ... rustfmt --edition 2021 --check libs/hbb_common/src/compress.rs libs/hbb_common/src/native_worker_sandbox.rs  # GREEN
docker run ... bash -n scripts/verify.sh scripts/apple-conform-check.sh  # GREEN
docker run ... cargo test -p compress_it --color never  # GREEN: 4 compression tests
bash scripts/verify.sh                    # GREEN: VERIFY: all gates green, incl. mobile peer-zstd no-in-process fallback source gate
docker run ... cargo check -p hbb_common --lib --target aarch64-linux-android  # STOPPED before hbb_common Rust code in openssl-sys/ring cross-native setup (missing Android OpenSSL/pkg-config and aarch64-linux-android-clang in this container)
docker run ... git diff --check           # GREEN after this ledger update
```

After the shared native-worker busy-admission change and the high-fd cleanup
runtime probe, these focused and full gates have been re-run successfully:

```text
docker run ... rustfmt --edition 2021 --check libs/hbb_common/src/native_worker_sandbox.rs libs/hbb_common/src/compress.rs src/native_clipboard_worker.rs libs/clipboard/src/platform/unix/filetype.rs libs/clipboard/src/platform/unix/serv_files.rs  # GREEN
docker run ... bash -n scripts/verify.sh  # GREEN
docker run ... cargo test -p hbb_common native_worker_sandbox --lib --color never  # GREEN: 8 Linux worker sandbox tests incl. inherited high-fd cleanup child probe + AF_INET seccomp EPERM runtime probe
bash scripts/verify.sh                    # GREEN: VERIFY: all gates green, incl. shared-worker non-blocking busy-admission source gates, high-fd cleanup runtime probe, native worker sandbox helper tests, Unix descriptor/file-content worker protocol tests, main crate compile, and R-A6 done-set
docker run ... git diff --check           # GREEN after this ledger update
```

After the latest post-reload validation of this dirty worktree, the full
source/runtime/advisory/UI matrix was re-run successfully:

```text
git diff --check                       # GREEN
bash scripts/verify.sh                 # GREEN: VERIFY: all gates green, incl. native-worker gates, R-T1/R-T12, R-A6 done-set, and main-crate compile
bash scripts/smoke-server.sh           # GREEN: loopback-only runtime smoke; one 127.0.0.1:21118 TCP listener, zero UDP, R-T1 capacity-shed, owner-safe limiter, forged-frame rejection, no plaintext canary
bash scripts/native-codec-watch.sh     # GREEN: vcpkg native set and manual advisory ledger in sync
bash scripts/audit.sh                  # GREEN: no unignored Rust advisories against the pinned snapshot
bash scripts/dart-audit.sh             # GREEN: no unignored Pub advisories against the pinned OSV snapshot
bash scripts/dart-verify.sh            # GREEN: flutter analyze lib/ zero errors + address-validator tests + Section 19 Dart-layer greps
bash scripts/flutter-verify.sh         # GREEN: FRB Rust bridge/cargo check gate; Dart-side ffigen warning remains nonfatal and covered by dart-verify
bash scripts/apple-conform-check.sh    # GREEN: SDK-free Apple source-conformance boundary, incl. macOS worker Seatbelt assertion
```

After the Windows CLIPRDR worker-boundary, bounded-parent-queue,
worker-pending-cleanup, private-native-constructor, fixed-timeout,
event-sender cleanup, and zero-conn broadcast-proxy follow-up, the exact current
worktree was re-run through the focused source and full Docker-backed
verification gates:

```text
rustfmt --edition 2021 libs/clipboard/src/lib.rs libs/clipboard/src/platform/windows.rs src/client/io_loop.rs src/ui_cm_interface.rs  # GREEN
docker run ... cargo check -p clipboard --lib --color never   # GREEN; only an unrelated pre-existing hbb_common redundant secretbox-import warning
bash -n scripts/verify.sh                                     # GREEN
git diff --check                                              # GREEN
bash scripts/verify.sh                                        # GREEN: VERIFY: all gates green, incl. Windows CLIPRDR worker proxy/source gates, bounded parent ClipboardFile queues, fixed/clamped timeout markers, event-sender cleanup, worker-side pending cleanup, no public native CLIPRDR constructor/helper, no direct VEC_MSG_CHANNEL use in windows.rs, native-worker gates, R-T1/R-T12, R-A6 done-set, and main-crate compile
```

After the desktop video capability-advertising wrapper closure, the focused
source gate and full Docker-backed verifier were re-run:

```text
git diff --check          # GREEN
bash scripts/verify.sh    # GREEN: VERIFY: all gates green, incl. the raw supported_decodings bypass source gate
bash scripts/build-debian.sh # GREEN: offline Docker double-build A==B, bc29f067458c0f3020cdec5c76e487d36d81e63a2b6aaf8ceac320038dcb0406
ANDROID_KEYSTORE=... ANDROID_KEYSTORE_PASS_FILE=... bash scripts/build-android.sh # GREEN: offline Docker build, apksigner verified one signer, add41e1ec9f096b2c5e9858c5d29de7a72deecbe38fde0a29abc9a73a9d28635
WINDOWS_BUILD_SOURCE=worktree bash scripts/build-windows-vm.sh # GREEN: transient KVM VM, --network none, loopback-only VNC, double-build A==B, exe=6b61d0466a2d631ea03515b794ef531dad94ede3b4d0e2380e831768985ca821, msi=291a5349a77a157f9b699586ac5a3f15d5e1d1c3e8157b6246e6a6b110d75dab
```

The Windows VM build path is now current for the application source represented
by the artifact hashes above. The separate build-host cleanliness issue remains
host-state, not application artifact state: an older harness revision installed
system libvirt and left the host default network behind. The current per-build
Windows VM itself used `--network none` and only loopback VNC, but the host still
needs privileged cleanup of the old `virbr0`/dnsmasq/IP-forwarding state before
the build host satisfies R-B11/R-B11a end-to-end.

Coverage highlights from the full pre-worker matrix, with the post-native-worker
`verify.sh`/Dart/smoke/Flutter/audit/Apple/native-codec reruns noted above:

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

- **Native viewer decoder sandbox beyond the first desktop worker slices.** The
  biggest remaining code hardening target beyond route security is the
  documented viewer residual: a deliberately connected, password-correct
  hostile peer can still feed media/content bytes into native parsers. The
  current source length-bounds and allocation-bounds those handoffs, and desktop
  VP8/VP9/AV1 software video, desktop Opus packet decode, desktop
  peer-controlled zstd decompression, and desktop normal clipboard SET now cross
  same-artifact worker processes instead of being parsed directly in the main
  process, with parent-side timeouts that kill the child on hung round-trips.
  Linux worker children now run with no-new-privs, parent-death kill,
  non-dumpability, fd/memory/file-size/core resource ceilings, inherited-fd
  cleanup, and a Linux x86_64/aarch64 post-exec seccomp deny filter. Windows
  worker children are now hidden and assigned to a Job Object with active-process,
  kill-on-job-close, and per-process memory limits before hostile-peer bytes are
  sent, with the Job Object guard retained for the child lifetime; worker entry
  also applies process mitigations for dynamic code, extension points, strict
  handle checks, and remote/low-integrity image loads. Mobile media decode and
  peer zstd now fail closed until platform workers/services exist instead of
  parsing hostile-peer bytes in-process. That is not yet a complete
  low-privilege sandbox. Remaining work includes mobile peer clipboard process
  isolation, mobile media/zstd platform-worker support if those peer features are
  to be enabled on mobile, Android's separate-process service shape, an iOS
  product-scope decision for the
  no-child-process model, Windows low-privilege/AppContainer or syscall-allowlist
  hardening beyond Job Object/process-mitigation guards, a broader
  macOS/desktop-Unix syscall or Seatbelt allowlist beyond NoNetwork, equivalent seccomp support before enabling
  parser workers on Linux architectures outside x86_64/aarch64 and/or a future
  true allowlist sandbox, and timeout/kill/restart semantics for the remaining
  parser surfaces.
  The separate native codec CVE/advisory watch is wired and source-gated, but it
  is only a tracking/coverage mechanism for vcpkg C/C++ libraries, not a
  substitute for those boundaries.

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
in-repository hardening work is the larger native viewer decoder sandbox beyond
the desktop software-video, Opus, peer-zstd, and normal-clipboard worker slices;
the native-codec advisory watch, the in-process handoff bounds, and the desktop
worker gates are present, and Linux x86_64/aarch64 worker children have fd
cleanup, resource ceilings, and a post-exec syscall deny filter. Linux
architectures without an implemented worker seccomp table now fail closed at
worker entry instead of parsing hostile content with only partial confinement.
Those closures deliberately do not claim full sandboxing or current CVE freedom.
macOS worker children now apply the Seatbelt NoNetwork profile at worker entry,
but that is not a full custom macOS allowlist or a BSD pledge/capsicum
equivalent. Windows same-artifact worker children, including the CLIPRDR worker,
now get hidden-window Job Object active-process, kill-on-job-close, and
process-memory limits with a retained guard, plus entry-time process mitigations
for dynamic code, extension points, strict handle checks, and remote/low-integrity
image loads, but that is not a Windows AppContainer, restricted-token, or syscall
allowlist sandbox. Windows CLIPRDR now has app-level and Rust<->C bridge length
caps plus null/bounded-read fail-closed guards, pending request/response
accounting, and a same-artifact worker boundary. Android clipboard
handoff now has aggregate item/byte caps, but Android clipboard still lacks a
separate process model. Mobile media decode now fails closed/no-advertises, and
mobile peer zstd now fails closed rather than using in-process native zstd;
enabling mobile media decode or compressed peer zstd features still requires a
platform worker/service boundary. Unix/macOS file-copy
clipboard now has descriptor-count caps, a same-artifact worker boundary for peer FILEDESCRIPTOR
PDU parsing, per-connection file-content request/byte accounting, and a
same-artifact worker boundary for the local file-list cache/PDU generation and
FileContents size/range reads. Windows and Android platform-native
socket-surface logic is present and source-gated. The Debian, Android, and
Windows artifacts recorded above are refreshed for the current application
source. The remaining local build-host residual is the old harness-created
system libvirt default network: the host has shown `virbr0`,
`192.168.122.1:53/tcp+udp`, `0.0.0.0%virbr0:67/udp`, and
`net.ipv4.ip_forward=1`. `.harness-state/provisioned` records that the harness
installed `libvirt-daemon-system`, so cleanup is allowed to reverse it, but this
session lacks noninteractive sudo. `scripts/cleanup.sh --build-host-network`
now performs the manifest-gated teardown and fails closed without privileges;
`scripts/host-provision.sh` no longer installs `libvirt-daemon-system` and
pre/post-audits for this class before future provisioning.

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
