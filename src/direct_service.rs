use hbb_common::{
    allow_err,
    config::{self, Config, PermanentPasswordPrsRead},
    log, sleep, tokio,
};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::{anyhow::anyhow, ResultType};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "android")]
use std::sync::Mutex;

#[cfg(not(target_os = "android"))]
use crate::server::check_zombie;
use crate::server::{new as new_server, ServerPtr};

// R-D4 (Stage 2): the rendezvous-mediator PROTOCOL is removed from the tree. The
// registration loop, `register_pk`, the relay / punch-hole / intranet handlers, the
// UDP/KCP path (`start_ipv6`/`udp_nat_listen` + the `kcp_stream` accept), the `Sink`,
// `start_all` itself, and `CheckIfResendPk`'s resend logic are gone — they were
// reachable only from the bypassed `start_all` (R-D4 Stage 1). This makes `register_pk`,
// `request_relay`, the relay-punch protocol and the KCP accept SYMBOL-ABSENT (R-SV10),
// not merely unreachable.
//
// What remains here is the direct-only service path — `start_direct_only` ->
// `direct_server`, the single v4, PAKE-gated TCP listener (R-F4/R-D5) — plus the R-A4
// startup + post-listen socket-surface self-checks. The inherited no-op SHELLS are all REMOVED:
// `RendezvousMediator::restart()` + its callers, `CheckIfResendPk`, and the deploy shell
// (NEEDS_DEPLOY + reset_needs_deploy_notification + the `Data::Deployed` IPC arm/sender, R-SV6(c)).
// And this file is now RENAMED from the misleading inherited name to `direct_service` (R-D4 Stage 3):
// it is honestly the direct-only service module, so the old mediator module name is grep-absent
// (R-SV10). Nothing of the mediator survives in name or symbol — only the direct listener remains.

fn get_direct_port() -> i32 {
    // R-F4: the direct port is the single PINNED compile-time constant 21118 — never
    // a runtime port option read from config (an override R-S12 forbids) and never
    // the inherited rendezvous-port-plus-two derivation (which would silently shift
    // the port and desync the §10.4 CPace `CI` KAT be16(21118)=527e). One mode, one
    // constant; a different port is a build-time change to config::DIRECT_PORT.
    config::DIRECT_PORT
}

#[cfg(any(target_os = "android", test))]
#[derive(Default)]
struct AndroidListenerLifecycle {
    generation: u64,
    rebuild_epoch: u64,
    active: bool,
}

#[cfg(any(target_os = "android", test))]
impl AndroidListenerLifecycle {
    fn begin_generation(&mut self) -> Option<u64> {
        let Some(next) = self.generation.checked_add(1) else {
            self.active = false;
            return None;
        };
        self.generation = next;
        self.rebuild_epoch = 0;
        self.active = true;
        Some(next)
    }

    fn stop_generation(&mut self, expected_generation: u64) -> bool {
        if !self.active || expected_generation == 0 || self.generation != expected_generation {
            return false;
        }
        self.active = false;
        true
    }

    fn request_rebuild(&mut self, expected_generation: u64) -> Option<u64> {
        if !self.active || expected_generation == 0 || self.generation != expected_generation {
            return None;
        }
        let Some(next) = self.rebuild_epoch.checked_add(1) else {
            self.active = false;
            return None;
        };
        self.rebuild_epoch = next;
        Some(next)
    }

    fn snapshot(&self, expected_generation: u64) -> Option<u64> {
        (self.active && expected_generation != 0 && self.generation == expected_generation)
            .then_some(self.rebuild_epoch)
    }
}

#[cfg(target_os = "android")]
static ANDROID_LISTENER_LIFECYCLE: Mutex<AndroidListenerLifecycle> =
    Mutex::new(AndroidListenerLifecycle {
        generation: 0,
        rebuild_epoch: 0,
        active: false,
    });

/// R-D7a / R-S9 / R-G1 (verify-ground-truth): the REAL, live state of the direct listener —
/// `true` iff `direct_server` currently holds a bound `TcpListener` on the pinned v4 port. It is
/// the single source of truth the UI reads for "reachable on :21118" (via the FFI
/// `main_get_common("direct-listener-bound")`), NOT a Dart-side optimistic flag: on Android
/// `serverModel.isStart` is set before `init_service` and never synced from the native service, so
/// after a boot listener-only start (BR-17) it is `false` while the listener is UP — the lie this
/// signal replaces. It is published by an RAII `ListenerBoundGuard` (below) stored INSIDE the bound
/// listener's `Option`, so it is tied to the listener's LIFETIME and cleared on EVERY teardown path
/// — see that guard's doc. Reflects reachability within the accept-loop poll (~1s).
static DIRECT_LISTENER_BOUND: AtomicBool = AtomicBool::new(false);

/// R-D7a / R-G1: read the live direct-listener-bound signal above — the true socket state the UI
/// surfaces as "reachable on :21118". Compiles on every target (the FFI key handler is not
/// Android-gated); on the desktop `--service` it mirrors the process/unit-lifetime listener.
pub fn is_direct_listener_bound() -> bool {
    DIRECT_LISTENER_BOUND.load(Ordering::SeqCst)
}

/// R-G1 (verify-ground-truth, R2-1 fix): RAII guard that ties `DIRECT_LISTENER_BOUND` to the bound
/// listener's LIFETIME. `new()` (called only after a successful `listen_any_v4`) publishes `true`;
/// its `Drop` publishes `false`. It is held INSIDE the `Option<(TcpListener, ListenerBoundGuard)>`
/// in `direct_server`, so the flag is cleared on EVERY teardown — the graceful `return`s (R-T9
/// shutdown, R-D7a Android service-stop), the `listener = None` replacements (R-T13 rebuild, the
/// R-S9 no-password park), AND — decisively — the runtime-abort of the `direct_server` task future
/// when `start_direct_only`'s keep-alive returns after a stop: dropping the future runs `Drop` for
/// its live locals (the `listener` held across the `accept().await`), which a bare `store(false)`
/// statement placed AFTER that `.await` would never reach. Because only a thread that binds
/// constructs a guard, and port exclusivity means at most one thread holds the bound listener at a
/// time, a superseded never-bound Android thread cannot clear the live one (this subsumes the old
/// per-thread `i_am_bound` gate).
struct ListenerBoundGuard;
impl ListenerBoundGuard {
    fn new() -> Self {
        DIRECT_LISTENER_BOUND.store(true, Ordering::SeqCst);
        ListenerBoundGuard
    }
}
impl Drop for ListenerBoundGuard {
    fn drop(&mut self) {
        DIRECT_LISTENER_BOUND.store(false, Ordering::SeqCst);
    }
}

/// R-D7a: the Android controlled-side server is OWNED by the mandatory `MainService` foreground
/// service and shares its lifetime — there is no headless `--service` on Android (a Flutter
/// `cdylib`). `ANDROID_LISTENER_LIFECYCLE` serializes generation begin, exact-generation stop, and
/// exact-generation network rebuild. A callback queued by an obsolete service therefore cannot
/// advance the rebuild epoch after a replacement service owns the listener. The accept loop and
/// keep-alive compare the generation they were STARTED UNDER against the current active ownership
/// snapshot. Exact deactivation means "the owning service was destroyed, tear the listener down";
/// a newer begin supersedes an older generation, while an admitted rebuild advances only the
/// current generation's epoch and rebinds the same port.
///   - `MainService.onCreate` -> JNI `startServer` calls `android_begin_generation()` and hands its
///     RETURN by value into the spawned server thread (through `start_server` -> `start_direct_only`
///     -> `direct_server`), so the accept loop + keep-alive run under EXACTLY that generation —
///     never a late lifecycle-state read inside the thread. That timing distinction
///     is load-bearing (N1/F1): a late load could read a generation a concurrent `stopServer`/
///     `startServer` had already superseded (or the post-stop value itself), letting a stopped
///     service's thread believe it was current and keep the listener bound ("Stop doesn't stop").
///     With the captured value, any later begin changes the generation and an exact stop deactivates
///     it, so the same lifecycle snapshot rejects this thread in either case.
///   - `MainService.onDestroy` -> JNI `stopServer` calls `android_request_stop()` with the exact
///     generation it owns. A delayed obsolete Service cannot supersede a replacement generation.
///     `direct_server` observes deactivation or supersession at its loop top and `return`s (dropping
///     the `TcpListener` local -> socket closed), and `start_direct_only` observes it in its
///     keep-alive poll and `return`s (so the JNI thread + its `#[tokio::main]` runtime unwind,
///     aborting any live accept task -> socket closed). No config write — the stop is the OS
///     foreground-service lifecycle, not an option (the dead `stop-service` writes are deleted; the
///     key is pinned `N`).
/// Desktop/iOS never touch this: their listener lifetime is the process / `systemd`-unit lifetime
/// (R-X9), so the whole mechanism is `#[cfg(target_os = "android")]`.
/// R-D7a: establish a fresh Android server generation at service start (JNI `startServer`);
/// returns the new generation the spawned server's accept loop + keep-alive run under.
#[cfg(target_os = "android")]
pub fn android_begin_generation() -> u64 {
    let mut lifecycle = ANDROID_LISTENER_LIFECYCLE.lock().unwrap();
    match lifecycle.begin_generation() {
        Some(generation) => generation,
        None => {
            log::error!("R-D7a: Android server generation exhausted");
            0
        }
    }
}

/// R-D7a: deactivate the exact owned Android server generation (JNI `stopServer` on
/// `MainService.onDestroy`). The graceful teardown twin of process-death fd close: the running
/// accept loop + keep-alive observe that exact generation becoming inactive and unwind, closing the
/// listening socket. Stop does not allocate a generation ID; only a successful begin does.
#[cfg(target_os = "android")]
pub fn android_request_stop(expected_generation: u64) -> bool {
    let mut lifecycle = ANDROID_LISTENER_LIFECYCLE.lock().unwrap();
    if lifecycle.stop_generation(expected_generation) {
        log::info!(
            "R-D7a: Android stopServer — deactivated owned listener generation {expected_generation}"
        );
        true
    } else {
        log::warn!(
            "R-D7a: rejected stale or inactive Android stopServer generation {expected_generation}; current generation is {}",
            lifecycle.generation
        );
        false
    }
}

/// R-T13/R-D7a: request a listener rebuild only for the exact current service generation.
/// Generation validation and epoch advancement occur under the same lock as begin/stop, so a stale
/// callback cannot pass validation and then advance the replacement generation's rebuild epoch.
#[cfg(target_os = "android")]
pub fn android_request_listener_rebuild(expected_generation: u64, reason: &str) -> bool {
    let mut lifecycle = ANDROID_LISTENER_LIFECYCLE.lock().unwrap();
    match lifecycle.request_rebuild(expected_generation) {
        Some(epoch) => {
            log::info!(
                "R-T13: direct listener rebuild requested by exact Android service generation {expected_generation} ({reason}); epoch={epoch}"
            );
            true
        }
        None => {
            log::warn!(
                "R-T13: rejected stale or exhausted Android listener rebuild generation {expected_generation}; current generation is {}",
                lifecycle.generation
            );
            false
        }
    }
}

/// Return the rebuild epoch only while `expected_generation` is still the exact current Android
/// service generation. The one snapshot prevents a stop/restart from interleaving between a
/// generation check and an independently loaded rebuild counter.
#[cfg(target_os = "android")]
fn android_listener_lifecycle_snapshot(expected_generation: u64) -> Option<u64> {
    ANDROID_LISTENER_LIFECYCLE
        .lock()
        .unwrap()
        .snapshot(expected_generation)
}

/// R-A4 startup self-check: refuse to listen unless the controlled-side runtime
/// invariants hold. Defense-in-depth over the R-S16 funnel — confirm the policy
/// reads back pinned (verification-method/approve-mode) through Config::get_option
/// and that the empty BUILTIN/HARD override funnels carry no managed value. A
/// violation returns an error before admission: the desktop entry turns it into a
/// nonzero process outcome before starting local IPC, while Android/iOS share the
/// interactive app process and surface the reason without exiting. The permanent-password
/// credential is deliberately NOT checked here (finding D): an empty password fails
/// closed at RUNTIME via the `direct_server` park (nothing bound) + the per-connection
/// R-S9 bail (server.rs), so the old startup exit for that case — redundant with the
/// park and fatal to the shared-process Android app — is gone. The companion
/// bound-socket-surface assertion (exactly one TCP v4 listener on the pinned port,
/// zero UDP of any kind) runs post-listen in `assert_socket_surface` — it needs the
/// listener up first, so it lives at the bind site rather than here.
// R-A4 is UNCONDITIONAL (R-R2b): every shipped binary refuses to listen unless the
// pinned policy + the one-TCP/zero-UDP surface verify — never behind a feature flag.
pub(crate) fn assert_startup_invariants() -> Result<(), String> {
    let mut ok = true;
    if Config::get_option(hbb_common::config::keys::OPTION_VERIFICATION_METHOD)
        != "use-permanent-password"
    {
        log::error!("R-A4: verification-method is not pinned to use-permanent-password");
        ok = false;
    }
    if Config::get_option(hbb_common::config::keys::OPTION_APPROVE_MODE) != "password" {
        log::error!("R-A4: approve-mode is not pinned to password");
        ok = false;
    }
    // NOTE (finding D): the empty-permanent-password branch was REMOVED here. An empty
    // permanent password already fails closed at RUNTIME without a startup exit — the
    // `direct_server` accept loop PARKS (binds no listener) while the PRS is empty
    // (the R-S9 park below) and every connection is refused per-connection (server.rs,
    // R-S9 bail). The startup exit was BOTH redundant with that park AND fatal on
    // Android, where the Rust core shares the interactive app process:
    // std::process::exit(1) crashed the whole app when "Start service" was tapped before
    // a password was set. Routing the empty-password case through the park keeps it
    // fail-closed on every platform, and a desktop --service that starts before
    // `rustdesk --password` provisioning now PARKS rather than crash-loops under systemd.
    // R-X12: the capture+input backend is compile-pinned to X11 (is_x11() == true). Assert it at
    // startup so any future un-pin that lets is_x11() go false (a Wayland/misdetected session) refuses
    // to listen rather than silently failing X11 capture — the runtime half of the X11 pin.
    #[cfg(target_os = "linux")]
    if !crate::platform::linux::is_x11() {
        log::error!("R-X12: is_x11() is not true — the X11 capture/input pin is violated");
        ok = false;
    }
    // R-A4 / R-S16(d)(iv)(v): the second/third config funnels MUST carry no managed
    // override — BUILTIN_SETTINGS (get_builtin_option) and HARD_SETTINGS (including
    // conn-type) MUST be empty, or a signed-custom value could shadow the pinned policy
    // outside the get_option funnel the PINNED_SETTINGS table covers.
    if !hbb_common::config::HARD_SETTINGS.read().unwrap().is_empty() {
        log::error!(
            "R-A4/R-S16(d)(v): HARD_SETTINGS carries a managed override — refusing to listen"
        );
        ok = false;
    }
    if !hbb_common::config::BUILTIN_SETTINGS
        .read()
        .unwrap()
        .is_empty()
    {
        log::error!(
            "R-A4/R-S16(d)(iv): BUILTIN_SETTINGS carries a managed override — refusing to listen"
        );
        ok = false;
    }
    if !ok {
        let reason =
            "server startup security invariants violated (misconfiguration) — refusing to start"
                .to_string();
        log::error!("R-A4: {reason}");
        return Err(reason);
    }
    Ok(())
}

/// R-A4 (§9) post-listen socket-surface assertion. Once the direct listener is
/// bound, THIS --server process's reachable surface MUST equal exactly one TCP
/// listener on the pinned v4 port and ZERO UDP sockets of any kind (ephemeral
/// egress UDP included — a STUN probe or a dependency phoning home would slip
/// past a listener-only check). A violation is fail-closed (refuse to serve).
/// Every platform scopes the check to THIS process's own sockets: Linux and
/// Android map `/proc/self/fd` socket inodes to the `/proc/self/net` rows, and
/// Windows uses the IP Helper owner-PID tables — so a co-resident SSH/DNS/desktop
/// socket sharing the box's network namespace is correctly ignored (the box is
/// NOT guaranteed its own netns; docs/DEPLOYMENT.md runs it alongside SSH).
/// Targets without a platform assertion are recorded as unavailable and rest on
/// the §18 compile-out + build smoke tests. This is a bind/listener-surface check
/// only — it does NOT catch TCP egress (an outbound connect has no listener row),
/// which rests on R-D6 + firewall.
fn assert_socket_surface(port: u16) {
    use hbb_common::socket_surface::{check_surface, SurfaceCheck};
    match check_surface(port) {
        SurfaceCheck::Ok => {
            log::info!("R-A4: socket surface verified — exactly one TCP v4:{port}, zero UDP")
        }
        SurfaceCheck::Unavailable(why) => log::warn!(
            "R-A4: runtime socket-surface check unavailable ({why}); surface rests on the \
             §18 compile-out + the build smoke-test (R-B4)"
        ),
        SurfaceCheck::Violation(why) => {
            // Desktop --service: a real surface violation is fatal (refuse to serve;
            // systemd restarts). On Android/iOS the Rust core shares the interactive app
            // process, which legitimately owns extra sockets (the Flutter engine / Dart
            // VM / JNI), so the process-scoped "zero UDP" invariant is false-positive-
            // prone there — never process::exit (finding D). Log the violation loudly and
            // keep serving: every connection is still CPace-gated + R-S9-refused, so a
            // co-process UDP socket is not an access path to the direct listener.
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                log::error!("R-A4: socket-surface violation — {why}; refusing to serve");
                std::process::exit(1);
            }
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                log::error!(
                    "R-A4: socket-surface check reported a violation on mobile ({why}); \
                     NOT fatal here (Android/JNI legitimately owns extra sockets) — the \
                     direct listener stays CPace-gated + R-S9-refused"
                );
            }
        }
    }
}

/// R-D4 / §17 / §18: the direct-only service entry — the minimal KEEP path lifted out of
/// the inherited `start_all`, whose register/STUN/KCP/LAN protocol is now REMOVED from
/// the tree (R-D4 Stage 2, above), not merely bypassed.
///
/// The fork ships NO rendezvous mediator: no registration loop / `register_pk` /
/// heartbeat, no STUN/NAT probe, no LAN discovery, no remote sysinfo POST
/// (R-SV6(b)), no `test_rendezvous_server` probe. The box is reachable ONLY by a
/// deliberate, PAKE-gated direct connection on the one v4 TCP port (R-F4 21118 / R-D5
/// v4-only), so this entry just stands up the genuinely-shared startup and the listener:
///   - `assert_startup_invariants()` — the R-A4 policy/pin self-check (refuse to listen);
///   - the zombie reaper + the `Server`;
///   - `spawn(direct_server)` — binds the listener and runs `assert_socket_surface()`
///     post-listen (R-A4 live surface: exactly 1×TCP v4, 0×UDP);
///   - on Linux, the seat0/greeter capture-session discovery R-S14/R-X14 needs.
///
/// AV1 is wire-only and libaom is absent, so this service entry stands up no benchmark,
/// encoder, or decoder for it at startup; VP9 is the software-video default.
/// R-T1(a) (§20): self-enforce a per-process file-descriptor ceiling at startup so the flood/leak
/// blast-radius bound holds under ANY launcher (systemd, a per-user supervisor, a bare container —
/// R-D8), not only the unit's LimitNOFILE. Legitimate single-user use is a handful of sessions; a
/// high fd ceiling only serves an attacker or a descriptor leak. The concurrent-authorized-session
/// cap (connection.rs, MAX_AUTHED_SESSIONS) is the companion in-process bound. A per-process RSS
/// ceiling has no clean setrlimit (RLIMIT_AS is virtual not resident; RLIMIT_NPROC is per-UID), so
/// the cgroup MemoryMax/TasksMax remains the redundant outer RSS/task bound.
#[cfg(target_os = "linux")]
fn self_enforce_resource_limits() {
    use hbb_common::libc;
    // R-T1(a): bound THIS process's open-fd ceiling so an accept()-flood is service-fatal, not
    // host-fatal, under ANY launcher (systemd / a per-user supervisor / a bare container — R-D8).
    // We lower only the SOFT limit and PRESERVE the inherited HARD ceiling: the --server is held
    // at SOFT_NOFILE (the kernel returns EMFILE past it — R-T12 backs off), while a child the
    // --server spawns — notably the owner's full-access terminal (R-F1) — can raise its own soft
    // limit back via `ulimit -n`. A resource bound is launcher-independent AND owner-safe; a
    // PRIVILEGE/syscall sandbox is neither, so the binary never self-applies one (R-D3a — that is
    // the launcher's job, since a self-applied prctl latch would confine the owner's shell too).
    const SOFT_NOFILE: libc::rlim_t = 8192;
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid resource id + writable rlimit pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        log::warn!(
            "R-T1(a): getrlimit(RLIMIT_NOFILE) failed, fd ceiling not self-enforced: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    lim.rlim_cur = SOFT_NOFILE.min(lim.rlim_max);
    // SAFETY: same; lowers the soft limit only, never raises the inherited hard ceiling.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };
    if rc == 0 {
        log::info!(
            "R-T1(a): self-enforced RLIMIT_NOFILE soft={} (hard ceiling {} preserved for child shells)",
            lim.rlim_cur, lim.rlim_max
        );
    } else {
        log::warn!(
            "R-T1(a): setrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn self_enforce_resource_limits() {}

#[cfg(all(not(any(target_os = "android", target_os = "ios")), unix))]
pub(crate) struct ControlledServerShutdownSignals {
    sigterm: tokio::signal::unix::Signal,
    sigint: tokio::signal::unix::Signal,
}

#[cfg(all(not(any(target_os = "android", target_os = "ios")), windows))]
pub(crate) struct ControlledServerShutdownSignals {
    ctrl_c: tokio::signal::windows::CtrlC,
}

#[cfg(all(
    not(any(target_os = "android", target_os = "ios")),
    not(any(unix, windows))
))]
pub(crate) struct ControlledServerShutdownSignals;

/// Install the controlled-side process signal receivers before main, service-control, or public
/// listener admission begins. Tokio keeps a registered Unix signal disposition for process life,
/// so registration failure cannot be downgraded to a detached task diagnostic.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn install_controlled_server_shutdown_signals(
) -> ResultType<ControlledServerShutdownSignals> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let sigterm = signal(SignalKind::terminate())
            .map_err(|err| anyhow!("Failed to install controlled-server SIGTERM receiver: {err}"))?;
        let sigint = signal(SignalKind::interrupt())
            .map_err(|err| anyhow!("Failed to install controlled-server SIGINT receiver: {err}"))?;
        return Ok(ControlledServerShutdownSignals { sigterm, sigint });
    }
    #[cfg(windows)]
    {
        let ctrl_c = tokio::signal::windows::ctrl_c()
            .map_err(|err| anyhow!("Failed to install controlled-server Ctrl-C receiver: {err}"))?;
        return Ok(ControlledServerShutdownSignals { ctrl_c });
    }
    #[cfg(not(any(unix, windows)))]
    Err(anyhow!(
        "Controlled-server shutdown signals are unsupported on this desktop target"
    ))
}

#[cfg(all(not(any(target_os = "android", target_os = "ios")), unix))]
impl ControlledServerShutdownSignals {
    async fn recv(&mut self) -> ResultType<&'static str> {
        let (name, received) = tokio::select! {
            received = self.sigterm.recv() => ("SIGTERM", received),
            received = self.sigint.recv() => ("SIGINT", received),
        };
        if received.is_some() {
            Ok(name)
        } else {
            Err(anyhow!("Controlled-server {name} receiver ended unexpectedly"))
        }
    }
}

#[cfg(all(not(any(target_os = "android", target_os = "ios")), windows))]
impl ControlledServerShutdownSignals {
    async fn recv(&mut self) -> ResultType<&'static str> {
        if self.ctrl_c.recv().await.is_some() {
            Ok("Ctrl-C")
        } else {
            Err(anyhow!(
                "Controlled-server Ctrl-C receiver ended unexpectedly"
            ))
        }
    }
}

#[cfg(all(
    not(any(target_os = "android", target_os = "ios")),
    not(any(unix, windows))
))]
impl ControlledServerShutdownSignals {
    async fn recv(&mut self) -> ResultType<&'static str> {
        Err(anyhow!(
            "Controlled-server shutdown signals are unsupported on this desktop target"
        ))
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn wait_for_direct_listener_task(
    task: &mut Option<tokio::task::JoinHandle<()>>,
) -> Result<(), tokio::task::JoinError> {
    match task.as_mut() {
        Some(task) => task.await,
        None => std::future::pending().await,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
enum ControlledServerLifecycleEvent {
    ShutdownRequested,
    Signal(ResultType<&'static str>),
    DirectListener(Result<(), tokio::task::JoinError>),
    DesktopIpc(Result<(), String>),
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
enum ControlledServerStartupEvent {
    ShutdownRequested,
    Signal(ResultType<&'static str>),
    DesktopIpcReady(Result<(), String>),
    DesktopIpc(Result<(), String>),
}

/// Complete the one desktop ownership chain. Cancellation first stops admission; the exact public
/// listener task and native IPC worker are then observed and joined before the sole process
/// finalizer runs. Native thread joining is delegated to Tokio's blocking pool.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn finish_owned_controlled_server_lifecycle(
    mut direct_listener: Option<tokio::task::JoinHandle<()>>,
    direct_listener_outcome: Option<Result<(), tokio::task::JoinError>>,
    mut ipc_worker: Option<crate::ipc::DesktopIpcWorker>,
    ipc_outcome: Option<Result<(), String>>,
) -> ! {
    let direct_listener_outcome = match direct_listener_outcome {
        Some(outcome) => Some(outcome),
        None => match direct_listener.take() {
            Some(task) => Some(task.await),
            None => None,
        },
    };
    if let Some(Err(err)) = direct_listener_outcome {
        log::error!("Controlled-server direct listener task failed during shutdown: {err}");
        crate::server::request_graceful_shutdown_after_listener_failure();
    }

    if let Some(worker) = ipc_worker.as_mut() {
        let ipc_outcome = match ipc_outcome {
            Some(outcome) => outcome,
            None => worker.wait_for_completion().await,
        };
        if let Err(err) = ipc_outcome {
            log::error!("Controlled-server IPC worker failed: {err}");
            crate::server::request_graceful_shutdown_after_listener_failure();
        }
    }
    if let Some(worker) = ipc_worker {
        if let Err(err) = worker.join().await {
            log::error!("Controlled-server IPC worker join failed: {err}");
            crate::server::request_graceful_shutdown_after_listener_failure();
        }
    }

    crate::server::finish_graceful_shutdown().await
}

/// Own the complete desktop controlled-side lifetime. Readiness is observed before the public
/// listener may start. Normal signal/service cancellation and every unexpected listener/worker
/// completion converge on exact task/thread join before the one finalizer.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn own_controlled_server_lifecycle(
    server: Option<ServerPtr>,
    mut ipc_worker: crate::ipc::DesktopIpcWorker,
    mut signals: ControlledServerShutdownSignals,
) -> ! {
    let shutdown = crate::server::shutdown_token();
    let (ipc_readiness, ipc_completion) = ipc_worker.startup_receivers();
    let startup_event = tokio::select! {
        biased;
        _ = shutdown.cancelled() => ControlledServerStartupEvent::ShutdownRequested,
        signal = signals.recv() => ControlledServerStartupEvent::Signal(signal),
        readiness = ipc_readiness => {
            ControlledServerStartupEvent::DesktopIpcReady(readiness.unwrap_or_else(|_| {
                Err("desktop IPC worker ended before reporting readiness".to_owned())
            }))
        }
        outcome = ipc_completion => {
            ControlledServerStartupEvent::DesktopIpc(outcome.unwrap_or_else(|_| {
                Err("desktop IPC worker ended without reporting an outcome".to_owned())
            }))
        }
    };

    match startup_event {
        ControlledServerStartupEvent::DesktopIpcReady(Ok(())) => {}
        ControlledServerStartupEvent::ShutdownRequested => {
            finish_owned_controlled_server_lifecycle(None, None, Some(ipc_worker), None).await;
        }
        ControlledServerStartupEvent::Signal(Ok(name)) => {
            log::info!("R-T9: {name} received during controlled-server startup");
            crate::server::request_graceful_shutdown();
            finish_owned_controlled_server_lifecycle(None, None, Some(ipc_worker), None).await;
        }
        ControlledServerStartupEvent::Signal(Err(err)) => {
            log::error!("Controlled-server shutdown receiver failed during startup: {err}");
            crate::server::request_graceful_shutdown_after_listener_failure();
            finish_owned_controlled_server_lifecycle(None, None, Some(ipc_worker), None).await;
        }
        ControlledServerStartupEvent::DesktopIpcReady(Err(err)) => {
            log::error!("Controlled-server IPC readiness failed: {err}");
            crate::server::request_graceful_shutdown_after_listener_failure();
            finish_owned_controlled_server_lifecycle(None, None, Some(ipc_worker), None).await;
        }
        ControlledServerStartupEvent::DesktopIpc(outcome) => {
            match &outcome {
                Ok(()) => log::error!("Controlled-server IPC worker returned before readiness"),
                Err(err) => {
                    log::error!("Controlled-server IPC worker failed before readiness: {err}")
                }
            }
            crate::server::request_graceful_shutdown_after_listener_failure();
            finish_owned_controlled_server_lifecycle(None, None, Some(ipc_worker), Some(outcome))
                .await;
        }
    }

    let mut direct_listener = server.map(|server| {
        tokio::spawn(async move {
            direct_server(server, None).await;
        })
    });
    // It is ok to run xdesktop manager when the headless function is not allowed.
    #[cfg(target_os = "linux")]
    if direct_listener.is_some() && crate::is_server() {
        crate::platform::linux_desktop_manager::start_xdesktop();
    }

    let event = tokio::select! {
        biased;
        _ = shutdown.cancelled() => ControlledServerLifecycleEvent::ShutdownRequested,
        signal = signals.recv() => ControlledServerLifecycleEvent::Signal(signal),
        outcome = wait_for_direct_listener_task(&mut direct_listener) => {
            ControlledServerLifecycleEvent::DirectListener(outcome)
        }
        outcome = ipc_worker.wait_for_completion() => {
            ControlledServerLifecycleEvent::DesktopIpc(outcome)
        }
    };

    let mut direct_listener_outcome = None;
    let mut ipc_outcome = None;
    match event {
        ControlledServerLifecycleEvent::ShutdownRequested => {}
        ControlledServerLifecycleEvent::Signal(Ok(name)) => {
            log::info!("R-T9: {name} received");
            crate::server::request_graceful_shutdown();
        }
        ControlledServerLifecycleEvent::Signal(Err(err)) => {
            log::error!("Controlled-server shutdown receiver failed: {err}");
            crate::server::request_graceful_shutdown_after_listener_failure();
        }
        ControlledServerLifecycleEvent::DirectListener(outcome) => {
            direct_listener_outcome = Some(outcome);
            log::error!("Controlled-server direct listener completed without a shutdown request");
            crate::server::request_graceful_shutdown_after_listener_failure();
        }
        ControlledServerLifecycleEvent::DesktopIpc(outcome) => {
            ipc_outcome = Some(outcome);
            log::error!("Controlled-server IPC worker completed without a shutdown request");
            crate::server::request_graceful_shutdown_after_listener_failure();
        }
    }
    finish_owned_controlled_server_lifecycle(
        direct_listener,
        direct_listener_outcome,
        Some(ipc_worker),
        ipc_outcome,
    )
    .await
}

/// Android/iOS receive the exact mobile listener-generation input. Desktop receives an already
/// installed signal owner, so listener/IPC admission cannot race fallible signal registration.
pub async fn start_direct_only(
    #[cfg(any(target_os = "android", target_os = "ios"))]
    android_generation: Option<u64>,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    shutdown_signals: ControlledServerShutdownSignals,
) {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    if let Err(_reason) = assert_startup_invariants() {
        // Reached ONLY on Android/iOS — the desktop --service checks this before entering
        // start_direct_only. The Rust core shares the interactive app process here, so we
        // must not exit (finding D): surface the failure to the Dart UI (best-effort
        // msgbox on the main event channel) and refuse to bind — fail closed, no listener.
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let _ = crate::flutter::push_global_event(
                crate::flutter::APP_TYPE_MAIN,
                serde_json::json!({
                    "name": "msgbox",
                    "type": "custom-error",
                    "title": "Start service",
                    "text": _reason,
                })
                .to_string(),
            );
        }
        return;
    }
    self_enforce_resource_limits();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let server = if config::is_outgoing_only() {
            None
        } else {
            #[cfg(not(target_os = "android"))]
            check_zombie();
            Some(new_server())
        };
        let ipc_worker = match crate::ipc::spawn_desktop_ipc_worker() {
            Ok(worker) => worker,
            Err(err) => {
                log::error!("Controlled-server IPC worker spawn failed: {err}");
                crate::server::request_graceful_shutdown_after_listener_failure();
                finish_owned_controlled_server_lifecycle(None, None, None, None).await
            }
        };
        own_controlled_server_lifecycle(server, ipc_worker, shutdown_signals).await;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        if config::is_outgoing_only() {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            loop {
                sleep(1.).await;
            }
        }
        // R-D7a: check_zombie reaps `--cm` child processes, a desktop `--service` concern; the Android
        // cdylib spawns none (its connection-manager is in-process), so on Android it would be a no-op
        // reaper thread that outlives each service-owned run — skip it so no idle thread leaks per
        // MainService start/stop cycle. The direct listener's own teardown is the generation edge above.
        #[cfg(not(target_os = "android"))]
        check_zombie();
        let server = new_server();
        let server_cloned = server.clone();
        let direct_listener = tokio::spawn(async move {
            direct_server(server_cloned, android_generation).await;
        });
        // It is ok to run xdesktop manager when the headless function is not allowed.
        #[cfg(target_os = "linux")]
        if crate::is_server() {
            crate::platform::linux_desktop_manager::start_xdesktop();
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let _direct_listener = direct_listener;
        #[cfg(target_os = "ios")]
        loop {
            sleep(3600.).await;
        }
        // Android (R-D7a): the listener is OWNED by `MainService` and shares its lifetime. Poll the
        // service-owned-listener generation this server thread runs under; when `MainService.onDestroy`
        // -> `stopServer` deactivates it, return so this `#[tokio::main]` runtime (the JNI-spawned
        // thread) unwinds — dropping the runtime aborts the live `direct_server` accept task, closing
        // the listening socket. A graceful "Stop service" closes the socket via this teardown; an
        // OS/OEM/battery kill closes it by process death (onStartCommand is START_NOT_STICKY, so no
        // zombie auto-restart rebinds a listener the user stopped — R-S14).
        #[cfg(target_os = "android")]
        {
            // R-D7a (N1/F1 fix): compare against the generation CAPTURED at service start and passed
            // in by value — NOT a late lifecycle-state read, which could adopt the newer generation
            // from a concurrent `stopServer`/`startServer` and so keep this (stopped) service's
            // thread alive. On the legitimate Android path this is always `Some`
            // (the JNI `startServer` supplies it); a `None` here means a misrouted start — fail closed.
            let my_generation = match android_generation {
                Some(g) => g,
                None => {
                    log::error!(
                        "R-D7a: start_direct_only reached on Android with no service generation — fail closed (no listener)"
                    );
                    return;
                }
            };
            loop {
                if android_listener_lifecycle_snapshot(my_generation).is_none() {
                    log::info!(
                        "R-D7a: Android service stopped — start_direct_only returns so the server thread + tokio runtime unwind (listener socket closed)"
                    );
                    return;
                }
                sleep(1.).await;
            }
        }
    }
}

#[cfg_attr(not(target_os = "android"), allow(unused_variables))]
async fn direct_server(server: ServerPtr, android_generation: Option<u64>) {
    let mut listener = None;
    let mut port = 0;
    // R-D7a (Android, N1/F1 fix): the service-owned-listener generation this accept task runs
    // under is PASSED IN BY VALUE from the JNI `startServer` entry (android_begin_generation's
    // return, via start_server -> start_direct_only), NOT re-loaded from the global here. A late
    // `load()` could adopt a generation a concurrent stop/re-start already superseded — the N1/F1
    // orphaned-listener race — so a "stopped" service's accept task could keep the socket bound.
    // Using the captured value, `MainService.onDestroy` -> `stopServer` deactivates this exact
    // generation, so the loop-top snapshot below fails, drops the `listener` local, and stops
    // accepting. Desktop/iOS: absent — the listener lifetime is the process/unit lifetime (R-X9).
    #[cfg(target_os = "android")]
    let my_generation = match android_generation {
        Some(g) => g,
        None => {
            log::error!(
                "R-D7a: direct_server started on Android with no service generation — fail closed (not binding)"
            );
            return;
        }
    };
    #[cfg(target_os = "android")]
    let mut seen_rebuild_epoch = match android_listener_lifecycle_snapshot(my_generation) {
        Some(epoch) => epoch,
        None => {
            log::error!(
                "R-D7a: direct_server generation was inactive or superseded before listener startup — fail closed (not binding)"
            );
            return;
        }
    };
    // R-T12: the consecutive accept()-error streak, driving the escalating bounded back-off in the
    // error arm below; reset on any successful accept or the benign 1s poll-timeout.
    let mut accept_err_streak: u32 = 0;
    // The consecutive bind()-error streak, driving the escalating bounded back-off in the bind arm
    // below before RE-attempting the bind. The port is a pinned compile-time constant (R-F4
    // get_direct_port), so the listener always rebinds the same v4 address; a transient bind failure
    // backs off and retries the identical bind, and the streak resets on a successful bind.
    let mut bind_err_streak: u32 = 0;
    // R-S9 fail-closed park: true while the listener is parked because no permanent password is
    // set, so the loud "PARKED" diagnostic below is logged once per entry into that state rather
    // than on every 1s poll. Reset the moment a usable password is present.
    let mut parked_no_password = false;
    loop {
        // R-T9 (§20): on graceful shutdown, stop accepting and drop the listener (returning here
        // drops the `listener` local, so the listening socket closes and new SYNs get an RST), then
        // leave the accept loop. The retained desktop lifecycle owner joins this task and then
        // drives the live-session/local-IPC finalizer; this branch guarantees no new connection is
        // admitted after cancellation.
        if crate::server::is_shutting_down() {
            log::info!("R-T9: shutdown — direct_server stops accepting");
            // R-G1: returning drops the `listener` local -> its ListenerBoundGuard's Drop publishes
            // DIRECT_LISTENER_BOUND = false (no manual store needed).
            return;
        }
        // R-D7a (Android): the foreground service that owns this listener was destroyed
        // (MainService.onDestroy -> stopServer -> android_request_stop deactivated the generation).
        // Return so the `listener` local drops and the listening socket closes; the accept task
        // ends. No config write — symmetric with the desktop R-T9 edge above; a "service stopped,
        // listener still bound" half-state is unrepresentable. (Desktop/iOS never take this branch.)
        #[cfg(target_os = "android")]
        {
            let rebuild_epoch = match android_listener_lifecycle_snapshot(my_generation) {
                Some(epoch) => epoch,
                None => {
                    log::info!(
                        "R-D7a: Android service stopped — direct_server drops the listener and stops accepting"
                    );
                    // R-G1: returning drops the `listener` local -> its ListenerBoundGuard's Drop
                    // publishes DIRECT_LISTENER_BOUND = false. If the start_direct_only keep-alive
                    // returns first and aborts this task, dropping the future has the same result.
                    return;
                }
            };
            if rebuild_epoch != seen_rebuild_epoch {
                seen_rebuild_epoch = rebuild_epoch;
                if listener.is_some() {
                    // R-T13: an exact-generation network-change rebuild drops the existing listener
                    // so the next iteration re-enters the audited bind path.
                    log::info!(
                        "R-T13: rebuilding direct listener after exact-generation Android network change"
                    );
                    // R-G1: dropping the listener tuple publishes false; the next successful bind
                    // constructs a fresh guard and publishes true.
                    listener = None;
                    continue;
                }
            }
        }
        // R-S9 fail-closed: the "listen on 0.0.0.0 IFF a permanent password is set"
        // invariant is enforced at RUNTIME here — this park is now the PRIMARY guard for
        // the empty-password case (the startup exit that used to also cover it was removed
        // from assert_startup_invariants — finding D — because it crashed the shared-process
        // Android app and was redundant with this park). Two entry paths, both fail closed:
        //   - fresh start with no password provisioned: `listener` is already None, so
        //     NOTHING is ever bound; log the parked state once and keep polling;
        //   - password CLEARED at runtime (set_permanent_password("") from the UI) while
        //     listening: drop the listener so no bound-but-dead 0.0.0.0 socket lingers.
        // Either way the bind block below stays skipped until a password is set, when it
        // re-binds and re-runs assert_socket_surface. The per-connection gate (server.rs,
        // R-S9) already refuses every connection in this window, so no listener is ever an
        // access path without a password — the socket simply tracks the credential.
        let prs_status = crate::server::effective_permanent_password_prs_status().await;
        if !prs_status.is_available() {
            if listener.is_some() {
                match prs_status {
                    PermanentPasswordPrsRead::UndecryptableStorage => log::error!(
                        "R-S9: stored permanent password PRS cannot be decrypted - dropping the direct listener until the password is provisioned again"
                    ),
                    PermanentPasswordPrsRead::Empty => log::warn!(
                        "R-S9: permanent password cleared at runtime - dropping the direct listener until one is set again"
                    ),
                    PermanentPasswordPrsRead::Available(_) => {}
                }
                // R-G1: dropping the listener tuple runs its ListenerBoundGuard Drop -> false.
                listener = None;
            } else if !parked_no_password {
                // Log ONCE per entry so a --service / Android app started before password
                // provisioning is diagnosable rather than silently non-listening.
                match prs_status {
                    PermanentPasswordPrsRead::UndecryptableStorage => log::error!(
                        "R-S9: stored permanent password PRS cannot be decrypted - the direct listener is PARKED (nothing bound, all connections refused) until the password is provisioned again"
                    ),
                    PermanentPasswordPrsRead::Empty => log::warn!(
                        "R-S9: no permanent password set - the direct listener is PARKED (nothing bound, all connections refused) until one is provisioned"
                    ),
                    PermanentPasswordPrsRead::Available(_) => {}
                }
            }
            parked_no_password = true;
            sleep(1.).await;
            continue;
        }
        parked_no_password = false;
        // R-D4 / R-F4 / R-X9: the direct listener is UNCONDITIONAL — it is the box's only
        // inbound path (§17), so it has no enable-toggle at all. Upstream's `direct-server`
        // option (which gated the listener) was REMOVED from the tree entirely (R-G4 / R-SV1),
        // and the stop-service runtime toggle that could suppress it is now excised too (R-X9):
        // the listener reads no option to decide whether to start — it always starts. R-F4 pins
        // the port as the compile-time constant get_direct_port() → 21118, never a runtime option.
        if listener.is_none() {
            port = get_direct_port();
            match hbb_common::tcp::listen_any_v4(port as _).await {
                Ok(l) => {
                    bind_err_streak = 0; // a successful bind resets the retry back-off
                    // R-G1 (verify-ground-truth): the listener is bound — store it WITH a fresh
                    // ListenerBoundGuard, whose `new()` publishes DIRECT_LISTENER_BOUND = true. The
                    // guard now lives inside `listener`, so it is dropped (publishing false) on every
                    // teardown path, including the runtime-abort of this task (R2-1 fix).
                    listener = Some((l, ListenerBoundGuard::new()));
                    log::info!(
                        "Direct server listening on: {:?}",
                        listener.as_ref().map(|(l, _)| l.local_addr())
                    );
                    // R-A4: the listener is up — assert the live socket surface
                    // (exactly one TCP v4 listener on the pinned port, zero UDP
                    // of any kind) now, before accepting any connection.
                    assert_socket_surface(port as u16);
                }
                Err(err) => {
                    // A bind failure (e.g. a transient EADDRINUSE while a
                    // just-exited --server's socket lingers in TIME_WAIT on a fast restart) is
                    // retried — it is not terminal. The port is a pinned constant (R-F4), so the listener
                    // always rebinds the same v4 address: back off a bounded, escalating
                    // amount (100ms·2^streak, capped at 5s), then fall back to the top of the accept loop —
                    // `listener` is still None, so the next iteration re-enters this bind path, while the
                    // loop top honors shutdown (R-T9), the Android rebuild epoch (R-T13), and the runtime
                    // password check (R-S9).
                    bind_err_streak = bind_err_streak.saturating_add(1);
                    let backoff_ms = (100u64 << bind_err_streak.min(6)).min(5000);
                    log::error!(
                        "Failed to bind direct server on port {}: {} — retrying in {}ms",
                        port,
                        err,
                        backoff_ms
                    );
                    sleep(backoff_ms as f32 / 1000.0).await;
                    continue;
                }
            }
        }
        if let Some((l, _)) = listener.as_mut() {
            match hbb_common::timeout(1000, l.accept()).await {
                Ok(Ok((stream, addr))) => {
                    accept_err_streak = 0; // R-T12: a successful accept resets the error back-off
                    // R-T1(b) / R-T0 rule 2 ("shed cheaply, early"): acquire the pre-key handshake
                    // slot FIRST — before ANY per-socket setup, the task spawn, or the server lock —
                    // so a SHED connection (semaphore full under a flood) costs accept+close, not
                    // accept+setsockopt(×2)+close. Under a sustained flood — including a malicious
                    // router opening connections faster than handshakes complete — the shed path is
                    // the hot path, so it must touch no resource the connection will not use. The
                    // permit moves into the spawned task and is released after keying (server.rs),
                    // bounding only the attacker-reachable half-open population.
                    let permit = match crate::server::PREKEY_HANDSHAKE_SLOTS
                        .clone()
                        .try_acquire_owned()
                    {
                        Ok(p) => p,
                        Err(_) => {
                            crate::server::note_security_event(
                                crate::server::SecurityEvent::Shed,
                                addr.ip(),
                            );
                            // R-T1: damp the accept-and-drop CPU spin under a sustained flood
                            // without materially delaying a legitimate connection (the kernel
                            // backlog absorbs the burst); dropping `stream` here closes the fd.
                            sleep(0.002).await;
                            continue;
                        }
                    };
                    // Permit held — this connection WILL be handled, so set up its socket now (a
                    // shed connection skipped all of the below).
                    if let Err(e) = stream.set_nodelay(true) {
                        crate::server::note_accept_setup_error(
                            crate::server::AcceptSetupEvent::NodelayFailed,
                            addr.ip(),
                            &e,
                        );
                    }
                    // R-T10 (§20): enable TCP keepalive on the accepted peer socket immediately
                    // after set_nodelay — the kernel-level backstop the NAT'd-client reality
                    // demands. UDP is off precisely BECAUSE the client is behind NAT (R-S13(d)), so
                    // idle/rebinding/sleeping NAT mappings that vanish WITHOUT a FIN/RST are the
                    // common case; without keepalive a dead peer would hold an fd + task + capture
                    // subscription + CM IPC until the ~30 s app deadline (test_delay_timer), and any
                    // future read path that failed to arm that timer would hang forever. The app
                    // 30 s deadline stays the portable PRIMARY guarantee; this is the kernel backstop.
                    // OS-aware (the knobs differ): with_time → TCP_KEEPIDLE (Linux/Android) /
                    // TCP_KEEPALIVE (macOS) / keepalivetime (Windows); with_interval → TCP_KEEPINTVL;
                    // with_retries → TCP_KEEPCNT, COMPILED OUT on Windows (SIO_KEEPALIVE_VALS has no
                    // retry field — the probe count is OS-chosen there).
                    {
                        let keepalive = socket2::TcpKeepalive::new()
                            .with_time(std::time::Duration::from_secs(30))
                            .with_interval(std::time::Duration::from_secs(10));
                        #[cfg(not(target_os = "windows"))]
                        let keepalive = keepalive.with_retries(3);
                        if let Err(e) =
                            socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive)
                        {
                            crate::server::note_accept_setup_error(
                                crate::server::AcceptSetupEvent::KeepaliveFailed,
                                addr.ip(),
                                &e,
                            );
                        }
                    }
                    let local_addr = stream
                        .local_addr()
                        .unwrap_or(Config::get_any_listen_addr(true));
                    let server = server.clone();
                    tokio::spawn(async move {
                        allow_err!(
                            crate::server::create_tcp_connection(
                                server,
                                hbb_common::Stream::from(stream, local_addr),
                                addr,
                                None, // Direct connections don't have control_permissions
                                permit,
                                android_generation,
                            )
                            .await
                        );
                    });
                }
                Ok(Err(e)) => {
                    // R-T12: a real accept() error (EMFILE/ENFILE/WSAEMFILE/WSAENOBUFS under fd/
                    // resource exhaustion — note_accept_error maps the errno) — observe it
                    // rate-limited, then back off with an ESCALATING bounded delay, not a flat sleep:
                    // the kernel keeps signalling the socket readable while accept() returns EMFILE,
                    // so a fixed sleep still busy-spins. min(50ms·2^streak, 5s) damps the spin yet
                    // recovers fast once fds free up; the streak resets on the next success/timeout.
                    crate::server::note_accept_error(port as u16, &e);
                    let backoff_ms = (50u64 << accept_err_streak.min(7)).min(5000);
                    accept_err_streak = accept_err_streak.saturating_add(1);
                    sleep(backoff_ms as f32 / 1000.0).await;
                }
                Err(_) => {
                    // The 1s poll timeout — normal idle; loop to re-check disabled/port.
                    accept_err_streak = 0; // R-T12: idle, not erroring — reset the back-off
                }
            }
        } else {
            sleep(1.).await;
        }
    }
}

// R-D4: the `CheckIfResendPk` no-op RAII shell (the original resent `register_pk` on a post-config-
// sync pk change — moot with no registration) is REMOVED with the mediator-shell sweep.

#[cfg(test)]
mod android_listener_lifecycle_tests {
    use super::AndroidListenerLifecycle;

    #[test]
    fn stale_network_callback_cannot_advance_replacement_generation_epoch() {
        let mut lifecycle = AndroidListenerLifecycle::default();

        let first = lifecycle.begin_generation().unwrap();
        assert_eq!(lifecycle.snapshot(first), Some(0));
        assert_eq!(lifecycle.request_rebuild(first), Some(1));
        assert_eq!(lifecycle.snapshot(first), Some(1));

        assert!(!lifecycle.stop_generation(first + 1));
        assert_eq!(lifecycle.snapshot(first), Some(1));
        assert!(lifecycle.stop_generation(first));
        assert_eq!(lifecycle.snapshot(first), None);

        let replacement = lifecycle.begin_generation().unwrap();
        assert!(replacement > first);
        assert_eq!(lifecycle.snapshot(replacement), Some(0));
        assert_eq!(lifecycle.request_rebuild(replacement), Some(1));

        assert_eq!(lifecycle.request_rebuild(first), None);
        assert_eq!(lifecycle.snapshot(replacement), Some(1));
        assert!(!lifecycle.stop_generation(first));
        assert_eq!(lifecycle.snapshot(replacement), Some(1));
    }

    #[test]
    fn invalid_or_exhausted_listener_lifecycle_transitions_fail_closed() {
        let mut lifecycle = AndroidListenerLifecycle::default();

        assert_eq!(lifecycle.request_rebuild(0), None);
        assert!(!lifecycle.stop_generation(0));
        assert_eq!(lifecycle.snapshot(0), None);

        lifecycle.generation = u64::MAX;
        lifecycle.active = true;
        assert!(lifecycle.stop_generation(u64::MAX));
        assert_eq!(lifecycle.snapshot(u64::MAX), None);

        lifecycle.active = true;
        assert_eq!(lifecycle.begin_generation(), None);
        assert!(!lifecycle.stop_generation(u64::MAX));
        assert_eq!(lifecycle.generation, u64::MAX);
        assert!(!lifecycle.active);
        assert_eq!(lifecycle.snapshot(u64::MAX), None);

        lifecycle.generation = 7;
        lifecycle.rebuild_epoch = u64::MAX;
        lifecycle.active = true;
        assert_eq!(lifecycle.request_rebuild(7), None);
        assert_eq!(lifecycle.rebuild_epoch, u64::MAX);
        assert!(!lifecycle.active);
        assert_eq!(lifecycle.snapshot(7), None);
    }
}
