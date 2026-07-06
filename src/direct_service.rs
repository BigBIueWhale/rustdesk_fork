use hbb_common::{
    allow_err,
    config::{self, Config},
    log, sleep, tokio,
};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::server::{new as new_server, ServerPtr};
#[cfg(not(target_os = "android"))]
use crate::server::check_zombie;

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

static LISTENER_REBUILD_EPOCH: AtomicU64 = AtomicU64::new(0);

/// R-T13 (§20): Android network switches can invalidate the direct listener while the foreground
/// service stays alive. Kotlin observes the platform network lifecycle and calls this narrow hook;
/// the accept loop below reacts by dropping the existing listener (`listener = None`) and rebinding
/// the same pinned v4 port. This avoids restarting the whole server or reintroducing a runtime port
/// mode while still driving the existing direct-listener rebuild path.
pub fn request_direct_listener_rebuild(reason: &str) {
    let epoch = LISTENER_REBUILD_EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
    log::info!(
        "R-T13: direct listener rebuild requested by Android network lifecycle ({reason}); epoch={epoch}"
    );
}

/// R-D7a: the Android controlled-side server is OWNED by the mandatory `MainService` foreground
/// service and shares its lifetime — there is no headless `--service` on Android (a Flutter
/// `cdylib`). This monotonic generation counter binds the direct listener to the service instance
/// that started it. It is the STRUCTURAL TWIN of `LISTENER_REBUILD_EPOCH` above (R-T13): a
/// `fetch_add(1)` supersedes any running generation, and the accept loop / keep-alive compare the
/// generation they started under against the current one — but here supersession means "the owning
/// service was destroyed, tear the listener down" rather than "rebind the same port".
///   - `MainService.onCreate` -> JNI `startServer` calls `android_begin_generation()` to establish a
///     fresh generation before spawning the server thread, so the new server runs under the current
///     generation and any stale prior thread (a fast stop->start) is already superseded.
///   - `MainService.onDestroy` -> JNI `stopServer` calls `android_request_stop()` to supersede the
///     running generation. `direct_server` observes it at its loop top and `return`s (dropping the
///     `TcpListener` local -> socket closed), and `start_direct_only` observes it in its keep-alive
///     poll and `return`s (so the JNI thread + its `#[tokio::main]` runtime unwind, aborting any
///     live accept task -> socket closed). No config write — the stop is the OS foreground-service
///     lifecycle, not an option (the dead `stop-service` writes are deleted; the key is pinned `N`).
/// Desktop/iOS never touch this: their listener lifetime is the process / `systemd`-unit lifetime
/// (R-X9), so the whole mechanism is `#[cfg(target_os = "android")]`.
#[cfg(target_os = "android")]
static ANDROID_SERVER_GENERATION: AtomicU64 = AtomicU64::new(0);

/// R-D7a: establish a fresh Android server generation at service start (JNI `startServer`);
/// returns the new generation the spawned server's accept loop + keep-alive run under.
#[cfg(target_os = "android")]
pub fn android_begin_generation() -> u64 {
    ANDROID_SERVER_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
}

/// R-D7a: supersede any running Android server generation (JNI `stopServer` on
/// `MainService.onDestroy`). The graceful teardown twin of process-death fd close: the running
/// accept loop + keep-alive observe the bump and unwind, closing the listening socket.
#[cfg(target_os = "android")]
pub fn android_request_stop() {
    let generation = ANDROID_SERVER_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    log::info!(
        "R-D7a: Android stopServer — superseding the service-owned listener generation (now {generation})"
    );
}

/// R-D7a: true iff `generation` is still the current Android server generation, i.e. no later
/// `android_begin_generation()` / `android_request_stop()` has superseded it.
#[cfg(target_os = "android")]
fn android_generation_current(generation: u64) -> bool {
    ANDROID_SERVER_GENERATION.load(Ordering::SeqCst) == generation
}

/// R-A4 startup self-check: refuse to listen unless the controlled-side runtime
/// invariants hold. Defense-in-depth over the R-S16 funnel — confirm the policy
/// reads back pinned (verification-method/approve-mode) through Config::get_option
/// and that the empty BUILTIN/HARD override funnels carry no managed value. A
/// violation is fail-closed: on the desktop --service the process EXITS (systemd
/// restarts it, never serving insecure); on Android/iOS the Rust core shares the
/// interactive app process, so it returns Err instead of exiting (finding D) and
/// `start_direct_only` surfaces the reason + refuses to bind. The permanent-password
/// credential is deliberately NOT checked here (finding D): an empty password fails
/// closed at RUNTIME via the `direct_server` park (nothing bound) + the per-connection
/// R-S9 bail (server.rs), so the old startup exit for that case — redundant with the
/// park and fatal to the shared-process Android app — is gone. The companion
/// bound-socket-surface assertion (exactly one TCP v4 listener on the pinned port,
/// zero UDP of any kind) runs post-listen in `assert_socket_surface` — it needs the
/// listener up first, so it lives at the bind site rather than here.
// R-A4 is UNCONDITIONAL (R-R2b): every shipped binary refuses to listen unless the
// pinned policy + the one-TCP/zero-UDP surface verify — never behind a feature flag.
fn assert_startup_invariants() -> Result<(), String> {
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
    // override or preset credential — BUILTIN_SETTINGS (get_builtin_option) and
    // HARD_SETTINGS (the preset-password / conn-type funnel) MUST be empty, or a
    // server-/preset-pushed value could shadow the pinned policy outside the
    // get_option funnel the PINNED_SETTINGS table covers.
    if !hbb_common::config::HARD_SETTINGS.read().unwrap().is_empty() {
        log::error!("R-A4/R-S16(d)(v): HARD_SETTINGS carries a preset/managed override — refusing to listen");
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
        // Fail-closed. These are build-integrity invariants that never fire on a correct
        // build. On the desktop --service a violation must never serve insecure, so it
        // exits and systemd restarts it. On Android/iOS the Rust core shares the
        // interactive app process, so process::exit would crash the whole app (finding
        // D): return the reason instead so `start_direct_only` refuses to bind and
        // surfaces it to the Dart UI — never exiting on mobile.
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            log::error!("R-A4: startup invariants violated — the box refuses to run insecure");
            std::process::exit(1);
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let reason =
                "server startup security invariants violated (misconfiguration) — refusing to start"
                    .to_string();
            log::error!("R-A4: {reason} (mobile: refusing to bind, not exiting the app process)");
            return Err(reason);
        }
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
/// `test_av1` is deliberately NOT carried over: it is an `AomEncoder` benchmark (not the
/// decoder the R-D4 prose states) that the per-session encode path instantiates on
/// demand anyway, so the headless service entry stands up no codec at startup. The AV1
/// gate then resolves useable-without-benchmark — acceptable on the §17 desktop (VP9
/// fallback + PreferCodec remain).
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

pub async fn start_direct_only() {
    if let Err(_reason) = assert_startup_invariants() {
        // Reached ONLY on Android/iOS — the desktop --service exits inside the assert and
        // never returns Err. The Rust core shares the interactive app process here, so we
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
    if config::is_outgoing_only() {
        // A viewer-only box binds no inbound listener (R-SV5); park the service future.
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
    tokio::spawn(async move {
        direct_server(server_cloned).await;
    });
    // R-T9 (§20): install the graceful-shutdown handler. SIGTERM (what `systemctl stop` / an
    // upgrade sends) or SIGINT stops the accept loop and drains live sessions with a bounded
    // deadline before exiting — so an upgrade mid-session does not SIGKILL a connection mid-write
    // and truncate an in-flight transfer on the peer. The unit's pkill / KillMode=mixed /
    // TimeoutStopSec=30 remain the hard backstop for a hung process.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    tokio::spawn(async {
        // The drain is initiated only from inside an actual signal branch (so a target with no
        // signal mechanism simply never shuts down here, rather than draining on startup).
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("R-T9: failed to install SIGTERM handler: {}", e);
                    return;
                }
            };
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("R-T9: failed to install SIGINT handler: {}", e);
                    return;
                }
            };
            tokio::select! {
                _ = sigterm.recv() => log::info!("R-T9: SIGTERM received"),
                _ = sigint.recv() => log::info!("R-T9: SIGINT received"),
            }
            crate::server::begin_graceful_shutdown().await;
        }
        #[cfg(windows)]
        {
            if let Err(e) = tokio::signal::ctrl_c().await {
                log::error!("R-T9: failed to await Ctrl-C: {}", e);
                return;
            }
            log::info!("R-T9: Ctrl-C received");
            crate::server::begin_graceful_shutdown().await;
        }
    });
    // It is ok to run xdesktop manager when the headless function is not allowed.
    #[cfg(target_os = "linux")]
    if crate::is_server() {
        crate::platform::linux_desktop_manager::start_xdesktop();
    }
    // The direct listener runs in its spawned task; there is no registration loop to
    // re-enter, so just keep the service future alive without busy-work.
    //
    // Desktop/iOS: the listener lifetime is the process / `systemd`-unit lifetime (R-X9), so park
    // indefinitely — a graceful stop is the R-T9 SIGTERM drain path above, process death otherwise.
    #[cfg(not(target_os = "android"))]
    loop {
        sleep(3600.).await;
    }
    // Android (R-D7a): the listener is OWNED by `MainService` and shares its lifetime. Poll the
    // service-owned-listener generation this server thread runs under; when `MainService.onDestroy`
    // -> `stopServer` supersedes it, return so this `#[tokio::main]` runtime (the JNI-spawned
    // thread) unwinds — dropping the runtime aborts the live `direct_server` accept task, closing
    // the listening socket. A graceful "Stop service" closes the socket via this teardown; an
    // OS/OEM/battery kill closes it by process death (onStartCommand is START_NOT_STICKY, so no
    // zombie auto-restart rebinds a listener the user stopped — R-S14).
    #[cfg(target_os = "android")]
    {
        let my_generation = ANDROID_SERVER_GENERATION.load(Ordering::SeqCst);
        loop {
            if !android_generation_current(my_generation) {
                log::info!(
                    "R-D7a: Android service stopped — start_direct_only returns so the server thread + tokio runtime unwind (listener socket closed)"
                );
                return;
            }
            sleep(1.).await;
        }
    }
}

async fn direct_server(server: ServerPtr) {
    let mut listener = None;
    let mut port = 0;
    let mut seen_rebuild_epoch = LISTENER_REBUILD_EPOCH.load(Ordering::SeqCst);
    // R-D7a (Android): the service-owned-listener generation this accept task runs under. It was
    // established by JNI `startServer` (android_begin_generation) BEFORE this thread was spawned,
    // so the snapshot here reads that generation; when `MainService.onDestroy` -> `stopServer`
    // supersedes it, the loop-top check below returns and drops the `listener` local (socket
    // closed). Desktop/iOS: absent — the listener lifetime is the process/unit lifetime (R-X9).
    #[cfg(target_os = "android")]
    let my_generation = ANDROID_SERVER_GENERATION.load(Ordering::SeqCst);
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
        // leave the accept loop. begin_graceful_shutdown() drives the live-session drain and the
        // process exit; this only guarantees no new connection is admitted past the signal.
        if crate::server::is_shutting_down() {
            log::info!("R-T9: shutdown — direct_server stops accepting");
            return;
        }
        // R-D7a (Android): the foreground service that owns this listener was destroyed
        // (MainService.onDestroy -> stopServer -> android_request_stop bumped the generation).
        // Return so the `listener` local drops and the listening socket closes; the accept task
        // ends. No config write — symmetric with the desktop R-T9 edge above; a "service stopped,
        // listener still bound" half-state is unrepresentable. (Desktop/iOS never take this branch.)
        #[cfg(target_os = "android")]
        if !android_generation_current(my_generation) {
            log::info!(
                "R-D7a: Android service stopped — direct_server drops the listener and stops accepting"
            );
            return;
        }
        let rebuild_epoch = LISTENER_REBUILD_EPOCH.load(Ordering::SeqCst);
        if rebuild_epoch != seen_rebuild_epoch {
            seen_rebuild_epoch = rebuild_epoch;
            if listener.is_some() {
                // R-T13: network-change rebuild — drop the existing listener so the next iteration
                // re-enters the already-audited bind path (`listener = None` -> listen_any_v4).
                log::info!("R-T13: rebuilding direct listener after Android network change");
                listener = None;
                continue;
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
        if Config::get_permanent_password_prs().is_empty() {
            if listener.is_some() {
                log::warn!(
                    "R-S9: permanent password cleared at runtime — dropping the direct listener until one is set again"
                );
                listener = None;
            } else if !parked_no_password {
                // Log ONCE per entry so a --service / Android app started before password
                // provisioning is diagnosable rather than silently non-listening.
                log::warn!(
                    "R-S9: no permanent password set — the direct listener is PARKED (nothing bound, all connections refused) until one is provisioned"
                );
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
                    listener = Some(l);
                    bind_err_streak = 0; // a successful bind resets the retry back-off
                    log::info!(
                        "Direct server listening on: {:?}",
                        listener.as_ref().map(|l| l.local_addr())
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
        if let Some(l) = listener.as_mut() {
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
// sync pk change — moot with no registration) is REMOVED with the mediator-shell sweep. Its sole
// construction site was the macOS-gated `server.rs` wait_initial_config_sync.
