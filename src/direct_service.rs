use hbb_common::{
    allow_err,
    config::{self, Config},
    log, sleep, tokio,
};

use crate::server::{check_zombie, new as new_server, ServerPtr};

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

/// R-A4 startup self-check: refuse to listen unless the controlled-side runtime
/// invariants hold. Defense-in-depth over the R-S16 funnel — confirm the policy
/// reads back pinned (verification-method/approve-mode) through Config::get_option
/// and that a usable permanent-password credential exists (R-S9). A violation is
/// fail-closed: the process exits rather than serve insecure. The empty
/// BUILTIN/HARD funnels are checked below; the companion bound-socket-surface
/// assertion (exactly one TCP v4 listener on the pinned port, zero UDP of any
/// kind) runs post-listen in `assert_socket_surface` — it needs the listener up
/// first, so it lives at the bind site rather than here.
// R-A4 is UNCONDITIONAL (R-R2b): every shipped binary refuses to listen unless the
// pinned policy + the one-TCP/zero-UDP surface verify — never behind a feature flag.
fn assert_startup_invariants() {
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
    if Config::get_permanent_password_prs().is_empty() {
        log::error!("R-A4/R-S9: no permanent password is set — refusing to listen");
        ok = false;
    }
    // R-X12: the capture+input backend is compile-pinned to X11 (is_x11() == true). Assert it at
    // startup so any future un-pin that lets is_x11() go false (a Wayland/misdetected session) refuses
    // to listen rather than silently failing X11 capture — the runtime half of the X11 pin.
    #[cfg(target_os = "linux")]
    if !crate::platform::linux::is_x11() {
        log::error!("R-X12: is_x11() is not true — the X11 capture/input pin is violated");
        ok = false;
    }
    // R-A4 / R-S9 / R-T15(d): assert the source whitelist is NOT default-open. This is a runtime
    // regression-guard on the default-deny inversion — an empty whitelist MUST block; if a refactor
    // flipped `check_whitelist` back to default-open, an empty whitelist would admit any source, so
    // here it fails closed (refuse to listen). The TEST-NET-3 sample IP (RFC 5737) must be denied
    // by an empty whitelist for the invariant to hold.
    if crate::server::Connection::whitelist_admits(
        "",
        "203.0.113.1".parse::<std::net::IpAddr>().unwrap(),
    ) {
        log::error!(
            "R-A4/R-S9: the source whitelist policy is default-OPEN (an empty whitelist admits) — refusing to listen"
        );
        ok = false;
    }
    // R-S9: surface the effective whitelist policy at startup so a default-deny lockout is never
    // SILENT. An empty whitelist is a valid deny-all (not an error), but the operator MUST know
    // inbound is fully blocked and how to open it.
    {
        let wl = Config::get_option(hbb_common::config::keys::OPTION_WHITELIST);
        let entries: Vec<&str> = wl.split(',').filter(|x| !x.is_empty()).collect();
        if entries.is_empty() {
            log::warn!(
                "R-S9: the source whitelist is EMPTY — default-deny is BLOCKING ALL inbound connections. \
                 Set whitelist=0.0.0.0/0 for connect-from-anywhere (CPace remains the gate), or a CIDR to scope access."
            );
        } else if entries.iter().any(|x| *x == "0.0.0.0" || *x == "0.0.0.0/0") {
            log::info!(
                "R-S9: the source whitelist permits ANY source (explicit 0.0.0.0/0 opt-out); CPace is the authentication gate."
            );
        } else {
            log::info!(
                "R-S9: the source whitelist restricts inbound to {} CIDR(s).",
                entries.len()
            );
        }
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
    if !hbb_common::config::BUILTIN_SETTINGS.read().unwrap().is_empty() {
        log::error!("R-A4/R-S16(d)(iv): BUILTIN_SETTINGS carries a managed override — refusing to listen");
        ok = false;
    }
    if !ok {
        log::error!("R-A4: startup invariants violated — the box refuses to run insecure");
        std::process::exit(1);
    }
}

/// R-A4 (§9) post-listen socket-surface assertion. Once the direct listener is
/// bound, the controlled box's reachable surface MUST equal exactly one TCP
/// listener on the pinned v4 port and ZERO UDP sockets of any kind (ephemeral
/// egress UDP included — a STUN probe or a dependency phoning home would slip
/// past a listener-only check). A violation is fail-closed (refuse to serve); a
/// platform without `/proc/self/net` (non-Linux) is recorded as unavailable and
/// the surface then rests on the §18 compile-out + the R-B4 build smoke-test.
/// This is a bind/listener-surface check only — it does NOT catch TCP egress
/// (an outbound connect has no listener row), which rests on R-D6 + firewall.
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
            log::error!("R-A4: socket-surface violation — {why}; refusing to serve");
            std::process::exit(1);
        }
    }
}

/// R-D4 / §17 / §18: the direct-only service entry — the minimal KEEP path lifted out of
/// the inherited `start_all`, whose register/STUN/KCP/LAN protocol is now REMOVED from
/// the tree (R-D4 Stage 2, above), not merely bypassed.
///
/// The fork ships NO rendezvous mediator: no registration loop / `register_pk` /
/// heartbeat, no STUN/NAT probe, no LAN discovery, no `hbbs_http::sync` sysinfo POST
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
pub async fn start_direct_only() {
    assert_startup_invariants();
    if config::is_outgoing_only() {
        // A viewer-only box binds no inbound listener (R-SV5); park the service future.
        loop {
            sleep(1.).await;
        }
    }
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
    loop {
        sleep(3600.).await;
    }
}

async fn direct_server(server: ServerPtr) {
    let mut listener = None;
    let mut port = 0;
    // R-T12: the consecutive accept()-error streak, driving the escalating bounded back-off in the
    // error arm below; reset on any successful accept or the benign 1s poll-timeout.
    let mut accept_err_streak: u32 = 0;
    loop {
        // R-T9 (§20): on graceful shutdown, stop accepting and drop the listener (returning here
        // drops the `listener` local, so the listening socket closes and new SYNs get an RST), then
        // leave the accept loop. begin_graceful_shutdown() drives the live-session drain and the
        // process exit; this only guarantees no new connection is admitted past the signal.
        if crate::server::is_shutting_down() {
            log::info!("R-T9: shutdown — direct_server stops accepting");
            return;
        }
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
                    // to-do: pass to ui
                    log::error!(
                        "Failed to start direct server on port: {}, error: {}",
                        port,
                        err
                    );
                    loop {
                        if port != get_direct_port() {
                            break;
                        }
                        sleep(1.).await;
                    }
                }
            }
        }
        if let Some(l) = listener.as_mut() {
            if port != get_direct_port() {
                log::info!("Exit direct access listen");
                listener = None;
                continue;
            }
            match hbb_common::timeout(1000, l.accept()).await {
                Ok(Ok((stream, addr))) => {
                    accept_err_streak = 0; // R-T12: a successful accept resets the error back-off
                    stream.set_nodelay(true).ok();
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
                            log::warn!("R-T10: failed to set TCP keepalive on {}: {}", addr, e);
                        }
                    }
                    // R-T1(b) / R-T0 rule 2: acquire a pre-key handshake slot BEFORE spawning a
                    // task or taking the server lock — so a shed connection costs accept+close,
                    // not spawn+lock+handshake. The permit moves into the task and is released
                    // after keying (server.rs), bounding only the attacker-reachable half-opens.
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
                    log::info!("direct access from {}", addr);
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
                                false,
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
