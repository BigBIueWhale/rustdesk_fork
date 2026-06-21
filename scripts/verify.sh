#!/usr/bin/env bash
#
# verify.sh — the day-to-day "secure by assertion" CI gate (§9.2/§9.3, R-V3).
#
# Runs, in a disposable container built from scripts/Dockerfile.devcheck on the
# pinned 1.75 toolchain:
#   1. the §10.4 PAKE KATs + the R-P3 self-consistency / negative KATs (R-A10);
#   2. the wire-level CPace handshake + two-key-cipher integration tests;
#   3. the R-S16 PINNED_SETTINGS policy funnel test (now unconditional, R-R2b);
#   4. a compile check of the whole main crate (hardening unconditional);
#   5. the R-A6 build-time greps — forbidden tokens of the COMPLETED excisions
#      MUST be absent; tokens of the not-yet-excised paths are reported as TODO.
#
# This is the reproducible assurance basis the §11 review and the spec's
# "secure by assertion" gates rest on. It is NOT the release build (that is the
# vcpkg flow in build-debian.sh). Exit non-zero if any gate fails.
#
# COMPANION GATE: scripts/audit.sh runs the R-R3/R-A7 dependency-advisory check
# (cargo-audit against deny.toml + a pinned advisory-db). It is kept separate
# because it needs the advisory-db + a cargo-audit compile — slower, and run in
# CI / before a release rather than on every inner-loop edit.
#
# Usage:  scripts/verify.sh
set -euo pipefail

cd "$(dirname "$0")/.."
IMG=rd-devcheck
RUN=(docker run --rm
  -v "$PWD:/work:rw"
  -v rd-cargo-cache:/usr/local/cargo/registry
  -v rd-git-cache:/usr/local/cargo/git
  -v rd-verify-target:/build
  -e CARGO_TARGET_DIR=/build
  -w /work "$IMG")

echo "== building the compile-check image =="
docker volume create rd-cargo-cache  >/dev/null
docker volume create rd-git-cache    >/dev/null
docker volume create rd-verify-target >/dev/null
docker build -q -t "$IMG" -f scripts/Dockerfile.devcheck scripts >/dev/null

echo "== (1-3) KAT + handshake + policy funnel + R-A4 surface + R-S7 frame/decompress (pinned 1.75) =="
"${RUN[@]}" cargo test -p pake -p cpace_it -p config_it -p surface_it -p compress_it -p address_it -p host_pin_it --color never

echo "== (4) main crate compile check (hardening is UNCONDITIONAL — one binary, R-R2b) =="
"${RUN[@]}" cargo check --features linux-pkg-config --color never

echo "== (5) R-A6 forbidden-token greps =="
# Greps run over the Rust source only, never requirements.html / the status docs
# (which legitimately name the tokens). A non-comment hit is a failure.
ra6_clean() { # token, human label
  local tok="$1" label="$2" hits
  hits=$(grep -RInE "$tok" src libs --include='*.rs' 2>/dev/null \
           | grep -v '//' | grep -v 'libs/pake' | grep -v 'libs/cpace_it' || true)
  if [ -n "$hits" ]; then
    echo "  FAIL R-A6: '$label' must be absent but is present:"; echo "$hits" | sed 's/^/      /'
    return 1
  fi
  echo "  ok  $label absent"
}

rc=0
# Completed excisions — these MUST stay at zero (hard gate).
ra6_clean 'crate::updater|mod updater|"download-new-version"|"update-me"' 'R-X1 auto-updater RCE'    || rc=1
ra6_clean 'plugin_framework|install_plugin_with_url|"--plugin-install"'    'R-X2 native-plugin loader' || rc=1
ra6_clean '"--import-config"|"--remove"|fn import_config'                  'R-X4 trust-anchor CLI gadgets' || rc=1
ra6_clean 'DEBUG_BOOT_COMPLETED'                                          'R-X6 fake-boot broadcast'  || rc=1
ra6_clean 'RUSTDESK_FORCED_DISPLAY_SERVER'                                'R-X12 display-server knob' || rc=1
ra6_clean 'gtk_sudo|run_cmds_privileged|"-gtk-sudo"'                      'R-X11 gtk_sudo elevation'  || rc=1
ra6_clean 'start_uinput_service'                                         'R-X13 dormant uinput listener' || rc=1
# R-X7 / §18: the responder 2FA machinery (the `require_2fa` field + the Auth2fa gate/handler +
# the trusted-device bypass + the raii session-2FA state) is excised from connection.rs — 2FA
# was pinned-off-dead (`2fa`="" so require_2fa was always None ⇒ every branch was unreachable).
# The viewer-side `send2fa` sender + the `Auth2FA` proto field + auth_2fa.rs defer with the
# Sciter sweep (R-B6, since ui.rs/remote.rs still call them), so this gate is scoped to the
# now-absent responder tokens.
ra6_clean 'require_2fa|set_session_2fa'                                   'R-X7 responder 2FA machinery' || rc=1
# R-S16(d)(ii): the runtime SwitchPermission widener (the conn-side handler that
# re-assigned conn.keyboard/clipboard/audio/... bypassing the pinned policy) is
# removed. The qualified `ipc::Data::SwitchPermission` token was unique to that
# handler arm; the CM-side senders use the unqualified `Data::SwitchPermission`
# (R-G7 GUI surface), so this gate is specific to the widener.
ra6_clean 'ipc::Data::SwitchPermission'                                  'R-S16(d)(ii) SwitchPermission widener' || rc=1
# R-A6 / R-S2 / R-G4: the switch-sides role-swap feature is FULLY excised. SwitchSidesResponse
# was a password-bypass + 2FA-skip authorization path (R-S2) — the resume itself was deleted by
# R-A2 (2cf3ad6), and this removes the rest for structural absence: the 3 proto messages
# (SwitchSidesRequest/SwitchSidesResponse/SwitchBack) + their Misc/Message Union arms, the ipc
# Data variants + relay handlers, the connection.rs UUID statics/helpers + the LIVE responder
# handler (the run_me("--switch_uuid") process-spawn), the client.rs consume/send_switch_login/
# handle_hash flow, the io_loop SwitchBack handler, and the whole flutter switch_sides FFI+UI.
# Case-sensitive, so the R-B6-deferred sciter `switch_sides` {} stub + `switch_back` trait method
# (lowercase) are not matched. The proto twin is gated just below.
ra6_clean 'SwitchSides|SwitchBack'                                       'R-A6/R-S2 switch-sides role-swap' || rc=1
if grep -qE 'SwitchSides|SwitchBack' libs/hbb_common/protos/message.proto 2>/dev/null; then
  echo "  FAIL R-A6: switch-sides proto messages/arms must be absent from message.proto"; rc=1
else echo "  ok  R-A6/R-S2 switch-sides proto absent"; fi
# R-S2 FSM-collapse: the post-keying salted-hash password oracle is deleted. With CPace
# (R-P14) every connection is mutually password-authenticated at keying, and R-A1 (now
# unconditional) refuses unkeyed streams before Connection::start, so the inherited
# login-time `validate_password`/`verify_h1` challenge-response was unreachable (R-S6) — the
# responder authorizes purely on the CPace KEYED edge. The call site now reads `!is_secured()`
# alone (fail-closed: an unkeyed stream is rejected, never password-validated). The 30-s
# recent-session resume `is_recent_session` + its entire dead SESSIONS cache (the only populator
# was `validate_password`, so it was never filled) are deleted too; the lone remaining FSM token
# is the `Hash{salt,challenge}` emission `set_hash` — still the viewer's login trigger, whose
# removal needs the prompt-flow rework (a dedicated follow-on).
ra6_clean 'validate_password|verify_h1|is_recent_session'               'R-S2 post-key oracle + recent-session resume' || rc=1
# R-SV7 / §18: the Telegram 2FA push/enrollment egress (a hardcoded api.telegram.org
# POST that leaked the box id + peer IP, gated on `bot`/`2fa` not `api-server`, so the
# R-D6 api-server pin never silenced it) is excised from the tree — structurally
# absent, not config-pinned (R-SV1). The fn defs and the URL literal are gone; only
# `//` comments naming the host remain (filtered above).
ra6_clean 'api\.telegram\.org|send_2fa_code_to_telegram|get_chatid_telegram' 'R-SV7 Telegram 2FA egress' || rc=1
# R-SV6(c) / §18: the device-deploy egress — deploy_device() POSTed {id,uuid,pk}+token to
# get_api_server()+"/api/devices/deploy" (account-server device registration a sovereign
# fork has no server for) — is excised: the endpoint literal + the --deploy CLI driver are
# gone (deploy_device is a refuse-stub; the §19/R-G4 sweep removes its flutter UI caller).
ra6_clean 'api/devices/deploy|api/devices/cli' 'R-SV6(c) device-deploy/assign egress' || rc=1
# R-D4 Stage 2 / R-SV10: the rendezvous-mediator PROTOCOL is removed from the tree (the
# register loop + register_pk method, the relay/punch-hole/intranet handlers, the UDP/KCP
# path). These worker symbols were mediator-internal and are now tree-wide absent — the
# direct-only service entry (start_direct_only -> direct_server) is all that remains.
ra6_clean 'handle_request_relay|handle_punch_hole|udp_nat_listen|punch_udp_hole|KcpStream::accept' 'R-D4 Stage 2 mediator relay/punch/KCP protocol' || rc=1
# R-SV6(b)/R-SV3/R-X3 / §18: the HBBS heartbeat/sysinfo POST loop (start_hbbs_sync_async)
# is excised — it POSTed get_sysinfo() to <api-server>/api/{heartbeat,sysinfo} and adopted
# server `strategy` config via handle_config_options (R-X3's heartbeat re-home twin). The
# endpoints + the worker + the re-home handler are gone; only the local broadcast channel
# (signal_receiver/is_pro) survives in mod hbbs_http::sync.
ra6_clean 'api/heartbeat|api/sysinfo|heartbeat_url|handle_config_options|start_hbbs_sync_async' 'R-SV6(b) HBBS heartbeat/sysinfo egress' || rc=1
# R-S18 / Appendix C #22: the viewer's auto-sent OS-credential leak is removed — upstream
# built `os_login: Some(OSLogin {os-username, os-password})` + the hwid device fingerprint
# into the LoginRequest on EVERY connect (client.rs create_login_msg), so a substituted
# peer (R-S17) harvested the operator's stored OS creds with no interaction. The responder
# already ignores os_login (0685c28); deleting the sender completes the symmetric removal.
ra6_clean 'Some\(OSLogin|\.set_logon\(' 'R-S18 viewer os_login + elevation-with-logon senders' || rc=1
# R-S15 (Appendix C #19): the viewer's in-session PeerConfig writes from peer-controlled data — the
# PeerInfo arm's username/hostname/platform (client.rs handle_peer_info) and the BackNotification
# privacy-mode impl_key (io_loop.rs update_privacy_mode) — MUST be funnelled through
# hbb_common::config::bound_peer_config_string (strip control chars + clamp length), so a
# keyed-but-hostile peer cannot inject unbounded/injection strings into the on-disk config. The
# initiator-side twin of the responder's R-S11 config-write gate. KAT: config_it tests/r_s15.rs.
r_s15_missing=
for f in src/client.rs src/client/io_loop.rs; do
  grep -q 'bound_peer_config_string' "$f" || r_s15_missing="$r_s15_missing $f"
done
if [ -n "$r_s15_missing" ]; then
  echo "  FAIL R-S15: peer-config-write bound absent in:$r_s15_missing"; rc=1
else
  echo "  ok  R-S15 viewer PeerConfig-write bound present (client.rs + io_loop.rs)"
fi
# R-T1 / R-T12 (§20 CRITICAL): the DMZ connection-flood bound + flood-safe observability MUST be
# present — the pre-key handshake semaphore (PREKEY_HANDSHAKE_SLOTS, acquired in the accept loop
# before the task is spawned, server.rs) and the rate-limited AGGREGATED security log
# (note_security_event), so an unauthenticated flood is shed before it can exhaust the host
# WITHOUT the shed itself becoming a log-amplification DoS (R-T0 rule 1). The systemd cgroup caps
# (res/rustdesk.service MemoryMax/TasksMax) bound the blast radius to the service, never the host.
r_t1_missing=
grep -q 'PREKEY_HANDSHAKE_SLOTS' src/server.rs                  || r_t1_missing="$r_t1_missing server.rs:semaphore"
grep -q 'fn note_security_event' src/server.rs                  || r_t1_missing="$r_t1_missing server.rs:agg-log"
grep -q 'try_acquire_owned' src/rendezvous_mediator.rs          || r_t1_missing="$r_t1_missing mediator:acquire-before-spawn"
grep -q 'MemoryMax=' res/rustdesk.service                       || r_t1_missing="$r_t1_missing service:MemoryMax"
if [ -n "$r_t1_missing" ]; then
  echo "  FAIL R-T1: connection-flood bound / flood-safe observability absent:$r_t1_missing"; rc=1
else
  echo "  ok  R-T1/R-T12 connection-flood bound + flood-safe observability present"
fi
# R-T7 (§20): every frame on a KEYED (Dual) stream MUST be AEAD-authenticated — the ≤1-byte
# decrypt bypass is removed from the Dual arm (the one path by which a byte could reach the
# application parser unauthenticated; also the closure of the unkeyed→keyed boundary, R-T6).
# The legacy single-key Encrypt::dec ≤1-byte (the dead rendezvous health-check heartbeat) may
# remain, so this asserts AT MOST ONE `bytes.len() <= 1` in tcp.rs (the keyed Dual one is gone).
r_t7_n=$(grep -c 'bytes.len() <= 1' libs/hbb_common/src/tcp.rs 2>/dev/null || echo 99)
if [ "$r_t7_n" -gt 1 ]; then
  echo "  FAIL R-T7: the keyed (Dual) <=1-byte decrypt bypass must be removed (found $r_t7_n in tcp.rs)"; rc=1
else
  echo "  ok  R-T7 keyed-stream <=1-byte AEAD bypass removed ($r_t7_n legacy Encrypt occurrence left)"
fi
# R-T2 (§20): the FramedStream poison flag. A keyed stream's write nonce is pre-incremented by
# `seal` before the ciphertext is flushed; reusing a stream after a send error would re-flush
# stale bytes under an advanced nonce and permanently desync the c2s direction. The poison flag
# (5th tuple field) makes "a send/recv error is fatal-to-the-connection" structural: send_bytes
# bails when poisoned and sets it on any send error; next() returns EOF when poisoned and sets it
# on any read or decrypt/auth failure. Presence gate: the short-circuit guard (>=2 sites:
# send_bytes + next) and the poison-set (>=3 sites: send error, decrypt-fail, read-err).
r_t2_guard=$(grep -c 'if self.4 {' libs/hbb_common/src/tcp.rs 2>/dev/null || echo 0)
r_t2_set=$(grep -c 'self.4 = true' libs/hbb_common/src/tcp.rs 2>/dev/null || echo 0)
if [ "$r_t2_guard" -ge 2 ] && [ "$r_t2_set" -ge 3 ]; then
  echo "  ok  R-T2 FramedStream poison flag present (guard x$r_t2_guard, poison-set x$r_t2_set)"
else
  echo "  FAIL R-T2: poison flag incomplete (guard=$r_t2_guard need>=2, set=$r_t2_set need>=3)"; rc=1
fi
# R-T8 / R-T16 (§20): the single-writer + framing/processing-order contract is CODIFIED at the
# FramedStream type (and at the Connection.stream owner) so a refactor cannot silently regress to
# a second writer (wire-interleave / cipher desync) or to parsing a raw TCP segment. The invariant
# already holds structurally — the write API is &mut self, the type owns a Box<dyn> socket and is
# not Clone, and the stream is never split / Arc<Mutex>-wrapped — so this gate (a) keeps the
# contract docs present and (b) forbids the one realistic second-writer regression: an Arc<Mutex>
# write-wrapper or a `.split()` of the stream in CODE (doc-comment mentions, `///`, are excluded).
r_t8_missing=
grep -q 'Single-writer contract (R-T8' libs/hbb_common/src/tcp.rs        || r_t8_missing="$r_t8_missing tcp-writer-doc"
grep -q 'Framing + processing-order contract (R-T16' libs/hbb_common/src/tcp.rs || r_t8_missing="$r_t8_missing tcp-framing-doc"
grep -q 'the single writer' src/server/connection.rs                     || r_t8_missing="$r_t8_missing conn-stream-doc"
if grep -n '\.split()' libs/hbb_common/src/tcp.rs 2>/dev/null | grep -vq '///'; then
  r_t8_missing="$r_t8_missing tcp-split!"
fi
if grep -rn 'Arc<.*Mutex<.*FramedStream' src libs/hbb_common/src 2>/dev/null | grep -vq '///'; then
  r_t8_missing="$r_t8_missing arc-mutex-framedstream!"
fi
if [ -n "$r_t8_missing" ]; then
  echo "  FAIL R-T8/R-T16: single-writer/framing contract codification incomplete or violated:$r_t8_missing"; rc=1
else
  echo "  ok  R-T8/R-T16 single-writer + framing/processing-order contract codified (no second-writer handle)"
fi
# R-T9 (§20): graceful shutdown on SIGTERM/SIGINT. A process-wide CancellationToken (server.rs) is
# cancelled by the signal handler (rendezvous_mediator.rs); the accept loop then stops accepting and
# drops its listener, every live session's run-loop drains via its `cancelled()` select-arm
# (CloseReason -> flush -> CM Close), and a BOUNDED drain deadline — shorter than the unit's
# TimeoutStopSec — precedes a force-exit(0). The pkill/KillMode=mixed path stays the backstop.
# Presence gate across the three layers (server primitive, connection drain arm, mediator handler).
r_t9_missing=
grep -q 'fn begin_graceful_shutdown' src/server.rs         || r_t9_missing="$r_t9_missing begin_graceful_shutdown"
grep -q 'fn is_shutting_down' src/server.rs                || r_t9_missing="$r_t9_missing is_shutting_down"
grep -q 'SHUTDOWN_TOKEN' src/server.rs                     || r_t9_missing="$r_t9_missing SHUTDOWN_TOKEN"
grep -q 'shutdown.cancelled()' src/server/connection.rs    || r_t9_missing="$r_t9_missing conn-drain-arm"
grep -q 'SignalKind::terminate' src/rendezvous_mediator.rs || r_t9_missing="$r_t9_missing sigterm-handler"
grep -q 'is_shutting_down()' src/rendezvous_mediator.rs    || r_t9_missing="$r_t9_missing accept-stop"
grep -q 'TimeoutStopSec' res/rustdesk.service              || r_t9_missing="$r_t9_missing service-timeoutstopsec"
if [ -n "$r_t9_missing" ]; then
  echo "  FAIL R-T9: graceful-shutdown machinery incomplete:$r_t9_missing"; rc=1
else
  echo "  ok  R-T9 graceful shutdown present (signal handler + accept-stop + drain arm + bounded exit)"
fi
# R-T14 (§20): the cross-backend cancellation-safety guarantee — dropping a tokio read future
# consumes ZERO bytes on epoll/kqueue/IOCP because mio's do_io does a synchronous std recv (no
# kernel overlapped buffer in flight) — MUST be documented WITH its mio/tokio citation at the read
# site (the basis R-T5 relies on), so a contributor cannot "fix" it with a hand-rolled WSARecv
# overlapped read that would reintroduce a real per-OS hazard. Presence gate on the citation.
r_t14_missing=
grep -q 'R-T14' libs/hbb_common/src/tcp.rs                   || r_t14_missing="$r_t14_missing anchor"
grep -q 'mio 1.0.3 / tokio 1.44.2' libs/hbb_common/src/tcp.rs || r_t14_missing="$r_t14_missing citation"
grep -q 'do_io' libs/hbb_common/src/tcp.rs                   || r_t14_missing="$r_t14_missing do_io-basis"
if [ -n "$r_t14_missing" ]; then
  echo "  FAIL R-T14: cross-backend cancellation-safety citation incomplete:$r_t14_missing"; rc=1
else
  echo "  ok  R-T14 cross-backend cancellation-safety guarantee documented (mio/tokio cited at read site)"
fi
# R-S9 / R-T15(d) (§20): check_whitelist is inverted to DEFAULT-DENY — an unset or all-unparseable
# whitelist BLOCKS (it does not pass), with an explicit 0.0.0.0/0 entry the auditable
# connect-from-anywhere opt-out. The decision is factored into a pure `whitelist_admits` so
# assert_startup_invariants (R-A4) asserts the "not default-open" invariant at runtime (an empty
# whitelist MUST deny, else refuse to listen). The legacy default-ALLOW gate must be gone.
r_t15d_missing=
grep -q 'fn whitelist_admits' src/server/connection.rs    || r_t15d_missing="$r_t15d_missing admits-fn"
grep -q 'Self::whitelist_admits' src/server/connection.rs || r_t15d_missing="$r_t15d_missing check-uses-admits"
grep -q 'whitelist_admits(' src/rendezvous_mediator.rs    || r_t15d_missing="$r_t15d_missing a4-selftest"
if grep -q '!whitelist.is_empty()' src/server/connection.rs; then
  r_t15d_missing="$r_t15d_missing legacy-default-allow!"
fi
if [ -n "$r_t15d_missing" ]; then
  echo "  FAIL R-S9/R-T15(d): default-deny whitelist incomplete:$r_t15d_missing"; rc=1
else
  echo "  ok  R-S9/R-T15(d) whitelist default-deny + R-A4 not-default-open self-test present"
fi
# R-T15(a) / R-P12: secret-zeroization in libs/pake — curve25519-dalek 4.1.3 impls the Zeroize
# TRAIT but not Drop, so secrets not explicitly wiped linger on attacker-inducible abort/timeout
# paths. The ISK master secret is wrapped in Zeroizing, the initiator's ephemeral scalar is wiped
# on the decompress-error early-return, and the two *AwaitConfirm states carry a Drop that wipes
# their session keys / ephemeral scalar on the R-P14b step-timeout drop. The KATs check derived
# VALUES, not wiping, so this is a presence gate.
r_t15a_missing=
grep -q 'impl Drop for InitiatorAwaitConfirm' libs/pake/src/lib.rs || r_t15a_missing="$r_t15a_missing InitiatorDrop"
grep -q 'impl Drop for ResponderAwaitConfirm' libs/pake/src/lib.rs || r_t15a_missing="$r_t15a_missing ResponderDrop"
grep -q 'Zeroizing::new(compute_isk' libs/pake/src/lib.rs            || r_t15a_missing="$r_t15a_missing isk-Zeroizing"
if [ -n "$r_t15a_missing" ]; then
  echo "  FAIL R-T15(a): pake secret-zeroization absent:$r_t15a_missing"; rc=1
else
  echo "  ok  R-T15(a) pake secret-zeroization present (isk Zeroizing + *AwaitConfirm Drop)"
fi
# R-T11 (§20): the PUBLIC listener (listen_any_v4) MUST bind WITHOUT SO_REUSEPORT — a single-
# instance service needs no kernel load-balance group, and REUSEPORT lets another same-uid (root)
# process silently join the group and steal inbound connections (invisible to R-A4's own-process
# /proc self-check, violating R-D3 "no second listener"). It binds via the dedicated
# new_listener_socket (SO_REUSEADDR on non-Windows only; Windows omits it for an exclusive bind).
if grep -A4 'pub async fn listen_any_v4' libs/hbb_common/src/tcp.rs | grep -q 'new_listener_socket'; then
  echo "  ok  R-T11 public listener binds via REUSEPORT-free new_listener_socket"
else
  echo "  FAIL R-T11: listen_any_v4 must bind via new_listener_socket (no SO_REUSEPORT)"; rc=1
fi
# R-P5 / R-SV4(b): the SignedId <-> PublicKey device-identity key bootstrap is removed. The
# viewer's `secure_connection` (the only SignedId user) + the whole initiator-side
# rendezvous/relay/NAT-punch cluster it lived in (_start_inner/connect/request_relay/
# create_relay) are deleted (Client::_start is now direct-only, fail-closed); the responder's
# handling went earlier (9e65a5b); and the `SignedId`/`PublicKey` proto messages are deleted
# (reserved 3,4). Gate the proto keying types — `SignedId`, the `set_public_key` setter, and the
# `Union::PublicKey` arm — NOT the sodiumoxide `sign::PublicKey`/`box_::PublicKey` crypto types,
# which legitimately remain. Only `//` doc comments naming SignedId survive (filtered above).
ra6_clean 'SignedId|set_public_key|message::Union::PublicKey' 'R-P5 SignedId/PublicKey device-identity keying' || rc=1
# R-SV4(b)/R-S13(d)/R-SV10 (no rendezvous path in either role): the initiator-side
# rendezvous/relay/NAT-punch cluster (Client::_start_inner / secure_connection /
# udp_nat_connect) AND the responder-side relay-dialer (create_relay_connection — which dialed
# a relay server via set_request_relay, a "dial nobody" violation if ever reached) are deleted,
# orphaned by the mediator excision (R-D4). This locks in R-SV10's "no path reaches
# Client::_start's rendezvous branch" so a regression cannot silently re-introduce one. (The
# proto setter set_request_relay is intentionally NOT gated — it lives in generated code.)
ra6_clean 'create_relay_connection|_start_inner|secure_connection|udp_nat_connect' 'R-SV4(b)/R-SV10 rendezvous/relay connect cluster' || rc=1
# R-SV / R-D / §18 (dial nobody): the viewer's peer-list ONLINE-STATUS query is removed — it
# connected to get_rendezvous_server() (defaulting to the built-in rs-ny.rustdesk.com) and sent an
# OnlineRequest carrying Config::get_id() + the peer ids (a box-id + peer-list leak on every list
# refresh). The egress fns (create_online_stream / the OnlineRequest send) are gone; peer_online
# now reports every peer offline with no network call. (Only `//` comments name them, filtered.)
ra6_clean 'create_online_stream|set_online_request' 'R-SV viewer online-status egress' || rc=1
# R-SV6(b) / R-G4 / §18 (dial nobody): the OIDC ACCOUNT-LOGIN egress is excised. account.rs's
# auth_task POSTed { deviceInfo: get_login_device_info() } to <api-server>/api/oidc/auth (a
# device-fingerprint leak), polled /api/oidc/auth-query for an access token, and warmed
# /api/login-options. OidcSession::account_auth is now a refuse-stub with NO network call (R-SV1
# structural absence, not the empty-api-server pin). Only `//` doc comments name the endpoints.
ra6_clean 'api/oidc|fn auth_task' 'R-SV6(b)/R-G4 OIDC account-login egress' || rc=1
# R-SV4(b) / R-D5 / §18: the common.rs NAT-type/IPv6 STUN probes are removed — test_nat_ipv4 /
# test_ipv6 -> stun_ipv4_test/stun_ipv6_test resolved + queried hardcoded public STUN servers
# (stun.l.google.com etc.). A direct-IP fork does no NAT traversal; the probes were dead
# (test_nat_type is a no-op, df3d12f) and are deleted structurally (R-SV1), with the `stunclient`
# crate dep dropped. (The other STUN source, `webrtc.rs DEFAULT_ICE_SERVERS`, is DEAD SOURCE — the
# `webrtc` feature is never enabled in the fork, so that module is not compiled; removing the
# whole webrtc transport is an un-verifiable-here follow-on, like the Windows/sciter excisions.)
ra6_clean 'STUNS_V4|STUNS_V6|stunclient|stun_ipv4_test|stun_ipv6_test|test_nat_ipv4|stun\.l\.google' 'R-SV4(b) common.rs STUN NAT-probes' || rc=1
# R-G6 / R-SV4: the direct-only fork has no relay to fall back to, so the inherited
# connection-failure "relay-hint" advice (try a relay / add the "/r" suffix) is dead and
# misdirecting. on_establish_connection_error now always surfaces the plain error msgbox;
# the "relay-hint"/"relay-hint2" emission is removed. (The hyphenated token is distinct from
# the lang key `relay_hint_tip` (underscore), whose 51-file sweep is a deferred lang cleanup.)
ra6_clean 'relay-hint' 'R-G6 relay-fallback hint emission' || rc=1
# §19 closing-box dead-lang-key sweep: lang keys whose UI was removed by earlier §8/§18/§19
# work and which now have NO live translate() caller — relay_hint_tip/websocket_tip (R-G6,
# relay/websocket UI), enable-2fa-title/enable-bot-tip (R-X7, 2FA UI), powered_by_me (R-G8,
# the "Powered by RustDesk" badge). Removed from all 51 lang tables + the lang.rs RustDesk
# app-name substitution exclusion that only existed to protect the powered_by_me string.
ra6_clean '"(relay_hint_tip|websocket_tip|enable-2fa-title|enable-bot-tip|powered_by_me)"' '§19 dead lang keys' || rc=1

echo "== pending excisions (informational TODO, not yet a hard gate) =="
for t in 'mod auth_2fa:R-X7 2FA/TOTP' 'mod lan:R-X5 LAN discovery' \
         'terminal_helper:R-X8 terminal' 'mod custom_server:R-X4 custom_server module'; do
  tok=${t%%:*}; lbl=${t#*:}
  n=$(grep -RIl "$tok" src libs --include='*.rs' 2>/dev/null | grep -v 'libs/pake' | wc -l | tr -d ' ')
  echo "  TODO $lbl — still referenced in $n file(s)"
done

if [ "$rc" -ne 0 ]; then
  echo "VERIFY: FAILED (a completed-excision R-A6 gate regressed)"; exit 1
fi
echo "VERIFY: all gates green (KATs + handshake + policy funnel + main-crate compile + R-A6 done-set)"
