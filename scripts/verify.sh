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
# R-S16(d)(ii): the runtime SwitchPermission widener (the conn-side handler that
# re-assigned conn.keyboard/clipboard/audio/... bypassing the pinned policy) is
# removed. The qualified `ipc::Data::SwitchPermission` token was unique to that
# handler arm; the CM-side senders use the unqualified `Data::SwitchPermission`
# (R-G7 GUI surface), so this gate is specific to the widener.
ra6_clean 'ipc::Data::SwitchPermission'                                  'R-S16(d)(ii) SwitchPermission widener' || rc=1
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
# R-P5 / R-SV4(b): the SignedId <-> PublicKey device-identity key bootstrap is removed. The
# viewer's `secure_connection` (the only SignedId user) + the whole initiator-side
# rendezvous/relay/NAT-punch cluster it lived in (_start_inner/connect/request_relay/
# create_relay) are deleted (Client::_start is now direct-only, fail-closed); the responder's
# handling went earlier (9e65a5b); and the `SignedId`/`PublicKey` proto messages are deleted
# (reserved 3,4). Gate the proto keying types — `SignedId`, the `set_public_key` setter, and the
# `Union::PublicKey` arm — NOT the sodiumoxide `sign::PublicKey`/`box_::PublicKey` crypto types,
# which legitimately remain. Only `//` doc comments naming SignedId survive (filtered above).
ra6_clean 'SignedId|set_public_key|message::Union::PublicKey' 'R-P5 SignedId/PublicKey device-identity keying' || rc=1
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
