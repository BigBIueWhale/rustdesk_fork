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
# COMPANION GATE: scripts/apple-conform-check.sh runs the R-R2 apple (macOS/iOS)
# SOURCE-conformance gate — the retain-and-check invariant + the R-A6 greps on the
# Apple cfg + a cross-compile `cargo check --target *-apple-*` (the macOS-pinned Rust
# 1.81). Kept separate because it builds a second toolchain image and cross-checks the
# apple targets (slower), and apple is NOT a build target (R-R2) — a pre-release / CI
# gate, not an inner-loop one. The Linux `cargo check` below cannot see the cfg(macos)/
# cfg(ios) clusters, so that gate is where their hardening is proven.
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

# (3b) IPC parent-dir hardening BEHAVIOR (R-S11a / R-S11a(b)): the docker test-runner is root, so these
# unit tests actually exercise the root-only branches — symlink-parent reject, and the R-S11a(b)
# foreign-owned service dir REJECT-AND-RECREATE (fresh inode, never fchown-adopt) + its fail-closed on a
# non-emptyable foreign dir. These were un-run before (verify.sh only `cargo check`ed the main crate).
echo "== (3b) IPC parent-dir hardening behavior tests (R-S11a/R-S11a(b), root-exercised) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config ipc::ipc_fs::tests --color never

# (3b-i) IPC service-socket peer-uid AUTHORIZATION policy (R-S11a / §17 root box): the Linux `_service`
# IPC socket is 0666 (world-connectable so the active non-root user process can reach it), gated at
# accept-time by is_allowed_service_peer_uid — admits ONLY root (SO_PEERCRED uid 0) or the active-session
# uid, and FAIL-CLOSED (root-only) when active_uid is unknown — backed by a /proc/pid/exe match against
# the current binary. test_service_peer_uid_policy pins that boundary; it lives in `ipc::ipc_auth::tests`,
# which the `ipc::ipc_fs::tests` filter above does NOT match, so it was previously UNGATED. Gate it so the
# local-privilege-escalation boundary on the root box cannot silently regress (the win/macos peer-policy
# tests in the same module are cfg-compiled out on this Linux build and simply filter out).
echo "== (3b-i) IPC service-socket peer-uid authorization policy (R-S11a/§17) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config ipc::ipc_auth::tests --color never

# (3b-ii) api-server RESOLUTION sovereignty (R-SV6(d)/R-D6): get_api_server("","") and
# get_custom_rendezvous_server("") must resolve to "" — no hardwired global host. The upstream
# "https://admin.rustdesk.com" fallback is excised and PROD_RENDEZVOUS_SERVER stays empty (zero
# write sites), so the account/address-book HttpService egress (post_request / main_http_request
# -> create_http_client_async) dials NOBODY by default. This guards the resolution layer; the
# config-pin layer (api-server/custom-rendezvous-server pinned empty) is covered by config_it.
echo "== (3b-ii) api-server resolution dials-nobody behavior test (R-SV6(d)) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config common::tests::api_server_resolution_defaults_to_sovereign_empty --color never

# (3b-iv) R-A4/R-X4: the rendezvous trust anchor (get_key) must return the baked RS_PUB_KEY and IGNORE
# a stored "key" override. Upstream re-pointed the client via Config::get_option("key") / the async IPC
# options blob / the Windows license; the fork reads NO override. "key" is unpinned so the override
# actually persists, so this proves the READ is inert (the runtime half of R-X4 — the CLI gadgets that
# wrote it are gone, gated separately at R-X4). A regression reverting get_key to the override read
# would pass the CLI-gadget gate but FAIL here.
echo "== (3b-iv) trust-anchor get_key ignores a stored override (R-A4/R-X4) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config common::tests::get_key_is_the_pinned_anchor_ignoring_overrides --color never

# (3b-iii) R-S11 / Appendix C #15: the MAIN IPC channel (UI⇄service, 0o0600 same-uid) is a config-
# integrity boundary. main_channel_admits_config_write is a POSITIVE allowlist over the config-mutating
# arms, rejecting: (a) the whole-config SyncConfig(Some) push (Config::set overwrites the ENTIRE config
# with NO is_option_can_save/pin check); (b) the Data::Config STRUCT-FIELD writes that bypass
# is_option_can_save — `id` (+ set_key_confirmed(false)) and `salt` (set_salt's hashed-pw guard is a
# no-op under the fork's PRS-plaintext) — which have NO legit main-channel writer; (c) Data::Socks(Some)
# (set_socks, the proxy/local-MITM primitive an Options-key allowlist would miss). The legit operator
# writes (permanent-password / unlock-pin / voice-call-input) + reads (value=None) pass. The cross-uid
# sync uses the peer-uid-gated _service channel. Behavior-tested AND the loop routes through the
# allowlist before handle() (R-A6 reachability), AND the allowlist is asserted POSITIVE (not a one-arm
# denylist that would let id/salt/Socks through — the exact "missed sibling" the 5th sweep found).
echo "== (3b-iii) IPC main-channel config-write positive allowlist (R-S11) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config ipc::test::main_channel_rejects_whole_config_sync_write --color never
r_s11=
grep -q 'if !main_channel_admits_config_write(&data)' src/ipc.rs                       || r_s11="$r_s11 loop-not-wired"
grep -qE '"permanent-password" \| "unlock-pin" \| "voice-call-input"' src/ipc.rs       || r_s11="$r_s11 no-positive-config-allowlist"
grep -q 'Data::Socks(Some(_)) => false' src/ipc.rs                                     || r_s11="$r_s11 socks-not-rejected"
if [ -n "$r_s11" ]; then echo "  FAIL R-S11 main-channel config-write allowlist:$r_s11"; rc=1; else
  echo "  ok  R-S11 main-channel config-write POSITIVE allowlist (SyncConfig+id+salt+Socks rejected; legit operator writes pass)"; fi

# (3c) File-transfer write-path safety (R-S8/R-A5): the receive-write opens are NO-FOLLOW
# (open_recv_write_no_follow / O_NOFOLLOW) so a local symlink swapped in at the target after the
# path-validation fails the open rather than redirecting root's write (the §4.3 symlink TOCTOU).
# These hbb_common fs tests were previously UN-RUNNABLE on the pinned 1.75 (a dead webrtc dev-dep
# pulled sdp/webrtc-util which need a newer rustc) — now runnable after that excision (R-SV4).
echo "== (3c) file-transfer no-follow write + path-traversal tests (R-S8/R-A5) =="
"${RUN[@]}" cargo test -p hbb_common --lib fs::tests --color never

# (3c-i) IPC service-path sharing (R-S11a / R-X13): the `_service` cross-user socket path MUST resolve
# the SAME under root and the active user (shared `-service/` parent dir) so the user `--server`/UI
# process can reach the root service, while non-service channels stay per-uid. After R-X13 collapsed
# is_service_ipc_postfix to `_service`-only (the `_uinput_*` channels excised with the uinput module),
# this guards that the surviving service channel still shares correctly. (Classification is separately
# gated by config_it/ipc_socket_mode.rs; this is the path-resolution consequence.)
echo "== (3c-i) IPC _service path-sharing across uids (R-S11a/R-X13) =="
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_service_ipc_path_is_shared_across_uids --color never

echo "== (4) main crate compile check (hardening is UNCONDITIONAL — one binary, R-R2b) =="
"${RUN[@]}" cargo check --features linux-pkg-config --color never

# (4a) the SHIPPED release ALSO enables unix-file-copy-paste (build.py --flutter --unix-file-copy-paste,
# flutter-build.yml) — the clipboard-FILE Cliprdr arm (connection.rs, R-A2 capability gate at (5)) is
# compiled ONLY under that feature, so (4) above never compiles it. Compile-check it too so the arm + its
# can_sub_file_clipboard_service() gate stay buildable (this feature pulls the FUSE clipboard-file path).
echo "== (4a) unix-file-copy-paste feature compile check (the shipped clipboard-file arm) =="
"${RUN[@]}" cargo check --features linux-pkg-config,unix-file-copy-paste --color never

echo "== (5) R-A6 forbidden-token greps =="
# Greps run over the Rust source only, never requirements.html / the status docs
# (which legitimately name the tokens). A non-comment hit is a failure.
ra6_clean() { # token, human label
  local tok="$1" label="$2" hits
  hits=$(grep -RInE "$tok" src libs --include='*.rs' 2>/dev/null \
           | grep -v '//' | grep -v 'libs/pake' | grep -v 'libs/cpace_it' \
           | grep -v 'bridge_generated' || true)  # bridge_generated.rs(.io.rs) are gitignored FRB
                                                   # output regenerated from flutter_ffi.rs; a gate
                                                   # validates source, never a derived artifact.
  if [ -n "$hits" ]; then
    echo "  FAIL R-A6: '$label' must be absent but is present:"; echo "$hits" | sed 's/^/      /'
    return 1
  fi
  echo "  ok  $label absent"
}

rc=0
# Completed excisions — these MUST stay at zero (hard gate).
ra6_clean 'crate::updater|mod updater|"download-new-version"|"update-me"' 'R-X1 auto-updater RCE'    || rc=1
# R-X1 / R-SV2 / R-A6 — the self-updater FUNCTION surface the string-key gate above missed: the
# platform fetch-and-run re-install (macOS update_me/update_from_dmg/update_to/extract_update_dmg,
# Windows update_me/update_to/update_me_msi) + the main_update_me FFI that drove them. R-A6 names
# update_me/update_from_dmg/extract_update_dmg in its Apple-cfg pass; all must be absent on EVERY
# source (these clusters are cfg(macos)/cfg(windows), invisible to the Linux cargo check below).
ra6_clean 'fn update_me\b|main_update_me|update_from_dmg|extract_update_dmg|update_me_msi|fn update_to\b' 'R-X1 self-updater fns (macOS DMG / Windows MSI / FFI)' || rc=1
ra6_clean 'plugin_framework|install_plugin_with_url|"--plugin-install"'    'R-X2 native-plugin loader' || rc=1
ra6_clean '"--import-config"|"--remove"|fn import_config'                  'R-X4 trust-anchor CLI gadgets' || rc=1
# R-X5: the LAN-discovery UDP listener/querier (the 0.0.0.0:RENDEZVOUS_PORT+3=21119 responder that
# disclosed MAC/ID/hostname/active-username/platform, removed in 322aebb) MUST stay absent — §8's
# "removed not disabled" bar + R-A4's zero-UDP runtime check. (lan.rs persists only for WoL +
# a discover() no-op, a separate R-G2 Discovered-tab follow-on; that residual is the TODO below.)
ra6_clean 'start_lan_listening|spawn_wait_responses|handle_received_peers|RENDEZVOUS_PORT *\+ *3' 'R-X5 LAN-discovery listener/querier/bind' || rc=1
# R-SV4(c)/R-SV10 / §18: Wake-on-LAN is DROPPED. The inherited lan::send_wol broadcast WoL magic
# packets (UDP) over EVERY LAN interface (`wol::send_wol`, iterating default_net interfaces × the
# stored LanPeer MACs) — a live viewer-side LAN egress at odds with the direct-IP-only/sovereign
# posture (R-SV5). send_wol is now a NO-OP; assert the wol::send_wol broadcast call is gone (its only
# caller flutter_ffi::main_wol is then a harmless stub — the Dart WoL peer-card UI removal is the R-G2
# follow-on). discover() was already a no-op (R-X5).
ra6_clean 'wol::send_wol' 'R-SV4(c) Wake-on-LAN UDP-broadcast egress (lan::send_wol)' || rc=1
# R-SV1 / R-X1 / §18: the hbbs_http::downloader reqwest-GET fetch-to-buffer subsystem is EXCISED. It was
# orphaned by the R-X1 updater excision — its sole starter (the `download-new-version` Flutter key +
# updater::get_download_file_from_url) was already gone, leaving `download_file` caller-less and the
# `download-data-`/`remove-downloader`/`cancel-downloader` Dart keys unreachable. Removed wholesale (the
# module file + the flutter_ffi key handlers) so the binary cannot perform that GET — the code is gone.
if [ -e src/hbbs_http/downloader.rs ]; then
  echo "  FAIL R-SV1: the excised hbbs_http/downloader.rs reappeared"; rc=1
else
  echo "  ok  R-SV1 hbbs_http/downloader.rs module file absent"
fi
ra6_clean 'hbbs_http::downloader|mod downloader|fn do_download' 'R-SV1 downloader call-path/module/worker' || rc=1
ra6_clean 'DEBUG_BOOT_COMPLETED'                                          'R-X6 fake-boot broadcast'  || rc=1
# R-X6: the Linux D-Bus deep-link delivery transport (src/server/dbus.rs: session-bus name
# org.rustdesk.rustdesk, method NewConnection) is EXCISED. It ignored the caller (any co-installed
# same-session app could fire it — a local-IPC injection vector) and claimed the bus name with
# replace_existing=true (a name-hijack to intercept legitimate links). The module is deleted; uni-links
# are self-handled per-instance (core_main); their embedded key/password/relay is stripped (R-X6, below). \bstart_dbus_server
# excludes the kept no-op FFI shim main_start_dbus_server (no word boundary before "start").
ra6_clean 'crate::dbus|org\.rustdesk\.rustdesk|\bstart_dbus_server' 'R-X6 D-Bus deep-link transport (NewConnection)' || rc=1
# R-X6 (cont.): dbus-crossroads (the D-Bus SERVER framework) was the dead Cargo-dep residual of the
# excised dbus.rs — zero crossroads:: usage remains, so the dep is dropped. Assert it stays gone (the
# base `dbus` crate stays for the legit platform/linux.rs session-bus call — do NOT gate that out).
grep -qE '^dbus-crossroads = ' Cargo.toml && { echo "  FAIL R-X6: the dead dbus-crossroads dep (only the excised dbus.rs used it) is back in Cargo.toml"; rc=1; }
# R-X6 (macOS _url sender-auth): the SEPARATE _url deep-link IPC listener (server::start_ipc_url_server)
# bypasses the main handle() service-accept gate, so it MUST authenticate its sender (peer-uid + peer-exe)
# like the protected _service channel — else any same-uid process injects a rustdesk:// connect/relay/key.
if grep -qE 'fn start_ipc_url_server' src/server.rs && ! grep -qE 'authorize_url_ipc_sender' src/server.rs; then
  echo "  FAIL R-X6: macOS start_ipc_url_server does not authenticate its _url IPC sender (peer-uid+exe)"; rc=1
else
  echo "  ok  R-X6 macOS _url IPC listener authenticates its sender (authorize_url_ipc_sender)"
fi
# R-X6 deep-link embedded-credential strip — BOTH layers (a Dart-only strip is bypassable, since the raw
# URI reaches the Rust core via bind.sendUrlScheme). (1) The Dart parser urlLinkToCmdArgs
# (flutter/lib/common.dart) MUST NOT fold an embedded ?key= into the id, nor propagate ?password=/?relay=
# into the connect call or the launch args — a malicious rustdesk:// link must carry no trust anchor/cred.
if grep -qF '?key=$key' flutter/lib/common.dart || grep -qF "['--password', password]" flutter/lib/common.dart; then
  echo "  FAIL R-X6: flutter/lib/common.dart deep-link parser still carries an embedded key/password"; rc=1
elif ! grep -qF 'connect-only and MUST NOT carry an embedded' flutter/lib/common.dart; then
  echo "  FAIL R-X6: the urlLinkToCmdArgs R-X6 strip marker is gone (regrowth risk)"; rc=1
else
  echo "  ok  R-X6 Dart deep-link parser strips embedded key/password/relay"
fi
# (2) The Rust core LoginConfigHandler::initialize (src/client.rs) MUST NOT adopt an embedded ?key= into
# other_server, nor re-adopt a persisted/option-injected other-server-key.
if grep -qE 'args_map\.remove\("key"\)' src/client.rs; then
  echo "  FAIL R-X6: src/client.rs still parses an embedded ?key= into other_server"; rc=1
elif ! grep -qF 'NEVER adopt an embedded' src/client.rs; then
  echo "  FAIL R-X6: the client.rs ?key= strip marker is gone (regrowth risk)"; rc=1
else
  echo "  ok  R-X6 Rust core never adopts an embedded ?key= (other_server key held empty)"
fi
# R-X6 confirmation gate: a deep-link-initiated connection MUST be confirmed by the user. The Dart gate
# (confirmDeepLinkConnect via msgBox) wraps every rustdesk:// connect, routed through the `fromUri`
# discriminator so the user-typed CLI is NOT gated but every URI-derived connect is.
if grep -qF 'confirmDeepLinkConnect' flutter/lib/common.dart && grep -qF 'fromUri' flutter/lib/common.dart; then
  echo "  ok  R-X6 deep-link connect is confirmation-gated (confirmDeepLinkConnect + fromUri)"
else
  echo "  FAIL R-X6: the deep-link-connect confirmation gate (confirmDeepLinkConnect/fromUri) is missing"; rc=1
fi
# R-X6 deep-link WRITE authorities: rustdesk://config/<b64> (server + key trust-anchor write) and
# rustdesk://password/<pw> (permanent-password write) MUST be ignored, not honored (the same trust-anchor
# / credential-injection class as R-X4). Assert urlLinkToCmdArgs still treats them as ignore-return-null.
if grep -qF '["config", "password"].contains(uri.authority)' flutter/lib/common.dart && grep -qF 'Ignoring rustdesk:// server/credential write authority' flutter/lib/common.dart; then
  echo "  ok  R-X6 deep-link config/password WRITE authorities are ignored (no trust-anchor/credential write)"
else
  echo "  FAIL R-X6: the rustdesk://config + rustdesk://password WRITE authorities are not provably excised"; rc=1
fi
# R-X6 Android manifest hardening (committed d4cb686 + f8ddac8) — lock it against regrowth. The dropped
# tokens survive only in explanatory comments, so gate on LIVE <uses-permission>/<service> declarations +
# the allowBackup/requestLegacyExternalStorage attributes + the cleartext-deny network-security-config.
AMF=flutter/android/app/src/main/AndroidManifest.xml
if grep -qF 'android:allowBackup="false"' "$AMF" \
   && ! grep -qE '(uses-permission|<service)[^>]*(SYSTEM_ALERT_WINDOW|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|FloatingWindowService)' "$AMF" \
   && ! grep -qE 'android:requestLegacyExternalStorage' "$AMF" \
   && grep -qF 'cleartextTrafficPermitted="false"' flutter/android/app/src/main/res/xml/network_security_config.xml; then
  echo "  ok  R-X6 Android manifest hardened (allowBackup=false; no live overlay/legacy-storage/floating-svc decl; cleartext-deny)"
else
  echo "  FAIL R-X6: Android manifest hardening regressed (allowBackup / a live SYSTEM_ALERT_WINDOW|storage|FloatingWindowService decl / requestLegacyExternalStorage / network-security-config)"; rc=1
fi
# R-X6 Android: the dead floating-window / SYSTEM_ALERT_WINDOW Dart UI is excised (commit 917ebd0; the
# native FloatingWindowService was cut in f8ddac8). Assert no LIVE kSystemAlertWindow reference regrows in
# the Flutter UI — a regrown overlay-permission request would re-introduce the dropped permission AND the
# canStartOnBoot silent-disable boot-start bug. (Filter the grep -rn 'file:line:' prefix so the lone
# explanatory comment in consts.dart is not a false positive.)
if grep -rn 'kSystemAlertWindow' flutter/lib/ | grep -vE ':[0-9]+:[[:space:]]*//' | grep -q .; then
  echo "  FAIL R-X6: a live kSystemAlertWindow reference regrew in flutter/lib (floating-window/overlay UI)"; rc=1
else
  echo "  ok  R-X6 Android floating-window / SYSTEM_ALERT_WINDOW Dart UI excised (no live ref)"
fi
# R-X8/R-X6 terminal-admin (run-as-administrator) viewer mode -- EXCISED. It set IS_TERMINAL_ADMIN=Y, which
# client.rs handle_hash short-circuited into a msgbox ("terminal-admin-login") the Flutter model has NO
# handler for -> a guaranteed blank-dialog dead-end that then closes the connection (a 100%-failure
# affordance). The field + env + the get_key admin branch + the 5 peer-card menu items + the --terminal-admin
# CLI + the terminal-admin deep-link are all removed; the plain (non-admin) _terminalAction stays. (The inert
# terminal-admin-login-tip lang strings are harmless localization data and are intentionally left in place.)
ra6_clean 'is_terminal_admin|IS_TERMINAL_ADMIN|terminal-admin-service-id' 'R-X8/R-X6 terminal-admin viewer field/env/service-id-key' || rc=1
if grep -rqE 'setEnvTerminalAdmin|_terminalRunAsAdminAction|IS_TERMINAL_ADMIN|terminal-admin|isTerminalRunAsAdmin' flutter/lib/; then
  echo "  FAIL R-X8/R-X6: a terminal-admin (run-as-administrator) trigger regrew in flutter/lib"; rc=1
elif grep -rqF '_terminalAction(context)' flutter/lib/common/widgets/peer_card.dart; then
  echo "  ok  R-X8/R-X6 terminal-admin viewer mode excised (env/method/menu/CLI/deep-link); non-admin terminal kept"
else
  echo "  FAIL R-X8/R-X6: the non-admin _terminalAction was lost (over-excision)"; rc=1
fi
ra6_clean 'ConfigureUpdate|TestNatResponse'                              'R-X3 server-push config-update + NAT-response rewrite arms' || rc=1
# R-P3 / R-P14: the inherited insecure direct-mode used a plaintext constant-byte ack ("direct-ok")
# to admit a peer WITHOUT the PAKE key-confirmation. The fork makes CPace mandatory (R-A1), so any
# such constant ack MUST stay absent — its return would be a PAKE bypass.
ra6_clean 'direct-ok'                                                     'R-P3 insecure constant-byte ack (direct-ok), PAKE bypass' || rc=1
ra6_clean 'RUSTDESK_FORCED_DISPLAY_SERVER'                                'R-X12 display-server knob' || rc=1
# R-X12: is_x11() is compile-pinned `true` in BOTH the main crate (src/platform/linux.rs) and scrap
# (libs/scrap/src/common/mod.rs) — the capture+input backend is X11 with NO runtime display-server
# selector (the `*IS_X11` detection cache + the is_x11_or_headless() body are gone). Startup-asserted
# (R-A4, direct_service). Guards a regression that re-adds runtime capture/input backend selection.
# (The scrap `wayland` feature drop + `mod wayland` compile-out is the remaining R-X12 stage — task #4.)
r_x12_pin=
grep -A1 'pub fn is_x11() -> bool {' src/platform/linux.rs        | grep -qE '^\s*true\s*$' || r_x12_pin="$r_x12_pin main-is_x11"
grep -A1 'pub fn is_x11() -> bool {' libs/scrap/src/common/mod.rs | grep -qE '^\s*true\s*$' || r_x12_pin="$r_x12_pin scrap-is_x11"
grep -q 'static ref IS_X11' src/platform/linux.rs && r_x12_pin="$r_x12_pin IS_X11-cache-returned"
if [ -n "$r_x12_pin" ]; then
  echo "  FAIL R-X12: is_x11() X11-pin incomplete:$r_x12_pin"; rc=1
else
  echo "  ok  R-X12 is_x11() compile-pinned true (main + scrap; no runtime display-server selection)"
fi
# R-X12 (§8) — the Wayland/pipewire CAPTURE path is COMPILED OUT (the CI-grep deliverable): the scrap
# `wayland` feature + `mod wayland` (libs/scrap/src/wayland/ — the xdg-portal ScreenCast + restore-token
# persistence, R-S14) are REMOVED; X11 is the sole compile-pinned capture backend (the gstreamer/dbus/
# zbus pipewire surface is no longer linked). Asserts the feature enabling + `mod wayland` + the dir absent.
r_x12_cap=
grep -qE 'scrap = .*wayland'                Cargo.toml            && r_x12_cap="$r_x12_cap root-scrap-wayland-feature"
grep -qE '^wayland = \['                     libs/scrap/Cargo.toml && r_x12_cap="$r_x12_cap scrap-wayland-feature"
grep -rqE '^[[:space:]]*(pub )?mod wayland'   libs/scrap/src        && r_x12_cap="$r_x12_cap scrap-mod-wayland"
[ -e libs/scrap/src/wayland ]                                      && r_x12_cap="$r_x12_cap scrap-wayland-dir"
if [ -n "$r_x12_cap" ]; then
  echo "  FAIL R-X12: Wayland capture not compiled out:$r_x12_cap"; rc=1
else
  echo "  ok  R-X12 Wayland/pipewire capture compiled out (no scrap wayland feature / mod wayland / dir)"
fi
ra6_clean 'gtk_sudo|run_cmds_privileged|"-gtk-sudo"'                      'R-X11 gtk_sudo elevation'  || rc=1
ra6_clean 'start_uinput_service'                                         'R-X13 dormant uinput listener' || rc=1
# R-X13 (§8): the rdp_input module — Wayland-portal RDP keyboard/mouse injection via the dbus
# org.freedesktop.portal.RemoteDesktop session (RdpInputKeyboard/RdpInputMouse as the enigo custom
# backend) — is EXCISED. XTEST/enigo is the pinned sole injector (wayland_use_rdp_input() was already
# false by construction), so this was compiled-in dead surface (§8 "removed not disabled"). The module
# file + setup_rdp_input + the selector + the dead branches are gone. (uinput + the scrap::wayland
# capture path remain a deferred R-X12/R-X13 stage — task #4.)
if [ -e src/server/rdp_input.rs ]; then
  echo "  FAIL R-X13: the excised src/server/rdp_input.rs reappeared"; rc=1
else
  echo "  ok  R-X13 rdp_input module file absent"
fi
ra6_clean 'RdpInput|fn setup_rdp_input|wayland_use_rdp_input|mod rdp_input' 'R-X13 rdp_input Wayland-portal injection (module/setup/selector)' || rc=1
# R-X13 (§8): the uinput INJECTION module — Wayland kernel input injection (/dev/uinput) driven over a
# cross-uid `_uinput_*` IPC SERVICE — is EXCISED (src/server/uinput.rs, 1350 lines). XTEST/enigo is the
# pinned sole injector (wayland_use_uinput() was already false). Gone: the module, the client
# (UInputKeyboard/UInputMouse + setup_uinput/set_uinput_resolution/update_mouse_resolution), and the
# uinput-only IPC-auth helpers (log_rejected_uinput_connection, ensure_peer_executable_matches_current_by_fd).
# The _service-channel peer-uid authorization is UNTOUCHED (gate 3b-i still green). [Deferred residual,
# task #4: the dead wayland_use_uinput() selector + its dead dispatch guards + the `_uinput_` postfix in
# is_service_ipc_postfix.]
if [ -e src/server/uinput.rs ]; then
  echo "  FAIL R-X13: the excised src/server/uinput.rs reappeared"; rc=1
else
  echo "  ok  R-X13 uinput module file absent"
fi
ra6_clean 'mod uinput|UInputKeyboard|UInputMouse|fn setup_uinput|update_mouse_resolution|set_uinput_resolution|log_rejected_uinput_connection|ensure_peer_executable_matches_current_by_fd' 'R-X13 uinput injection module/client + cross-uid IPC auth helpers' || rc=1
# R-X13 (§8): the uinput DISPATCH guards (the wayland_use_uinput() selector + its dead `if false`
# branches in the input hot-path) AND the coupled Wayland clipboard-input echo-suppression subsystem
# (the WRITER chain set_clipboard_for_paste_sync/input_text_via_clipboard_server/record_..._for_sync_filter
# in input_service.rs + the READER should_skip_wayland_clipboard_sync/is_recent_wayland_clipboard_input
# in clipboard_service.rs + the owner-marked SET path in clipboard.rs) are EXCISED — XTEST/enigo is the
# unconditional sole injector and nothing self-injects clipboard text, so there is no echo to suppress.
ra6_clean 'wayland_use_uinput|should_skip_wayland_clipboard_sync|is_recent_wayland_clipboard_input|input_text_via_clipboard_server|set_clipboard_for_paste_sync|set_with_owner_marker_for_linux' 'R-X13 uinput dispatch guards + Wayland clipboard-input echo-suppression subsystem' || rc=1
# R-X14 (Appendix C #17, a Tier-1-class remote root-context PAM oracle): the os_login -> PAM
# desktop-session-start in linux_desktop_manager.rs is EXCISED. Upstream let a peer's
# LoginRequest.os_login drive a real PAM credential check + a root window-manager-launch script to
# spawn an X session as an arbitrary OS account — on the plaintext direct path BEFORE the password
# check. The whole X-session-spawn + PAM subsystem is removed (linux_desktop_manager collapsed to
# seat0 capture-discovery only; the connection wrapper ignores os_login). These tokens MUST stay
# absent (the capture-side discovery — get_username/is_headless/seat0 — is kept, R-S14).
ra6_clean 'pam::Client|try_start_x_session|start_x_session|start_x11|add_xauth_cookie|pam_get_service_name|should_check_linux_headless_os_auth|should_record_linux_headless_os_auth' 'R-X14 os_login->PAM desktop-session-start + the connection.rs headless OS-auth limiter site (R-T15 line 254)' || rc=1
# R-X8: the terminal OS-login SECOND CREDENTIAL is excised — the terminal is now SessionUser-only
# (one PAKE password -> the service user's shell, R-F1; should_use_terminal_os_login_scope gone,
# prepare_terminal_login_for_authorization renamed to prepare_terminal_session_user). What goes to
# zero: the Windows LogonUserW admin-check (handle_administrator_check / get_logon_user_token /
# is_user_token_admin) AND the whole per-terminal OS-credential rate-limit + concurrency subsystem
# (login_failure_check.rs DELETED: FailureScope / TerminalOsLogin / evaluate_os_credential_policy /
# record_os_credential_failure / try_acquire_os_credential_login_gate, plus the connection.rs
# check_failure / update_failure_with_scope shims — R-T15b had already excised LOGIN_FAILURES, so
# CPace GUESS_FAILURES (R-P14c) is the sole online-guess limiter). CreateProcessWithLogonW is R-X9.
ra6_clean 'should_use_terminal_os_login_scope|prepare_terminal_login_for_authorization|handle_administrator_check|get_logon_user_token|is_user_token_admin|LogonUserW|FailureScope|TerminalOsLogin|TERMINAL_OS_LOGIN_FAILED_MSG|try_acquire_os_credential_login_gate|evaluate_os_credential_policy|record_os_credential_failure|update_failure_with_scope|check_failure_with_scope' 'R-X8 terminal OS-login second-credential + its FailureScope/login_failure_check limiter subsystem' || rc=1
# R-X9: the CONTROLLED-side os-credential ELEVATION (peer OS username+password -> Windows
# CreateProcessWithLogonW) is excised; only Direct UAC elevation (handle_elevation_request(
# StartPara::Direct) / platform::elevate) remains. The viewer already stopped SENDING it (R-S18).
# Removed: the connection.rs ElevationRequest Logon arm, portable_service.rs StartPara::Logon + its
# match arm, platform/windows.rs create_process_with_logon, and the message.proto
# ElevationRequestWithLogon message + its `logon` oneof field.
ra6_clean 'create_process_with_logon|CreateProcessWithLogonW|StartPara::Logon|elevation_request::Union::Logon' 'R-X9 os-credential elevation (CreateProcessWithLogonW)' || rc=1
if grep -qE 'message +ElevationRequestWithLogon' libs/hbb_common/protos/message.proto; then
  echo "  FAIL R-X9: message ElevationRequestWithLogon still present in message.proto"; rc=1
else
  echo "  ok  R-X9 ElevationRequestWithLogon absent from message.proto"
fi
# R-X4 (custom_server): the custom-rendezvous-server-from-exe-name feature is excised. The installer
# could embed a rendezvous/api server in the exe NAME (rustdesk-host=... ; rustdesk-licensed-<b64>.exe),
# parsed by custom_server.rs and injected as custom-rendezvous-server / api-server at 4 sites
# (get_rendezvous_server, get_custom_rendezvous_server, get_api_server_, bootstrap EXE_RENDEZVOUS_SERVER
# + the install-time config write) -- a server config arriving from the binary's filename, a
# sovereignty/trust-anchor egress vector on a direct-IP-only fork. The whole module +
# get_license_from_exe_name + get_license(CustomServer) go to zero.
ra6_clean 'mod custom_server|get_custom_server_from_string|get_license_from_exe_name|\bCustomServer\b|EXE_RENDEZVOUS_SERVER' 'R-X4 custom-rendezvous-server-from-exe-name (custom_server module + get_license_from_exe_name + the EXE_RENDEZVOUS_SERVER config-level override)' || rc=1
# R-X14 (cont.): the excision is COMPLETE through the build + packaging — with zero pam:: usage the dead
# `pam` crate dep, its transitive pam-sys libpam runtime link, the .deb libpam0g Depends, and the
# /etc/pam.d/rustdesk install were all dead weight (a third-party git dep + a runtime-link + a dead
# config). Assert they stay gone so the supply-chain / runtime-link surface cannot silently regrow.
grep -qE '^pam = '      Cargo.toml  && { echo "  FAIL R-X14: the dead 'pam' crate dep is back in Cargo.toml"; rc=1; }
grep -q  'libpam0g'     build.py    && { echo "  FAIL R-X14: the .deb still Depends on libpam0g (the binary has no PAM)"; rc=1; }
grep -qE 'pam\.d/rustdesk' build.py && { echo "  FAIL R-X14: the .deb still installs the dead /etc/pam.d/rustdesk"; rc=1; }
[ -e res/pam.d ] && { echo "  FAIL R-X14: the dead res/pam.d/ PAM config files are back"; rc=1; } || true
# Supply-chain hygiene (§18 sovereignty / §11 dep surface): third-party (git) deps whose ONLY users were
# excised features stay removed from Cargo.toml, so the dep + its runtime-link + transitive surface cannot
# silently regrow. pam (R-X14, above) + dbus-crossroads (R-X6, gated at its R-ID) are done; here the two
# input/transport residuals: evdev (R-X12/X13 -- no raw /dev/input reading; X11+XTEST is the input path)
# and kcp-sys (R-D5 -- the KCP reliable-UDP transport, exactly what the no-UDP/direct-IP thesis sheds).
grep -qE '^evdev = ' Cargo.toml && { echo "  FAIL supply-chain: the dead evdev dep (input excision) is back in Cargo.toml"; rc=1; }
grep -qE '^kcp-sys'  Cargo.toml && { echo "  FAIL supply-chain: the dead kcp-sys dep (KCP reliable-UDP, vs the no-UDP thesis) is back"; rc=1; }
# R-X7 / §18: the 2FA machinery is FULLY excised. Responder side: the `require_2fa` field, the
# Auth2fa gate/handler, the trusted-device bypass, the raii session-2FA state (2FA was
# pinned-off-dead: `2fa`="" so require_2fa was always None ⇒ every branch unreachable). Now also:
# the viewer-side `send2fa` sender, the `Auth2FA` proto field, src/auth_2fa.rs, the totp-rs +
# qrcode-generator deps, and the Sciter 2FA UI (index/msgbox/common.tis) — no 2FA path on either
# side or on the wire. Two hard gates lock it in (the second covers the module/proto/dep/FFI):
ra6_clean 'require_2fa|set_session_2fa'                                   'R-X7 responder 2FA machinery' || rc=1
ra6_clean 'totp|Auth2FA|auth_2fa|generate2fa|verify2fa|set_auth_2fa|add_trusted_device' 'R-X7 2FA module/totp-rs/Auth2FA proto/FFI/trusted-device' || rc=1
# R-S16(d)(ii): the runtime SwitchPermission widener (the conn-side handler that
# re-assigned conn.keyboard/clipboard/audio/... bypassing the pinned policy) is
# removed. The qualified `ipc::Data::SwitchPermission` token was unique to that
# handler arm; the CM-side senders use the unqualified `Data::SwitchPermission`
# (R-G7 GUI surface), so this gate is specific to the widener.
ra6_clean 'ipc::Data::SwitchPermission'                                  'R-S16(d)(ii) SwitchPermission widener' || rc=1
# R-S16(d) / flutter UI correctness (the pinned-policy audit): a control whose write the policy funnel
# rejects must not render as a live, mutating affordance that silently no-ops.
#  - is_option_fixed() reports PINNED_SETTINGS keys as fixed, so every pinned control auto-greys (BUG4 root).
#  - the desktop CM mid-session permission icons are non-interactive (Data::SwitchPermission excised; BUG1).
#  - the desktop "Stop service" button is hidden when stop-service is pinned (BUG4(a): the service is
#    un-killable by a local write by design; a live button would stay "Stop" with no feedback).
#  - the mobile audio/file/clipboard permission toggles re-read the stored value after the rejected write,
#    so the switch flag cannot diverge from the enforced config (BUG4(b)).
r_s16d_ui=""
grep -qF 'PINNED_SETTINGS.iter().any' src/ui_interface.rs || r_s16d_ui="$r_s16d_ui is_option_fixed-pinned"
grep -qF 'final canModifyPermission = false' flutter/lib/desktop/pages/server_page.dart || r_s16d_ui="$r_s16d_ui cm-perms-noninteractive"
grep -qF 'isOptionFixed(kOptionStopService)' flutter/lib/desktop/pages/desktop_setting_page.dart || r_s16d_ui="$r_s16d_ui stop-service-hide"
[ "$(grep -cF 'R-S16(d): re-sync the flag to the STORED value' flutter/lib/models/server_model.dart)" -ge 3 ] || r_s16d_ui="$r_s16d_ui mobile-toggle-resync"
if [ -n "$r_s16d_ui" ]; then
  echo "  FAIL R-S16(d)/UI: a pinned-policy control reverted to a live silent-no-op affordance:$r_s16d_ui"; rc=1
else
  echo "  ok  R-S16(d)/UI pinned controls grey + CM perms inert + Stop-service hidden + mobile toggles re-sync"
fi
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
# R-SV6(d) / R-D6 / §18: the hardwired global api-server default ("https://admin.rustdesk.com")
# is excised — get_api_server_'s fallback is String::new() (behavior-gated at (3b-ii)). Assert the
# host literal never returns to the tree (a cheap string backstop for the resolution-layer test).
ra6_clean 'admin\.rustdesk\.com' 'R-SV6(d) hardwired global api-server default (admin.rustdesk.com)' || rc=1
# R-D4 Stage 2 / R-SV10: the rendezvous-mediator PROTOCOL is removed from the tree (the
# register loop + register_pk method, the relay/punch-hole/intranet handlers, the UDP/KCP
# path). These worker symbols were mediator-internal and are now tree-wide absent — the
# direct-only service entry (start_direct_only -> direct_server) is all that remains.
ra6_clean 'handle_request_relay|handle_punch_hole|udp_nat_listen|punch_udp_hole|KcpStream::accept' 'R-D4 Stage 2 mediator relay/punch/KCP protocol' || rc=1
# R-D4 Stage 3 / R-SV10: the inherited `rendezvous_mediator` module is RENAMED to `direct_service`.
# After Stage 1/2 (the registration/relay/UDP protocol + every no-op shell are gone), the module is
# honestly the direct-only service path (start_direct_only -> direct_server + the R-A4/R-T* self-
# checks), so the spec's must-be-absent token `mod rendezvous_mediator` — and the misleading module
# name itself — are grep-absent across the tree (R-SV10 names `mod rendezvous_mediator` in its set).
if [ -f src/rendezvous_mediator.rs ] || grep -rqI 'rendezvous_mediator' src/ libs/ --include=*.rs 2>/dev/null; then
  echo "  FAIL R-D4 Stage 3/R-SV10: the inherited rendezvous_mediator module name is back (it is renamed to direct_service)"; rc=1
else
  echo "  ok  R-D4 Stage 3/R-SV10 module renamed rendezvous_mediator -> direct_service (the spec token 'mod rendezvous_mediator' is grep-absent; the module is honestly the direct-only service path)"
fi
# R-D4 Stage 4 / R-SV4 / R-SV10 / §8: the rendezvous WIRE PROTOCOL itself is removed from
# rendezvous.proto. Stage 2 removed the mediator HANDLERS (Rust); this removes the MESSAGES they spoke
# -- RendezvousMessage (the ~22-variant oneof: RegisterPeer/PunchHole*/RegisterPk*/RequestRelay/
# RelayResponse/TestNat*/FetchLocalAddr/LocalAddr/ConfigUpdate/SoftwareUpdate/PeerDiscovery/Online*/
# KeyExchange/HealthCheck/HttpProxy*) + the NatType enum. The fork had ZERO senders + its sole reader
# (common.rs get_next_nonkeyexchange_msg) was dead. KEPT: ConnType + ControlPermissions + HeaderEntry
# (the three types still used on the direct path). The binary can no longer encode/parse a rendezvous
# message (R-SV1 structural absence). The proto comment naming the removed types starts with `//`, so
# the anchored `^message`/`^enum` greps below do not match it.
if grep -qE '^message RendezvousMessage|^message PunchHole|^message RegisterPk|^message RequestRelay|^message RelayResponse|^enum NatType' libs/hbb_common/protos/rendezvous.proto; then
  echo "  FAIL R-D4 Stage 4/R-SV4: the rendezvous wire protocol (RendezvousMessage / PunchHole / NatType / ...) is back in rendezvous.proto"; rc=1
else
  echo "  ok  R-D4 Stage 4/R-SV4 rendezvous wire protocol absent from rendezvous.proto (only ConnType/ControlPermissions/HeaderEntry remain)"
fi
ra6_clean '\bRendezvousMessage\b|rendezvous_message::|get_next_nonkeyexchange_msg' 'R-D4 Stage 4/R-SV4 RendezvousMessage type + oneof submodule + its dead parser' || rc=1
# R-SV4/R-SV10 / §18 (sovereignty): the Change-ID flow's rendezvous-dialing register_pk sender is
# EXCISED. The inherited ui_interface::check_id connect_tcp'd to RENDEZVOUS_PORT and sent RegisterPk
# (registering the device pk + checking ID availability with the rendezvous) — a sovereignty/egress
# leak (R-D6 "dial nobody") and the register_pk R-SV10 greps absent. change_id_shared_ now stores a
# changed ID LOCALLY (the ID is a vestigial label — R-SV5 connects by IP, never by ID). Assert no
# register_pk SENDER (set_register_pk) or the check_id rendezvous-dial helper survives.
ra6_clean 'set_register_pk|async fn check_id' 'R-SV4/R-SV10 Change-ID register_pk rendezvous-dial' || rc=1
# R-SV4(e)/R-S11: the service IPC handler's mediator-control arm that reached an OUTBOUND rendezvous
# DIAL is REMOVED OUTRIGHT (§8 "removed not disabled"). Upstream's Data::TestRendezvousServer ->
# crate::test_rendezvous_server (connect_tcp to RENDEZVOUS_PORT, latency-probing each configured
# rendezvous) was first neutered to a no-op; the whole IPC message is now gone — the variant, its
# (zero-caller) ipc::test_rendezvous_server sender, AND the no-op handler arm — so a local IPC message
# can no longer even NAME a rendezvous dial. The dead common::refresh_rendezvous_server wrapper (the
# message's only would-be caller) is removed with it. (Data::Deployed, the mediator-redeploy arm, is
# likewise REMOVED — R-SV6(c)/R-D4 — with its dead notify_deployed() sender and the NEEDS_DEPLOY flag.)
if grep -qE 'TestRendezvousServer' src/ipc.rs || grep -qE 'fn refresh_rendezvous_server' src/common.rs; then
  echo "  FAIL R-SV4(e)/R-S11: an IPC rendezvous-dial residue survives (Data::TestRendezvousServer in ipc.rs or refresh_rendezvous_server in common.rs must be fully removed)"; rc=1
else
  echo "  ok  R-SV4(e)/R-S11 IPC rendezvous-dial message fully removed (Data::TestRendezvousServer variant+sender+handler + refresh_rendezvous_server wrapper gone; Data::Deployed removed)"
fi
# R-X10 (§8 run-mode plurality): the GUI/client (`is_server == false`) startup path NEVER auto-starts
# a controlled server — the controlled side starts ONLY via the installed `--service`/`--server` (one
# mode, R-D8). The inherited `else { start_server(true) }` fallback in server.rs's `is_server == false`
# branch (a SECOND, non-installed-service way to run the controlled side — the portable/quick-support/
# run-from-terminal twin) is removed. Assert NO non-comment `start_server(true)` survives in server.rs
# (the legitimate `start_server(true, false)` entries live in core_main.rs's `--server` arm, KEPT).
r_x10_n=$(grep -E 'start_server\(true' src/server.rs 2>/dev/null | grep -vcE '//' || true)
if [ "${r_x10_n:-1}" -eq 0 ]; then
  echo "  ok  R-X10 GUI/client path never auto-starts a controlled server (server-fallback removed; controlled = installed --service only)"
else
  echo "  FAIL R-X10: a start_server(true) fallback survives in server.rs's is_server==false branch (found ${r_x10_n} non-comment)"; rc=1
fi
# R-X10 (cont.): the --no-server flag + its vestigial no_server param are compiled out (the GUI never
# starts a controlled server, so the flag was redundant; ipc.rs's main-window restart no longer passes
# it; start_server is now 1-arg). Assert the flag string is absent (R-A6).
ra6_clean '"--no-server"' 'R-X10 --no-server flag (the GUI never starts a controlled server -> compiled out)' || rc=1
# R-D6 / §18 (sovereignty): the box never phones home with audit logs. The connection/alarm/file
# audit POST helpers (post_conn_audit/post_alarm_audit/post_file_audit -> <api-server>/api/audit/*)
# are EXCISED — absent, not merely api-server-pinned — so an audit-egress leak cannot regress in.
ra6_clean 'post_conn_audit|post_alarm_audit|post_file_audit' 'R-D6 audit phone-home (conn/alarm/file POST)' || rc=1
# R-D6(d)(iii)/R-S11: socks/proxy is INERT AT THE ACCESSOR. set_socks/get_socks/get_network_type bypass
# the get_option funnel (they read the structured CONFIG2.socks field), so the PINNED_SETTINGS proxy-url
# pin does not reach them — the inherited guard only checked the RustDesk-SIGNED OVERWRITE_SETTINGS, which
# is EMPTY on a fork, leaving set_socks LIVE. The fork makes each accessor consult the proxy-url pin
# DIRECTLY (pinned_setting), so a local main-channel IPC Data::Socks write cannot install a proxy (a
# local-MITM / egress-reroute primitive, and the trigger that flips CheckTestNatType's is_direct to fire
# a STUN UDP probe). Behavior is proven by config_it (socks_is_inert_under_the_proxy_pin); this is belt.
r_d6socks_n=$(grep -c 'pinned_setting(keys::OPTION_PROXY_URL).is_some()' libs/hbb_common/src/config.rs 2>/dev/null || echo 0)
if [ "${r_d6socks_n:-0}" -ge 3 ]; then
  echo "  ok  R-D6(d)(iii) socks/proxy inert at the accessor (set_socks/get_socks/get_network_type honor the proxy-url pin; behavior-tested by config_it)"
else
  echo "  FAIL R-D6(d)(iii): socks accessors not all inert-at-accessor (found ${r_d6socks_n}/3 proxy-url pin checks in config.rs)"; rc=1
fi
# R-SV6(b)/R-SV1/R-SV10 / §18: the session-record UPLOAD egress (hbbs_http::record_upload — a reqwest
# POST of the recorded session to <api-server>/api/record) is EXCISED — the whole module is removed
# from the tree, not merely its is_enable() neutralized (the prior state). Recording stays local
# (R-D6 dial-nobody). The video_service caller now hard-codes the upload channel to None.
ra6_clean 'record_upload|api/record\b' 'R-SV6(b) session-record upload egress' || rc=1
# R-SV3 / R-SV1 (§18 sovereignty): the version-check phone-home is DELETED structurally, not
# neutered. Upstream's hbb_common `version_check_request` built a device-fingerprinted POST
# (os/arch/device_id) to a HARDWIRED api.rustdesk.com/version endpoint — a global-reaching egress
# the R-D6 api-server pin never covered, fired ~1s after launch by the Dart `checkUpdate`. That
# caller + the egress worker were already gone and `check_software_update` neutered; this locks in
# the BUILDER's removal so no version_check_request / VersionCheck{Request,Response} / hardwired
# api.rustdesk.com endpoint survives in the binary (Dart-side excision comments are `//`-filtered).
ra6_clean 'version_check_request|VersionCheckRequest|VersionCheckResponse|VER_TYPE_RUSTDESK|api\.rustdesk\.com' 'R-SV3 version-check phone-home (api.rustdesk.com builder)' || rc=1
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
ra6_clean 'Some\(OSLogin|\.set_logon\(|ElevateWithLogon|elevate_with_logon' 'R-S18 viewer os_login + elevation-with-logon senders' || rc=1
# R-S18 / Appendix C: the OSLogin message + the `os_login` field (12) are now DELETED from
# message.proto entirely (field 12 retired, not reused) and every responder read is gone. The
# responder used to clear+ignore a parsed os_login (R-X14); now the peer cannot encode an OS
# username/password into the LoginRequest AT ALL -- structural absence in the parsed auth protocol,
# not a runtime strip. (The two cfg(windows) login branches that read os_login.username -- the dead
# "installed version" refuse + the prelogin guard -- are removed/simplified accordingly.)
ra6_clean '\bOSLogin\b|\bos_login\b' 'R-S18 OSLogin message + os_login field/reads (peer OS-credential in the parsed LoginRequest)' || rc=1
if grep -qE '^\s*message OSLogin|^\s*OSLogin +os_login' libs/hbb_common/protos/message.proto; then
  echo "  FAIL R-S18: the OSLogin message or os_login field declaration is back in message.proto"; rc=1
else
  echo "  ok  R-S18 OSLogin message + os_login field absent from message.proto (field 12 retired)"
fi
# R-S18 / Appendix C #22 (cont.): the persisted os-username/os-password OPTION READS the spec names
# for deletion are gone from the Rust viewer — get_option("os-username"/"os-password") + should_auto_login()
# (which returned the STORED os-password to auto-type into the remote OS on connect, a persisted second
# OS credential). The manual input_os_password path (operator types a FRESH password — not persisted,
# not named by R-S18) stays. NB the sciter src/ui/header.tis "OS Password" menu cluster (.tis runtime
# script, not the shipped flutter UI, not grepped by this .rs gate) is a tracked follow-on.
ra6_clean 'get_option\("os-username"\)|get_option\("os-password"\)|fn should_auto_login' 'R-S18 viewer persisted os-credential reads (.rs)' || rc=1
# R-S18 (sciter UI): the "OS Password" persistence cluster — the EditOsPassword widget +
# editOSPassword get/set('os-password') dialog — is removed from src/ui/*.tis too (ra6_clean greps
# .rs only). The sciter UI is the verify build, not shipped, but the source must conform symmetrically.
if grep -rInE "get_option\('os-password'\)|set_option\('os-password'|editOSPassword|EditOsPassword" src/ui --include='*.tis' 2>/dev/null | grep -qv '//'; then
  echo "  FAIL R-S18: sciter os-password persistence present in .tis:"; \
    grep -rInE "get_option\('os-password'\)|set_option\('os-password'|editOSPassword|EditOsPassword" src/ui --include='*.tis' | grep -v '//' | sed 's/^/      /'; rc=1
else echo "  ok  R-S18 sciter os-password persistence (.tis) absent"; fi
# R-S15 (Appendix C #19): the viewer's in-session PeerConfig writes from peer-controlled data MUST be
# funnelled through a validated allowlist before save_config — a keyed-but-hostile host (§4.4) must not
# inject unbounded/injection strings into the on-disk config. The initiator-side twin of the responder's
# R-S11 gate. This gate VALUE-asserts the SPECIFIC named writes are routed (not mere token presence,
# which passed green despite the service_id sibling write being unbounded): (a) PeerInfo + service_id
# clamped via hbb_common::config::bound_peer_config_string; (b) the privacy-mode impl_key REJECTED
# unless it is in the compile-time get_supported_privacy_mode_impl() set. KAT: config_it tests/r_s15.rs.
r_s15_missing=
for f in src/client.rs src/client/io_loop.rs; do
  grep -q 'bound_peer_config_string' "$f" || r_s15_missing="$r_s15_missing $f:bound-absent"
done
# the TerminalResponse.service_id write is bounded — AND the raw unbounded clone is gone (regression guard)
grep -q 'bound_peer_config_string(&opened.service_id)' src/client/io_loop.rs || r_s15_missing="$r_s15_missing service_id-unbounded"
grep -qE 'set_option\(key, opened\.service_id\.clone' src/client/io_loop.rs && r_s15_missing="$r_s15_missing service_id-RAW-write-present"
# the privacy-mode impl_key is allowlist-validated against the supported set before the insert
grep -q 'get_supported_privacy_mode_impl()' src/client/io_loop.rs || r_s15_missing="$r_s15_missing impl_key-unvalidated"
if [ -n "$r_s15_missing" ]; then
  echo "  FAIL R-S15: peer-config-write allowlist gap:$r_s15_missing"; rc=1
else
  echo "  ok  R-S15 viewer PeerConfig writes routed (PeerInfo+service_id bounded; impl_key validated vs supported set)"
fi
# R-A2 (clipboard-file capability parity): the inbound Cliprdr clipboard-FILE arm (connection.rs ~2311)
# drives unix_file_clip::serve_clip_messages — the FUSE context + host-clipboard file:// injection. It
# MUST gate on the SAME capability as the SUBSCRIPTION (can_sub_file_clipboard_service = clipboard +
# file-transfer enabled, NOT one-way), like the text-clipboard arms gate on `if self.clipboard` — not
# merely the peer-reported is_support_file_copy_paste version (no security meaning). This arm is
# #[cfg(unix-file-copy-paste)] (compiled out of (4), compiled IN at (4a)), so this is a source-structure
# gate: assert the combined capability+version gate is present AND the version is no longer the sole gate.
r_clip_file=
grep -A1 'if self.can_sub_file_clipboard_service()' src/server/connection.rs | grep -q 'is_support_file_copy_paste' || r_clip_file="$r_clip_file inbound-cliprdr-not-capability-gated"
grep -qE 'if crate::is_support_file_copy_paste\(&self\.lr\.version\) \{' src/server/connection.rs && r_clip_file="$r_clip_file version-only-sole-gate-present"
if [ -n "$r_clip_file" ]; then
  echo "  FAIL R-A2 clipboard-file inbound arm capability gap:$r_clip_file"; rc=1
else
  echo "  ok  R-A2 inbound clipboard-file (Cliprdr) arm gated on can_sub_file_clipboard_service (not version-only)"
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
grep -q 'try_acquire_owned' src/direct_service.rs          || r_t1_missing="$r_t1_missing mediator:acquire-before-spawn"
# R-T1(a): the memory ceilings MUST be host-RELATIVE percentages, NEVER an absolute byte count — an
# absolute `4G` is a no-op on a 2 GiB box (the spec names this exact regression). Anchored `^…=NN%$`
# fails on MemoryMax=4G / =2147483648 / =infinity; presence-only greps did not. TasksMax is a count.
grep -qE '^MemoryMax=[0-9]+%$'  res/rustdesk.service            || r_t1_missing="$r_t1_missing service:MemoryMax-not-percent"
grep -qE '^MemoryHigh=[0-9]+%$' res/rustdesk.service            || r_t1_missing="$r_t1_missing service:MemoryHigh-not-percent"
grep -qE '^TasksMax=[0-9]+$'    res/rustdesk.service            || r_t1_missing="$r_t1_missing service:TasksMax"
# The fd bound + the auto-restart the R-T1 comment claims but did not check (gap-analysis-3). LimitNOFILE
# is SECURITY-relevant: upstream's 100000 only serves an fd-exhaustion attacker; the fork pins the bounded
# 8192 (single-user headroom). Restart=on-failure keeps the headless box up after a crash; RestartSec the delay.
grep -qE '^LimitNOFILE=8192$'   res/rustdesk.service            || r_t1_missing="$r_t1_missing service:LimitNOFILE(bounded-8192-not-100000)"
grep -qE '^Restart=on-failure$' res/rustdesk.service            || r_t1_missing="$r_t1_missing service:Restart"
grep -qE '^RestartSec=[0-9]+$'  res/rustdesk.service            || r_t1_missing="$r_t1_missing service:RestartSec"
if [ -n "$r_t1_missing" ]; then
  echo "  FAIL R-T1: connection-flood bound / flood-safe observability absent:$r_t1_missing"; rc=1
else
  echo "  ok  R-T1/R-T12 connection-flood bound + flood-safe observability present"
fi
# R-T12 (§20): the accept-error arm MUST (a) MAP the fd/resource-exhaustion errnos (EMFILE/ENFILE/
# ENOBUFS / WSAEMFILE/WSAENOBUFS) via raw_os_error() so the operator sees the cause, not a bare int,
# and (b) apply an ESCALATING bounded back-off (a per-streak-counter min(50ms·2^n, 5s)), not a flat
# sleep — under an fd-exhaustion flood the kernel keeps signalling the socket readable while accept()
# returns EMFILE, so a fixed sleep still busy-spins. (The 3-way outcome split + rate-limited
# aggregation are gated by R-T1/R-T12 above.)
r_t12_eb=
grep -qE 'accept_err_streak'              src/direct_service.rs || r_t12_eb="$r_t12_eb no-streak-counter"
grep -qE '\(50u64 << accept_err_streak\.min\(7\)\)\.min\(5000\)' src/direct_service.rs || r_t12_eb="$r_t12_eb no-escalating-bounded-backoff(50<<streak.min7-cap5000)"
grep -qE 'fn accept_error_class'          src/server.rs              || r_t12_eb="$r_t12_eb no-errno-mapper"
grep -qE 'libc::EMFILE|libc::ENFILE'      src/server.rs              || r_t12_eb="$r_t12_eb no-EMFILE-map"
if [ -n "$r_t12_eb" ]; then
  echo "  FAIL R-T12: accept-error escalating-backoff/errno-map incomplete:$r_t12_eb"; rc=1
else
  echo "  ok  R-T12 accept-error escalating bounded back-off + EMFILE/ENFILE errno mapping present"
fi
# R-SV10 (§18, the FIFTH config funnel): LocalConfig::get_option reads the UNPINNED _local namespace —
# unlike Config::get_option it has NO PINNED_SETTINGS head-guard (config.rs). CI MUST assert no
# SECURITY-RELEVANT key resolves through it without a pin or a compile-out (mirroring R-S16(d)(iv)'s
# get_builtin_option treatment). The spec names enable-check-update — the software-updater egress —
# which R-SV3 compiles OUT. The other capability-adjacent LocalConfig readers are #[cfg(windows)]
# (pre-elevate-service @ core_main.rs = the local-pref elevation; the printer-job action @ io_loop.rs),
# so the Linux build (the cargo-check gate below) compiles them out — unreachable on the deployed box.
# The remaining readers are benign UI prefs (lang/texture-render/video-dir/input-source/group-panel).
r_sv10=
# (a) no LocalConfig reader resolves the updater-egress key, and the const stays UNDEFINED (R-SV3
#     excised both — only an excision comment remains in config.rs); a re-add of either re-opens it.
grep -rnE 'LocalConfig::get_option[^)]*(OPTION_ENABLE_CHECK_UPDATE|"enable-check-update")' src libs --include=*.rs | grep -qv '//' && r_sv10="$r_sv10 enable-check-update-reader"
grep -rqE '^[[:space:]]*pub const OPTION_ENABLE_CHECK_UPDATE' libs/hbb_common/src/config.rs && r_sv10="$r_sv10 OPTION_ENABLE_CHECK_UPDATE-redefined"
# (b) the local-pref elevation read, IF present, MUST be confined to core_main.rs under #[cfg(windows)]
preelev_sites=$(grep -rlE 'LocalConfig::get_option\("pre-elevate-service"\)' src --include=*.rs || true)
if [ -n "$preelev_sites" ]; then
  [ "$preelev_sites" = "src/core_main.rs" ] || r_sv10="$r_sv10 pre-elevate-service-outside-core_main($preelev_sites)"
  grep -B6 'LocalConfig::get_option("pre-elevate-service")' src/core_main.rs | grep -q '#\[cfg(windows)\]' || r_sv10="$r_sv10 pre-elevate-service-not-windows-gated"
fi
if [ -n "$r_sv10" ]; then
  echo "  FAIL R-SV10: a security-relevant key resolves through the unpinned LocalConfig funnel:$r_sv10"; rc=1
else
  echo "  ok  R-SV10 LocalConfig funnel clean (enable-check-update excised; pre-elevate-service windows-gated)"
fi
# R-D3a (§17): the root service unit MUST carry the kernel sandbox (the upstream unit had none),
# shrinking the blast radius of any memory-corruption bug missed by the §8 excisions. MemoryDenyWriteExecute
# (W^X) is the code-injection-primitive blocker, ENABLED after examples/mdwe_codec_probe empirically
# proved the software VP9 codec path maps no W+X under the exact PR_SET_MDWE primitive systemd applies
# (run by smoke-server.sh). This gate asserts the sandbox directives + the validated MDWE line are present
# (uncommented) so a regression that drops them fails closed.
r_d3a_missing=
grep -qE '^CapabilityBoundingSet='      res/rustdesk.service || r_d3a_missing="$r_d3a_missing CapabilityBoundingSet"
grep -qE '^RestrictAddressFamilies=AF_UNIX AF_INET$' res/rustdesk.service || r_d3a_missing="$r_d3a_missing RestrictAddressFamilies-v4only"
grep -qE '^SystemCallFilter=@system-service' res/rustdesk.service || r_d3a_missing="$r_d3a_missing SystemCallFilter"
# The 6 kernel-sandbox directives that were PRESENT but ungated (gap-analysis-3): a regression dropping
# any silently strips a confinement layer off the internet-exposed root box. Value-anchored (^…=…$) so a
# weakened value (e.g. RestrictRealtime=no) also fails, not just a deletion.
grep -qE '^SystemCallFilter=~@mount @reboot @swap$' res/rustdesk.service || r_d3a_missing="$r_d3a_missing SystemCallFilter-subtraction"
grep -qE '^ProtectKernelModules=yes$'       res/rustdesk.service || r_d3a_missing="$r_d3a_missing ProtectKernelModules"
grep -qE '^ProtectKernelTunables=yes$'      res/rustdesk.service || r_d3a_missing="$r_d3a_missing ProtectKernelTunables"
grep -qE '^RestrictRealtime=yes$'           res/rustdesk.service || r_d3a_missing="$r_d3a_missing RestrictRealtime"
grep -qE '^LockPersonality=yes$'            res/rustdesk.service || r_d3a_missing="$r_d3a_missing LockPersonality"
grep -qE '^SystemCallArchitectures=native$' res/rustdesk.service || r_d3a_missing="$r_d3a_missing SystemCallArchitectures-native"
grep -qE '^MemoryDenyWriteExecute=yes$'  res/rustdesk.service || r_d3a_missing="$r_d3a_missing MemoryDenyWriteExecute(validated)"
grep -q 'PR_SET_MDWE' examples/mdwe_codec_probe.rs           || r_d3a_missing="$r_d3a_missing mdwe_codec_probe"
if [ -n "$r_d3a_missing" ]; then
  echo "  FAIL R-D3a: systemd sandbox / validated-MDWE incomplete:$r_d3a_missing"; rc=1
else
  echo "  ok  R-D3a systemd sandbox + MemoryDenyWriteExecute (W^X, codec-validated by mdwe_codec_probe) present"
fi
# R-T7 (§20): every frame on a KEYED (Dual) stream MUST be AEAD-authenticated — the ≤1-byte
# decrypt bypass is removed (the one path by which a byte could reach the application parser
# unauthenticated; also the closure of the unkeyed→keyed boundary, R-T6). The legacy single-key
# `Encrypt` cipher (which carried the only ≤1-byte bypass) was excised entirely at R-A6, so this
# now asserts ZERO `bytes.len() <= 1` in tcp.rs — the keyed edge is CPace/Dual-only.
r_t7_n=$(grep -c 'bytes.len() <= 1' libs/hbb_common/src/tcp.rs 2>/dev/null || true)
if [ "${r_t7_n:-99}" -gt 0 ]; then
  echo "  FAIL R-T7: a <=1-byte decrypt bypass remains in tcp.rs (found $r_t7_n) — must be ZERO"; rc=1
else
  echo "  ok  R-T7 <=1-byte AEAD bypass fully removed (single-key Encrypt excised, R-A6)"
fi
# R-T2 (§20): the FramedStream poison flag. A keyed stream's write nonce is pre-incremented by
# `seal` before the ciphertext is flushed; reusing a stream after a send error would re-flush
# stale bytes under an advanced nonce and permanently desync the c2s direction. The poison flag
# (the `pub bool` tuple field, `.3` after R-T5 folded the cipher into the codec) makes "a
# send/recv error is fatal-to-the-connection" structural: send_bytes bails when poisoned and sets
# it on any send error; next() returns EOF when poisoned and sets it on any read OR (now codec-fold)
# decrypt/auth failure. Presence gate: the short-circuit guard (>=2 sites: send_bytes + next) and
# the poison-set (>=2 sites: send error, and next's unified read/decrypt error).
r_t2_guard=$(grep -c 'if self.3 {' libs/hbb_common/src/tcp.rs 2>/dev/null || true)
r_t2_set=$(grep -c 'self.3 = true' libs/hbb_common/src/tcp.rs 2>/dev/null || true)
if [ "${r_t2_guard:-0}" -ge 2 ] && [ "${r_t2_set:-0}" -ge 2 ]; then
  echo "  ok  R-T2 FramedStream poison flag present (guard x$r_t2_guard, poison-set x$r_t2_set)"
else
  echo "  FAIL R-T2: poison flag incomplete (guard=$r_t2_guard need>=2, set=$r_t2_set need>=2)"; rc=1
fi
# R-T5 (§20): decryption is FOLDED INTO the Framed-owned codec (SecretboxCodec) — decode()
# reassembles ONE frame then authenticates+decrypts it, advancing read_seq INSIDE decode, so a
# dropped next() (select!/timeout losing the race) cannot desync the recv counter. The cipher
# lives in the codec, inheriting tokio-util's StreamExt::next cancel-safety verbatim. Gate: the
# codec + its Decoder/Encoder impls + the Framed<_,SecretboxCodec> type + the mandated regression
# test (drives next() under a biased select and asserts read_seq unchanged via recv_counter).
r_t5_missing=
grep -q 'pub struct SecretboxCodec' libs/hbb_common/src/tcp.rs              || r_t5_missing="$r_t5_missing codec-struct"
grep -q 'impl Decoder for SecretboxCodec' libs/hbb_common/src/tcp.rs        || r_t5_missing="$r_t5_missing decoder-impl"
grep -q 'impl Encoder<Bytes> for SecretboxCodec' libs/hbb_common/src/tcp.rs || r_t5_missing="$r_t5_missing encoder-impl"
grep -q 'Framed<DynTcpStream, SecretboxCodec>' libs/hbb_common/src/tcp.rs   || r_t5_missing="$r_t5_missing framed-type"
grep -rq 'recv_counter' libs/cpace_it/tests/                               || r_t5_missing="$r_t5_missing regression-test"
if [ -n "$r_t5_missing" ]; then
  echo "  FAIL R-T5: decrypt-in-codec incomplete:$r_t5_missing"; rc=1
else
  echo "  ok  R-T5 decrypt folded into SecretboxCodec (read_seq advances in decode) + regression test"
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
# cancelled by the signal handler (direct_service.rs); the accept loop then stops accepting and
# drops its listener, every live session's run-loop drains via its `cancelled()` select-arm
# (CloseReason -> flush -> CM Close), and a BOUNDED drain deadline — shorter than the unit's
# TimeoutStopSec — precedes a force-exit(0). The pkill/KillMode=mixed path stays the backstop.
# Presence gate across the three layers (server primitive, connection drain arm, mediator handler).
r_t9_missing=
grep -q 'fn begin_graceful_shutdown' src/server.rs         || r_t9_missing="$r_t9_missing begin_graceful_shutdown"
grep -q 'fn is_shutting_down' src/server.rs                || r_t9_missing="$r_t9_missing is_shutting_down"
grep -q 'SHUTDOWN_TOKEN' src/server.rs                     || r_t9_missing="$r_t9_missing SHUTDOWN_TOKEN"
grep -q 'shutdown.cancelled()' src/server/connection.rs    || r_t9_missing="$r_t9_missing conn-drain-arm"
grep -q 'SignalKind::terminate' src/direct_service.rs || r_t9_missing="$r_t9_missing sigterm-handler"
grep -q 'is_shutting_down()' src/direct_service.rs    || r_t9_missing="$r_t9_missing accept-stop"
grep -qE '^TimeoutStopSec=[1-9][0-9]*$' res/rustdesk.service || r_t9_missing="$r_t9_missing service-TimeoutStopSec(must be a positive drain backstop, =0 is infinite)"
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
grep -q 'whitelist_admits(' src/direct_service.rs    || r_t15d_missing="$r_t15d_missing a4-selftest"
if grep -q '!whitelist.is_empty()' src/server/connection.rs; then
  r_t15d_missing="$r_t15d_missing legacy-default-allow!"
fi
if [ -n "$r_t15d_missing" ]; then
  echo "  FAIL R-S9/R-T15(d): default-deny whitelist incomplete:$r_t15d_missing"; rc=1
else
  echo "  ok  R-S9/R-T15(d) whitelist default-deny + R-A4 not-default-open self-test present"
fi
# R-S9 / BUG3 (flutter UI correctness): the whitelist SETTINGS UI must agree with the default-DENY backend.
# Upstream shows the amber caution only when the whitelist is SET (so empty looks "off" = open); on the fork
# an EMPTY whitelist blocks ALL inbound (the device is unreachable), so the caution icon must flag the EMPTY
# state instead. Assert the flipped offstage polarity on both desktop + mobile (a regrowth to the upstream
# `!hasWhitelist`/`!_onlyWhiteList` polarity -- where empty silently looks reachable -- fails here).
if grep -qF 'offstage: hasWhitelist.value' flutter/lib/desktop/pages/desktop_setting_page.dart \
   && grep -qF 'offstage: _onlyWhiteList,' flutter/lib/mobile/pages/settings_page.dart; then
  echo "  ok  R-S9/BUG3 whitelist UI flags the EMPTY (unreachable) state, matching the default-deny backend"
else
  echo "  FAIL R-S9/BUG3: whitelist settings UI not re-gated to fork default-deny (empty=unreachable) semantics"; rc=1
fi
# R-T10 (§20): TCP keepalive on every accepted peer socket — the kernel backstop the NAT'd-client
# reality demands (idle/rebinding/sleeping NAT mappings vanish WITHOUT a FIN/RST, so a dead peer
# would otherwise hold an fd+task+capture+CM until the app deadline). Set at the accept site via
# socket2 0.5's SockRef + TcpKeepalive (with_time + with_interval; with_retries compiled out on
# Windows), the app 30s deadline staying the portable primary. Gate: the 0.5 dep + accept-site call.
r_t10_missing=
grep -q '^socket2 = "0.5"' Cargo.toml                  || r_t10_missing="$r_t10_missing socket2-0.5-dep"
grep -q 'set_tcp_keepalive' src/direct_service.rs || r_t10_missing="$r_t10_missing keepalive-call"
grep -q 'with_time' src/direct_service.rs         || r_t10_missing="$r_t10_missing with_time-knob"
if [ -n "$r_t10_missing" ]; then
  echo "  FAIL R-T10: TCP keepalive on accepted sockets incomplete:$r_t10_missing"; rc=1
else
  echo "  ok  R-T10 TCP keepalive set on accepted peer sockets (SockRef + TcpKeepalive, app deadline primary)"
fi
# R-T3 (§20) per-send WRITE-DEADLINE — the in-place half of R-T3. (The dedicated-writer-task half — so
# the reader/control channels stay pollable DURING a write — is the larger FramedStream-internal refactor
# tracked in task R-T3; the current loop still blocks for up to one deadline on a wedged write, but it is
# BOUNDED, not infinite.) A peer that completes the PAKE then stops reading must not wedge the connection's
# read loop unboundedly: every peer write goes through FramedStream::send_bytes_raw, which bounds the flush
# by the stream's send-timeout field and R-T2 poisons the stream on a timeout, so the session DROPS instead
# of blocking forever. That field is honored only when > 0 (tcp.rs `if self.2 > 0`), so the connection MUST
# install a NON-ZERO deadline via set_send_timeout. Lock the whole chain so it cannot silently regress to an
# unbounded blocking write (which would hand an idle adversarial peer a per-connection read-loop stall).
r_t3_missing=
grep -qE 'conn\.stream\.set_send_timeout\('            src/server/connection.rs   || r_t3_missing="$r_t3_missing set_send_timeout-call"
grep -qE 'SEND_TIMEOUT_VIDEO: u64 = [1-9]'             src/server/connection.rs   || r_t3_missing="$r_t3_missing nonzero-SEND_TIMEOUT_VIDEO"
grep -qE 'SEND_TIMEOUT_OTHER: u64 = SEND_TIMEOUT_VIDEO' src/server/connection.rs   || r_t3_missing="$r_t3_missing SEND_TIMEOUT_OTHER"
grep -qE 'if self\.2 > 0'                              libs/hbb_common/src/tcp.rs || r_t3_missing="$r_t3_missing tcp-deadline-apply"
if [ -n "$r_t3_missing" ]; then
  echo "  FAIL R-T3: per-send write deadline incomplete:$r_t3_missing"; rc=1
else
  echo "  ok  R-T3 per-send write deadline installed (set_send_timeout + non-zero SEND_TIMEOUT_*, applied in send_bytes_raw, R-T2 poison)"
fi
# R-T15(b) / R-S10: the inherited LOGIN_FAILURES limiter — unbounded-growth / never-decaying /
# full-IPv6-keyed, and on dead paths (the legacy unkeyed/salted-hash login is gone) — MUST be
# excised so the live online-guess limiter is unambiguously the bounded, decaying, per-v4-source
# GUESS_FAILURES in cpace.rs (R-P14c). Gate: no LOGIN_FAILURES reference remains in CODE (the
# excision-documenting comments are allowed), and GUESS_FAILURES (the live limiter) is still present.
r_t15b_missing=
grep -q 'static ref LOGIN_FAILURES' src/server/connection.rs && r_t15b_missing="$r_t15b_missing static-present!"
grep -q 'fn check_failure_ipv6_prefix' src/server/connection.rs && r_t15b_missing="$r_t15b_missing ipv6-helper-present!"
grep -q 'fn get_ipv6_prefixes' src/server/connection.rs && r_t15b_missing="$r_t15b_missing prefixes-helper-present!"
grep -q 'GUESS_FAILURES' libs/hbb_common/src/cpace.rs || r_t15b_missing="$r_t15b_missing guess-failures-MISSING!"
if [ -z "$r_t15b_missing" ]; then
  echo "  ok  R-T15(b) LOGIN_FAILURES limiter excised (GUESS_FAILURES remains the live limiter)"
else
  echo "  FAIL R-T15(b): excision incomplete:$r_t15b_missing"; rc=1
fi
# R-S10(b): the live online-guess limiter (GUESS_FAILURES, cpace.rs) MUST be bounded by VALUE, not just
# present — a HARD entry-count ceiling (MAX_TRACKED_SOURCES) with oldest-window eviction ON TOP of the
# time-eviction, plus a finite per-source threshold and window. Value-assert the named constants + the
# eviction path + the flood-cap KAT (cpace_it/tests/guess_limiter_cap.rs, run under -p cpace_it above),
# so a regression to unbounded / never-decaying tracking fails closed (presence-only would not catch it).
r_s10b=
grep -qE '^const MAX_TRACKED_SOURCES: usize = 8192;'                  libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-8192-cap"
grep -qE 'while map\.len\(\) > MAX_TRACKED_SOURCES'                   libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-cap-eviction"
grep -qE '^const MAX_GUESSES_PER_WINDOW: u32 = 10;'                   libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-threshold-value"
grep -qE '^const GUESS_WINDOW: Duration = Duration::from_secs\(60\);' libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-window-value"
grep -qE 'map\.retain'                                               libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-time-eviction"
[ -f libs/cpace_it/tests/guess_limiter_cap.rs ]                                                   || r_s10b="$r_s10b no-cap-KAT"
if [ -z "$r_s10b" ]; then
  echo "  ok  R-S10(b) online-guess limiter bounded by value (8192-source cap + oldest-eviction + 10/60s + KAT)"
else
  echo "  FAIL R-S10(b): limiter bound weakened:$r_s10b"; rc=1
fi
# R-T4 (§20, part): the per-connection SYNC cleanup (privacy-off/screen-unblank, the video-fetch
# notify, remove_connection, cursor-record-stop) MUST run on cancellation, so it lives in
# Connection's Drop (which Rust runs when the run-loop future is dropped at its await), not only in
# the post-loop tail it previously sat in (where a cancelled session left the console BLANKED — a
# local-security regression — and the Server map diverged). Gate: the cleanup is in Drop + the tail
# documents the move. (The CM-child kill_on_drop sub-part of R-T4 is DEFERRED-WITH-REASON, not a
# pending TODO: the spec assumes the CM child is per-connection, but it is uid-SHARED — before
# spawning, connection.rs:~4497 does connect_for_uid(uid,"_cm") and REUSES an existing CM, skipping
# the spawn. A connection-owned kill_on_drop would therefore kill a CM still serving OTHER live
# connections from the same uid (a cross-connection regression). The correct model for a shared
# process is the current central CHILD_PROCESS reap + the CM self-exiting when its last IPC client
# disconnects, so this sub-part MUST NOT be implemented as literally written.)
r_t4_missing=
grep -q 'the per-connection cleanup that was previously straight-line' src/server/connection.rs || r_t4_missing="$r_t4_missing drop-cleanup"
grep -q 'have MOVED into' src/server/connection.rs || r_t4_missing="$r_t4_missing tail-note"
if [ -z "$r_t4_missing" ]; then
  echo "  ok  R-T4 (part) sync teardown cleanup folded into Connection::Drop (runs on cancellation)"
else
  echo "  FAIL R-T4: teardown cleanup not folded into Drop:$r_t4_missing"; rc=1
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
if grep -A14 'pub async fn listen_any_v4' libs/hbb_common/src/tcp.rs | grep -q 'new_listener_socket'; then
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
ra6_clean 'SignedId|set_signed_id|set_public_key|message::Union::PublicKey' 'R-P5 SignedId/PublicKey device-identity keying' || rc=1
# R-A5: the directional-cipher nonce IS the per-direction counter, so seal/open MUST use a CHECKED
# increment (checked_add, fail-closed at 2^64) — a raw `seq += 1` would silently WRAP in a release
# build, resetting to an already-used nonce and reusing (key, nonce) (catastrophic for the AEAD).
# Assert the raw compound-increment never returns to cpace.rs's DirectionalCipher.
ra6_clean 'write_seq *\+=|read_seq *\+=' 'R-A5 unchecked nonce-counter increment (must be checked_add)' || rc=1
# R-A5: the directional-cipher two-key DISTINCTNESS assert MUST read back the ENGAGED cipher state
# (self.send_key / self.recv_key), NOT the derived input `keys` — HKDF makes the inputs distinct by
# construction, so a check on `keys` only restates that; the regression R-A5 exists to catch is a
# keying-mis-wire that engages one key BOTH ways (e.g. `recv_key: Key(keys.send)`), which the input
# check passes but the engaged read-back fails closed on. Assert the engaged form is present and the
# old input-key form (`keys.send, keys.recv` in an assert) is gone.
r_a5_dist=
grep -qE 'cipher\.send_key\.0,\s*cipher\.recv_key\.0' libs/hbb_common/src/cpace.rs || r_a5_dist="$r_a5_dist engaged-key-assert-missing"
grep -qE 'keys\.send, keys\.recv'                     libs/hbb_common/src/cpace.rs && r_a5_dist="$r_a5_dist input-key-assert-still-present"
if [ -n "$r_a5_dist" ]; then
  echo "  FAIL R-A5: engaged-key distinctness assert incomplete:$r_a5_dist"; rc=1
else
  echo "  ok  R-A5 engaged-cipher send/recv-key distinctness asserted (self.send_key/recv_key, not derived inputs)"
fi
# R-A2/R-S2 (authorization is a single keyed-edge choke-point): `self.authorized = true` must appear
# EXACTLY ONCE in connection.rs — it lives in `send_logon_response_and_keep_alive`, reached only on
# the CPace-keyed + whitelisted + password-login path, and EVERY privileged inbound handler
# (input/clipboard/file/capture/terminal/port-forward) is gated behind the lone `else if
# self.authorized` arm of `on_message`. A second set-point is a candidate auth-bypass — fail closed.
# (Audited: only Misc::CloseReason, LoginRequest, and TestDelay dispatch pre-authorization, all
# side-effect-free.)
r_a2_n=$(grep -c 'self\.authorized = true' src/server/connection.rs 2>/dev/null || true)
if [ "${r_a2_n:-99}" -ne 1 ]; then
  echo "  FAIL R-A2/R-S2: expected EXACTLY ONE 'self.authorized = true' in connection.rs (found $r_a2_n) — a new authorization point needs an auth-bypass re-audit"; rc=1
else
  echo "  ok  R-A2/R-S2 single authorization choke-point (self.authorized=true x1; privileged handlers gated)"
fi
# Secrets-at-rest: the config writer `store_path` MUST create files mode 0o600 (owner-only). Every
# password-equivalent lives in a config file — the box's permanent-password PRS (main Config) and the
# viewer's per-peer password/password_prs + os/rdp creds (PeerConfig), all encrypted under the
# machine-UUID wrapper, but the FILE MODE is the at-rest perimeter against other local users. Audited:
# both go through `store_path` -> `confy::store_path_perms(.., from_mode(0o600))`. Assert it survives;
# a regression to a world/group-readable mode would expose the password-equivalent to any local account.
r_secrets_n=$(grep -c 'from_mode(0o600)' libs/hbb_common/src/config.rs 2>/dev/null || true)
if [ "${r_secrets_n:-0}" -lt 1 ]; then
  echo "  FAIL secrets-at-rest: config store_path must write mode 0o600 (from_mode(0o600) missing in config.rs)"; rc=1
else
  echo "  ok  secrets-at-rest config files written mode 0o600 (owner-only; permanent-password PRS + peer creds)"
fi
# R-S17/R-S13 (viewer-side MITM gate): the viewer MUST verify the responder's HostIdentity host-proof
# AND pin-compare it before trusting the keyed session. `key_initiator` (client.rs) reads the proof,
# `verify_host_identity` checks the Ed25519 signature over the session transcript, then
# `host_pin::get_pinned_pk` does the SSH-known_hosts fail-closed compare: a MISMATCH refuses
# (substitution/MITM), and FIRST-CONTACT refuses too — NO trust-on-first-use. The smoke's probe
# verifies the SIGNATURE but does NOT pin, so this gate is the only guard that the pin-compare (the
# actual MITM gate) is not silently dropped. Assert both calls survive in client.rs.
r_s17v_n=$(grep -cE 'verify_host_identity|get_pinned_pk' src/client.rs 2>/dev/null || true)
if [ "${r_s17v_n:-0}" -lt 2 ]; then
  echo "  FAIL R-S17: viewer host-proof verify + pin-compare (verify_host_identity + get_pinned_pk) missing in client.rs — MITM gate regressed"; rc=1
else
  echo "  ok  R-S17 viewer verifies host-proof + pin-compares (fail-closed, no trust-on-first-use)"
fi
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
# R-SV4 / §18 (dial nobody): the DEFAULT rendezvous-server list (RENDEZVOUS_SERVERS in
# hbb_common/config.rs) must stay EMPTY. Upstream baked "rs-ny.rustdesk.com" in as the fallback used
# whenever no server is configured, so a "direct-IP only" binary still carried a hardwired upstream
# broker -- one revived caller away from a phone-home. The connect paths are already neutered (the
# gates above) and the latency probe early-returns on <=1 server, so it never dialed; the const is
# now &[] for defense-in-depth -- get_rendezvous_server[s]() fall back to nothing, dialing nobody.
# Two hardened gates (presence-vs-VALUE): (a) structural -- no quoted host on the const's definition
# line, catching ANY hardwired default (rustdesk or not); (b) value -- no rs-*.rustdesk.com host
# anywhere in code, catching the host hardcoded elsewhere (`//` comments are filtered).
if grep -nE 'pub const RENDEZVOUS_SERVERS[^=]*=[^;]*"' libs/hbb_common/src/config.rs; then
  echo "  FAIL R-SV4/§18: RENDEZVOUS_SERVERS must be empty (&[]) -- no hardwired rendezvous broker baked into the direct-IP binary"; rc=1
else
  echo "  ok  R-SV4/§18 RENDEZVOUS_SERVERS default empty (no hardwired rendezvous broker; dial nobody)"
fi
ra6_clean 'rs-[a-z]+\.rustdesk\.com' 'R-SV4/§18 hardwired rs-*.rustdesk.com rendezvous host (RENDEZVOUS_SERVERS emptied)' || rc=1
# R-SV1 / §8 / §18 (no device fingerprinting): the upstream hbb_common::fingerprint module -- a
# HARDWARE fingerprint generator (sysinfo-collected cpu brand/speed/cores/mem/platform/arch/addr,
# obfuscated with a hand-rolled AES: the S-box TABLE + expand_key/gf_mul/add_round_key) that upstream
# used to identify devices to the rendezvous -- is REMOVED. The fork excised the rendezvous
# registration that consumed it, orphaning the module (declared `pub mod fingerprint` but ZERO callers
# tree-wide; the live get_fingerprint/pk_to_fingerprint/--get-fingerprint paths are the UNRELATED
# Ed25519 PUBLIC-KEY fingerprint for R-S17 host pinning). Gone not disabled: no dead privacy-hostile
# device-fingerprinting machinery (or hand-rolled crypto) left compiled into the binary.
if [ -f libs/hbb_common/src/fingerprint.rs ]; then
  echo "  FAIL R-SV1/§8: the device-fingerprint module (hbb_common/fingerprint.rs) is back"; rc=1
else
  echo "  ok  R-SV1/§8 device-fingerprint module removed (hbb_common/fingerprint.rs absent)"
fi
ra6_clean 'FingerprintingInfo|get_fingerprinting_info|fn expand_key|fn gf_mul|mod fingerprint' 'R-SV1/§8 device-fingerprint (hardware-id + hand-rolled-AES) machinery' || rc=1
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
# R-SV4(d) / R-S11 / §18: the NAT/STUN startup ENTRY symbols are cfg-ABSENT, not stubbed —
# test_nat_type (the startup probe, already a no-op after the egressing test_nat_type_/test_ipv6/
# STUNS_* leaves were excised) + CheckTestNatType (the RAII Drop-guard that fired it at arm entry, the
# R-S11 reachability concern) are EXCISED, meeting the spec's "a no-op stub is DIFFERENT from being
# cfg-absent" bar so the sound-symbol-grep holds (the leaves are R-SV4(b) above).
ra6_clean 'test_nat_type|CheckTestNatType' 'R-SV4(d) NAT/STUN entry symbols (test_nat_type/CheckTestNatType)' || rc=1
# R-SV4: the WebRTC transport (a second STUN/ICE source — DEFAULT_ICE_SERVERS) MUST NOT be compiled —
# the hbb_common `webrtc` feature is never ENABLED (the root dep pulls hbb_common with no features and
# hbb_common's default is empty), so `mod webrtc` (#[cfg(feature="webrtc")]) is absent from every
# build. This replaces the prior comment-only assertion with a real gate.
r_sv4_webrtc=
grep -qE 'hbb_common = \{[^}]*features = \[[^]]*"webrtc"' Cargo.toml && r_sv4_webrtc="$r_sv4_webrtc root-enables-webrtc"
grep -qE '^default = \[[^]]*"webrtc"' libs/hbb_common/Cargo.toml && r_sv4_webrtc="$r_sv4_webrtc hbb_common-default-webrtc"
if [ -n "$r_sv4_webrtc" ]; then
  echo "  FAIL R-SV4: the webrtc transport feature is enabled:$r_sv4_webrtc"; rc=1
else
  echo "  ok  R-SV4 webrtc transport feature not enabled (no STUN/ICE DEFAULT_ICE_SERVERS compiled)"
fi
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
# §18 / R-R2b (universal software codec): hwcodec/vram (the GPU/VRAM hardware-codec deps —
# ffmpeg amf/nvcodec/qsv) AND mediacodec (Android's MediaCodec hardware decode/encode) — each a
# native attack surface (Appendix C #2b) AND a build-reproducibility hazard — are compiled out of
# EVERY build path; the fork is CPU-only software vpx/aom. The optional
# feature DEFINITIONS in Cargo.toml/scrap are inert (never selected) — what this forbids is
# any build script / CI job / driver that ENABLES them: a `--features …hwcodec/vram…`, a
# `--hwcodec`/`--vram` flag, a RUSTDESK_FEATURES/extra_features carrying them, or a
# features.append('hwcodec'). Full-line comments (the R-R2b "dropped" notes) are exempt;
# `nvram` (a libvirt term in cleanup.sh) is not a match. The desktop scripts dropped it
# early, but the flutter mobile scripts + the CI matrix + build.py's own flags still
# selected it until 575859a's follow-on — this locks the universal drop in tree-wide.
hw_hits=$(grep -RInE 'hwcodec|vram|mediacodec' \
            --include='*.sh' --include='*.py' --include='*.yml' --include='*.yaml' --include='*.ps1' . 2>/dev/null \
          | grep -vE '/target/|requirements\.html|scripts/verify\.sh' \
          | grep -vE ':[0-9]+:[[:space:]]*#' \
          | grep -viE 'nvram' || true)
if [ -n "$hw_hits" ]; then
  echo "  FAIL §18/R-R2b: a build path still ENABLES hwcodec/vram/mediacodec (must be universally compiled out):"
  echo "$hw_hits" | sed 's/^/      /'; rc=1
elif grep -E '^default *=' Cargo.toml | grep -qiE 'hwcodec|vram|mediacodec'; then
  echo "  FAIL §18/R-R2b: the Cargo.toml default feature pulls in hwcodec/vram/mediacodec"; rc=1
else
  echo "  ok  §18/R-R2b hwcodec/vram/mediacodec never selected in any build path (CPU-only software codec)"
fi
# R-R2b (native deps): the vcpkg manifest must not pull the hardware-codec native
# libraries — ffmpeg (the amf/nvcodec/qsv hwaccel backend) and mfx-dispatch (Intel
# MediaSDK/QSV) — nor their hwaccel override pins (ffnvcodec, amd-amf). The fork's
# vcpkg.json carries ONLY the CPU-only software set: aom libvpx libyuv opus
# libjpeg-turbo (+ android oboe/cpu-features). This locks the prune so a manifest edit
# can't silently re-introduce the GPU/hardware-codec native attack surface — and the
# multi-hour ffmpeg build that made the §12.2 Windows VM build infeasible. (The
# hwcodec gate above covers the Rust/feature side; this covers the native-dep side.)
if [ -f vcpkg.json ] && grep -qE '"(ffmpeg|mfx-dispatch|ffnvcodec|amd-amf)"' vcpkg.json; then
  echo "  FAIL §18/R-R2b: vcpkg.json still lists a hardware-codec native dep (ffmpeg/mfx-dispatch/ffnvcodec/amd-amf):"
  grep -nE '"(ffmpeg|mfx-dispatch|ffnvcodec|amd-amf)"' vcpkg.json | sed 's/^/      /'; rc=1
else
  echo "  ok  §18/R-R2b vcpkg.json native set is CPU-only software codec (no ffmpeg/mfx-dispatch)"
fi
# R-R2a (§12 / sovereignty): the .deb + systemd is the SOLE Linux package model. The AppImage
# recipe (whose `update-information` self-updater collides with R-X1 "the fork ships its own
# releases") and the Flatpak manifest (a portal-sandbox, no-systemd posture colliding with
# R-D1/R-D3a "the systemd confinement IS the model") are DELETED from the tree — not merely
# unbuilt — so that sovereignty/sandbox-model drift cannot regress in. Gate their absence (the
# appimage/ + flatpak/ dirs gone) AND that no workflow builds them. PHASE 2 (also done): the
# non-Debian distro packaging — res/PKGBUILD (Arch) + res/rpm*.spec (Fedora/SUSE) + build.py's
# pacman/yum/zypper branches + the CI rpmbuild/makepkg (arch) steps — is excised too, so the .deb
# is the ONLY Linux artifact (the harmless apt-get `rpm` tooling install is not a build step).
rr2a_bad=
[ -e appimage ] && rr2a_bad="$rr2a_bad appimage-dir"
[ -e flatpak ]  && rr2a_bad="$rr2a_bad flatpak-dir"
[ -e res/PKGBUILD ] && rr2a_bad="$rr2a_bad PKGBUILD"
ls res/rpm*.spec >/dev/null 2>&1 && rr2a_bad="$rr2a_bad rpm-spec"
if grep -rqIE 'build-appimage:|build-flatpak:|appimage-builder|flatpak-builder|rpmbuild|makepkg|arch-makepkg|"appimage/\*\*"|"flatpak/\*\*"' .github/workflows/ 2>/dev/null; then
  rr2a_bad="$rr2a_bad CI-ref"
fi
if [ -n "$rr2a_bad" ]; then
  echo "  FAIL R-R2a: non-.deb Linux packaging must be ABSENT (.deb+systemd is the sole model):$rr2a_bad"; rc=1
else
  echo "  ok  R-R2a non-.deb Linux packaging excised — AppImage/Flatpak + PKGBUILD/rpm (.deb+systemd is the sole Linux model)"
fi
# R-SV8 (§18 sovereignty, MUST): no Firebase / FCM / Google-services on ANY artifact (iOS source +
# Android). The iOS GoogleService-Info.plist shipped LIVE Google creds (API_KEY / GCM_SENDER_ID /
# GOOGLE_APP_ID) + DATABASE_URL https://rustdesk.firebaseio.com, bundled at the Xcode/CocoaPods
# layer — invisible to cargo/cfg. The push entitlements (aps-environment APNs + wifi-info SSID
# fingerprint) are already stripped (Runner.entitlements is an empty dict) and Android is
# google-services-free; this locks in the residual creds-plist deletion. (build_fdroid.sh's
# gms/firebase STRIP sed, the spec, and the entitlements R-SV8 comment legitimately NAME the
# tokens — the checks below target the actual creds/endpoint/entitlement, not those mentions.)
rsv8_bad=
[ -e flutter/ios/Runner/GoogleService-Info.plist ] && rsv8_bad="$rsv8_bad ios-creds-plist"
[ -n "$(find flutter/android -name google-services.json 2>/dev/null)" ] && rsv8_bad="$rsv8_bad android-google-services"
grep -rqIE 'firebaseio\.com|IS_GCM_ENABLED|GOOGLE_APP_ID' flutter 2>/dev/null && rsv8_bad="$rsv8_bad firebase-creds/endpoint"
grep -qE '<key>' flutter/ios/Runner/Runner.entitlements 2>/dev/null && rsv8_bad="$rsv8_bad ios-push-entitlement"
grep -qE '^[[:space:]]*firebase_' flutter/pubspec.yaml 2>/dev/null && rsv8_bad="$rsv8_bad firebase-dep"
# R-SV8 per-pod allow-list (R-SV1 enforces sovereignty on the cfg-checked Apple source too): no
# auto-updater or telemetry rides the macOS/iOS source — no Sparkle (the macOS phone-home-and-
# fetch-run auto-updater, an R-X1 surface), no Crashlytics/Fabric, no Sentry, no AppCenter.
# Verified ZERO mentions (code AND comments) in flutter/macos + flutter/ios; this locks it in.
grep -rqIE 'Sparkle|Crashlytics|Fabric|Sentry|AppCenter' flutter/macos flutter/ios 2>/dev/null && rsv8_bad="$rsv8_bad apple-telemetry/updater-pod"
if [ -n "$rsv8_bad" ]; then
  echo "  FAIL R-SV8: Firebase/telemetry/auto-updater residue on an artifact or the Apple source (MUST be absent):$rsv8_bad"; rc=1
else
  echo "  ok  R-SV8 no Firebase/FCM/Google-services + no Sparkle/Crashlytics/Sentry telemetry (iOS plist + push entitlements + Android + Apple source all clean)"
fi
# R-SV9 (§18 sovereignty): the front-ends MUST carry no PLAINTEXT-http link (a downgrade/MITM
# vector). The installer's EULA #agreement link opened http://rustdesk.com/privacy over cleartext —
# fixed to https. (The broader SHOULD — delete/repoint the ~28 rustdesk.com / github.com/rustdesk
# advertising + doc links across both front-ends + the config.rs HELPER_URL doc map — is a separate
# de-branding pass needing an operator-resource decision; not yet gated.) Gate the MUST: no
# `http://`-scheme rustdesk/github link in the UI front-ends (.tis / .dart). The common.rs is_public
# unit-test string is a .rs test, not a UI link, so it is out of scope.
rsv9_http=$(grep -rInE 'http://[^ ]*(rustdesk|github)' src/ui flutter/lib --include='*.tis' --include='*.dart' 2>/dev/null || true)
if [ -n "$rsv9_http" ]; then
  echo "  FAIL R-SV9: a plaintext-http rustdesk/github link remains in a front-end (MUST be https or removed):"; echo "$rsv9_http" | sed 's/^/      /'; rc=1
else
  echo "  ok  R-SV9 no plaintext-http rustdesk/github link in the front-ends (the MUST; the SHOULD de-brand is pending)"
fi
# R-S11a / R-S8 (cross-uid IPC authorization + parent-dir hardening): two MUSTs over the world-mode
# 0o0666 `_service`/`_uinput_*` sockets. (a) AUTHORIZATION — the `_service` UID gate authorizes the
# peer against a FRESH active-user lookup (active_uid_fresh, src/ipc/auth.rs), NOT the service-loop
# cache, so a just-switched-out user cannot pass in the cache-lag window (matching uinput); the cached
# active_uid() stays only for config-sync routing. (b) the parent dir the root service owns + locks
# down BEFORE binding — opened O_NOFOLLOW (symlink-TOCTOU, R-S8), the opened FD fchmod'd to the
# expected mode (0o0711 service / 0o0700 else) + fchown'd, stale artifacts scrubbed — so a local user
# cannot pre-stage a world-traversable dir/socket the service trusts. Gate both present + wired.
# R-S11a(b) reject-and-recreate (a foreign-owned service dir is rmdir'd + recreated on a FRESH inode,
# never fchown-adopted, so a pre-set ACL cannot survive) is DONE (commit b46e427) + behavior-tested at (3b).
r_s11a_missing=
grep -q 'fn active_uid_fresh' src/ipc/auth.rs                      || r_s11a_missing="$r_s11a_missing fresh-auth-fn"
grep -q 'let active_uid = active_uid_fresh()' src/ipc/auth.rs      || r_s11a_missing="$r_s11a_missing fresh-auth-wire"
grep -q 'ensure_secure_ipc_parent_dir(&path, postfix)' src/ipc.rs || r_s11a_missing="$r_s11a_missing new_listener-wire"
grep -q 'scrub_secure_ipc_parent_dir(&path, postfix)'  src/ipc.rs || r_s11a_missing="$r_s11a_missing scrub-wire"
grep -q 'fn ensure_secure_ipc_parent_dir' src/ipc/fs.rs           || r_s11a_missing="$r_s11a_missing ensure-fn"
grep -q 'O_NOFOLLOW' src/ipc/fs.rs                                 || r_s11a_missing="$r_s11a_missing O_NOFOLLOW"
grep -q 'fn expected_ipc_parent_mode' src/ipc/fs.rs               || r_s11a_missing="$r_s11a_missing expected-mode"
grep -qE '0o0?711' src/ipc/fs.rs                                   || r_s11a_missing="$r_s11a_missing 0o711"
if [ -n "$r_s11a_missing" ]; then
  echo "  FAIL R-S11a/R-S8: IPC fresh-auth or parent-dir hardening incomplete/unwired:$r_s11a_missing"; rc=1
else
  echo "  ok  R-S11a(a) fresh _service active-uid auth + R-S11a(b)/R-S8 parent-dir hardening (O_NOFOLLOW+0o0711+scrub) present & wired"
fi
# R-S8 / R-A5 (file-transfer write-path no-follow — DISTINCT from the IPC parent-dir O_NOFOLLOW above):
# the receive-WRITE opens in hbb_common/src/fs.rs MUST be no-follow (open_recv_write_no_follow /
# O_NOFOLLOW), closing the §4.3 symlink TOCTOU on the file-receive path — a local user swapping the
# target for a symlink AFTER the path-validation must not redirect root's write onto an arbitrary file.
# Upstream/inherited used a path-based File::create/OpenOptions (TOCTOU-prone, acknowledged in-code).
# Assert the helper + O_NOFOLLOW are present AND the raw symlink-following create is gone from the
# write path; the refuse-symlink / allow-regular behavior is proven by the (3c) tests.
r_s8ft_missing=
grep -q 'fn open_recv_write_no_follow' libs/hbb_common/src/fs.rs           || r_s8ft_missing="$r_s8ft_missing helper"
grep -q 'O_NOFOLLOW' libs/hbb_common/src/fs.rs                             || r_s8ft_missing="$r_s8ft_missing O_NOFOLLOW"
grep -q 'open_recv_write_no_follow(&path, true)' libs/hbb_common/src/fs.rs || r_s8ft_missing="$r_s8ft_missing data-write-wired"
if grep -qE 'File::create\(&path\)' libs/hbb_common/src/fs.rs; then r_s8ft_missing="$r_s8ft_missing raw-File::create-remains"; fi
if [ -n "$r_s8ft_missing" ]; then
  echo "  FAIL R-S8/R-A5: file-transfer receive-write is not no-follow:$r_s8ft_missing"; rc=1
else
  echo "  ok  R-S8/R-A5 file-transfer receive-write is no-follow (O_NOFOLLOW closes the §4.3 symlink-TOCTOU; behavior-tested at (3c))"
fi
# R-S14 (screen capture bound to a PAKE session — a reused grant must not capture outside one): the
# controlled-side capture is per-connection — started only in the authorized (CPace-keyed) Connection
# setup (try_add_primay_video_service, after the R-A2 single self.authorized point) and torn down in
# its Drop (R-T4: stop capture / unblank on disconnect). The Android "reused grant" vector — a
# foreground-service AUTO-RESTART re-entering capture WITHOUT a fresh PAKE session — is closed by
# MainService.onStartCommand returning START_NOT_STICKY (not START_STICKY): a restart never resumes
# capture on its own. Gate that the Android capture service stays NOT_STICKY.
r_s14_kt=flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainService.kt
if grep -q 'START_NOT_STICKY' "$r_s14_kt" 2>/dev/null && ! grep -qE 'return[[:space:]]+START_STICKY\b' "$r_s14_kt" 2>/dev/null; then
  echo "  ok  R-S14 Android capture service is START_NOT_STICKY (an auto-restart never re-enters capture outside a fresh PAKE session; desktop capture is per-Connection via R-A2 + R-T4)"
else
  echo "  FAIL R-S14: MainService.onStartCommand must return START_NOT_STICKY (not START_STICKY) so an auto-restart cannot resume capture outside a PAKE session"; rc=1
fi
# R-G5 / R-S17 (the host-key-pin DIALOGS — the one new MITM defense the fork ADDS): the viewer's
# host-proof verify + pin-compare (R-S17, gated above on the client.rs side) is only USABLE if the GUI
# lets the operator SEED a pin on first contact (and re-pin on a mismatch). The flutter dialogs MUST
# exist: hostNotPinnedDialog (first-contact fingerprint seed) -> bind.sessionPinHost, dispatched from
# the `host-not-pinned-prompt` model event. A regression that dropped them would silently revert the
# viewer to blind trust-on-first-use (the absence IS the security regression — a presence gate).
r_g5_missing=
grep -q 'void hostNotPinnedDialog' flutter/lib/common/widgets/dialog.dart 2>/dev/null || r_g5_missing="$r_g5_missing seed-dialog"
grep -q 'bind.sessionPinHost' flutter/lib/common/widgets/dialog.dart 2>/dev/null       || r_g5_missing="$r_g5_missing pin-action"
grep -q 'host-not-pinned-prompt' flutter/lib/models/model.dart 2>/dev/null             || r_g5_missing="$r_g5_missing prompt-dispatch"
if [ -n "$r_g5_missing" ]; then
  echo "  FAIL R-G5/R-S17: the host-key-pin GUI dialogs are missing (the MITM-defense UI must stay; their absence reverts to trust-on-first-use):$r_g5_missing"; rc=1
else
  echo "  ok  R-G5/R-S17 host-key-pin dialogs present (first-contact fingerprint seed -> sessionPinHost; no silent trust-on-first-use)"
fi
# R-X7a / R-G1 (no inert pinned-policy SELECTOR survives — removed, not greyed): verification-method +
# approve-mode are R-S16-pinned (use-permanent-password / password), so a UI that PRESENTS+WRITES them
# is the exact "defaulted-off-but-present" hazard R-G1 forbids — the funnel overrides the write and
# is_option_can_save rejects it, leaving a divergent dead presentation. The fork REMOVES the
# verification-method/approve-mode/one-time-password selectors (desktop Safety tab + Android server
# page), leaving only "Set permanent password". Gate that NO flutter UI WRITES those pinned keys — no
# mainSetOption with verification-method/approve-mode (literal or kOption* const) and no
# setVerificationMethod/setApproveMode model setter. (Reading them for display via mainGetOption is fine.)
rx7a_hits=$(grep -rInE 'setVerificationMethod|setApproveMode|mainSetOption[^;]*verification-method|mainSetOption[^;]*approve-mode|mainSetOption[^;]*kOptionVerificationMethod|mainSetOption[^;]*kOptionApproveMode' flutter/lib --include='*.dart' 2>/dev/null | grep -v 'generated_bridge' | grep -vE ':[0-9]+:[[:space:]]*//' || true)
if [ -n "$rx7a_hits" ]; then
  echo "  FAIL R-X7a/R-G1: a flutter UI still WRITES the pinned verification-method/approve-mode policy (remove the selector, do not disable it):"; echo "$rx7a_hits" | sed 's/^/      /'; rc=1
else
  echo "  ok  R-X7a/R-G1 no flutter UI writes the pinned verification-method/approve-mode selectors (removed not greyed; display-reads only)"
fi
# R-S5 / R-A3 (seal the set_raw plaintext-tunnel escape — Appendix C #4, a Tier-1 finding): upstream's
# port-forward/RDP tunnel calls FramedStream::set_raw AFTER login to DROP the secretbox, so the
# tunnelled bytes cross an otherwise-keyed session in plaintext ("the plaintext path is deleted, not
# defaulted off", §1; acceptance criterion 3). The fork seals it in two layers: (1) enable-tunnel=N is
# pinned in PINNED_SETTINGS (gated above under R-S16), so the only set_raw caller — the port-forward
# loop (connection.rs try_port_forward_loop) — is policy-unreachable; and (2) FramedStream::set_raw is
# made FAIL-CLOSED — it asserts the codec carries no engaged cipher (cipher.is_none()) and PANICS
# rather than downgrade a keyed stream (R-A3, "absent or assert-only" per R-A6). Layer 2 is the
# structural backstop: were a future edit to re-reach set_raw on a keyed stream, it aborts instead of
# leaking plaintext. Gate that the R-A3 downgrade-refusal assert stays present — its removal would
# silently restore the plaintext tunnel, so the absence IS the regression (a presence gate).
r_s5_missing=
grep -q 'fn set_raw' libs/hbb_common/src/tcp.rs                                || r_s5_missing="$r_s5_missing set_raw-fn"
grep -qF 'cipher.is_none()' libs/hbb_common/src/tcp.rs                          || r_s5_missing="$r_s5_missing cipher-guard"
grep -qF 'R-A3: set_raw on a keyed session stream' libs/hbb_common/src/tcp.rs   || r_s5_missing="$r_s5_missing a3-assert"
if [ -n "$r_s5_missing" ]; then
  echo "  FAIL R-S5/R-A3: the set_raw plaintext-tunnel seal regressed (FramedStream::set_raw must fail-closed assert cipher.is_none(), refusing to downgrade a keyed session stream):$r_s5_missing"; rc=1
else
  echo "  ok  R-S5/R-A3 set_raw seal intact (fail-closed assert refuses to strip a keyed session stream; enable-tunnel=N pins the only caller unreachable)"
fi
# R-X7 (Rust OTP excision): the rotating one-time (temporary) password is EXCISED from the Rust tree
# — the permanent password is the sole credential and sole CPace PRS (R-S9/R-P1). R-A6 lists
# TEMPORARY_PASSWORD/update_temporary_password/check_update_temporary_password/get_auto_*numeric* as
# must-be-ZERO; the 2FA half of R-X7 was already gated above, this closes the OTP half. The whole
# chain is gone: the TEMPORARY_PASSWORD store + numeric generator (password_security/config), the
# FFI/IPC/sciter forwarders (ui_interface/ipc/ui/flutter_ffi), the consecutive-wrong-attempt rotation
# (connection.rs TEMPORARY_PASSWORD_FAILURES), and the dead option keys. `Config::get_auto_password`
# STAYS (shared with the Hash challenge — R-T15(c) deferred — and salt generation). The FRB-generated
# bridge is excluded (gitignored, regenerated from flutter_ffi.rs, so it tracks this automatically).
rx7otp_hits=$(grep -rInE 'TEMPORARY_PASSWORD|TEMPORARY_PASSWD|temporary_password|temporary_enabled|get_auto_numeric_password' src libs --include='*.rs' 2>/dev/null | grep -vE 'bridge_generated' | grep -vE ':[0-9]+:[[:space:]]*//|R-X7' || true)
if [ -n "$rx7otp_hits" ]; then
  echo "  FAIL R-X7: the temporary/one-time-password machinery must be absent from the Rust tree (the OTP half of R-X7 — permanent password is the sole credential):"; echo "$rx7otp_hits" | sed 's/^/      /'; rc=1
else
  echo "  ok  R-X7 temporary/one-time-password machinery excised (Rust: store/generator/FFI/IPC/rotation/dead-keys; get_auto_password kept for the Hash challenge + salt)"
fi
# R-F4 (the direct port is a single PINNED compile-time constant, never a runtime knob): the listener
# binds exactly one port, pinned to the literal 21118 (config::DIRECT_PORT) — NOT the inherited
# RENDEZVOUS_PORT+2 derivation (which would silently shift the port and desync the §10.4 CPace CI KAT
# be16(21118)=527e), and NOT a runtime `direct-access-port` option (an override R-S12 forbids). The
# spec's R-A6 mandates exactly this check. Assert the const is 21118, get_direct_port returns the const,
# and no direct-access-port config read exists anywhere.
r_f4_missing=
grep -qE 'pub const DIRECT_PORT: i32 = 21118;' libs/hbb_common/src/config.rs || r_f4_missing="$r_f4_missing const-21118"
grep -qF 'config::DIRECT_PORT' src/direct_service.rs                     || r_f4_missing="$r_f4_missing get_direct_port-returns-const"
if grep -rInE 'get_option\([^)]*direct-access-port|OPTION_DIRECT_ACCESS_PORT' src libs --include='*.rs' 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*//' | grep -q .; then
  r_f4_missing="$r_f4_missing direct-access-port-read-present"
fi
if [ -n "$r_f4_missing" ]; then
  echo "  FAIL R-F4: the direct port must be the pinned compile-time literal 21118 (config::DIRECT_PORT), never the RENDEZVOUS_PORT+2 derivation or a runtime direct-access-port option:$r_f4_missing"; rc=1
else
  echo "  ok  R-F4 direct port pinned to the compile-time literal 21118 (get_direct_port returns config::DIRECT_PORT; no direct-access-port config read; CI KAT be16=527e holds)"
fi

echo "== (6) .msi generator determinism (R-B2) =="
# The WiX .msi generator (res/msi/preprocess.py) MUST emit DETERMINISTIC GUIDs + a sorted component
# order, so a same-host same-version .msi rebuild is byte-identical (the recorded-SHA bar, R-B2). Every
# GUID is a uuid5 of a STABLE key (ProductCode=name+version, components=relpath, UpgradeCode/upgrade-id=
# name) and the dist glob is sorted; NO uuid.uuid4() call (random per build) survives -- incl. the
# rename-path replace_component_guids_in_wxs. Package.wxs pins the ProductCode attr (else WiX 4
# auto-generates a fresh ProductCode each build). Guards the f2f7eb2 + line-541 determinism fixes.
r_b2msi=
grep -qF 'uuid.uuid4(' res/msi/preprocess.py                            && r_b2msi="$r_b2msi uuid4-call-present"
grep -qF 'product_code = uuid.uuid5' res/msi/preprocess.py              || r_b2msi="$r_b2msi ProductCode-not-uuid5"
grep -qF 'comp_guid = uuid.uuid5' res/msi/preprocess.py                 || r_b2msi="$r_b2msi component-not-uuid5"
grep -qF 'sorted(path.glob' res/msi/preprocess.py                       || r_b2msi="$r_b2msi glob-not-sorted"
grep -qF 'upgrade_id = uuid.uuid5' res/msi/preprocess.py                || r_b2msi="$r_b2msi upgradeid-not-uuid5"
grep -qF 'ProductCode="$(var.ProductCode)"' res/msi/Package/Package.wxs || r_b2msi="$r_b2msi wxs-ProductCode-unpinned"
if [ -n "$r_b2msi" ]; then echo "  FAIL R-B2 .msi-generator determinism:$r_b2msi"; rc=1; else
  echo "  ok  R-B2 .msi generator -> deterministic GUIDs+order (ProductCode/component/upgrade uuid5, sorted glob, no uuid4 calls, Package.wxs pins ProductCode)"; fi

echo "== pending excisions (informational TODO, not yet a hard gate) =="
for t in 'mod lan:R-X5 lan.rs residual (WoL send_wol + discover no-op; the discovery LISTENER is excised + hard-gated above — full removal is the R-G2 Discovered-tab/WoL-UI follow-on)' \
         'terminal_helper:R-X8 terminal' 'mod custom_server:R-X4 custom_server module — NB ALSO used by src/platform/windows.rs (get_license/get_license_from_exe_name, the dead custom-rendezvous-server-from-exe-name feature) which this mod-decl grep does NOT count; its removal edits the cfg(windows) build (un-validatable in the Linux docker), so R-X4 is WINDOWS-BUILD-BLOCKED, not a clean Linux excision'; do
  tok=${t%%:*}; lbl=${t#*:}
  n=$(grep -RIl "$tok" src libs --include='*.rs' 2>/dev/null | grep -v 'libs/pake' | wc -l | tr -d ' ' || true)
  echo "  TODO $lbl — still referenced in $n file(s)"
done

if [ "$rc" -ne 0 ]; then
  echo "VERIFY: FAILED (a completed-excision R-A6 gate regressed)"; exit 1
fi
echo "VERIFY: all gates green (KATs + handshake + policy funnel + main-crate compile + R-A6 done-set)"
