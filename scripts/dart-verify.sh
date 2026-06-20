#!/usr/bin/env bash
#
# dart-verify.sh — analyze the Flutter/Dart UI (lib/) in docker.
#
# flutter-verify.sh cargo-checks the feature="flutter" RUST; this gates the DART side, so
# the §19 GUI sweep (removing dead widgets/strings) and the R-S17 known-hosts dialogs are
# verifiable. It runs `flutter pub get` + the full FRB codegen (the Dart bridge too) +
# `flutter analyze lib/`, requiring ZERO ERRORS — the ~238 info/warnings are the upstream
# baseline (style lints), and test/ has pre-existing errors out of scope here. No socket is
# bound by pub-get/codegen/analyze, so this is safe on the DMZ host (never publishes a port).
#
# R-B12 FINDING (documented, not silently swallowed): under the PINNED flutter 3.24.5,
# `flutter pub get` RESOLVES A DIFFERENT pubspec.lock than the committed one — it downgrades
# ~10 packages to the 3.24.5 SDK constraints and adds the flutter_test/leak_tracker dev-deps.
# So the committed flutter/pubspec.lock is NOT consistent with the pinned flutter, i.e. the
# Dart side does NOT build from the committed lock as-is (the R-R1 "build from the committed
# lockfile" invariant is broken on the Dart side). Reconciling it (regenerate the lock under
# flutter 3.24.5, or align the flutter pin to the lock) is an open R-B12/R-R3 item. Until
# then this harness RESTORES the committed pubspec.lock after analyzing, so it never mutates
# the pin behind your back.
set -euo pipefail
cd "$(dirname "$0")/.."

IMG=rd-fluttercheck
RUN=(docker run --rm
  -v "$PWD:/work:rw"
  -v rd-pub-cache:/root/.pub-cache
  -v rd-cargo-cache:/usr/local/cargo/registry
  -v rd-git-cache:/usr/local/cargo/git
  -v rd-verify-target:/build
  -e CARGO_TARGET_DIR=/build
  -w /work "$IMG")

echo "== ensuring images + caches =="
docker volume create rd-pub-cache     >/dev/null
docker volume create rd-cargo-cache   >/dev/null
docker volume create rd-git-cache     >/dev/null
docker volume create rd-verify-target >/dev/null
docker build -q -t rd-devcheck -f scripts/Dockerfile.devcheck     scripts >/dev/null
docker build -q -t "$IMG"      -f scripts/Dockerfile.fluttercheck scripts >/dev/null

echo "== flutter pub get + full FRB codegen + flutter analyze lib/ (zero-errors gate) =="
"${RUN[@]}" bash -c '
  set -e
  cd /work/flutter
  cp pubspec.lock /tmp/pubspec.lock.pin
  trap "cp /tmp/pubspec.lock.pin /work/flutter/pubspec.lock" EXIT  # preserve the committed pin
  flutter pub get >/dev/null
  cd /work
  flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
      --dart-output ./flutter/lib/generated_bridge.dart >/dev/null 2>&1
  cd /work/flutter
  out="$(flutter analyze lib/ 2>&1 || true)"
  errs="$(printf "%s\n" "$out" | grep -c "error •" || true)"
  echo "  lib/ analyze errors: $errs"
  if [ "$errs" != "0" ]; then
    printf "%s\n" "$out" | grep "error •"
    echo "DART-VERIFY: FAILED — $errs error(s) in lib/"
    exit 1
  fi
'
echo "== §19 / R-A6 Dart-layer grep (dead GUI tokens absent) =="
# Extends the R-A6/R-SV10 grep set into the Dart + asset layers (§19's CI hook). Each
# token names a UI surface whose backend §8/§18 removed; a non-comment hit fails the gate.
# Host-side (plain file content — no flutter needed). Grows as the §19 sweep proceeds.
dg_clean() { # token, label
  local tok="$1" label="$2" hits
  # exclude the FRB-GENERATED bridge (git-ignored, regenerated — not authored Dart)
  hits=$(grep -RInE "$tok" flutter/lib flutter/assets 2>/dev/null | grep -v '//' | grep -v 'generated_bridge' || true)
  if [ -n "$hits" ]; then
    echo "  FAIL §19: '$label' must be absent but is present:"; echo "$hits" | sed 's/^/      /'
    exit 1
  fi
  echo "  ok  $label absent"
}
# R-G3: the insecure/relay security-badge assets + states are deleted — the channel is
# ALWAYS secure+direct (§10 PAKE + R-SV4/R-D4), so a badge that could render "insecure"
# or "relayed" is both dead and a dangerous security MISLABEL. (secure.svg is the one kept.)
dg_clean 'insecure\.svg|secure_relay\.svg|insecure_relay\.svg' 'R-G3 insecure/relay security-badge assets'
# R-G4 / R-SV3 / §18: the startup version-check FFI trigger is gone — the app makes no
# api.rustdesk.com/version call at launch (the updater + version-check are excised).
dg_clean 'bind\.mainGetSoftwareUpdateUrl' 'R-G4/R-SV3 startup version-check FFI trigger'
# R-G4 / §18: the dead update GUI is removed — the desktop update card, the mobile
# _buildUpdateUI banner, and the UpdateProgress downloader widget (the file that issued the
# `download-new-version` / `update-me` FFI egress). None may reappear.
dg_clean '_buildUpdateUI|UpdateProgress|handleUpdate' 'R-G4 dead update widgets'
# R-G4 / R-SV3 / §18: the check-update / auto-update settings toggles are removed (the
# version-check + updater are excised, so the option keys back nothing).
dg_clean 'enable-check-update|allow-auto-update' 'R-G4/R-SV3 update-toggle option keys'
dg_clean 'Download new version|Check for software update on startup' 'R-G4 update-UI strings'
# R-G4 / §19: the OIDC SSO provider-login is removed — the "Login with Google/GitHub/…" widgets
# (_IconOP / ButtonOP / WidgetOP / LoginWidgetOP / ConfigOP + kOpSvgList), the loginDialog
# third-auth section, queryOidcLoginOptions, and the auth-*.svg provider icons. A direct-IP fork
# has no account server to enumerate providers (mainGetApiServer is pinned empty), so the section
# was always dead (empty loginOptions ⇒ Offstage). None may reappear.
dg_clean 'LoginWidgetOP|kOpSvgList|kAuthReqTypeOidc|queryOidcLoginOptions' 'R-G4 OIDC SSO provider-login widgets'
# R-G4 / §19: the "Network"/server-config UI is deleted — config UI for the rendezvous / relay /
# api-server infrastructure the fork structurally removed. Desktop: the _Network/_NetworkState
# classes ("ID/Relay Server" editor + SOCKS proxy + WebSocket switch) + the SettingsTabKey.network
# enum value + its tabKeys include + both _settingTabs()/_children() switch cases. Mobile: the
# ID/Relay-Server + Socks5/Http(s)-Proxy SettingsTiles + the _hideServer/_hideProxy state. Plus the
# shared changeSocks5Proxy proxy-editor (desktop_setting_page) and showServerSettings dialog
# (mobile/widgets/dialog.dart) — both now uncalled. (showServerSettingsWithValue stays for the QR
# scan_page; the mobile "Use WebSocket"/"Deploy" tiles are separate follow-ons.) None may reappear.
dg_clean 'SettingsTabKey\.network|changeSocks5Proxy|void showServerSettings\(' 'R-G4 Network/server-config UI (tab + SOCKS + server dialog)'
# R-G4 / R-SV6 / §19: the desktop "Account" settings tab is deleted — the _Account/_AccountState
# classes (the rustdesk-account login/logout panel) + the SettingsTabKey.account enum value + its
# tabKeys include + both _settingTabs()/_children() switch cases. A direct-IP fork has no account
# server (account/OIDC compiled out, R-SV6); the account is no longer a configurable concept. The
# loginDialog/UserModel/toolbar+mobile account entry points are the rest of the account sweep. No
# desktop Account tab may reappear.
dg_clean 'SettingsTabKey\.account' 'R-G4 desktop Account settings tab'
# R-X2 / R-G4 / §19: the desktop "Plugin" settings tab is deleted — the native-plugin loader is
# excised (R-X2: mod plugin / plugin_framework absent) and plugin_feature_is_enabled() is pinned
# SyncReturn(false), so the tab was always hidden + dead. Removed the _Plugin/_PluginState classes
# (incl. the "login to use plugins" loginDialog button) + the SettingsTabKey.plugin enum value +
# its tabKeys include + both switch cases. (The plugin_feature_is_enabled FFI stub stays — a
# flutter-verify trim follow-on.) No desktop Plugin tab may reappear.
dg_clean 'SettingsTabKey\.plugin|class _Plugin\b' 'R-X2/R-G4 dead Plugin settings tab'
# R-G / R-D / §18 (dial nobody): the peer-list ONLINE-STATUS query trigger is removed — a
# direct-IP fork has no rendezvous server to ask which peers are online, and the backend query is
# a no-egress stub (cebfdf2). The `bind.queryOnlines` calls are gone (peers_view) and the online
# dot (`getOnline`) renders nothing; no `bind.queryOnlines` call may reappear.
dg_clean 'bind\.queryOnlines' 'R-G/R-D online-status query trigger'
# R-G8 / §19 (de-brand): a sovereign fork advertises no upstream brand — the user-facing
# rustdesk.com links are removed (the About/website "rustdesk.com" + "powered by" badge, the
# Privacy Statement / EULA privacy.html links, the macOS/Linux permission-card docs "Help"
# links). Gate the privacy + docs URL paths (the `rustdesk.com/pricing` in the dead
# "use public server" guide goes with the R-G2 server-UI removal). Only `//` comments name them.
dg_clean 'rustdesk\.com/privacy|rustdesk\.com/docs' 'R-G8 rustdesk.com privacy/docs links'
# R-S18 / R-X8 / §19: the viewer never solicits OS credentials to push to the host. The
# host-triggered os-login dialogs (enterUserLoginDialog / enterUserLoginAndPasswordDialog, fed
# by the session-login / terminal-admin-login msgbox prompts) AND the os-username/os-password
# fields in the connect dialog (_connectDialog's osUsernameController / osPasswordController)
# are deleted — the responder strips os_login (R-X14/0685c28) and create_login_msg no longer
# sends it (R-S18), so the UI that collected the operator's OS creds is structurally gone.
dg_clean 'enterUserLoginDialog|enterUserLoginAndPasswordDialog|osUsernameController|osPasswordController' 'R-S18/R-X8 viewer os-login dialog (OS-credential push UI)'

echo "DART-VERIFY: flutter analyze lib/ is GREEN (zero errors) + §19 Dart-layer greps clean"
