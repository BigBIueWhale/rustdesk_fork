#!/usr/bin/env bash
# scripts/apple-conform-check.sh - R-R2 Apple (macOS/iOS) source-conformance gate.
#
# Apple is not an artifact target on this Linux build host, but the macOS/iOS
# source must still inherit the fork's security posture. This gate proves the
# source layer with:
#   1. retain-and-check over the Apple source, plist, entitlement, pod, and Xcode
#      project surfaces;
#   2. R-A6 Apple-cfg forbidden-token and sole-backend assertions;
#   3. structured metadata allow-lists for Info.plist, entitlements, Podfile.lock,
#      and PBXShellScriptBuildPhase shell scripts;
#   4. Rust parse checks plus cargo cross-checks for the documented default matrix:
#        aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios
#      using the real Apple features: macOS = flutter,unix-file-copy-paste;
#      iOS = flutter.
#
# Override the matrix only for focused diagnosis:
#   APPLE_TARGETS="x86_64-apple-darwin aarch64-apple-ios" scripts/apple-conform-check.sh
# Legacy APPLE_TARGET=<target> is accepted as a single-target override, but the
# default remains the full R-R2 target matrix.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

BASE_IMG=rd-devcheck
IMG=rd-apple-check
SDK_DIR="${MACOS_SDK_DIR:-$REPO/online/macos-sdk}"
DEFAULT_APPLE_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios)

die(){ echo "FATAL: $*" >&2; exit 1; }
note(){ echo "  $*"; }
rc=0

if [ -n "${APPLE_TARGETS:-}" ]; then
  targets_raw="${APPLE_TARGETS//,/ }"
  read -r -a SELECTED_APPLE_TARGETS <<< "$targets_raw"
elif [ -n "${APPLE_TARGET:-}" ]; then
  SELECTED_APPLE_TARGETS=("$APPLE_TARGET")
else
  SELECTED_APPLE_TARGETS=("${DEFAULT_APPLE_TARGETS[@]}")
fi

valid_apple_target(){
  case "$1" in
    aarch64-apple-darwin|x86_64-apple-darwin|aarch64-apple-ios) return 0 ;;
    *) return 1 ;;
  esac
}
target_features(){
  case "$1" in
    *-apple-ios) echo "flutter" ;;
    *-apple-darwin) echo "flutter,unix-file-copy-paste" ;;
    *) die "unsupported Apple target: $1" ;;
  esac
}
target_triplet(){
  case "$1" in
    aarch64-apple-ios) echo "arm64-ios" ;;
    aarch64-apple-darwin) echo "arm64-osx" ;;
    x86_64-apple-darwin) echo "x64-osx" ;;
    *) die "unsupported Apple target: $1" ;;
  esac
}
target_env_lower(){ echo "$1" | tr '-' '_'; }
target_env_upper(){ echo "$1" | tr '[:lower:]-' '[:upper:]_'; }
version_hash(){
  if [ -e "$REPO/src/version.rs" ]; then
    sha256sum "$REPO/src/version.rs" | awk '{print $1}'
  else
    echo "__MISSING__"
  fi
}

for t in "${SELECTED_APPLE_TARGETS[@]}"; do
  valid_apple_target "$t" || die "unsupported APPLE_TARGETS entry '$t'"
done

# ---- preflight ----
command -v docker >/dev/null 2>&1 || die "docker not found - this gate runs entirely in containers"
[ -f "$REPO/scripts/apple-cc-shim.sh" ] || die "scripts/apple-cc-shim.sh missing"
[ -f "$REPO/scripts/Dockerfile.devcheck" ] || die "scripts/Dockerfile.devcheck missing"
[ -f "$REPO/scripts/Dockerfile.apple-check" ] || die "scripts/Dockerfile.apple-check missing"

echo "== building the apple-check image (devcheck base + Rust 1.81 + Apple std targets) =="
docker build -q -t "$BASE_IMG" -f scripts/Dockerfile.devcheck scripts >/dev/null \
  || die "could not build $BASE_IMG from scripts/Dockerfile.devcheck"
docker build -q -t "$IMG" -f scripts/Dockerfile.apple-check scripts >/dev/null \
  || die "could not build $IMG from scripts/Dockerfile.apple-check"

# ---- Apple source set (R-R2 retain-and-check) ----
APPLE_RS=(
  src/platform/macos.rs
  src/privacy_mode/macos.rs
  src/whiteboard/macos.rs
  libs/hbb_common/src/platform/macos.rs
  libs/enigo/src/macos/macos_impl.rs
)
APPLE_OTHER=(
  src/platform/macos.mm
  flutter/ios/Runner/AppDelegate.swift
  flutter/ios/Runner/Info.plist
  flutter/ios/Runner/Runner.entitlements
  flutter/ios/Podfile.lock
  flutter/ios/Runner.xcodeproj/project.pbxproj
  flutter/macos/Runner/Info.plist
  flutter/macos/Runner/Release.entitlements
  flutter/macos/Runner/DebugProfile.entitlements
  flutter/macos/Podfile.lock
  flutter/macos/Runner.xcodeproj/project.pbxproj
)
GREP_SRC=("${APPLE_RS[@]/#/$REPO/}" "$REPO/src/platform/macos.mm")

echo "== (1) retain-and-check: hardened Apple sources and metadata must be present (R-R2/R-A6) =="
for f in "${APPLE_RS[@]}" "${APPLE_OTHER[@]}"; do
  [ -e "$REPO/$f" ] || {
    echo "  MISSING $f - R-R2 is retain-and-check; deleting Apple source drops hardening a future Apple build must inherit"
    rc=1
  }
done
[ "$rc" = 0 ] && note "ok  all ${#APPLE_RS[@]} Rust + ${#APPLE_OTHER[@]} metadata/source files present"

echo "== (2) R-A6 Apple-cfg forbidden-token greps =="
apple_absent(){
  local hits
  hits=$(grep -rnE "$1" "${GREP_SRC[@]}" 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*//' || true)
  if [ -n "$hits" ]; then
    echo "  FAIL $2 - Apple-cfg token present:"
    echo "$hits" | sed 's/^/      /'
    rc=1
  else
    note "ok  $2 - absent on the Apple source"
  fi
}

apple_absent 'fn update_me\b|update_from_dmg|extract_update_dmg|fn update_to\b' \
  'R-X1 macOS DMG self-updater'
apple_absent 'fn elevate\b|bool Elevate\b|AuthorizationExecuteWithPrivileges' \
  'R-X9/X11 in-process root-exec (osascript elevate / Authorization Elevate)'
apple_absent 'libpam|pam_authenticate|\bpam::' \
  'R-X14 PAM (absent-by-construction on Apple)'

echo "== (2b) R-X12/R-X13 macOS sole-backend assertions =="
if grep -qE 'pub mod quartz' "$REPO/libs/scrap/src/lib.rs"; then
  note "ok  R-X12 macOS capture = quartz/CGDisplayStream present (sole backend)"
else
  echo "  FAIL R-X12: macOS quartz capture backend is missing from libs/scrap/src/lib.rs"
  rc=1
fi
if grep -qE 'CGEventPost' "$REPO/libs/enigo/src/macos/macos_impl.rs"; then
  note "ok  R-X13 macOS input = CGEvent present (sole injector)"
else
  echo "  FAIL R-X13: macOS CGEvent injector is missing from libs/enigo/src/macos/macos_impl.rs"
  rc=1
fi

echo "== (2b-i) R-S11b-1 macOS _service has no whole-config bus =="
r_s11b=
grep -q 'pub(crate) fn service_channel_admits_message' "$REPO/src/ipc.rs" || r_s11b="$r_s11b no-service-message-gate"
grep -q 'Data::Test => true' "$REPO/src/ipc.rs" || r_s11b="$r_s11b service-gate-misses-test"
grep -q 'Data::BeginMacosServiceOwnedUnattendedPasswordChange' "$REPO/src/ipc.rs" || r_s11b="$r_s11b macos-service-password-begin-not-typed"
grep -q 'Data::FinishMacosServiceOwnedUnattendedPasswordChange { .. } => true' "$REPO/src/ipc.rs" || r_s11b="$r_s11b macos-service-password-finish-not-typed"
service_dispatch_block=$(awk '/service_channel_admits_message\(&data\)/,/continue;/' "$REPO/src/ipc.rs")
echo "$service_dispatch_block" | grep -q 'service_channel_admits_message(&data)' || r_s11b="$r_s11b service-loop-not-wired"
if echo "$service_dispatch_block" | grep -q 'Data::SyncConfig'; then
  r_s11b="$r_s11b service-loop-still-admits-syncconfig"
fi
if grep -q 'SyncConfig' "$REPO/src/ipc.rs"; then
  r_s11b="$r_s11b whole-config-ipc-variant-present"
fi
if awk '/^async fn handle\(/,/^}/' "$REPO/src/ipc.rs" | grep -qE 'Data::SyncConfig\(Some\([^)]*\)\)[[:space:]]*=>'; then
  r_s11b="$r_s11b whole-config-write-handler-present"
fi
if grep -q 'SyncConfig' "$REPO/src/server.rs"; then
  r_s11b="$r_s11b server-whole-config-import-present"
fi
if awk '/probe_existing_listener/,/^}/' "$REPO/src/ipc/fs.rs" | grep -q 'Data::SyncConfig'; then
  r_s11b="$r_s11b service-probe-reads-config"
fi
grep -q 'stream.send(&Data::Test)' "$REPO/src/ipc/fs.rs" || r_s11b="$r_s11b service-probe-not-test-ping"
if grep -q 'connect_service' "$REPO/src/server.rs"; then
  r_s11b="$r_s11b server-still-connects-service-channel"
fi
if grep -qE 'wait_initial_config_sync|sync_and_watch_config_dir|CONFIG_SYNC_(INTERVAL|INITIAL)' "$REPO/src/server.rs"; then
  r_s11b="$r_s11b service-config-sync-loop-present"
fi
if [ -n "$r_s11b" ]; then
  echo "  FAIL R-S11b-1 macOS _service whole-config bus removal:$r_s11b"
  rc=1
else
  note "ok  R-S11b-1/R-S11c-1f macOS _service admits liveness plus typed service-owned password begin/finish requests; whole-config IPC and imports are absent"
fi

echo "== (2b-ii) R-S11b-2a/R-S11b-3a macOS service-owned password/options are not ordinary IPC =="
r_s11b2=
grep -q -- '<string>--service-owned-server</string>' "$REPO/src/platform/privileges_scripts/agent.plist" || r_s11b2="$r_s11b2 agent-server-not-marked"
grep -q 'MainIpcAuthority::ServiceOwned' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 service-owned-authority-missing"
grep -q 'Data::SetUserOwnedPermanentPassword(_) => {' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 typed-password-arm-missing"
grep -A3 'Data::SetUserOwnedPermanentPassword(_) => {' "$REPO/src/ipc.rs" | grep -q 'authority.allows_main_channel_user_owned_password_write()' || r_s11b2="$r_s11b2 typed-password-write-not-authority-gated"
grep -q 'Data::SetUserOwnedPermanentPasswordResult(false)' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 typed-password-reject-nack-missing"
grep -q 'BeginMacosServiceOwnedUnattendedPasswordChange' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-begin-missing"
grep -q 'MacosServiceOwnedUnattendedPasswordChallenge {' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-challenge-missing"
grep -q 'FinishMacosServiceOwnedUnattendedPasswordChange {' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-finish-missing"
main_channel_mutation_policy=$(awk '/pub\(crate\) fn main_channel_admits_state_mutation/,/^}/' "$REPO/src/ipc.rs")
echo "$main_channel_mutation_policy" | grep -q 'Data::BeginMacosServiceOwnedUnattendedPasswordChange' || r_s11b2="$r_s11b2 macos-service-password-begin-not-denied-on-main"
echo "$main_channel_mutation_policy" | grep -q 'Data::MacosServiceOwnedUnattendedPasswordChallenge { .. }' || r_s11b2="$r_s11b2 macos-service-password-challenge-not-denied-on-main"
echo "$main_channel_mutation_policy" | grep -q 'Data::FinishMacosServiceOwnedUnattendedPasswordChange { .. } => false' || r_s11b2="$r_s11b2 macos-service-password-finish-not-denied-on-main"
grep -q 'Data::CommitServiceOwnedUnattendedPasswordChange(_) => {' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-commit-missing"
grep -A5 'Data::CommitServiceOwnedUnattendedPasswordChange(_) => {' "$REPO/src/ipc.rs" | grep -q 'peer_authority.allows_service_owned_unattended_password_commit()' || r_s11b2="$r_s11b2 macos-service-password-commit-not-root-peer-gated"
grep -q 'MACOS_SERVICE_OWNED_PASSWORD_PENDING' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-pending-map-missing"
grep -q 'MACOS_SERVICE_OWNED_PASSWORD_MAX_PENDING' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-pending-cap-missing"
grep -q 'macos_store_service_owned_password_request' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-begin-store-missing"
grep -q 'macos_take_service_owned_password_request' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-finish-consume-missing"
grep -q 'peer_pid()' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-peer-pid-missing"
grep -q 'peer_uid()' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-peer-uid-missing"
grep -q 'macos_service_owned_unattended_password_digest' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-request-digest-missing"
grep -q 'MACOS_SERVICE_OWNED_PASSWORD_REQUEST_CONTEXT' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-digest-context-missing"
grep -q 'service_owned_unattended_password_authorization(&password_digest)' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-ui-auth-not-digest-bound"
grep -q 'macos_service_owned_password_authorization_right_is_ready' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-right-readiness-gate-missing"
grep -q 'MacEnsureServiceOwnedUnattendedPasswordAuthorizationRight' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-setup-missing"
grep -q 'AuthorizationRightSet(NULL' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-set-missing"
grep -q 'AuthorizationRightGet(RustDeskSetUnattendedPasswordRight()' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-existence-check-missing"
grep -q 'CFSTR("shared")' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-shared-key-missing"
grep -q 'kCFBooleanFalse' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-not-nonshared"
grep -q 'CFSTR("timeout")' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-timeout-key-missing"
grep -q 'const int32_t timeout = 0' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-timeout-not-zero"
grep -q 'CFSTR("group")' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-group-key-missing"
grep -q 'CFSTR("admin")' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-admin-group-missing"
grep -q 'MacCreateAdminAuthorizationExternalFormForRequest' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-auth-create-missing"
grep -q 'AuthorizationMakeExternalForm' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-externalize-missing"
grep -q 'MacVerifyAdminAuthorizationExternalFormForRequest' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-auth-verify-missing"
grep -q 'AuthorizationCreateFromExternalForm' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-internalize-missing"
grep -q 'kAuthorizationFlagDefaults, NULL' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-daemon-verification-may-interact"
grep -q 'RustDeskSetUnattendedPasswordRight' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-custom-right-missing"
grep -q 'com.carriez.RustDesk.set-unattended-password' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-right-name-missing"
grep -q 'RequestDigestIsValid' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-digest-validation-missing"
grep -q 'kAuthorizationEnvironmentPrompt' "$REPO/src/platform/macos.mm" || r_s11b2="$r_s11b2 macos-service-password-digest-prompt-missing"
grep -q 'request_digest: \&\[u8\]' "$REPO/src/platform/macos.rs" || r_s11b2="$r_s11b2 macos-service-password-rust-api-not-digest-bound"
grep -q 'ensure_service_owned_unattended_password_authorization_right' "$REPO/src/platform/macos.rs" || r_s11b2="$r_s11b2 macos-service-password-rust-right-setup-missing"
grep -q 'MacCreateAdminAuthorizationExternalFormForRequest' "$REPO/src/platform/macos.rs" || r_s11b2="$r_s11b2 macos-service-password-rust-auth-create-missing"
grep -q 'MacVerifyAdminAuthorizationExternalFormForRequest' "$REPO/src/platform/macos.rs" || r_s11b2="$r_s11b2 macos-service-password-rust-auth-verify-missing"
grep -q 'handle_macos_service_owned_unattended_password_begin' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-begin-handler-missing"
grep -q 'handle_macos_service_owned_unattended_password_finish' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-finish-handler-missing"
grep -q 'crate::platform::is_installed() && crate::platform::is_installed_daemon(false)' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-install-state-gate-missing"
grep -q 'Self::RootUnixPeer => true' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 macos-service-password-commit-not-root-gated"
macos_auth_create_block=$(awk '/MacCreateAdminAuthorizationExternalFormForRequest/,/^}/' "$REPO/src/platform/macos.mm")
macos_auth_verify_block=$(awk '/MacVerifyAdminAuthorizationExternalFormForRequest/,/^}/' "$REPO/src/platform/macos.mm")
if echo "$macos_auth_create_block$macos_auth_verify_block" | grep -q 'kAuthorizationRightExecute'; then
  r_s11b2="$r_s11b2 macos-service-password-uses-generic-execute-right"
fi
if echo "$macos_auth_verify_block" | grep -q 'kAuthorizationFlagInteractionAllowed'; then
  r_s11b2="$r_s11b2 macos-service-password-daemon-verification-can-interact"
fi
if grep -q 'RequestMacosServiceOwnedUnattendedPasswordChange' "$REPO/src/ipc.rs"; then
  r_s11b2="$r_s11b2 macos-service-password-old-single-message-request-present"
fi
if grep -q 'extern "C" bool MacCreateAdminAuthorizationExternalForm(' "$REPO/src/platform/macos.mm"; then
  r_s11b2="$r_s11b2 macos-service-password-old-auth-create-present"
fi
if grep -q 'extern "C" bool MacVerifyAdminAuthorizationExternalForm(' "$REPO/src/platform/macos.mm"; then
  r_s11b2="$r_s11b2 macos-service-password-old-auth-verify-present"
fi
grep -q '"permanent-password" => authority.allows_main_channel_user_owned_password_write()' "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 password-still-generic-config-key"
grep -q '"permanent-password" => authority.allows_main_channel_password_write()' "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 password-still-generic-config-key"
grep -q 'Data::Config((' "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 generic-config-write-shape-present"
grep -q 'send_config(' "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 generic-send-config-present"
grep -q 'Socks(Option' "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 socks-ipc-variant-present"
grep -q 'Data::Socks' "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 socks-ipc-reference-present"
grep -q 'Data::Options(Some(_)) => authority.allows_main_channel_options_write()' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 options-write-not-authority-gated"
grep -q 'Rejected options write over ordinary IPC for service-owned server' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 options-write-not-denied"
grep -qF '(OPTION_KEY, "")' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 trust-anchor-option-not-pinned-empty"
grep -qF '(OPTION_PROXY_USERNAME, "")' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 proxy-username-not-pinned-empty"
grep -qF '(OPTION_PROXY_PASSWORD, "")' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 proxy-password-not-pinned-empty"
if rg -n 'RemoveTrustedDevices|ClearTrustedDevices|main(Get|Remove|Clear)TrustedDevices|add_trusted_device|set_key_confirmed\(' "$REPO/src" "$REPO/libs" --glob '*.rs' >/tmp/r_s11b3_apple_trust_writers.$$; then
  r_s11b2="$r_s11b2 trusted-device-or-key-confirmation-writer-present:$(tr '\n' ';' </tmp/r_s11b3_apple_trust_writers.$$)"
fi
grep -q 'OptionsSetResult(bool)' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 options-typed-result-missing"
grep -q 'Data::OptionsSetResult(false)' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 options-reject-nack-missing"
grep -q 'Options write requires daemon ACK' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 local-fallback-not-blocked"
set_options_fn=$(awk '/pub async fn set_options/,/^}/' "$REPO/src/ipc.rs")
if echo "$set_options_fn" | grep -q 'crate::platform::is_installed'; then
  r_s11b2="$r_s11b2 options-fallback-uses-install-heuristic"
fi
if [ "$(echo "$set_options_fn" | grep -c 'Config::set_options(value)')" -ne 1 ]; then
  r_s11b2="$r_s11b2 options-caller-persistence-not-ack-only"
fi
grep -q 'SyncConfig' "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 whole-config-ipc-variant-present"
grep -q 'SyncConfig' "$REPO/src/server.rs" && r_s11b2="$r_s11b2 server-whole-config-import-present"
grep -q 'Rejected permanent password storage sync from service-owned server' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 storage-sync-not-denied"
grep -q 'Rejected permanent password salt sync from service-owned server' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 standalone-salt-sync-not-denied"
rm -f /tmp/r_s11b3_apple_trust_writers.$$
if [ -n "$r_s11b2" ]; then
  echo "  FAIL R-S11b-2a/R-S11b-3a macOS service-owned IPC closure:$r_s11b2"
  rc=1
else
  note "ok  R-S11b-2/R-S11b-3a LaunchAgent marks service-owned --server; ordinary password config writes are absent; typed user-owned password/options writes are denied by source policy; trust-anchor/proxy credential option keys are pinned empty; trusted-device/key-confirmation writers are absent; macOS service-owned password provisioning uses one-shot peer-bound requests, a nonshared timeout-zero custom Authorization Services right, request-digest confirmation, noninteractive external-form verification, and root-service commit; whole-config IPC is absent; storage/salt sync is denied"
fi

echo "== (2b-iii) R-S11c-4a macOS CM pre-login filesystem IPC rejected =="
r_s11c4=
grep -q 'struct CmFileAuthority' "$REPO/src/ui_cm_interface.rs" || r_s11c4="$r_s11c4 no-cm-file-authority-type"
grep -q 'file_authority: CmFileAuthority' "$REPO/src/ui_cm_interface.rs" || r_s11c4="$r_s11c4 desktop-runner-has-no-authority-state"
grep -q 'let file_authority = CmFileAuthority::from_login' "$REPO/src/ui_cm_interface.rs" || r_s11c4="$r_s11c4 desktop-login-does-not-derive-authority"
grep -q 'authorize_cm_ipc_connection(&stream)' "$REPO/src/ui_cm_interface.rs" || r_s11c4="$r_s11c4 desktop-cm-peer-auth-not-wired"
grep -q 'AuthorizedFS {' "$REPO/src/ipc.rs" || r_s11c4="$r_s11c4 authorized-fs-variant-missing"
grep -q 'ValidateCmConnection {' "$REPO/src/ipc.rs" || r_s11c4="$r_s11c4 cm-validation-message-missing"
grep -q 'pub(crate) async fn validate_cm_connection_authority' "$REPO/src/ipc.rs" || r_s11c4="$r_s11c4 cm-validation-client-helper-missing"
grep -q 'conn.cm_auth_token == cm_auth_token' "$REPO/src/server/connection.rs" || r_s11c4="$r_s11c4 cm-validation-not-bound-to-server-token"
grep -q 'conn_type.allows_file_authority()' "$REPO/src/server/connection.rs" || r_s11c4="$r_s11c4 cm-validation-not-bound-to-conn-type"
grep -q 'Rejected CM login without matching authorized server connection' "$REPO/src/ui_cm_interface.rs" || r_s11c4="$r_s11c4 desktop-invalid-login-reject-log-missing"
grep -q 'Rejected CM AuthorizedFS without matching authorized file-capable login' "$REPO/src/ui_cm_interface.rs" || r_s11c4="$r_s11c4 desktop-authorizedfs-reject-log-missing"
grep -q 'Rejected unauthenticated CM Data::FS on desktop IPC' "$REPO/src/ui_cm_interface.rs" || r_s11c4="$r_s11c4 desktop-plain-fs-reject-log-missing"
desktop_cm_login_block=$(awk '/Data::Login{id/,/self.cm.add_connection/' "$REPO/src/ui_cm_interface.rs")
desktop_validate_line=$(echo "$desktop_cm_login_block" | grep -n 'validate_cm_connection_authority' | head -1 | cut -d: -f1 || true)
desktop_add_line=$(echo "$desktop_cm_login_block" | grep -n 'self.cm.add_connection' | head -1 | cut -d: -f1 || true)
if [ -z "$desktop_validate_line" ] || [ -z "$desktop_add_line" ] || [ "$desktop_validate_line" -ge "$desktop_add_line" ]; then
  r_s11c4="$r_s11c4 desktop-login-validation-not-before-add_connection"
fi
desktop_cm_fs_block=$(awk '/Data::AuthorizedFS/,/Data::FS\(_\)/' "$REPO/src/ui_cm_interface.rs")
desktop_gate_line=$(echo "$desktop_cm_fs_block" | grep -n 'if !self.file_authority.allows_fs(cm_auth_token == self.cm_auth_token)' | head -1 | cut -d: -f1 || true)
desktop_handle_line=$(echo "$desktop_cm_fs_block" | grep -n 'handle_fs' | head -1 | cut -d: -f1 || true)
if [ -z "$desktop_gate_line" ] || [ -z "$desktop_handle_line" ] || [ "$desktop_gate_line" -ge "$desktop_handle_line" ]; then
  r_s11c4="$r_s11c4 desktop-fs-gate-not-before-handle_fs"
fi
if [ -n "$r_s11c4" ]; then
  echo "  FAIL R-S11c-4a macOS CM pre-login file IPC closure:$r_s11c4"
  rc=1
else
  note "ok  R-S11c-4a macOS CM rejects forged desktop login/plain FS unless the main server validates the active connection id/type/token"
fi

echo "== (2b-iii-b) R-S11c-11 macOS CM endpoint-selection proof =="
r_s11c11=
grep -q 'CmEndpointChallenge {' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-endpoint-challenge"
grep -q 'CmEndpointProof {' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-endpoint-proof"
grep -q 'CmServerChallenge {' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-server-challenge"
grep -q 'CmServerProof {' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-server-proof"
grep -q 'hmacsha256::authenticate' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-hmac-proof"
grep -q 'hmacsha256::verify' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-hmac-verify"
grep -q 'CM_SERVER_PROOF_CONTEXT' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-directional-server-proof-context"
grep -q 'verify_cm_server_proof' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-server-proof-verify"
grep -q 'authenticate_cm_endpoint_launch_proof(&mut stream, cm_launch_token()).await' "$REPO/src/server/connection.rs" || r_s11c11="$r_s11c11 server-does-not-authenticate-cm-launch-proof"
grep -q 'answer_cm_endpoint_challenge(&mut stream).await' "$REPO/src/ui_cm_interface.rs" || r_s11c11="$r_s11c11 cm-listener-does-not-answer-launch-proof"
grep -q 'authenticate_macos_cm_endpoint(&stream, expected_arg)' "$REPO/src/server/connection.rs" || r_s11c11="$r_s11c11 macos-cm-process-shape-not-checked"
grep -q 'pub(crate) fn authenticate_macos_cm_endpoint' "$REPO/src/ipc/auth.rs" || r_s11c11="$r_s11c11 macos-cm-auth-helper-missing"
grep -q 'peer_process_is_current_exe_with_first_arg(peer_pid, "--server")' "$REPO/src/ipc/auth.rs" || r_s11c11="$r_s11c11 cm-listener-peer-not-server-arg-bound"
grep -q 'run_as_user_with_env(args.clone(), cm_launch_env())' "$REPO/src/server/connection.rs" || r_s11c11="$r_s11c11 macos-run-as-user-token-env-not-wired"
grep -q 'pub fn run_as_user_with_env' "$REPO/src/platform/macos.rs" || r_s11c11="$r_s11c11 macos-token-env-launcher-missing"
cm_listener_auth_block=$(awk '/authorize_cm_ipc_connection\(&stream\)/,/tokio::spawn/' "$REPO/src/ui_cm_interface.rs")
cm_listener_proof_line=$(echo "$cm_listener_auth_block" | grep -n 'answer_cm_endpoint_challenge(&mut stream).await' | head -1 | cut -d: -f1 || true)
cm_listener_spawn_line=$(echo "$cm_listener_auth_block" | grep -n 'tokio::spawn' | head -1 | cut -d: -f1 || true)
if [ -z "$cm_listener_proof_line" ] || [ -z "$cm_listener_spawn_line" ] || [ "$cm_listener_proof_line" -ge "$cm_listener_spawn_line" ]; then
  r_s11c11="$r_s11c11 cm-listener-proof-not-before-normal-ipc-loop"
fi
answer_fn_line=$(grep -n 'pub(crate) async fn answer_cm_endpoint_challenge' "$REPO/src/ipc.rs" | head -1 | cut -d: -f1 || true)
cm_server_challenge_line=$(awk -v start="$answer_fn_line" 'NR > start && /Data::CmServerChallenge/ { print NR; exit }' "$REPO/src/ipc.rs")
cm_server_verify_line=$(awk -v start="$answer_fn_line" 'NR > start && /verify_cm_server_proof/ { print NR; exit }' "$REPO/src/ipc.rs")
cm_endpoint_challenge_line=$(awk -v start="$answer_fn_line" 'NR > start && /Data::CmEndpointChallenge/ { print NR; exit }' "$REPO/src/ipc.rs")
if [ -z "$answer_fn_line" ] || [ -z "$cm_server_challenge_line" ] || [ -z "$cm_server_verify_line" ] || [ -z "$cm_endpoint_challenge_line" ] || [ "$cm_server_challenge_line" -ge "$cm_server_verify_line" ] || [ "$cm_server_verify_line" -ge "$cm_endpoint_challenge_line" ]; then
  r_s11c11="$r_s11c11 cm-listener-server-proof-not-before-endpoint-proof"
fi
server_auth_fn_line=$(grep -n 'pub(crate) async fn authenticate_cm_endpoint_launch_proof' "$REPO/src/ipc.rs" | head -1 | cut -d: -f1 || true)
server_proof_send_line=$(awk -v start="$server_auth_fn_line" 'NR > start && /Data::CmServerProof/ { print NR; exit }' "$REPO/src/ipc.rs")
server_endpoint_challenge_line=$(awk -v start="$server_auth_fn_line" 'NR > start && /Data::CmEndpointChallenge/ { print NR; exit }' "$REPO/src/ipc.rs")
if [ -z "$server_auth_fn_line" ] || [ -z "$server_proof_send_line" ] || [ -z "$server_endpoint_challenge_line" ] || [ "$server_proof_send_line" -ge "$server_endpoint_challenge_line" ]; then
  r_s11c11="$r_s11c11 server-peer-proof-not-before-endpoint-challenge"
fi
macos_process_line=$(grep -n 'authenticate_macos_cm_endpoint(&stream, expected_arg)' "$REPO/src/server/connection.rs" | head -1 | cut -d: -f1 || true)
macos_proof_line=$(awk -v start="$macos_process_line" 'NR > start && /authenticate_cm_endpoint_launch_proof\(&mut stream, cm_launch_token\(\)\)\.await/ { print NR; exit }' "$REPO/src/server/connection.rs")
if [ -z "$macos_process_line" ] || [ -z "$macos_proof_line" ] || [ "$macos_process_line" -ge "$macos_proof_line" ]; then
  r_s11c11="$r_s11c11 macos-cm-proof-not-after-process-shape-check"
fi
for line in $(grep -n 'crate::ipc::connect(1000, "_cm")' "$REPO/src/server/connection.rs" | cut -d: -f1); do
  if ! sed -n "$((line-3)),$((line-1))p" "$REPO/src/server/connection.rs" | grep -q '#\[cfg(not(any(target_os = "linux", target_os = "macos")))\]'; then
    r_s11c11="$r_s11c11 raw-macos-cm-connect-reintroduced"
    break
  fi
done
if [ -n "$r_s11c11" ]; then
  echo "  FAIL R-S11c-11 macOS CM endpoint-selection proof:$r_s11c11"
  rc=1
else
  note "ok  R-S11c-11 macOS CM endpoint selection requires launch-bound proof before token-bearing CM login"
fi

echo "== (2b-iii-c) R-S11c-8 macOS whiteboard helper authority =="
r_s11c8=
grep -q 'WhiteboardEndpointChallenge {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 no-whiteboard-endpoint-challenge"
grep -q 'WhiteboardEndpointProof {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 no-whiteboard-endpoint-proof"
grep -q 'WhiteboardServerChallenge {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 no-whiteboard-server-challenge"
grep -q 'WhiteboardServerProof {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 no-whiteboard-server-proof"
grep -q 'WhiteboardBind {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 no-whiteboard-bind-message"
grep -q 'WhiteboardEvent {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 no-whiteboard-event-message"
grep -q 'WhiteboardClose {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 no-whiteboard-close-message"
grep -q 'WhiteboardShutdown' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 no-whiteboard-shutdown-message"
grep -q 'WHITEBOARD_LAUNCH_TOKEN_ENV' "$REPO/src/common.rs" || r_s11c8="$r_s11c8 no-whiteboard-launch-token-env"
grep -q 'WHITEBOARD_LAUNCH_PARENT_ENV' "$REPO/src/common.rs" || r_s11c8="$r_s11c8 no-whiteboard-launch-parent-env"
grep -q 'whiteboard_endpoint_postfix(&launch_token)' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 client-does-not-use-launch-scoped-endpoint"
grep -q 'authenticate_whiteboard_endpoint_launch_proof(&mut stream, launch_token)' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 client-does-not-authenticate-whiteboard-endpoint"
grep -q 'authorize_whiteboard_ipc_connection(&stream, expected_parent_pid)' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-does-not-check-parent-pid"
grep -q 'answer_whiteboard_endpoint_challenge(&mut stream).await' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-does-not-prove-launch-token"
grep -q 'WhiteboardIpcState' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-state-machine-missing"
grep -q 'super::client::get_key_cursor(conn_id)' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-does-not-derive-render-key"
grep -q 'register_whiteboard(self.inner.id)' "$REPO/src/server/connection.rs" || r_s11c8="$r_s11c8 connection-register-not-id-based"
whiteboard_register_context=$(grep -B4 -A2 'register_whiteboard(self.inner.id)' "$REPO/src/server/connection.rs" || true)
echo "$whiteboard_register_context" | grep -q 'if self.is_authed_remote_conn()' || r_s11c8="$r_s11c8 register-not-remote-auth-type-gated"
grep -q 'run_as_user_with_env(' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 macos-whiteboard-launch-env-not-wired"
grep -q 'pub fn run_as_user_with_env' "$REPO/src/platform/macos.rs" || r_s11c8="$r_s11c8 macos-env-launcher-missing"
if grep -RIn 'Whiteboard((String' "$REPO/src/ipc.rs" "$REPO/src/whiteboard" 2>/dev/null >/tmp/rd_apple_whiteboard_tuple.$$; then
  r_s11c8="$r_s11c8 legacy-whiteboard-tuple-message-present"
fi
if grep -RIn 'Data::Whiteboard((' "$REPO/src/whiteboard" "$REPO/src/server" 2>/dev/null >/tmp/rd_apple_whiteboard_tuple_send.$$; then
  r_s11c8="$r_s11c8 legacy-whiteboard-tuple-send-present"
fi
if grep -q 'ipc::connect(1000, "_whiteboard")' "$REPO/src/whiteboard/client.rs"; then
  r_s11c8="$r_s11c8 raw-fixed-whiteboard-connect-present"
fi
if grep -q 'new_listener("_whiteboard")' "$REPO/src/whiteboard/server.rs"; then
  r_s11c8="$r_s11c8 fixed-whiteboard-listener-present"
fi
if grep -q 'send_event(("".to_string(), CustomEvent::Exit))' "$REPO/src/whiteboard/server.rs"; then
  r_s11c8="$r_s11c8 unconditional-whiteboard-global-exit-present"
fi
if [ -n "$r_s11c8" ]; then
  echo "  FAIL R-S11c-8 macOS whiteboard helper authority:$r_s11c8"
  rc=1
else
  note "ok  R-S11c-8 macOS whiteboard helper uses launch-scoped endpoint proof, parent-pid admission, and per-connection event tokens"
fi
rm -f /tmp/rd_apple_whiteboard_tuple.$$ /tmp/rd_apple_whiteboard_tuple_send.$$

echo "== (2b-iv) R-S11c-5 macOS privileged-service packaging =="
r_s11c5=
daemon_plist="$REPO/src/platform/privileges_scripts/daemon.plist"
install_scpt="$REPO/src/platform/privileges_scripts/install.scpt"
update_scpt="$REPO/src/platform/privileges_scripts/update.scpt"
uninstall_scpt="$REPO/src/platform/privileges_scripts/uninstall.scpt"
macos_rs="$REPO/src/platform/macos.rs"
macos_helper_command_sources=("$REPO/src/platform/macos.rs" "$REPO/src/ipc.rs")
daemon_args_block=$(awk '/<key>ProgramArguments<\/key>/,/<\/array>/' "$daemon_plist")
echo "$daemon_args_block" | grep -q '<string>/Applications/RustDesk.app/Contents/MacOS/service</string>' || r_s11c5="$r_s11c5 daemon-not-direct-service-exec"
if echo "$daemon_args_block" | grep -qE '<string>/(bin|usr/bin)/(sh|bash)</string>|<string>-c</string>'; then
  r_s11c5="$r_s11c5 daemon-shell-launch"
fi
grep -q '<string>/Library/Logs/RustDesk/rustdesk_service.err</string>' "$daemon_plist" || r_s11c5="$r_s11c5 daemon-stderr-not-library-log"
grep -q '<string>/Library/Logs/RustDesk/rustdesk_service.out</string>' "$daemon_plist" || r_s11c5="$r_s11c5 daemon-stdout-not-library-log"
for command in osascript launchctl open ls ioreg; do
  if grep -F "Command::new(\"$command\")" "${macos_helper_command_sources[@]}" >/dev/null; then
    r_s11c5="$r_s11c5 macos-path-selected-$command"
  fi
done
for system_path in /usr/bin/osascript /bin/launchctl /usr/bin/open /usr/sbin/ioreg; do
  grep -F "\"$system_path\"" "${macos_helper_command_sources[@]}" >/dev/null || r_s11c5="$r_s11c5 macos-absolute-${system_path##*/}-missing"
done
grep -Fq 'const MACOS_OPEN: &str = "/usr/bin/open";' "$REPO/src/ipc.rs" || r_s11c5="$r_s11c5 macos-ipc-open-absolute-missing"
grep -Fq 'Command::new(MACOS_OPEN)' "$REPO/src/ipc.rs" || r_s11c5="$r_s11c5 macos-ipc-reopen-not-absolute"
grep -q 'pub(crate) fn console_owner_uid' "$macos_rs" || r_s11c5="$r_s11c5 macos-console-owner-uid-missing"
grep -Fq 'std::fs::metadata("/dev/console")' "$macos_rs" || r_s11c5="$r_s11c5 macos-console-owner-not-dev-console-backed"
grep -q 'hbb_common::libc::getpwuid_r' "$macos_rs" || r_s11c5="$r_s11c5 macos-active-user-not-passwd-r-backed"
grep -Fq 'bail!("No valid active console uid")' "$macos_rs" || r_s11c5="$r_s11c5 macos-launch-asuser-no-empty-uid-gate"
if grep -q 'fn get_active_user(t: &str)' "$macos_rs" || grep -q 'split_whitespace().nth(2)' "$macos_rs"; then
  r_s11c5="$r_s11c5 macos-active-user-ls-parser-present"
fi
if grep -q '/tmp/rustdesk_service' "$daemon_plist" "$install_scpt" "$update_scpt" "$uninstall_scpt"; then
  r_s11c5="$r_s11c5 tmp-daemon-log-path"
fi
for script in "$install_scpt" "$update_scpt"; do
  script_sh_line=$(grep 'set sh to' "$script")
  grep -q 'set reject_symlinks to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-symlink-reject"
  grep -q 'quoted form of service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-service-exec-symlink-not-checked"
  grep -q 'set verify_app_bundle_tree to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-app-tree-verifier"
  grep -qF '[ ! -d " & quoted form of app_bundle' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-app-bundle-dir-not-required"
  grep -qF '[ ! -f " & quoted form of service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-service-exec-file-not-required"
  grep -qF '[ ! -x " & quoted form of service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-service-exec-executable-not-required"
  grep -Fq '/usr/bin/find " & quoted form of app_bundle & " -type l -print | while IFS= read -r app_link' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-app-tree-symlinks-not-enumerated"
  grep -Fq 'done || exit 1;' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-app-tree-verifier-not-fail-closed"
  grep -Fq '/bin/readlink \"$app_link\"' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-app-symlink-target-not-read"
  grep -Fq 'case \"$app_target\" in " & quoted form of app_bundle & "/*)' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-absolute-symlink-target-not-contained"
  grep -Fq '*../*|../*|*/..|..)' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-relative-symlink-escape-not-rejected"
  grep -q 'set reject_root_pref_symlinks to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-root-pref-symlink-reject-missing"
  grep -q 'quoted form of root_prefs_file' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-root-pref-file-not-named"
  grep -q 'quoted form of root_prefs2_file' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-root-pref2-file-not-named"
  grep -q '/usr/bin/install -d -o root -g wheel -m 0755' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-root-dir-install"
  grep -q 'quoted form of log_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-log-dir"
  grep -q 'quoted form of log_stderr' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-stderr-log-path"
  grep -q 'quoted form of log_stdout' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-stdout-log-path"
  grep -q 'quoted form of support_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-support-dir"
  grep -q 'quoted form of root_prefs_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-root-prefs-dir"
  grep -q '/bin/chmod -N " & quoted form of log_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-dirs-acl-not-cleared"
  grep -q '/bin/rm -f " & quoted form of log_stderr' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-logs-not-recreated"
  grep -q '/bin/chmod -N " & quoted form of log_stderr' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-log-acl-not-cleared"
  grep -q '/usr/sbin/chown -R root:wheel " & quoted form of app_bundle' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-app-not-root-owned"
  grep -q '/bin/chmod -RN " & quoted form of app_bundle' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-app-acl-not-cleared"
  grep -q '/bin/chmod -R u+rwX,go+rX,go-w " & quoted form of app_bundle' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-app-mode-not-locked"
  grep -q '/usr/bin/printf %s " & quoted form of daemon_file' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-daemon-plist-not-printf-written"
  grep -q '/usr/bin/printf %s " & quoted form of agent_file' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-agent-plist-not-printf-written"
  grep -q '/bin/chmod -N " & quoted form of daemon_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-daemon-plist-acl-not-cleared"
  grep -q '/bin/chmod -N " & quoted form of agent_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-agent-plist-acl-not-cleared"
  grep -q '/bin/chmod 0644 " & quoted form of daemon_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-daemon-plist-mode-missing"
  grep -q '/bin/chmod 0644 " & quoted form of agent_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-agent-plist-mode-missing"
  grep -Fq '[ -L \"$user_prefs\" ]' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-source-pref-dir-symlink-not-rejected"
  grep -Fq '[ -L \"$user_prefs/RustDesk.toml\" ]' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-source-pref-symlink-not-rejected"
  grep -Fq 'if [ -L \"$prefs_file\" ]; then exit 1; fi' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-root-pref-file-symlink-not-rejected"
  echo "$script_sh_line" | grep -q 'reject_root_pref_symlinks.*copy_user_prefs' || r_s11c5="$r_s11c5 $(basename "$script")-root-pref-symlink-reject-not-before-copy"
done
grep -q 'verify_app_bundle_tree.*secure_app' "$install_scpt" || r_s11c5="$r_s11c5 install-app-tree-not-verified-before-secure"
grep -Fq '{ " & verify_app_bundle_tree & " } && /usr/sbin/chown -R root:wheel' "$update_scpt" || r_s11c5="$r_s11c5 update-app-tree-not-verified-after-ditto-before-chown"
if grep -qE 'chown -R .*:staff|quoted form of user & ":staff"|/Users/" & user|echo " & quoted form of (daemon|agent)_file' "$install_scpt" "$update_scpt"; then
  r_s11c5="$r_s11c5 user-owned-or-echo-plist-install"
fi
if grep -qE '> " & (daemon|agent)_plist|launchctl unload -w " & daemon_plist|/bin/rm /Library/Launch' "$install_scpt" "$update_scpt" "$uninstall_scpt"; then
  r_s11c5="$r_s11c5 unquoted-privileged-path"
fi
grep -q 'arg(active_user_home)' "$REPO/src/platform/macos.rs" || r_s11c5="$r_s11c5 install-call-does-not-pass-home"
grep -q 'arg(&active_user_home)' "$REPO/src/platform/macos.rs" || r_s11c5="$r_s11c5 update-call-does-not-pass-home"
if [ -n "$r_s11c5" ]; then
  echo "  FAIL R-S11c-5 macOS privileged-service packaging:$r_s11c5"
  rc=1
else
  note "ok  R-S11c-5 LaunchDaemon uses direct argv; local helper launchers use absolute system paths; active-console identity is /dev/console/passwd-backed"
fi

# (2c) Appendix C #2b is an ACCEPTED, documented residual: the fork SHOULD (not MUST) sandbox the decode
# path. Commit 0c54912 deliberately reverted the ENTIRE native-worker decode-sandbox subsystem (the
# per-codec worker processes + the macOS Seatbelt sandbox file + the Android isolatedProcess services
# + ~1800 lines of verify.sh worker gates) as "a documented residual, not a MUST". That revert updated
# verify.sh but missed THIS macOS Seatbelt assertion, leaving apple-conform-check failing on a
# deliberately-absent file. Removed to match: the macOS worker sandbox is intentionally gone (the
# universal #2b residual), so the Apple source carries no worker hardening to retain. (Re-closing #2b
# later restores the subsystem on ALL platforms, not Apple alone — this is not a presence-of-absence pin.)
echo "== (2c) Appendix C #2b native-worker decode sandbox: accepted residual (reverted 0c54912) — no macOS worker hardening to assert =="

echo "== (2d) Apple metadata allow-lists: plist/entitlements/pods/Xcode shell phases =="
docker run --rm -i -v "$REPO:/work:ro" -w /work "$IMG" python3 - <<'PY' || rc=1
from pathlib import Path
import ast
import plistlib
import re
import sys
import xml.etree.ElementTree as ET

FAIL = []

def fail(msg):
    FAIL.append(msg)

def duplicate_plist_keys(path):
    root = ET.fromstring(Path(path).read_bytes())

    def walk(elem, where):
        children = list(elem)
        if elem.tag == "dict":
            seen = set()
            i = 0
            while i < len(children):
                child = children[i]
                if child.tag == "key":
                    key = child.text or ""
                    if key in seen:
                        fail(f"{path}: duplicate plist key {key!r} at {where}")
                    seen.add(key)
                    if i + 1 < len(children):
                        walk(children[i + 1], f"{where}.{key}")
                    i += 2
                else:
                    walk(child, where)
                    i += 1
        else:
            for child in children:
                walk(child, where)

    walk(root, path)

def load_plist(path):
    duplicate_plist_keys(path)
    with open(path, "rb") as fh:
        return plistlib.load(fh)

def assert_keys(path, expected):
    got = load_plist(path)
    actual = set(got.keys())
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        fail(f"{path}: plist key allow-list mismatch; missing={missing} extra={extra}")
    for forbidden in ("com.apple.developer.associated-domains", "associated-domains",
                      "NSUserActivityTypes", "aps-environment",
                      "com.apple.developer.networking.wifi-info"):
        if forbidden in actual:
            fail(f"{path}: forbidden Apple capability/deep-link key present: {forbidden}")
    return got

IOS_INFO_KEYS = {
    "CADisableMinimumFrameDurationOnPhone",
    "CFBundleDevelopmentRegion",
    "CFBundleDisplayName",
    "CFBundleExecutable",
    "CFBundleIdentifier",
    "CFBundleInfoDictionaryVersion",
    "CFBundleName",
    "CFBundlePackageType",
    "CFBundleShortVersionString",
    "CFBundleSignature",
    "CFBundleURLTypes",
    "CFBundleVersion",
    "ITSAppUsesNonExemptEncryption",
    "LSRequiresIPhoneOS",
    # iOS 14+ gates connections to local-network hosts behind this usage string; without it the
    # fork's core direct-IP LAN connect is silently blocked (APPLE-4). Direct-IP only — no Bonjour,
    # so NSBonjourServices stays absent.
    "NSLocalNetworkUsageDescription",
    "UIApplicationSupportsIndirectInputEvents",
    "UILaunchStoryboardName",
    "UIMainStoryboardFile",
    "UISupportedInterfaceOrientations",
    "UISupportedInterfaceOrientations~ipad",
    # UIFileSharingEnabled / UISupportsDocumentBrowser are DROPPED: the iOS config (the connect-
    # equivalent Argon2id PRS, R-P1/R-S9) lives in Documents (getApplicationDocumentsDirectory ->
    # APP_DIR -> Config::path). Dropping them closes the Files-app / iTunes file-sharing BROWSE
    # exposure of that directory. The BACKUP channel — the true analog of Android's allowBackup="false"
    # (R-X6) — is closed separately by the NSURLIsExcludedFromBackupKey exclusion in AppDelegate.swift
    # (asserted by the (2e) check). Absent == disabled.
    "UIViewControllerBasedStatusBarAppearance",
    "io.flutter.embedded_views_preview",
}
MACOS_INFO_KEYS = {
    "CFBundleDevelopmentRegion",
    "CFBundleExecutable",
    "CFBundleIconFile",
    "CFBundleIdentifier",
    "CFBundleInfoDictionaryVersion",
    "CFBundleName",
    "CFBundlePackageType",
    "CFBundleShortVersionString",
    "CFBundleURLTypes",
    "CFBundleVersion",
    "LSMinimumSystemVersion",
    "LSUIElement",
    "NSHumanReadableCopyright",
    "NSMainNibFile",
    "NSMicrophoneUsageDescription",
    "NSPrincipalClass",
}

ios_info = assert_keys("flutter/ios/Runner/Info.plist", IOS_INFO_KEYS)
macos_info = assert_keys("flutter/macos/Runner/Info.plist", MACOS_INFO_KEYS)

def assert_rustdesk_scheme(path, obj):
    url_types = obj.get("CFBundleURLTypes")
    if not isinstance(url_types, list):
        fail(f"{path}: CFBundleURLTypes is not a list")
        return
    schemes = []
    for item in url_types:
        if isinstance(item, dict):
            schemes.extend(item.get("CFBundleURLSchemes", []))
    if schemes != ["rustdesk"]:
        fail(f"{path}: expected the sole URL scheme ['rustdesk'], got {schemes!r}")

assert_rustdesk_scheme("flutter/ios/Runner/Info.plist", ios_info)
assert_rustdesk_scheme("flutter/macos/Runner/Info.plist", macos_info)

if load_plist("flutter/ios/Runner/Runner.entitlements") != {}:
    fail("flutter/ios/Runner/Runner.entitlements: iOS entitlements must remain an empty dict")

EXPECTED_RELEASE_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": False,
    "com.apple.security.cs.allow-jit": True,
    "com.apple.security.device.audio-input": True,
    "com.apple.security.network.client": True,
}
EXPECTED_DEBUG_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": False,
    "com.apple.security.cs.allow-jit": True,
    "com.apple.security.device.audio-input": True,
    "com.apple.security.network.server": True,
}
if load_plist("flutter/macos/Runner/Release.entitlements") != EXPECTED_RELEASE_ENTITLEMENTS:
    fail("flutter/macos/Runner/Release.entitlements: entitlement allow-list/value mismatch")
if load_plist("flutter/macos/Runner/DebugProfile.entitlements") != EXPECTED_DEBUG_ENTITLEMENTS:
    fail("flutter/macos/Runner/DebugProfile.entitlements: entitlement allow-list/value mismatch")

# APPLE_POD_ALLOWLISTS: exact top-level pod + checksum allow-lists for R-SV8/R-A6.
EXPECTED_IOS_PODS = [
    "device_info_plus (0.0.1)",
    "DKImagePickerController/Core (4.3.4)",
    "DKImagePickerController/ImageDataManager (4.3.4)",
    "DKImagePickerController/PhotoGallery (4.3.4)",
    "DKImagePickerController/Resource (4.3.4)",
    "DKPhotoGallery (0.0.17)",
    "DKPhotoGallery/Core (0.0.17)",
    "DKPhotoGallery/Model (0.0.17)",
    "DKPhotoGallery/Preview (0.0.17)",
    "DKPhotoGallery/Resource (0.0.17)",
    "file_picker (0.0.1)",
    "Flutter (1.0.0)",
    "flutter_keyboard_visibility (0.0.1)",
    "image_picker_ios (0.0.1)",
    "MTBBarcodeScanner (5.0.11)",
    "package_info_plus (0.4.5)",
    "path_provider_foundation (0.0.1)",
    "qr_code_scanner (0.2.0)",
    "SDWebImage (5.18.11)",
    "SDWebImage/Core (5.18.11)",
    "sqflite (0.0.3)",
    "SwiftyGif (5.4.4)",
    "uni_links (0.0.1)",
    "url_launcher_ios (0.0.1)",
    "video_player_avfoundation (0.0.1)",
    "wakelock_plus (0.0.1)",
]
EXPECTED_IOS_CHECKSUMS = {
    "device_info_plus": "c6fb39579d0f423935b0c9ce7ee2f44b71b9fce6",
    "DKImagePickerController": "b512c28220a2b8ac7419f21c491fc8534b7601ac",
    "DKPhotoGallery": "fdfad5125a9fdda9cc57df834d49df790dbb4179",
    "file_picker": "ce3938a0df3cc1ef404671531facef740d03f920",
    "Flutter": "e0871f40cf51350855a761d2e70bf5af5b9b5de7",
    "flutter_keyboard_visibility": "0339d06371254c3eb25eeb90ba8d17dca8f9c069",
    "image_picker_ios": "99dfe1854b4fa34d0364e74a78448a0151025425",
    "MTBBarcodeScanner": "f453b33c4b7dfe545d8c6484ed744d55671788cb",
    "package_info_plus": "115f4ad11e0698c8c1c5d8a689390df880f47e85",
    "path_provider_foundation": "3784922295ac71e43754bd15e0653ccfd36a147c",
    "qr_code_scanner": "bb67d64904c3b9658ada8c402e8b4d406d5d796e",
    "SDWebImage": "a3ba0b8faac7228c3c8eadd1a55c9c9fe5e16457",
    "sqflite": "673a0e54cc04b7d6dba8d24fb8095b31c3a99eec",
    "SwiftyGif": "93a1cc87bf3a51916001cf8f3d63835fb64c819f",
    "uni_links": "d97da20c7701486ba192624d99bffaaffcfc298a",
    "url_launcher_ios": "5334b05cef931de560670eeae103fd3e431ac3fe",
    "video_player_avfoundation": "02011213dab73ae3687df27ce441fbbcc82b5579",
    "wakelock_plus": "8b09852c8876491e4b6d179e17dfe2a0b5f60d47",
}
EXPECTED_MACOS_PODS = [
    "desktop_drop (0.0.1)",
    "desktop_multi_window (0.0.1)",
    "device_info_plus (0.0.1)",
    "file_selector_macos (0.0.1)",
    "flutter_custom_cursor (0.0.1)",
    "FlutterMacOS (1.0.0)",
    "FMDB (2.7.12)",
    "FMDB/Core (2.7.12)",
    "FMDB/standard (2.7.12)",
    "package_info_plus (0.0.1)",
    "path_provider_foundation (0.0.1)",
    "screen_retriever (0.0.1)",
    "sqflite (0.0.2)",
    "texture_rgba_renderer (0.0.1)",
    "uni_links_desktop (0.0.1)",
    "url_launcher_macos (0.0.1)",
    "video_player_avfoundation (0.0.1)",
    "wakelock_plus (0.0.1)",
    "window_manager (0.2.0)",
    "window_size (0.0.2)",
]
EXPECTED_MACOS_CHECKSUMS = {
    "desktop_drop": "e0b672a7d84c0a6cbc378595e82cdb15f2970a43",
    "desktop_multi_window": "93667594ccc4b88d91a97972fd3b1b89667fa80a",
    "device_info_plus": "b0fafc687fb901e2af612763340f1b0d4352f8e5",
    "file_selector_macos": "6280b52b459ae6c590af5d78fc35c7267a3c4b31",
    "flutter_custom_cursor": "37e588711a2746f5cf48adb58b582cacff11c0c6",
    "FlutterMacOS": "8f6f14fa908a6fb3fba0cd85dbd81ec4b251fb24",
    "FMDB": "728731dd336af3936ce00f91d9d8495f5718a0e6",
    "package_info_plus": "122abb51244f66eead59ce7c9c200d6b53111779",
    "path_provider_foundation": "080d55be775b7414fd5a5ef3ac137b97b097e564",
    "screen_retriever": "4f97c103641aab8ce183fa5af3b87029df167936",
    "sqflite": "c73556b2499b92f0b6e6946abe4a4084510cdf90",
    "texture_rgba_renderer": "6661f577ea5d4990e964c7e3840e544ac798e6da",
    "uni_links_desktop": "34322c2646e4c9abc69b62e1865f9782d2850ba2",
    "url_launcher_macos": "0fba8ddabfc33ce0a9afe7c5fef5aab3d8d2d673",
    "video_player_avfoundation": "2cef49524dd1f16c5300b9cd6efd9611ce03639b",
    "wakelock_plus": "21ddc249ac4b8d018838dbdabd65c5976c308497",
    "window_manager": "1d01fa7ac65a6e6f83b965471b1a7fdd3f06166c",
    "window_size": "4bd15034e6e3d0720fd77928a7c42e5492cfece9",
}
FORBIDDEN_POD_TOKENS = ("Firebase", "Crashlytics", "Fabric", "Sentry", "AppCenter", "Sparkle")

def parse_podfile(path):
    pods = []
    checksums = {}
    section = None
    for line in Path(path).read_text().splitlines():
        if line and not line.startswith(" "):
            section = line.rstrip(":")
            continue
        if section == "PODS" and line.startswith("  - "):
            pods.append(line[4:].strip().rstrip(":"))
        elif section == "SPEC CHECKSUMS" and line.startswith("  "):
            name, value = line.strip().split(": ", 1)
            checksums[name] = value
    return pods, checksums

def assert_podfile(path, expected_pods, expected_checksums):
    pods, checksums = parse_podfile(path)
    if pods != expected_pods:
        fail(f"{path}: pod allow-list mismatch\n  expected={expected_pods!r}\n  actual={pods!r}")
    if checksums != expected_checksums:
        fail(f"{path}: SPEC CHECKSUMS allow-list mismatch")
    joined = "\n".join(pods + sorted(checksums))
    for token in FORBIDDEN_POD_TOKENS:
        if token in joined:
            fail(f"{path}: forbidden telemetry/updater pod token present: {token}")

assert_podfile("flutter/ios/Podfile.lock", EXPECTED_IOS_PODS, EXPECTED_IOS_CHECKSUMS)
assert_podfile("flutter/macos/Podfile.lock", EXPECTED_MACOS_PODS, EXPECTED_MACOS_CHECKSUMS)

# PBXShellScriptBuildPhase allow-list: exact decoded shellScript values.
COCOAPODS_MANIFEST_SCRIPT = """diff "${PODS_PODFILE_DIR_PATH}/Podfile.lock" "${PODS_ROOT}/Manifest.lock" > /dev/null
if [ $? != 0 ] ; then
    # print error to STDERR
    echo "error: The sandbox is not in sync with the Podfile.lock. Run 'pod install' or update your CocoaPods installation." >&2
    exit 1
fi
# This output is used by Xcode 'outputs' to avoid re-running this script phase.
echo "SUCCESS" > "${SCRIPT_OUTPUT_FILE_0}"
"""
EXPECTED_IOS_SCRIPTS = [
    '/bin/sh "$FLUTTER_ROOT/packages/flutter_tools/bin/xcode_backend.sh" embed_and_thin',
    '"${PODS_ROOT}/Target Support Files/Pods-Runner/Pods-Runner-frameworks.sh"\n',
    COCOAPODS_MANIFEST_SCRIPT,
    '/bin/sh "$FLUTTER_ROOT/packages/flutter_tools/bin/xcode_backend.sh" build',
]
EXPECTED_MACOS_SCRIPTS = [
    'echo "$PRODUCT_NAME.app" > "$PROJECT_DIR"/Flutter/ephemeral/.app_filename && "$FLUTTER_ROOT"/packages/flutter_tools/bin/macos_assemble.sh embed\n',
    '"$FLUTTER_ROOT"/packages/flutter_tools/bin/macos_assemble.sh && touch Flutter/ephemeral/tripwire',
    '"${PODS_ROOT}/Target Support Files/Pods-Runner/Pods-Runner-frameworks.sh"\n',
    COCOAPODS_MANIFEST_SCRIPT,
]
FORBIDDEN_SHELL_TOKENS = ("curl", "codesign", "security", "PlistBuddy", "osascript")

def decode_shell_scripts(path):
    text = Path(path).read_text()
    scripts = []
    for match in re.finditer(r'shellScript = ("(?:\\.|[^"\\])*");', text):
        scripts.append(ast.literal_eval(match.group(1)))
    return scripts

def assert_shell_scripts(path, expected):
    scripts = decode_shell_scripts(path)
    if scripts != expected:
        fail(f"{path}: PBXShellScriptBuildPhase allow-list mismatch\n  expected={expected!r}\n  actual={scripts!r}")
    for script in scripts:
        for token in FORBIDDEN_SHELL_TOKENS:
            if re.search(rf'(^|[^A-Za-z0-9_./-]){re.escape(token)}([^A-Za-z0-9_./-]|$)', script):
                fail(f"{path}: forbidden shell token {token!r} in script {script!r}")

assert_shell_scripts("flutter/ios/Runner.xcodeproj/project.pbxproj", EXPECTED_IOS_SCRIPTS)
assert_shell_scripts("flutter/macos/Runner.xcodeproj/project.pbxproj", EXPECTED_MACOS_SCRIPTS)

if FAIL:
    for item in FAIL:
        print(f"  FAIL {item}")
    sys.exit(1)
print("  ok  metadata allow-lists: plist keys, entitlements, pods, checksums, and Xcode shell phases")
PY

echo "== (2e) R-X6 iOS twin: config-store backup exclusion wired in AppDelegate.swift =="
# The iOS analog of Android's allowBackup="false": the config store (the Documents dir holding the
# per-peer connect-equivalent Argon2id PRS and the machine-UUID wrapper key) must be excluded from
# iCloud/iTunes device backups via NSURLIsExcludedFromBackupKey. This is a source-presence assertion —
# the Swift is not built on this Linux host (no Xcode), like the fork's other Apple source-conformance
# items — so it proves the exclusion stays WIRED, not that it runs.
if grep -q 'isExcludedFromBackup' "$REPO/flutter/ios/Runner/AppDelegate.swift"; then
  note "ok  R-X6 iOS: AppDelegate sets NSURLIsExcludedFromBackupKey on the config store (source-layer; Swift not built here)"
else
  echo "  FAIL R-X6 iOS: AppDelegate.swift no longer excludes the config store from backup (isExcludedFromBackup absent)"
  rc=1
fi

echo "== (3) rustfmt parse-check of Rust Apple sources (SDK-free syntax gate) =="
docker run --rm -i -v "$REPO:/work:ro" -w /work "$IMG" bash -s -- "${APPLE_RS[@]}" <<'SH' || rc=1
set -euo pipefail
rc=0
for f in "$@"; do
  if ! rustfmt --emit stdout --edition 2021 "$f" >/dev/null 2>/tmp/rfe; then
    echo "  PARSE-FAIL $f"
    sed 's/^/      /' /tmp/rfe
    rc=1
  fi
done
[ "$rc" = 0 ] && echo "  ok  all Apple .rs sources parse"
exit "$rc"
SH

echo "== (4) cross-compile coherence matrix (Rust 1.81, actual Apple features) =="
echo "  targets: ${SELECTED_APPLE_TARGETS[*]}"
before_version_hash=$(version_hash)
COMMON_CHECK=( docker run --rm
  -v "$REPO:/work:rw"
  -v rd-cargo-cache:/usr/local/cargo/registry
  -v rd-git-cache:/usr/local/cargo/git
  -v rd-apple-target:/build
  -e CARGO_TARGET_DIR=/build
  -e RUSTUP_TOOLCHAIN=1.81.0
  -e SOURCE_DATE_EPOCH=1700000000
  -e PKG_CONFIG_ALLOW_CROSS=1
  -w /work )

for target in "${SELECTED_APPLE_TARGETS[@]}"; do
  features=$(target_features "$target")
  triplet=$(target_triplet "$target")
  lower_env=$(target_env_lower "$target")
  upper_env=$(target_env_upper "$target")
  log="/tmp/apple-xcheck-$target.log"
  echo "  -- $target features=$features"

  if [ -d "$SDK_DIR" ]; then
    note "online/macos-sdk present ($SDK_DIR) -> real Apple SDK cross-check"
    set +e
    "${COMMON_CHECK[@]}" \
      -v "$SDK_DIR:/apple-sdk:ro" \
      -e SDKROOT=/apple-sdk \
      -e BINDGEN_EXTRA_CLANG_ARGS="-isysroot /apple-sdk" \
      -e "CFLAGS_$lower_env=-isysroot /apple-sdk" \
      "$IMG" bash -s -- "$target" "$features" "$triplet" <<'SH' > "$log" 2>&1
set -euo pipefail
target="$1"; features="$2"; triplet="$3"
stub=/tmp/apple-vcpkg
rm -rf "$stub"
mkdir -p "$stub/installed/$triplet/include" "$stub/installed/$triplet/lib"
for d in opus vpx libyuv aom; do
  [ -d "/usr/include/$d" ] && ln -s "/usr/include/$d" "$stub/installed/$triplet/include/$d"
done
export VCPKG_ROOT="$stub"
cargo +1.81.0 check --target "$target" --features "$features"
SH
    xrc=$?
    set -e
    if [ "$xrc" = 0 ]; then
      note "ok  $target real-SDK cross-check compiled clean"
    else
      echo "  FAIL $target real-SDK cross-check failed:"
      tail -40 "$log" | sed 's/^/      /'
      rc=1
    fi
  else
    note "no online/macos-sdk -> SDK-free best-effort check with scripts/apple-cc-shim.sh"
    set +e
    "${COMMON_CHECK[@]}" \
      -v "$REPO/scripts/apple-cc-shim.sh:/applecc:ro" \
      -e SDKROOT=/tmp \
      -e BINDGEN_EXTRA_CLANG_ARGS="-isysroot /tmp" \
      -e "CC_$lower_env=/applecc" \
      -e "CXX_$lower_env=/applecc" \
      -e "CFLAGS_$lower_env=-isysroot /tmp" \
      -e "CXXFLAGS_$lower_env=-isysroot /tmp" \
      -e "CARGO_TARGET_${upper_env}_LINKER=/applecc" \
      "$IMG" bash -s -- "$target" "$features" "$triplet" <<'SH' > "$log" 2>&1
set -euo pipefail
target="$1"; features="$2"; triplet="$3"
stub=/tmp/apple-vcpkg
rm -rf "$stub"
mkdir -p "$stub/installed/$triplet/include" "$stub/installed/$triplet/lib"
for d in opus vpx libyuv aom; do
  [ -d "/usr/include/$d" ] && ln -s "/usr/include/$d" "$stub/installed/$triplet/include/$d"
done
export VCPKG_ROOT="$stub"
cargo +1.81.0 check --target "$target" --features "$features"
SH
    xrc=$?
    set -e
    if [ "$xrc" = 0 ]; then
      note "ok  $target compiled clean even without Apple SDK headers"
    elif grep -qE 'error\[E[0-9]{4}\]' "$log"; then
      echo "  FAIL $target has a Rust compiler error (real Apple-cfg coherence break):"
      grep -nE 'error\[E[0-9]{4}\]' "$log" | head -25 | sed 's/^/      /'
      rc=1
    elif grep -qE 'Checking rustdesk|Compiling rustdesk|Checking hbb_common|Compiling hbb_common|Checking scrap|Compiling scrap' "$log" \
      && grep -qE "coreaudio-sys|AudioUnit|fatal error: .+ file not found|framework=|inttypes\.h|vpx/vp8\.h" "$log"; then
      note "ok  $target reached the expected Apple SDK/header boundary with no Rust error"
    else
      echo "  FAIL $target failed before the accepted SDK/header boundary:"
      tail -40 "$log" | sed 's/^/      /'
      rc=1
    fi
  fi
done

after_version_hash=$(version_hash)
if [ "$before_version_hash" != "$after_version_hash" ]; then
  echo "  FAIL non-mutating Apple gate: src/version.rs changed during cargo check"
  echo "       before=$before_version_hash after=$after_version_hash"
  rc=1
else
  note "ok  non-mutating source proof: src/version.rs hash unchanged (SOURCE_DATE_EPOCH=1700000000)"
fi

echo
if [ "$rc" = 0 ]; then
  echo "== apple-conform-check PASS =="
else
  echo "== apple-conform-check FAIL =="
fi
exit "$rc"
