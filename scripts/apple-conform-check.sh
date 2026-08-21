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
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

# shellcheck source=scripts/lib.sh
source scripts/lib.sh
load_pins

# shellcheck source=scripts/verify-scan.sh
source scripts/verify-scan.sh
verify_scan_preflight

APPLE_CHECK_TMP=$(umask 077 && mktemp -d /tmp/rustdesk-apple-check.XXXXXXXXXX)
readonly APPLE_CHECK_TMP
readonly APPLE_CHECK_TMP_IDENTITY="$(stat -c '%d:%i' -- "$APPLE_CHECK_TMP")"
readonly APPLE_CHECK_TMP_UID="$(id -u)"
readonly APPLE_CHECK_TMP_GID="$(id -g)"
cleanup_apple_check_tmp() {
  local status=$?
  trap - EXIT HUP INT TERM
  if ! /usr/bin/python3 -I -S "$REPO/scripts/restore-private-directory-modes.py" \
      --root "$APPLE_CHECK_TMP" \
      --expected-identity "$APPLE_CHECK_TMP_IDENTITY" \
      --owner "$APPLE_CHECK_TMP_UID" \
      --group "$APPLE_CHECK_TMP_GID"; then
    echo "apple-conform-check: failed to restore private workspace directory modes: $APPLE_CHECK_TMP" >&2
    status=1
  fi
  if ! rm -rf -- "$APPLE_CHECK_TMP"; then
    echo "apple-conform-check: failed to remove private workspace: $APPLE_CHECK_TMP" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup_apple_check_tmp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if ! python3 - "$APPLE_CHECK_TMP" <<'PY'
import os
import stat
import sys

metadata = os.lstat(sys.argv[1])
if (
    not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != os.geteuid()
    or stat.S_IMODE(metadata.st_mode) != 0o700
):
    raise SystemExit("apple-conform-check: private workspace is not a current-UID mode-0700 directory")
PY
then
  exit 1
fi
verify_scan_self_test "$APPLE_CHECK_TMP"

die(){ echo "FATAL: $*" >&2; exit 1; }
note(){ echo "  $*"; }
rc=0
readonly DOCKER_BIN=/usr/bin/docker
readonly APPLE_DOCKER_HOST=unix:///var/run/docker.sock
readonly APPLE_DOCKER_CONFIG="$APPLE_CHECK_TMP/docker-config"
readonly BUILD_UID="$(id -u)"
readonly BUILD_GID="$(id -g)"
readonly IMG="$APPLE_CHECK_IMAGE_ID"
readonly APPLE_TOOLCHAIN_ROOT=/usr/local/rustup/toolchains/1.81.0-x86_64-unknown-linux-gnu
readonly APPLE_TOOLCHAIN_BIN="$APPLE_TOOLCHAIN_ROOT/bin"
readonly APPLE_CHECK_PATH="$APPLE_TOOLCHAIN_BIN:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly SELECTED_APPLE_TARGETS=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  aarch64-apple-ios
)

verify_apple_docker_authority() {
  [ "$(stat -c '%u:%g:%a:%h' -- "$APPLE_DOCKER_CONFIG")" = "$BUILD_UID:$BUILD_GID:700:2" ] \
    || die "private Docker configuration directory metadata changed"
  [ "$(stat -c '%u:%g:%a:%h' -- "$APPLE_DOCKER_CONFIG/config.json")" = "$BUILD_UID:$BUILD_GID:600:1" ] \
    || die "private Docker configuration file metadata changed"
  [ "$(cat "$APPLE_DOCKER_CONFIG/config.json")" = "{}" ] \
    || die "private Docker configuration bytes changed"
}

apple_docker() {
  local status=0
  verify_apple_docker_authority
  env -i \
    PATH=/usr/bin:/bin \
    HOME="$APPLE_CHECK_TMP" \
    DOCKER_HOST="$APPLE_DOCKER_HOST" \
    DOCKER_CONFIG="$APPLE_DOCKER_CONFIG" \
    "$DOCKER_BIN" \
      --host "$APPLE_DOCKER_HOST" \
      --config "$APPLE_DOCKER_CONFIG" \
      "$@" || status=$?
  verify_apple_docker_authority
  return "$status"
}

apple_image_provenance() {
  local status=0
  verify_apple_docker_authority
  env -i \
    PATH=/usr/bin:/bin \
    HOME="$APPLE_CHECK_TMP" \
    DOCKER_HOST="$APPLE_DOCKER_HOST" \
    DOCKER_CONFIG="$APPLE_DOCKER_CONFIG" \
    /usr/bin/python3 "$REPO/scripts/offline-image-provenance.py" \
      "$@" || status=$?
  verify_apple_docker_authority
  return "$status"
}

archive_current_source() {
  /usr/bin/git -C "$REPO" ls-files -z --cached --others --exclude-standard \
    | /usr/bin/python3 -c '
import os
import sys

root = os.fsencode(sys.argv[1])
for relative in sys.stdin.buffer.read().split(b"\0"):
    if relative and os.path.lexists(os.path.join(root, relative)):
        sys.stdout.buffer.write(relative + b"\0")
' "$REPO" \
    | tar --create --file=- --directory="$REPO" --null --verbatim-files-from \
        --no-recursion --files-from=- --sort=name --format=gnu --mtime='@0' \
        --owner=0 --group=0 --numeric-owner
}

echo "== (0) Apple checker host scratch uses one private workspace (R-S11c-10x) =="
r_s11c10x=
grep -qE '^APPLE_CHECK_TMP=\$\(umask 077 && mktemp -d /tmp/rustdesk-apple-check\.XXXXXXXXXX\)$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x no-private-workspace-create"
grep -qE '^readonly APPLE_CHECK_TMP$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x workspace-not-readonly"
grep -qF 'readonly APPLE_CHECK_TMP_IDENTITY="$(stat -c '\''%d:%i'\'' -- "$APPLE_CHECK_TMP")"' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x workspace-identity-not-retained"
grep -qE '^trap cleanup_apple_check_tmp EXIT$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x no-exit-cleanup"
grep -qE "^trap 'exit 129' HUP$" "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x no-hup-failure"
grep -qE "^trap 'exit 130' INT$" "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x no-int-failure"
grep -qE "^trap 'exit 143' TERM$" "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x no-term-failure"
grep -qE '^[[:space:]]+trap - EXIT HUP INT TERM$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x cleanup-traps-not-disarmed"
grep -qE '^  if ! /usr/bin/python3 -I -S "\$REPO/scripts/restore-private-directory-modes\.py"' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x nofollow-directory-mode-restorer-missing"
grep -qE '^[[:space:]]+--expected-identity "\$APPLE_CHECK_TMP_IDENTITY"' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x cleanup-identity-not-reproved"
grep -qE '^[[:space:]]+if ! rm -rf -- "\$APPLE_CHECK_TMP"; then$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x cleanup-not-fail-closed"
grep -qE '^metadata = os\.lstat\(sys\.argv\[1\]\)$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x nofollow-metadata-proof-missing"
grep -qE '^[[:space:]]+not stat\.S_ISDIR\(metadata\.st_mode\)$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x directory-type-not-enforced"
grep -qE '^[[:space:]]+or metadata\.st_uid != os\.geteuid\(\)$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x owner-not-enforced"
grep -qE '^[[:space:]]+or stat\.S_IMODE\(metadata\.st_mode\) != 0o700$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x mode-not-enforced"
grep -qE '^[[:space:]]+anchor_log="\$APPLE_CHECK_TMP/apple-anchor-\$target\.log"$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x anchor-log-not-private"
grep -qE '^[[:space:]]+log="\$APPLE_CHECK_TMP/apple-xcheck-\$target\.log"$' "$REPO/scripts/apple-conform-check.sh" || r_s11c10x="$r_s11c10x target-log-not-private"
if grep -nE '/tmp/(r_s11b3_apple|r[d]_apple|apple-xcheck-)' "$REPO/scripts/apple-conform-check.sh"; then
  r_s11c10x="$r_s11c10x predictable-host-scratch-name-present"
fi
public_tmp_redirections=$(grep -nE "[0-9]*(>>?|<<?)[[:space:]]*['\"]?/t[m]p/" "$REPO/scripts/apple-conform-check.sh" || true)
if [ -n "$public_tmp_redirections" ]; then
  printf '%s\n' "$public_tmp_redirections"
  r_s11c10x="$r_s11c10x host-public-temp-redirection-present"
fi
grep -qF 'R-S11c-10x — Apple checker private host scratch authority' "$REPO/HARDENING_STATUS.md" || r_s11c10x="$r_s11c10x hardening-ledger-missing"
grep -qF 'Apple checker private host scratch authority' "$REPO/requirements.html" || r_s11c10x="$r_s11c10x requirements-disposition-missing"
if [ -n "$r_s11c10x" ]; then
  echo "  FAIL R-S11c-10x Apple checker private host scratch authority:$r_s11c10x"
  rc=1
else
  note "ok  R-S11c-10x Apple checker host output is confined to one current-UID mode-0700 workspace"
fi

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
apple_sdk_boundary_after_successful_workspace_anchor() {
  awk '
    rust_error_line == 0 &&
      (/^[[:space:]]*error\[[A-Z][0-9]+\]:/ ||
       (/^[[:space:]]*error:/ &&
        $0 !~ /^[[:space:]]*error: failed to run custom build command for `[^`]+`$/)) {
        rust_error_line = NR
      }
    boundary_line == 0 &&
      (/fatal error: .* file not found/ ||
       /fatal error: .*: No such file or directory/ ||
       /ld: framework not found/ ||
       /ld: library not found for/) {
        boundary_line = NR
    }
    END {
      accepted = boundary_line > 0 &&
        (rust_error_line == 0 || rust_error_line > boundary_line)
      exit !accepted
    }
  ' "$1"
}

apple_sdk_boundary_self_test() {
  local fixture="$APPLE_CHECK_TMP/apple-sdk-boundary-self-test.log"
  printf '%s\n' \
    'error: failed to run custom build command for `coreaudio-sys v0.2.15`' \
    "wrapper.h:1:10: fatal error: 'AudioUnit/AudioUnit.h' file not found" \
    >"$fixture"
  apple_sdk_boundary_after_successful_workspace_anchor "$fixture" \
    || die "Apple SDK classifier rejected an exact boundary after the successful workspace anchor"
  printf '%s\n' \
    '   Compiling coreaudio-sys v0.2.15' \
    >"$fixture"
  if apple_sdk_boundary_after_successful_workspace_anchor "$fixture"; then
    die "Apple SDK classifier accepted a log without an SDK boundary"
  fi
  printf '%s\n' \
    'error[E0308]: mismatched types' \
    "wrapper.h:1:10: fatal error: 'AudioUnit/AudioUnit.h' file not found" \
    >"$fixture"
  if apple_sdk_boundary_after_successful_workspace_anchor "$fixture"; then
    die "Apple SDK classifier accepted a prior coded Rust diagnostic"
  fi
  printf '%s\n' \
    'error: expected item, found keyword `let`' \
    "wrapper.h:1:10: fatal error: 'AudioUnit/AudioUnit.h' file not found" \
    >"$fixture"
  if apple_sdk_boundary_after_successful_workspace_anchor "$fixture"; then
    die "Apple SDK classifier accepted a prior uncoded Rust diagnostic"
  fi
  printf '%s\n' \
    'error: failed to run custom build command' \
    "wrapper.h:1:10: fatal error: 'AudioUnit/AudioUnit.h' file not found" \
    >"$fixture"
  if apple_sdk_boundary_after_successful_workspace_anchor "$fixture"; then
    die "Apple SDK classifier accepted an inexact Cargo wrapper diagnostic"
  fi
  rm -f -- "$fixture"
}

apple_sdk_boundary_self_test

# ---- preflight ----
[ "$BUILD_UID" -ne 0 ] || die "refusing host or container-root execution"
[ "$BUILD_GID" -ne 0 ] || die "refusing a root primary group"
[ -f "$DOCKER_BIN" ] && [ ! -L "$DOCKER_BIN" ] && [ -x "$DOCKER_BIN" ] \
  || die "trusted Docker client is unavailable at $DOCKER_BIN"
[ "$(stat -c '%u:%g:%a:%h' -- "$DOCKER_BIN")" = "0:0:755:1" ] \
  || die "trusted Docker client metadata is invalid"
[ -S /var/run/docker.sock ] || die "fixed local Docker socket is unavailable"
case "${DOCKER_HOST:-$APPLE_DOCKER_HOST}" in
  "$APPLE_DOCKER_HOST") ;;
  *) die "caller Docker endpoint authority is forbidden" ;;
esac
for name in DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS; do
  [ -z "${!name:-}" ] || die "caller $name authority is forbidden"
done
[ -z "${APPLE_TARGET:-}" ] && [ -z "${APPLE_TARGETS:-}" ] \
  || die "the R-R2 release verdict always runs the exact three-target matrix"
[ -z "${MACOS_SDK_DIR:-}" ] \
  || die "caller-selected Apple SDK authority is forbidden"
[ -f "$REPO/scripts/apple-cc-shim.sh" ] || die "scripts/apple-cc-shim.sh missing"
[ -f "$REPO/scripts/Dockerfile.apple-check" ] || die "scripts/Dockerfile.apple-check missing"
[ -f "$REPO/scripts/apple-toolchain-release.py" ] \
  || die "scripts/apple-toolchain-release.py missing"
[ -f "$REPO/scripts/apple-toolchain-provenance.py" ] \
  || die "scripts/apple-toolchain-provenance.py missing"
: "${APPLE_CHECK_IMAGE_ID:?APPLE_CHECK_IMAGE_ID is unset}"
: "${APPLE_CHECK_IMAGE_CONFIG_ID:?APPLE_CHECK_IMAGE_CONFIG_ID is unset}"
: "${APPLE_CHECK_IMAGE_MANIFEST_ID:?APPLE_CHECK_IMAGE_MANIFEST_ID is unset}"
: "${SHA256_APPLE_CHECK_DOCKERFILE:?SHA256_APPLE_CHECK_DOCKERFILE is unset}"
: "${SHA256_APPLE_CHECK_CARGO:?SHA256_APPLE_CHECK_CARGO is unset}"
: "${SHA256_APPLE_CHECK_RUSTC:?SHA256_APPLE_CHECK_RUSTC is unset}"
: "${SHA256_APPLE_CHECK_DPKG_MANIFEST:?SHA256_APPLE_CHECK_DPKG_MANIFEST is unset}"
: "${SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER:?SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER is unset}"
: "${SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER:?SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER is unset}"
: "${DEV_CHECK_IMAGE_ID:?DEV_CHECK_IMAGE_ID is unset}"
: "${DEV_CHECK_IMAGE_MANIFEST_ID:?DEV_CHECK_IMAGE_MANIFEST_ID is unset}"
: "${APPLE_CHECK_SOURCE_DATE_EPOCH:?APPLE_CHECK_SOURCE_DATE_EPOCH is unset}"
: "${APPLE_RUST_RELEASE_VERSION:?APPLE_RUST_RELEASE_VERSION is unset}"
: "${APPLE_RUST_RELEASE_DATE:?APPLE_RUST_RELEASE_DATE is unset}"
: "${APPLE_RUST_RELEASE_SIGNING_FINGERPRINT:?APPLE_RUST_RELEASE_SIGNING_FINGERPRINT is unset}"
: "${SHA256_APPLE_RUST_RELEASE_PUBLIC_KEY:?SHA256_APPLE_RUST_RELEASE_PUBLIC_KEY is unset}"
: "${SHA256_APPLE_RUST_RELEASE_MANIFEST:?SHA256_APPLE_RUST_RELEASE_MANIFEST is unset}"
: "${SHA256_APPLE_RUST_RELEASE_MANIFEST_SIGNATURE:?SHA256_APPLE_RUST_RELEASE_MANIFEST_SIGNATURE is unset}"
: "${SHA256_APPLE_RUSTC_HOST_COMPONENT:?SHA256_APPLE_RUSTC_HOST_COMPONENT is unset}"
: "${SHA256_APPLE_CARGO_HOST_COMPONENT:?SHA256_APPLE_CARGO_HOST_COMPONENT is unset}"
: "${SHA256_APPLE_RUST_STD_HOST_COMPONENT:?SHA256_APPLE_RUST_STD_HOST_COMPONENT is unset}"
: "${SHA256_APPLE_RUST_STD_AARCH64_DARWIN_COMPONENT:?SHA256_APPLE_RUST_STD_AARCH64_DARWIN_COMPONENT is unset}"
: "${SHA256_APPLE_RUST_STD_X86_64_DARWIN_COMPONENT:?SHA256_APPLE_RUST_STD_X86_64_DARWIN_COMPONENT is unset}"
: "${SHA256_APPLE_RUST_STD_AARCH64_IOS_COMPONENT:?SHA256_APPLE_RUST_STD_AARCH64_IOS_COMPONENT is unset}"
: "${APPLE_TOOLCHAIN_TREE_SHA256:?APPLE_TOOLCHAIN_TREE_SHA256 is unset}"
: "${APPLE_TOOLCHAIN_FILES:?APPLE_TOOLCHAIN_FILES is unset}"
: "${APPLE_TOOLCHAIN_DIRECTORIES:?APPLE_TOOLCHAIN_DIRECTORIES is unset}"
: "${APPLE_TOOLCHAIN_CONTENT_BYTES:?APPLE_TOOLCHAIN_CONTENT_BYTES is unset}"
: "${SHA256_CARGO_VENDOR_CLOSURE_V1:?SHA256_CARGO_VENDOR_CLOSURE_V1 is unset}"
: "${SHA256_CARGO_VENDOR_CONFIG:?SHA256_CARGO_VENDOR_CONFIG is unset}"
[[ "$IMG" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "malformed immutable Apple-check image ID"
[[ "$APPLE_CHECK_IMAGE_CONFIG_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "malformed immutable Apple-check config ID"
[[ "$APPLE_CHECK_IMAGE_MANIFEST_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "malformed immutable Apple-check manifest ID"
[[ "$APPLE_TOOLCHAIN_TREE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || die "malformed Apple toolchain tree SHA-256"
for value in "$APPLE_TOOLCHAIN_FILES" "$APPLE_TOOLCHAIN_DIRECTORIES" \
    "$APPLE_TOOLCHAIN_CONTENT_BYTES"; do
  [[ "$value" =~ ^[1-9][0-9]*$ ]] \
    || die "malformed positive Apple toolchain closure count"
done
[ "$(sha256sum scripts/Dockerfile.apple-check | awk '{print $1}')" = "$SHA256_APPLE_CHECK_DOCKERFILE" ] \
  || die "Apple-check acquisition recipe differs from its reviewed pin"
[ "$(sha256sum scripts/apple-toolchain-release.py | awk '{print $1}')" = "$SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER" ] \
  || die "Apple toolchain release helper differs from its reviewed pin"
[ "$(sha256sum scripts/apple-toolchain-provenance.py | awk '{print $1}')" = "$SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER" ] \
  || die "Apple toolchain provenance helper differs from its reviewed pin"
[ "$(sha256sum online/cargo-vendor-config.toml | awk '{print $1}')" = "$SHA256_CARGO_VENDOR_CONFIG" ] \
  || die "Cargo vendor source map differs from its reviewed pin"

install -d -m 0700 "$APPLE_DOCKER_CONFIG"
install -m 0600 /dev/null "$APPLE_DOCKER_CONFIG/config.json"
printf '{}\n' >"$APPLE_DOCKER_CONFIG/config.json"
verify_apple_docker_authority

IMAGE_ID="$(apple_docker image inspect --format '{{.Id}}' "$IMG")" \
  || die "immutable Apple-check image is not present locally"
[ "$IMAGE_ID" = "$IMG" ] || die "local Apple-check image identity differs from its pin"
readonly IMAGE_ID

APPLE_IMAGE_SPEC=(
  --role apple-check
  --expected-id "$APPLE_CHECK_IMAGE_ID"
  --base "rd-devcheck@${DEV_CHECK_IMAGE_ID}"
  --base-manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
  --dockerfile-sha "$SHA256_APPLE_CHECK_DOCKERFILE"
  --source-date-epoch "$APPLE_CHECK_SOURCE_DATE_EPOCH"
  --release-helper-sha "$SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER"
  --provenance-helper-sha "$SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER"
  --rust-version "$APPLE_RUST_RELEASE_VERSION"
  --release-date "$APPLE_RUST_RELEASE_DATE"
  --signing-fingerprint "$APPLE_RUST_RELEASE_SIGNING_FINGERPRINT"
  --release-public-key-sha "$SHA256_APPLE_RUST_RELEASE_PUBLIC_KEY"
  --release-manifest-sha "$SHA256_APPLE_RUST_RELEASE_MANIFEST"
  --release-manifest-signature-sha "$SHA256_APPLE_RUST_RELEASE_MANIFEST_SIGNATURE"
  --rustc-host-sha "$SHA256_APPLE_RUSTC_HOST_COMPONENT"
  --cargo-host-sha "$SHA256_APPLE_CARGO_HOST_COMPONENT"
  --rust-std-host-sha "$SHA256_APPLE_RUST_STD_HOST_COMPONENT"
  --rust-std-aarch64-darwin-sha "$SHA256_APPLE_RUST_STD_AARCH64_DARWIN_COMPONENT"
  --rust-std-x86-64-darwin-sha "$SHA256_APPLE_RUST_STD_X86_64_DARWIN_COMPONENT"
  --rust-std-aarch64-ios-sha "$SHA256_APPLE_RUST_STD_AARCH64_IOS_COMPONENT"
  --cargo-sha "$SHA256_APPLE_CHECK_CARGO"
  --rustc-sha "$SHA256_APPLE_CHECK_RUSTC"
  --dpkg-sha "$SHA256_APPLE_CHECK_DPKG_MANIFEST"
  --toolchain-tree-sha "$APPLE_TOOLCHAIN_TREE_SHA256"
  --toolchain-files "$APPLE_TOOLCHAIN_FILES"
  --toolchain-directories "$APPLE_TOOLCHAIN_DIRECTORIES"
  --toolchain-content-bytes "$APPLE_TOOLCHAIN_CONTENT_BYTES"
  --config-id "$APPLE_CHECK_IMAGE_CONFIG_ID"
  --manifest-id "$APPLE_CHECK_IMAGE_MANIFEST_ID"
)
apple_image_provenance verify-local \
  --image-ref "$IMAGE_ID" "${APPLE_IMAGE_SPEC[@]}" \
  || die "immutable Apple-check image provenance verification failed"

readonly APPLE_SOURCE_ARCHIVE="$APPLE_CHECK_TMP/source.tar"
readonly APPLE_SOURCE="$APPLE_CHECK_TMP/source"
readonly APPLE_VENDOR_PARENT="$APPLE_CHECK_TMP/vendor-input"
readonly APPLE_VENDOR="$APPLE_VENDOR_PARENT/subtree"
readonly APPLE_TARGET="$APPLE_CHECK_TMP/target"
readonly APPLE_CARGO_CONFIG="$APPLE_CHECK_TMP/cargo-config.toml"
install -d -m 0700 "$APPLE_SOURCE" "$APPLE_TARGET"
archive_current_source >"$APPLE_SOURCE_ARCHIVE"
SOURCE_DIGEST="$(sha256sum "$APPLE_SOURCE_ARCHIVE" | awk '{print $1}')"
readonly SOURCE_DIGEST
tar --extract --file="$APPLE_SOURCE_ARCHIVE" --directory="$APPLE_SOURCE" --no-same-owner
chmod -R a-w "$APPLE_SOURCE"
/usr/bin/python3 scripts/online-input-provenance.py snapshot-subtree-create \
  --source online/cargo-vendor \
  --destination "$APPLE_VENDOR_PARENT" \
  --expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"
{
  printf '[net]\noffline = true\n'
  sed 's#directory = .*#directory = "/vendor"#' online/cargo-vendor-config.toml
} >"$APPLE_CARGO_CONFIG"
chmod 0400 "$APPLE_CARGO_CONFIG"
[ "$(grep -c '^directory = "/vendor"$' "$APPLE_CARGO_CONFIG")" -eq 1 ] \
  || die "private Cargo source map has an invalid vendor-directory cardinality"
[ "$(stat -c '%u:%g:%a:%h' "$APPLE_TARGET")" = "$BUILD_UID:$BUILD_GID:700:2" ] \
  || die "private Cargo target metadata is invalid"
[ "$(stat -c '%u:%g:%a:%h' "$APPLE_CARGO_CONFIG")" = "$BUILD_UID:$BUILD_GID:400:1" ] \
  || die "private Cargo config metadata is invalid"

readonly IMAGE_PREFLIGHT_OUT="$APPLE_CHECK_TMP/image-preflight.out"
readonly IMAGE_PREFLIGHT_ERR="$APPLE_CHECK_TMP/image-preflight.err"
set +e
apple_docker run --rm --pull=never --network=none --read-only \
  --user "$BUILD_UID:$BUILD_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=32 --memory=256m --memory-swap=256m --cpus=1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m \
  --env HOME=/tmp \
  --env RUSTUP_HOME=/usr/local/rustup \
  --env CARGO_HOME=/usr/local/cargo \
  --env PATH="$APPLE_CHECK_PATH" \
  "$IMAGE_ID" /bin/bash --noprofile --norc -euo pipefail -c '
    [ "$(id -u)" -ne 0 ] && [ "$(id -g)" -ne 0 ]
    toolchain=/usr/local/rustup/toolchains/1.81.0-x86_64-unknown-linux-gnu
    cargo_path="$toolchain/bin/cargo"
    rustc_path="$toolchain/bin/rustc"
    [ "$(command -v cargo)" = "$cargo_path" ]
    [ "$(command -v rustc)" = "$rustc_path" ]
    printf "rustc=%s\n" "$(rustc --version)"
    printf "cargo=%s\n" "$(cargo --version)"
    printf "cargo-path=%s\n" "$(command -v cargo)"
    printf "rustc-path=%s\n" "$(command -v rustc)"
    cargo_sha="$(sha256sum "$cargo_path")"; cargo_sha="${cargo_sha%% *}"
    rustc_sha="$(sha256sum "$rustc_path")"; rustc_sha="${rustc_sha%% *}"
    release_helper_sha="$(sha256sum /usr/local/libexec/apple-toolchain-release.py)"
    release_helper_sha="${release_helper_sha%% *}"
    provenance_helper_sha="$(sha256sum /usr/local/libexec/apple-toolchain-provenance.py)"
    provenance_helper_sha="${provenance_helper_sha%% *}"
    dpkg_sha="$(dpkg-query -W | LC_ALL=C sort | sha256sum)"; dpkg_sha="${dpkg_sha%% *}"
    printf "cargo-sha=%s\n" "$cargo_sha"
    printf "rustc-sha=%s\n" "$rustc_sha"
    printf "release-helper-sha=%s\n" "$release_helper_sha"
    printf "provenance-helper-sha=%s\n" "$provenance_helper_sha"
    printf "dpkg-sha=%s\n" "$dpkg_sha"
    find "$toolchain/lib/rustlib" -mindepth 2 -maxdepth 2 \
      -type d -name lib -printf "%h\n" \
      | sed "s#^.*/rustlib/##" | LC_ALL=C sort
    python3 /usr/local/libexec/apple-toolchain-provenance.py \
      --root "$toolchain" --owner 1000 --group 1000
    printf "sodium=%s\n" "${SODIUM_USE_PKG_CONFIG-}"
  ' >"$IMAGE_PREFLIGHT_OUT" 2>"$IMAGE_PREFLIGHT_ERR"
IMAGE_PREFLIGHT_STATUS=$?
set -e
[ "$IMAGE_PREFLIGHT_STATUS" -eq 0 ] && [ ! -s "$IMAGE_PREFLIGHT_ERR" ] \
  || { cat "$IMAGE_PREFLIGHT_ERR" >&2; die "immutable Apple-check image preflight failed"; }
readonly EXPECTED_IMAGE_PREFLIGHT="$APPLE_CHECK_TMP/image-preflight.expected"
cat >"$EXPECTED_IMAGE_PREFLIGHT" <<EOF
rustc=rustc 1.81.0 (eeb90cda1 2024-09-04)
cargo=cargo 1.81.0 (2dbb1af80 2024-08-20)
cargo-path=$APPLE_TOOLCHAIN_BIN/cargo
rustc-path=$APPLE_TOOLCHAIN_BIN/rustc
cargo-sha=$SHA256_APPLE_CHECK_CARGO
rustc-sha=$SHA256_APPLE_CHECK_RUSTC
release-helper-sha=$SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER
provenance-helper-sha=$SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER
dpkg-sha=$SHA256_APPLE_CHECK_DPKG_MANIFEST
aarch64-apple-darwin
aarch64-apple-ios
x86_64-apple-darwin
x86_64-unknown-linux-gnu
{"content_bytes":$APPLE_TOOLCHAIN_CONTENT_BYTES,"contract":"rustdesk-apple-toolchain-tree-v1","directories":$APPLE_TOOLCHAIN_DIRECTORIES,"files":$APPLE_TOOLCHAIN_FILES,"sha256":"$APPLE_TOOLCHAIN_TREE_SHA256"}
sodium=1
EOF
chmod 0600 "$EXPECTED_IMAGE_PREFLIGHT"
cmp "$EXPECTED_IMAGE_PREFLIGHT" "$IMAGE_PREFLIGHT_OUT" \
  || die "immutable Apple-check image contents differ from reviewed pins"

APPLE_READ_RUN=(apple_docker run --rm --interactive --pull=never --network=none --read-only
  --user "$BUILD_UID:$BUILD_GID"
  --cap-drop=ALL --security-opt=no-new-privileges
  --pids-limit=64 --memory=512m --memory-swap=512m --cpus=1
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m
  --mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"
  --workdir /work
  "$IMAGE_ID")

COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only
  --user "$BUILD_UID:$BUILD_GID"
  --cap-drop=ALL --security-opt=no-new-privileges
  --pids-limit=512 --memory=12g --memory-swap=12g --cpus=4
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g
  --mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"
  --mount "type=bind,source=$APPLE_VENDOR,target=/vendor,readonly"
  --mount "type=bind,source=$APPLE_TARGET,target=/build"
  --mount "type=bind,source=$APPLE_CARGO_CONFIG,target=/tmp/cargo-config.toml,readonly"
  --env HOME=/tmp/apple-home
  --env CARGO_HOME=/tmp/cargo-home
  --env CARGO_TARGET_DIR=/build
  --env CARGO_INCREMENTAL=0
  --env CARGO_NET_OFFLINE=true
  --env PATH="$APPLE_CHECK_PATH"
  --env SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN"
  --env PKG_CONFIG_ALLOW_CROSS=1
  --workdir /work)

# ---- Apple source set (R-R2 retain-and-check) ----
APPLE_RS=(
  src/platform/macos.rs
  src/privacy_mode/macos.rs
  src/whiteboard/macos.rs
  libs/hbb_common/src/platform/macos.rs
  libs/clipboard/src/platform/unix/macos/item_data_provider.rs
  libs/clipboard/src/platform/unix/macos/paste_observer.rs
  libs/clipboard/src/platform/unix/macos/pasteboard_context.rs
  libs/clipboard/src/platform/unix/macos/paste_task.rs
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
  flutter/macos/Runner/Profile.entitlements
  flutter/macos/Runner/Debug.entitlements
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
  local hits raw="$APPLE_CHECK_TMP/apple-absent-raw" filtered="$APPLE_CHECK_TMP/apple-absent-filtered"
  if verify_scan_capture "$raw" -rnE "$1" "${GREP_SRC[@]}"; then
    if verify_scan_capture "$filtered" -vE ':[0-9]+:[[:space:]]*//' "$raw"; then
      hits=$(<"$filtered")
    else
      hits=
    fi
  else
    hits=
  fi
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

echo "== (2a-0) R-SV6b shared direct-address authority on Apple =="
r_sv6b=
config2_block=$(awk '/pub struct Config2 \{/,/^}/' "$REPO/libs/hbb_common/src/config.rs")
grep -qF 'pub options: HashMap<String, String>' <<<"$config2_block" || r_sv6b="$r_sv6b config2-options-map-missing"
if grep -qE '[[:space:]](rendezvous_server|nat_type|serial):' <<<"$config2_block"; then
  r_sv6b="$r_sv6b retired-config2-network-field-present"
fi
if grep -qE 'other_server|other-server-key|const PUBLIC_SERVER|Config::get_rendezvous_server|id\.contains\("@"\)' "$REPO/src/client.rs"; then
  r_sv6b="$r_sv6b cross-server-client-authority-present"
fi
if grep -qE 'PROD_RENDEZVOUS_SERVER|pub const (RENDEZVOUS_SERVERS|RENDEZVOUS_PORT|RENDEZVOUS_TIMEOUT|REG_INTERVAL)|pub fn get_rendezvous_servers?\(|pub fn (set|get)_nat_type\(|pub fn (set|get)_serial\(' "$REPO/libs/hbb_common/src/config.rs"; then
  r_sv6b="$r_sv6b rendezvous-nat-resolver-or-state-present"
fi
grep -qE 'pub async fn get_nat_type\(' "$REPO/src/common.rs" && r_sv6b="$r_sv6b nat-wrapper-present"
grep -qF 'self.id = id;' "$REPO/src/client.rs" || r_sv6b="$r_sv6b exact-address-assignment-missing"
grep -qF 'let pure_id = self.id.clone();' "$REPO/src/client.rs" || r_sv6b="$r_sv6b exact-login-identity-missing"
grep -qF 'fn login_identity_does_not_parse_cross_server_grammar()' "$REPO/src/client.rs" || r_sv6b="$r_sv6b client-regression-missing"
grep -qF 'fn config2_ignores_retired_network_state_and_never_serializes_it()' "$REPO/libs/hbb_common/src/config.rs" || r_sv6b="$r_sv6b config2-regression-missing"
if [ -n "$r_sv6b" ]; then
  echo "  FAIL R-SV6b shared direct-address authority:$r_sv6b"
  rc=1
else
  note "ok  R-SV6b Apple source has exact direct-address identity and no rendezvous/NAT compatibility actuator"
fi

echo "== (2a-0a) R-SV6c peer-presence excision and retained local status authority =="
r_sv6c=
if grep -qE 'static ref ONLINE[[:space:]]*:|fn (get_online_state|reset_online|update_latency)\(' "$REPO/libs/hbb_common/src/config.rs"; then
  r_sv6c="$r_sv6c config-latency-state-present"
fi
grep -qF 'OnlineStatus' "$REPO/src/ipc.rs" && r_sv6c="$r_sv6c online-status-ipc-present"
grep -qE 'peer_online|query_online_states' "$REPO/src/client.rs" && r_sv6c="$r_sv6c peer-query-backend-present"
grep -qE 'async_tasks|query_onlines|callback_query_onlines' "$REPO/src/flutter.rs" \
  && r_sv6c="$r_sv6c flutter-query-runner-present"
grep -qE 'main_get_connect_status|main_check_connect_status|query_onlines' "$REPO/src/flutter_ffi.rs" \
  && r_sv6c="$r_sv6c retired-status-ffi-present"
grep -qE 'status_num|start_option_status_sync|check_connect_status' "$REPO/src/ui_interface.rs" \
  && r_sv6c="$r_sv6c retired-main-status-vocabulary-present"
grep -qF 'pub fn main_start_status_sync()' "$REPO/src/flutter_ffi.rs" \
  || r_sv6c="$r_sv6c typed-status-sync-ffi-missing"
grep -qF 'pub fn start_main_status_sync()' "$REPO/src/ui_interface.rs" \
  || r_sv6c="$r_sv6c main-status-sync-entry-missing"
grep -qF '.spawn(sync_main_status)' "$REPO/src/ui_interface.rs" \
  || r_sv6c="$r_sv6c main-status-worker-owner-missing"
grep -qF 'async fn sync_main_status()' "$REPO/src/ui_interface.rs" \
  || r_sv6c="$r_sv6c main-status-worker-missing"
if grep -qE 'queryOnlines|query_onlines|callback_query_onlines|_updateOnlineState|_getOnlineStates|PeerSortType\.status|_startCheckOnlines|_queryOnlines|getOnline\(|mainGetConnectStatus|mainCheckConnectStatus|OnlineStatusWidget|connectStatus|status_num' \
  "$REPO/flutter/lib/models/peer_model.dart" \
  "$REPO/flutter/lib/models/server_model.dart" \
  "$REPO/flutter/lib/common/widgets/peers_view.dart" \
  "$REPO/flutter/lib/desktop/pages/connection_page.dart" \
  "$REPO/flutter/lib/desktop/pages/desktop_home_page.dart" \
  "$REPO/flutter/lib/main.dart" \
  "$REPO/flutter/lib/web/bridge.dart"; then
  r_sv6c="$r_sv6c Dart-peer-presence-or-compatibility-surface-present"
fi
grep -qE 'VisibilityDetector|WindowListener|_curPeers|_lastQueryPeers' "$REPO/flutter/lib/common/widgets/peers_view.dart" \
  && r_sv6c="$r_sv6c peer-list-presence-lifecycle-tracking-present"
grep -qE 'bool[[:space:]]+online([[:space:]]|=)' "$REPO/flutter/lib/models/peer_model.dart" \
  && r_sv6c="$r_sv6c Dart-peer-online-state-present"
grep -qF 'class DirectListenerStatusWidget extends StatefulWidget' "$REPO/flutter/lib/desktop/pages/connection_page.dart" \
  || r_sv6c="$r_sv6c direct-listener-widget-missing"
grep -qF "mainGetCommon(key: 'direct-listener-bound')" "$REPO/flutter/lib/desktop/pages/connection_page.dart" \
  || r_sv6c="$r_sv6c direct-listener-bound-fact-missing"
grep -qF "mainGetCommon(key: 'permanent-password-set')" "$REPO/flutter/lib/desktop/pages/connection_page.dart" \
  || r_sv6c="$r_sv6c password-provisioning-reason-missing"
grep -qF 'await bind.mainStartStatusSync();' "$REPO/flutter/lib/main.dart" \
  || r_sv6c="$r_sv6c desktop-status-sync-trigger-missing"
if [ -n "$r_sv6c" ]; then
  echo "  FAIL R-SV6c Apple peer-presence/status source closure:$r_sv6c"
  rc=1
else
  note "ok  R-SV6c Apple source has no peer-presence plane and retains only typed local status sync"
fi

echo "== (2a-0b) R-SV6d public/custom-rendezvous selection-state excision =="
r_sv6d=
if grep -qE 'using_public_server|main_is_using_public_server' \
  "$REPO/src/common.rs" "$REPO/src/flutter_ffi.rs" "$REPO/src/client.rs"; then
  r_sv6d="$r_sv6d Rust-public-server-predicate-or-ffi-present"
fi
if grep -RInE --include='*.dart' \
  'using_public_server|usingPublicServer|mainIsUsingPublicServer|is_using_public_server' \
  "$REPO/flutter/lib" >/dev/null; then
  r_sv6d="$r_sv6d Dart-public-server-predicate-or-compatibility-surface-present"
fi
grep -qF 'fn direct_only_custom_quality_is_not_relay_capped_before_login()' "$REPO/src/client.rs" \
  || r_sv6d="$r_sv6d direct-quality-regression-missing"
grep -qF 'assert_eq!(options.custom_image_quality, 180 << 8);' "$REPO/src/client.rs" \
  || r_sv6d="$r_sv6d direct-quality-assertion-missing"
grep -qF 'assert_eq!(options.custom_fps, 90);' "$REPO/src/client.rs" \
  || r_sv6d="$r_sv6d direct-fps-assertion-missing"
r_sv6d_policy_scope=$(awk '
  $0 == "        } else if q == \"custom\" {" { capture=1 }
  capture { print }
  capture && $0 == "        }" { exit }
' "$REPO/src/client.rs")
if [ -z "$r_sv6d_policy_scope" ]; then
  r_sv6d="$r_sv6d custom-fps-policy-source-scope-missing"
elif echo "$r_sv6d_policy_scope" | grep -qF '#[cfg(feature = "flutter")]'; then
  r_sv6d="$r_sv6d custom-fps-policy-remains-flutter-feature-gated"
fi
r_sv6d_test_scope=$(awk '
  $0 == "    fn direct_only_custom_quality_is_not_relay_capped_before_login() {" { capture=1 }
  capture { print }
  capture && $0 == "    }" { exit }
' "$REPO/src/client.rs")
if [ -z "$r_sv6d_test_scope" ]; then
  r_sv6d="$r_sv6d custom-fps-regression-source-scope-missing"
elif echo "$r_sv6d_test_scope" | grep -qF '#[cfg(feature = "flutter")]'; then
  r_sv6d="$r_sv6d custom-fps-regression-remains-flutter-feature-gated"
fi
grep -qF "bool hideFps = versionCmp(ffi.ffiModel.pi.version, '1.2.0') < 0;" \
  "$REPO/flutter/lib/common/widgets/dialog.dart" || r_sv6d="$r_sv6d version-only-fps-gate-missing"
grep -qF "bool hideMoreQuality = versionCmp(ffi.ffiModel.pi.version, '1.2.2') < 0;" \
  "$REPO/flutter/lib/common/widgets/dialog.dart" || r_sv6d="$r_sv6d version-only-quality-gate-missing"
grep -qE '_queryInterval|Duration\(seconds: (6|20)\)' "$REPO/flutter/lib/common/widgets/peers_view.dart" \
  && r_sv6d="$r_sv6d retired-public-custom-peer-cadence-present"
if [ -n "$r_sv6d" ]; then
  echo "  FAIL R-SV6d Apple public/custom-rendezvous source closure:$r_sv6d"
  rc=1
else
  note "ok  R-SV6d Apple source has no public/custom-rendezvous predicate and retains direct-only UI semantics"
fi

echo "== (2a-0b1) R-SV6a Apple account logout/API-server presentation excision =="
r_sv6a_logout=
r_sv6a_status_options=$(awk '/^pub enum MainStatusOptionKey \{/{capture=1} capture{print} capture && /^pub struct MainStatusOption \{/{exit}' "$REPO/src/ipc.rs")
if grep -qE 'ApiServer|OPTION_API_SERVER' <<<"$r_sv6a_status_options"; then
  r_sv6a_logout="$r_sv6a_logout api-server-main-status-contract-present"
fi
if grep -RInE --include='*.dart' 'logOut|log_out|apiServer|/api/logout' "$REPO/flutter/lib" >/dev/null; then
  r_sv6a_logout="$r_sv6a_logout Flutter-logout-compatibility-present"
fi
if grep -RInF --include='*.rs' '("Logout",' "$REPO/src/lang" >/dev/null; then
  r_sv6a_logout="$r_sv6a_logout logout-localization-key-present"
fi
r_sv6a_status_test=$(awk '/fn main_status_options_are_explicitly_allowlisted_and_bounded\(\)/{capture=1} capture{print} capture && /^    }$/{exit}' "$REPO/src/ipc.rs")
echo "$r_sv6a_status_test" | grep -qF 'keys::OPTION_API_SERVER.to_owned(),' \
  || r_sv6a_logout="$r_sv6a_logout api-server-IPC-rejection-regression-missing"
grep -qF '(OPTION_API_SERVER, ""),' "$REPO/libs/hbb_common/src/config.rs" \
  || r_sv6a_logout="$r_sv6a_logout api-server-stale-value-mask-missing"
grep -qF '<tr><td>191</td>' "$REPO/requirements.html" \
  || r_sv6a_logout="$r_sv6a_logout appendix-disposition-missing"
grep -qF 'R-SV6a-1 — logout and API-server presentation residue' "$REPO/HARDENING_STATUS.md" \
  || r_sv6a_logout="$r_sv6a_logout ledger-disposition-missing"
if [ -n "$r_sv6a_logout" ]; then
  echo "  FAIL R-SV6a Apple account logout/API-server presentation closure:$r_sv6a_logout"
  rc=1
else
  note "ok  R-SV6a Apple shared source has no logout API/localization or API-server IPC presentation contract; the empty stale-config mask remains"
fi

echo "== (2a-0c) R-G1 dead Dart policy-option aliases stay excised =="
r_g1_dead_dart=
if grep -RInE --include='*.dart' \
  'kOption(HideServerSetting|HideProxySetting|DisableChangeId|AllowDeepLinkServerSettings)|hide-server-settings|hide-proxy-settings|disable-change-id|allow-deep-link-server-settings' \
  "$REPO/flutter/lib" >/dev/null; then
  r_g1_dead_dart="$r_g1_dead_dart retired-Dart-policy-option-vocabulary-present"
fi
grep -qF 'Dead Dart policy-option aliases — CLOSED/GATED (R-G1)' "$REPO/HARDENING_STATUS.md" \
  || r_g1_dead_dart="$r_g1_dead_dart hardening-ledger-not-closed"
if [ -n "$r_g1_dead_dart" ]; then
  echo "  FAIL R-G1 Apple dead Dart policy-option alias closure:$r_g1_dead_dart"
  rc=1
else
  note "ok  R-G1 Apple source has no dead server/proxy/Change-ID/deep-link option aliases"
fi

echo "== (2a-0d) R-G2/R-SV5 direct-address UI model and exact-target preservation =="
r_g2_address=
[ ! -e "$REPO/flutter/lib/common/formatter/id_formatter.dart" ] \
  || r_g2_address="$r_g2_address legacy-id-formatter-file-present"
if grep -RInE --include='*.dart' 'IDTextEditingController|IDTextInputFormatter|formatID|trimID' \
  "$REPO/flutter/lib" >/dev/null; then
  r_g2_address="$r_g2_address legacy-numeric-id-api-present"
fi
grep -qF 'class DirectAddressTextEditingController extends TextEditingController' \
  "$REPO/flutter/lib/common/formatter/direct_address.dart" \
  || r_g2_address="$r_g2_address direct-address-controller-missing"
grep -qF 'String normalizeDirectAddress(String address) => address.trim();' \
  "$REPO/flutter/lib/common/formatter/direct_address.dart" \
  || r_g2_address="$r_g2_address outer-whitespace-only-normalizer-missing"
if grep -nF "replaceAll(' ', '')" "$REPO/flutter/lib/common.dart" \
  "$REPO/flutter/lib/common/formatter/direct_address.dart" \
  "$REPO/flutter/lib/desktop/pages/connection_page.dart" \
  "$REPO/flutter/lib/mobile/pages/connection_page.dart" >/dev/null \
  || grep -nF 'replaceAll(" ", "")' "$REPO/flutter/lib/common.dart" \
  "$REPO/flutter/lib/common/formatter/direct_address.dart" \
  "$REPO/flutter/lib/desktop/pages/connection_page.dart" \
  "$REPO/flutter/lib/mobile/pages/connection_page.dart" >/dev/null; then
  r_g2_address="$r_g2_address all-space-deletion-present"
fi
grep -qF 'connect(BuildContext context, String address,' "$REPO/flutter/lib/common.dart" \
  || r_g2_address="$r_g2_address address-choke-point-signature-missing"
grep -qF '? widget.peer.id' "$REPO/flutter/lib/common/widgets/autocomplete.dart" \
  || r_g2_address="$r_g2_address raw-autocomplete-address-display-missing"
[ "$(grep -Fc 'peer.alias.isEmpty ? peer.id : peer.alias' "$REPO/flutter/lib/common/widgets/peer_card.dart")" -eq 3 ] \
  || r_g2_address="$r_g2_address raw-peer-address-display-inventory-wrong"
grep -qF 'Numeric-ID address formatter/controller — CLOSED/GATED (R-G2/R-SV5)' \
  "$REPO/HARDENING_STATUS.md" \
  || r_g2_address="$r_g2_address hardening-ledger-not-closed"
if [ -n "$r_g2_address" ]; then
  echo "  FAIL R-G2/R-SV5 Apple direct-address UI closure:$r_g2_address"
  rc=1
else
  note "ok  R-G2/R-SV5 Apple Flutter source uses exact direct addresses with no numeric-ID formatter"
fi

echo "== (2a) R-S11e-17 typed CM file response authority =="
r_s11e17=
if verify_scan_capture "$APPLE_CHECK_TMP/r_s11e17_forbidden.txt" -nE 'RawMessage|ReadJobInitResult|FileBlockFromCM|FileReadDone|FileReadError|FileDigestFromCM|AllFilesResult|WriteJobRejected' \
  "$REPO/src/ipc.rs" "$REPO/src/ui_cm_interface.rs" "$REPO/src/server/connection.rs"; then
  r_s11e17="$r_s11e17 legacy-untyped-response-surface-present"
fi
if verify_scan_capture "$APPLE_CHECK_TMP/r_s11e17_aux_digest_state.txt" -nE 'digest_request' "$REPO/src/server/connection.rs"; then
  r_s11e17="$r_s11e17 digest-authority-remains-auxiliary-state"
fi
if verify_scan_capture "$APPLE_CHECK_TMP/r_s11e17_cm_proto.txt" -nE 'Message::new|write_to_bytes|parse_from_bytes' "$REPO/src/ui_cm_interface.rs"; then
  r_s11e17="$r_s11e17 cm-still-constructs-or-parses-network-protobuf"
fi
grep -Fq 'CmFileResponse(CmFileResponse)' "$REPO/src/ipc.rs" || r_s11e17="$r_s11e17 typed-envelope-missing"
grep -Fq 'pub enum CmFileResponseKind' "$REPO/src/ipc.rs" || r_s11e17="$r_s11e17 closed-response-enum-missing"
grep -Fq 'fn cm_file_response_session_authorized' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 exact-session-gate-missing"
grep -Fq 'CmWritePhase::Finalizing' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 finalization-phase-missing"
grep -Fq 'CmWritePhase::AwaitingPeerConfirm' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 confirmation-phase-missing"
grep -Fq 'CmWritePhase::CheckingDigest' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 exclusive-digest-phase-missing"
grep -Fq 'CmReadPhase::AwaitingPeerConfirm' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 read-confirmation-phase-missing"
grep -Fq 'CM_IPC_MAX_FRAME_BYTES' "$REPO/src/ipc.rs" || r_s11e17="$r_s11e17 aggregate-frame-limit-missing"
grep -Fq 'CM_FILE_BLOCK_MAX_FRAME_BYTES' "$REPO/src/ipc.rs" || r_s11e17="$r_s11e17 read-block-frame-limit-missing"
grep -Fq 'CM_FILE_BLOCK_READ_TIMEOUT_MS' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 read-block-timeout-missing"
grep -Fq 'cm_file_job_ids_seen: HashSet<i32>' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 job-id-nonreuse-missing"
grep -Fq 'pub enum CmFileOperation' "$REPO/src/ipc.rs" || r_s11e17="$r_s11e17 operation-descriptor-missing"
grep -Fq 'expected_operation == &operation' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 operation-descriptor-match-missing"
grep -Fq 'async fn send_fs(&mut self, data: ipc::FS) -> Result<(), String>' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 helper-enqueue-result-missing"
grep -Fq 'connection manager IPC is unavailable' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 helper-enqueue-failure-not-explicit"
grep -Fq 'file_count: Option<usize>' "$REPO/src/server/connection.rs" || r_s11e17="$r_s11e17 read-file-number-authority-missing"
grep -Fq 'matches!(self, Self::FileTransfer)' "$REPO/src/ipc.rs" || r_s11e17="$r_s11e17 file-authority-not-filetransfer-only"
grep -Fq 'R-S11e-17 — typed connection-manager file response authority' "$REPO/HARDENING_STATUS.md" || r_s11e17="$r_s11e17 hardening-ledger-missing"
grep -Fq 'Helper responses carry exact operation authority' "$REPO/requirements.html" || r_s11e17="$r_s11e17 requirements-disposition-missing"
if [ -n "$r_s11e17" ]; then
  echo "  FAIL R-S11e-17 typed CM file response authority:$r_s11e17"
  rc=1
else
  note "ok  R-S11e-17 Apple source accepts only typed, session/generation-bound CM file responses"
fi

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

apple_password_gate_dir="$APPLE_CHECK_TMP/apple-password-gate"
mkdir -m 0700 "$apple_password_gate_dir"
if ! python3 - "$REPO" "$apple_password_gate_dir" <<'PY'
import functools
import re
import sys
from pathlib import Path

repo = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
paths = {
    "ipc": "src/ipc.rs",
    "password": "src/ipc/password.rs",
    "auth": "src/ipc/auth.rs",
    "core": "src/core_main.rs",
    "macos_rs": "src/platform/macos.rs",
    "macos_mm": "src/platform/macos.mm",
    "windows": "src/platform/windows.rs",
}
original = {name: (repo / path).read_text() for name, path in paths.items()}


@functools.lru_cache(maxsize=None)
def mask_noncode(source):
    masked = list(source)
    i = 0
    while i < len(source):
        if source.startswith("//", i):
            end = source.find("\n", i + 2)
            end = len(source) if end < 0 else end
            masked[i:end] = " " * (end - i)
            i = end
            continue
        if source.startswith("/*", i):
            depth = 1
            end = i + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            masked[i:end] = " " * (end - i)
            i = end
            continue
        raw = re.match(r'(?:b?r)(#*)"', source[i:])
        if raw:
            close = '"' + raw.group(1)
            end = source.find(close, i + raw.end())
            end = len(source) if end < 0 else end + len(close)
            masked[i:end] = " " * (end - i)
            i = end
            continue
        if source[i] == '"':
            end = i + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == '"':
                    end += 1
                    break
                else:
                    end += 1
            masked[i:end] = " " * (end - i)
            i = end
            continue
        if source[i] == "'":
            end = i + 1
            if end < len(source) and source[end] == "\\":
                end += 2
            else:
                end += 1
            if end < len(source) and source[end] == "'":
                end += 1
                masked[i:end] = " " * (end - i)
                i = end
                continue
        i += 1
    return "".join(masked)


def item(source, needle, start=0):
    begin = source.find(needle, start)
    if begin < 0:
        raise ValueError(f"missing item marker: {needle}")
    masked = mask_noncode(source)
    marker_brace = needle.find("{")
    brace = (
        begin + marker_brace
        if marker_brace >= 0
        else masked.find("{", begin + len(needle))
    )
    if brace < 0:
        raise ValueError(f"missing item body: {needle}")
    depth = 0
    for index in range(brace, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return source[begin:index + 1]
    raise ValueError(f"unterminated item body: {needle}")


def ordered(body, markers):
    cursor = 0
    for marker in markers:
        position = body.find(marker, cursor)
        if position < 0:
            return False
        cursor = position + len(marker)
    return True


def analyze(sources):
    findings = {"b1": [], "b2": [], "cli": []}

    def need(group, label, condition):
        if not condition:
            findings[group].append(label)

    ipc = sources["ipc"]
    password = sources["password"]
    auth = sources["auth"]
    core = sources["core"]
    macos_rs = sources["macos_rs"]
    macos_mm = sources["macos_mm"]
    windows = sources["windows"]

    try:
        service_request = item(ipc, "pub(crate) enum ServiceIpcRequest")
        service_response = item(ipc, "pub(crate) enum ServiceIpcResponse")
        sas_request = item(ipc, "pub(crate) enum WindowsServiceSasIpcRequest")
        sas_response = item(ipc, "pub(crate) enum WindowsServiceSasIpcResponse")
        data = item(ipc, "pub enum Data {")
        request_variants = set(re.findall(r"^    ([A-Z][A-Za-z0-9_]*)", service_request, re.MULTILINE))
        response_variants = set(re.findall(r"^    ([A-Z][A-Za-z0-9_]*)", service_response, re.MULTILINE))
        sas_request_variants = set(re.findall(r"^    ([A-Z][A-Za-z0-9_]*)", sas_request, re.MULTILINE))
        sas_response_variants = set(re.findall(r"^    ([A-Z][A-Za-z0-9_]*)", sas_response, re.MULTILINE))
        data_variants = set(re.findall(r"^    ([A-Z][A-Za-z0-9_]*)", data, re.MULTILINE))
        need("b1", "service-request-not-exact", request_variants == {
            "LivenessProbe",
            "EnsurePasswordRightReady",
            "SetShareRdp",
        } and "    LivenessProbe {}," in service_request
            and "    SetShareRdp {" in service_request
            and "enabled: bool" in service_request)
        need("b1", "service-response-not-exact", response_variants == {
            "Liveness",
            "PasswordRightReady",
            "ShareRdpSet",
        } and "    Liveness {}," in service_response
            and "    PasswordRightReady {" in service_response
            and "ready: bool" in service_response
            and "    ShareRdpSet {" in service_response
            and "accepted: bool" in service_response)
        need("b1", "service-sas-request-not-exact", sas_request_variants == {
            "Dispatch",
        } and "    Dispatch {}," in sas_request)
        need("b1", "service-sas-response-not-exact", sas_response_variants == {
            "DispatchAccepted",
        } and "    DispatchAccepted {" in sas_response and "accepted: bool" in sas_response)
        need("b1", "service-envelope-allows-unknown-fields", all(token in ipc for token in [
            '#[serde(tag = "t", deny_unknown_fields)]\npub(crate) enum ServiceIpcRequest',
            '#[serde(tag = "t", deny_unknown_fields)]\npub(crate) enum ServiceIpcResponse',
            '#[serde(tag = "t", deny_unknown_fields)]\npub(crate) enum WindowsServiceSasIpcRequest',
            '#[serde(tag = "t", deny_unknown_fields)]\npub(crate) enum WindowsServiceSasIpcResponse',
        ]))
        protocol_variant_sets = (
            request_variants,
            response_variants,
            sas_request_variants,
            sas_response_variants,
        )
        need("b1", "service-protocol-variant-name-collision",
             sum(len(variants) for variants in protocol_variant_sets)
             == len(set().union(*protocol_variant_sets))
             and not set().union(*protocol_variant_sets).intersection(data_variants))
        dispatch = item(ipc, "async fn handle_service_ipc_transaction")
        need("b1", "service-dispatch-not-single-bounded-frame", dispatch.count("next_service_request_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)") == 1 and "loop {" not in dispatch)
        need("b1", "service-dispatch-not-typed", ordered(dispatch, ["next_service_request_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)", "handle_service_request(request, &mut stream).await"]) and "Data::" not in dispatch and "next_timeout(" not in dispatch)
        handler = item(ipc, "async fn handle_service_request")
        need("b1", "service-handler-not-typed", all(token in handler for token in [
            "ServiceIpcRequest::LivenessProbe {}",
            "ServiceIpcResponse::Liveness {}",
            "ServiceIpcRequest::EnsurePasswordRightReady {}",
            "ServiceIpcResponse::PasswordRightReady { ready }",
        ]) and "Data::" not in handler
            and "PermanentPasswordSnapshot" not in handler)
        windows_service = item(windows, "async fn handle_windows_service_ipc_request")
        need("b1", "windows-service-handler-not-typed",
             ".next_service_request_timeout(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)" in windows_service
             and ".next_timeout(" not in windows_service and "ipc::Data::" not in windows_service)
        windows_sas = item(windows, "async fn handle_windows_service_sas_ipc_request")
        need("b1", "windows-service-sas-handler-not-typed",
             ".next_windows_service_sas_request_timeout(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)" in windows_sas
             and "WindowsServiceSasIpcRequest::Dispatch {}" in windows_sas
             and ".next_timeout(" not in windows_sas and "ipc::Data::" not in windows_sas)
        snapshot_client = item(ipc, "pub async fn refresh_macos_service_owned_permanent_password_snapshot")
        need("b1", "macos-service-snapshot-client-not-raw", all(token in snapshot_client for token in [
            "is_service_owned_server_process()",
            "password::SERVICE_CREDENTIAL_IPC_POSTFIX",
            "Endpoint::connect(path)",
            "macos_service_server_authorization_snapshot(",
            "authorize_macos_service_server_snapshot_for_task(authorization, deadline).await",
            "send_credential_snapshot_request_unix(",
            "receive_credential_replica_unix(",
            "Config::set_permanent_password_prs_for_runtime(replica.as_str())",
        ]) and not any(token in snapshot_client for token in [
            "connect_service(", "send_service_request_timeout(",
            "next_service_response_timeout(", "ServiceIpcRequest::",
            "ServiceIpcResponse::", "storage", "salt",
        ]))
        readiness_client = item(ipc, "async fn macos_service_owned_password_authorization_right_ready")
        need("b1", "macos-service-readiness-client-not-typed", all(token in readiness_client for token in [
            "send_service_request_timeout(",
            "ServiceIpcRequest::EnsurePasswordRightReady {}",
            "next_service_response_timeout(",
            "ServiceIpcResponse::PasswordRightReady { ready }",
        ]) and "send_json_timeout(" not in readiness_client and "next_timeout(" not in readiness_client)
        share_rdp_client = item(ipc, "async fn set_service_owned_share_rdp_with_ack")
        need("b1", "windows-service-share-rdp-client-not-typed", all(token in share_rdp_client for token in [
            "send_service_request_timeout(",
            "ServiceIpcRequest::SetShareRdp { enabled: enable }",
            "next_service_response_timeout(ms_timeout)",
            "ServiceIpcResponse::ShareRdpSet { accepted }",
        ]) and "send_json_timeout(" not in share_rdp_client and "next_timeout(" not in share_rdp_client)
        sas_client = item(ipc, "pub(crate) async fn request_windows_service_owned_sas")
        need("b1", "windows-service-sas-client-not-typed", all(token in sas_client for token in [
            "send_windows_service_sas_request_timeout(",
            "WindowsServiceSasIpcRequest::Dispatch {}",
            "next_windows_service_sas_response_timeout(",
            "WindowsServiceSasIpcResponse::DispatchAccepted { accepted: true }",
        ]) and "send_json_timeout(" not in sas_client and "next_timeout(" not in sas_client)
        main_request = item(ipc, "pub enum MainIpcRequest")
        need("b1", "service-variant-remains-in-data-union", not any(token in data for token in [
            "MacosServiceOwned",
            "RequestServiceOwned",
            "ServiceOwnedShareRdp",
            "ServiceOwnedSasDispatch",
        ]) and not re.search(r"^    Test,$", data, re.MULTILINE))
        need("b1", "password-secret-present-on-serde-protocol", not any(
            token in data + main_request + service_request + service_response
            for token in [
                "SensitivePassword", "PasswordWithAuthorization",
                "RequestMacosServiceOwnedUnattendedPasswordChange",
                "PermanentPasswordSnapshot", "PermanentPasswordSnapshotResult",
            ]
        ))
        need("b1", "service-directional-regression-missing", all(token in ipc for token in [
            '#[cfg(not(any(target_os = "android", target_os = "ios")))]\n'
            '    #[test]\n'
            '    fn service_channel_uses_closed_directional_protocol()',
            "fn service_channel_uses_closed_directional_protocol()",
            "serde_json::from_slice::<ServiceIpcResponse>(&request).is_err()",
            "serde_json::from_slice::<ServiceIpcRequest>(&response).is_err()",
            "serde_json::from_slice::<ServiceIpcRequest>(&cross_purpose).is_err()",
            "serde_json::from_slice::<ServiceIpcResponse>(&readiness_request).is_err()",
            "serde_json::from_slice::<ServiceIpcRequest>(&readiness_response).is_err()",
            "serde_json::from_slice::<ServiceIpcResponse>(&share_rdp_request).is_err()",
            "serde_json::from_slice::<ServiceIpcRequest>(&share_rdp_response).is_err()",
            "fn windows_service_sas_channel_uses_closed_directional_protocol()",
            "serde_json::from_slice::<WindowsServiceSasIpcResponse>(&request).is_err()",
            "serde_json::from_slice::<WindowsServiceSasIpcRequest>(&response).is_err()",
            'assert_eq!(request, br#"{"t":"LivenessProbe"}"#)',
            'assert_eq!(response, br#"{"t":"Liveness"}"#)',
            'assert_eq!(request, br#"{"t":"Dispatch"}"#)',
            'br#"{"t":"DispatchAccepted","accepted":true}"#',
            'br#"{"t":"LivenessProbe","c":null}"#',
            'br#"{"t":"Liveness","c":null}"#',
            'br#"{"t":"EnsurePasswordRightReady"}"#',
            'br#"{"t":"PasswordRightReady","ready":true}"#',
            'br#"{"t":"EnsurePasswordRightReady","c":null}"#',
            'br#"{"t":"PasswordRightReady","ready":true,"c":null}"#',
            'br#"{"t":"SetShareRdp","enabled":true}"#',
            'br#"{"t":"ShareRdpSet","accepted":true}"#',
            'br#"{"t":"SetShareRdp","enabled":true,"c":null}"#',
            'br#"{"t":"ShareRdpSet","accepted":true,"c":null}"#',
            'br#"{"t":"Dispatch","c":null}"#',
            'br#"{"t":"DispatchAccepted","accepted":true,"c":null}"#',
        ]))
        need("b1", "service-resource-boundary-missing", all(token in ipc for token in [
            "pub(crate) const SERVICE_IPC_MAX_FRAME_BYTES: usize = 32 * 1024;",
            "pub(crate) const SERVICE_IPC_REQUEST_TIMEOUT_MS: u64 = 1_000;",
            "const SERVICE_IPC_TRANSACTION_BUDGET: usize = 4;",
            "fn try_acquire_service_ipc_transaction_slot()",
        ]))
        connect = item(ipc, "pub async fn connect(ms_timeout")
        connect_path = item(ipc, "async fn connect_with_path")
        raw_guard = "password::USER_PASSWORD_IPC_POSTFIX | password::SERVICE_PASSWORD_IPC_POSTFIX"
        credential_guard = 'if postfix == password::SERVICE_CREDENTIAL_IPC_POSTFIX'
        need("b1", "generic-connect-allows-password-endpoint",
             raw_guard in connect and raw_guard in connect_path
             and "sensitive password endpoints require the raw transport" in connect
             and "sensitive password endpoints require the raw transport" in connect_path
             and credential_guard in connect and credential_guard in connect_path
             and "the service credential endpoint requires the raw transport" in connect
             and "the service credential endpoint requires the raw transport" in connect_path)
        password_prod = password.rsplit("#[cfg(test)]", 1)[0]
        forbidden_framing = ["serde::", "Serialize", "Deserialize", "serde_json", "Framed", "BytesCodec", "BytesMut", "tokio_util"]
        need("b1", "raw-password-module-uses-generic-framing", not any(token in password_prod for token in forbidden_framing))
    except ValueError as error:
        findings["b1"].append(f"structural-parse:{error}")

    try:
        prepare_main = item(ipc, "async fn prepare_main_ipc")
        run_main = item(ipc, "async fn run_main_ipc")
        prepare_service = item(ipc, "async fn prepare_service_ipc")
        run_service = item(ipc, "async fn run_service_ipc")
        main_sensitive = item(ipc, "async fn handle_sensitive_main_ipc_transaction")
        mac_sensitive = item(ipc, "async fn handle_sensitive_macos_service_ipc_transaction")
        mac_password_mutation = item(ipc, "async fn handle_macos_service_owned_unattended_password_request")
        mac_service_auth = item(ipc, "async fn authorize_macos_service_scoped_ipc_connection_for_task")
        mac_password_auth = item(ipc, "async fn authorize_macos_service_scoped_password_stream_for_task")
        mac_credential_auth = item(ipc, "async fn authorize_macos_service_scoped_credential_stream_for_task")
        bounded_proof = item(ipc, "async fn run_bounded_macos_security_proof")
        proof_finish = item(ipc, "impl MacosSecurityProofWorker")
        proof_drop = item(ipc, "impl Drop for MacosSecurityProofWorker")
        readiness_server = item(ipc, "async fn macos_service_owned_password_authorization_right_is_ready")
        snapshot_peer = item(ipc, "async fn macos_peer_is_service_owned_server")
        snapshot_identity = item(ipc, "fn macos_peer_is_service_owned_server_blocking")
        snapshot_argv = item(ipc, "fn macos_service_owned_server_live_argv_is_expected")
        snapshot_path = item(ipc, "fn macos_root_wheel_path_is_trusted")
        snapshot_plist = item(ipc, "fn macos_service_owned_server_launch_agent_plist_value_is_expected")
        snapshot_launchd = item(ipc, "fn macos_launch_agent_owns_service_owned_server_pid")
        snapshot_bounded_child = item(ipc, "fn run_macos_bounded_child_stdout")
        snapshot_child_cleanup = item(ipc, "fn terminate_and_reap_macos_bounded_child")
        snapshot_handler = item(ipc, "async fn handle_macos_service_credential_snapshot_transaction")
        client = item(ipc, "async fn set_service_owned_unattended_password_with_ack")
        connect_sensitive = item(ipc, "async fn connect_sensitive_unix")
        connect_service = item(ipc, "async fn connect_with_path")
        coordinator = item(ipc, "impl PasswordMutationCoordinator")
        ledger = item(ipc, "impl PasswordMutationLedger")
        fingerprint_drop = item(ipc, "impl Drop for PasswordMutationFingerprint")
        service_setter = item(ipc, "fn set_service_owned_unattended_password_sensitive")
        service_client_wrapper = item(ipc, "async fn set_service_owned_unattended_password_with_ack")

        need("b2", "raw-endpoints-not-dedicated", all(token in password for token in [
            'USER_PASSWORD_IPC_POSTFIX: &str = "_password"',
            'SERVICE_PASSWORD_IPC_POSTFIX: &str = "_service_password"',
            'SERVICE_CREDENTIAL_IPC_POSTFIX: &str = "_service_credential"',
        ]) and "new_listener(password::USER_PASSWORD_IPC_POSTFIX)" in prepare_main
            and "new_listener(password::SERVICE_PASSWORD_IPC_POSTFIX)" in prepare_service
            and "new_listener(password::SERVICE_CREDENTIAL_IPC_POSTFIX)" in prepare_service
            and "credential_incoming: Incoming" in ipc)
        need("b2", "raw-wire-shape-not-fixed", all(token in password for token in [
            'const REQUEST_MAGIC: [u8; 8] = *b"RDPWREQ\\0";',
            'const STATUS_MAGIC: [u8; 8] = *b"RDPWSTS\\0";',
            "const PROTOCOL_VERSION: u8 = 1;",
            "pub(crate) const REQUEST_HEADER_BYTES: usize = 36;",
            "pub(crate) const STATUS_FRAME_BYTES: usize = 32;",
            "const REQUEST_BODY_MAX_BYTES: usize = UNATTENDED_PASSWORD_MAX_BYTES + MACOS_AUTHORIZATION_MAX_BYTES;",
            "const CREDENTIAL_REPLICA_BYTES: usize = 44;",
            "CredentialSnapshotRequest = 3",
            "CredentialReplica = 4",
        ]))
        header_decode = item(password, "pub(crate) fn decode(")
        header_validate = item(password, "fn validate(&self)")
        need("b2", "raw-header-not-canonical-or-endpoint-bound", all(token in header_decode for token in [
            "bytes[..8] != REQUEST_MAGIC", "bytes[8] != PROTOCOL_VERSION",
            "bytes[9] != 0 || bytes[11] != 0", "kind != expected_kind", "Self::new(",
        ]) and all(token in header_validate for token in [
            "nil operation UUID", "UNATTENDED_PASSWORD_MAX_BYTES",
            "MACOS_AUTHORIZATION_MAX_BYTES", "CredentialSnapshotRequest",
            "CredentialReplica", "CREDENTIAL_REPLICA_BYTES", "checked_add",
        ]))
        receive_request = item(password, "pub(crate) async fn receive_request_unix")
        receive_status = item(password, "pub(crate) async fn receive_status_unix")
        send_request = item(password, "pub(crate) async fn send_request_unix")
        decode_status = item(password, "pub(crate) fn decode_status")
        need("b2", "raw-request-not-exact-eof-utf8", ordered(receive_request, [
            "read_exact(&mut header_bytes.0)", "SensitiveRequestHeader::decode(&header_bytes.0, expected_kind)",
            "InboundSensitiveRequest::allocate(header)", "read_exact(request.body_mut())",
            "request.validate_utf8()", "stream.read(&mut trailing.0)", "if read != 0",
        ]))
        need("b2", "raw-status-not-canonical-exact-eof", all(token in decode_status for token in [
            "bytes[..8] != STATUS_MAGIC", "bytes[8] != PROTOCOL_VERSION", "bytes[9] != 0",
            "bytes[11] != 0", "bytes[28..].iter().any", "expected_operation_id.as_bytes()",
        ]) and ordered(receive_status, ["read_exact(&mut bytes.0)", "decode_status(&bytes.0, operation_id)", "stream.read(&mut trailing.0)", "!= 0"]))
        need("b2", "raw-send-not-header-body-shutdown-deadline", ordered(send_request, [
            "SensitiveRequestHeader::new(", "remaining_millis(deadline)", "stream.write_all(&header)",
            "stream.write_all(password.as_bytes())", "stream.write_all(authorization_bytes)", "stream.shutdown()",
        ]) and send_request.count("with_deadline(deadline") >= 4)
        password_prod = password.rsplit("#[cfg(test)]", 1)[0]
        need("b2", "sensitive-buffers-not-self-zeroizing", all(token in password_prod for token in [
            "impl Drop for SensitivePasswordStorage", "value.erase();", "impl Drop for FixedSensitiveBody",
            "zeroize_sensitive_bytes(&mut self.bytes);", "impl Drop for SensitiveAuthorization",
            "zeroize_sensitive_bytes(&mut self.0);", "impl<const N: usize> Drop for SensitiveStackBytes",
            "SensitivePassword([REDACTED])", "zeroize_sensitive_bytes(&mut body.bytes[password_len..]);",
        ]) and "Serialize for SensitivePassword" not in password_prod and "Deserialize" not in password_prod)
        need("b2", "main-peer-auth-not-before-secret-read", ordered(run_main, [
            "SensitiveMainListenerEvent::Accepted(stream)", "sensitive_main_ipc_authority(&stream)",
            "try_acquire_sensitive_main_ipc_transaction_slot(authority)", "handle_sensitive_main_ipc_transaction(",
        ]) and "SensitivePayloadKind::Password" in main_sensitive)
        password_accept = run_service[run_service.find("result = password_incoming.next()") : run_service.find("result = incoming.next()")]
        need("b2", "macos-peer-auth-not-before-secret-read", ordered(password_accept, [
            "try_acquire_service_password_ipc_transaction_slot()", "try_acquire_macos_service_password_ipc_authorization_slot()",
            "transactions.spawn(async move", "let deadline = tokio::time::Instant::now()",
            "authorize_macos_service_scoped_password_stream_for_task(", "if authorized",
            "handle_sensitive_macos_service_ipc_transaction(",
        ]) and "receive_request_unix" not in password_accept and ordered(mac_sensitive, [
            "SensitivePayloadKind::PasswordWithAuthorization", "try_acquire_macos_service_password_ipc_authorization_slot()",
            "run_bounded_macos_security_proof(", "request.into_password()", "handle_macos_service_owned_unattended_password_request(",
            "send_status_unix",
        ]))
        credential_accept = run_service[
            run_service.find("result = credential_incoming.next()")
            : run_service.find("result = password_incoming.next()")
        ]
        need("b2", "macos-credential-peer-auth-not-before-request", ordered(
            credential_accept,
            [
                "try_acquire_service_credential_ipc_transaction_slot()",
                "try_acquire_macos_service_credential_ipc_authorization_slot()",
                "service_scoped_ipc_authorization_snapshot_from_stream(",
                "transactions.spawn(async move",
                "authorize_macos_service_scoped_credential_stream_for_task(",
                "handle_macos_service_credential_snapshot_transaction(",
            ],
        ) and "receive_credential_snapshot_request_unix" not in credential_accept
            and all(token in mac_credential_auth for token in [
                "run_bounded_macos_security_proof(",
                "authorize_service_scoped_ipc_authorization_snapshot(",
            ]))
        need("b2", "macos-audit-snapshot-not-immediate", ordered(mac_password_auth, [
            "service_scoped_ipc_authorization_snapshot_from_stream(stream, postfix)",
            "run_bounded_macos_security_proof(deadline", "authorize_service_scoped_ipc_authorization_snapshot(authorization)",
        ]) and ordered(mac_service_auth, [
            "service_scoped_ipc_authorization_snapshot(stream, postfix)",
            "run_bounded_macos_security_proof(deadline", "authorize_service_scoped_ipc_authorization_snapshot(authorization)",
        ]))
        need("b2", "macos-budgets-not-separated", all(token in ipc for token in [
            "const SERVICE_PASSWORD_IPC_TRANSACTION_BUDGET: usize = 4;",
            "static SERVICE_PASSWORD_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>>",
            "const MACOS_SERVICE_IPC_AUTHORIZATION_BUDGET: usize = 4;",
            "static MACOS_SERVICE_IPC_AUTHORIZATION_SLOTS: OnceLock<Arc<Semaphore>>",
            "const MACOS_SERVICE_PASSWORD_IPC_AUTHORIZATION_BUDGET: usize = 4;",
            "static MACOS_SERVICE_PASSWORD_IPC_AUTHORIZATION_SLOTS: OnceLock<Arc<Semaphore>>",
            "const SERVICE_CREDENTIAL_IPC_TRANSACTION_BUDGET: usize = 2;",
            "static SERVICE_CREDENTIAL_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>>",
            "const MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_BUDGET: usize = 2;",
            "static MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_SLOTS: OnceLock<Arc<Semaphore>>",
        ]) and "MACOS_SERVICE_PASSWORD_IPC_AUTHORIZATION_SLOTS" not in item(ipc, "fn try_acquire_macos_service_ipc_authorization_slot")
            and "MACOS_SERVICE_IPC_AUTHORIZATION_SLOTS" not in item(ipc, "fn try_acquire_macos_service_password_ipc_authorization_slot")
            and "MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_SLOTS" not in item(ipc, "fn try_acquire_macos_service_ipc_authorization_slot")
            and "MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_SLOTS" not in item(ipc, "fn try_acquire_macos_service_password_ipc_authorization_slot")
            and "MACOS_SERVICE_IPC_AUTHORIZATION_SLOTS" not in item(ipc, "fn try_acquire_macos_service_credential_ipc_authorization_slot")
            and "MACOS_SERVICE_PASSWORD_IPC_AUTHORIZATION_SLOTS" not in item(ipc, "fn try_acquire_macos_service_credential_ipc_authorization_slot"))
        need("b2", "macos-proof-worker-ownership-not-exact", all(token in bounded_proof for token in [
            "std::thread::Builder::new()", "tokio::sync::oneshot::channel()", "MacosSecurityProofWorker",
            "tokio::time::timeout_at(deadline, result_rx)", "std::process::abort();", "owner.finish();",
        ]) and "spawn_blocking" not in bounded_proof and all(token in proof_finish for token in [
            "self.worker.take()", "worker.join().is_err()", "std::process::abort();",
        ]) and all(token in proof_drop for token in ["self.worker.is_some()", "std::process::abort();"]))
        need("b2", "macos-security-proof-not-absolute-deadline", "timeout_at(deadline" in bounded_proof and "timeout_at(deadline" in item(password, "async fn with_deadline"))
        proof_callers = readiness_server + snapshot_peer + snapshot_client + mac_password_auth + mac_credential_auth + mac_service_auth + mac_sensitive + connect_sensitive + connect_service
        need("b2", "macos-native-proof-detached-spawn-blocking", "spawn_blocking" not in proof_callers)
        need("b2", "readiness-snapshot-not-password-budgeted", ordered(readiness_server, [
            "try_acquire_macos_service_password_ipc_authorization_slot()", "run_bounded_macos_security_proof(deadline", "ensure_service_owned_unattended_password_authorization_right()",
        ]) and ordered(snapshot_peer, [
            "macos_peer_process_identity_from_stream(",
            "try_acquire_macos_service_credential_ipc_authorization_slot()",
            "let proof_deadline = deadline.into_std();",
            "run_bounded_macos_security_proof(deadline",
            "macos_peer_is_service_owned_server_blocking(",
            "proof_deadline",
        ]))

        server_snapshot = item(auth, "pub(crate) fn macos_service_server_authorization_snapshot")
        peer_snapshot = item(auth, "pub(crate) fn macos_peer_process_identity_from_stream")
        server_verify = item(auth, "pub(crate) fn authorize_macos_service_server_snapshot")
        scoped_snapshot = item(auth, "pub(crate) fn service_scoped_ipc_authorization_snapshot_from_stream")
        scoped_verify = item(auth, "pub(crate) fn authorize_service_scoped_ipc_authorization_snapshot")
        identity_pair = item(auth, "fn macos_service_ipc_allows_installed_app_and_privileged_helper")
        identity_match = item(auth, "fn ensure_peer_executable_matches_current_macos_identity")
        need("b2", "macos-peer-identity-not-audit-token-snapshot", all(token in scoped_snapshot for token in [
            "peer_uid_from_fd(fd)", "peer_pid_from_fd(fd)", "peer_audit_token_from_fd(fd)", "MacosPeerProcessIdentity",
        ]) and "ensure_peer_executable_matches_current_macos_identity(&identity" in scoped_verify and all(token in auth for token in [
            "libc::LOCAL_PEEREPID", "libc::LOCAL_PEERTOKEN", "attributes.set_audit_token(audit_token.as_concrete_TypeRef())",
            "MacosSecCode::copy_guest_with_attribues", "MacosCodeSigningFlags::STRICT_VALIDATE",
        ]) and "libc::LOCAL_PEERPID" not in auth)
        need("b2", "macos-installed-app-helper-identity-not-exact", all(token in auth for token in [
            '"/Library/PrivilegedHelperTools/com.carriez.rustdesk_service"',
            'identifier "com.carriez.rustdesk"', 'identifier "com.carriez.rustdesk_service"',
            "macos_privileged_helper_path_is_expected_and_trusted", "macos_installed_app_path_is_expected_and_trusted",
            "macos_path_has_no_extended_acl", "macos_peer_code_satisfies_requirement",
        ]) and all(token in identity_pair for token in [
            "hbb_common::config::is_service_ipc_postfix(postfix)", "macos_peer_is_trusted_installed_app(peer_identity)",
            "macos_privileged_helper_path_is_expected_and_trusted(current_exe)",
        ]) and "macos_service_ipc_allows_installed_app_and_privileged_helper(identity, &current_exe, postfix)" in identity_match)
        need("b2", "client-server-auth-not-before-send", ordered(connect_sensitive, [
            "Endpoint::connect(path)", "password::SERVICE_PASSWORD_IPC_POSTFIX =>", "macos_service_server_authorization_snapshot(",
            "authorize_macos_service_server_snapshot_for_task(authorization, deadline).await", "password::remaining_millis(deadline)", "Ok(stream)",
        ]) and "macos_peer_process_identity_from_stream(stream, context)?" in server_snapshot
            and ordered(peer_snapshot, [
            "peer_uid_from_fd(fd)", "peer_pid_from_fd(fd)", "peer_audit_token_from_fd(fd)",
        ]) and ordered(server_verify, ["identity.uid != 0", "macos_peer_is_trusted_privileged_helper(&authorization.identity)"]) and ordered(service_client_wrapper, [
            "connect_sensitive_unix(deadline", "password::send_request_unix(",
        ]) and ordered(snapshot_client, [
            "Endpoint::connect(path)",
            "macos_service_server_authorization_snapshot(",
            "authorize_macos_service_server_snapshot_for_task(authorization, deadline).await",
            "send_credential_snapshot_request_unix(",
        ]))

        prompt_call = "tokio::task::spawn_blocking(|| {\n                crate::platform::service_owned_unattended_password_authorization()"
        readiness = client.find("macos_service_owned_password_authorization_right_ready(readiness_deadline).await")
        prompt = client.find(prompt_call)
        fresh_deadline = client.find("let deadline = tokio::time::Instant::now()", prompt)
        raw_connect = client.find("connect_sensitive_unix(deadline", fresh_deadline)
        need("b2", "macos-user-prompt-sequence-not-readiness-prompt-fresh-deadline", -1 not in (readiness, prompt, fresh_deadline, raw_connect) and readiness < prompt < fresh_deadline < raw_connect and "timeout_at" not in client[prompt:fresh_deadline])
        platform_prompt = item(macos_rs, "pub fn service_owned_unattended_password_authorization")
        sensitive_authorization = item(password, "impl SensitiveAuthorization")
        need("b2", "macos-authorization-capability-not-self-owned", "ResultType<crate::ipc::password::SensitiveAuthorization>" in platform_prompt and ordered(platform_prompt, [
            "SensitiveAuthorization::new(vec![0u8; len])", "authorization.as_mut_bytes().as_mut_ptr()", "Ok(authorization)",
        ]) and "pub(crate) fn as_mut_bytes" in sensitive_authorization and "impl Drop for SensitiveAuthorization" in password)
        native_create = item(macos_mm, 'extern "C" bool MacCreateServiceOwnedUnattendedPasswordAuthorizationExternalForm')
        native_verify = item(macos_mm, 'extern "C" bool MacVerifyServiceOwnedUnattendedPasswordAuthorizationExternalForm')
        need("b2", "macos-native-authorization-not-explicitly-wiped", ordered(native_create, [
            "AuthorizationExternalForm externalForm = {};", "AuthorizationMakeExternalForm", "memcpy(buffer", "explicit_bzero(&externalForm",
        ]) and ordered(native_verify, [
            "AuthorizationExternalForm externalForm = {};", "memcpy(&externalForm", "AuthorizationCreateFromExternalForm", "explicit_bzero(&externalForm",
        ]))
        right_match = item(macos_mm, "static bool RustDeskSetUnattendedPasswordRightMatchesExpected")
        need("b2", "macos-authorization-right-not-exact", all(token in right_match for token in [
            'CFSTR("class"), CFSTR("user")', 'CFSTR("group"), CFSTR("admin")',
            'CFSTR("shared"), false', 'CFSTR("allow-root"), false',
            'CFSTR("authenticate-user"), true', 'CFSTR("session-owner"), false',
            'CFSTR("extract-password"), false', 'CFSTR("timeout"), 0',
        ]) and "kAuthorizationFlagInteractionAllowed" not in native_verify and "kAuthorizationRightExecute" not in native_create + native_verify)

        need("b2", "password-finality-ledger-not-keyed-hmac", all(token in ipc for token in [
            "hmacsha256::gen_key()", "hmacsha256::authenticate(value.as_bytes(), key)",
            "PASSWORD_MUTATION_RESULT_BUDGET: usize = 64", "password_mutation_id_is_valid(operation_id)",
        ]) and "zeroize_sensitive_bytes(&mut self.fingerprint_key.0);" in ledger and "zeroize_sensitive_bytes(&mut self.0 .0);" in fingerprint_drop and not any(token in coordinator for token in ["entries.remove", "pop_front", "completed.clear"]))
        need("b2", "password-finality-control-flow-invalid", all(token in coordinator for token in [
            "prepare_if_allowed", "entry.kind != kind || entry.fingerprint != fingerprint", "PasswordMutationState::Prepared",
            "fn acknowledge", "PasswordMutationState::Pending", "fn complete", "PasswordMutationState::Complete(result, std::time::Instant::now())",
            "async fn wait_for_complete", "async fn drain", "fn clear_after_transactions_drain",
        ]) and ordered(mac_password_mutation, [
            "prepare_if_allowed(", "preparation.owns_preparation", "acknowledge(&operation_id", "spawn_password_mutation(",
            "worker.await", "PasswordMutationStatus::Complete(result)",
        ]))
        uuid = client.find("let operation_id = hbb_common::uuid::Uuid::new_v4();")
        retry_loop = client.find("loop {", uuid)
        need("b2", "password-client-retry-not-stable-finality", uuid >= 0 and retry_loop > uuid and client.count("Uuid::new_v4") == 1 and all(token in client for token in [
            "recovery_required = true", "UnixSensitivePasswordSendError::Uncertain", "receive_status_unix(&mut stream, operation_id, deadline)",
            "windows_credential_client_decision(status, recovery_required)", "Retrying service-owned password operation until its final state is known",
        ]))
        service_shutdown = [
            "password_mutations().begin_shutdown();", "while let Some(result) = transactions.join_next().await",
            "password_mutations().drain().await;", "password_mutations().clear_after_transactions_drain();",
        ]
        need("b2", "password-ledger-shutdown-not-drained-cleared", ordered(run_service, service_shutdown) and ordered(run_main, service_shutdown))

        need("b2", "snapshot-requester-argv-not-exact", all(token in snapshot_argv for token in [
            "cmd.len() == 3", 'Some("--server")', "Some(crate::common::SERVICE_OWNED_SERVER_ARG)",
        ]) and "macos_service_owned_server_live_argv_is_expected(process.cmd())" in snapshot_identity)
        need("b2", "snapshot-requester-not-installed-launchd-plist-proven", all(token in snapshot_identity for token in [
            "macos_peer_is_trusted_installed_app(&identity)", "macos_launch_agent_owns_service_owned_server_pid(peer_uid, peer_pid, proof_deadline)",
        ]) and all(token in snapshot_path for token in [
            "std::fs::symlink_metadata(path)", "!metadata.file_type().is_symlink()", "metadata.uid() == 0",
            "metadata.gid() == 0", "mode() & 0o022 == 0", "macos_path_has_no_extended_acl(path)",
        ]) and all(token in snapshot_plist for token in [
            'dict.get("Label")', '"ProgramArguments"', "program_arguments.len() != expected_arguments.len()",
            '"--server"', "SERVICE_OWNED_SERVER_ARG", '"RunAtLoad"', '"KeepAlive"',
            "keep_alive.len() != 2", 'get("SuccessfulExit")', 'get("AfterInitialDemand")',
        ]) and ordered(snapshot_launchd, [
            "macos_service_owned_server_launch_agent_plist_is_trusted", "macos_service_owned_server_launch_agent_plist_content_is_expected",
            "proof_deadline.checked_sub(MACOS_LAUNCHCTL_REAP_RESERVE)", 'format!("gui/{peer_uid}/{label}")',
            "Command::new(MACOS_LAUNCHCTL)", "run_macos_bounded_child_stdout(",
            "macos_launchctl_service_identity(&output.stdout, &target)",
            "reported_identity != Some((peer_pid, expected_plist.as_str()))",
        ]) and 'const MACOS_LAUNCHCTL: &str = "/bin/launchctl";' in ipc and ordered(snapshot_handler, [
            "let deadline = tokio::time::Instant::now()",
            "receive_credential_snapshot_request_unix(&mut stream, deadline)",
            "macos_peer_is_service_owned_server(&stream, deadline).await",
            'service_owned_runtime_prs_replica("macOS")',
            "send_credential_replica_unix(&mut stream, operation_id, &replica, deadline)",
        ]) and not any(token in snapshot_handler for token in [
            "get_local_permanent_password_storage_and_salt",
            "send_service_response_timeout", "ServiceIpcResponse",
            "storage", "salt",
        ]))
        need("b2", "snapshot-launchctl-child-not-resource-bounded", all(token in ipc for token in [
            "const MACOS_LAUNCHCTL_STDOUT_MAX_BYTES: usize = 256 * 1024;",
            "const MACOS_LAUNCHCTL_REAP_RESERVE: std::time::Duration =",
            "std::time::Duration::from_millis(50);",
            "flags | hbb_common::libc::O_NONBLOCK",
            "macos_bounded_child_stdout_accepts_exact_output",
            "macos_bounded_child_stdout_terminates_on_overflow",
            "macos_bounded_child_stdout_terminates_on_deadline",
        ]) and ordered(snapshot_bounded_child, [
            ".stdin(std::process::Stdio::null())", ".stdout(std::process::Stdio::piped())",
            ".stderr(std::process::Stdio::null())", ".spawn()", "child.stdout.take()",
            "set_macos_bounded_child_stdout_nonblocking(&stdout)",
            "count > stdout_limit.saturating_sub(captured.len())", "child.try_wait()",
            "if now >= deadline", "MACOS_LAUNCHCTL_POLL_INTERVAL.min(deadline.saturating_duration_since(now))",
        ]) and all(token in snapshot_child_cleanup for token in [
            "child.try_wait()", "child.kill().err()", "child.wait()",
        ]) and "command.output()" not in snapshot_launchd)
        need("b2", "service-password-ordinary-fallback-present", not any(token in service_setter + service_client_wrapper for token in [
            "set_user_owned_permanent_password", "Config::set_permanent_password", "main_ipc_request(",
            "connect_service(", "send_json_timeout(", "RequestMacosServiceOwnedUnattendedPasswordChange",
        ]) and "connect_sensitive_unix(deadline, password::SERVICE_PASSWORD_IPC_POSTFIX" in service_client_wrapper)
        obsolete = [
            "RequestMacosServiceOwnedUnattendedPasswordChange", "BeginMacosServiceOwnedUnattendedPasswordChange",
            "MacosServiceOwnedUnattendedPasswordChallenge", "FinishMacosServiceOwnedUnattendedPasswordChange",
            "MACOS_SERVICE_OWNED_PASSWORD_PENDING", "MACOS_SERVICE_OWNED_PASSWORD_MAX_PENDING",
            "MacosServiceOwnedPasswordRequest", "macos_store_service_owned_password_request",
            "macos_take_service_owned_password_request", "macos_schedule_service_owned_password_request_expiry",
            "MACOS_SERVICE_OWNED_PASSWORD_REQUEST_TTL", "password_digest", "request_digest",
            "authorization: Vec::new()", "RootUnixPeer",
        ]
        need("b2", "obsolete-json-password-protocol-present", not any(token in ipc + macos_rs for token in obsolete))
    except ValueError as error:
        findings["b2"].append(f"structural-parse:{error}")

    try:
        cli_parse = item(core, "fn password_cli_input")
        cli_read = item(core, "fn read_unattended_password_line")
        cli_stdin = item(core, "fn read_unattended_password_from_stdin")
        cli_prompt = item(core, "fn prompt_unattended_password")
        cli_set = item(core, "fn set_cli_permanent_password")
        core_main = item(core, "pub fn core_main()")
        cli_scope = item(core, "fn is_user_main_ipc_scope_cli_command")
        sensitive_password = item(password, "impl SensitivePassword {")
        password_arm_start = core_main.find('matches!(args[0].as_str(), "--password" | "--password-stdin")')
        password_arm_end = core_main.find('args[0] == "--option"', password_arm_start)
        password_arm = core_main[password_arm_start:password_arm_end]
        need("cli", "cli-password-command-not-exact", all(token in cli_parse for token in [
            'Some("--password") if args.len() == 1 => Ok(PasswordCliInput::Terminal)',
            'Some("--password-stdin") if args.len() == 1 => Ok(PasswordCliInput::Stdin)',
            "_ => Err(PASSWORD_CLI_USAGE)",
        ]) and not re.search(r"args\s*\[\s*1\s*\]|args\.get\(1\)", cli_parse + password_arm))
        need("cli", "cli-hidden-confirmed-prompt-not-wiping", "Result<crate::ipc::SensitivePassword, String>" in cli_prompt and cli_prompt.count("rpassword::prompt_password") == 2 and ordered(cli_prompt, [
            'prompt_password("New permanent password: ")', "validate_unattended_password(password.as_str())",
            'prompt_password("Confirm permanent password: ")', "validate_unattended_password(confirmation.as_str())",
            "let matches = password.constant_time_eq(&confirmation)", "confirmation.zeroize()", "if !matches", "Ok(password)",
        ]))
        need("cli", "cli-password-equality-not-constant-time", "hbb_common::sodiumoxide::utils::memcmp(self.as_bytes(), other.as_bytes())" in sensitive_password
            and "password == confirmation" not in cli_prompt
            and "impl PartialEq for SensitivePassword" not in password
            and "impl Eq for SensitivePassword" not in password
            and "fn sensitive_password_constant_time_comparison_matches_equal_bytes_only" in password)
        need("cli", "cli-stdin-not-terminal-refused", ordered(cli_stdin, ["std::io::stdin()", "stdin.is_terminal()", "return Err(", "read_unattended_password_line(&mut stdin.lock())"]))
        need("cli", "cli-stdin-not-bounded-utf8-zeroized", all(token in core for token in [
            "struct SensitivePasswordInput(Vec<u8>)", "impl Drop for SensitivePasswordInput",
            "zeroize_sensitive_bytes(&mut self.0)",
        ]) and ordered(cli_read, [
            "UNATTENDED_PASSWORD_MAX_BYTES + 2", "reader.take((crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES + 2) as u64)",
            "read_until(b'\\n'", "bytes.0.len() > crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES",
            "String::from_utf8", "err.into_bytes()", "zeroize_sensitive_bytes(&mut invalid)",
        ]))
        need("cli", "cli-password-secret-read-from-env", not any(token in cli_parse + cli_read + cli_stdin + cli_prompt + cli_set + password_arm for token in [
            "std::env::var", "std::env::var_os", "env::var(", "env::var_os(",
        ]))
        need("cli", "cli-sensitive-value-not-passed-directly", "crate::ipc::set_permanent_password_sensitive(password)" in cli_set and ordered(password_arm, [
            "password_cli_input(&args)", "PasswordCliInput::Terminal => prompt_unattended_password()",
            "PasswordCliInput::Stdin => read_unattended_password_from_stdin()", "set_cli_permanent_password(password)",
        ]))
        need("cli", "cli-negative-regression-tests-missing", all(token in core for token in [
            "fn password_cli_rejects_positional_secrets", "fn password_stdin_reader_is_line_bounded_and_utf8_only",
            'password_cli_input(&args(&["--password", "secret"]))',
            'password_cli_input(&args(&["--password-stdin", "secret"]))',
        ]))
        need("cli", "obsolete-get-id-command-present", all(token not in core_main for token in [
            'args[0] == "--get-id"', 'println!("{}", crate::ipc::get_id());',
        ]) and 'Some("--get-id")' not in cli_scope
            and 'Some("--option")' in cli_scope
            and "fn obsolete_get_id_command_has_no_user_main_ipc_scope()" in core)
        need("cli", "account-assignment-command-present", all(token not in core_main for token in [
            'args[0] == "--assign"', 'Authorization: Bearer',
        ]) and 'Some("--assign")' not in cli_scope
            and "fn user_main_ipc_scope_cli_command_matches_option_only()" in core)
    except ValueError as error:
        findings["cli"].append(f"structural-parse:{error}")

    return findings


findings = analyze(original)


def mutation(name, file_name, old, new, group, expected):
    if old not in original[file_name]:
        findings[group].append(f"mutation-self-test-{name}-fixture-missing")
        return
    changed = dict(original)
    changed[file_name] = changed[file_name].replace(old, new, 1)
    observed = analyze(changed)[group]
    if expected not in observed:
        findings[group].append(f"mutation-self-test-{name}-not-detected")


def scoped_mutation(name, file_name, scope_anchor, old, new, group, expected):
    try:
        scope = item(original[file_name], scope_anchor)
    except ValueError:
        findings[group].append(f"mutation-self-test-{name}-scope-missing")
        return
    if scope.count(old) != 1:
        findings[group].append(f"mutation-self-test-{name}-fixture-not-unique")
        return
    changed = dict(original)
    changed[file_name] = original[file_name].replace(scope, scope.replace(old, new, 1), 1)
    observed = analyze(changed)[group]
    if expected not in observed:
        findings[group].append(f"mutation-self-test-{name}-not-detected")


mutation("service-request-shape", "ipc", "    LivenessProbe {},", "    LivenessProbe { nonce: String },", "b1", "service-request-not-exact")
mutation("service-response-shape", "ipc", "    Liveness {},", "    Liveness { nonce: String },", "b1", "service-response-not-exact")
mutation("service-unknown-fields", "ipc", '#[serde(tag = "t", deny_unknown_fields)]\npub(crate) enum ServiceIpcRequest', '#[serde(tag = "t")]\npub(crate) enum ServiceIpcRequest', "b1", "service-envelope-allows-unknown-fields")
mutation("service-direction-tag-collision", "ipc", "    PasswordRightReady { ready: bool },", "    EnsurePasswordRightReady {},", "b1", "service-response-not-exact")
mutation("service-sas-request-shape", "ipc", "    Dispatch {},", "    Dispatch { nonce: String },", "b1", "service-sas-request-not-exact")
mutation("service-sas-response-shape", "ipc", "    DispatchAccepted { accepted: bool },", "    DispatchAccepted { accepted: String },", "b1", "service-sas-response-not-exact")
mutation("service-generic-dispatch", "ipc", ".next_service_request_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)", ".next_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)", "b1", "service-dispatch-not-single-bounded-frame")
mutation("windows-service-generic-dispatch", "windows", ".next_service_request_timeout(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)", ".next_timeout(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)", "b1", "windows-service-handler-not-typed")
mutation("windows-service-sas-generic-dispatch", "windows", ".next_windows_service_sas_request_timeout(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)", ".next_timeout(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)", "b1", "windows-service-sas-handler-not-typed")
mutation("macos-service-snapshot-raw-client", "ipc", "password::send_credential_snapshot_request_unix(&mut stream, operation_id, deadline).await?;", "c.send_service_request_timeout(&ServiceIpcRequest::LivenessProbe {}, ms_timeout).await?;", "b1", "macos-service-snapshot-client-not-raw")
mutation("macos-service-readiness-generic-client", "ipc", "c.send_service_request_timeout(\n        &ServiceIpcRequest::EnsurePasswordRightReady {},", "c.send_json_timeout(\n        &ServiceIpcRequest::EnsurePasswordRightReady {},", "b1", "macos-service-readiness-client-not-typed")
mutation("windows-service-share-rdp-generic-client", "ipc", "c.send_service_request_timeout(\n        &ServiceIpcRequest::SetShareRdp { enabled: enable },", "c.send_json_timeout(\n        &ServiceIpcRequest::SetShareRdp { enabled: enable },", "b1", "windows-service-share-rdp-client-not-typed")
mutation("windows-service-sas-generic-client", "ipc", ".send_windows_service_sas_request_timeout(", ".send_json_timeout(", "b1", "windows-service-sas-client-not-typed")
mutation("service-directional-wire-regression", "ipc", 'assert_eq!(request, br#"{"t":"LivenessProbe"}"#);', 'assert_eq!(request, br#"{"t":"LivenessProbe","c":null}"#);', "b1", "service-directional-regression-missing")
mutation("service-directional-desktop-scope", "ipc", '#[cfg(not(any(target_os = "android", target_os = "ios")))]\n    #[test]\n    fn service_channel_uses_closed_directional_protocol()', '#[cfg(any(target_os = "linux", target_os = "macos"))]\n    #[test]\n    fn service_channel_uses_closed_directional_protocol()', "b1", "service-directional-regression-missing")
mutation("macos-readiness-request-wire-regression", "ipc", 'br#"{"t":"EnsurePasswordRightReady"}"#', 'br#"{"t":"EnsurePasswordRightReady","c":null}"#', "b1", "service-directional-regression-missing")
mutation("macos-readiness-response-wire-regression", "ipc", 'br#"{"t":"PasswordRightReady","ready":true}"#', 'br#"{"t":"PasswordRightReady","ready":false}"#', "b1", "service-directional-regression-missing")
mutation("windows-share-rdp-request-wire-regression", "ipc", 'br#"{"t":"SetShareRdp","enabled":true}"#', 'br#"{"t":"SetShareRdp","enabled":false}"#', "b1", "service-directional-regression-missing")
mutation("windows-share-rdp-response-wire-regression", "ipc", 'br#"{"t":"ShareRdpSet","accepted":true}"#', 'br#"{"t":"ShareRdpSet","accepted":false}"#', "b1", "service-directional-regression-missing")
mutation("service-data-residue", "ipc", "    ClickTime(i64),\n    Close,", "    ClickTime(i64),\n    Test,\n    Close,", "b1", "service-variant-remains-in-data-union")
mutation("generic-transport", "ipc", 'bail!("sensitive password endpoints require the raw transport");', 'return connect_with_path(ms_timeout, "", postfix).await;', "b1", "generic-connect-allows-password-endpoint")
mutation("endpoint-kind", "ipc", "password::SensitivePayloadKind::PasswordWithAuthorization,\n        deadline,", "password::SensitivePayloadKind::Password,\n        deadline,", "b2", "macos-peer-auth-not-before-secret-read")
scoped_mutation("credential-peer-proof", "ipc", "async fn run_service_ipc", "authorize_macos_service_scoped_credential_stream_for_task(", "authorize_macos_service_scoped_password_stream_for_task(", "b2", "macos-credential-peer-auth-not-before-request")
scoped_mutation("credential-raw-response", "ipc", "async fn handle_macos_service_credential_snapshot_transaction", "password::send_credential_replica_unix(&mut stream, operation_id, &replica, deadline)", "stream.send_service_response_timeout(&ServiceIpcResponse::Liveness {}, SERVICE_IPC_REQUEST_TIMEOUT_MS)", "b2", "snapshot-requester-not-installed-launchd-plist-proven")
mutation("absolute-proof-deadline", "ipc", "tokio::time::timeout_at(deadline, result_rx)", "tokio::time::timeout(std::time::Duration::from_secs(1), result_rx)", "b2", "macos-proof-worker-ownership-not-exact")
mutation("proof-worker-owner", "ipc", "let worker = std::thread::Builder::new()", "let worker = tokio::task::spawn_blocking", "b2", "macos-proof-worker-ownership-not-exact")
mutation("native-capability-wipe", "macos_mm", "explicit_bzero(&externalForm, sizeof(externalForm));", "memset(&externalForm, 0, sizeof(externalForm));", "b2", "macos-native-authorization-not-explicitly-wiped")
mutation("fresh-transport-deadline", "ipc", '#[cfg(target_os = "macos")]\n        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms_timeout);', '#[cfg(target_os = "macos")]\n        let deadline = readiness_deadline;', "b2", "macos-user-prompt-sequence-not-readiness-prompt-fresh-deadline")
mutation("ledger-clear", "ipc", "password_mutations().clear_after_transactions_drain();", "password_mutations().begin_shutdown();", "b2", "password-ledger-shutdown-not-drained-cleared")
mutation("snapshot-exact-argv", "ipc", "cmd.len() == 3", "cmd.len() >= 3", "b2", "snapshot-requester-argv-not-exact")
mutation("cli-exact-arity", "core", 'Some("--password") if args.len() == 1', 'Some("--password") if !args.is_empty()', "cli", "cli-password-command-not-exact")
mutation("cli-stdin-bound", "core", "reader.take((crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES + 2) as u64)", "reader.take(u64::MAX)", "cli", "cli-stdin-not-bounded-utf8-zeroized")
mutation("cli-confirmation-wipe", "core", "if !confirmation.zeroize()", "if confirmation.as_str().is_empty()", "cli", "cli-hidden-confirmed-prompt-not-wiping")
mutation("cli-constant-time-call", "core", "password.constant_time_eq(&confirmation)", "password == confirmation", "cli", "cli-password-equality-not-constant-time")
mutation("cli-constant-time-primitive", "password", "hbb_common::sodiumoxide::utils::memcmp(self.as_bytes(), other.as_bytes())", "self.as_bytes() == other.as_bytes()", "cli", "cli-password-equality-not-constant-time")
mutation("cli-generic-secret-equality", "password", "impl fmt::Debug for SensitivePassword", "impl PartialEq for SensitivePassword {\n    fn eq(&self, other: &Self) -> bool { self.as_bytes() == other.as_bytes() }\n}\n\nimpl fmt::Debug for SensitivePassword", "cli", "cli-password-equality-not-constant-time")
mutation("obsolete-get-id-handler", "core", '} else if args[0] == "--option" {', '} else if args[0] == "--get-id" {\n            println!("{}", crate::ipc::get_id());\n            return None;\n        } else if args[0] == "--option" {', "cli", "obsolete-get-id-command-present")
mutation("obsolete-get-id-scope", "core", 'Some("--option")', 'Some("--get-id") | Some("--option")', "cli", "obsolete-get-id-command-present")
mutation("account-assignment-handler", "core", '} else if args[0] == "--option" {', '} else if args[0] == "--assign" {\n            let header = "Authorization: Bearer ";\n            return None;\n        } else if args[0] == "--option" {', "cli", "account-assignment-command-present")
mutation("account-assignment-scope", "core", 'Some("--option")', 'Some("--option") | Some("--assign")', "cli", "account-assignment-command-present")

for name, group in [("r_s11b", "b1"), ("r_s11b2", "b2"), ("r_s11e16", "cli")]:
    (out_dir / name).write_text(" ".join(findings[group]))
PY
then
  printf '%s\n' 'apple-password-structural-checker-failed' >"$apple_password_gate_dir/r_s11b"
  printf '%s\n' 'apple-password-structural-checker-failed' >"$apple_password_gate_dir/r_s11b2"
  printf '%s\n' 'apple-password-structural-checker-failed' >"$apple_password_gate_dir/r_s11e16"
fi

echo "== (2b-i) R-S11b-1 macOS _service is bounded control IPC, never a password/config bus =="
r_s11b=$(<"$apple_password_gate_dir/r_s11b")
grep -Fq 'Protected service IPC resource boundary' "$REPO/requirements.html" || r_s11b="$r_s11b service-resource-requirements-missing"
grep -Fq 'R-S11c-26 — protected service IPC resource boundary' "$REPO/HARDENING_STATUS.md" || r_s11b="$r_s11b service-resource-ledger-missing"
grep -q 'SyncConfig' "$REPO/src/ipc.rs" && r_s11b="$r_s11b whole-config-ipc-variant-present"
grep -q 'SyncConfig' "$REPO/src/server.rs" && r_s11b="$r_s11b server-whole-config-import-present"
grep -q 'send_service_request_timeout(&ServiceIpcRequest::LivenessProbe {}, 1000)' "$REPO/src/ipc/fs.rs" || r_s11b="$r_s11b service-probe-not-typed-liveness"
grep -q 'Ok(Some(ServiceIpcResponse::Liveness {}))' "$REPO/src/ipc/fs.rs" || r_s11b="$r_s11b service-probe-not-validating-typed-response"
grep -Fq 'R-S11dx' "$REPO/requirements.html" || r_s11b="$r_s11b typed-service-protocol-requirement-missing"
grep -Fq 'R-S11dx/R-S11e-142' "$REPO/HARDENING_STATUS.md" || r_s11b="$r_s11b typed-service-protocol-ledger-missing"
if grep -q 'connect_service' "$REPO/src/server.rs"; then
  r_s11b="$r_s11b server-still-connects-service-channel"
fi
if grep -qE 'wait_initial_config_sync|sync_and_watch_config_dir|CONFIG_SYNC_(INTERVAL|INITIAL)' "$REPO/src/server.rs"; then
  r_s11b="$r_s11b service-config-sync-loop-present"
fi
if [ -n "$r_s11b" ]; then
  echo "  FAIL R-S11b-1 macOS service IPC closure:$r_s11b"
  rc=1
else
  note "ok  R-S11b-1/R-S11c-1f/R-S11dx _service is a closed directional liveness/readiness protocol outside Data; password and credential secrets remain raw-only"
fi

echo "== (2b-i-a) R-S11ep/R-S11e-177, R-S11fd/R-S11e-191, and R-S11fe/R-S11e-192 macOS runtime PRS launchd authority =="
if /usr/bin/python3 -I -S "$REPO/scripts/verify-macos-service-credential-ipc.py" \
    --repo "$REPO" --self-test; then
  note "ok  R-S11ep/R-S11e-177, R-S11fd/R-S11e-191, and R-S11fe/R-S11e-192 macOS proves both peers plus one bounded exact top-level launchd service record before a canonical raw _service_credential PRS exchange"
else
  echo "  FAIL R-S11ep/R-S11e-177, R-S11fd/R-S11e-191, or R-S11fe/R-S11e-192 macOS runtime PRS escaped its raw proof-before-secret launchd authority"
  rc=1
fi

echo "== (2b-ii) R-S11b-2a/R-S11b-3a macOS raw password authority and finality =="
r_s11b2=$(<"$apple_password_gate_dir/r_s11b2")
grep -q -- '<string>--service-owned-server</string>' "$REPO/src/platform/privileges_scripts/agent.plist" || r_s11b2="$r_s11b2 agent-server-not-marked"
grep -qF 'set_permanent_password_storage_for_sync' "$REPO/libs/hbb_common/src/config.rs" && r_s11b2="$r_s11b2 ordinary-main-credential-sync-writer-present"
grep -q 'RUNTIME_PERMANENT_PASSWORD_PRS' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 macos-service-password-runtime-overlay-missing"
grep -q 'runtime_password_snapshot_does_not_persist' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 macos-service-password-runtime-nonpersist-test-missing"
grep -q 'test_set_permanent_password_persists_generated_storage_salt' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 explicit-password-persistence-test-missing"
grep -q 'effective_permanent_password_prs' "$REPO/src/direct_service.rs" || r_s11b2="$r_s11b2 macos-service-password-listener-not-effective-prs"
grep -q 'let credential = effective_permanent_password_credential_snapshot().await' "$REPO/src/server.rs" || r_s11b2="$r_s11b2 macos-service-password-cpace-snapshot-missing"
grep -q 'let (prs_status, credential_generation) = credential.into_parts();' "$REPO/src/server.rs" || r_s11b2="$r_s11b2 macos-service-password-generation-binding-missing"
grep -q 'PermanentPasswordPrsRead::Available(prs) => prs' "$REPO/src/server.rs" || r_s11b2="$r_s11b2 macos-service-password-cpace-available-prs-missing"
grep -q 'PermanentPasswordPrsRead::Empty =>' "$REPO/src/server.rs" || r_s11b2="$r_s11b2 macos-service-password-cpace-empty-prs-refusal-missing"
grep -q 'PermanentPasswordPrsRead::UndecryptableStorage =>' "$REPO/src/server.rs" || r_s11b2="$r_s11b2 macos-service-password-cpace-undecryptable-prs-refusal-missing"
if grep -qF 'get_permanent_password_prs' "$REPO/libs/hbb_common/src/config.rs" "$REPO/src/server.rs" ||
   grep -qF 'into_prs(' "$REPO/libs/hbb_common/src/config.rs" "$REPO/src/server.rs"; then
  r_s11b2="$r_s11b2 macos-service-password-cpace-string-flattener-present"
fi
grep -Fq 'security-framework = "2.10"' "$REPO/Cargo.toml" || r_s11b2="$r_s11b2 macos-security-framework-direct-dependency-missing"
grep -Fq '<span class="id">R-S11g</span>' "$REPO/requirements.html" || r_s11b2="$r_s11b2 transaction-finality-requirement-missing"
grep -Fq '<span class="id">R-S11i</span>' "$REPO/requirements.html" || r_s11b2="$r_s11b2 raw-password-ipc-requirement-missing"
grep -Fq '<span class="id">R-S19a</span>' "$REPO/requirements.html" || r_s11b2="$r_s11b2 input-lifecycle-requirement-missing"
grep -Fq '<tr><td>126</td>' "$REPO/requirements.html" || r_s11b2="$r_s11b2 transaction-input-appendix-missing"
grep -Fq 'R-S11e-21 — raw password transaction finality and service-owned SAS' "$REPO/HARDENING_STATUS.md" || r_s11b2="$r_s11b2 transaction-finality-ledger-missing"
grep -Fq 'R-S11e-4 — macOS service proof ownership' "$REPO/HARDENING_STATUS.md" || r_s11b2="$r_s11b2 macos-service-proof-ownership-ledger-missing"
grep -Fq 'R-S11e-9 — macOS service audit-token peer code identity' "$REPO/HARDENING_STATUS.md" || r_s11b2="$r_s11b2 macos-service-ipc-audit-token-ledger-missing"
grep -Fq 'R-S11e-2 — macOS service client-side server authentication' "$REPO/HARDENING_STATUS.md" || r_s11b2="$r_s11b2 macos-service-client-auth-ledger-missing"

# Retain the independent desktop-input and options policy checks that share this ledger section.
grep -q 'pub fn handle_owned_mouse' "$REPO/src/server/input_service.rs" || r_s11b2="$r_s11b2 macos-owned-mouse-dispatch-missing"
grep -q 'pub fn handle_owned_pointer' "$REPO/src/server/input_service.rs" || r_s11b2="$r_s11b2 macos-owned-pointer-dispatch-missing"
grep -q 'pub fn handle_owned_key' "$REPO/src/server/input_service.rs" || r_s11b2="$r_s11b2 macos-owned-key-dispatch-missing"
grep -q 'QUEUE.exec_sync' "$REPO/src/server/input_service.rs" || r_s11b2="$r_s11b2 macos-owned-input-not-synchronous"
grep -q 'pub fn finish_owned_input_dispatch' "$REPO/src/server/input_service.rs" || r_s11b2="$r_s11b2 macos-owned-input-barrier-missing"
grep -q 'finish_owned_input_dispatch' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 macos-input-cleanup-barrier-not-wired"
grep -Fq 'const INPUT_QUEUE_CAPACITY: usize = 256;' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-count-cap-missing"
grep -Fq 'const INPUT_QUEUE_MAX_BYTES: usize = 256 * 1024;' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-byte-cap-missing"
grep -Fq 'state: AtomicUsize' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-nonblocking-cancellation-state-missing"
grep -q 'fn spawn_input_worker_supervisor' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-worker-supervisor-missing"
grep -q 'struct InputWorkerCompletion' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-worker-completion-missing"
grep -q 'SyncSender<std::thread::JoinHandle<()>>' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-supervisor-handle-handoff-missing"
grep -q 'auth_conn_type == AuthConnType::Remote && !self.start_input_worker().await' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-worker-not-remote-auth-bound"
grep -q 'struct InputKeyOwnership' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-key-ownership-missing"
grep -q 'pub enum OwnedPhysicalKey' "$REPO/src/server/input_service.rs" || r_s11b2="$r_s11b2 desktop-input-canonical-key-id-missing"
grep -q 'pub fn owned_physical_key' "$REPO/src/server/input_service.rs" || r_s11b2="$r_s11b2 desktop-input-key-resolution-missing"
grep -q 'struct InputBlockOwnerRegistry' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-block-input-owner-registry-missing"
grep -q 'SpecialKey(KeyEvent)' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-special-key-queue-path-missing"
grep -q 'desktop_input_drop_delegates_join_without_waiting_for_dispatch' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-drop-supervisor-test-missing"
grep -q 'desktop_special_keys_are_consumed_and_trigger_only_on_edges' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-special-key-edge-test-missing"
grep -q 'desktop_key_state_survives_unwind_until_cleanup_release' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-unwind-ownership-test-missing"
grep -q 'keyboard input mode and payload are inconsistent' "$REPO/src/server/connection.rs" || r_s11b2="$r_s11b2 desktop-input-structural-validation-missing"
grep -qF '(OPTION_KEY, "")' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 trust-anchor-option-not-pinned-empty"
grep -qF '(OPTION_PROXY_USERNAME, "")' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 proxy-username-not-pinned-empty"
grep -qF '(OPTION_PROXY_PASSWORD, "")' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 proxy-password-not-pinned-empty"
if verify_scan_capture "$APPLE_CHECK_TMP/r_s11b3_apple_trust_writers" -rInE --include='*.rs' 'RemoveTrustedDevices|ClearTrustedDevices|main(Get|Remove|Clear)TrustedDevices|add_trusted_device|set_key_confirmed\(' "$REPO/src" "$REPO/libs"; then
  r_s11b2="$r_s11b2 trusted-device-or-key-confirmation-writer-present:$(tr '\n' ';' <"$APPLE_CHECK_TMP/r_s11b3_apple_trust_writers")"
fi
grep -q 'MainIpcRequest::SetOption(requested)' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 option-write-not-typed"
grep -q 'current_process_allows_main_channel_options_write()' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 options-write-not-authority-gated"
grep -q 'OptionSet {' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 option-typed-result-missing"
grep -q 'result: IpcMutationResult::Rejected' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 option-reject-nack-missing"
grep -q 'effective: Some(effective)' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 receiver-effective-option-missing"
grep -q 'Option write requires daemon ACK' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 local-fallback-not-blocked"
set_option_fn=$(awk '/pub async fn set_option/,/^}/' "$REPO/src/ipc.rs")
echo "$set_option_fn" | grep -q 'crate::platform::is_installed' && r_s11b2="$r_s11b2 options-fallback-uses-install-heuristic"
echo "$set_option_fn" | grep -q 'Config::set_option' && r_s11b2="$r_s11b2 option-caller-local-persistence-present"
option_handler=$(awk '/MainIpcRequest::SetOption\(value\) => \{/,/MainIpcRequest::ValidateCmConnection/' "$REPO/src/ipc.rs")
grep -q 'Config::set_option(key_name.clone(), value.value);' <<<"$option_handler" || r_s11b2="$r_s11b2 exact-option-persistence-missing"
grep -q 'value: Config::get_option(&key_name)' <<<"$option_handler" || r_s11b2="$r_s11b2 receiver-effective-read-missing"
echo "$option_handler" | grep -q 'Config::set_options' && r_s11b2="$r_s11b2 whole-options-replacement-present"
grep -q 'match ipc::set_option(&key, &value)' "$REPO/src/ui_interface.rs" || r_s11b2="$r_s11b2 ui-exact-option-request-missing"
grep -q 'options.insert(key.clone(), effective);' "$REPO/src/ui_interface.rs" || r_s11b2="$r_s11b2 ui-exact-cache-update-missing"
for token in \
  'MainIpcRequest::SetOptions' \
  'MainIpcResponse::OptionsSet' \
  'merge_main_status_options' \
  'ipc::set_options' \
  'pub async fn set_options' \
  'pub fn main_set_options' \
  'mainSetOptions'; do
  grep -Fq "$token" "$REPO/src/ipc.rs" "$REPO/src/ui_interface.rs" "$REPO/src/flutter_ffi.rs" "$REPO/flutter/lib/web/bridge.dart" &&
    r_s11b2="$r_s11b2 retired-whole-options-surface-present:$token"
done
for token in \
  'pub fn set_options(' \
  'fn purify_options('; do
  grep -Fq "$token" "$REPO/libs/hbb_common/src/config.rs" &&
    r_s11b2="$r_s11b2 retired-whole-options-config-writer-present:$token"
done
for token in \
  'fn get_salt(' \
  'fn get_effective_permanent_password_salt(' \
  'pub fn get_preset_password_storage_and_salt('; do
  grep -Fq "$token" "$REPO/libs/hbb_common/src/config.rs" &&
    r_s11b2="$r_s11b2 retired-salt-reader-surface-present:$token"
done
grep -q 'SyncConfig' "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 whole-config-ipc-variant-present"
grep -q 'SyncConfig' "$REPO/src/server.rs" && r_s11b2="$r_s11b2 server-whole-config-import-present"
main_config_enum=$(awk '/pub enum MainConfigKey/,/^}/' "$REPO/src/ipc.rs")
main_config_handler=$(awk '/MainIpcRequest::Config\(key\) => \{/,/MainIpcRequest::SetOption\(value\) => \{/' "$REPO/src/ipc.rs")
echo "$main_config_enum" | grep -q 'PermanentPasswordStorageAndSalt' && r_s11b2="$r_s11b2 credential-storage-main-config-key-present"
echo "$main_config_enum" | grep -Eq '^[[:space:]]*Salt([[:space:]]|,)' && r_s11b2="$r_s11b2 standalone-salt-main-config-key-present"
for token in \
  'sync_permanent_password_storage_from_daemon' \
  'apply_permanent_password_storage_and_salt_payload' \
  'current_process_allows_main_channel_permanent_password_storage_sync' \
  'allows_main_channel_password_storage_sync'; do
  grep -qF "$token" "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 ordinary-main-credential-mirror-symbol-present:$token"
done
for token in \
  'get_local_permanent_password_storage_and_salt' \
  'get_existing_key_pair' \
  'get_key_pair(' \
  'password_prs' \
  'get_salt('; do
  grep -qF "$token" <<<"$main_config_handler" && r_s11b2="$r_s11b2 main-config-handler-secret-read-present:$token"
done
grep -qF 'storage + "\n" + &salt' "$REPO/src/ipc.rs" && r_s11b2="$r_s11b2 credential-storage-string-payload-present"
grep -q 'PermanentPasswordSet' <<<"$main_config_enum" || r_s11b2="$r_s11b2 typed-password-status-key-missing"
grep -q 'MainConfigKey::PermanentPasswordSet => Some' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 typed-password-status-handler-missing"
grep -q 'permanent_password_is_set_for_current_process().await' "$REPO/src/ipc.rs" || r_s11b2="$r_s11b2 receiver-derived-password-status-missing"
grep -q 'ipc::is_permanent_password_set()' "$REPO/src/ui_interface.rs" || r_s11b2="$r_s11b2 ui-password-status-not-daemon-derived"
for token in \
  'LocalPermanentPasswordSet' \
  'PermanentPasswordIsPreset' \
  'permanent_password_is_local_for_current_process' \
  'permanent_password_is_preset_for_current_process' \
  'is_local_permanent_password_set' \
  'is_permanent_password_preset'; do
  grep -qF "$token" "$REPO/src/ipc.rs" "$REPO/src/ui_interface.rs" &&
    r_s11b2="$r_s11b2 retired-password-status-subtype-present:$token"
done
for token in \
  'decode_preset_password_h1_from_storage' \
  'preset_permanent_password_storage_is_usable_for_auth' \
  'has_usable_preset_password' \
  'is_using_preset_password' \
  'preset_password_storage_and_salt' \
  'has_local_permanent_password'; do
  grep -qF "$token" "$REPO/libs/hbb_common/src/config.rs" "$REPO/libs/hbb_common/src/config/permanent_password.rs" &&
    r_s11b2="$r_s11b2 retired-preset-credential-classifier-present:$token"
done
if grep -RInE 'isPresetPassword|is_preset_password|buildPresetPasswordWarning|preset_password_warning|preset-password-in-use-tip|remove-preset-password-warning' \
  "$REPO/src/flutter_ffi.rs" "$REPO/src/bridge_generated.rs" "$REPO/src/bridge_generated.io.rs" "$REPO/flutter/lib" "$REPO/src/lang" >/dev/null; then
  r_s11b2="$r_s11b2 retired-preset-password-presentation-present"
fi
grep -q 'Self::read_permanent_password_prs().is_available()' "$REPO/libs/hbb_common/src/config.rs" || r_s11b2="$r_s11b2 typed-password-status-authority-missing"
grep -Fq 'R-S11b-3q — preset-password credential/status compatibility excised' "$REPO/HARDENING_STATUS.md" || r_s11b2="$r_s11b2 preset-password-excision-ledger-missing"
grep -Fq '<tr><td>241</td>' "$REPO/requirements.html" || r_s11b2="$r_s11b2 preset-password-excision-appendix-missing"
grep -Fq 'R-S11b-4e — ordinary main IPC credential mirror excised' "$REPO/HARDENING_STATUS.md" || r_s11b2="$r_s11b2 credential-mirror-ledger-missing"
grep -Fq '<tr><td>237</td>' "$REPO/requirements.html" || r_s11b2="$r_s11b2 credential-mirror-appendix-missing"
grep -Fq 'R-S11b-3n — ordinary main IPC option mutation is single-key and receiver-effective' "$REPO/HARDENING_STATUS.md" || r_s11b2="$r_s11b2 single-option-ledger-missing"
grep -Fq 'R-S11b-3o — production-dead whole-options config writer excised' "$REPO/HARDENING_STATUS.md" || r_s11b2="$r_s11b2 whole-options-config-ledger-missing"
grep -Fq 'R-S11b-3p — production-dead effective and standalone salt readers excised' "$REPO/HARDENING_STATUS.md" || r_s11b2="$r_s11b2 obsolete-salt-reader-ledger-missing"
grep -Fq '<tr><td>238</td>' "$REPO/requirements.html" || r_s11b2="$r_s11b2 single-option-appendix-missing"
grep -Fq '<tr><td>239</td>' "$REPO/requirements.html" || r_s11b2="$r_s11b2 whole-options-config-appendix-missing"
grep -Fq '<tr><td>240</td>' "$REPO/requirements.html" || r_s11b2="$r_s11b2 obsolete-salt-reader-appendix-missing"
if [ -n "$r_s11b2" ]; then
  echo "  FAIL R-S11b-2a/R-S11b-3a macOS raw password IPC:$r_s11b2"
  rc=1
else
  note "ok  R-S11b-2a/R-S11b-3a password mutations use fixed raw endpoint-bound frames, pre-body audit-token peer proof, separate bounded transaction/Security.framework lanes, exact joined native-proof ownership, root-helper client authentication, user-paced Authorization Services with wiping capability storage, keyed replay finality, and drained/cleared shutdown state; ordinary serde/config fallbacks are absent"
fi

echo "== (2b-ii-a) R-S11e-16 macOS password provisioning ingress =="
r_s11e16=$(<"$apple_password_gate_dir/r_s11e16")
grep -Fq 'sudo rustdesk --password' "$REPO/docs/DEPLOYMENT.md" || r_s11e16="$r_s11e16 safe-deployment-command-missing"
grep -Eq -- 'sudo rustdesk --password[[:space:]]+[^`[:space:]]' "$REPO/docs/DEPLOYMENT.md" && r_s11e16="$r_s11e16 password-valued-deployment-command-present"
grep -Fq 'Permanent-password provisioning through visible process arguments' "$REPO/requirements.html" || r_s11e16="$r_s11e16 requirements-disposition-missing"
grep -Fq 'R-S11e-16 — permanent-password provisioning ingress' "$REPO/HARDENING_STATUS.md" || r_s11e16="$r_s11e16 ledger-disposition-missing"
if [ -n "$r_s11e16" ]; then
  echo "  FAIL R-S11e-16 macOS password provisioning ingress:$r_s11e16"
  rc=1
else
  note "ok  R-S11e-16 accepts only exact --password/--password-stdin commands, uses a confirmed hidden TTY prompt with explicit libsodium constant-time comparison or bounded non-TTY UTF-8 stdin, keeps secrets out of argv/environment, rejects generic password equality, and carries secrets in self-zeroizing values"
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
grep -qF 'cm_file_login_published: bool' "$REPO/src/server/connection.rs" || r_s11c4="$r_s11c4 producer-login-publication-state-missing"
grep -qF 'cm_file_login_published: false' "$REPO/src/server/connection.rs" || r_s11c4="$r_s11c4 producer-login-publication-state-not-closed"
grep -qF 'so no current Rust compile/test or installed operation was run' "$REPO/HARDENING_STATUS.md" || r_s11c4="$r_s11c4 current-source-native-evidence-boundary-missing"
cm_login_producer_block=$(awk '/fn try_start_cm\(/,/fn send_to_cm\(/' "$REPO/src/server/connection.rs")
cm_login_reset_line=$(echo "$cm_login_producer_block" | grep -nF 'self.cm_file_login_published = false;' | head -1 | cut -d: -f1 || true)
cm_login_send_line=$(echo "$cm_login_producer_block" | grep -nF 'if self.send_to_cm(login).await {' | head -1 | cut -d: -f1 || true)
cm_login_commit_line=$(echo "$cm_login_producer_block" | grep -nF 'self.cm_file_login_published = publishes_file_authority;' | head -1 | cut -d: -f1 || true)
if [ -z "$cm_login_reset_line" ] || [ -z "$cm_login_send_line" ] || [ -z "$cm_login_commit_line" ] \
    || [ "$cm_login_reset_line" -ge "$cm_login_send_line" ] \
    || [ "$cm_login_send_line" -ge "$cm_login_commit_line" ]; then
  r_s11c4="$r_s11c4 producer-login-publication-not-success-linearized"
fi
cm_fs_producer_block=$(awk '/fn send_fs\(/,/async fn send_login_error/' "$REPO/src/server/connection.rs")
cm_fs_producer_gate_line=$(echo "$cm_fs_producer_block" | grep -nF 'if !cm_file_request_session_authorized(' | head -1 | cut -d: -f1 || true)
cm_fs_producer_send_line=$(echo "$cm_fs_producer_block" | grep -nF '.send(data)' | head -1 | cut -d: -f1 || true)
for authority_input in 'self.authorized' 'self.file_transfer.is_some()' 'self.file' 'self.cm_file_login_published'; do
  echo "$cm_fs_producer_block" | grep -Fq "$authority_input" || r_s11c4="$r_s11c4 producer-file-gate-missing-$authority_input"
done
if [ -z "$cm_fs_producer_gate_line" ] || [ -z "$cm_fs_producer_send_line" ] \
    || [ "$cm_fs_producer_gate_line" -ge "$cm_fs_producer_send_line" ]; then
  r_s11c4="$r_s11c4 producer-file-gate-not-before-send"
fi
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
  note "ok  R-S11c-4a macOS file producers require a successfully published authorized FileTransfer login before the common filesystem-send choke point, and CM rejects forged desktop login/plain FS unless the main server validates the active connection id/type/token"
fi

echo "== (2b-iii-a1) R-S11c-4d bounded exact-owner macOS CM command publication =="
r_s11c4d=
cm_command_sender=$(awk '/async fn send_to_cm\(/,/fn publish_cm_terminal/' "$REPO/src/server/connection.rs")
cm_file_sender=$(awk '/async fn send_fs\(/,/async fn send_login_error/' "$REPO/src/server/connection.rs")
cm_connection_drop=$(awk '/impl Drop for Connection \{/,/struct LinuxHeadlessHandle/' "$REPO/src/server/connection.rs")
cm_ipc_bootstrap=$(awk '/async fn start_ipc\(/,/\/\/ in case screen is sleep and blank/' "$REPO/src/server/connection.rs")
for binding in \
  'const CM_COMMAND_QUEUE_CAPACITY: usize = 2;' \
  'let (tx_to_cm, rx_to_cm) = mpsc::channel::<ipc::Data>(CM_COMMAND_QUEUE_CAPACITY);' \
  'tx_to_cm: mpsc::Sender<ipc::Data>' \
  'rx_to_cm: mpsc::Receiver<ipc::Data>' \
  'fn cm_command_queue_has_exact_capacity_and_recovers_after_dequeue()'; do
  grep -qF "$binding" "$REPO/src/server/connection.rs" || r_s11c4d="$r_s11c4d bounded-command-binding-missing"
done
grep -qF 'let (tx_to_cm, rx_to_cm) = mpsc::unbounded_channel' "$REPO/src/server/connection.rs" \
  && r_s11c4d="$r_s11c4d unbounded-command-channel-present"
for binding in \
  'async fn send_to_cm(&mut self, data: ipc::Data) -> bool' \
  'CM_COMMAND_QUEUE_SEND_TIMEOUT,' \
  'self.tx_to_cm.send(data)' \
  'connection-manager command queue backpressure timed out'; do
  grep -qF "$binding" <<<"$cm_command_sender" || r_s11c4d="$r_s11c4d bounded-control-publication-missing"
done
for binding in \
  'async fn send_fs(&mut self, data: ipc::FS) -> Result<(), String>' \
  'CM_COMMAND_QUEUE_SEND_TIMEOUT,' \
  'self.tx_to_cm.send(data)'; do
  grep -qF "$binding" <<<"$cm_file_sender" || r_s11c4d="$r_s11c4d bounded-file-publication-missing"
done
for binding in \
  'pub(crate) enum CmConnectionTerminal {' \
  'cm_terminal: Option<oneshot::Sender<crate::ui_cm_interface::CmConnectionTerminal>>' \
  'cm_terminal: oneshot::Receiver<crate::ui_cm_interface::CmConnectionTerminal>' \
  'self.publish_cm_terminal(terminal);'; do
  grep -qF "$binding" "$REPO/src/server/connection.rs" "$REPO/src/ui_cm_interface.rs" \
    || r_s11c4d="$r_s11c4d terminal-lane-binding-missing"
done
drop_terminal_line=$(grep -nF -m 1 'self.publish_cm_terminal(crate::ui_cm_interface::CmConnectionTerminal::Close);' <<<"$cm_connection_drop" | cut -d: -f1 || true)
drop_owner_line=$(grep -nF -m 1 'drop(self.cm_ipc_owner.take());' <<<"$cm_connection_drop" | cut -d: -f1 || true)
desktop_terminal_line=$(grep -nF -m 1 'terminal = &mut cm_terminal =>' <<<"$cm_ipc_bootstrap" | cut -d: -f1 || true)
desktop_command_line=$(grep -nF -m 1 'event = async {' <<<"$cm_ipc_bootstrap" | cut -d: -f1 || true)
if [ -z "$drop_terminal_line" ] || [ -z "$drop_owner_line" ] || [ "$drop_terminal_line" -ge "$drop_owner_line" ] \
    || [ -z "$desktop_terminal_line" ] || [ -z "$desktop_command_line" ] || [ "$desktop_terminal_line" -ge "$desktop_command_line" ]; then
  r_s11c4d="$r_s11c4d terminal-finality-order-invalid"
fi
grep -qF 'finite per-connection CM command queue' "$REPO/requirements.html" \
  || r_s11c4d="$r_s11c4d normative-command-budget-missing"
grep -qF 'R-S11c-4d — bounded exact-owner CM command publication' "$REPO/HARDENING_STATUS.md" \
  || r_s11c4d="$r_s11c4d hardening-ledger-missing"
if [ -n "$r_s11c4d" ]; then
  echo "  FAIL R-S11c-4d bounded exact-owner macOS CM command publication:$r_s11c4d"
  rc=1
else
  note "ok  R-S11c-4d macOS Connection-to-CM commands use bounded deadline-backed publication and an exact terminal lane preempts queued work"
fi

echo "== (2b-iii-a2) R-G9 Apple shared presentation serialization contract =="
r_g9=
cm_login_ipc=$(awk '/^[[:space:]]*Login \{/{capture=1} capture{print} capture && /^[[:space:]]*\},/{exit}' "$REPO/src/ipc.rs")
cm_client_dto=$(awk '/^pub struct Client \{/{capture=1} capture{print} capture && /^}/{exit}' "$REPO/src/ui_cm_interface.rs")
[ -n "$cm_login_ipc" ] || r_g9="$r_g9 cm-login-ipc-block-missing"
[ -n "$cm_client_dto" ] || r_g9="$r_g9 cm-client-dto-block-missing"
for field in restart recording block_input; do
  if grep -qE "^[[:space:]]*$field:[[:space:]]*bool," <<<"$cm_login_ipc"; then
    r_g9="$r_g9 cm-login-serialized-$field"
  fi
  if grep -qE "^[[:space:]]*pub[[:space:]]+$field:[[:space:]]*bool," <<<"$cm_client_dto"; then
    r_g9="$r_g9 cm-client-serialized-$field"
  fi
  grep -qE "^[[:space:]]*$field:[[:space:]]*bool," "$REPO/src/server/connection.rs" \
    || r_g9="$r_g9 connection-authority-missing-$field"
done
if grep -qE 'sameServer|same_server' "$REPO/flutter/lib/models/peer_model.dart"; then
  r_g9="$r_g9 saved-peer-cloud-provenance"
fi
grep -qF 'fn cm_presentation_contract_omits_connection_only_permissions()' "$REPO/src/ui_cm_interface.rs" \
  || r_g9="$r_g9 cm-serialization-regression-missing"
grep -qF "expect(serialized, isNot(contains('same_server')));" "$REPO/flutter/test/peer_model_test.dart" \
  || r_g9="$r_g9 saved-peer-serialization-regression-missing"
for permission in Restart Recording BlockInput; do
  grep -qF "conn.send_permission(Permission::$permission, false).await;" "$REPO/src/server/connection.rs" \
    || r_g9="$r_g9 server-permission-path-missing-$permission"
  grep -qF "Ok(Permission::$permission) =>" "$REPO/src/client/io_loop.rs" \
    || r_g9="$r_g9 viewer-permission-path-missing-$permission"
done
grep -qF '<span class="id">R-G9</span>' "$REPO/requirements.html" || r_g9="$r_g9 requirement-missing"
grep -qF '<tr><td>189</td>' "$REPO/requirements.html" || r_g9="$r_g9 appendix-row-missing"
grep -qF 'R-G9 — minimal presentation and compatibility serialization contracts' "$REPO/HARDENING_STATUS.md" \
  || r_g9="$r_g9 hardening-ledger-missing"
if [ -n "$r_g9" ]; then
  echo "  FAIL R-G9 Apple shared presentation serialization contract:$r_g9"
  rc=1
else
  note "ok  R-G9 shared CM/peer DTOs omit dead fields while authenticated Connection and viewer permission paths remain live"
fi

echo "== (2b-iii-a3) R-G4a Apple switch-sides compatibility state excision =="
r_g4a=
for path in \
  src/client.rs src/client/io_loop.rs src/server/connection.rs src/ipc.rs \
  src/ui_cm_interface.rs src/ui_session_interface.rs src/flutter.rs src/flutter_ffi.rs; do
  if sed '/^#\[cfg(test)\]/,$d' "$REPO/$path" \
    | grep -qE 'SwitchSides|SwitchBack|switch_sides|switchSides|switch_back|switchBack|switch_uuid|switchUuid|from_switch|fromSwitch'; then
    r_g4a="$r_g4a $path-role-swap-residue"
  fi
done
if grep -RInE --include='*.dart' \
  'SwitchSides|SwitchBack|switch_sides|switchSides|switch_back|switchBack|switch_uuid|switchUuid|from_switch|fromSwitch' \
  "$REPO/flutter/lib" >/dev/null; then
  r_g4a="$r_g4a authored-Dart-role-swap-residue"
fi
grep -qF 'assert!(!login_payload.contains_key("from_switch"));' "$REPO/src/ui_cm_interface.rs" \
  || r_g4a="$r_g4a cm-login-serialization-regression-missing"
grep -qF 'assert!(!client_payload.contains_key("from_switch"));' "$REPO/src/ui_cm_interface.rs" \
  || r_g4a="$r_g4a cm-client-serialization-regression-missing"
grep -qF "expect(serialized, isNot(contains('from_switch')));" "$REPO/flutter/test/server_model_test.dart" \
  || r_g4a="$r_g4a Flutter-legacy-key-regression-missing"
[ "$(grep -cF 'self.authorized = true;' "$REPO/src/server/connection.rs")" -eq 1 ] \
  || r_g4a="$r_g4a sole-PAKE-authorization-edge-not-preserved"
grep -qF '.get("keyboard")' "$REPO/src/ui_cm_interface.rs" \
  || r_g4a="$r_g4a retained-CM-capability-fact-not-proven"
grep -qF '<span class="id">R-G4a</span>' "$REPO/requirements.html" || r_g4a="$r_g4a requirement-missing"
grep -qF '<tr><td>190</td>' "$REPO/requirements.html" || r_g4a="$r_g4a appendix-row-missing"
grep -qF 'R-G4a — switch-sides role-swap compatibility state excision' "$REPO/HARDENING_STATUS.md" \
  || r_g4a="$r_g4a hardening-ledger-missing"
if [ -n "$r_g4a" ]; then
  echo "  FAIL R-G4a Apple switch-sides compatibility closure:$r_g4a"
  rc=1
else
  note "ok  R-G4a shared Apple source has no switch-sides role-swap API/state; legacy JSON is ignored and sole PAKE authorization remains"
fi

echo "== (2b-iii-b) R-S11c-11 macOS CM endpoint-selection proof =="
r_s11c11=
if ! python3 "$REPO/scripts/verify-cm-process-ownership.py" --self-test; then
  r_s11c11="$r_s11c11 exact-process-verifier-self-test-failed"
fi
if ! python3 "$REPO/scripts/verify-cm-process-ownership.py" "$REPO"; then
  r_s11c11="$r_s11c11 exact-process-verifier-failed"
fi
grep -q 'CmEndpointChallenge {' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-endpoint-challenge"
grep -q 'CmEndpointProof {' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-endpoint-proof"
grep -q 'CmServerChallenge {' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-server-challenge"
grep -q 'CmServerProof {' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-server-proof"
grep -q 'hmacsha256::authenticate' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-hmac-proof"
grep -q 'hmacsha256::verify' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-hmac-verify"
grep -q 'CM_SERVER_PROOF_CONTEXT' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-directional-server-proof-context"
grep -q 'verify_cm_server_proof' "$REPO/src/ipc.rs" || r_s11c11="$r_s11c11 no-cm-server-proof-verify"
grep -q '&generation.launch_token' "$REPO/src/server/connection.rs" || r_s11c11="$r_s11c11 server-does-not-use-generation-bound-cm-launch-proof"
grep -q 'answer_cm_endpoint_challenge(&mut stream).await' "$REPO/src/ui_cm_interface.rs" || r_s11c11="$r_s11c11 cm-listener-does-not-answer-launch-proof"
grep -q 'authenticate_macos_cm_endpoint(&stream, expected_arg, generation.identity)' "$REPO/src/server/connection.rs" || r_s11c11="$r_s11c11 macos-cm-exact-process-not-checked"
grep -q 'pub(crate) fn authenticate_macos_cm_endpoint' "$REPO/src/ipc/auth.rs" || r_s11c11="$r_s11c11 macos-cm-auth-helper-missing"
grep -q 'let args = macos_process_cmdline_args(peer_pid)?;' "$REPO/src/ipc/auth.rs" || r_s11c11="$r_s11c11 macos-cm-process-argv-not-read"
grep -q 'if !cm_process_argv_is_expected(&args, expected_arg)' "$REPO/src/ipc/auth.rs" || r_s11c11="$r_s11c11 macos-cm-process-role-not-exact"
if grep -q 'pub(crate) async fn send_to_cm' "$REPO/src/ui_interface.rs" || grep -q 'ipc::connect(1000, "_cm")' "$REPO/src/ui_interface.rs"; then
  r_s11c11="$r_s11c11 raw-cm-ui-notification-helper-present"
fi
if grep -R -n -E 'Data::Theme|Data::Language|Theme\(String\)|Language\(String\)' "$REPO/src" >/dev/null; then
  r_s11c11="$r_s11c11 cm-theme-language-ipc-side-channel-present"
fi
grep -q 'libc::getppid()' "$REPO/src/ipc/auth.rs" || r_s11c11="$r_s11c11 macos-cm-listener-live-parent-not-checked"
grep -q 'peer_pid != Some(expected_parent_pid)' "$REPO/src/ipc/auth.rs" || r_s11c11="$r_s11c11 macos-cm-listener-exact-parent-peer-not-checked"
grep -q 'Refusing root-to-user connection-manager launch; the user-context service must own it' "$REPO/src/server/connection.rs" || r_s11c11="$r_s11c11 macos-root-to-user-cm-not-fail-closed"
if grep -q 'fn run_as_user' "$REPO/src/platform/macos.rs"; then
  r_s11c11="$r_s11c11 macos-root-to-user-launcher-present"
fi
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
macos_process_line=$(grep -n 'authenticate_macos_cm_endpoint(&stream, expected_arg, generation.identity)' "$REPO/src/server/connection.rs" | head -1 | cut -d: -f1 || true)
macos_proof_line=$(awk -v start="$macos_process_line" 'NR > start && /&generation.launch_token/ { print NR; exit }' "$REPO/src/server/connection.rs")
if [ -z "$macos_process_line" ] || [ -z "$macos_proof_line" ] || [ "$macos_process_line" -ge "$macos_proof_line" ]; then
  r_s11c11="$r_s11c11 macos-cm-proof-not-after-process-shape-check"
fi
for line in $(grep -n 'crate::ipc::connect(1000, "_cm")' "$REPO/src/server/connection.rs" | cut -d: -f1); do
  if ! sed -n "$((line-3)),$((line-1))p" "$REPO/src/server/connection.rs" | grep -q '#\[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))\]'; then
    r_s11c11="$r_s11c11 raw-macos-cm-connect-reintroduced"
    break
  fi
done
if [ -n "$r_s11c11" ]; then
  echo "  FAIL R-S11c-11 macOS CM endpoint-selection proof:$r_s11c11"
  rc=1
else
  note "ok  R-S11c-11/R-S11gi macOS CM selection retains and leases the exact launched child and proves its live launch parent before token-bearing login"
fi

echo "== (2b-iii-c) R-S11c-8/R-S11dz macOS whiteboard helper authority and resource finality =="
r_s11c8=
grep -q 'pub(crate) enum WhiteboardOwnerHandshake {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 owner-handshake-protocol-missing"
grep -q 'pub(crate) enum WhiteboardHelperHandshake {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 helper-handshake-protocol-missing"
grep -q 'pub(crate) enum WhiteboardIpcCommand {' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 command-protocol-missing"
whiteboard_envelopes=$(grep -B2 -E 'pub\(crate\) enum Whiteboard(OwnerHandshake|HelperHandshake|IpcCommand)' "$REPO/src/ipc.rs" || true)
[ "$(echo "$whiteboard_envelopes" | grep -c 'deny_unknown_fields')" -eq 3 ] || r_s11c8="$r_s11c8 directional-protocols-do-not-all-deny-unknown-fields"
grep -q 'pub(crate) const WHITEBOARD_IPC_MAX_FRAME_BYTES: usize = 64 \* 1024;' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 whiteboard-frame-cap-missing"
grep -q 'pub(crate) const WHITEBOARD_IPC_COMMAND_CAPACITY: usize = 64;' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 whiteboard-command-capacity-missing"
grep -q 'pub(crate) const WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS: usize = 16;' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 whiteboard-active-token-cap-missing"
grep -q 'pub(crate) const WHITEBOARD_IPC_IO_TIMEOUT_MS: u64 = 1_000;' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 whiteboard-io-deadline-missing"
grep -q 'Self::new_with_max_packet_length(conn, WHITEBOARD_IPC_MAX_FRAME_BYTES)' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 whiteboard-constructor-not-frame-capped"
grep -q 'pub(crate) async fn next_whiteboard_command_timeout' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 strict-command-reader-missing"
grep -q 'WHITEBOARD_LAUNCH_TOKEN_ENV' "$REPO/src/common.rs" || r_s11c8="$r_s11c8 no-whiteboard-launch-token-env"
grep -q 'WHITEBOARD_LAUNCH_PARENT_ENV' "$REPO/src/common.rs" || r_s11c8="$r_s11c8 no-whiteboard-launch-parent-env"
grep -q 'whiteboard_endpoint_postfix(&launch_token)' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 client-does-not-use-launch-scoped-endpoint"
grep -q 'authenticate_whiteboard_endpoint_launch_proof(&mut stream, launch_token)' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 client-does-not-authenticate-whiteboard-endpoint"
grep -q 'authorize_whiteboard_ipc_connection(&stream, expected_parent_pid)' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-does-not-check-parent-pid"
grep -q 'answer_whiteboard_endpoint_challenge(&mut stream).await' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-does-not-prove-launch-token"
grep -q 'const WHITEBOARD_PROCESS_ROLE: &str = "--whiteboard";' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 fixed-whiteboard-role-missing"
grep -q 'fn whiteboard_role_bound_challenge' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 whiteboard-role-bound-proof-missing"
grep -q 'let role = current_whiteboard_process_role()?' "$REPO/src/ipc.rs" || r_s11c8="$r_s11c8 whiteboard-proof-does-not-use-exact-current-role"
grep -q 'WhiteboardIpcState' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-state-machine-missing"
grep -q 'super::client::get_key_cursor(conn_id)' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-does-not-derive-render-key"
grep -q 'Connection::new_whiteboard(stream)' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 accepted-stream-not-frame-capped"
grep -q 'handle_new_stream(stream, &mut rx_exit).await' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 accepted-stream-not-owned"
grep -q 'next_whiteboard_command_timeout(ipc::WHITEBOARD_IPC_IO_TIMEOUT_MS)' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-command-read-not-bounded"
grep -q 'self.active.len() < ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-active-token-map-unbounded"
grep -q 'whiteboard_connection_token_is_valid(&token)' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 helper-accepts-malformed-token"
grep -q 'send_whiteboard_event("".to_string(), CustomEvent::Exit);' "$REPO/src/whiteboard/server.rs" || r_s11c8="$r_s11c8 terminal-stream-does-not-exit-overlay"
grep -q 'let (tx, mut rx) = channel(ipc::WHITEBOARD_IPC_COMMAND_CAPACITY);' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 client-command-channel-unbounded"
grep -q 'sender.try_send(command)' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 client-command-admission-not-nonblocking"
grep -q 'drop(tx);' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 local-sender-prevents-channel-closure"
grep -q 'send_whiteboard_command_timeout(' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 typed-deadline-command-writer-missing"
grep -q 'register_whiteboard(self.inner.id)' "$REPO/src/server/connection.rs" || r_s11c8="$r_s11c8 connection-register-not-id-based"
whiteboard_register_context=$(grep -B4 -A2 'register_whiteboard(self.inner.id)' "$REPO/src/server/connection.rs" || true)
echo "$whiteboard_register_context" | grep -q 'if self.is_authed_remote_conn()' || r_s11c8="$r_s11c8 register-not-remote-auth-type-gated"
grep -q 'Refusing root-to-user whiteboard launch; the user-context service must own it' "$REPO/src/whiteboard/client.rs" || r_s11c8="$r_s11c8 macos-root-to-user-whiteboard-not-fail-closed"
if grep -q 'fn run_as_user' "$REPO/src/platform/macos.rs"; then
  r_s11c8="$r_s11c8 macos-root-to-user-launcher-present"
fi
if grep -RIn 'Whiteboard((String' "$REPO/src/ipc.rs" "$REPO/src/whiteboard" 2>/dev/null >"$APPLE_CHECK_TMP/rd_apple_whiteboard_tuple"; then
  r_s11c8="$r_s11c8 legacy-whiteboard-tuple-message-present"
fi
if grep -RIn 'Data::Whiteboard((' "$REPO/src/whiteboard" "$REPO/src/server" 2>/dev/null >"$APPLE_CHECK_TMP/rd_apple_whiteboard_tuple_send"; then
  r_s11c8="$r_s11c8 legacy-whiteboard-tuple-send-present"
fi
if grep -q 'ipc::connect(1000, "_whiteboard")' "$REPO/src/whiteboard/client.rs"; then
  r_s11c8="$r_s11c8 raw-fixed-whiteboard-connect-present"
fi
if grep -q 'new_listener("_whiteboard")' "$REPO/src/whiteboard/server.rs"; then
  r_s11c8="$r_s11c8 fixed-whiteboard-listener-present"
fi
if grep -q 'tokio::spawn(handle_new_stream' "$REPO/src/whiteboard/server.rs"; then
  r_s11c8="$r_s11c8 detached-whiteboard-stream-handler-present"
fi
data_protocol=$(awk '/^pub enum Data \{/{capture=1} capture{print} capture && /^}/{exit}' "$REPO/src/ipc.rs")
if echo "$data_protocol" | grep -Eq 'Whiteboard(EndpointChallenge|EndpointProof|ServerChallenge|ServerProof|Bind|Event|Close|Shutdown)'; then
  r_s11c8="$r_s11c8 cross-purpose-data-retains-whiteboard-protocol"
fi
if grep -q 'allow_err!(stream' "$REPO/src/whiteboard/client.rs"; then
  r_s11c8="$r_s11c8 whiteboard-transport-error-ignored"
fi
grep -Fq '<span class="id">R-S11dz</span>' "$REPO/requirements.html" || r_s11c8="$r_s11c8 whiteboard-protocol-requirement-missing"
grep -Fq '<tr><td>279</td>' "$REPO/requirements.html" || r_s11c8="$r_s11c8 whiteboard-protocol-appendix-row-missing"
grep -Fq 'R-S11dz/R-S11e-144 — whiteboard helper protocol and resource finality' "$REPO/HARDENING_STATUS.md" || r_s11c8="$r_s11c8 whiteboard-protocol-ledger-missing"
if [ -n "$r_s11c8" ]; then
  echo "  FAIL R-S11c-8 macOS whiteboard helper authority:$r_s11c8"
  rc=1
else
  note "ok  R-S11c-8/R-S11dz macOS whiteboard uses closed directional protocols, a capped codec/queue/token map, exact launch and parent proof, one owned stream, deadline wakes, and terminal overlay exit"
fi

echo "== (2b-iii-c1) R-S11ea macOS desktop URL/instance closed bounded protocol =="
r_s11ea=
grep -q 'pub(crate) enum DesktopUrlIpcRequest {' "$REPO/src/ipc.rs" || r_s11ea="$r_s11ea request-protocol-missing"
desktop_url_envelope=$(grep -B2 -A4 'pub(crate) enum DesktopUrlIpcRequest {' "$REPO/src/ipc.rs" || true)
[ "$(echo "$desktop_url_envelope" | grep -c 'deny_unknown_fields')" -eq 1 ] || r_s11ea="$r_s11ea request-protocol-does-not-deny-unknown-fields"
for operation in 'OpenUrl { url: String },' 'Activate {},' 'CloseAll {},'; do
  echo "$desktop_url_envelope" | grep -Fq "$operation" || r_s11ea="$r_s11ea missing-$operation"
done
desktop_url_variants=$(echo "$desktop_url_envelope" | sed -n '/pub(crate) enum DesktopUrlIpcRequest {/,/^}/p' | grep -c '^    [A-Za-z]')
[ "$desktop_url_variants" -eq 3 ] || r_s11ea="$r_s11ea operation-vocabulary-not-exact"
grep -q 'pub(crate) const DESKTOP_URL_IPC_MAX_FRAME_BYTES: usize = 8 \* 1024;' "$REPO/src/ipc.rs" || r_s11ea="$r_s11ea frame-cap-missing"
grep -q 'pub(crate) const DESKTOP_URL_IPC_IO_TIMEOUT_MS: u64 = 1_000;' "$REPO/src/ipc.rs" || r_s11ea="$r_s11ea io-deadline-missing"
grep -q 'Self::new_with_max_packet_length(conn, DESKTOP_URL_IPC_MAX_FRAME_BYTES)' "$REPO/src/ipc.rs" || r_s11ea="$r_s11ea capped-constructor-missing"
[ "$(grep -c 'ConnectionTmpl::new_desktop_url(client)' "$REPO/src/ipc.rs")" -eq 2 ] || r_s11ea="$r_s11ea connecting-stream-cap-coverage-drift"
grep -q 'send_desktop_url_ipc_request(DesktopUrlIpcRequest::from_url(url)?).await' "$REPO/src/ipc.rs" || r_s11ea="$r_s11ea sender-validation-missing"
grep -q 'DesktopUrlIpcRequest::CloseAll {}' "$REPO/src/ipc.rs" || r_s11ea="$r_s11ea typed-close-sender-missing"
grep -q 'DesktopUrlIpcRequest::Activate {}' "$REPO/src/ipc.rs" || r_s11ea="$r_s11ea typed-activate-sender-missing"
desktop_url_receiver=$(sed -n '/pub async fn start_ipc_url_server()/,/^#\[cfg(test)\]/p' "$REPO/src/server.rs")
desktop_url_accept_line=$(echo "$desktop_url_receiver" | grep -n 'Connection::new_desktop_url(conn)' | head -1 | cut -d: -f1 || true)
desktop_url_auth_line=$(echo "$desktop_url_receiver" | grep -n 'authorize_url_ipc_sender(&conn)' | head -1 | cut -d: -f1 || true)
desktop_url_read_line=$(echo "$desktop_url_receiver" | grep -n 'next_desktop_url_request_timeout' | head -1 | cut -d: -f1 || true)
desktop_url_validate_line=$(echo "$desktop_url_receiver" | grep -n 'DesktopUrlIpcRequest::validate' | head -1 | cut -d: -f1 || true)
if [ -z "$desktop_url_accept_line" ] || [ -z "$desktop_url_auth_line" ] || [ -z "$desktop_url_read_line" ] || [ -z "$desktop_url_validate_line" ] \
    || [ "$desktop_url_accept_line" -ge "$desktop_url_auth_line" ] || [ "$desktop_url_auth_line" -ge "$desktop_url_read_line" ] \
    || [ "$desktop_url_read_line" -ge "$desktop_url_validate_line" ]; then
  r_s11ea="$r_s11ea receiver-cap-auth-read-validation-order"
fi
for event in on_url_scheme_received on_desktop_instance_activate_requested on_desktop_instances_close_requested; do
  echo "$desktop_url_receiver" | grep -Fq "\"name\": \"$event\"" || r_s11ea="$r_s11ea rust-event-$event-missing"
  grep -Fq "name == '$event'" "$REPO/flutter/lib/models/model.dart" || r_s11ea="$r_s11ea dart-event-$event-missing"
done
grep -q 'crate::ipc::activate_main_instance()' "$REPO/src/platform/macos.rs" || r_s11ea="$r_s11ea macos-typed-activation-missing"
data_protocol=$(awk '/^pub enum Data \{/{capture=1} capture{print} capture && /^}/{exit}' "$REPO/src/ipc.rs")
if echo "$data_protocol" | grep -q 'UrlLink'; then r_s11ea="$r_s11ea cross-purpose-data-url-variant"; fi
if grep -RInE 'IPC_ACTION_CLOSE|kUrlActionClose|handle_url_scheme\(""' \
    "$REPO/src/ipc.rs" "$REPO/src/platform/macos.rs" "$REPO/flutter/lib/consts.dart" "$REPO/flutter/lib/models/model.dart" >/dev/null; then
  r_s11ea="$r_s11ea string-control-sentinel"
fi
if echo "$desktop_url_receiver" | grep -Eq 'Connection::new\(conn\)|next_timeout\(1000\)|Data::UrlLink'; then
  r_s11ea="$r_s11ea legacy-unbounded-receiver"
fi
grep -Fq '<span class="id">R-S11ea</span>' "$REPO/requirements.html" || r_s11ea="$r_s11ea requirement-missing"
grep -Fq '<tr><td>280</td>' "$REPO/requirements.html" || r_s11ea="$r_s11ea appendix-row-missing"
grep -Fq 'R-S11ea/R-S11e-145 — desktop URL/instance handoff closed protocol and resource budget' "$REPO/HARDENING_STATUS.md" || r_s11ea="$r_s11ea ledger-missing"
if [ -n "$r_s11ea" ]; then
  echo "  FAIL R-S11ea macOS desktop URL/instance IPC:$r_s11ea"
  rc=1
else
  note "ok  R-S11ea macOS desktop URL/instance IPC authenticates before one strict typed request, caps both stream ends and I/O time, revalidates direct-address URLs, and dispatches distinct open/activate/close events without sentinels"
fi

echo "== (2b-iv) R-S11c-5 macOS privileged-service packaging =="
r_s11c5=
daemon_plist="$REPO/src/platform/privileges_scripts/daemon.plist"
install_scpt="$REPO/src/platform/privileges_scripts/install.scpt"
update_scpt="$REPO/src/platform/privileges_scripts/update.scpt"
uninstall_scpt="$REPO/src/platform/privileges_scripts/uninstall.scpt"
macos_rs="$REPO/src/platform/macos.rs"
macos_production_source=$(awk '/^#\[cfg\(test\)\]/{exit} {print}' "$macos_rs")
macos_helper_command_sources=("$REPO/src/platform/macos.rs" "$REPO/src/ipc.rs" "$REPO/src/ipc/auth.rs")
daemon_args_block=$(awk '/<key>ProgramArguments<\/key>/,/<\/array>/' "$daemon_plist")
echo "$daemon_args_block" | grep -q '<string>/Library/PrivilegedHelperTools/com.carriez.rustdesk_service</string>' || r_s11c5="$r_s11c5 daemon-not-privileged-helper-exec"
if echo "$daemon_args_block" | grep -qE '<string>/(bin|usr/bin)/(sh|bash)</string>|<string>-c</string>'; then
  r_s11c5="$r_s11c5 daemon-shell-launch"
fi
grep -q '<string>/Library/Application Support/RustDesk</string>' "$daemon_plist" || r_s11c5="$r_s11c5 daemon-working-dir-not-root-support"
grep -q '<string>/Library/Logs/RustDesk/rustdesk_service.err</string>' "$daemon_plist" || r_s11c5="$r_s11c5 daemon-stderr-not-library-log"
grep -q '<string>/Library/Logs/RustDesk/rustdesk_service.out</string>' "$daemon_plist" || r_s11c5="$r_s11c5 daemon-stdout-not-library-log"
[ ! -e "$update_scpt" ] || r_s11c5="$r_s11c5 update-scpt-present"
if grep -RInE 'update_daemon_agent|update_source_dir|\.rustdeskupdate|get_update_temp_dir|try_remove_temp_update_dir|update\.scpt' \
  "$REPO/src/platform/macos.rs" "$REPO/src/core_main.rs" "$REPO/src/flutter_ffi.rs" "$REPO/src/ui_interface.rs" "$REPO/src/platform/privileges_scripts" 2>/dev/null >"$APPLE_CHECK_TMP/rd_apple_macos_update"; then
  r_s11c5="$r_s11c5 macos-privileged-update-surface-present"
fi
for command in osascript launchctl open ls ioreg codesign; do
  if grep -F "Command::new(\"$command\")" "${macos_helper_command_sources[@]}" >/dev/null; then
    r_s11c5="$r_s11c5 macos-path-selected-$command"
  fi
done
for system_path in /usr/bin/osascript /bin/launchctl /usr/bin/open /usr/sbin/ioreg; do
  grep -F "\"$system_path\"" "${macos_helper_command_sources[@]}" >/dev/null || r_s11c5="$r_s11c5 macos-absolute-${system_path##*/}-missing"
done
grep -Fq 'println!("cargo:rustc-link-lib=framework=IOKit");' "$REPO/build.rs" || r_s11c5="$r_s11c5 macos-iokit-link-missing"
grep -Fq '#import <IOKit/pwr_mgt/IOPMLib.h>' "$REPO/src/platform/macos.mm" || r_s11c5="$r_s11c5 macos-iopmlib-import-missing"
grep -Fq 'extern "C" bool MacDeclareRemoteUserActivity()' "$REPO/src/platform/macos.mm" || r_s11c5="$r_s11c5 macos-user-activity-native-helper-missing"
grep -Fq 'IOPMAssertionDeclareUserActivity(' "$REPO/src/platform/macos.mm" || r_s11c5="$r_s11c5 macos-user-activity-iopm-call-missing"
grep -Fq 'kIOPMUserActiveRemote' "$REPO/src/platform/macos.mm" || r_s11c5="$r_s11c5 macos-user-activity-not-remote"
grep -Fq 'crate::platform::declare_remote_user_activity();' "$REPO/src/server.rs" || r_s11c5="$r_s11c5 macos-server-native-user-activity-not-wired"
if grep -Fq 'caffeinate' "$REPO/src/server.rs" "$REPO/src/platform/macos.rs"; then
  r_s11c5="$r_s11c5 macos-caffeinate-subprocess-present"
fi
for obsolete in 'fn run_as_user' 'fn run_as_user_with_env' 'command.arg("asuser")' 'macos_launch_env_key_is_allowed' '/usr/bin/env'; do
  if grep -Fq "$obsolete" <<<"$macos_production_source"; then
    r_s11c5="$r_s11c5 macos-root-to-user-launcher-present:$obsolete"
  fi
done
grep -Fq 'const MACOS_OPEN: &str = "/usr/bin/open";' "$macos_rs" || r_s11c5="$r_s11c5 macos-open-absolute-missing"
grep -Fq 'Command::new(MACOS_OPEN)' "$macos_rs" || r_s11c5="$r_s11c5 macos-reopen-not-absolute"
grep -Fq 'const MACOS_PRIVILEGED_HELPER_EXEC: &str =' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-service-ipc-helper-const-missing"
grep -Fq '/Library/PrivilegedHelperTools/com.carriez.rustdesk_service' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-service-ipc-helper-path-missing"
grep -Fq 'const MACOS_PRIVILEGED_HELPER_DIR: &str = "/Library/PrivilegedHelperTools";' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-service-ipc-helper-dir-const-missing"
grep -Fq 'security-framework = "2.10"' "$REPO/Cargo.toml" || r_s11c5="$r_s11c5 macos-security-framework-direct-dependency-missing"
grep -Fq 'const MACOS_PRIVILEGED_HELPER_REQUIREMENT: &str =' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-helper-code-requirement-const-missing"
grep -Fq 'certificate leaf[subject.OU] = "HZF9JMC8YN"' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-helper-teamid-requirement-missing"
grep -Fq 'identifier "service" or identifier "com.carriez.rustdesk_service"' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-helper-identifier-requirement-missing"
grep -Fq 'const MACOS_INSTALLED_APP_REQUIREMENT: &str =' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-app-code-requirement-const-missing"
grep -Fq 'identifier "com.carriez.rustdesk"' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-app-identifier-requirement-missing"
grep -Fq 'fn render_macos_service_template(s: &str) -> String' "$macos_rs" || r_s11c5="$r_s11c5 macos-service-template-renderer-missing"
if grep -qE 'fn correct_app_name|fn get_bundle_id|bundleIdentifier' "$macos_rs"; then
  r_s11c5="$r_s11c5 macos-privileged-template-live-bundle-id-rewrite-present"
fi
macos_template_renderer=$(awk '/fn render_macos_service_template\(s: &str\) -> String/,/^}/' "$macos_rs")
echo "$macos_template_renderer" | grep -Fq '"/Applications/RustDesk.app/Contents/MacOS/RustDesk"' || r_s11c5="$r_s11c5 macos-template-app-executable-source-missing"
echo "$macos_template_renderer" | grep -Fq '&app_executable' || r_s11c5="$r_s11c5 macos-template-app-executable-target-missing"
echo "$macos_template_renderer" | grep -Fq '"com.carriez.RustDesk_service"' || r_s11c5="$r_s11c5 macos-template-service-label-source-missing"
echo "$macos_template_renderer" | grep -Fq '&service_label' || r_s11c5="$r_s11c5 macos-template-service-label-target-missing"
echo "$macos_template_renderer" | grep -Fq '"com.carriez.RustDesk_server"' || r_s11c5="$r_s11c5 macos-template-server-label-source-missing"
echo "$macos_template_renderer" | grep -Fq '&server_label' || r_s11c5="$r_s11c5 macos-template-server-label-target-missing"
if echo "$macos_template_renderer" | grep -qE 'replace\("com\.carriez\.rustdesk"|replace\("rustdesk"'; then
  r_s11c5="$r_s11c5 macos-template-fixed-lowercase-identifier-rewritten"
fi
grep -Fq '<string>com.carriez.rustdesk</string>' "$REPO/src/platform/privileges_scripts/daemon.plist" || r_s11c5="$r_s11c5 macos-daemon-associated-bundle-id-not-fixed"
grep -Fq '<string>com.carriez.rustdesk</string>' "$REPO/src/platform/privileges_scripts/agent.plist" || r_s11c5="$r_s11c5 macos-agent-associated-bundle-id-not-fixed"
grep -Fq 'macOS privileged service template identity input' "$REPO/requirements.html" || r_s11c5="$r_s11c5 macos-template-identity-requirements-missing"
grep -Fq 'R-S11c-21 — macOS privileged service template identity input' "$REPO/HARDENING_STATUS.md" || r_s11c5="$r_s11c5 macos-template-identity-ledger-missing"
grep -Fq 'macOS residual process launch provenance' "$REPO/requirements.html" || r_s11c5="$r_s11c5 macos-residual-process-launch-requirements-missing"
grep -Fq 'R-S11e-10 — macOS residual process launch provenance' "$REPO/HARDENING_STATUS.md" || r_s11c5="$r_s11c5 macos-residual-process-launch-ledger-missing"
grep -Fq 'fn macos_installed_app_bundle_path() -> PathBuf' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-app-bundle-path-helper-missing"
grep -Fq 'fn macos_privileged_helper_path_is_expected_and_trusted(current_exe: &Path) -> bool' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-service-ipc-helper-trust-missing"
grep -Fq 'fn macos_installed_app_path_is_expected_and_trusted(peer_exe: &Path) -> bool' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-service-ipc-app-trust-missing"
grep -Fq 'fn macos_path_has_no_extended_acl(path: &Path) -> bool' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-acl-check-missing"
grep -Fq 'CString::new(path.as_os_str().as_bytes().to_vec())' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-acl-cstring-missing"
grep -Fq 'acl_get_link_np(path_c.as_ptr(), MACOS_ACL_TYPE_EXTENDED)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-acl-get-link-missing"
grep -Fq 'acl_valid_link_np(path_c.as_ptr(), MACOS_ACL_TYPE_EXTENDED, acl)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-acl-valid-link-missing"
grep -Fq 'acl_get_entry(acl, MACOS_ACL_FIRST_ENTRY, &mut entry)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-acl-entry-missing"
grep -Fq 'acl_free(self.0)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-acl-free-missing"
grep -Fq 'macOS runtime service ACL inspection provenance' "$REPO/requirements.html" || r_s11c5="$r_s11c5 macos-runtime-acl-requirements-missing"
grep -Fq 'R-S11c-17 — macOS runtime service ACL inspection provenance' "$REPO/HARDENING_STATUS.md" || r_s11c5="$r_s11c5 macos-runtime-acl-ledger-missing"
grep -Fq 'macOS privileged installer ACL enforcement provenance' "$REPO/requirements.html" || r_s11c5="$r_s11c5 macos-installer-acl-requirements-missing"
grep -Fq 'R-S11c-18 — macOS privileged installer ACL enforcement provenance' "$REPO/HARDENING_STATUS.md" || r_s11c5="$r_s11c5 macos-installer-acl-ledger-missing"
grep -Fq 'fn macos_path_has_expected_type_and_permissions(' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-mode-check-helper-missing"
grep -Fq 'fn macos_privileged_helper_satisfies_code_requirement(path: &Path) -> bool' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-helper-codesign-check-missing"
grep -Fq 'fn macos_installed_app_satisfies_code_requirement(path: &Path) -> bool' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-app-codesign-check-missing"
grep -Fq 'MacosSecStaticCode::from_path(&url, MacosCodeSigningFlags::NONE)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-static-code-check-not-native"
grep -Fq 'MacosCodeSigningFlags::STRICT_VALIDATE' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-code-requirement-not-strict"
grep -Fq 'MacosCodeSigningFlags::CHECK_ALL_ARCHITECTURES' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-static-code-all-architectures-missing"
grep -Fq 'MacosCodeSigningFlags::CHECK_NESTED_CODE' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-static-app-nested-code-check-missing"
grep -Fq 'code.check_validity(validation_flags, &requirement)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-static-code-validation-flags-not-used"
if grep -Fq 'Command::new(MACOS_CODESIGN)' "$REPO/src/ipc/auth.rs" || grep -Fq 'const MACOS_CODESIGN' "$REPO/src/ipc/auth.rs"; then
  r_s11c5="$r_s11c5 macos-rust-codesign-subprocess-present"
fi
if grep -Fq 'Command::new(MACOS_LS)' "$REPO/src/ipc/auth.rs" \
  || grep -Fq 'const MACOS_LS' "$REPO/src/ipc/auth.rs" \
  || grep -Fq 'Command::new("/bin/ls")' "${macos_helper_command_sources[@]}" \
  || grep -Fq 'Command::new("ls")' "${macos_helper_command_sources[@]}"; then
  r_s11c5="$r_s11c5 macos-runtime-acl-ls-parser-present"
fi
grep -Fq 'MACOS_PRIVILEGED_HELPER_REQUIREMENT' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-helper-requirement-not-used"
grep -Fq 'MACOS_INSTALLED_APP_REQUIREMENT' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-app-requirement-not-used"
grep -Fq 'fs::symlink_metadata(path)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-symlink-metadata-missing"
grep -Fq 'metadata.file_type().is_symlink()' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-symlink-gate-missing"
grep -Fq 'macos_root_wheel_not_group_world_writable(&metadata)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-helper-root-wheel-mode-gate-missing"
grep -Fq 'macos_root_owned_not_group_world_writable(&metadata)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-app-root-owned-mode-gate-missing"
grep -Fq 'require_executable && metadata.permissions().mode() & 0o111 == 0' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-runtime-exec-mode-gate-missing"
grep -Fq 'macos_privileged_helper_satisfies_code_requirement(expected)' "$REPO/src/ipc/auth.rs" || r_s11c5="$r_s11c5 macos-service-ipc-helper-code-requirement-not-enforced"
macos_service_identity_block=$(awk '/fn macos_service_ipc_allows_installed_app_and_privileged_helper/,/^}/' "$REPO/src/ipc/auth.rs")
echo "$macos_service_identity_block" | grep -Fq 'macos_privileged_helper_path_is_expected_and_trusted(current_exe)' || r_s11c5="$r_s11c5 macos-service-ipc-current-helper-not-verified"
echo "$macos_service_identity_block" | grep -Fq 'macos_peer_is_trusted_installed_app(peer_identity)' || r_s11c5="$r_s11c5 macos-service-ipc-peer-app-not-verified"
macos_app_trust_block=$(awk '/fn macos_installed_app_path_is_expected_and_trusted/,/^}/' "$REPO/src/ipc/auth.rs")
echo "$macos_app_trust_block" | grep -Fq 'macos_installed_app_executable_path()' || r_s11c5="$r_s11c5 macos-app-executable-path-not-checked"
echo "$macos_app_trust_block" | grep -Fq 'macos_path_has_expected_type_and_permissions(&app_executable, false, true, false)' || r_s11c5="$r_s11c5 macos-app-executable-permissions-not-checked"
echo "$macos_app_trust_block" | grep -Fq 'macos_installed_app_satisfies_code_requirement(&app_bundle)' || r_s11c5="$r_s11c5 macos-app-code-requirement-not-enforced"
line_app_check=$(grep -n 'macos_peer_is_trusted_installed_app(peer_identity)' "$REPO/src/ipc/auth.rs" | tail -n 1 | cut -d: -f1)
line_helper_check=$(grep -n 'macos_privileged_helper_path_is_expected_and_trusted(current_exe)' "$REPO/src/ipc/auth.rs" | tail -n 1 | cut -d: -f1)
if [ -z "$line_app_check" ] || [ -z "$line_helper_check" ] || [ "$line_app_check" -ge "$line_helper_check" ]; then
  r_s11c5="$r_s11c5 macos-service-ipc-helper-checked-before-app-peer"
fi
if grep -q 'macos_service_ipc_allows_gui_and_service_binaries' "$REPO/src/ipc/auth.rs"; then
  r_s11c5="$r_s11c5 macos-service-ipc-old-gui-service-binary-model-present"
fi
if echo "$macos_service_identity_block" | grep -qE 'peer_dir|current_dir|OsStr::new\("service"\)|executable_paths_match\(peer_dir, current_dir\)'; then
  r_s11c5="$r_s11c5 macos-service-ipc-old-same-directory-model-present"
fi
grep -q 'pub(crate) fn console_owner_uid' "$macos_rs" || r_s11c5="$r_s11c5 macos-console-owner-uid-missing"
grep -Fq 'std::fs::metadata("/dev/console")' "$macos_rs" || r_s11c5="$r_s11c5 macos-console-owner-not-dev-console-backed"
grep -q 'hbb_common::libc::getpwuid_r' "$macos_rs" || r_s11c5="$r_s11c5 macos-active-user-not-passwd-r-backed"
if grep -q 'fn get_active_user(t: &str)' "$macos_rs" || grep -q 'split_whitespace().nth(2)' "$macos_rs"; then
  r_s11c5="$r_s11c5 macos-active-user-ls-parser-present"
fi
if grep -q '/tmp/rustdesk_service' "$daemon_plist" "$install_scpt" "$uninstall_scpt"; then
  r_s11c5="$r_s11c5 tmp-daemon-log-path"
fi
if grep -q '/Applications/RustDesk.app/Contents/MacOS/service' "$daemon_plist"; then
  r_s11c5="$r_s11c5 app-bundle-root-service-path"
fi
grep -Fq 'bundled_service_exec: PathBuf' "$macos_rs" || r_s11c5="$r_s11c5 macos-install-context-no-bundled-helper"
grep -Fq 'fn bundled_service_executable() -> Option<PathBuf>' "$macos_rs" || r_s11c5="$r_s11c5 macos-bundled-helper-resolver-missing"
grep -Fq '.arg(&context.bundled_service_exec)' "$macos_rs" || r_s11c5="$r_s11c5 macos-install-does-not-pass-bundled-helper"
script="$install_scpt"
script_sh_line=$(grep 'set sh to' "$script")
grep -q 'on run {daemon_file, agent_file, bundled_service_exec}' "$script" || r_s11c5="$r_s11c5 install-does-not-take-bundled-helper"
grep -q 'set temp_service_exec to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-temp-helper-missing"
grep -q 'set cleanup_temp to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-temp-helper-cleanup-missing"
grep -q 'set reject_symlinks to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-symlink-reject"
grep -q 'set helper_requirement to "=anchor apple generic' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-requirement-missing"
grep -q 'certificate leaf\[subject.OU\] = \\"HZF9JMC8YN\\"' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-teamid-requirement-missing"
grep -q 'identifier \\"service\\" or identifier \\"com.carriez.rustdesk_service\\"' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-identifier-requirement-missing"
grep -q 'quoted form of helper_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-dir-symlink-not-checked"
grep -q 'quoted form of service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-service-exec-symlink-not-checked"
grep -q 'quoted form of bundled_service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-bundled-helper-not-checked"
grep -q 'set verify_bundled_service_exec to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-bundled-helper-verifier"
grep -q 'set install_service_exec to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-helper-installer"
grep -q 'set verify_service_exec to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-service-exec-verifier"
grep -q '/usr/bin/codesign --verify --strict --all-architectures -R " & quoted form of helper_requirement' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-codesign-check-missing"
grep -q '/usr/bin/install -o root -g wheel -m 0755 " & quoted form of bundled_service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-not-installed-from-bundle"
grep -q '/usr/bin/cmp -s " & quoted form of bundled_service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-copy-not-byte-checked"
grep -q '/Library/PrivilegedHelperTools' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-dir-not-used"
grep -q '/Library/PrivilegedHelperTools/com.carriez.rustdesk_service' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-exec-not-used"
grep -q "/usr/bin/stat -f '%Su:%Sg'" "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-owner-not-statted"
grep -q 'root:wheel' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-root-wheel-not-required"
grep -q -- '-perm +022' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-write-bit-not-rejected"
grep -qF '/bin/chmod -N \"$service_component\"' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-acl-postcondition-missing"
if grep -qE '/bin/ls -lde|NR > 1 \{exit 1\}' "$script"; then
  r_s11c5="$r_s11c5 $(basename "$script")-helper-acl-formatter-parser-present"
fi
grep -qF '[ ! -f " & quoted form of service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-service-exec-file-not-required"
grep -qF '[ ! -x " & quoted form of service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-service-exec-executable-not-required"
grep -q '/usr/bin/install -d -o root -g wheel -m 0755' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-root-dir-install"
grep -q 'quoted form of log_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-log-dir"
grep -q 'quoted form of log_stderr' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-stderr-log-path"
grep -q 'quoted form of log_stdout' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-stdout-log-path"
grep -q 'quoted form of support_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-support-dir"
grep -q 'quoted form of root_prefs_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-root-prefs-dir"
grep -q '/bin/chmod -N " & quoted form of log_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-dirs-acl-not-cleared"
grep -q '/bin/rm -f " & quoted form of log_stderr' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-logs-not-recreated"
grep -q '/bin/chmod -N " & quoted form of log_stderr' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-log-acl-not-cleared"
grep -q '/usr/bin/printf %s " & quoted form of daemon_file' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-daemon-plist-not-printf-written"
grep -q '/usr/bin/printf %s " & quoted form of agent_file' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-agent-plist-not-printf-written"
grep -q '/bin/chmod -N " & quoted form of daemon_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-daemon-plist-acl-not-cleared"
grep -q '/bin/chmod -N " & quoted form of agent_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-agent-plist-acl-not-cleared"
grep -q '/bin/chmod 0644 " & quoted form of daemon_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-daemon-plist-mode-missing"
grep -q '/bin/chmod 0644 " & quoted form of agent_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-agent-plist-mode-missing"
echo "$script_sh_line" | grep -q 'reject_symlinks.*verify_bundled_service_exec.*create_helper_dir.*secure_helper_dir.*install_service_exec.*verify_service_exec.*write_daemon_plist.*write_agent_plist.*verify_service_exec.*load_service' || r_s11c5="$r_s11c5 install-helper-not-installed-and-reverified-before-load"
grep -q 'set remove_service_exec to "/bin/rm -f " & quoted form of service_exec' "$uninstall_scpt" || r_s11c5="$r_s11c5 uninstall-does-not-remove-helper"
grep -q 'quoted form of temp_service_exec' "$uninstall_scpt" || r_s11c5="$r_s11c5 uninstall-does-not-remove-temp-helper"
grep -q 'quoted form of service_exec' "$uninstall_scpt" || r_s11c5="$r_s11c5 uninstall-helper-path-not-quoted"
if grep -qE 'verify_app_bundle_tree|secure_app|copy_user_prefs|user_home|root_prefs_file|root_prefs2_file|/bin/cp -f|/usr/sbin/chown -R root:wheel " & quoted form of app_bundle' "$install_scpt"; then
  r_s11c5="$r_s11c5 install-adopts-app-or-user-config"
fi
if grep -qE 'chown -R .*:staff|quoted form of user & ":staff"|/Users/" & user|echo " & quoted form of (daemon|agent)_file' "$install_scpt"; then
  r_s11c5="$r_s11c5 user-owned-or-echo-plist-install"
fi
if grep -qE '> " & (daemon|agent)_plist|launchctl unload -w " & daemon_plist|/bin/rm /Library/Launch' "$install_scpt" "$uninstall_scpt"; then
  r_s11c5="$r_s11c5 unquoted-privileged-path"
fi
if grep -qE 'let active_user_home|arg\(active_user_home\)|arg\(&active_user_home\)' "$REPO/src/platform/macos.rs"; then
  r_s11c5="$r_s11c5 macos-install-imports-active-user-home"
fi
if [ -n "$r_s11c5" ]; then
  echo "  FAIL R-S11c-5 macOS privileged-service packaging:$r_s11c5"
  rc=1
else
  note "ok  R-S11c-5 LaunchDaemon uses a signed root-owned PrivilegedHelperTools executable, and _service IPC identity matches that deployed helper model; dormant updater and active-user config import are absent"
fi

echo "== (2b-iii-c5a) macOS privileged helper current-build binding (R-S11au/R-S11e-61) =="
r_s11e61=
python3 "$REPO/scripts/verify-macos-helper-build-binding.py" --repo "$REPO" \
  || r_s11e61="$r_s11e61 macos-helper-build-binding-semantic-invalid"
python3 "$REPO/scripts/verify-macos-helper-build-binding.py" --repo "$REPO" --self-test \
  || r_s11e61="$r_s11e61 macos-helper-build-binding-mutations-invalid"
python3 -m py_compile "$REPO/scripts/verify-macos-helper-build-binding.py" \
  || r_s11e61="$r_s11e61 validator-python-syntax-invalid"
if [ -n "$r_s11e61" ]; then
  echo "  FAIL R-S11e-61 macOS helper current-build binding:$r_s11e61"
  rc=1
else
  note "ok  R-S11e-61 signed installed-app nested code, deployed helper bytes, stale-upgrade detection/reinstall, and partial-state uninstall share one current-build authority"
fi

echo "== (2b-iii-c5b) macOS variadic file-creation ABI (R-S11av/R-S11e-62) =="
r_s11e62=
python3 "$REPO/scripts/verify-macos-variadic-open-mode.py" --repo "$REPO" \
  || r_s11e62="$r_s11e62 macos-variadic-open-mode-semantic-invalid"
python3 "$REPO/scripts/verify-macos-variadic-open-mode.py" --repo "$REPO" --self-test \
  || r_s11e62="$r_s11e62 macos-variadic-open-mode-mutations-invalid"
python3 -m py_compile "$REPO/scripts/verify-macos-variadic-open-mode.py" \
  || r_s11e62="$r_s11e62 validator-python-syntax-invalid"
if [ -n "$r_s11e62" ]; then
  echo "  FAIL R-S11e-62 macOS variadic file-creation ABI:$r_s11e62"
  rc=1
else
  note "ok  R-S11e-62 macOS-reachable variadic creation modes are ABI-promoted while fixed-prototype mode_t calls remain exact"
fi

echo "== (2b-iv-a) Cross-platform root-to-user helper authority is closed (R-S11x/R-S11e-38) =="
r_s11e38=
for obsolete in 'fn run_as_user' 'fn run_as_user_with_env' 'command.arg("asuser")' 'macos_launch_env_key_is_allowed'; do
  if grep -Fq "$obsolete" "$macos_rs"; then
    r_s11e38="$r_s11e38 macos-generic-root-to-user-launch-present:$obsolete"
  fi
done
grep -Fq 'Refusing root-to-user connection-manager launch; the user-context service must own it' "$REPO/src/server/connection.rs" || r_s11e38="$r_s11e38 cm-root-transition-not-fail-closed"
grep -Fq 'Refusing root-to-user whiteboard launch; the user-context service must own it' "$REPO/src/whiteboard/client.rs" || r_s11e38="$r_s11e38 whiteboard-root-transition-not-fail-closed"
grep -Fq '<span class="id">R-S11x</span>' "$REPO/requirements.html" || r_s11e38="$r_s11e38 normative-requirement-missing"
grep -Fq '<tr><td>146</td>' "$REPO/requirements.html" || r_s11e38="$r_s11e38 appendix-disposition-missing"
grep -Fq 'R-S11e-38 — cross-platform root-to-user helper launch authority' "$REPO/HARDENING_STATUS.md" || r_s11e38="$r_s11e38 hardening-ledger-missing"
if [ -n "$r_s11e38" ]; then
  echo "  FAIL R-S11e-38 cross-platform root-to-user helper authority:$r_s11e38"
  rc=1
else
  note "ok  R-S11e-38 macOS carries no generic root-to-user CM/whiteboard launcher and unexpected root transitions fail closed"
fi

echo "== (2b-iv-a-0a) macOS numeric service-principal authority (R-S11ag/R-S11e-47) =="
r_s11e47=
macos_root_policy=$(awk '/fn effective_uid_is_root\(/,/#\[cfg\(test\)\]/' "$macos_rs")
macos_service_entry=$(awk '/pub fn start_os_service\(/,/#\[cfg\(test\)\]/' "$macos_rs")
macos_root_test=$(awk '/fn r_s11e47_macos_root_principal_is_numeric_effective_uid\(\)/,/^    }/' "$macos_rs")
macos_core_service_entry=$(awk '/#\[cfg\(target_os = "macos"\)\]/{capture=1} capture{print} capture && /#\[cfg\(target_os = "linux"\)\]/{exit}' "$REPO/src/core_main.rs")
macos_service_binary=$(cat "$REPO/src/service.rs")
for binding in \
  'fn effective_uid_is_root(effective_uid: hbb_common::libc::uid_t) -> bool {' \
  'effective_uid == 0' \
  'effective_uid_is_root(unsafe { hbb_common::libc::geteuid() })'; do
  grep -qF "$binding" <<<"$macos_root_policy" || r_s11e47="$r_s11e47 numeric-effective-uid-policy-missing"
done
if grep -qF 'crate::username() == "root"' <<<"$macos_root_policy"; then
  r_s11e47="$r_s11e47 account-name-root-policy-present"
fi
for binding in \
  'pub fn start_os_service() -> ResultType<()> {' \
  'if !is_root() {' \
  'bail!("macOS --service requires effective UID 0");' \
  'log::info!("Username: {}", crate::username());' \
  'crate::ipc::start(crate::POSTFIX_SERVICE)'; do
  grep -qF "$binding" <<<"$macos_service_entry" || r_s11e47="$r_s11e47 service-receiver-principal-boundary-missing"
done
service_guard_line=$(grep -nF 'if !is_root() {' <<<"$macos_service_entry" | cut -d: -f1 || true)
service_log_line=$(grep -nF 'log::info!("Username: {}", crate::username());' <<<"$macos_service_entry" | cut -d: -f1 || true)
service_listener_line=$(grep -nF 'crate::ipc::start(crate::POSTFIX_SERVICE)' <<<"$macos_service_entry" | cut -d: -f1 || true)
if [ -z "$service_guard_line" ] || [ -z "$service_log_line" ] || [ -z "$service_listener_line" ] \
  || [ "$service_guard_line" -ge "$service_log_line" ] || [ "$service_log_line" -ge "$service_listener_line" ]; then
  r_s11e47="$r_s11e47 service-principal-check-order-invalid"
fi
for binding in \
  '#[cfg(target_os = "macos")]' \
  'if service_supervisor_role == crate::common::ServiceSupervisorRole::Exact {' \
  'if let Err(err) = crate::platform::macos::run_service() {' \
  'eprintln!("macOS service bootstrap authority failed closed: {err}");' \
  'std::process::exit(1);'; do
  grep -qF "$binding" <<<"$macos_core_service_entry" || r_s11e47="$r_s11e47 common-service-entry-error-propagation-missing"
done
for binding in \
  '#[cfg(target_os = "macos")]' \
  'if let Err(err) = crate::platform::macos::run_service() {' \
  'eprintln!("macOS service bootstrap authority failed closed: {err}");' \
  'std::process::exit(1);'; do
  grep -qF "$binding" <<<"$macos_service_binary" || r_s11e47="$r_s11e47 dedicated-service-entry-error-propagation-missing"
done
for binding in \
  'fn r_s11e47_macos_root_principal_is_numeric_effective_uid()' \
  'assert!(effective_uid_is_root(0));' \
  'assert!(!effective_uid_is_root(1));' \
  'assert!(!effective_uid_is_root(501));'; do
  grep -qF "$binding" <<<"$macos_root_test" || r_s11e47="$r_s11e47 numeric-root-regression-missing"
done
grep -qF '<span class="id">R-S11ag</span>' "$REPO/requirements.html" || r_s11e47="$r_s11e47 normative-requirement-missing"
grep -qF '<tr><td>155</td>' "$REPO/requirements.html" || r_s11e47="$r_s11e47 appendix-disposition-missing"
grep -qF 'R-S11e-47 — macOS numeric service-principal authority' "$REPO/HARDENING_STATUS.md" || r_s11e47="$r_s11e47 hardening-ledger-missing"
if [ -n "$r_s11e47" ]; then
  echo "  FAIL R-S11e-47 macOS numeric service-principal authority:$r_s11e47"
  rc=1
else
  note "ok  R-S11e-47 macOS source binds the protected service listener to numeric effective UID 0 and propagates rejection at both entries; native Apple evidence remains pending R-R2/R-B2"
fi

echo "== (2b-iv-a-0b) macOS service-owned config/log root (R-S11al/R-S11e-52) =="
r_s11e52=
config_rs="$REPO/libs/hbb_common/src/config.rs"
macos_service_home=$(awk '/fn service_principal_home\(\)/,/pub fn run_service\(\)/' "$macos_rs")
macos_service_bootstrap=$(awk '/pub fn run_service\(\)/,/#\[cfg\(test\)\]/' "$macos_rs")
macos_config_root=$(awk '/struct MacosServiceOwnedConfigRoot/,/#\[cfg\(target_os = "linux"\)\]/{print}' "$config_rs")
macos_config_get_home=$(awk '/pub fn get_home\(\)/,/^    }/' "$config_rs")
macos_config_initialize=$(awk '/pub fn initialize_macos_service_owned_root\(/,/#\[cfg\(target_os = "linux"\)\]/{print}' "$config_rs")
macos_config_path=$(awk '/pub fn path<P: AsRef<Path>>\(p: P\)/{in_path=1} in_path && /#\[cfg\(target_os = "macos"\)\]/{capture=1} capture{print} capture && /#\[cfg\(target_os = "linux"\)\]/{exit}' "$config_rs")
macos_config_log_path=$(awk '/pub fn log_path\(\)/,/pub fn ipc_path\(postfix/' "$config_rs")
macos_config_test=$(awk '/fn r_s11e52_macos_service_owned_paths_ignore_ambient_home\(\)/,/^    }/' "$config_rs")
macos_core_entry=$(awk '/#\[cfg\(target_os = "macos"\)\]/{capture=1} capture{print} capture && /#\[cfg\(target_os = "linux"\)\]/{exit}' "$REPO/src/core_main.rs")
for binding in \
  'let effective_uid = unsafe { hbb_common::libc::geteuid() };' \
  'if !effective_uid_is_root(effective_uid) {' \
  'passwd_entry_for_uid(effective_uid)' \
  '!home.is_absolute()' \
  'let metadata = std::fs::metadata(&home)' \
  '!metadata.is_dir()' \
  'metadata.uid() != 0' \
  'metadata.mode() & 0o022 != 0'; do
  grep -qF "$binding" <<<"$macos_service_home" || r_s11e52="$r_s11e52 service-home-principal-proof-missing"
done
for binding in \
  'let home = service_principal_home()?;' \
  'crate::common::load_custom_client();' \
  'Config::initialize_macos_service_owned_root(home)?;' \
  'hbb_common::init_log(false, "service");' \
  'start_os_service()'; do
  grep -qF "$binding" <<<"$macos_service_bootstrap" || r_s11e52="$r_s11e52 centralized-bootstrap-binding-missing"
done
home_line=$(grep -nF 'let home = service_principal_home()?;' <<<"$macos_service_bootstrap" | cut -d: -f1 || true)
identity_line=$(grep -nF 'crate::common::load_custom_client();' <<<"$macos_service_bootstrap" | cut -d: -f1 || true)
config_line=$(grep -nF 'Config::initialize_macos_service_owned_root(home)?;' <<<"$macos_service_bootstrap" | cut -d: -f1 || true)
log_line=$(grep -nF 'hbb_common::init_log(false, "service");' <<<"$macos_service_bootstrap" | cut -d: -f1 || true)
listener_line=$(grep -nF 'start_os_service()' <<<"$macos_service_bootstrap" | tail -n1 | cut -d: -f1 || true)
if [ -z "$home_line" ] || [ -z "$identity_line" ] || [ -z "$config_line" ] \
  || [ -z "$log_line" ] || [ -z "$listener_line" ] \
  || [ "$home_line" -ge "$identity_line" ] || [ "$identity_line" -ge "$config_line" ] \
  || [ "$config_line" -ge "$log_line" ] || [ "$log_line" -ge "$listener_line" ]; then
  r_s11e52="$r_s11e52 centralized-bootstrap-order-invalid"
fi
for binding in \
  'struct MacosServiceOwnedConfigRoot {' \
  'static MACOS_SERVICE_OWNED_CONFIG_ROOT: OnceLock<MacosServiceOwnedConfigRoot>' \
  'fn macos_service_owned_config_root_from(' \
  '.join("Application Support")' \
  '.join("Logs").join(app_name)'; do
  grep -qF "$binding" <<<"$macos_config_root" || r_s11e52="$r_s11e52 immutable-config-root-derivation-missing"
done
for binding in \
  'if let Some(root) = macos_service_owned_config_root() {' \
  'return root.home.clone();'; do
  grep -qF "$binding" <<<"$macos_config_get_home" || r_s11e52="$r_s11e52 service-get-home-consumer-missing"
done
for binding in \
  'MACOS_SERVICE_OWNED_CONFIG_ROOT.set(candidate.clone())' \
  'existing == &candidate' \
  'macOS service-owned config root was initialized inconsistently'; do
  grep -qF "$binding" <<<"$macos_config_initialize" || r_s11e52="$r_s11e52 immutable-root-initializer-missing"
done
grep -qF 'let mut path = root.path.clone();' <<<"$macos_config_path" || r_s11e52="$r_s11e52 service-config-path-consumer-missing"
grep -qF 'return root.log_path.clone();' <<<"$macos_config_log_path" || r_s11e52="$r_s11e52 service-log-path-consumer-missing"
for entry in "$macos_core_entry" "$macos_service_binary"; do
  grep -qF 'crate::platform::macos::run_service()' <<<"$entry" || r_s11e52="$r_s11e52 service-entry-not-centralized"
  grep -qF 'std::process::exit(1);' <<<"$entry" || r_s11e52="$r_s11e52 service-entry-failure-not-propagated"
  if grep -qF 'load_custom_client()' <<<"$entry" || grep -qF 'init_log(' <<<"$entry"; then
    r_s11e52="$r_s11e52 service-entry-prebootstrap-config-or-log-present"
  fi
done
for binding in \
  'fn r_s11e52_macos_service_owned_paths_ignore_ambient_home()' \
  'Path::new("/var/root/Library/Application Support/com.carriez.RustDesk")' \
  'Path::new("/var/root/Library/Logs/RustDesk")' \
  'Path::new("relative/root")' \
  '"../RustDesk"' \
  '".."'; do
  grep -qF "$binding" <<<"$macos_config_test" || r_s11e52="$r_s11e52 path-derivation-regression-missing"
done
grep -qF '<span class="id">R-S11al</span>' "$REPO/requirements.html" || r_s11e52="$r_s11e52 normative-requirement-missing"
grep -qF '<tr><td>160</td>' "$REPO/requirements.html" || r_s11e52="$r_s11e52 appendix-disposition-missing"
grep -qF 'R-S11e-52 — macOS service-owned configuration/log root' "$REPO/HARDENING_STATUS.md" || r_s11e52="$r_s11e52 hardening-ledger-missing"
if [ -n "$r_s11e52" ]; then
  echo "  FAIL R-S11e-52 macOS service-owned config/log root:$r_s11e52"
  rc=1
else
  note "ok  R-S11e-52 macOS source centralizes both service entries and binds config/log storage to the protected passwd-derived UID-0 home before logging or listener startup; native Apple evidence remains pending R-R2/R-B2"
fi

echo "== (2b-iv-a-0c) authority-bearing IPC listener failure outcome (R-S11am/R-S11e-53) =="
r_s11e53=
server_shutdown=$(awk '/static SHUTDOWN_FAILURE_LATCHED/,/pub struct Server/' "$REPO/src/server.rs")
ipc_source=$(cat "$REPO/src/ipc.rs")
for binding in \
  'static SHUTDOWN_FAILURE_LATCHED: AtomicBool = AtomicBool::new(false);' \
  'pub(crate) fn request_graceful_shutdown_after_listener_failure() {' \
  'SHUTDOWN_FAILURE_LATCHED.store(true, Ordering::Release);' \
  'request_graceful_shutdown();' \
  'SHUTDOWN_FAILURE_LATCHED.load(Ordering::Acquire)' \
  'std::process::exit(exit_code);' \
  'fn r_s11e53_listener_failure_selects_nonzero_process_status()'; do
  grep -qF "$binding" <<<"$server_shutdown" || r_s11e53="$r_s11e53 shutdown-outcome-binding-missing"
done
if grep -qF 'std::process::exit(0);' <<<"$server_shutdown"; then
  r_s11e53="$r_s11e53 hardcoded-success-finalizer-present"
fi
python3 - "$REPO/src/ipc.rs" <<'PY' || r_s11e53="$r_s11e53 listener-producer-set-invalid"
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
messages = (
    "main password IPC listener ended unexpectedly",
    "main IPC listener ended unexpectedly",
    "protected service password IPC listener ended unexpectedly",
    "protected service credential IPC listener ended unexpectedly",
    "protected macOS service credential IPC listener ended unexpectedly",
    "protected _service IPC listener ended unexpectedly",
    "Windows service-main control IPC listener ended unexpectedly",
    "Windows service credential IPC listener ended unexpectedly",
)
helper = "crate::server::request_graceful_shutdown_after_listener_failure();"
if source.count(helper) != len(messages):
    raise SystemExit(1)
for message in messages:
    anchor = f'listener_error = Some("{message}".to_owned());'
    if source.count(anchor) != 1:
        raise SystemExit(1)
    start = source.index(anchor) + len(anchor)
    end = source.find("break;", start)
    if end < 0:
        raise SystemExit(1)
    branch = source[start:end]
    if branch.count(helper) != 1 or "crate::server::request_graceful_shutdown();" in branch:
        raise SystemExit(1)
PY
grep -qF '<span class="id">R-S11am</span>' "$REPO/requirements.html" || r_s11e53="$r_s11e53 normative-requirement-missing"
grep -qF '<tr><td>161</td>' "$REPO/requirements.html" || r_s11e53="$r_s11e53 appendix-disposition-missing"
grep -qF 'R-S11e-53 — authority-bearing IPC listener failure outcome' "$REPO/HARDENING_STATUS.md" \
  || r_s11e53="$r_s11e53 hardening-ledger-missing"
if [ -n "$r_s11e53" ]; then
  echo "  FAIL R-S11e-53 authority-bearing IPC listener failure outcome:$r_s11e53"
  rc=1
else
  note "ok  R-S11e-53 every fatal desktop IPC listener ending latches nonzero outcome before drain; protected macOS service channels return that post-drain error to their foreground entry"
fi

echo "== (2b-iv-a-0d) macOS LaunchDaemon protected IPC signal drain (R-S11ao/R-S11e-55) =="
r_s11e55=
python3 - "$REPO" <<'PY' || r_s11e55="$r_s11e55 signal-registration-or-drain-order-invalid"
from pathlib import Path
import sys

repo = Path(sys.argv[1])
cargo = (repo / "Cargo.toml").read_text(encoding="utf-8")
macos = (repo / "src/platform/macos.rs").read_text(encoding="utf-8")
ipc = (repo / "src/ipc.rs").read_text(encoding="utf-8")
core = (repo / "src/core_main.rs").read_text(encoding="utf-8")
service = (repo / "src/service.rs").read_text(encoding="utf-8")

def region(source, start, end):
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]

def ordered(source, *needles):
    position = -1
    for needle in needles:
        position = source.index(needle, position + 1)

if cargo.count('ctrlc = { version = "3.2", features = ["termination"] }') != 1:
    raise SystemExit(1)
if macos.count("ctrlc::set_handler") != 1:
    raise SystemExit(1)

handler = region(
    macos,
    "fn install_macos_service_shutdown_handler()",
    "\npub fn start_os_service()",
)
ordered(
    handler,
    "ctrlc::set_handler(|| {",
    "crate::server::request_graceful_shutdown();",
    '.map_err(|err| anyhow!("Failed to install macOS service shutdown handlers: {err}"))',
)
callback = region(handler, "ctrlc::set_handler(|| {", "\n    })\n    .map_err")
callback = callback.split("{", 1)[1].strip()
if callback != "crate::server::request_graceful_shutdown();":
    raise SystemExit(1)
for forbidden in (
    "request_graceful_shutdown_after_listener_failure",
    "begin_graceful_shutdown",
    "finish_graceful_shutdown",
    "process::exit",
    "tokio::",
    ".join(",
    "sleep(",
    "log::",
):
    if forbidden in handler:
        raise SystemExit(1)

start = region(macos, "pub fn start_os_service()", "\n#[cfg(test)]")
ordered(
    start,
    "if !is_root()",
    'bail!("macOS --service requires effective UID 0")',
    "install_macos_service_shutdown_handler()?;",
    "crate::ipc::start(crate::POSTFIX_SERVICE)",
)
run = region(macos, "pub fn run_service()", "\n#[cfg(test)]")
ordered(
    run,
    "let home = service_principal_home()?;",
    "Config::initialize_macos_service_owned_root(home)?;",
    'hbb_common::init_log(false, "service");',
    "start_os_service()",
)
if "crate::platform::macos::run_service()" not in core:
    raise SystemExit(1)
if "crate::platform::macos::run_service()" not in service:
    raise SystemExit(1)

drain = region(
    ipc,
    "async fn run_service_ipc(postfix: &str, listeners: PreparedServiceIpc)",
    '\n#[cfg(target_os = "linux")]\nasync fn handle_sensitive_linux_service_ipc_transaction',
)
ordered(
    drain,
    "_ = shutdown.cancelled() => break,",
    "password_mutations().begin_shutdown();",
    "while let Some(result) = transactions.join_next().await",
    "password_mutations().drain().await;",
    "password_mutations().clear_after_transactions_drain();",
    "drop(listener_guard);",
)
PY
grep -qF '<span class="id">R-S11ao</span>' "$REPO/requirements.html" || r_s11e55="$r_s11e55 normative-requirement-missing"
grep -qF '<tr><td>163</td>' "$REPO/requirements.html" || r_s11e55="$r_s11e55 appendix-disposition-missing"
grep -qF 'R-S11e-55 — macOS LaunchDaemon protected IPC signal drain' "$REPO/HARDENING_STATUS.md" \
  || r_s11e55="$r_s11e55 hardening-ledger-missing"
if [ -n "$r_s11e55" ]; then
  echo "  FAIL R-S11e-55 macOS LaunchDaemon protected IPC signal drain:$r_s11e55"
  rc=1
else
  note "ok  R-S11e-55 macOS installs fallible cancellation-only termination handling after root proof and before protected listener admission; the existing listener owner drains all accepted service/password work"
fi

echo "== (2b-iv-a-0e) desktop controlled-server signal/listener lifecycle ownership (R-S11ap/R-S11e-56) =="
r_s11e56=
python3 "$REPO/scripts/verify-desktop-ipc-lifecycle.py" --repo "$REPO" \
  || r_s11e56="$r_s11e56 controlled-server-lifecycle-ownership-invalid"
grep -qF '<span class="id">R-S11ap</span>' "$REPO/requirements.html" || r_s11e56="$r_s11e56 normative-requirement-missing"
grep -qF '<tr><td>164</td>' "$REPO/requirements.html" || r_s11e56="$r_s11e56 appendix-row-missing"
grep -qF 'R-S11e-56 — desktop controlled-server signal/listener lifecycle ownership' "$REPO/HARDENING_STATUS.md" \
  || r_s11e56="$r_s11e56 hardening-ledger-missing"
if [ -n "$r_s11e56" ]; then
  echo "  FAIL R-S11e-56 desktop controlled-server signal/listener lifecycle:$r_s11e56"
  rc=1
else
  note "ok  R-S11e-56 macOS/shared desktop installs signals before admission and retains the public listener under the R-S11as owner"
fi

echo "== (2b-iv-a-0f) non-returning graceful-shutdown finalizer ownership (R-S11aq/R-S11e-57) =="
r_s11e57=
python3 "$REPO/scripts/verify-desktop-ipc-lifecycle.py" --repo "$REPO" \
  || r_s11e57="$r_s11e57 shutdown-finalizer-ownership-invalid"
grep -qF '<span class="id">R-S11aq</span>' "$REPO/requirements.html" || r_s11e57="$r_s11e57 normative-requirement-missing"
grep -qF '<tr><td>165</td>' "$REPO/requirements.html" || r_s11e57="$r_s11e57 appendix-row-missing"
grep -qF 'R-S11e-57 — non-returning graceful-shutdown finalizer ownership' "$REPO/HARDENING_STATUS.md" \
  || r_s11e57="$r_s11e57 hardening-ledger-missing"
if [ -n "$r_s11e57" ]; then
  echo "  FAIL R-S11e-57 graceful-shutdown finalizer ownership:$r_s11e57"
  rc=1
else
  note "ok  R-S11e-57 the macOS/shared finalizer is non-returning and has one post-join retained owner"
fi

echo "== (2b-iv-a-0g) protected Unix service IPC foreground lifecycle ownership (R-S11ar/R-S11e-58) =="
r_s11e58=
python3 "$REPO/scripts/verify-desktop-ipc-lifecycle.py" --repo "$REPO" \
  || r_s11e58="$r_s11e58 protected-service-outcome-ownership-invalid"
grep -qF 'fn r_s11e58_protected_service_ipc_returns_listener_failure_to_its_owner()' "$REPO/src/ipc.rs" \
  || r_s11e58="$r_s11e58 focused-regression-missing"
grep -qF '<span class="id">R-S11ar</span>' "$REPO/requirements.html" || r_s11e58="$r_s11e58 normative-requirement-missing"
grep -qF '<tr><td>166</td>' "$REPO/requirements.html" || r_s11e58="$r_s11e58 appendix-row-missing"
grep -qF 'R-S11e-58 — protected Unix service IPC foreground lifecycle ownership' "$REPO/HARDENING_STATUS.md" \
  || r_s11e58="$r_s11e58 hardening-ledger-missing"
if [ -n "$r_s11e58" ]; then
  echo "  FAIL R-S11e-58 protected service IPC lifecycle ownership:$r_s11e58"
  rc=1
else
  note "ok  R-S11e-58 macOS protected IPC returns its complete post-drain outcome to the synchronous service entry"
fi

echo "== (2b-iv-a-0h) desktop local-IPC readiness and retained native-worker ownership (R-S11as/R-S11e-59) =="
r_s11e59=
python3 "$REPO/scripts/verify-desktop-ipc-lifecycle.py" --repo "$REPO" \
  || r_s11e59="$r_s11e59 desktop-ipc-lifecycle-semantic-invalid"
python3 "$REPO/scripts/verify-desktop-ipc-lifecycle.py" --repo "$REPO" --self-test \
  || r_s11e59="$r_s11e59 desktop-ipc-lifecycle-mutations-invalid"
grep -qF '<span class="id">R-S11as</span>' "$REPO/requirements.html" || r_s11e59="$r_s11e59 normative-requirement-missing"
grep -qF '<tr><td>167</td>' "$REPO/requirements.html" || r_s11e59="$r_s11e59 appendix-row-missing"
grep -qF 'R-S11e-59 — desktop local-IPC readiness and retained native-worker ownership' "$REPO/HARDENING_STATUS.md" \
  || r_s11e59="$r_s11e59 hardening-ledger-missing"
if [ -n "$r_s11e59" ]; then
  echo "  FAIL R-S11e-59 desktop IPC lifecycle ownership:$r_s11e59"
  rc=1
else
  note "ok  R-S11e-59 macOS/shared desktop local IPC is ready before public admission and exactly joined before the sole finalizer"
fi
echo "== (2b-iv-a-1) macOS child inherited descriptor authority (R-S11t/R-S11e-34) =="
r_s11e34=
hbb_macos_descriptor_policy=$(awk '/const MAX_MACOS_DESCRIPTOR_LIMIT/,/#\[cfg\(test\)\]/' "$REPO/libs/hbb_common/src/platform/macos.rs")
macos_platform_source=$(cat "$REPO/src/platform/macos.rs")
macos_checked_command=$(awk '/fn run_checked_command/,/fn launchctl_query_succeeds/' "$REPO/src/platform/macos.rs")
macos_launchctl_query=$(awk '/fn launchctl_query_succeeds/,/fn launchctl_service_loaded/' "$REPO/src/platform/macos.rs")
macos_uninstall=$(awk '/pub fn uninstall_service/,/pub fn get_cursor_pos/' "$REPO/src/platform/macos.rs")
macos_lock_query=$(awk '/pub fn is_locked/,/pub fn declare_remote_user_activity/' "$REPO/src/platform/macos.rs")
macos_service_snapshot_query=$(awk '/fn macos_launch_agent_owns_service_owned_server_pid/,/^[}]$/' "$REPO/src/ipc.rs")
macos_run_me=$(awk '/pub fn run_me_with_env/,/#\[inline\]/{print}' "$REPO/src/common.rs")
macos_hwcodec_check=$(awk '/pub fn start_check_process\(\)/,/^}/' "$REPO/libs/scrap/src/common/hwcodec.rs")
portable_pty_unix=$(cat "$REPO/libs/portable_pty/src/unix.rs")
portable_pty_spawn=$(awk '/fn spawn_command\(&self, builder: CommandBuilder\)/,/let mut child = cmd.spawn\(\)\?;/' "$REPO/libs/portable_pty/src/unix.rs")
terminal_pty_launch=$(awk '/let pty_system = portable_pty::native_pty_system\(\);/,/drop\(slave\);/' "$REPO/src/server/terminal_service.rs")
for policy_binding in \
  'const MAX_MACOS_DESCRIPTOR_LIMIT: u64 = 1_048_576;' \
  'fn validated_macos_descriptor_upper_bound(descriptor_limit: u64)' \
  'descriptor_limit == libc::RLIM_INFINITY' \
  'descriptor_limit > MAX_MACOS_DESCRIPTOR_LIMIT' \
  'libc::getrlimit(libc::RLIMIT_NOFILE' \
  'for entry in fs::read_dir("/dev/fd")?' \
  'descriptors.sort_unstable();' \
  'descriptors.dedup();' \
  'let descriptor_flags = libc::fcntl(fd, libc::F_GETFD);' \
  'libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC)' \
  'Err(err) if err.raw_os_error() == Some(libc::EBADF)' \
  'for fd in (libc::STDERR_FILENO + 1)..=last_fd' \
  'if fd <= last_fd' \
  'pub fn configure_command_close_nonstdio_on_exec(command: &mut Command)' \
  'command.pre_exec(move || {' \
  'mark_nonstdio_descriptors_close_on_exec(last_fd, &observed_descriptors)'; do
  grep -qF "$policy_binding" <<<"$hbb_macos_descriptor_policy" \
    || r_s11e34="$r_s11e34 shared-macos-policy-binding-missing"
done
check_apple_r_s11e34_helper_contract() {
  local helper_source=$1
  local helper_policy=$2
  local helper_execution=$3
  local helper_policy_line helper_execution_line
  grep -qF "$helper_policy" <<<"$helper_source" || r_s11e34="$r_s11e34 macos-helper-policy-missing"
  grep -qF "$helper_execution" <<<"$helper_source" || r_s11e34="$r_s11e34 macos-helper-execution-missing"
  helper_policy_line=$(grep -nF "$helper_policy" <<<"$helper_source" | head -n1 | cut -d: -f1 || true)
  helper_execution_line=$(grep -nF "$helper_execution" <<<"$helper_source" | head -n1 | cut -d: -f1 || true)
  if [ -z "$helper_policy_line" ] || [ -z "$helper_execution_line" ] \
    || [ "$helper_policy_line" -ge "$helper_execution_line" ]; then
    r_s11e34="$r_s11e34 macos-helper-policy-order-invalid"
  fi
}
check_apple_r_s11e34_helper_contract "$macos_checked_command" 'configure_command_close_nonstdio_on_exec(command)' 'command.status()'
check_apple_r_s11e34_helper_contract "$macos_launchctl_query" 'configure_command_close_nonstdio_on_exec(&mut command)' 'command.status()'
check_apple_r_s11e34_helper_contract "$macos_uninstall" 'configure_command_close_nonstdio_on_exec(' 'command.spawn()'
check_apple_r_s11e34_helper_contract "$macos_lock_query" 'configure_command_close_nonstdio_on_exec(' 'command.output()'
check_apple_r_s11e34_helper_contract "$macos_service_snapshot_query" 'configure_command_close_nonstdio_on_exec(&mut command)' 'run_macos_bounded_child_stdout('
check_apple_r_s11e34_helper_contract "$macos_run_me" 'platform::macos::configure_command_close_nonstdio_on_exec(&mut cmd)' 'let result = cmd.args(&args).spawn();'
check_apple_r_s11e34_helper_contract "$macos_hwcodec_check" 'platform::macos::configure_command_close_nonstdio_on_exec(' 'command.spawn()'
[ "$(grep -cF 'command.status()' <<<"$macos_platform_source")" = 2 ] \
  || r_s11e34="$r_s11e34 macos-platform-status-inventory-drift"
[ "$(grep -cF 'command.spawn()' <<<"$macos_platform_source")" = 1 ] \
  || r_s11e34="$r_s11e34 macos-platform-spawn-inventory-drift"
[ "$(grep -cF 'command.output()' <<<"$macos_platform_source")" = 2 ] \
  || r_s11e34="$r_s11e34 macos-platform-output-inventory-drift"
[ "$(grep -cF 'run_checked_command(' <<<"$macos_platform_source")" = 6 ] \
  || r_s11e34="$r_s11e34 macos-checked-command-inventory-drift"
for pty_policy_binding in \
  'const MAX_UNIX_DESCRIPTOR_LIMIT: u64 = 1_048_576;' \
  'struct UnixChildDescriptorPolicy' \
  'libc::getrlimit(libc::RLIMIT_NOFILE' \
  'for entry in std::fs::read_dir("/dev/fd")?' \
  'observed_descriptors.sort_unstable();' \
  'observed_descriptors.dedup();' \
  'let flags = libc::fcntl(fd, libc::F_GETFD);' \
  'libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC)' \
  'error.raw_os_error() == Some(libc::EBADF)' \
  'for fd in (libc::STDERR_FILENO + 1)..=self.last_fd' \
  'descriptor_policy.mark_close_on_exec()?;'; do
  grep -qF "$pty_policy_binding" <<<"$portable_pty_unix" \
    || r_s11e34="$r_s11e34 portable-pty-policy-binding-missing"
done
check_apple_r_s11e34_helper_contract "$portable_pty_spawn" \
  'let descriptor_policy = UnixChildDescriptorPolicy::prepare()?;' \
  'cmd.stdin(self.as_stdio()?)'
check_apple_r_s11e34_helper_contract "$portable_pty_spawn" \
  'descriptor_policy.mark_close_on_exec()?;' \
  'let mut child = cmd.spawn()?;'
if grep -qF 'close_random_fds' <<<"$portable_pty_unix"; then
  r_s11e34="$r_s11e34 obsolete-portable-pty-best-effort-close-present"
fi
for pty_test_binding in \
  'fn unix_child_descriptor_limit_is_bounded()' \
  'fn pty_child_exec_failure_is_reported()' \
  'the PTY spawn hid its post-fork exec failure from the parent' \
  'fn pty_child_excludes_injected_nonstdio_descriptor()' \
  'the intermediate PTY test image must prove the injected descriptor object' \
  'the final PTY test image inherited the injected descriptor object'; do
  grep -qF "$pty_test_binding" <<<"$portable_pty_unix" \
    || r_s11e34="$r_s11e34 portable-pty-regression-binding-missing"
done
grep -qF 'portable-pty = { path = "libs/portable_pty" }' "$REPO/Cargo.toml" \
  || r_s11e34="$r_s11e34 portable-pty-root-path-binding-missing"
grep -qF '"libs/portable_pty"' "$REPO/Cargo.toml" \
  || r_s11e34="$r_s11e34 portable-pty-workspace-member-missing"
grep -qF 'filedescriptor = { version = "0.8", git = "https://github.com/rustdesk-org/wezterm", branch = "rustdesk/pty_based_0.8.1" }' "$REPO/libs/portable_pty/Cargo.toml" \
  || r_s11e34="$r_s11e34 portable-pty-filedescriptor-pin-missing"
grep -qF '80174f8009f41565f0fa8c66dab90d4f9211ae16' "$REPO/libs/portable_pty/RUSTDESK_PROVENANCE.md" \
  || r_s11e34="$r_s11e34 portable-pty-provenance-commit-missing"
portable_pty_lock_record=$(awk '
  /^\[\[package\]\]$/ { if (capture) exit; in_package=1; next }
  in_package && /^name = "portable-pty"$/ { capture=1 }
  capture { print }
' "$REPO/Cargo.lock")
grep -qF 'version = "0.8.1"' <<<"$portable_pty_lock_record" \
  || r_s11e34="$r_s11e34 portable-pty-lock-version-missing"
if grep -qF 'source = ' <<<"$portable_pty_lock_record"; then
  r_s11e34="$r_s11e34 portable-pty-lock-still-external"
fi
grep -qF 'let mut cmd = CommandBuilder::new(&shell);' <<<"$terminal_pty_launch" \
  || r_s11e34="$r_s11e34 macos-terminal-command-builder-missing"
grep -qF '.spawn_command(cmd)' <<<"$terminal_pty_launch" \
  || r_s11e34="$r_s11e34 macos-terminal-portable-pty-launch-missing"
if grep -qE '^[[:space:]]*osascript[[:space:]]*=' "$REPO/libs/hbb_common/Cargo.toml" \
  || grep -qF 'name = "osascript"' "$REPO/Cargo.lock" \
  || grep -qF 'pub fn alert(' "$REPO/libs/hbb_common/src/platform/macos.rs"; then
  r_s11e34="$r_s11e34 obsolete-dependency-owned-macos-launch-present"
fi
grep -qF 'fn macos_command_descriptor_limit_is_bounded()' "$REPO/libs/hbb_common/src/platform/macos.rs" \
  || r_s11e34="$r_s11e34 descriptor-limit-regression-missing"
for actual_child_binding in \
  'fn macos_command_excludes_injected_nonstdio_descriptor()' \
  'exec 9<\"$1\"; exec \"$2\" \"$3\" --nocapture' \
  'the intermediate test image must prove the injected descriptor object' \
  'configure_command_close_nonstdio_on_exec(&mut child).unwrap();' \
  'the final test image inherited the injected descriptor object'; do
  grep -qF "$actual_child_binding" "$REPO/libs/hbb_common/src/platform/macos.rs" \
    || r_s11e34="$r_s11e34 macos-actual-child-regression-binding-missing"
done
grep -qF '<span class="id">R-S11t</span>' "$REPO/requirements.html" \
  || r_s11e34="$r_s11e34 normative-requirement-missing"
grep -qF '<tr><td>142</td>' "$REPO/requirements.html" \
  || r_s11e34="$r_s11e34 appendix-row-missing"
grep -qF 'R-S11e-34 — macOS child inherited descriptor authority' "$REPO/HARDENING_STATUS.md" \
  || r_s11e34="$r_s11e34 hardening-ledger-missing"
if [ -n "$r_s11e34" ]; then
  echo "  FAIL R-S11e-34 macOS child inherited descriptor authority:$r_s11e34"
  rc=1
else
  note "ok  R-S11e-34 every production macOS child image is stdio-only; the unused dependency-owned PATH launch is absent"
fi

echo "== (2b-iv-a-1aa) desktop lock-screen mechanism authority (R-S11er/R-S11e-179) =="
r_s11e179=
lock_dispatch=$(awk '/fn lock_screen_with_key_handler\(/,/#\[cfg\(any\(target_os = "linux", target_os = "macos"\)\)\]/' "$REPO/src/server/input_service.rs")
windows_lock_workstation=$(awk '/pub fn lock_workstation\(\)/,/^}/' "$REPO/src/platform/windows.rs")
for lock_binding in \
  'if #[cfg(target_os = "linux")]' \
  'rdev::linux_keycode_from_key(RdevKey::KeyL)' \
  'dispatch_physical_lock_chord(&mut key_handler, &[ControlKey::Meta], code as u32)?;' \
  'else if #[cfg(target_os = "macos")]' \
  'rdev::macos_keycode_from_key(RdevKey::KeyQ)' \
  '&[ControlKey::Meta, ControlKey::Control]' \
  'else if #[cfg(target_os = "windows")]' \
  'crate::platform::lock_workstation()?;'; do
  grep -qF "$lock_binding" <<<"$lock_dispatch" \
    || r_s11e179="$r_s11e179 platform-lock-dispatch-binding-missing"
done
if grep -qF 'crate::platform::lock_screen' "$REPO/src/server/input_service.rs"; then
  r_s11e179="$r_s11e179 generic-platform-lock-abstraction-present"
fi
if grep -qE 'XDG_SCREENSAVER_PATHS|xdg_screensaver|xdg-screensaver|pub fn lock_screen\(' "$REPO/src/platform/linux.rs"; then
  r_s11e179="$r_s11e179 dormant-linux-lock-helper-present"
fi
if grep -qE 'CGSession|pub fn lock_screen\(' "$REPO/src/platform/macos.rs"; then
  r_s11e179="$r_s11e179 dormant-macos-lock-helper-present"
fi
for windows_binding in \
  'pub fn lock_workstation() -> ResultType<()> {' \
  'pub fn LockWorkStation() -> BOOL;' \
  'if LockWorkStation() == FALSE {' \
  'let error = GetLastError();' \
  'bail!("LockWorkStation failed with Windows error {error}");' \
  'Ok(())'; do
  grep -qF "$windows_binding" <<<"$windows_lock_workstation" \
    || r_s11e179="$r_s11e179 windows-native-lock-result-binding-missing"
done
grep -qF '<span class="id">R-S11er</span>' "$REPO/requirements.html" \
  || r_s11e179="$r_s11e179 normative-requirement-missing"
grep -qF '<tr><td>300</td>' "$REPO/requirements.html" \
  || r_s11e179="$r_s11e179 appendix-row-missing"
grep -qF 'R-S11er/R-S11e-179 desktop lock-screen mechanism authority' "$REPO/HARDENING_STATUS.md" \
  || r_s11e179="$r_s11e179 hardening-ledger-missing"
if [ -n "$r_s11e179" ]; then
  echo "  FAIL R-S11e-179 desktop lock-screen mechanism authority:$r_s11e179"
  rc=1
else
  note "ok  R-S11e-179 macOS retains only the owned Control-Command-Q lock path; dormant CGSession launch is absent"
fi

echo "== (2b-iv-a-1a) macOS administrator-script environment finality (R-S11az/R-S11e-66) =="
r_s11e66=
macos_privileged_policy=$(awk '/fn configure_macos_privileged_script_command/,/fn macos_privileged_service_script_command/' "$REPO/src/platform/macos.rs")
macos_privileged_creator=$(awk '/fn macos_privileged_service_script_command/,/fn launchctl_query_succeeds/' "$REPO/src/platform/macos.rs")
macos_privileged_install=$(awk '/fn run_service_install/,/fn render_macos_service_template/' "$REPO/src/platform/macos.rs")
macos_privileged_uninstall=$(awk '/pub fn uninstall_service/,/pub fn get_cursor_pos/' "$REPO/src/platform/macos.rs")
for binding in \
  '.env_clear()' \
  '.env("PATH", MACOS_PRIVILEGED_SCRIPT_PATH)' \
  '.env("LANG", "C")' \
  '.env("LC_ALL", "C")' \
  '.current_dir("/")'; do
  grep -qF "$binding" <<<"$macos_privileged_policy" \
    || r_s11e66="$r_s11e66 closed-environment-binding-missing"
done
grep -qF 'const MACOS_PRIVILEGED_SCRIPT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";' "$REPO/src/platform/macos.rs" \
  || r_s11e66="$r_s11e66 fixed-system-path-missing"
[ "$(grep -cF 'Command::new(MACOS_OSASCRIPT)' "$REPO/src/platform/macos.rs")" = 1 ] \
  || r_s11e66="$r_s11e66 osascript-construction-inventory-drift"
grep -qF 'let mut command = Command::new(MACOS_OSASCRIPT);' <<<"$macos_privileged_creator" \
  || r_s11e66="$r_s11e66 closed-constructor-missing"
grep -qF 'configure_macos_privileged_script_command(&mut command);' <<<"$macos_privileged_creator" \
  || r_s11e66="$r_s11e66 constructor-policy-call-missing"
for caller in "$macos_privileged_install" "$macos_privileged_uninstall"; do
  [ "$(grep -cF 'macos_privileged_service_script_command()' <<<"$caller")" = 1 ] \
    || r_s11e66="$r_s11e66 privileged-caller-topology-invalid"
  if grep -qF 'Command::new(MACOS_OSASCRIPT)' <<<"$caller"; then
    r_s11e66="$r_s11e66 direct-privileged-constructor-present"
  fi
  if grep -Eq '[.]env(_clear|_remove)?[(]|[.]current_dir[(]' <<<"$caller"; then
    r_s11e66="$r_s11e66 post-construction-ambient-mutation-present"
  fi
done
[ "$(grep -cF '.env(' <<<"$macos_privileged_policy")" = 3 ] \
  || r_s11e66="$r_s11e66 replacement-environment-inventory-drift"
[ "$(grep -cF '.current_dir(' <<<"$macos_privileged_policy")" = 1 ] \
  || r_s11e66="$r_s11e66 working-directory-inventory-drift"
grep -qF 'fn r_s11e66_macos_privileged_script_environment_is_exact()' "$REPO/src/platform/macos.rs" \
  || r_s11e66="$r_s11e66 actual-child-environment-regression-missing"
grep -qF '<span class="id">R-S11az</span>' "$REPO/requirements.html" \
  || r_s11e66="$r_s11e66 normative-requirement-missing"
grep -qF '<tr><td>174</td>' "$REPO/requirements.html" \
  || r_s11e66="$r_s11e66 appendix-row-missing"
grep -qF 'R-S11e-66 — macOS administrator-script environment finality' "$REPO/HARDENING_STATUS.md" \
  || r_s11e66="$r_s11e66 hardening-ledger-missing"
if [ -n "$r_s11e66" ]; then
  echo "  FAIL R-S11e-66 macOS administrator-script environment finality:$r_s11e66"
  rc=1
else
  note "ok  R-S11e-66 administrator-authorized service scripts receive only the fixed system PATH/C locale and root working directory"
fi

echo "== (2b-iv-b) R-S11c-16 macOS privileged service completion authority =="
r_s11c16=
grep -q 'fn run_checked_command(command: &mut Command, description: &str) -> bool' "$macos_rs" || r_s11c16="$r_s11c16 no-checked-command-helper"
grep -q 'Ok(status) if status.success() => true' "$macos_rs" || r_s11c16="$r_s11c16 status-success-not-explicit"
grep -q 'fn launchctl_service_loaded(domain: &str, service_target: &str) -> Option<bool>' "$macos_rs" || r_s11c16="$r_s11c16 no-domain-aware-launchctl-query"
grep -q 'fn ensure_launchctl_service_removed(domain: &str, service_target: &str) -> bool' "$macos_rs" || r_s11c16="$r_s11c16 no-launchctl-bootout-verifier"
grep -q 'fn restart_launch_agent(agent_plist_file: &str, label: &str) -> bool' "$macos_rs" || r_s11c16="$r_s11c16 no-launch-agent-restart-verifier"
macos_install_service_body=$(awk '/pub fn install_service\(\) -> bool/,/^}/' "$macos_rs")
echo "$macos_install_service_body" | grep -Fq 'run_service_install(context)' || r_s11c16="$r_s11c16 install-wrapper-not-checked-install"
if echo "$macos_install_service_body" | grep -Fq 'service_plists_exist'; then
  r_s11c16="$r_s11c16 install-wrapper-plist-only-success"
fi
grep -q 'restart_launch_agent(&context.agent_plist_file, &server_launch_agent_label())' "$macos_rs" || r_s11c16="$r_s11c16 install-agent-load-not-authoritative"
grep -q 'return func();' "$macos_rs" || r_s11c16="$r_s11c16 sync-uninstall-return-not-propagated"
grep -q 'if !ensure_launchctl_service_removed(&launch_agent_domain, &launch_agent_target)' "$macos_rs" || r_s11c16="$r_s11c16 uninstall-agent-bootout-not-authoritative"
if perl -0ne 'exit(/\.status\(\)\s*\.ok\(\)/ ? 0 : 1)' "$macos_rs"; then
  r_s11c16="$r_s11c16 status-result-discard"
fi
grep -q 'set unload_existing_service to "/bin/launchctl print system' "$install_scpt" || r_s11c16="$r_s11c16 install-no-domain-aware-daemon-bootout"
grep -q 'set load_service to "/bin/launchctl enable ' "$install_scpt" || r_s11c16="$r_s11c16 install-daemon-enable-missing"
grep -q '/bin/launchctl bootstrap system ' "$install_scpt" || r_s11c16="$r_s11c16 install-daemon-bootstrap-missing"
grep -q 'unload_existing_service.*load_service' "$install_scpt" || r_s11c16="$r_s11c16 install-order-not-pinned"
grep -q 'set unload_service to "/bin/launchctl print system' "$uninstall_scpt" || r_s11c16="$r_s11c16 uninstall-no-domain-aware-daemon-bootout"
grep -q 'set verify_unloaded to "/bin/launchctl print system' "$uninstall_scpt" || r_s11c16="$r_s11c16 uninstall-daemon-bootout-not-verified"
grep -q 'set verify_removed to "if \[ -e " & quoted form of daemon_plist' "$uninstall_scpt" || r_s11c16="$r_s11c16 uninstall-plist-removal-not-verified"
grep -q 'set sh to "set -e;"' "$uninstall_scpt" || r_s11c16="$r_s11c16 uninstall-not-set-e"
if grep -qE '/bin/launchctl (list|load|unload|remove)( |")' "$install_scpt" "$uninstall_scpt"; then
  r_s11c16="$r_s11c16 legacy-launchctl-lifecycle-present"
fi
grep -q 'R-S11c-16 and R-S11c-10j make service lifecycle completion status-authoritative' "$REPO/requirements.html" || r_s11c16="$r_s11c16 requirements-disposition-missing"
grep -q 'R-S11c-16 — Desktop service lifecycle completion authority' "$REPO/HARDENING_STATUS.md" || r_s11c16="$r_s11c16 hardening-ledger-missing"
if [ -n "$r_s11c16" ]; then
  echo "  FAIL R-S11c-16 macOS privileged service completion authority:$r_s11c16"
  rc=1
else
  note "ok  R-S11c-16 macOS service install/uninstall checks AppleScript exit status, launchd label state, and plist postconditions"
fi

echo "== (2b-iv-c) R-S11c-20 Unix terminal shell command provenance =="
r_s11c20=
terminal_service_rs="$REPO/src/server/terminal_service.rs"
unix_terminal_shell_block=$(awk '/fn get_default_shell\(\) -> Result<String>/,/^#\[cfg\(target_os = "macos"\)\]/' "$terminal_service_rs")
grep -Fq 'fn trusted_unix_terminal_shell_path(path: &Path) -> Option<PathBuf>' "$terminal_service_rs" || r_s11c20="$r_s11c20 trusted-resolver-missing"
grep -Fq 'const UNIX_TERMINAL_SHELLS' "$terminal_service_rs" || r_s11c20="$r_s11c20 candidate-set-missing"
grep -Fq 'metadata.uid() == 0' "$terminal_service_rs" || r_s11c20="$r_s11c20 not-root-owned-gated"
grep -Fq 'metadata.mode() & 0o022 == 0' "$terminal_service_rs" || r_s11c20="$r_s11c20 writable-mode-not-gated"
grep -Fq 'metadata.mode() & 0o111 != 0' "$terminal_service_rs" || r_s11c20="$r_s11c20 executable-mode-not-gated"
grep -Fq 'trusted_unix_terminal_shell_rejects_relative_and_parent_paths' "$terminal_service_rs" || r_s11c20="$r_s11c20 bad-path-test-missing"
grep -Fq 'trusted_unix_terminal_shell_returns_absolute_candidate_when_available' "$terminal_service_rs" || r_s11c20="$r_s11c20 candidate-test-missing"
if echo "$unix_terminal_shell_block" | grep -qE 'std::env::var\("SHELL"\)|Ok\("/bin/sh"\.to_string\(\)\)|return Ok\(shell\)|CommandBuilder::new\("(sh|bash|zsh)"\)'; then
  r_s11c20="$r_s11c20 ambient-or-bare-shell-fallback"
fi
grep -q 'Unix terminal default-shell command provenance' "$REPO/requirements.html" || r_s11c20="$r_s11c20 requirements-disposition-missing"
grep -q 'R-S11c-20 — Unix terminal default-shell command provenance' "$REPO/HARDENING_STATUS.md" || r_s11c20="$r_s11c20 hardening-ledger-missing"
if [ -n "$r_s11c20" ]; then
  echo "  FAIL R-S11c-20 Unix terminal shell command provenance:$r_s11c20"
  rc=1
else
  note "ok  R-S11c-20 Unix terminal opens only trusted absolute root-owned shell candidates, with no SHELL/PATH fallback"
fi

echo "== (2b-iv-d) R-S11e-12 macOS clipboard-file paste no-follow finalize =="
paste_task_rs="$REPO/libs/clipboard/src/platform/unix/macos/paste_task.rs"
r_s11e12=
grep -qF 'fn open_dir_path_no_follow(path: &Path) -> io::Result<File>' "$paste_task_rs" || r_s11e12="$r_s11e12 no-target-dir-nofollow-open"
grep -qF 'fn open_relative_parent_dir_no_follow(' "$paste_task_rs" || r_s11e12="$r_s11e12 no-relative-parent-nofollow-walk"
grep -qF 'fn open_relative_file_exclusive_no_follow(' "$paste_task_rs" || r_s11e12="$r_s11e12 no-exclusive-file-open"
grep -qF 'fn rename_relative_file_exclusive_no_follow(' "$paste_task_rs" || r_s11e12="$r_s11e12 no-exclusive-rename"
grep -qF 'libc::O_NOFOLLOW' "$paste_task_rs" || r_s11e12="$r_s11e12 no-onofollow"
grep -qF 'libc::O_EXCL' "$paste_task_rs" || r_s11e12="$r_s11e12 no-exclusive-create"
grep -qF 'libc::renameatx_np' "$paste_task_rs" || r_s11e12="$r_s11e12 no-renameatx-np"
grep -qF 'libc::RENAME_EXCL' "$paste_task_rs" || r_s11e12="$r_s11e12 no-rename-excl"
grep -qF 'libc::fsetxattr' "$paste_task_rs" || r_s11e12="$r_s11e12 progress-xattr-not-fd-bound"
grep -qF 'libc::fremovexattr' "$paste_task_rs" || r_s11e12="$r_s11e12 progress-xattr-remove-not-fd-bound"
grep -qF 'task_handle.update_next(0)?;' "$paste_task_rs" || r_s11e12="$r_s11e12 initial-filesystem-errors-masked"
grep -qF 'macOS clipboard-file paste no-follow finalize' "$REPO/requirements.html" || r_s11e12="$r_s11e12 requirements-disposition-missing"
grep -qF 'R-S11e-12 — macOS clipboard-file paste no-follow finalize' "$REPO/HARDENING_STATUS.md" || r_s11e12="$r_s11e12 hardening-ledger-missing"
if grep -nE 'std::fs::File::create|std::fs::create_dir_all|std::fs::rename|std::fs::remove_file|File::options\(\)|xattr::(set|remove)|update_next\(0\)\.ok' "$paste_task_rs" >"$APPLE_CHECK_TMP/rd_apple_r_s11e12"; then
  cat "$APPLE_CHECK_TMP/rd_apple_r_s11e12"
  r_s11e12="$r_s11e12 path-based-paste-filesystem-op"
fi
if [ -n "$r_s11e12" ]; then
  echo "  FAIL R-S11e-12 macOS clipboard-file paste no-follow finalize:$r_s11e12"
  rc=1
else
  note "ok  R-S11e-12 macOS clipboard-file paste uses fd-relative no-follow create/unlink/xattr/finalize with no path-based write fallback"
fi

echo "== (2b-iv-e) R-S11e-13 macOS clipboard-file paste placeholder temp authority =="
pasteboard_context_rs="$REPO/libs/clipboard/src/platform/unix/macos/pasteboard_context.rs"
item_data_provider_rs="$REPO/libs/clipboard/src/platform/unix/macos/item_data_provider.rs"
paste_observer_rs="$REPO/libs/clipboard/src/platform/unix/macos/paste_observer.rs"
pasteboard_readme="$REPO/libs/clipboard/src/platform/unix/macos/README.md"
r_s11e13=
grep -qF 'const PLACEHOLDER_DIR_PREFIX: &str = "rustdesk-clipboard-";' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-private-dir-prefix"
grep -qF 'fn create_placeholder_dir() -> io::Result<(PathBuf, File)>' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-private-dir-creator"
grep -qF 'std::env::temp_dir()' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-user-temp-base"
grep -qF 'libc::mkdir(dir_c.as_ptr(), 0o700 as libc::mode_t)' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-private-dir-mkdir"
grep -qF 'libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-private-dir-nofollow-open"
grep -qF 'libc::fchmod(dir.as_raw_fd(), 0o700 as libc::mode_t)' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-private-dir-mode-normalize"
grep -qF 'stat.st_uid != current_euid' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-private-dir-owner-check"
grep -qF 'stat.st_mode & 0o077 != 0' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-private-dir-group-other-reject"
grep -qF 'pub(super) fn create_placeholder_file(' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-placeholder-file-creator"
grep -qF 'libc::openat(' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-openat-placeholder-create"
grep -qF 'libc::O_EXCL' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-exclusive-placeholder-create"
grep -qF '0o600 as libc::c_uint' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-owner-only-promoted-placeholder-mode"
grep -qF 'fn remove_placeholder_file(' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-placeholder-unlink-helper"
grep -qF 'libc::unlinkat' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-unlinkat-placeholder-cleanup"
grep -qF 'fn count_placeholder_files(placeholder_dir: &Path) -> io::Result<usize>' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 no-fail-closed-placeholder-count"
grep -qF 'count_placeholder_files(&self.placeholder_dir)' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 temp-count-not-private-dir"
grep -qF 'observer.init(move |task_info|' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 paste-result-not-capturing-private-authority"
grep -qF 'remove_placeholder_file_logged(' "$pasteboard_context_rs" || r_s11e13="$r_s11e13 source-cleanup-not-private-authority"
grep -qF 'create_placeholder_file(' "$item_data_provider_rs" || r_s11e13="$r_s11e13 provider-not-using-private-creator"
grep -qF 'placeholder_dir_handle: Arc<File>' "$item_data_provider_rs" || r_s11e13="$r_s11e13 provider-missing-dir-handle"
grep -qF 'type PasteCallback = Box<dyn Fn(&PasteObserverInfo) + Send + '\''static>;' "$paste_observer_rs" || r_s11e13="$r_s11e13 observer-callback-not-capturable"
grep -qF 'private per-context temporary directory' "$pasteboard_readme" || r_s11e13="$r_s11e13 readme-not-updated"
grep -qF 'macOS clipboard-file paste placeholder temp authority' "$REPO/requirements.html" || r_s11e13="$r_s11e13 requirements-disposition-missing"
grep -qF 'R-S11e-13 — macOS clipboard-file paste placeholder temp authority' "$REPO/HARDENING_STATUS.md" || r_s11e13="$r_s11e13 hardening-ledger-missing"
if grep -nE 'format!\("/tmp/|read_dir\("/tmp"\)|std::fs::File::create\(&path\)|std::fs::remove_file\(path\)' "$pasteboard_context_rs" "$item_data_provider_rs" >"$APPLE_CHECK_TMP/rd_apple_r_s11e13"; then
  cat "$APPLE_CHECK_TMP/rd_apple_r_s11e13"
  r_s11e13="$r_s11e13 global-or-path-placeholder-op"
fi
if grep -nF 'std::fs::remove_file(&task_info.source_path)' "$pasteboard_context_rs" >"$APPLE_CHECK_TMP/rd_apple_r_s11e13_source"; then
  cat "$APPLE_CHECK_TMP/rd_apple_r_s11e13_source"
  r_s11e13="$r_s11e13 source-placeholder-path-cleanup"
fi
if [ -n "$r_s11e13" ]; then
  echo "  FAIL R-S11e-13 macOS clipboard-file paste placeholder temp authority:$r_s11e13"
  rc=1
else
  note "ok  R-S11e-13 macOS clipboard-file paste placeholders use a private per-context temp dir with fd-relative exclusive create/unlink"
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
"${APPLE_READ_RUN[@]}" python3 - <<'PY' || rc=1
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
    "com.apple.security.device.audio-input": True,
    "com.apple.security.network.client": True,
}
EXPECTED_PROFILE_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": False,
    "com.apple.security.device.audio-input": True,
    "com.apple.security.network.server": True,
}
EXPECTED_DEBUG_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": False,
    "com.apple.security.cs.allow-jit": True,
    "com.apple.security.device.audio-input": True,
    "com.apple.security.network.server": True,
}
if load_plist("flutter/macos/Runner/Release.entitlements") != EXPECTED_RELEASE_ENTITLEMENTS:
    fail("flutter/macos/Runner/Release.entitlements: entitlement allow-list/value mismatch")
if load_plist("flutter/macos/Runner/Profile.entitlements") != EXPECTED_PROFILE_ENTITLEMENTS:
    fail("flutter/macos/Runner/Profile.entitlements: entitlement allow-list/value mismatch")
if load_plist("flutter/macos/Runner/Debug.entitlements") != EXPECTED_DEBUG_ENTITLEMENTS:
    fail("flutter/macos/Runner/Debug.entitlements: entitlement allow-list/value mismatch")

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
# per-peer connect-equivalent Argon2id PRS ciphertext and device-ID metadata) must be excluded from
# iCloud/iTunes device backups via NSURLIsExcludedFromBackupKey. This is a source-presence assertion —
# the Swift is not built on this Linux host (no Xcode), like the fork's other Apple source-conformance
# items — so it proves the exclusion stays WIRED, not that it runs.
if grep -q 'isExcludedFromBackup' "$REPO/flutter/ios/Runner/AppDelegate.swift"; then
  note "ok  R-X6 iOS: AppDelegate sets NSURLIsExcludedFromBackupKey on the config store (source-layer; Swift not built here)"
else
  echo "  FAIL R-X6 iOS: AppDelegate.swift no longer excludes the config store from backup (isExcludedFromBackup absent)"
  rc=1
fi

echo "== (2f) R-S11bh mobile legacy at-rest migration requires live OS-key authority =="
if python3 scripts/verify-mobile-at-rest-fail-closed.py --repo . --self-test; then
  note "ok  R-S11bh Android/iOS legacy decrypt is migration-only after successful OS-key installation"
else
  echo "  FAIL R-S11bh mobile legacy at-rest fallback can bypass unavailable OS-key authority"
  rc=1
fi

echo "== (2g) R-S11bi macOS launchd explicit-domain lifecycle authority =="
if python3 scripts/verify-macos-launchd-lifecycle.py --repo . --self-test; then
  note "ok  R-S11bi macOS daemon/agent lifecycle uses explicit modern launchd domains and authoritative state proof"
else
  echo "  FAIL R-S11bi macOS launchd lifecycle retains implicit-domain or legacy completion authority"
  rc=1
fi

echo "== (2g-a) R-S11bn exact installed-service ownership classifier =="
if python3 scripts/verify-installed-service-classifier.py --repo . --self-test; then
  note "ok  R-S11bn Linux/macOS installed-service ownership uses exact supported executable identities"
else
  echo "  FAIL R-S11bn installed-service ownership regained ambient path-prefix authority"
  rc=1
fi

echo "== (2g-b) R-S11bo Unix desktop helper exact process roles =="
if python3 scripts/verify-unix-helper-process-role.py --repo . --self-test; then
  note "ok  R-S11bo Unix desktop helper IPC accepts only complete case-sensitive process-role vectors"
else
  echo "  FAIL R-S11bo Unix desktop helper IPC regained ambient first-argument process-role authority"
  rc=1
fi

echo "== (2g-b1) R-S11bs Unix incumbent-listener identity =="
if python3 scripts/verify-unix-listener-incumbent.py --repo . --self-test; then
  note "ok  R-S11bs Unix singleton detection requires current-principal/current-executable incumbent identity"
else
  echo "  FAIL R-S11bs Unix singleton detection regained connect-only or ambiguous-cleanup authority"
  rc=1
fi

echo "== (2g-c) R-S11bp/R-S11eh outgoing voice-call bounded exact-owner lifecycle =="
if python3 scripts/verify-viewer-voice-call-worker.py --repo . --self-test; then
  note "ok  R-S11bp/R-S11eh macOS/shared outgoing voice-call capture is bounded, event-driven, direct-writer, and exact-subscription-owned"
else
  echo "  FAIL R-S11bp/R-S11eh macOS/shared outgoing voice-call capture regained polling, detached subscription lifecycle, or intermediate unbounded audio"
  rc=1
fi

echo "== (2g-c1) R-S11ev outgoing viewer video mailbox =="
if python3 scripts/verify-viewer-video-mailbox.py --repo . --self-test; then
  note "ok  R-S11ev macOS/shared outgoing viewer video uses one bounded, fresh, generation-aware mailbox with exact teardown"
else
  echo "  FAIL R-S11ev macOS/shared outgoing viewer video regained split frame/token reachability, stale-GOP, or teardown debt"
  rc=1
fi

echo "== (2g-c2) R-S11ew/R-S11fr Flutter software-RGBA publication and recovery mailbox =="
if python3 scripts/verify-viewer-rgba-mailbox.py --repo . --self-test; then
  note "ok  R-S11ew/R-S11fr Apple/shared software RGBA publication is exact-session/token-owned, bounded, latest-wins, recoverable, commit-ordered, and pointer-free"
else
  echo "  FAIL R-S11ew/R-S11fr Apple/shared software RGBA publication regained stale, cross-session, cross-stream, unbounded, stranded-recovery, out-of-order-commit, or borrowed-pointer state"
  rc=1
fi

echo "== (2g-c2a) R-S11gu bounded exact-owner native-to-Dart cursor publication =="
if python3 scripts/verify-viewer-cursor-mailbox.py --repo . --self-test; then
  note "ok  R-S11gu Apple/shared cursor publication is exact-owner, topology-ordered, bounded, latest-wins, and stream-recoverable"
else
  echo "  FAIL R-S11gu Apple/shared cursor publication regained generic, stale-owner, stale-topology, unbounded, or stranded stream state"
  rc=1
fi

echo "== (2g-c2aa) R-S11gv exact bounded cursor-shape resources =="
if python3 scripts/verify-viewer-cursor-resources.py --repo . --self-test; then
  note "ok  R-S11gv Apple/shared cursor capture, identity, publication, presentation, and retirement are exact and bounded"
else
  echo "  FAIL R-S11gv Apple/shared cursor resources regained unchecked capture, stale identity, unacknowledged publication, unbounded registration, or incomplete teardown"
  rc=1
fi

echo "== (2g-c2ab) R-S11gw bounded controlled-side service egress =="
if python3 scripts/verify-controlled-control-egress.py --repo . --self-test; then
  note "ok  R-S11gw Apple/shared controlled-side synchronous service egress is ordered, bounded, and failure-visible"
else
  echo "  FAIL R-S11gw Apple/shared controlled-side service egress regained unbounded, reordered, oversized, silently dropped, or stranded state"
  rc=1
fi

echo "== (2g-c2ac) R-S11gx exact keyed-writer count-and-byte ownership =="
if python3 scripts/verify-keyed-writer-budget.py --repo . --self-test; then
  note "ok  R-S11gx Apple/shared keyed writer admission is pre-seal, exact-byte, active-frame-owned, and abort-final"
else
  echo "  FAIL R-S11gx Apple/shared keyed writer regained oversize pre-seal allocation, count/byte retention, active-frame, or abort-finality debt"
  rc=1
fi

echo "== (2g-c2ad) R-S11gy bounded connection-manager result ownership =="
if python3 scripts/verify-cm-egress-budget.py --repo . --self-test; then
  note "ok  R-S11gy Apple/shared connection-manager results have closed count-and-byte ownership at every in-process hop"
else
  echo "  FAIL R-S11gy Apple/shared connection-manager results regained an unbounded hop, incomplete raw-byte accounting, or nonterminal refusal"
  rc=1
fi

echo "== (2g-c2ada) R-S11hb exact bounded native clipboard-listener ownership =="
if python3 scripts/verify-clipboard-listener-ownership.py --repo . --self-test; then
  note "ok  R-S11hb Apple/shared native clipboard-listener callbacks are bounded, exact-generation-owned, and terminal-final"
else
  echo "  FAIL R-S11hb Apple/shared native clipboard-listener callbacks regained unbounded retention, name-only cleanup, or incomplete terminal finality"
  rc=1
fi

echo "== (2g-c2adb) R-S11hd coherent latest-state wakelock snapshot ownership =="
if python3 scripts/verify-wakelock-snapshot-mailbox.py --repo . --self-test; then
  note "ok  R-S11hd Apple/shared controlled-side wakelock snapshots are coherent, latest-state bounded, mutation-ordered, and terminal-visible"
else
  echo "  FAIL R-S11hd Apple/shared wakelock snapshots regained an unbounded queue, split-state read, stale overwrite, or hidden retirement"
  rc=1
fi

echo "== (2g-c2adc) R-S11he serialized controlled-side status refresh ownership =="
if python3 scripts/verify-server-status-refresh-loop.py --repo . --self-test; then
  note "ok  R-S11he Apple/shared controlled-side status refresh is sequential, failure-visible, and drainable"
else
  echo "  FAIL R-S11he Apple/shared status refresh regained overlapping timers, detached reconciliation, or incomplete finality"
  rc=1
fi

echo "== (2g-c2add) R-S11hf bounded exact-generation global Dart event dispatch =="
if python3 scripts/verify-global-event-dispatcher.py --repo . --self-test; then
  note "ok  R-S11hf Apple/shared global Dart event dispatch is bounded, serial, exact-generation-owned, and terminal-visible"
else
  echo "  FAIL R-S11hf Apple/shared global Dart event dispatch regained detached, overlapping, stale-generation, unbounded, or hidden-failure state"
  rc=1
fi

echo "== (2g-c2ae) R-S11gz exact bounded file-clipboard route ownership =="
if python3 scripts/verify-clipboard-route-budget.py --repo . --self-test; then
  note "ok  R-S11gz Apple/shared file-clipboard callbacks have exact connection-round routes and finite count-and-byte ownership"
else
  echo "  FAIL R-S11gz Apple/shared file-clipboard routing regained a shared receiver, colliding identity, stale cleanup, unbounded retention, or nonterminal refusal"
  rc=1
fi

echo "== (2g-c2b) R-S11go exact-owner ordered display-selection finality =="
if python3 scripts/verify-display-selection-finality.py --repo . --self-test; then
  note "ok  R-S11go Apple/shared display selection is exact-owner, typed, ordered, bounded, and failure-visible"
else
  echo "  FAIL R-S11go Apple/shared display selection regained stale-owner, generic-message, split-refresh, premature-local-commit, or controlled-side divergence"
  rc=1
fi

echo "== (2g-c3) R-S11ex/R-S11gf desktop Flutter texture lifecycle and Linux plugin load authority =="
if python3 scripts/verify-desktop-texture-lifecycle.py --repo . --self-test; then
  note "ok  R-S11ex/R-S11fa/R-S11fs/R-S11gf Apple/shared Flutter texture finality and presentation resumption, including pointer-evidenced missing-focus recovery, plus Linux plugin load authority have exact bounded owners"
else
  echo "  FAIL R-S11ex/R-S11fa/R-S11fs/R-S11gf Apple/shared Flutter texture lifecycle, exact presentation-resume recovery including pointer-evidenced missing-focus recovery, or Linux plugin load authority regressed"
  rc=1
fi

echo "== (2g-c4) R-S11fg/R-S11fh/R-S11fi/R-S11fj shared file-command, receive-persistence, and digest-inspection finality =="
if python3 scripts/verify-viewer-file-finality.py --repo . --self-test; then
  note "ok  R-S11fg/R-S11fh/R-S11fi/R-S11fj Apple/shared file frames retain exact writer completion and local persistence/digest failures are terminal"
else
  echo "  FAIL R-S11fg/R-S11fh/R-S11fi/R-S11fj Apple/shared file commands regained silent admission, discarded completion, ambiguous send progress, unbounded ownership, or ignored local persistence/digest failure"
  rc=1
fi

echo "== (3) cross-compile coherence matrix (Rust 1.81, actual Apple features) =="
echo "  targets: ${SELECTED_APPLE_TARGETS[*]}"
[ ! -e "$REPO/src/version.rs" ] || {
  echo "  FAIL non-mutating Apple gate: source tree contains generated src/version.rs"
  rc=1
}

for target in "${SELECTED_APPLE_TARGETS[@]}"; do
  features=$(target_features "$target")
  triplet=$(target_triplet "$target")
  lower_env=$(target_env_lower "$target")
  upper_env=$(target_env_upper "$target")
  anchor_log="$APPLE_CHECK_TMP/apple-anchor-$target.log"
  log="$APPLE_CHECK_TMP/apple-xcheck-$target.log"
  echo "  -- $target features=$features"

  set +e
  "${COMMON_CHECK[@]}" \
    --env SDKROOT=/tmp \
    --env BINDGEN_EXTRA_CLANG_ARGS="-isysroot /tmp" \
    --env "CC_$lower_env=/work/scripts/apple-cc-shim.sh" \
    --env "CXX_$lower_env=/work/scripts/apple-cc-shim.sh" \
    --env "CFLAGS_$lower_env=-isysroot /tmp" \
    --env "CXXFLAGS_$lower_env=-isysroot /tmp" \
    --env "CARGO_TARGET_${upper_env}_LINKER=/work/scripts/apple-cc-shim.sh" \
    "$IMAGE_ID" /bin/bash --noprofile --norc -s -- "$target" "$triplet" <<'SH' >"$anchor_log" 2>&1
set -euo pipefail
target="$1"; triplet="$2"
stub=/tmp/apple-vcpkg
rm -rf "$stub"
mkdir -p "$stub/installed/$triplet/include" "$stub/installed/$triplet/lib"
for d in opus vpx libyuv; do
  [ -d "/usr/include/$d" ] && ln -s "/usr/include/$d" "$stub/installed/$triplet/include/$d"
done
export VCPKG_ROOT="$stub"
cargo check --locked --offline --config /tmp/cargo-config.toml --jobs 1 \
  --package hbb_common --target "$target"
SH
  anchor_rc=$?
  set -e
  if [ "$anchor_rc" -ne 0 ]; then
    echo "  FAIL $target hbb_common workspace anchor did not compile cleanly:"
    tail -40 "$anchor_log" | sed 's/^/      /'
    rc=1
    continue
  fi
  note "ok  $target hbb_common workspace anchor compiled cleanly"

  set +e
  "${COMMON_CHECK[@]}" \
    --env SDKROOT=/tmp \
    --env BINDGEN_EXTRA_CLANG_ARGS="-isysroot /tmp" \
    --env "CC_$lower_env=/work/scripts/apple-cc-shim.sh" \
    --env "CXX_$lower_env=/work/scripts/apple-cc-shim.sh" \
    --env "CFLAGS_$lower_env=-isysroot /tmp" \
    --env "CXXFLAGS_$lower_env=-isysroot /tmp" \
    --env "CARGO_TARGET_${upper_env}_LINKER=/work/scripts/apple-cc-shim.sh" \
    "$IMAGE_ID" /bin/bash --noprofile --norc -s -- "$target" "$features" "$triplet" <<'SH' >"$log" 2>&1
set -euo pipefail
target="$1"; features="$2"; triplet="$3"
stub=/tmp/apple-vcpkg
rm -rf "$stub"
mkdir -p "$stub/installed/$triplet/include" "$stub/installed/$triplet/lib"
for d in opus vpx libyuv; do
  [ -d "/usr/include/$d" ] && ln -s "/usr/include/$d" "$stub/installed/$triplet/include/$d"
done
export VCPKG_ROOT="$stub"
cargo check --locked --offline --config /tmp/cargo-config.toml --jobs 1 \
  --target "$target" --features "$features"
SH
  xrc=$?
  set -e
  if [ "$xrc" = 0 ]; then
    note "ok  $target SDK-free cross-check compiled clean"
  elif grep -qE 'error\[E[0-9]{4}\]' "$log"; then
    echo "  FAIL $target has a Rust compiler error (real Apple-cfg coherence break):"
    grep -nE 'error\[E[0-9]{4}\]' "$log" | head -25 | sed 's/^/      /'
    rc=1
  elif apple_sdk_boundary_after_successful_workspace_anchor "$log"; then
    note "ok  $target reached the expected Apple SDK/header boundary with no Rust error"
  else
    echo "  FAIL $target failed before the accepted SDK/header boundary:"
    tail -40 "$log" | sed 's/^/      /'
    rc=1
  fi
done

echo "== Apple desktop port-forward mapping conformance (R-T17/PF-1..PF-5) =="
pf17=
grep -qF 'pub struct PortForwardTarget' "$REPO/src/client.rs" || pf17="$pf17 immutable-target"
grep -qF 'const MAX_PORT_FORWARD_HOST_BYTES: usize = 253;' "$REPO/src/client.rs" || pf17="$pf17 target-host-cap"
grep -qF "strip_prefix('[')" "$REPO/src/client.rs" || pf17="$pf17 bracketed-ipv6"
if grep -qE 'pub port_forward:[[:space:]]*\(' "$REPO/src/client.rs"; then pf17="$pf17 shared-target-state"; fi
grep -qF 'tcp::new_exclusive_listener' "$REPO/src/port_forward.rs" || pf17="$pf17 exclusive-listener"
grep -qF 'const MAX_PORT_FORWARD_CONNECTIONS_PER_MAPPING: usize = 32;' "$REPO/src/port_forward.rs" || pf17="$pf17 per-mapping-admission"
grep -qF 'const MAX_PORT_FORWARD_CONNECTIONS_PROCESS: usize = 128;' "$REPO/src/port_forward.rs" || pf17="$pf17 process-admission"
grep -qF 'fn try_acquire() -> Result<Self, String>' "$REPO/src/port_forward.rs" || pf17="$pf17 opaque-mapping-admission"
grep -qF 'mpsc::channel(1)' "$REPO/src/port_forward.rs" || pf17="$pf17 bounded-closed-control"
grep -qF 'reap_ready_tasks(&mut tasks' "$REPO/src/port_forward.rs" || pf17="$pf17 eager-task-reaping"
grep -qF 'drain_join_set(&mut tasks' "$REPO/src/port_forward.rs" || pf17="$pf17 connection-drain"
grep -qF 'relay_after_authorization(setup' "$REPO/src/port_forward.rs" || pf17="$pf17 post-login-relay"
if grep -qF 'allow_err!' "$REPO/src/port_forward.rs"; then pf17="$pf17 silent-io-error"; fi
if grep -qF 'mpsc::UnboundedReceiver<Data>' "$REPO/src/port_forward.rs"; then pf17="$pf17 general-data-listener-control"; fi
grep -qF '.name("rustdesk-port-forward-owner".to_owned())' "$REPO/src/ui_session_interface.rs" || pf17="$pf17 dedicated-owner-thread"
grep -qF 'tokio::runtime::Builder::new_current_thread()' "$REPO/src/ui_session_interface.rs" || pf17="$pf17 independent-owner-runtime"
grep -qF '.name("rustdesk-port-forward-one-off".to_owned())' "$REPO/src/port_forward.rs" || pf17="$pf17 one-off-owner-thread"
grep -qF 'std::sync::mpsc::sync_channel(PORT_FORWARD_OWNER_REAPER_CAPACITY)' "$REPO/src/port_forward.rs" || pf17="$pf17 bounded-owner-reaper"
grep -qF 'ensure_port_forward_owner_reaper();' "$REPO/src/ui_session_interface.rs" || pf17="$pf17 owner-reaper-prebootstrap"
grep -qF 'PORT_FORWARD_OWNER_REAPER.try_send(request)' "$REPO/src/port_forward.rs" || pf17="$pf17 nonblocking-owner-handoff"
[ "$(grep -cF 'std::process::abort();' "$REPO/src/port_forward.rs")" -ge 2 ] || pf17="$pf17 fail-stop-owner-handoff"
one_off_join=$(awk '/async fn join_one_off_owner_off_runtime/,/^}/' "$REPO/src/port_forward.rs")
ui_owner_impl=$(awk '/impl PortForwardSupervisorOwner/,/^}/' "$REPO/src/ui_session_interface.rs")
ui_owner_drop=$(awk '/impl Drop for PortForwardSupervisorOwner/,/^}/' "$REPO/src/ui_session_interface.rs")
if grep -qF '.join()' <<<"$one_off_join$ui_owner_impl$ui_owner_drop"; then pf17="$pf17 synchronous-join-fallback"; fi
grep -qF 'while let Some(command) = commands.recv().await' "$REPO/src/ui_session_interface.rs" || pf17="$pf17 supervisor-eof"
grep -qF 'drain_owned_port_forwards(&mut mappings).await;' "$REPO/src/ui_session_interface.rs" || pf17="$pf17 supervisor-drain"
grep -qF 'second_exclusive_listener_bind_is_refused' "$REPO/libs/hbb_common/src/tcp.rs" || pf17="$pf17 cfg-native-second-bind-test"
if [ -n "$pf17" ]; then
  echo "  FAIL R-T17 Apple desktop tunnel mapping conformance:$pf17"
  rc=1
else
  note "ok  macOS shares immutable target, exclusive bind, bounded admission/control, fail-stop nonblocking owner-reaper handoff, independent owner-runtime drain, post-login relay, and cfg-native second-bind test"
fi

if [ -e "$REPO/src/version.rs" ]; then
  echo "  FAIL non-mutating Apple gate: cargo check created source-tree version output"
  rc=1
else
  note "ok  non-mutating source proof: read-only source tree has no generated src/version.rs"
fi

/usr/bin/python3 scripts/online-input-provenance.py verify-subtree \
  --tree "$APPLE_VENDOR" \
  --expected "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
  || die "private Cargo vendor snapshot changed during Apple verification"
SOURCE_DIGEST_AFTER="$(archive_current_source | sha256sum | awk '{print $1}')"
[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ] \
  || die "Apple verification detected a change in the real source worktree"
FINAL_IMAGE_ID="$(apple_docker image inspect --format '{{.Id}}' "$IMAGE_ID")" \
  || die "immutable Apple-check image disappeared during verification"
[ "$FINAL_IMAGE_ID" = "$IMAGE_ID" ] \
  || die "immutable Apple-check image identity changed during verification"
verify_apple_docker_authority

echo
if [ "$rc" = 0 ]; then
  echo "== apple-conform-check PASS =="
else
  echo "== apple-conform-check FAIL =="
fi
exit "$rc"
