#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
[ "$PWD" = /work ] || {
  echo "version-metadata-check: repository must be mounted at /work" >&2
  exit 1
}
[ "${CARGO_TARGET_DIR:-}" = /build ] || {
  echo "version-metadata-check: CARGO_TARGET_DIR must be /build" >&2
  exit 1
}
[ "${CARGO_HOME:-}" = /tmp/cargo-home ] || {
  echo "version-metadata-check: CARGO_HOME must be /tmp/cargo-home" >&2
  exit 1
}
[ -f /tmp/cargo-config.toml ] && [ ! -L /tmp/cargo-config.toml ] || {
  echo "version-metadata-check: exact Cargo config mount is unavailable" >&2
  exit 1
}
case "${SOURCE_DATE_EPOCH:-}" in
  ''|*[!0-9]*|0[0-9]*)
    echo "version-metadata-check: SOURCE_DATE_EPOCH is not canonical" >&2
    exit 1
    ;;
esac

tmp="$(umask 077 && mktemp -d /tmp/rustdesk-version-metadata.XXXXXXXXXX)"
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  rm -rf -- "$tmp" || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

metadata="$(cargo --config /tmp/cargo-config.toml --offline --locked metadata --no-deps --format-version 1)"
app_version="$(printf '%s' "$metadata" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
packages = [package for package in data["packages"] if package["manifest_path"] == "/work/Cargo.toml"]
if len(packages) != 1:
    raise SystemExit("expected exactly one root Cargo package")
package = packages[0]
build_dependencies = {(dependency["name"], dependency.get("kind")) for dependency in package["dependencies"]}
if ("chrono", "build") not in build_dependencies:
    raise SystemExit("chrono is not a root build dependency")
if ("hbb_common", "build") in build_dependencies:
    raise SystemExit("hbb_common remains a root build dependency")
print(package["version"])
')"
expected_date="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M')"
expected="$tmp/expected-version.rs"
printf 'pub const VERSION: &str = "%s";\n#[allow(dead_code)]\npub const BUILD_DATE: &str = "%s";\n' \
  "$app_version" "$expected_date" >"$expected"

mapfile -d '' -t generated_outputs < <(
  find /build/debug/build -path '/build/debug/build/rustdesk-*/out/version.rs' -type f -print0
)
[ "${#generated_outputs[@]}" -gt 0 ] || {
  echo "version-metadata-check: no current Cargo OUT_DIR version output was generated" >&2
  exit 1
}
for generated in "${generated_outputs[@]}"; do
  cmp -- "$expected" "$generated" || {
    echo "version-metadata-check: unexpected generated metadata: $generated" >&2
    exit 1
  }
done

mapfile -d '' -t build_scripts < <(
  find /build/debug/build -path '/build/debug/build/rustdesk-*/build-script-build' -type f -print0
)
[ "${#build_scripts[@]}" -gt 0 ] || {
  echo "version-metadata-check: no current rustdesk build-script executable was produced" >&2
  exit 1
}

run_valid() {
  local build_script="$1" out
  out="$(mktemp -d "$tmp/valid.XXXXXXXXXX")"
  env \
    OUT_DIR="$out" \
    CARGO_PKG_VERSION="$app_version" \
    CARGO_CFG_TARGET_OS=linux \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    RUSTDESK_CANARY_OFFLINE=0 \
    "$build_script" >/dev/null
  cmp -- "$expected" "$out/version.rs"
}

run_invalid_epoch() {
  local build_script="$1" value="$2" out
  out="$(mktemp -d "$tmp/epoch.XXXXXXXXXX")"
  if env \
    OUT_DIR="$out" \
    CARGO_PKG_VERSION="$app_version" \
    CARGO_CFG_TARGET_OS=linux \
    SOURCE_DATE_EPOCH="$value" \
    RUSTDESK_CANARY_OFFLINE=0 \
    "$build_script" >/dev/null 2>&1; then
    echo "version-metadata-check: accepted invalid SOURCE_DATE_EPOCH: $value" >&2
    exit 1
  fi
  [ ! -e "$out/version.rs" ] || {
    echo "version-metadata-check: invalid SOURCE_DATE_EPOCH produced output: $value" >&2
    exit 1
  }
}

run_invalid_package_version() {
  local build_script="$1" value="$2" out
  out="$(mktemp -d "$tmp/package.XXXXXXXXXX")"
  if env \
    OUT_DIR="$out" \
    CARGO_PKG_VERSION="$value" \
    CARGO_CFG_TARGET_OS=linux \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    RUSTDESK_CANARY_OFFLINE=0 \
    "$build_script" >/dev/null 2>&1; then
    echo "version-metadata-check: accepted invalid CARGO_PKG_VERSION: $value" >&2
    exit 1
  fi
  [ ! -e "$out/version.rs" ]
}

run_invalid_fork() {
  local build_script="$1" fixture="$2" contents="${3-}" root
  root="$(mktemp -d "$tmp/fork.XXXXXXXXXX")"
  mkdir -p "$root/generated"
  case "$fixture" in
    missing) ;;
    directory) mkdir "$root/FORK_VERSION" ;;
    symlink)
      printf '%s-hardened.1\n' "$app_version" >"$root/fork-version-target"
      ln -s fork-version-target "$root/FORK_VERSION"
      ;;
    *) printf '%s' "$contents" >"$root/FORK_VERSION" ;;
  esac
  if (cd "$root" && env \
    OUT_DIR="$root/generated" \
    CARGO_PKG_VERSION="$app_version" \
    CARGO_CFG_TARGET_OS=linux \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    RUSTDESK_CANARY_OFFLINE=0 \
    "$build_script" >/dev/null 2>&1); then
    echo "version-metadata-check: accepted invalid FORK_VERSION fixture: $fixture" >&2
    exit 1
  fi
  [ ! -e "$root/generated/version.rs" ] || {
    echo "version-metadata-check: invalid FORK_VERSION produced output: $fixture" >&2
    exit 1
  }
}

for build_script in "${build_scripts[@]}"; do
  run_valid "$build_script"
  for value in '' -1 +1 abc 01700000000 9223372036854775808 9223372036854775807; do
    run_invalid_epoch "$build_script" "$value"
  done
  for value in '' 1.4 1.04.7 1.4.7-beta; do
    run_invalid_package_version "$build_script" "$value"
  done
  run_invalid_fork "$build_script" missing
  run_invalid_fork "$build_script" directory
  run_invalid_fork "$build_script" symlink
  run_invalid_fork "$build_script" empty ''
  run_invalid_fork "$build_script" no-final-newline "${app_version}-hardened.1"
  run_invalid_fork "$build_script" multiline "${app_version}-hardened.1"$'\nextra\n'
  run_invalid_fork "$build_script" wrong-base "${app_version}.0-hardened.1"$'\n'
  run_invalid_fork "$build_script" zero-counter "${app_version}-hardened.0"$'\n'
  run_invalid_fork "$build_script" leading-zero-counter "${app_version}-hardened.01"$'\n'
  run_invalid_fork "$build_script" nonnumeric-counter "${app_version}-hardened.x"$'\n'
done

[ ! -e /work/src/version.rs ]
echo "VERSION-METADATA-CHECK: exact OUT_DIR bytes and fail-closed metadata inputs are GREEN"
