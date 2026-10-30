#!/usr/bin/env bash
set -euo pipefail
umask 077
[ "$#" -eq 0 ] && [ "$PWD" = /source ] && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'language test entry differs' >&2; exit 1; }
readonly WORK=/tmp/language-selection
mkdir -m 700 -- "$WORK"
mkdir "$WORK/src"
cp /source/scripts/test-language-selection.rs "$WORK/src/lib.rs"
cp /source/src/lang.rs /source/src/lang_locale.rs "$WORK/src/"
cp -r /source/src/lang "$WORK/src/"
cat >"$WORK/Cargo.toml" <<'TOML'
[package]
name = "language-selection"
version = "0.0.0"
edition = "2021"
[lib]
path = "src/lib.rs"
[workspace]
[dependencies]
lazy_static = "=1.5.0"
regex = "=1.11.1"
sys-locale = "=0.3.1"
TOML
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
cargo generate-lockfile --manifest-path "$WORK/Cargo.toml" --offline
printf 'LANGUAGE_SELECTION_LOCK=sha256=%s\n' "$(sha256sum "$WORK/Cargo.lock" | cut -d ' ' -f 1)"
cargo test --manifest-path "$WORK/Cargo.toml" --offline --locked --lib --no-run --color never
cmp /source/scripts/test-language-selection.rs "$WORK/src/lib.rs"
cmp /source/src/lang.rs "$WORK/src/lang.rs"
cmp /source/src/lang_locale.rs "$WORK/src/lang_locale.rs"
diff -qr /source/src/lang "$WORK/src/lang"
test_executable=
for candidate in /cargo-target/debug/deps/language_selection-*; do
    [[ "$candidate" =~ ^/cargo-target/debug/deps/language_selection-[0-9a-f]{16}$ ]] || continue
    [ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -x "$candidate" ] \
        && [ "$(stat -c '%u:%g:%h' -- "$candidate")" = 1000:1000:1 ] || exit 1
    [ -z "$test_executable" ] || exit 1
    test_executable=$candidate
done
[ -n "$test_executable" ]
artifact_sha="$(sha256sum "$test_executable" | cut -d ' ' -f 1)"
printf 'LANGUAGE_SELECTION_ARTIFACT_BEFORE=sha256=%s\n' "$artifact_sha"
timeout --signal=TERM --kill-after=5s 10s "$test_executable" --test-threads=1 --color never
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'LANGUAGE_SELECTION_ARTIFACT=pass sha256=%s tests=15 unchanged=before-after\n' "$artifact_sha"
