#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    && [ "${CARGO_TARGET_DIR:-}" = /cargo-target ] \
    && [ -d /tmp/option-ack ] && [ ! -L /tmp/option-ack ] \
    && [ "$(stat -c '%u:%g:%a' /tmp/option-ack)" = 1000:1000:700 ] \
    || { echo 'Option bridge test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/option-ack/bridge
mkdir -m 0700 -- "$WORK" "$WORK/config" "$WORK/home"
printf 'OPTION_WIRE_BUILD=started target=linux-cdylib budget_seconds=240\n'
build_started=$SECONDS
build_status=0
timeout --signal=TERM --kill-after=5s 240s \
    cargo rustc --offline --locked --lib --crate-type cdylib \
        --features linux-pkg-config,flutter --message-format=json --color never \
        >"$WORK/build.json" || build_status=$?
library=$(python3 -I -S - "$WORK/build.json" "$build_status" <<'PY'
import json
import sys
from pathlib import Path

with Path(sys.argv[1]).open('rb') as stream:
    output = stream.read(4 * 1024 * 1024 + 1)
assert len(output) <= 4 * 1024 * 1024, 'option bridge Cargo metadata exceeds 4 MiB'
messages = [json.loads(line) for line in output.splitlines() if line.startswith(b'{')]
if sys.argv[2] != '0':
    errors = [m['message'].get('rendered', m['message']['message']) for m in messages
              if m.get('reason') == 'compiler-message' and m['message']['level'] == 'error']
    print('\n'.join(errors)[-16000:], file=sys.stderr)
    sys.exit('option bridge cdylib build failed: ' + sys.argv[2])
assert [m['success'] for m in messages if m.get('reason') == 'build-finished'] == [True]
artifacts = [m for m in messages if m.get('reason') == 'compiler-artifact'
             and m.get('manifest_path') == '/source/Cargo.toml'
             and m['target']['name'] == 'librustdesk'
             and m['target']['src_path'] == '/source/src/lib.rs']
assert len(artifacts) == 1
artifact = artifacts[0]
profile = artifact['profile']
assert artifact['target']['crate_types'] == ['cdylib']
assert profile['test'] is False and profile['debuginfo'] == 0 and profile['opt_level'] == '0'
assert profile['debug_assertions'] is True and profile['overflow_checks'] is True
libraries = [p for p in artifact['filenames'] if p.endswith('.so')]
assert libraries == ['/cargo-target/debug/liblibrustdesk.so']
print(libraries[0])
PY
)
[ -f "$library" ] && [ ! -L "$library" ] && [ -x "$library" ] \
    && [ "$(stat -c '%u:%g:%h' -- "$library")" = 1000:1000:2 ] \
    && [ ! -L /cargo-target/debug/deps/liblibrustdesk.so ] \
    && [ "$library" -ef /cargo-target/debug/deps/liblibrustdesk.so ]
artifact_sha=$(sha256sum "$library" | cut -d ' ' -f 1)
dart_sha=$(sha256sum /option-dart/client | cut -d ' ' -f 1)
printf 'OPTION_WIRE_BUILD=pass seconds=%s artifact_sha256=%s\n' \
    "$((SECONDS - build_started))" "$artifact_sha"
execution_started=$SECONDS
HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/config" \
    timeout --signal=TERM --kill-after=5s 30s /option-dart/client "$library"
[ "$(sha256sum "$library" | cut -d ' ' -f 1)" = "$artifact_sha" ]
[ "$(sha256sum /option-dart/client | cut -d ' ' -f 1)" = "$dart_sha" ]
printf 'OPTION_WIRE_ARTIFACT=pass sha256=%s library=%s dart_sha256=%s cases=15 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$library" "$dart_sha" "$((SECONDS - execution_started))"
