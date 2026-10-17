#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Local file-listing test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/local-file-listing
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
[ "${CARGO_TARGET_DIR:-}" = /cargo-target ]
printf 'LOCAL_FILE_LISTING_BUILD=started target=linux-cdylib budget_seconds=240\n'
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
if len(output) > 4 * 1024 * 1024:
    sys.exit('local listing Cargo metadata exceeds 4 MiB')
messages = [json.loads(line) for line in output.splitlines() if line.startswith(b'{')]
if sys.argv[2] != '0':
    errors = [m['message'].get('rendered', m['message']['message']) for m in messages
              if m.get('reason') == 'compiler-message' and m['message']['level'] == 'error']
    print('\n'.join(errors)[-16000:], file=sys.stderr)
    sys.exit('local listing cdylib build failed: ' + sys.argv[2])
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
assert len(libraries) == 1 and libraries[0] == '/cargo-target/debug/liblibrustdesk.so'
print(libraries[0])
PY
)
[ -f "$library" ] && [ ! -L "$library" ] && [ -x "$library" ] \
    && [ "$(stat -c '%u:%g' -- "$library")" = 1000:1000 ]
# Cargo publishes the top-level cdylib as a hard link to its private deps artifact.
[ ! -L /cargo-target/debug/deps/liblibrustdesk.so ] \
    && [ "$library" -ef /cargo-target/debug/deps/liblibrustdesk.so ] \
    && [ "$(stat -c '%h' -- "$library")" = 2 ]
artifact_sha=$(sha256sum "$library" | cut -d ' ' -f 1)
dart_sha=$(sha256sum /listing-dart/client | cut -d ' ' -f 1)
printf 'LOCAL_FILE_LISTING_BUILD=pass seconds=%s artifact_sha256=%s\n' \
    "$((SECONDS - build_started))" "$artifact_sha"
execution_started=$SECONDS
timeout --signal=TERM --kill-after=5s 30s \
    /listing-dart/client "$library"
[ "$(sha256sum "$library" | cut -d ' ' -f 1)" = "$artifact_sha" ]
[ "$(sha256sum /listing-dart/client | cut -d ' ' -f 1)" = "$dart_sha" ]
printf 'LOCAL_FILE_LISTING_ARTIFACT=pass sha256=%s library=%s dart_sha256=%s tests=3 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$library" "$dart_sha" "$((SECONDS - execution_started))"
