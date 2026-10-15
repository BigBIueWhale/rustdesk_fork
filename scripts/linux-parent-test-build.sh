# Shared guest-only compiler for the complete pinned Linux library test artifact.
# Callers retain test_executable and artifact_sha for exact behavioral execution.
build_linux_parent_test() {
    [ "$#" -eq 2 ] || return 1
    local work=$1 receipt_prefix=$2
    [[ "$work" = /tmp/pa-runtime || "$work" = /tmp/resolution-parent ]] \
        && [[ "$receipt_prefix" = PA_RUNTIME || "$receipt_prefix" = RESOLUTION_PARENT ]] \
        && [ "$PWD" = /source ] && [ "$(id -u):$(id -g)" = 1000:1000 ] \
        && [ "${CARGO_TARGET_DIR:-}" = /cargo-target ] \
        && [ -d "$work" ] && [ ! -L "$work" ] \
        && [ "$(stat -c '%u:%g:%a' -- "$work")" = 1000:1000:700 ] \
        || { echo 'Linux parent compiler entry authority differs' >&2; return 1; }
    printf '%s_BUILD=started target=linux-libtest budget_seconds=600\n' "$receipt_prefix"
    local build_started=$SECONDS
    local build_status=0
    timeout --signal=TERM --kill-after=5s 600s \
        cargo test --offline --locked --lib --features linux-pkg-config --no-run \
        --message-format=json-render-diagnostics --color never >"$work/build.json" || build_status=$?
    if [ "$build_status" -ne 0 ]; then
        python3 -I -S - "$work/build.json" <<'PY'
import os
import sys
with open(sys.argv[1], 'rb') as stream:
    stream.seek(0, os.SEEK_END)
    stream.seek(max(0, stream.tell() - 16000))
    print(stream.read(16000).decode('utf-8',errors='replace'),file=sys.stderr)
PY
        cat /sys/fs/cgroup/memory.events >&2
        exit "$build_status"
    fi
    test_executable="$(python3 -I -S - "$work/build.json" <<'PY'
import json
import os
import re
import sys

with open(sys.argv[1], 'rb') as stream:
    output = stream.read(4 * 1024 * 1024 + 1)
if len(output) > 4 * 1024 * 1024:
    sys.exit('Linux parent Cargo metadata exceeds 4 MiB')
artifacts = []
finished = []
for line in output.splitlines():
    if not line.startswith(b'{'):
        continue
    message = json.loads(line)
    if message.get('reason') == 'build-finished':
        finished.append(message.get('success'))
    if (message.get('reason') == 'compiler-artifact'
            and message.get('manifest_path') == '/source/Cargo.toml'
            and message.get('target', {}).get('name') == 'librustdesk'
            and message.get('target', {}).get('src_path') == '/source/src/lib.rs'
            and message.get('profile', {}).get('test') is True):
        if os.environ.get('CARGO_PROFILE_TEST_DEBUG') == '0':
            profile = message['profile']
            if (profile.get('debuginfo') != 0 or profile.get('opt_level') != '0'
                    or profile.get('debug_assertions') is not True
                    or profile.get('overflow_checks') is not True):
                sys.exit('bounded parent artifact compiler profile differs')
        artifacts.append(message.get('executable'))
if finished != [True] or len(artifacts) != 1 or not isinstance(artifacts[0], str):
    sys.exit('Linux parent build lacks one exact completed library test artifact')
if not re.fullmatch(r'/cargo-target/debug/deps/librustdesk-[0-9a-f]{16}', artifacts[0]):
    sys.exit('Linux parent test artifact is outside its private target directory')
print(artifacts[0])
PY
)"
    [ -f "$test_executable" ] && [ ! -L "$test_executable" ] \
        && [ -x "$test_executable" ] \
        && [ "$(stat -c '%u:%g:%h' -- "$test_executable")" = 1000:1000:1 ] \
        || { echo 'Linux parent test artifact metadata differs' >&2; exit 1; }
    artifact_sha="$(sha256sum "$test_executable" | cut -d ' ' -f 1)"
    [[ "$artifact_sha" =~ ^[0-9a-f]{64}$ ]]
    printf '%s_BUILD=pass seconds=%s artifact_sha256=%s\n' \
        "$receipt_prefix" "$((SECONDS - build_started))" "$artifact_sha"
}
