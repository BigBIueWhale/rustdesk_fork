#!/usr/bin/env -S -i /usr/bin/bash --noprofile --norc
set -euo pipefail
umask 077

readonly SAFE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
readonly ENV_MARKER_VALUE=rustdesk-release-workspace-runtime-v1
readonly UID_NOW="$(/usr/bin/id -u)"
readonly GID_NOW="$(/usr/bin/id -g)"

fail() {
    printf 'release-workspace-runtime: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] && [ "$1" = --self-test-vm-runtime ] \
    || fail 'usage: verify-release-workspace-runtime.sh --self-test-vm-runtime'
[ "$UID_NOW:$GID_NOW" = 4000:4000 ] \
    || fail 'requires UID/GID 4000'

if [ "${WORKSPACE_RUNTIME_ENV_MARKER:-}" != "$ENV_MARKER_VALUE" ]; then
    passwd_entry="$(/usr/bin/getent passwd "$UID_NOW")" \
        || fail 'cannot resolve the admitted principal home'
    safe_home="$(printf '%s\n' "$passwd_entry" | /usr/bin/awk -F: 'NF == 7 { print $6 }')"
    [ -n "$safe_home" ] && [ -d "$safe_home" ] \
        || fail 'the admitted principal home is invalid'
    exec /usr/bin/env -i \
        HOME="$safe_home" PATH="$SAFE_PATH" LC_ALL=C LANG=C TZ=UTC \
        WORKSPACE_RUNTIME_ENV_MARKER="$ENV_MARKER_VALUE" \
        /usr/bin/bash --noprofile --norc "$0" "$@"
fi

while IFS= read -r name; do
    case "$name" in
        HOME|PATH|LC_ALL|LANG|TZ|WORKSPACE_RUNTIME_ENV_MARKER|PWD|SHLVL|_) ;;
        *) fail "closed environment contains unexpected variable: $name" ;;
    esac
done < <(compgen -e)

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/.." && /usr/bin/pwd -P)"
readonly ENTRY_PREFLIGHT="$SCRIPT_DIR/verify-vm-entry-preflight.sh"
readonly RELEASE_PARENT="$SCRIPT_DIR/build-release.sh"
readonly PUBLISHER="$SCRIPT_DIR/publish-github-release.sh"
readonly TREE_HELPER="$SCRIPT_DIR/verify-private-tree-closure.py"
readonly FINALIZER="$SCRIPT_DIR/finalize-release-set.py"

for source in "$ENTRY_PREFLIGHT" "$RELEASE_PARENT" "$PUBLISHER" "$TREE_HELPER" \
    "$FINALIZER" "$SCRIPT_DIR/fork-version.sh" "$SCRIPT_DIR/lib.sh" \
    "$SCRIPT_DIR/pins.env"; do
    [ -f "$source" ] && [ ! -L "$source" ] \
        || fail "required source is absent or ambiguous: $source"
done

/usr/bin/bash "$ENTRY_PREFLIGHT" >/dev/null \
    || fail 'authenticated no-NIC verifier-VM admission failed'

ROOT=
ROOT_ID=
SUCCESS=0

cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT HUP INT TERM
    if [ -n "$ROOT" ]; then
        if [ -n "$ROOT_ID" ] && [ -d "$ROOT" ] && [ ! -L "$ROOT" ]; then
            /usr/bin/python3 -I -S "$TREE_HELPER" \
                --remove-private-root "$ROOT" --expected-identity "$ROOT_ID" \
                || cleanup_status=1
        else
            cleanup_status=1
        fi
    fi
    [ "$cleanup_status" -eq 0 ] || status=1
    if [ "$status" -eq 0 ] && [ "$SUCCESS" -eq 1 ]; then
        printf 'RELEASE_WORKSPACE_RUNTIME=pass uid=4000 gid=4000 network=none release=actual reset=actual publisher=actual closure=actual cleanup=joined\n'
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ROOT="$(/usr/bin/mktemp -d /tmp/rustdesk-release-workspace-runtime.XXXXXXXXXX)" \
    || fail 'cannot create the private runtime fixture root'
/usr/bin/chmod 0700 "$ROOT"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ROOT")" = 4000:4000:700 ] \
    || fail 'runtime fixture root metadata differs'
ROOT_ID="$(/usr/bin/stat -c '%d:%i' -- "$ROOT")" \
    || fail 'cannot record the runtime fixture root identity'

run_stage() {
    local label=$1 marker=$2 output status=0
    shift 2
    output="$("$@" 2>&1)" || status=$?
    [ "${#output}" -le 1048576 ] \
        || fail "$label output exceeded its byte bound"
    if [ "$status" -ne 0 ]; then
        printf '%s\n' "$output" | /usr/bin/tail -n 80 >&2
        fail "$label failed with status $status"
    fi
    if [ -n "$marker" ] && ! /usr/bin/grep -Fq -- "$marker" <<<"$output"; then
        printf '%s\n' "$output" | /usr/bin/tail -n 80 >&2
        fail "$label success marker is absent"
    fi
}

if /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 120s \
    /usr/bin/python3 -I -S "$TREE_HELPER" --self-test --scratch-fd 9 \
    --expected-identity 0:1 9<"$ROOT" >/dev/null 2>&1; then
    fail 'private-tree descriptor fixture accepted the wrong creation identity'
fi
[ -z "$(/usr/bin/find "$ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ] \
    || fail 'wrong-identity descriptor fixture created scratch state'

run_stage 'private-tree descriptor fixture' '' \
    /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 120s \
    /usr/bin/python3 -I -S "$TREE_HELPER" --self-test --scratch-fd 9 \
    --expected-identity "$ROOT_ID" \
    9<"$ROOT"

run_stage 'release transaction fixture' 'build-release self-test: OK' \
    /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 180s \
    /usr/bin/bash --noprofile --norc "$RELEASE_PARENT" --self-test

run_stage 'publisher transaction fixture' 'publish-github-release self-test: OK' \
    /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 180s \
    /usr/bin/bash --noprofile --norc "$PUBLISHER" --self-test

readonly RESET_REPO="$ROOT/reset-repository"
/usr/bin/install -d -m 0700 "$RESET_REPO/scripts" "$RESET_REPO/flutter"
for name in build-release.sh fork-version.sh lib.sh; do
    /usr/bin/install -m 0755 "$SCRIPT_DIR/$name" "$RESET_REPO/scripts/$name"
done
for name in finalize-release-set.py verify-private-tree-closure.py; do
    /usr/bin/install -m 0755 "$SCRIPT_DIR/$name" "$RESET_REPO/scripts/$name"
done
/usr/bin/install -m 0644 "$SCRIPT_DIR/pins.env" "$RESET_REPO/scripts/pins.env"
printf '/target/\n/flutter/.dart_tool/\n' >"$RESET_REPO/.gitignore"
printf 'release workspace reset fixture\n' >"$RESET_REPO/source"

export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0 GIT_NO_REPLACE_OBJECTS=1
/usr/bin/git -C "$RESET_REPO" -c core.hooksPath=/dev/null init --quiet --initial-branch=master \
    || fail 'cannot initialize the reset fixture repository'
/usr/bin/git -C "$RESET_REPO" -c core.hooksPath=/dev/null add -- . \
    || fail 'cannot stage the reset fixture repository'
/usr/bin/git -C "$RESET_REPO" -c core.hooksPath=/dev/null \
    -c user.name=fixture -c user.email=fixture.invalid \
    commit --quiet -m fixture \
    || fail 'cannot commit the reset fixture repository'
unset GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM \
    GIT_TERMINAL_PROMPT GIT_NO_REPLACE_OBJECTS

run_stage 'owner-only reset transaction fixture' \
    'build-release owner-only reset self-test: OK' \
    /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 180s \
    /usr/bin/bash --noprofile --norc \
    "$RESET_REPO/scripts/build-release.sh" --self-test-reset

SUCCESS=1
