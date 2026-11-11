#!/usr/bin/env bash
# Derive an exact candidate cache from authenticated inputs inside the owned VM.
set -euo pipefail
umask 077
[ "$#" -eq 1 ] && [ "$(id -u)" -ne 0 ] && [ "$(id -g)" -ne 0 ] \
    || { echo 'plugin cache derivation requires one phase and an ordinary principal' >&2; exit 1; }
case "$1" in prepare|derive|replay) ;; *) exit 1 ;; esac
source /authority/pins.env
readonly work=/work
[ "$(stat -c '%u:%g:%a' "$work")" = "$(id -u):$(id -g):700" ]
[ "$(stat -c '%u:%g:%a:%h:%s' /inputs/flutter.tar.xz)" = \
    "$(id -u):$(id -g):400:1:$SIZE_FLUTTER_PRESENTATION_CANDIDATE" ]
[ "$(sha256sum /inputs/flutter.tar.xz | awk '{print $1}')" = \
    "$SHA256_FLUTTER_PRESENTATION_CANDIDATE" ]
[ "$(sha256sum /authority/pubspec.lock | awk '{print $1}')" = \
    "$SHA256_FLUTTER_PRESENTATION_CANDIDATE_PROJECT_LOCK" ]
ulimit -f 524288
export FLUTTER_ROOT="$work/toolchain/flutter" PUB_CACHE="$work/pub-cache"
export PUB_HOSTED_URL=https://pub.dev CI=true FLUTTER_SUPPRESS_ANALYTICS=true
export DART_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0
export PATH="$FLUTTER_ROOT/bin/cache/dart-sdk/bin:/usr/bin:/bin"

run_logged() {
    local log=$1 status=0
    shift
    "$@" >"$log" 2>&1 || status=$?
    [ "$(stat -c '%s' "$log")" -le 2097152 ] \
        || { echo 'plugin cache diagnostics exceed their bound' >&2; return 1; }
    cat "$log"
    return "$status"
}

if [ "$1" != replay ]; then
    [ -z "$(find "$work" -mindepth 1 -maxdepth 1 -print -quit)" ]
    mkdir "$work/toolchain" "$work/project"
    tar -xJf /inputs/flutter.tar.xz -C "$work/toolchain" --no-same-owner --no-same-permissions
    cp -a /project-source/. "$work/project/"
    chmod -R u+rwX "$work/project"
    cp /authority/pubspec.lock "$work/project/pubspec.lock"
    cd "$work/project"
    [ "$(sha256sum pubspec.yaml | awk '{print $1}')" = \
        "$SHA256_FLUTTER_PLUGIN_MIGRATION_PROJECT_MANIFEST" ]
    sha256sum pubspec.yaml pubspec.lock >"$work/resolved.sha256"
    dart --version
    if [ "$1" = prepare ]; then
        printf 'FLUTTER_PLUGIN_CACHE_PREPARE=pass\n'
        exit 0
    fi
    mkdir "$work/pub-cache"
    cp -a /seed/. "$work/pub-cache/"
    chmod -R u+rwX "$work/pub-cache"
    run_logged "$work/derive.log" timeout --signal=TERM --kill-after=10s 300 \
        dart pub get --enforce-lockfile --no-example
    sha256sum --check --status "$work/resolved.sha256"
    # Discard only Pub's volatile bookkeeping in the freshly owned copy.
    rm -rf -- "$PUB_CACHE/active_roots" "$PUB_CACHE/_temp" "$PUB_CACHE/log" \
        "$PUB_CACHE/README.md" "$PUB_CACHE/hosted/pub.dev/.cache"
    while IFS= read -r -d '' checkout; do
        rm -rf -- "$checkout/.git/logs"
        rm -f -- "$checkout/.git/FETCH_HEAD" "$checkout/.git/ORIG_HEAD" \
            "$checkout/.git/COMMIT_EDITMSG" "$checkout/.git/index" "$checkout/.git/index.lock"
        git -c safe.directory="$checkout" -c index.version=2 -C "$checkout" read-tree HEAD
    done < <(find "$PUB_CACHE/git" -mindepth 1 -maxdepth 1 -type d ! -name cache -print0 | LC_ALL=C sort -z)
    while IFS= read -r -d '' bare; do
        rm -rf -- "$bare/logs"
        rm -f -- "$bare/FETCH_HEAD" "$bare/ORIG_HEAD"
    done < <(find "$PUB_CACHE/git/cache" -mindepth 1 -maxdepth 1 -type d -print0 | LC_ALL=C sort -z)
    printf 'FLUTTER_PLUGIN_CACHE_DERIVE=pass lock_sha256=%s\n' \
        "$SHA256_FLUTTER_PRESENTATION_CANDIDATE_PROJECT_LOCK"
else
    # Both the workspace and the completed cache subtrees must be read-only.
    export PUB_CACHE=/tmp/pub-cache
    python3 -I -S - <<'PY'
import os,shutil
paths=['/work','/seed','/tmp/pub-cache/hosted','/tmp/pub-cache/hosted-hashes','/tmp/pub-cache/git']
for path in paths:
    if not os.statvfs(path).f_flag & os.ST_RDONLY:
        raise ValueError('replay input mount is writable: '+path)
print('FLUTTER_PLUGIN_CACHE_READONLY=pass mounts='+str(len(paths)))
shutil.copytree('/work/project','/tmp/replay',ignore=shutil.ignore_patterns('.dart_tool','build'))
PY
    cd /tmp/replay
    sha256sum --check --status "$work/resolved.sha256"
    run_logged /tmp/replay.log timeout --signal=TERM --kill-after=10s 180 \
        dart pub get --offline --enforce-lockfile --no-example
    sha256sum --check --status "$work/resolved.sha256"
    printf 'FLUTTER_PLUGIN_CACHE_REPLAY=pass lock_sha256=%s cache=readonly network=none\n' \
        "$SHA256_FLUTTER_PRESENTATION_CANDIDATE_PROJECT_LOCK"
fi
