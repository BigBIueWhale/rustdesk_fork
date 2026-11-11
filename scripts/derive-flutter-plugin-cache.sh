#!/usr/bin/env bash
# Derive an exact candidate cache from authenticated inputs inside the owned VM.
set -euo pipefail
umask 077
[ "$#" -eq 1 ] && [ "$(id -u)" -ne 0 ] && [ "$(id -g)" -ne 0 ] \
    || { echo 'plugin cache derivation requires one phase and an ordinary principal' >&2; exit 1; }
case "$1" in derive|replay) ;; *) exit 1 ;; esac
source /authority/pins.env
readonly work=/work
[ "$(stat -c '%u:%g:%a' "$work")" = "$(id -u):$(id -g):700" ]
[ "$(stat -c '%u:%g:%a:%h:%s' /inputs/flutter.tar.xz)" = \
    "$(id -u):$(id -g):400:1:$SIZE_FLUTTER_PRESENTATION_CANDIDATE" ]
[ "$(sha256sum /inputs/flutter.tar.xz | awk '{print $1}')" = \
    "$SHA256_FLUTTER_PRESENTATION_CANDIDATE" ]
[ "$(sha256sum /authority/pubspec.lock | awk '{print $1}')" = \
    "$SHA256_FLUTTER_PLUGIN_MIGRATION_PROJECT_LOCK" ]
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

if [ "$1" = derive ]; then
    [ -z "$(find "$work" -mindepth 1 -maxdepth 1 -print -quit)" ]
    mkdir "$work/toolchain" "$work/project" "$work/pub-cache"
    tar -xJf /inputs/flutter.tar.xz -C "$work/toolchain" --no-same-owner --no-same-permissions
    cp -a /project-source/. "$work/project/"
    cp -a /seed/. "$work/pub-cache/"
    chmod -R u+rwX "$work/project" "$work/pub-cache"
    cp /authority/pubspec.lock "$work/project/pubspec.lock"
    python3 -I -S - <<'PY'
import pathlib
p=pathlib.Path('/work/project/pubspec.yaml');text=p.read_text()
for old,new in [('  file_picker: ^5.1.0\n','  file_selector: 1.1.0\n'),
                ('  sqflite: 2.2.8+4\n','  sqflite: 2.4.6\n'),
                ('  flutter_plugin_android_lifecycle: 2.0.17\n','')]:
    if text.count(old)!=1:
        raise ValueError('candidate manifest precondition differs: '+old.strip())
    text=text.replace(old,new)
p.write_text(text)
PY
    cd "$work/project"
    [ "$(sha256sum pubspec.yaml | awk '{print $1}')" = \
        "$SHA256_FLUTTER_PLUGIN_MIGRATION_PROJECT_MANIFEST" ]
    sha256sum pubspec.yaml pubspec.lock >"$work/resolved.sha256"
    dart --version
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
        "$SHA256_FLUTTER_PLUGIN_MIGRATION_PROJECT_LOCK"
else
    # The completed cache subtrees are mounted read-only into this fresh cache root.
    export PUB_CACHE=/tmp/pub-cache
    python3 -I -S - <<'PY'
import pathlib,shutil
shutil.copytree('/work/project','/tmp/replay',ignore=shutil.ignore_patterns('.dart_tool','build'))
PY
    cd /tmp/replay
    sha256sum --check --status "$work/resolved.sha256"
    run_logged "$work/replay.log" timeout --signal=TERM --kill-after=10s 180 \
        dart pub get --offline --enforce-lockfile --no-example
    sha256sum --check --status "$work/resolved.sha256"
    printf 'FLUTTER_PLUGIN_CACHE_REPLAY=pass lock_sha256=%s cache=readonly network=none\n' \
        "$SHA256_FLUTTER_PLUGIN_MIGRATION_PROJECT_LOCK"
fi
