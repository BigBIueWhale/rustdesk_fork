#!/usr/bin/env -S -i /usr/bin/bash --noprofile --norc
set -euo pipefail

readonly RELEASE_ENV_MARKER_VALUE=rustdesk-release-env-v1
readonly SAFE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

forbidden_inherited_name() {
    case "$1" in
        BASH_ENV|ENV|CDPATH|PYTHONPATH|PYTHONHOME|HARNESS_PREFIX|GIT_*|DOCKER_*|BUILDKIT_*|COMPOSE_*|\
        CC|CXX|CPP|AR|AS|LD|NM|OBJCOPY|OBJDUMP|RANLIB|READELF|STRIP|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|\
        RUST*|CARGO*|FLUTTER*|ANDROID*|JAVA_HOME|GRADLE_*|SOURCE_DATE_EPOCH|DOUBLE_BUILD|OUT_DIR|\
        ALLOW_DIRTY_TREE|WINDOWS_*|RELEASE_*|VCPKG_*|X_VCPKG_*|TMPDIR|LD_*|LIBRARY_PATH|CPATH|\
        C_INCLUDE_PATH|CPLUS_INCLUDE_PATH|PKG_CONFIG*|MAKEFLAGS|NINJAFLAGS|SHELLOPTS|BASHOPTS|\
        HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|all_proxy|no_proxy)
            return 0 ;;
        *) return 1 ;;
    esac
}

bootstrap_closed_environment() {
    local name uid passwd_entry safe_home
    if [ "${RUSTDESK_RELEASE_ENV_MARKER:-}" != "$RELEASE_ENV_MARKER_VALUE" ]; then
        while IFS= read -r name; do
            forbidden_inherited_name "$name" \
                && { printf 'build-release: forbidden inherited environment variable: %s\n' "$name" >&2; exit 1; }
        done < <(compgen -e)
        uid="$(/usr/bin/id -u)"
        passwd_entry="$(/usr/bin/getent passwd "$uid")" \
            || { printf 'build-release: cannot resolve current user home\n' >&2; exit 1; }
        safe_home="$(printf '%s\n' "$passwd_entry" | /usr/bin/awk -F: 'NF == 7 { print $6 }')"
        [ -n "$safe_home" ] && [ -d "$safe_home" ] \
            || { printf 'build-release: current user home is invalid\n' >&2; exit 1; }
        exec /usr/bin/env -i \
            HOME="$safe_home" PATH="$SAFE_PATH" LC_ALL=C LANG=C TZ=UTC \
            RUSTDESK_RELEASE_ENV_MARKER="$RELEASE_ENV_MARKER_VALUE" \
            /usr/bin/bash --noprofile --norc "$0" "$@"
    fi
    while IFS= read -r name; do
        case "$name" in
            HOME|PATH|LC_ALL|LANG|TZ|RUSTDESK_RELEASE_ENV_MARKER|PWD|SHLVL|_) ;;
            *) printf 'build-release: closed environment contains unexpected variable: %s\n' "$name" >&2; exit 1 ;;
        esac
    done < <(compgen -e)
}

bootstrap_closed_environment "$@"
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
# shellcheck source=scripts/fork-version.sh
source "$SCRIPT_DIR/fork-version.sh"
load_pins

export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0
export GIT_NO_REPLACE_OBJECTS=1

DOCTOR=0
SELF_TEST=0
SELF_TEST_RESET=0
SELF_TEST_CLEANUP_MISSING=0
for argument in "$@"; do
    case "$argument" in
        --doctor) DOCTOR=1 ;;
        --self-test) SELF_TEST=1 ;;
        --self-test-reset) SELF_TEST_RESET=1 ;;
        --self-test-cleanup-missing) SELF_TEST_CLEANUP_MISSING=1 ;;
        -h|--help) printf 'usage: %s [--doctor|--self-test|--self-test-reset|--self-test-cleanup-missing]\n' "${0##*/}"; exit 0 ;;
        *) die "unknown argument '$argument'" ;;
    esac
done
[ "$((DOCTOR + SELF_TEST + SELF_TEST_RESET + SELF_TEST_CLEANUP_MISSING))" -le 1 ] \
    || die "build-release operating modes are mutually exclusive"

readonly FINAL_OUT_DIR="$REPO_ROOT/dist"
readonly DOCKER_HOST_URI=unix:///var/run/docker.sock
readonly PRIVATE_TREE_CLOSURE_SOURCE="$SCRIPT_DIR/verify-private-tree-closure.py"
readonly -a CANONICAL_ASSETS=(
    rustdesk-x86_64.deb
    rustdesk-arm64.apk
    rustdesk-setup.exe
    rustdesk.msi
)

PINNED_HEAD=""
PINNED_HEAD_SHORT=""
FORK_VER=""
WORKSPACE=""
WORKSPACE_ID=""
DOCKER_CONFIG_DIR=""
PRIVATE_TREE_CLOSURE_PROBE=""
SOURCE_A=""
SOURCE_B=""
SOURCE_A_ID=""
SOURCE_B_ID=""
OUTPUT_A=""
OUTPUT_B=""
SET_A=""
SET_B=""
ONLINE_SNAPSHOT_PARENT=""
HOST_KEYSTORE=""
HOST_KEYSTORE_PASS_FILE=""
HOST_GOLDEN=""
DEBIAN_IMAGE_ID=""
ANDROID_IMAGE_ID=""
WINDOWS_IMAGE_ID=""
ORIGIN_URL=""
PINNED_ORIGIN_URL=""
NETWORK_REPO=""
WINDOWS_UNSAFE=0
KEEP_WORKSPACE=0
FIXTURE_MODE=0
FIXTURE_LOG=""
FIXTURE_ONLINE_DIGEST=""
FINAL_DESTINATION=""
FINAL_PARENT_ID=""
FINAL_TRANSACTION=""
FINAL_TRANSACTION_ID=""
FINAL_STAGE=""
FINAL_STAGE_ID=""
FINAL_OLD_ID=""
FINAL_DEST_HAD_OLD=0
FINAL_PUBLICATION_STATE=idle
PUBLICATION_LOCK_FD=""
CANONICAL_PUBLICATION_PARENT_ID=""
RELEASE_SUCCESS_MESSAGE=""
PUBLICATION_FIXTURE_STOP_AFTER_DISCARD_REMOVAL=0
CHILD_PATH="$SAFE_PATH"

git_closed() {
    command git --no-replace-objects -c core.hooksPath=/dev/null "$@"
}

assert_no_git_object_substitution() {
    local common_dir grafts alternates replacements
    common_dir="$(git_closed -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
        || die "cannot resolve repository common Git directory"
    grafts="$common_dir/info/grafts"
    alternates="$common_dir/objects/info/alternates"
    [ ! -e "$grafts" ] && [ ! -L "$grafts" ] || die "Git grafts are forbidden for release builds"
    [ ! -e "$alternates" ] && [ ! -L "$alternates" ] || die "Git object alternates are forbidden for release builds"
    replacements="$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace 2>/dev/null)" \
        || die "cannot inspect Git replacement refs"
    [ -z "$replacements" ] || die "Git replacement refs are forbidden for release builds"
}

assert_release_source_state() {
    local phase="$1" current branch dirt sparse index_flags
    current="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "$phase: cannot resolve HEAD"
    [ "$current" = "$PINNED_HEAD" ] || die "$phase: HEAD changed"
    branch="$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet --short HEAD 2>/dev/null)" \
        || die "$phase: release checkout is detached"
    [ "$branch" = master ] || die "$phase: release branch must be master"
    assert_no_git_object_substitution
    sparse="$(git_closed -C "$REPO_ROOT" config --local --no-includes --bool core.sparseCheckout 2>/dev/null || true)"
    [ "$sparse" != true ] || die "$phase: sparse checkout is forbidden"
    index_flags="$(git_closed -C "$REPO_ROOT" ls-files -v 2>/dev/null)" \
        || die "$phase: cannot inspect tracked-file index flags"
    if printf '%s\n' "$index_flags" | awk 'substr($0,1,1) != "H" { found=1 } END { exit found ? 0 : 1 }'; then
        die "$phase: assume-unchanged, skip-worktree, or noncanonical index flags are forbidden"
    fi
    git_closed -C "$REPO_ROOT" diff --no-ext-diff --quiet --ignore-submodules=none -- \
        || die "$phase: tracked worktree bytes differ from the index"
    git_closed -C "$REPO_ROOT" diff --cached --no-ext-diff --quiet --ignore-submodules=none -- \
        || die "$phase: index differs from HEAD"
    dirt="$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all 2>/dev/null)" \
        || die "$phase: cannot inspect source tree"
    [ -z "$dirt" ] || die "$phase: source tree is not clean, including untracked files"
}

assert_live_origin_master() {
    local phase="$1" output sha ref extra
    local -a rows
    [ -d "$NETWORK_REPO" ] || die "$phase: private network Git repository is absent"
    output="$(git_closed -C "$NETWORK_REPO" ls-remote --exit-code "$ORIGIN_URL" refs/heads/master 2>/dev/null)" \
        || die "$phase: cannot read live origin/master"
    mapfile -t rows <<< "$output"
    [ "${#rows[@]}" -eq 1 ] || die "$phase: live origin/master returned ${#rows[@]} rows"
    IFS=$'\t' read -r sha ref extra <<< "${rows[0]}"
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] && [ "$ref" = refs/heads/master ] && [ -z "$extra" ] \
        || die "$phase: live origin/master response is malformed"
    [ "$sha" = "$PINNED_HEAD" ] || die "$phase: live origin/master is $sha, expected $PINNED_HEAD"
}

assert_origin_identity() {
    local fetch_output push_output hostile
    local -a fetch_urls=() push_urls=()
    hostile="$(git_closed -C "$REPO_ROOT" config --local --no-includes --name-only --get-regexp \
        '^(include\.|includeif\.|url\.|http\.|credential\.|core\.(gitproxy|sshcommand)$|remote\.origin\.(proxy|receivepack|uploadpack)$)' \
        2>/dev/null || true)"
    [ -z "$hostile" ] || die "repository-local Git transport rewriting is forbidden for release builds"
    fetch_output="$(git_closed -C "$REPO_ROOT" config --local --no-includes --get-all remote.origin.url 2>/dev/null)" \
        || die "cannot read the raw origin URL from repository-local configuration"
    mapfile -t fetch_urls <<< "$fetch_output"
    if push_output="$(git_closed -C "$REPO_ROOT" config --local --no-includes --get-all remote.origin.pushurl 2>/dev/null)"; then
        mapfile -t push_urls <<< "$push_output"
    elif [ $? -ne 1 ]; then
        die "cannot read the raw origin push URL from repository-local configuration"
    fi
    [ "${#fetch_urls[@]}" -eq 1 ] || die "origin must have exactly one fetch URL"
    if [ "${#push_urls[@]}" -eq 0 ]; then push_urls=("${fetch_urls[0]}"); fi
    [ "${#push_urls[@]}" -eq 1 ] || die "origin must have at most one explicit push URL"
    [ "${fetch_urls[0]}" = "${push_urls[0]}" ] || die "origin fetch and push URLs differ"
    [[ "${fetch_urls[0]}" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git$ ]] \
        || die "origin must be one canonical GitHub HTTPS repository URL"
    [ "${fetch_urls[0]}" = https://github.com/BigBIueWhale/rustdesk_fork.git ] \
        || die "origin is not the pinned release repository"
    if [ -n "$PINNED_ORIGIN_URL" ] && [ "${fetch_urls[0]}" != "$PINNED_ORIGIN_URL" ]; then
        die "origin URL changed during the release transaction"
    fi
    PINNED_ORIGIN_URL="${fetch_urls[0]}"
    ORIGIN_URL="$PINNED_ORIGIN_URL"
}

initialize_network_repo() {
    NETWORK_REPO="$WORKSPACE/network.git"
    git_closed init --bare --quiet "$NETWORK_REPO" \
        || die "cannot initialize private network Git repository"
}

canonical_file() {
    local resolved
    resolved="$(readlink -f -- "$1" 2>/dev/null)" || die "cannot resolve required file: $1"
    [ -f "$resolved" ] || die "required file is absent: $resolved"
    printf '%s' "$resolved"
}

assert_private_signing_files() {
    python3 - "$HOST_KEYSTORE" "$HOST_KEYSTORE_PASS_FILE" "$(id -u)" <<'PY'
import stat
import sys
from pathlib import Path

paths = [Path(sys.argv[1]), Path(sys.argv[2])]
uid = int(sys.argv[3])
if paths[0].parent != paths[1].parent:
    raise SystemExit("Android signing files must share one protected directory")
for path in paths:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid:
        raise SystemExit(f"Android signing file is not a current-UID regular file: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit(f"Android signing file must have mode 0600: {path}")
for directory in (paths[0].parent, paths[0].parent.parent):
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid:
        raise SystemExit(f"Android signing parent is not a current-UID directory: {directory}")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit(f"Android signing parent must have mode 0700: {directory}")
PY
}

assert_release_docker_config() {
    local metadata resolved
    [ -d "$DOCKER_CONFIG_DIR" ] && [ ! -L "$DOCKER_CONFIG_DIR" ] \
        || die "release Docker configuration is not a real directory"
    resolved="$(readlink -f -- "$DOCKER_CONFIG_DIR" 2>/dev/null)" \
        || die "cannot resolve release Docker configuration"
    [ "$resolved" = "$DOCKER_CONFIG_DIR" ] \
        || die "release Docker configuration path is not canonical"
    [ "$(stat -c '%u:%a' -- "$DOCKER_CONFIG_DIR" 2>/dev/null)" = "$(id -u):700" ] \
        || die "release Docker configuration is not current-UID mode 0700"
    [ -f "$DOCKER_CONFIG_DIR/config.json" ] && [ ! -L "$DOCKER_CONFIG_DIR/config.json" ] \
        || die "release Docker config.json is not a regular file"
    metadata="$(stat -c '%u:%a:%h' -- "$DOCKER_CONFIG_DIR/config.json" 2>/dev/null)" \
        || die "cannot inspect release Docker config.json"
    [ "$metadata" = "$(id -u):600:1" ] \
        || die "release Docker config.json is not current-UID mode 0600 and non-hardlinked"
    cmp -s "$DOCKER_CONFIG_DIR/config.json" <(printf '{}\n') \
        || die "release Docker config.json does not equal the empty canonical configuration"
}

docker_local() {
    assert_release_docker_config
    DOCKER_HOST="$DOCKER_HOST_URI" DOCKER_CONFIG="$DOCKER_CONFIG_DIR" \
        command docker --host "$DOCKER_HOST_URI" --config "$DOCKER_CONFIG_DIR" "$@"
}

verify_release_builder_image() {
    local role="$1" image_id="$2"
    assert_release_docker_config
    (
        export DOCKER_HOST="$DOCKER_HOST_URI"
        export DOCKER_CONFIG="$DOCKER_CONFIG_DIR"
        require_pinned_builder_image "$role" "$image_id"
    ) || die "release preflight rejected the pinned $role image"
}

verify_all_release_builder_images() {
    verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"
    verify_release_builder_image android-builder "$ANDROID_IMAGE_ID"
    verify_release_builder_image win-helper "$WINDOWS_IMAGE_ID"
}

acquire_publication_lock() {
    local common_dir resolved metadata
    [ -z "$PUBLICATION_LOCK_FD" ] || return 0
    common_dir="$(git_closed -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
        || die "cannot resolve repository common Git directory for the release lock"
    [ -d "$common_dir" ] && [ ! -L "$common_dir" ] \
        || die "repository common Git directory is not a real directory"
    resolved="$(readlink -f -- "$common_dir" 2>/dev/null)" \
        || die "cannot canonicalize repository common Git directory"
    [ "$resolved" = "$common_dir" ] \
        || die "repository common Git directory is not canonical"
    metadata="$(stat -c '%u:%d:%i' -- "$common_dir" 2>/dev/null)" \
        || die "cannot inspect repository common Git directory"
    case "$metadata" in
        "$(id -u)":*) ;;
        *) die "repository common Git directory is not owned by the invoking UID" ;;
    esac
    exec {PUBLICATION_LOCK_FD}< "$common_dir" \
        || die "cannot open repository common Git directory for the release lock"
    flock -n "$PUBLICATION_LOCK_FD" \
        || die "another release build holds the repository publication lock"
    [ "$(stat -Lc '%u:%d:%i' "/proc/self/fd/$PUBLICATION_LOCK_FD" 2>/dev/null)" = "$metadata" ] \
        || die "repository publication lock descriptor identity differs"
}

create_workspace() {
    local source_hash private_hash commit_hash
    trap cleanup_release_workspace EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-release.XXXXXXXXXX)" \
        || die "cannot create private release workspace"
    PRIVATE_TREE_CLOSURE_PROBE="$WORKSPACE/private-tree-closure.py"
    chmod 0700 "$WORKSPACE"
    [ "$(stat -c '%u:%a' "$WORKSPACE")" = "$(id -u):700" ] \
        || die "release workspace is not current-UID mode 0700"
    WORKSPACE_ID="$(stat -c '%d:%i' "$WORKSPACE")" \
        || die "cannot record release workspace identity"
    [ -f "$PRIVATE_TREE_CLOSURE_SOURCE" ] && [ ! -L "$PRIVATE_TREE_CLOSURE_SOURCE" ] \
        || die "private-tree closure source is not a regular file"
    install -m 0500 "$PRIVATE_TREE_CLOSURE_SOURCE" "$PRIVATE_TREE_CLOSURE_PROBE"
    source_hash="$(sha256sum "$PRIVATE_TREE_CLOSURE_SOURCE" | awk '{print $1}')"
    private_hash="$(sha256sum "$PRIVATE_TREE_CLOSURE_PROBE" | awk '{print $1}')"
    [ "$private_hash" = "$source_hash" ] \
        || die "private-tree closure copy differs from its source"
    if [ "$SELF_TEST" -eq 0 ]; then
        commit_hash="$(git_closed -C "$REPO_ROOT" show \
            "$PINNED_HEAD:scripts/verify-private-tree-closure.py" | sha256sum | awk '{print $1}')" \
            || die "cannot read private-tree closure probe from the pinned commit"
        [ "$private_hash" = "$commit_hash" ] \
            || die "private-tree closure probe differs from the pinned commit"
    fi
    DOCKER_CONFIG_DIR="$WORKSPACE/docker-config"
    install -d -m 0700 "$DOCKER_CONFIG_DIR"
    printf '{}\n' > "$DOCKER_CONFIG_DIR/config.json"
    chmod 0600 "$DOCKER_CONFIG_DIR/config.json"
    assert_release_docker_config
}

assert_release_online_snapshot() {
    local phase="$1" parent="$ONLINE_SNAPSHOT_PARENT" online resolved metadata bad observed
    [ -n "$parent" ] || die "$phase: release online snapshot is not initialized"
    case "$parent" in
        /*) ;;
        *) die "$phase: release online snapshot path is not absolute" ;;
    esac
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        || die "$phase: release online snapshot parent is not a real directory"
    resolved="$(readlink -f -- "$parent" 2>/dev/null)" \
        || die "$phase: cannot resolve release online snapshot parent"
    [ "$resolved" = "$parent" ] \
        || die "$phase: release online snapshot path is not canonical"
    metadata="$(stat -c '%u:%a' -- "$parent" 2>/dev/null)" \
        || die "$phase: release online snapshot parent is absent"
    [ "$metadata" = "$(id -u):700" ] \
        || die "$phase: release online snapshot parent is not current-UID mode 0700"
    online="$parent/online"
    [ -d "$online" ] && [ ! -L "$online" ] \
        || die "$phase: release online snapshot tree is not a real directory"
    [ "$(stat -c '%u:%a' -- "$online" 2>/dev/null)" = "$(id -u):500" ] \
        || die "$phase: release online snapshot tree is not current-UID mode 0500"
    bad="$(find "$online" \( ! -uid "$(id -u)" -o \
        \( \( -type f -o -type d \) -perm /0222 \) \) -print -quit)" \
        || die "$phase: cannot inspect release online snapshot ownership and modes"
    [ -z "$bad" ] \
        || die "$phase: release online snapshot contains a writable or differently owned path: $bad"
    if [ "$FIXTURE_MODE" -eq 1 ]; then
        observed="$(sha256sum "$online/fixture-input" 2>/dev/null | awk '{print $1}')" \
            || die "$phase: fixture online snapshot is absent"
        [ "$observed" = "$FIXTURE_ONLINE_DIGEST" ] \
            || die "$phase: fixture online snapshot changed"
    else
        verify_private_online_snapshot "$parent"
    fi
}

create_release_online_snapshot() {
    [ -z "$ONLINE_SNAPSHOT_PARENT" ] || die "release online snapshot was already initialized"
    ONLINE_SNAPSHOT_PARENT="$WORKSPACE/online-input"
    create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    assert_release_online_snapshot "online snapshot creation"
}

run_snapshot_consumer() {
    local phase="$1" status=0
    shift
    assert_release_online_snapshot "$phase before use"
    "$@" || status=$?
    assert_release_online_snapshot "$phase after use"
    [ "$status" -eq 0 ]
}

recorded_private_tree_identity() {
    local path="$1"
    case "$path" in
        "$WORKSPACE") printf '%s' "$WORKSPACE_ID" ;;
        "$SOURCE_A") printf '%s' "$SOURCE_A_ID" ;;
        "$SOURCE_B") printf '%s' "$SOURCE_B_ID" ;;
        *) return 1 ;;
    esac
}

offline_normalize_exact_tree() {
    local path="$1" expected_identity="$2" role="$3" resolved observed bad uid gid
    uid="$(id -u)"
    gid="$(id -g)"
    [ -n "$expected_identity" ] || { warn "$role identity was not recorded"; return 1; }
    case "$path" in /*) ;; *) warn "$role path is not absolute"; return 1 ;; esac
    [ -d "$path" ] && [ ! -L "$path" ] \
        || { warn "$role is not a real directory: $path"; return 1; }
    resolved="$(readlink -f -- "$path" 2>/dev/null)" \
        || { warn "$role cannot be resolved: $path"; return 1; }
    [ "$resolved" = "$path" ] \
        || { warn "$role path is not canonical: $path"; return 1; }
    observed="$(stat -c '%d:%i' -- "$path" 2>/dev/null)" \
        || { warn "$role identity cannot be inspected: $path"; return 1; }
    [ "$observed" = "$expected_identity" ] \
        || { warn "$role identity changed: $path"; return 1; }
    if ! /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$path"; then
        warn "$role contains a mount boundary: $path"
        return 1
    fi
    [ -n "$DEBIAN_IMAGE_ID" ] \
        || { warn "$role cannot be normalized without the pinned Debian image ID"; return 1; }
    if ! (verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"); then
        warn "$role normalization image failed provenance verification"
        return 1
    fi
    if ! (
        docker_local run --rm --pull=never --network=none --read-only --user 0:0 \
            --cap-drop=ALL --cap-add=DAC_READ_SEARCH \
            --security-opt no-new-privileges \
            --mount "type=bind,src=$path,dst=/inspect,readonly,bind-recursive=disabled" \
            --mount "type=bind,src=$PRIVATE_TREE_CLOSURE_PROBE,dst=/probe.py,readonly" \
            "$DEBIAN_IMAGE_ID" /usr/bin/python3 /probe.py --inode-root /inspect
    ); then
        warn "$role contains an inode linked outside its boundary: $path"
        return 1
    fi
    observed="$(stat -c '%d:%i' -- "$path" 2>/dev/null)" \
        || { warn "$role disappeared after closure inspection: $path"; return 1; }
    [ "$observed" = "$expected_identity" ] \
        || { warn "$role identity changed after closure inspection: $path"; return 1; }
    if ! /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$path"; then
        warn "$role gained a mount boundary after closure inspection: $path"
        return 1
    fi
    if ! (
        docker_local run --rm --pull=never --network=none --read-only --user 0:0 \
            --cap-drop=ALL --cap-add=CHOWN \
            --security-opt no-new-privileges \
            --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled" \
            "$DEBIAN_IMAGE_ID" /bin/sh -ceu '
                owner="$1"
                /bin/chown --no-dereference 0:0 /cleanup
                /bin/chmod u+rwx,go-w /cleanup
                /usr/bin/find -P /cleanup -type d \
                    -exec /bin/chown --no-dereference 0:0 {} \; \
                    -exec /bin/chmod u+rwx,go-w {} \;
                /usr/bin/find -P /cleanup ! -type d ! -type l \
                    -exec /bin/chown --no-dereference 0:0 {} +
                /usr/bin/find -P /cleanup ! -type d ! -type l \
                    -exec /bin/chmod u+rw,go-w {} +
                /usr/bin/find -P /cleanup ! -type d ! -type l \
                    -exec /bin/chown --no-dereference "$owner" {} +
                /usr/bin/find -P /cleanup -type l \
                    -exec /bin/chown --no-dereference "$owner" {} +
                /usr/bin/find -P /cleanup -depth -type d \
                    -exec /bin/chown --no-dereference "$owner" {} +
            ' _ "$uid:$gid"
    ); then
        warn "$role offline ownership/access normalization failed: $path"
        return 1
    fi
    observed="$(stat -c '%d:%i' -- "$path" 2>/dev/null)" \
        || { warn "$role disappeared after normalization: $path"; return 1; }
    [ "$observed" = "$expected_identity" ] \
        || { warn "$role identity changed during normalization: $path"; return 1; }
    if ! /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$path"; then
        warn "$role gained a mount boundary during normalization: $path"
        return 1
    fi
    bad="$(find -P "$path" \( ! -uid "$uid" -o ! -gid "$gid" \) -print -quit 2>/dev/null)" \
        || { warn "$role normalized ownership cannot be inspected: $path"; return 1; }
    [ -z "$bad" ] \
        || { warn "$role retains foreign ownership after normalization: $bad"; return 1; }
    bad="$(find -P "$path" ! -type l -perm /022 -print -quit 2>/dev/null)" \
        || { warn "$role normalized modes cannot be inspected: $path"; return 1; }
    [ -z "$bad" ] \
        || { warn "$role retains group/world-writable state after normalization: $bad"; return 1; }
    bad="$(find -P "$path" -type d ! -perm -0700 -print -quit 2>/dev/null)" \
        || { warn "$role normalized directory access cannot be inspected: $path"; return 1; }
    [ -z "$bad" ] \
        || { warn "$role retains an owner-inaccessible directory after normalization: $bad"; return 1; }
}

normalize_snapshot_access() {
    local source="$1" phase="$2" expected
    case "$source" in
        "$SOURCE_A"|"$SOURCE_B") ;;
        *) die "$phase: snapshot normalization escaped the recorded sources" ;;
    esac
    expected="$(recorded_private_tree_identity "$source")" \
        || die "$phase: snapshot identity is unavailable"
    offline_normalize_exact_tree "$source" "$expected" "$phase snapshot" \
        || die "$phase: cannot normalize generated snapshot ownership/access"
    chmod 0700 "$source" || die "$phase: cannot restore snapshot root mode"
    [ "$(stat -c '%d:%i:%u:%g:%a' "$source")" = \
      "$expected:$(id -u):$(id -g):700" ] \
        || die "$phase: snapshot root identity/owner/mode differs after normalization"
}

normalize_workspace_access() {
    offline_normalize_exact_tree "$WORKSPACE" "$WORKSPACE_ID" "release workspace" \
        || return 1
    chmod 0700 "$WORKSPACE" || return 1
    [ "$(stat -c '%d:%i:%u:%g:%a' "$WORKSPACE")" = \
      "$WORKSPACE_ID:$(id -u):$(id -g):700" ]
}

prepare_unprivileged_workspace_removal() {
    local bad
    [ -n "$WORKSPACE" ] && [ -n "$WORKSPACE_ID" ] \
        || { warn "unprivileged workspace cleanup identity is unavailable"; return 1; }
    [ "$(stat -c '%d:%i' -- "$WORKSPACE" 2>/dev/null)" = "$WORKSPACE_ID" ] \
        || { warn "unprivileged workspace cleanup identity differs"; return 1; }
    /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$WORKSPACE" \
        || { warn "unprivileged workspace contains a mount boundary"; return 1; }
    bad="$(find -P "$WORKSPACE" -type d \
        \( ! -uid "$(id -u)" -o ! -gid "$(id -g)" \) -print -quit 2>/dev/null)" \
        || { warn "unprivileged workspace directory ownership cannot be inspected"; return 1; }
    [ -z "$bad" ] \
        || { warn "unprivileged workspace contains a foreign-owned directory: $bad"; return 1; }
    find -P "$WORKSPACE" -type d -exec chmod u+rwx,go-w {} + \
        || { warn "unprivileged workspace directories cannot be made removable"; return 1; }
    /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$WORKSPACE" \
        || { warn "unprivileged workspace gained a mount boundary"; return 1; }
    [ "$(stat -c '%d:%i:%u:%g:%a' -- "$WORKSPACE" 2>/dev/null)" = \
      "$WORKSPACE_ID:$(id -u):$(id -g):700" ] \
        || { warn "unprivileged workspace root postcondition differs"; return 1; }
}

query_git_worktree_registry() {
    local mode="$1" source="${2:-}"
    case "$mode" in
        exact) [ -n "$source" ] || return 2 ;;
        stale) [ -z "$source" ] || return 2 ;;
        self-test) [ -z "$source" ] || return 2 ;;
        self-test-unexpected) [ -z "$source" ] || return 2 ;;
        self-test-unexpected-after-spawn) [ -z "$source" ] || return 2 ;;
        *) return 2 ;;
    esac
    /usr/bin/python3 - "$REPO_ROOT" "$mode" "$source" <<'PY'
import os
import re
import selectors
import signal
import subprocess
import sys
import time

MAX_WORKTREE_FIELD_BYTES = 65536
MAX_WORKTREE_TOTAL_BYTES = 4 * 1024 * 1024
MAX_WORKTREE_FIELDS = 65536
READ_SIZE = 65536
QUERY_TIMEOUT_SECONDS = 15.0
TERMINATION_GRACE_SECONDS = 1.0


class RegistryQueryError(RuntimeError):
    pass


def nul_fields(chunks):
    pending = bytearray()
    field_count = 0
    for chunk in chunks:
        pending.extend(chunk)
        start = 0
        while True:
            delimiter = pending.find(b"\0", start)
            if delimiter < 0:
                break
            if delimiter - start > MAX_WORKTREE_FIELD_BYTES:
                raise ValueError("Git worktree registry field exceeds the parser bound")
            field_count += 1
            if field_count > MAX_WORKTREE_FIELDS:
                raise ValueError("Git worktree registry exceeds the field-count bound")
            yield bytes(pending[start:delimiter])
            start = delimiter + 1
        if start:
            del pending[:start]
        if len(pending) > MAX_WORKTREE_FIELD_BYTES:
            raise ValueError("Git worktree registry field exceeds the parser bound")
    if pending:
        raise ValueError("Git worktree registry has an unterminated field")


def bounded_chunks(stream, deadline):
    selector = selectors.DefaultSelector()
    total_bytes = 0
    selector.register(stream, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Git worktree registry query exceeded its deadline")
            if not selector.select(remaining):
                raise TimeoutError("Git worktree registry query exceeded its deadline")
            chunk = os.read(stream.fileno(), READ_SIZE)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_WORKTREE_TOTAL_BYTES:
                raise ValueError("Git worktree registry exceeds the total-byte bound")
            yield chunk
    finally:
        selector.close()


def stop_and_reap(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def inspect_registry(command, mode, source, timeout_seconds=QUERY_TIMEOUT_SECONDS, after_spawn=None):
    deadline = time.monotonic() + timeout_seconds
    needle = b"worktree " + os.fsencode(source) if mode == "exact" else None
    stale_pattern = re.compile(br"\Aworktree /tmp/rustdesk-release\.[A-Za-z0-9]{10}/")
    matches = 0
    stale = None
    process = None
    producer_reaped = False
    try:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise RegistryQueryError(f"cannot start Git worktree registry query: {exc}") from exc
        if after_spawn is not None:
            after_spawn(process)
        if process.stdout is None:
            raise RegistryQueryError("Git worktree registry query has no output stream")
        for field in nul_fields(bounded_chunks(process.stdout, deadline)):
            if needle is not None and field == needle:
                matches += 1
            elif mode == "stale" and stale is None and stale_pattern.match(field):
                stale = field[len(b"worktree "):]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Git worktree registry query exceeded its deadline")
        returncode = process.wait(timeout=remaining)
        producer_reaped = True
        if returncode != 0:
            raise RegistryQueryError(f"Git worktree registry query exited with status {returncode}")
        if mode == "exact":
            if matches > 1:
                raise RegistryQueryError("Git worktree registry contains duplicate exact paths")
            return matches == 1
        if mode == "stale":
            return stale
        raise RegistryQueryError("invalid Git worktree registry query mode")
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as exc:
        raise RegistryQueryError(f"cannot parse Git worktree registry: {exc}") from exc
    finally:
        if process is not None and not producer_reaped:
            stop_and_reap(process)
        if process is not None and process.stdout is not None:
            process.stdout.close()


def fake_producer(program):
    return [sys.executable, "-c", program]


def expect_query_error(program, mode, source, label, timeout_seconds=QUERY_TIMEOUT_SECONDS):
    try:
        inspect_registry(fake_producer(program), mode, source, timeout_seconds)
    except RegistryQueryError:
        return
    raise RegistryQueryError(f"registry parser self-test accepted {label}")


def run_self_test():
    expect_query_error(
        "import os; os.write(1, b'worktree /partial\\0'); raise SystemExit(7)",
        "exact",
        "/partial",
        "partial output followed by producer failure",
    )
    expect_query_error(
        f"import os; os.write(1, b'x' * {MAX_WORKTREE_FIELD_BYTES + 1} + b'\\0')",
        "stale",
        "",
        "an oversized field",
    )
    expect_query_error(
        "import os; os.write(1, b'worktree /unterminated')",
        "stale",
        "",
        "an unterminated field",
    )
    expect_query_error(
        "import os; os.write(1, b'worktree /duplicate\\0worktree /duplicate\\0')",
        "exact",
        "/duplicate",
        "duplicate exact worktree paths",
    )
    expect_query_error(
        f"import os; os.write(1, b'x\\0' * {MAX_WORKTREE_FIELDS + 1})",
        "stale",
        "",
        "a field count above the total-work bound",
    )
    fields_above_byte_bound = (MAX_WORKTREE_TOTAL_BYTES // 1024) + 1
    expect_query_error(
        f"import os; os.write(1, (b'x' * 1023 + b'\\0') * {fields_above_byte_bound})",
        "stale",
        "",
        "a byte count above the total-work bound",
    )
    expect_query_error(
        "import time; time.sleep(60)",
        "stale",
        "",
        "a nonterminating producer",
        0.05,
    )
    forced_kill = []

    def capture_forced_kill(process):
        forced_kill.append(process)

    try:
        inspect_registry(
            fake_producer(
                "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
            ),
            "stale",
            "",
            0.05,
            capture_forced_kill,
        )
    except RegistryQueryError:
        pass
    else:
        raise RegistryQueryError("registry parser self-test accepted a SIGTERM-ignoring producer")
    if len(forced_kill) != 1:
        raise RegistryQueryError("forced-kill fixture did not capture exactly one producer")
    process = forced_kill[0]
    try:
        waited_pid, waited_status = os.waitpid(process.pid, os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        if waited_pid == 0:
            os.kill(process.pid, signal.SIGKILL)
            waited_pid, waited_status = os.waitpid(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(waited_status)
        raise RegistryQueryError(
            f"forced-kill fixture found producer {waited_pid} was not already reaped"
        )
    expected = b"/tmp/rustdesk-release.ABCDE12345/pass-A/source"
    program = (
        "import os; "
        "os.write(1, (b'HEAD ' + b'0' * 40 + b'\\0') * 4096 + "
        "b'worktree /tmp/rustdesk-release.ABCDE12345/pass-A/source\\0')"
    )
    if inspect_registry(fake_producer(program), "stale", "") != expected:
        raise RegistryQueryError("registry parser self-test missed a late stale worktree")


def main():
    repository, mode, source = sys.argv[1:]
    if mode == "self-test-unexpected":
        raise RuntimeError("unexpected-exception status fixture")
    if mode == "self-test-unexpected-after-spawn":
        spawned = []

        def fail_after_spawn(process):
            spawned.append(process)
            raise RuntimeError("post-spawn unexpected-exception status fixture")

        try:
            inspect_registry(
                fake_producer("import time; time.sleep(60)"),
                "stale",
                "",
                after_spawn=fail_after_spawn,
            )
        except RuntimeError:
            if len(spawned) != 1 or spawned[0].poll() is None:
                print("post-spawn exception fixture retained its producer", file=sys.stderr)
                return 3
            raise
        raise RegistryQueryError("post-spawn exception fixture was not raised")
    if mode == "self-test":
        try:
            run_self_test()
        except RegistryQueryError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return 0

    command = [
        "/usr/bin/git",
        "--no-replace-objects",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        repository,
        "worktree",
        "list",
        "--porcelain",
        "-z",
    ]
    try:
        result = inspect_registry(command, mode, source)
    except RegistryQueryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if mode == "exact":
        print("present" if result else "absent")
        return 0
    if mode == "stale" and result is not None:
        rendered = result.decode("utf-8", "backslashreplace")
        print("interrupted release worktree requires explicit reconciliation: " + rendered, file=sys.stderr)
        return 1
    if mode != "stale":
        print("invalid Git worktree registry query mode", file=sys.stderr)
        return 2
    return 0


try:
    exit_status = main()
except BaseException as exc:
    print(f"unexpected Git worktree registry query failure: {type(exc).__name__}: {exc}", file=sys.stderr)
    exit_status = 2
raise SystemExit(exit_status)
PY
}

worktree_path_is_registered() {
    local source="$1" result
    [ -n "$source" ] || return 1
    result="$(query_git_worktree_registry exact "$source")" || return 2
    case "$result" in
        present) return 0 ;;
        absent) return 1 ;;
        *) return 2 ;;
    esac
}

assert_no_stale_release_worktrees() {
    query_git_worktree_registry stale
}

remove_snapshot_worktree_if_registered() {
    local source="$1" role="$2" query_status
    [ -n "$source" ] || return 0
    case "$source" in
        "$SOURCE_A"|"$SOURCE_B") ;;
        *) warn "$role cleanup escaped the recorded snapshot paths"; return 1 ;;
    esac
    query_status=0
    worktree_path_is_registered "$source" || query_status=$?
    case "$query_status" in
        0)
            if [ -d "$source" ] && [ ! -L "$source" ]; then
                chmod 0700 "$source" \
                    || { warn "$role root cannot be made removable"; return 1; }
                git_closed -C "$REPO_ROOT" worktree remove --force --force "$source" \
                    || { warn "$role registered worktree cannot be removed"; return 1; }
            elif [ ! -e "$source" ] && [ ! -L "$source" ]; then
                git_closed -C "$REPO_ROOT" worktree remove --force --force "$source" \
                    || { warn "$role absent registered worktree cannot be removed"; return 1; }
            else
                warn "$role registered path is not a removable real directory"
                return 1
            fi
            ;;
        1) ;;
        *) warn "$role worktree registration cannot be inspected"; return 1 ;;
    esac
    if worktree_path_is_registered "$source"; then
        warn "$role remains registered after cleanup"
        return 1
    else
        query_status=$?
        [ "$query_status" -eq 1 ] \
            || { warn "$role registration postcondition cannot be inspected"; return 1; }
    fi
    case "$role" in "snapshot A"|"snapshot B") ;; *) return 1 ;; esac
}

assert_snapshot_worktree_not_registered() {
    local source="$1" role="$2" query_status=0
    [ -n "$source" ] || return 0
    case "$source" in
        "$SOURCE_A"|"$SOURCE_B") ;;
        *) warn "$role registration inspection escaped the recorded snapshot paths"; return 1 ;;
    esac
    worktree_path_is_registered "$source" || query_status=$?
    case "$query_status" in
        0) warn "$role remains registered while its workspace boundary is invalid"; return 1 ;;
        1) return 0 ;;
        *) warn "$role registration cannot be inspected"; return 1 ;;
    esac
}

prepare_existing_dist_removal() {
    local destination="$1" bad
    [ "$destination" = "$FINAL_DESTINATION" ] \
        || die "existing-dist inspection escaped the registered destination"
    [ -d "$destination" ] && [ ! -L "$destination" ] \
        || die "existing dist is not a real directory"
    /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$destination" \
        || die "existing dist contains a mount boundary"
    bad="$(find -P "$destination" -type d \
        \( ! -uid "$(id -u)" -o ! -gid "$(id -g)" \) -print -quit 2>/dev/null)" \
        || die "existing dist directory ownership cannot be inspected"
    [ -z "$bad" ] || die "existing dist contains a foreign-owned directory: $bad"
}

cleanup_release_workspace() {
    local status=$? cleanup_failed=0 workspace_state=none worktrees_safe=0
    trap - EXIT
    trap '' HUP INT TERM
    if [ "$WINDOWS_UNSAFE" -eq 1 ] || [ "$KEEP_WORKSPACE" -eq 1 ]; then
        printf 'build-release: preserving private workspace for Windows reconciliation: %s\n' "$WORKSPACE" >&2
        exit "$status"
    fi
    reconcile_final_publication || cleanup_failed=1
    if [ -n "$WORKSPACE" ]; then
        if [ -n "$WORKSPACE_ID" ] && [ -d "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ] \
            && [ "$(stat -c '%d:%i' -- "$WORKSPACE" 2>/dev/null)" = "$WORKSPACE_ID" ]; then
            workspace_state=valid
        elif [ ! -e "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ]; then
            workspace_state=absent
            cleanup_failed=1
        else
            workspace_state=invalid
            cleanup_failed=1
        fi
        if [ "$workspace_state" = valid ] && [ "$cleanup_failed" -eq 0 ]; then
            if [ -f "$PRIVATE_TREE_CLOSURE_PROBE" ] && [ ! -L "$PRIVATE_TREE_CLOSURE_PROBE" ]; then
                /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$WORKSPACE" \
                    || cleanup_failed=1
            else
                cleanup_failed=1
            fi
        fi
        if [ "$FIXTURE_MODE" -eq 0 ]; then
            if [ "$workspace_state" = valid ] && [ "$cleanup_failed" -eq 0 ]; then
                if [ -n "$DEBIAN_IMAGE_ID" ]; then
                    normalize_workspace_access || cleanup_failed=1
                else
                    prepare_unprivileged_workspace_removal || cleanup_failed=1
                fi
                [ "$cleanup_failed" -ne 0 ] || worktrees_safe=1
            elif [ "$workspace_state" = absent ]; then
                worktrees_safe=1
            fi
            if [ "$worktrees_safe" -eq 1 ]; then
                remove_snapshot_worktree_if_registered "$SOURCE_A" "snapshot A" \
                    || cleanup_failed=1
                remove_snapshot_worktree_if_registered "$SOURCE_B" "snapshot B" \
                    || cleanup_failed=1
            fi
        elif [ "$workspace_state" = valid ] && [ "$cleanup_failed" -eq 0 ]; then
            prepare_unprivileged_workspace_removal || cleanup_failed=1
            if [ "$cleanup_failed" -eq 0 ]; then
                worktrees_safe=1
                remove_snapshot_worktree_if_registered "$SOURCE_A" "snapshot A" \
                    || cleanup_failed=1
                remove_snapshot_worktree_if_registered "$SOURCE_B" "snapshot B" \
                    || cleanup_failed=1
            fi
        fi
        if [ "$worktrees_safe" -eq 0 ]; then
            assert_snapshot_worktree_not_registered "$SOURCE_A" "snapshot A" \
                || cleanup_failed=1
            assert_snapshot_worktree_not_registered "$SOURCE_B" "snapshot B" \
                || cleanup_failed=1
        fi
        if [ "$workspace_state" = valid ] && [ "$cleanup_failed" -eq 0 ]; then
            if [ -f "$PRIVATE_TREE_CLOSURE_PROBE" ] && [ ! -L "$PRIVATE_TREE_CLOSURE_PROBE" ]; then
                /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$WORKSPACE" \
                    || cleanup_failed=1
            else
                cleanup_failed=1
            fi
        fi
        if [ "$workspace_state" = valid ] && [ "$cleanup_failed" -eq 0 ]; then
            if ! rm -rf -- "$WORKSPACE"; then
                printf 'build-release: cleanup removal failed; retained path: %s\n' "$WORKSPACE" >&2
                cleanup_failed=1
            elif [ -e "$WORKSPACE" ] || [ -L "$WORKSPACE" ]; then
                printf 'build-release: cleanup removal postcondition failed: %s\n' "$WORKSPACE" >&2
                cleanup_failed=1
            fi
        fi
        if [ "$cleanup_failed" -ne 0 ]; then
            printf 'build-release: cleanup failed; recorded private workspace state is %s: %s\n' \
                "$workspace_state" "$WORKSPACE" >&2
        fi
    fi
    if [ "$cleanup_failed" -eq 0 ] && [ "$status" -eq 0 ] \
        && [ -n "$CANONICAL_PUBLICATION_PARENT_ID" ]; then
        [ "$(assert_single_writer_publication_parent "$REPO_ROOT" 2>/dev/null)" = \
          "$CANONICAL_PUBLICATION_PARENT_ID" ] \
            && sync_exact_directory "$REPO_ROOT" "$CANONICAL_PUBLICATION_PARENT_ID" \
                "final publication parent" \
            || cleanup_failed=1
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
        [ "$status" -ne 0 ] || status=1
    elif [ "$status" -eq 0 ] && [ -n "$RELEASE_SUCCESS_MESSAGE" ]; then
        log "$RELEASE_SUCCESS_MESSAGE"
    fi
    exit "$status"
}

release_preflight() {
    local working_pins_hash commit_pins_hash
    require_cmd cmp git docker python3 sha256sum stat readlink install find date flock /usr/bin/grep
    acquire_publication_lock
    CANONICAL_PUBLICATION_PARENT_ID="$(assert_single_writer_publication_parent "$REPO_ROOT")" \
        || die "canonical publication parent does not have one local writer"
    recover_pending_publications "$REPO_ROOT" "$FINAL_OUT_DIR" \
        || die "release preflight cannot reconcile a prior publication transaction"
    clear_final_publication_state
    assert_no_stale_release_worktrees
    assert_repo_state
    assert_source_date_epoch
    assert_release_source_state "release preflight"
    assert_origin_identity
    initialize_network_repo
    assert_live_origin_master "release preflight"
    working_pins_hash="$(sha256sum "$PINS_FILE" | awk '{print $1}')"
    commit_pins_hash="$(git_closed -C "$REPO_ROOT" show "$PINNED_HEAD:scripts/pins.env" | sha256sum | awk '{print $1}')" \
        || die "cannot read pins.env from the pinned commit"
    [ "$working_pins_hash" = "$commit_pins_hash" ] \
        || die "loaded pins.env bytes do not match the pinned commit"
    run_child /usr/bin/bash --noprofile --norc "$REPO_ROOT/scripts/verify-release.sh" --preflight \
        || die "release source-gate preflight failed"
    require_online_complete
    HOST_KEYSTORE="$DEFAULT_ANDROID_KEYSTORE"
    HOST_KEYSTORE_PASS_FILE="$DEFAULT_ANDROID_KEYSTORE_PASS_FILE"
    [ -f "$HOST_KEYSTORE" ] && [ ! -L "$HOST_KEYSTORE" ] \
        || die "Android keystore must be a non-symlink regular file"
    [ -f "$HOST_KEYSTORE_PASS_FILE" ] && [ ! -L "$HOST_KEYSTORE_PASS_FILE" ] \
        || die "Android keystore password must be a non-symlink regular file"
    assert_private_signing_files
    HOST_GOLDEN="$(canonical_file "$REPO_ROOT/.harness-state/win11-golden.qcow2")"
    docker_local version >/dev/null || die "local Docker daemon is unavailable"
    DEBIAN_IMAGE_ID="${DEB_BUILDER_IMAGE_ID:-}"
    ANDROID_IMAGE_ID="${ANDROID_BUILDER_IMAGE_ID:-}"
    WINDOWS_IMAGE_ID="${WIN_HELPER_IMAGE_ID:-}"
    verify_all_release_builder_images
    create_release_online_snapshot
    log "release preflight OK: clean pushed master ${PINNED_HEAD_SHORT}"
}

assert_snapshot_exact() {
    local source="$1" phase="$2" current dirt ignored expected
    expected="$(recorded_private_tree_identity "$source")" \
        || die "$phase: snapshot identity is unavailable"
    [ "$(stat -c '%d:%i:%u:%g:%a' "$source" 2>/dev/null)" = \
      "$expected:$(id -u):$(id -g):700" ] \
        || die "$phase: snapshot root identity/owner/mode differs"
    current="$(git_closed -C "$source" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "$phase: cannot resolve snapshot HEAD"
    [ "$current" = "$PINNED_HEAD" ] || die "$phase: snapshot commit changed"
    git_closed -C "$source" symbolic-ref --quiet HEAD >/dev/null 2>&1 \
        && die "$phase: snapshot is not detached"
    dirt="$(git_closed -C "$source" status --porcelain=v1 --untracked-files=all 2>/dev/null)" \
        || die "$phase: cannot inspect snapshot"
    [ -z "$dirt" ] || die "$phase: snapshot has tracked or nonignored changes"
    git_closed -C "$source" diff --quiet --no-ext-diff HEAD -- \
        || die "$phase: snapshot worktree differs from HEAD"
    git_closed -C "$source" diff --cached --quiet --no-ext-diff HEAD -- \
        || die "$phase: snapshot index differs from HEAD"
    ignored="$(git_closed -C "$source" clean -nffdx 2>/dev/null)" \
        || die "$phase: cannot inspect ignored generated state"
    [ -z "$ignored" ] || die "$phase: snapshot retains ignored generated state"
}

create_snapshot() {
    local label="$1" source="$2" output="$3" set_dir="$4" identity
    case "$label" in
        A|B) ;;
        *) die "unknown release snapshot label: $label" ;;
    esac
    install -d -m 0700 "$(dirname "$source")" "$output" "$set_dir"
    git_closed -C "$REPO_ROOT" worktree add --quiet --detach "$source" "$PINNED_HEAD" \
        || die "cannot create detached release snapshot $label"
    chmod 0700 "$source"
    [ "$(stat -c '%u:%a' "$source")" = "$(id -u):700" ] \
        || die "release snapshot $label is not current-UID mode 0700"
    identity="$(stat -c '%d:%i' "$source")" \
        || die "cannot record release snapshot $label identity"
    case "$label" in
        A) SOURCE_A_ID="$identity" ;;
        B) SOURCE_B_ID="$identity" ;;
    esac
    assert_snapshot_exact "$source" "snapshot $label creation"
}

reset_snapshot_build_state() {
    local source="$1" label="$2" ignored
    normalize_snapshot_access "$source" "$label"
    /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$source" \
        || die "$label: snapshot contains a mount boundary before Git cleanup"
    git_closed -C "$source" clean -ffdx >/dev/null \
        || die "$label: cannot remove prior generated build state"
    /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$source" \
        || die "$label: snapshot contains a mount boundary after Git cleanup"
    ignored="$(git_closed -C "$source" clean -nffdx 2>/dev/null)" \
        || die "$label: cannot prove generated-state removal"
    [ -z "$ignored" ] || die "$label: ignored generated state remains after reset"
    assert_snapshot_exact "$source" "$label after generated-state reset"
}

run_child() {
    assert_release_docker_config
    /usr/bin/env -i \
        HOME="$HOME" PATH="$CHILD_PATH" LC_ALL=C LANG=C TZ=UTC \
        USER="$(id -un)" LOGNAME="$(id -un)" \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 \
        GIT_NO_REPLACE_OBJECTS=1 \
        DOCKER_HOST="$DOCKER_HOST_URI" DOCKER_CONFIG="$DOCKER_CONFIG_DIR" \
        "$@"
}

run_verification() {
    local source="$1" label="$2"
    if [ "$FIXTURE_MODE" -eq 1 ]; then
        return 0
    fi
    reset_snapshot_build_state "$source" "$label before verification"
    run_snapshot_consumer "$label complete release verification" \
        run_child ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online" \
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN" ALLOW_DIRTY_TREE=0 \
        RELEASE_SRC_COMMIT="$PINNED_HEAD" \
        /usr/bin/bash --noprofile --norc "$source/scripts/verify-release.sh" \
        || die "$label: complete release verification failed"
    reset_snapshot_build_state "$source" "$label after verification"
}

copy_artifact() {
    local source="$1" destination="$2"
    [ -f "$source" ] && [ ! -L "$source" ] && [ -s "$source" ] \
        || die "target did not produce regular non-empty ${destination##*/}"
    install -m 0400 "$source" "$destination"
}

invoke_target() {
    local label="$1" target="$2" source="$3" output="$4" set_dir="$5"
    local -a fixture_env=()
    [ -z "$FIXTURE_LOG" ] || fixture_env=(
        RELEASE_FIXTURE_LOG="$FIXTURE_LOG"
        RELEASE_FIXTURE_ONLINE="$ONLINE_SNAPSHOT_PARENT/online"
    )
    install -d -m 0700 "$output"
    case "$target" in
        debian)
            run_snapshot_consumer "$label Debian build" run_child "${fixture_env[@]}" \
                RUSTDESK_RELEASE_ONLINE_SNAPSHOT="$ONLINE_SNAPSHOT_PARENT" OUT_DIR="$output" \
                DOUBLE_BUILD=0 SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN" ALLOW_DIRTY_TREE=0 \
                RELEASE_SRC_COMMIT="$PINNED_HEAD" RELEASE_DOCKER_IMAGE_ID="$DEBIAN_IMAGE_ID" \
                /usr/bin/bash --noprofile --norc "$source/scripts/build-debian.sh" \
                || die "$label: Debian build returned failure"
            copy_artifact "$output/rustdesk-x86_64.deb" "$set_dir/rustdesk-x86_64.deb"
            ;;
        android)
            run_snapshot_consumer "$label Android build" run_child "${fixture_env[@]}" \
                RUSTDESK_RELEASE_ONLINE_SNAPSHOT="$ONLINE_SNAPSHOT_PARENT" OUT_DIR="$output" \
                DOUBLE_BUILD=0 SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN" ALLOW_DIRTY_TREE=0 \
                RELEASE_SRC_COMMIT="$PINNED_HEAD" RELEASE_DOCKER_IMAGE_ID="$ANDROID_IMAGE_ID" \
                ANDROID_KEYSTORE="$HOST_KEYSTORE" ANDROID_KEYSTORE_PASS_FILE="$HOST_KEYSTORE_PASS_FILE" \
                /usr/bin/bash --noprofile --norc "$source/scripts/build-android.sh" \
                || die "$label: Android build returned failure"
            copy_artifact "$output/rustdesk-arm64.apk" "$set_dir/rustdesk-arm64.apk"
            ;;
        windows)
            WINDOWS_UNSAFE=1
            if ! run_snapshot_consumer "$label Windows build" run_child "${fixture_env[@]}" \
                RUSTDESK_RELEASE_ONLINE_SNAPSHOT="$ONLINE_SNAPSHOT_PARENT" OUT_DIR="$output" \
                DOUBLE_BUILD=0 SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN" ALLOW_DIRTY_TREE=0 \
                RELEASE_SRC_COMMIT="$PINNED_HEAD" WINDOWS_BUILD_SOURCE=head \
                HARNESS_STATE_DIR="$output/windows-state" WINDOWS_GOLDEN_IMAGE="$HOST_GOLDEN" \
                /usr/bin/bash --noprofile --norc "$source/scripts/build-windows-vm.sh"; then
                KEEP_WORKSPACE=1
                die "$label: Windows build returned failure; workspace retained because VM ownership is unresolved"
            fi
            WINDOWS_UNSAFE=0
            copy_artifact "$output/rustdesk-setup.exe" "$set_dir/rustdesk-setup.exe"
            copy_artifact "$output/rustdesk.msi" "$set_dir/rustdesk.msi"
            ;;
        *) die "unknown release target: $target" ;;
    esac
}

build_snapshot() {
    local label="$1" source="$2" output="$3" set_dir="$4" target
    run_verification "$source" "$label"
    for target in debian android windows; do
        log "$label: building $target"
        invoke_target "$label" "$target" "$source" "$output/$target" "$set_dir"
        if [ "$FIXTURE_MODE" -eq 0 ]; then
            reset_snapshot_build_state "$source" "$label after $target"
            verify_all_release_builder_images
        fi
    done
}

assert_exact_set() {
    local directory="$1" with_manifest="$2"
    python3 - "$directory" "$with_manifest" "${CANONICAL_ASSETS[@]}" <<'PY'
import os
import stat
import sys
from pathlib import Path

directory = Path(sys.argv[1])
expected = set(sys.argv[3:])
if sys.argv[2] == "1":
    expected.add("SHA256SUMS")
metadata = directory.lstat()
if not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit(f"release set is not a real directory: {directory}")
entries = list(os.scandir(directory))
if {entry.name for entry in entries} != expected or len(entries) != len(expected):
    raise SystemExit(f"release set has missing or extra entries: {directory}")
for entry in entries:
    metadata = entry.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise SystemExit(f"release entry is not a regular non-empty file: {entry.name!r}")
PY
}

compare_snapshots() {
    local name hash_a hash_b
    assert_exact_set "$SET_A" 0
    assert_exact_set "$SET_B" 0
    for name in "${CANONICAL_ASSETS[@]}"; do
        hash_a="$(sha256sum "$SET_A/$name" | awk '{print $1}')"
        hash_b="$(sha256sum "$SET_B/$name" | awk '{print $1}')"
        [ "$hash_a" = "$hash_b" ] \
            || die "independent snapshot mismatch for $name ($hash_a vs $hash_b)"
    done
}

write_manifest() {
    local directory="$1"
    assert_exact_set "$directory" 0
    chmod u+w "$directory"
    (
        cd "$directory"
        {
            printf '# rustdesk-fork release manifest v1\n'
            printf '# fork-version: %s\n' "$FORK_VER"
            printf '# commit: %s\n' "$PINNED_HEAD"
            printf '# source-date-epoch: %s\n' "$SOURCE_DATE_EPOCH_PIN"
            printf '# reproducibility: independent-snapshots-a-equals-b\n'
            sha256sum "${CANONICAL_ASSETS[@]}"
        } > SHA256SUMS
        chmod 0400 SHA256SUMS
    )
    assert_exact_set "$directory" 1
    (cd "$directory" && sha256sum -c --strict --status SHA256SUMS) \
        || die "release manifest checksum verification failed"
}

strict_manifest_proof() {
    local directory="$1" expected_header actual_header line name hash index
    local -a checksums
    assert_exact_set "$directory" 1
    [ "$(wc -l < "$directory/SHA256SUMS")" -eq 9 ] \
        || die "release manifest must have exactly nine lines"
    expected_header="$(printf '%s\n' \
        '# rustdesk-fork release manifest v1' \
        "# fork-version: $FORK_VER" \
        "# commit: $PINNED_HEAD" \
        "# source-date-epoch: $SOURCE_DATE_EPOCH_PIN" \
        '# reproducibility: independent-snapshots-a-equals-b')"
    actual_header="$(head -n 5 "$directory/SHA256SUMS")"
    [ "$actual_header" = "$expected_header" ] || die "release manifest metadata is not pinned-source exact"
    mapfile -t checksums < <(tail -n +6 "$directory/SHA256SUMS")
    [ "${#checksums[@]}" -eq 4 ] || die "release manifest checksum count is invalid"
    for index in "${!CANONICAL_ASSETS[@]}"; do
        line="${checksums[index]}"
        name="${CANONICAL_ASSETS[index]}"
        hash="${line%%  *}"
        [[ "$hash" =~ ^[0-9a-f]{64}$ ]] && [ "$line" = "$hash  $name" ] \
            || die "release manifest entry is not canonical for $name"
    done
    (cd "$directory" && sha256sum -c --strict --status SHA256SUMS) \
        || die "release manifest content does not verify"
}

assert_single_writer_publication_parent() {
    /usr/bin/python3 - "$1" "$(id -u)" <<'PY'
import errno
import grp
import os
import pwd
import stat
import sys

path = sys.argv[1]
uid = int(sys.argv[2])
if os.path.realpath(path) != path:
    raise SystemExit("publication parent is not canonical")
metadata = os.lstat(path)
if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid:
    raise SystemExit("publication parent is not an invoking-user directory")
if metadata.st_mode & stat.S_IWOTH:
    raise SystemExit("publication parent is world-writable")
if metadata.st_mode & stat.S_IWGRP:
    names = set(grp.getgrgid(metadata.st_gid).gr_mem)
    writers = {entry.pw_uid for entry in pwd.getpwall() if entry.pw_gid == metadata.st_gid}
    writers.update(pwd.getpwnam(name).pw_uid for name in names)
    if writers - {uid}:
        raise SystemExit("publication parent group has another local principal")
try:
    acl = os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)
except OSError as error:
    if error.errno not in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
        raise
else:
    if acl:
        raise SystemExit("publication parent has an extended access ACL")
if metadata.st_mode & stat.S_IRWXU != stat.S_IRWXU:
    raise SystemExit("publication parent lacks invoking-user access")
print("{}:{}".format(metadata.st_dev, metadata.st_ino))
PY
}

sync_exact_directory() {
    /usr/bin/python3 - "$1" "$2" "$3" <<'PY'
import os
import sys

path, identity, role = sys.argv[1:]
expected = tuple(int(part) for part in identity.split(":"))
descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    metadata = os.fstat(descriptor)
    if (metadata.st_dev, metadata.st_ino) != expected:
        raise SystemExit(f"{role} identity changed before synchronization")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

atomic_exchange_or_install() {
    python3 - "$1" "$2" "$3" "$4" "$5" "$6" "${7:--}" <<'PY'
import ctypes
import os
import stat
import sys

source = os.fsencode(sys.argv[1])
destination = os.fsencode(sys.argv[2])
expected_source = tuple(int(value) for value in sys.argv[3].split(":"))
expected_destination = None
if sys.argv[4] != "-":
    expected_destination = tuple(int(value) for value in sys.argv[4].split(":"))
expected_destination_parent = tuple(int(value) for value in sys.argv[5].split(":"))
expected_source_parent = tuple(int(value) for value in sys.argv[6].split(":"))
fixture_action = sys.argv[7]
if fixture_action not in ("-", "create-destination-after-check"):
    raise SystemExit("release exchange fixture action is invalid")
source_parent, source_name = os.path.split(source)
destination_parent, destination_name = os.path.split(destination)
if not source_name or not destination_name:
    raise SystemExit("release exchange path has an empty final component")
source_parent_fd = os.open(source_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
destination_parent_fd = os.open(
    destination_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
)


def identity(parent_fd, name):
    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit("release exchange path is not a real directory")
    return metadata.st_dev, metadata.st_ino


try:
    source_parent_stat = os.fstat(source_parent_fd)
    if (source_parent_stat.st_dev, source_parent_stat.st_ino) != expected_source_parent:
        raise SystemExit("release transaction identity changed before exchange")
    destination_parent_stat = os.fstat(destination_parent_fd)
    if (destination_parent_stat.st_dev, destination_parent_stat.st_ino) != expected_destination_parent:
        raise SystemExit("release parent identity changed before exchange")
    if identity(source_parent_fd, source_name) != expected_source:
        raise SystemExit("release staging identity changed before exchange")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if expected_destination is None:
        try:
            os.stat(destination_name, dir_fd=destination_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SystemExit("release destination appeared before installation")
        if fixture_action == "create-destination-after-check":
            os.mkdir(destination_name, 0o700, dir_fd=destination_parent_fd)
        if renameat2(
            source_parent_fd, source_name, destination_parent_fd, destination_name, 1
        ) != 0:
            error = ctypes.get_errno()
            raise SystemExit("release no-clobber installation failed: " + os.strerror(error))
    else:
        if identity(destination_parent_fd, destination_name) != expected_destination:
            raise SystemExit("release destination identity changed before exchange")
        if renameat2(
            source_parent_fd, source_name, destination_parent_fd, destination_name, 2
        ) != 0:
            error = ctypes.get_errno()
            raise SystemExit("release exchange failed: " + os.strerror(error))
    if identity(destination_parent_fd, destination_name) != expected_source:
        raise SystemExit("installed release identity differs after exchange")
    if expected_destination is None:
        try:
            os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SystemExit("release staging path survived installation")
    elif identity(source_parent_fd, source_name) != expected_destination:
        raise SystemExit("displaced release identity differs after exchange")
    os.fsync(destination_parent_fd)
    os.fsync(source_parent_fd)
finally:
    os.close(destination_parent_fd)
    os.close(source_parent_fd)
PY
}

path_identity() {
    local path="$1"
    if [ -L "$path" ]; then
        printf invalid
    elif [ -d "$path" ]; then
        stat -c '%d:%i' -- "$path" 2>/dev/null || printf invalid
    elif [ -e "$path" ]; then
        printf invalid
    else
        printf absent
    fi
}

prove_recorded_published_dist() {
    local destination="$1" commit="$2" version="$3" epoch="$4" manifest_hash="$5"
    local expected_header actual_header observed_manifest line name hash index root_metadata root_identity
    local -a checksums
    root_metadata="$(stat -c '%d:%i:%u:%g:%a' -- "$destination" 2>/dev/null)" \
        || die "published dist root cannot be inspected"
    root_identity="${root_metadata%:*:*:*}"
    case "$root_metadata" in
        "$root_identity:$(id -u):$(id -g):700"|"$root_identity:$(id -u):$(id -g):555") ;;
        *) die "published dist root is not the exact current-user identity at mode 0700 or 0555" ;;
    esac
    (
        assert_exact_set "$destination" 1
        [ "$(wc -l < "$destination/SHA256SUMS")" -eq 9 ] \
            || die "published release manifest must have exactly nine lines"
        expected_header="$(printf '%s\n' \
            '# rustdesk-fork release manifest v1' \
            "# fork-version: $version" \
            "# commit: $commit" \
            "# source-date-epoch: $epoch" \
            '# reproducibility: independent-snapshots-a-equals-b')"
        actual_header="$(head -n 5 "$destination/SHA256SUMS")"
        [ "$actual_header" = "$expected_header" ] \
            || die "published release manifest metadata differs from its transaction record"
        observed_manifest="$(sha256sum "$destination/SHA256SUMS" | awk '{print $1}')"
        [ "$observed_manifest" = "$manifest_hash" ] \
            || die "published release manifest digest differs from its transaction record"
        mapfile -t checksums < <(tail -n +6 "$destination/SHA256SUMS")
        [ "${#checksums[@]}" -eq 4 ] \
            || die "published release manifest checksum count is invalid"
        for index in "${!CANONICAL_ASSETS[@]}"; do
            line="${checksums[index]}"
            name="${CANONICAL_ASSETS[index]}"
            hash="${line%%  *}"
            [[ "$hash" =~ ^[0-9a-f]{64}$ ]] && [ "$line" = "$hash  $name" ] \
                || die "published release manifest entry is not canonical for $name"
        done
        (cd "$destination" && sha256sum -c --strict --status SHA256SUMS) \
            || die "published release manifest content does not verify"
        for name in "${CANONICAL_ASSETS[@]}" SHA256SUMS; do
            [ "$(stat -c '%a' "$destination/$name")" = 444 ] \
                || die "published dist file is not immutable mode 0444: $name"
        done
    )
    if [ "$(stat -c '%a' -- "$destination")" = 700 ]; then
        [ "$(stat -c '%d:%i' -- "$destination")" = "$root_identity" ] \
            || die "published dist identity changed before root finalization"
        chmod 0555 "$destination" \
            || die "published dist root cannot be finalized to mode 0555"
    fi
    [ "$(stat -c '%d:%i:%u:%g:%a' -- "$destination")" = \
      "$root_identity:$(id -u):$(id -g):555" ] \
        || die "published dist root finalization postcondition failed"
    /usr/bin/python3 - "$destination" "$root_identity" <<'PY'
import os
import sys

path, identity = sys.argv[1:]
expected = tuple(int(part) for part in identity.split(":"))
descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    metadata = os.fstat(descriptor)
    if (metadata.st_dev, metadata.st_ino) != expected:
        raise SystemExit("published dist identity changed before root sync")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

prove_published_dist() {
    local destination="$1" manifest_hash
    manifest_hash="$(sha256sum "$destination/SHA256SUMS" | awk '{print $1}')" \
        || die "cannot hash published release manifest"
    prove_recorded_published_dist \
        "$destination" "$PINNED_HEAD" "$FORK_VER" "$SOURCE_DATE_EPOCH_PIN" "$manifest_hash"
}

sync_staged_publication_payload() {
    /usr/bin/python3 - "$FINAL_STAGE" "$FINAL_STAGE_ID" \
        "$FINAL_TRANSACTION" "$FINAL_TRANSACTION_ID" "$(id -u)" "$(id -g)" \
        "${CANONICAL_ASSETS[@]}" SHA256SUMS <<'PY'
import os
import stat
import sys

(
    path,
    identity,
    transaction,
    transaction_identity,
    uid_text,
    gid_text,
    *expected_names,
) = sys.argv[1:]
expected_identity = tuple(int(part) for part in identity.split(":"))
expected_transaction_identity = tuple(
    int(part) for part in transaction_identity.split(":")
)
uid = int(uid_text)
gid = int(gid_text)
directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    directory = os.fstat(directory_fd)
    if (
        (directory.st_dev, directory.st_ino) != expected_identity
        or directory.st_uid != uid
        or directory.st_gid != gid
        or stat.S_IMODE(directory.st_mode) != 0o700
    ):
        raise SystemExit("publication payload root differs before durability commit")
    names = os.listdir(directory_fd)
    if len(names) != len(expected_names) or set(names) != set(expected_names):
        raise SystemExit("publication payload inventory differs before durability commit")
    for name in expected_names:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != uid
                or metadata.st_gid != gid
                or stat.S_IMODE(metadata.st_mode) != 0o444
                or metadata.st_nlink != 1
            ):
                raise SystemExit(f"publication payload entry is not durable-input exact: {name}")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
transaction_fd = os.open(
    transaction, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
)
try:
    transaction_metadata = os.fstat(transaction_fd)
    if (
        (transaction_metadata.st_dev, transaction_metadata.st_ino)
        != expected_transaction_identity
        or transaction_metadata.st_uid != uid
        or transaction_metadata.st_gid != gid
        or stat.S_IMODE(transaction_metadata.st_mode) != 0o700
    ):
        raise SystemExit("publication transaction differs before payload-name commit")
    payload_metadata = os.stat("payload", dir_fd=transaction_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(payload_metadata.st_mode)
        or (payload_metadata.st_dev, payload_metadata.st_ino) != expected_identity
    ):
        raise SystemExit("publication payload name differs before durability commit")
    os.fsync(transaction_fd)
finally:
    os.close(transaction_fd)
PY
}

sync_publication_directories() {
    /usr/bin/python3 - "$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import os
import sys

(
    destination_parent,
    destination_parent_identity,
    destination,
    destination_identity,
    transaction,
    transaction_identity,
) = sys.argv[1:]


def expected(value):
    return tuple(int(part) for part in value.split(":"))


destination_fd = os.open(
    destination_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
)
published_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
transaction_fd = os.open(transaction, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    metadata = os.fstat(destination_fd)
    if (metadata.st_dev, metadata.st_ino) != expected(destination_parent_identity):
        raise SystemExit("publication parent identity changed before recovery sync")
    metadata = os.fstat(published_fd)
    if (metadata.st_dev, metadata.st_ino) != expected(destination_identity):
        raise SystemExit("published release identity changed before recovery sync")
    metadata = os.fstat(transaction_fd)
    if (metadata.st_dev, metadata.st_ino) != expected(transaction_identity):
        raise SystemExit("publication transaction identity changed before recovery sync")
    os.fsync(published_fd)
    os.fsync(transaction_fd)
    os.fsync(destination_fd)
finally:
    os.close(transaction_fd)
    os.close(published_fd)
    os.close(destination_fd)
PY
}

write_publication_record() {
    local manifest_hash="$1" old_id=-
    [ "$FINAL_DEST_HAD_OLD" -eq 0 ] || old_id="$FINAL_OLD_ID"
    /usr/bin/python3 - \
        "$FINAL_TRANSACTION" "$FINAL_TRANSACTION_ID" "$(basename "$FINAL_DESTINATION")" \
        "$FINAL_PARENT_ID" "$FINAL_STAGE_ID" "$old_id" "$FINAL_DEST_HAD_OLD" \
        "$PINNED_HEAD" "$FORK_VER" "$SOURCE_DATE_EPOCH_PIN" "$manifest_hash" <<'PY'
import os
import re
import stat
import sys

(
    transaction,
    transaction_identity,
    destination,
    parent_identity,
    payload_identity,
    old_identity,
    had_old,
    commit,
    version,
    epoch,
    manifest_hash,
) = sys.argv[1:]
identity_pattern = re.compile(r"[0-9]+:[0-9]+")
if not re.fullmatch(r"[A-Za-z0-9._+-]+", destination):
    raise SystemExit("publication destination name is not canonical")
if not re.fullmatch(r"[A-Za-z0-9._+-]+", version):
    raise SystemExit("publication version is not canonical")
if not re.fullmatch(r"[0-9a-f]{40}", commit):
    raise SystemExit("publication commit is not canonical")
if not re.fullmatch(r"[0-9]+", epoch):
    raise SystemExit("publication epoch is not canonical")
if not re.fullmatch(r"[0-9a-f]{64}", manifest_hash):
    raise SystemExit("publication manifest digest is not canonical")
for value in (transaction_identity, parent_identity, payload_identity):
    if not identity_pattern.fullmatch(value):
        raise SystemExit("publication identity is not canonical")
if had_old not in ("0", "1") or (had_old == "0") != (old_identity == "-"):
    raise SystemExit("publication prior-destination state is inconsistent")
if old_identity != "-" and not identity_pattern.fullmatch(old_identity):
    raise SystemExit("publication prior-destination identity is not canonical")

transaction_bytes = os.fsencode(transaction)
transaction_fd = os.open(
    transaction_bytes, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
)
parent_fd = os.open(
    os.path.dirname(transaction_bytes), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
)
temporary = os.fsencode(f".record.tmp.{os.getpid()}")
record = b"record"
contents = (
    "rustdesk-release-transaction-v1\n"
    f"destination={destination}\n"
    f"parent_id={parent_identity}\n"
    f"transaction_id={transaction_identity}\n"
    f"payload_id={payload_identity}\n"
    f"old_id={old_identity}\n"
    f"had_old={had_old}\n"
    f"commit={commit}\n"
    f"version={version}\n"
    f"epoch={epoch}\n"
    f"manifest_sha256={manifest_hash}\n"
).encode("ascii")
try:
    metadata = os.fstat(transaction_fd)
    if f"{metadata.st_dev}:{metadata.st_ino}" != transaction_identity:
        raise SystemExit("publication transaction identity changed before record commit")
    try:
        os.stat(record, dir_fd=transaction_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit("publication transaction record already exists")
    record_fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=transaction_fd,
    )
    try:
        offset = 0
        while offset < len(contents):
            offset += os.write(record_fd, contents[offset:])
        os.fchmod(record_fd, 0o600)
        os.fsync(record_fd)
    finally:
        os.close(record_fd)
    os.rename(temporary, record, src_dir_fd=transaction_fd, dst_dir_fd=transaction_fd)
    os.fsync(transaction_fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
    os.close(transaction_fd)
PY
}

read_publication_record() {
    /usr/bin/python3 - "$1" "$2" "$3" "$(id -u)" "$(id -g)" <<'PY'
import os
import re
import stat
import sys

transaction, expected_destination, expected_parent, uid_text, gid_text = sys.argv[1:]
uid = int(uid_text)
gid = int(gid_text)
identity_pattern = re.compile(r"[0-9]+:[0-9]+")
transaction_fd = os.open(transaction, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    transaction_metadata = os.fstat(transaction_fd)
    if not stat.S_ISDIR(transaction_metadata.st_mode):
        raise SystemExit("publication transaction is not a real directory")
    if (
        transaction_metadata.st_uid != uid
        or transaction_metadata.st_gid != gid
        or stat.S_IMODE(transaction_metadata.st_mode) != 0o700
    ):
        raise SystemExit("publication transaction is not current-user mode 0700")
    transaction_identity = f"{transaction_metadata.st_dev}:{transaction_metadata.st_ino}"
    record_fd = os.open("record", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=transaction_fd)
    try:
        record_metadata = os.fstat(record_fd)
        if not stat.S_ISREG(record_metadata.st_mode):
            raise SystemExit("publication transaction record is not a regular file")
        if (
            record_metadata.st_uid != uid
            or record_metadata.st_gid != gid
            or stat.S_IMODE(record_metadata.st_mode) != 0o600
            or record_metadata.st_nlink != 1
        ):
            raise SystemExit("publication transaction record is not current-UID mode 0600 and non-hardlinked")
        chunks = []
        remaining = 4097
        while remaining:
            chunk = os.read(record_fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
    finally:
        os.close(record_fd)
finally:
    os.close(transaction_fd)
if len(contents) > 4096 or not contents.endswith(b"\n"):
    raise SystemExit("publication transaction record has invalid bounds")
try:
    lines = contents.decode("ascii").splitlines()
except UnicodeDecodeError as error:
    raise SystemExit("publication transaction record is not ASCII") from error
keys = (
    "destination",
    "parent_id",
    "transaction_id",
    "payload_id",
    "old_id",
    "had_old",
    "commit",
    "version",
    "epoch",
    "manifest_sha256",
)
if len(lines) != 11 or lines[0] != "rustdesk-release-transaction-v1":
    raise SystemExit("publication transaction record shape is invalid")
values = {}
for key, line in zip(keys, lines[1:]):
    prefix = key + "="
    if not line.startswith(prefix):
        raise SystemExit("publication transaction record order is invalid")
    values[key] = line[len(prefix):]
if values["destination"] != expected_destination:
    raise SystemExit("publication transaction destination differs")
if values["parent_id"] != expected_parent or not identity_pattern.fullmatch(expected_parent):
    raise SystemExit("publication transaction parent identity differs")
if values["transaction_id"] != transaction_identity:
    raise SystemExit("publication transaction inode identity differs")
if not identity_pattern.fullmatch(values["payload_id"]):
    raise SystemExit("publication payload identity is invalid")
if values["had_old"] not in ("0", "1"):
    raise SystemExit("publication prior-destination flag is invalid")
if (values["had_old"] == "0") != (values["old_id"] == "-"):
    raise SystemExit("publication prior-destination state is inconsistent")
if values["old_id"] != "-" and not identity_pattern.fullmatch(values["old_id"]):
    raise SystemExit("publication prior-destination identity is invalid")
if not re.fullmatch(r"[0-9a-f]{40}", values["commit"]):
    raise SystemExit("publication commit is invalid")
if not re.fullmatch(r"[A-Za-z0-9._+-]+", values["version"]):
    raise SystemExit("publication version is invalid")
if not re.fullmatch(r"[0-9]+", values["epoch"]):
    raise SystemExit("publication epoch is invalid")
if not re.fullmatch(r"[0-9a-f]{64}", values["manifest_sha256"]):
    raise SystemExit("publication manifest digest is invalid")
print("\t".join(values[key] for key in keys[3:]))
PY
}

commit_registered_final_transaction_discard() {
    local expected_identity="$1" parent base current_name terminal
    parent="$(dirname "$FINAL_DESTINATION")"
    base="$(basename "$FINAL_DESTINATION")"
    current_name="$(basename "$FINAL_TRANSACTION")"
    case "$current_name" in
        ".$base-release-transaction."*)
            terminal="$parent/.$base-release-discard.${current_name#.$base-release-transaction.}"
            [ "$(path_identity "$terminal")" = absent ] \
                || { warn "publication discard path already exists"; return 1; }
            /usr/bin/python3 - "$FINAL_TRANSACTION" "$terminal" "$expected_identity" "$FINAL_PARENT_ID" <<'PY'
import os
import stat
import sys

source = os.fsencode(sys.argv[1])
destination = os.fsencode(sys.argv[2])
expected_source = tuple(int(part) for part in sys.argv[3].split(":"))
expected_parent = tuple(int(part) for part in sys.argv[4].split(":"))
parent, source_name = os.path.split(source)
destination_parent, destination_name = os.path.split(destination)
if parent != destination_parent or not source_name or not destination_name:
    raise SystemExit("publication discard paths do not share one parent")
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    metadata = os.fstat(parent_fd)
    if (metadata.st_dev, metadata.st_ino) != expected_parent:
        raise SystemExit("publication parent identity changed before discard commit")
    metadata = os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != expected_source:
        raise SystemExit("publication transaction identity changed before discard commit")
    try:
        os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit("publication discard destination already exists")
    os.rename(source_name, destination_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
            FINAL_TRANSACTION="$terminal"
            ;;
        ".$base-release-discard."*) return 0 ;;
        *) warn "registered publication transaction name is noncanonical"; return 1 ;;
    esac
}

remove_registered_final_transaction() {
    local expected_identity="$1" observed bad parent base current_name
    [ -n "$FINAL_TRANSACTION" ] || return 0
    parent="$(dirname "$FINAL_DESTINATION")"
    base="$(basename "$FINAL_DESTINATION")"
    [ "$(dirname "$FINAL_TRANSACTION")" = "$parent" ] \
        || { warn "registered publication transaction escaped the destination parent"; return 1; }
    [ "$(stat -c '%d:%i' -- "$parent" 2>/dev/null)" = "$FINAL_PARENT_ID" ] \
        || { warn "registered publication parent identity differs"; return 1; }
    commit_registered_final_transaction_discard "$expected_identity" || return 1
    current_name="$(basename "$FINAL_TRANSACTION")"
    case "$current_name" in
        ".$base-release-discard."*) ;;
        *) warn "registered publication discard name is noncanonical"; return 1 ;;
    esac
    observed="$(path_identity "$FINAL_TRANSACTION")"
    [ "$observed" = "$expected_identity" ] \
        || { warn "registered publication transaction identity differs"; return 1; }
    /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$FINAL_TRANSACTION" \
        || { warn "registered publication transaction contains a mount boundary"; return 1; }
    bad="$(find -P "$FINAL_TRANSACTION" -type d \
        \( ! -uid "$(id -u)" -o ! -gid "$(id -g)" \) -print -quit 2>/dev/null)" \
        || { warn "registered publication transaction ownership cannot be inspected"; return 1; }
    [ -z "$bad" ] \
        || { warn "registered publication transaction contains a foreign-owned directory: $bad"; return 1; }
    find -P "$FINAL_TRANSACTION" -type d -exec chmod u+rwx,go-w {} + \
        || { warn "registered publication transaction directories cannot be made removable"; return 1; }
    /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$FINAL_TRANSACTION" \
        || { warn "registered publication transaction gained a mount boundary"; return 1; }
    [ "$(path_identity "$FINAL_TRANSACTION")" = "$expected_identity" ] \
        || { warn "registered publication transaction identity changed before removal"; return 1; }
    rm -rf -- "$FINAL_TRANSACTION" \
        || { warn "registered publication transaction removal failed"; return 1; }
    [ "$(path_identity "$FINAL_TRANSACTION")" = absent ] \
        || { warn "registered publication transaction remains after removal"; return 1; }
    if [ "$FIXTURE_MODE" -eq 1 ] \
        && [ "$PUBLICATION_FIXTURE_STOP_AFTER_DISCARD_REMOVAL" -eq 1 ]; then
        return 75
    fi
    /usr/bin/python3 - "$parent" "$FINAL_PARENT_ID" <<'PY'
import os
import sys

path, identity = sys.argv[1:]
expected = tuple(int(part) for part in identity.split(":"))
descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    metadata = os.fstat(descriptor)
    if (metadata.st_dev, metadata.st_ino) != expected:
        raise SystemExit("publication parent identity changed before discard-removal sync")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
    FINAL_TRANSACTION=""
    FINAL_TRANSACTION_ID=""
    FINAL_STAGE=""
}

reconcile_final_publication() {
    local destination_identity stage_identity expected_destination record old_id had_old
    local commit version epoch manifest_hash
    if [ "$FINAL_PUBLICATION_STATE" = idle ] || [ "$FINAL_PUBLICATION_STATE" = published ]; then
        [ -z "$FINAL_TRANSACTION" ] && [ -z "$FINAL_STAGE" ] \
            || { warn "terminal publication state retains a registered transaction"; return 1; }
        return 0
    fi
    [ -n "$FINAL_DESTINATION" ] && [ -n "$FINAL_PARENT_ID" ] \
        || { warn "publication identity state is incomplete"; return 1; }
    [ "$(stat -c '%d:%i' -- "$(dirname "$FINAL_DESTINATION")" 2>/dev/null)" = "$FINAL_PARENT_ID" ] \
        || { warn "publication parent identity changed"; return 1; }
    if [ "$FINAL_PUBLICATION_STATE" = transaction-initializing ] && [ -z "$FINAL_TRANSACTION" ]; then
        recover_pending_publications "$(dirname "$FINAL_DESTINATION")" "$FINAL_DESTINATION" \
            || return 1
        return 0
    fi
    [ -n "$FINAL_TRANSACTION" ] && [ -n "$FINAL_TRANSACTION_ID" ] \
        || { warn "publication transaction identity state is incomplete"; return 1; }
    if [ ! -f "$FINAL_TRANSACTION/record" ] || [ -L "$FINAL_TRANSACTION/record" ]; then
        case "$FINAL_PUBLICATION_STATE" in
            transaction-initializing|staging) ;;
            *) warn "exchange-capable publication has no durable record"; return 1 ;;
        esac
        [ "$(path_identity "$FINAL_DESTINATION")" = \
          "$([ "$FINAL_DEST_HAD_OLD" -eq 1 ] && printf '%s' "$FINAL_OLD_ID" || printf absent)" ] \
            || { warn "recordless publication changed the destination"; return 1; }
        remove_registered_final_transaction "$FINAL_TRANSACTION_ID" || return 1
        FINAL_PUBLICATION_STATE=idle
        return 0
    fi
    record="$(read_publication_record \
        "$FINAL_TRANSACTION" "$(basename "$FINAL_DESTINATION")" "$FINAL_PARENT_ID")" \
        || { warn "publication transaction record is invalid"; return 1; }
    IFS=$'\t' read -r FINAL_STAGE_ID old_id had_old commit version epoch manifest_hash <<< "$record"
    [ -n "$manifest_hash" ] \
        || { warn "publication transaction record is incomplete"; return 1; }
    [ "$had_old" = "$FINAL_DEST_HAD_OLD" ] \
        || { warn "publication prior-destination flag differs from memory"; return 1; }
    if [ "$had_old" -eq 1 ]; then
        [ "$old_id" = "$FINAL_OLD_ID" ] \
            || { warn "publication prior-destination identity differs from memory"; return 1; }
    else
        [ "$old_id" = - ] \
            || { warn "publication record unexpectedly names a prior destination"; return 1; }
    fi
    FINAL_STAGE="$FINAL_TRANSACTION/payload"
    destination_identity="$(path_identity "$FINAL_DESTINATION")"
    stage_identity="$(path_identity "$FINAL_STAGE")"

    if [ "$destination_identity" = "$FINAL_STAGE_ID" ]; then
        if [ "$FINAL_DEST_HAD_OLD" -eq 1 ] \
            && [ "$stage_identity" != "$FINAL_OLD_ID" ] \
            && [ "$stage_identity" != absent ]; then
            warn "displaced release identity is unresolved"
            return 1
        fi
        if [ "$FINAL_DEST_HAD_OLD" -eq 0 ] && [ "$stage_identity" != absent ]; then
            warn "publication retains an unexpected payload identity"
            return 1
        fi
        prove_recorded_published_dist \
            "$FINAL_DESTINATION" "$commit" "$version" "$epoch" "$manifest_hash" \
            || { warn "installed release proof failed"; return 1; }
        sync_publication_directories \
            "$(dirname "$FINAL_DESTINATION")" "$FINAL_PARENT_ID" \
            "$FINAL_DESTINATION" "$FINAL_STAGE_ID" \
            "$FINAL_TRANSACTION" "$FINAL_TRANSACTION_ID" \
            || { warn "published release durability recovery failed"; return 1; }
        FINAL_PUBLICATION_STATE=published
        remove_registered_final_transaction "$FINAL_TRANSACTION_ID" || return 1
        return 0
    fi

    case "$FINAL_PUBLICATION_STATE" in
        staging|exchange-pending) ;;
        *) warn "published release destination identity changed"; return 1 ;;
    esac
    if [ "$FINAL_DEST_HAD_OLD" -eq 1 ]; then
        expected_destination="$FINAL_OLD_ID"
    else
        expected_destination=absent
    fi
    [ "$destination_identity" = "$expected_destination" ] \
        || { warn "release exchange outcome is ambiguous"; return 1; }
    [ "$stage_identity" = "$FINAL_STAGE_ID" ] \
        || { warn "unpublished release payload identity changed"; return 1; }
    prove_recorded_published_dist "$FINAL_STAGE" "$commit" "$version" "$epoch" "$manifest_hash" \
        || { warn "unpublished release payload proof failed"; return 1; }
    remove_registered_final_transaction "$FINAL_TRANSACTION_ID" || return 1
    FINAL_PUBLICATION_STATE=idle
}

recover_pending_publications() {
    local parent="$1" destination="$2" base parent_id transaction transaction_id record
    local payload_id old_id had_old commit version epoch manifest_hash
    local -a transactions discards
    parent_id="$(assert_single_writer_publication_parent "$parent")" \
        || { warn "publication recovery parent does not have one local writer"; return 1; }
    base="$(basename "$destination")"
    shopt -s nullglob
    discards=("$parent/.$base-release-discard."*)
    transactions=("$parent/.$base-release-transaction."*)
    shopt -u nullglob
    for transaction in "${discards[@]}"; do
        [ -d "$transaction" ] && [ ! -L "$transaction" ] \
            || { warn "publication discard path is not a real directory"; return 1; }
        transaction_id="$(stat -c '%d:%i' -- "$transaction" 2>/dev/null)" \
            || { warn "publication discard identity cannot be recorded"; return 1; }
        FINAL_DESTINATION="$destination"
        FINAL_PARENT_ID="$parent_id"
        FINAL_TRANSACTION="$transaction"
        FINAL_TRANSACTION_ID="$transaction_id"
        FINAL_STAGE=""
        remove_registered_final_transaction "$transaction_id" || return 1
    done
    sync_exact_directory "$parent" "$parent_id" "publication recovery parent" \
        || { warn "publication recovery parent cannot be synchronized"; return 1; }
    [ "${#transactions[@]}" -le 1 ] \
        || { warn "multiple publication transactions require manual reconciliation"; return 1; }
    if [ "${#transactions[@]}" -eq 0 ]; then
        [ "$FINAL_PUBLICATION_STATE" != transaction-initializing ] \
            || FINAL_PUBLICATION_STATE=idle
        return 0
    fi
    transaction="${transactions[0]}"
    [ -d "$transaction" ] && [ ! -L "$transaction" ] \
        || { warn "publication transaction path is not a real directory"; return 1; }
    transaction_id="$(stat -c '%d:%i' -- "$transaction" 2>/dev/null)" \
        || { warn "publication transaction identity cannot be recorded"; return 1; }
    FINAL_DESTINATION="$destination"
    FINAL_PARENT_ID="$parent_id"
    FINAL_TRANSACTION="$transaction"
    FINAL_TRANSACTION_ID="$transaction_id"
    FINAL_STAGE="$transaction/payload"
    if [ ! -f "$transaction/record" ] || [ -L "$transaction/record" ]; then
        FINAL_DEST_HAD_OLD=0
        FINAL_OLD_ID=""
        FINAL_PUBLICATION_STATE=staging
        remove_registered_final_transaction "$transaction_id" || return 1
        FINAL_PUBLICATION_STATE=idle
        return 0
    fi
    record="$(read_publication_record "$transaction" "$base" "$parent_id")" \
        || { warn "publication recovery record is invalid"; return 1; }
    IFS=$'\t' read -r payload_id old_id had_old commit version epoch manifest_hash <<< "$record"
    [ -n "$manifest_hash" ] \
        || { warn "publication recovery record is incomplete"; return 1; }
    FINAL_STAGE_ID="$payload_id"
    FINAL_DEST_HAD_OLD="$had_old"
    if [ "$had_old" -eq 1 ]; then
        FINAL_OLD_ID="$old_id"
    else
        FINAL_OLD_ID=""
    fi
    FINAL_PUBLICATION_STATE=exchange-pending
    reconcile_final_publication || return 1
    case "$FINAL_PUBLICATION_STATE" in
        idle|published) ;;
        *) warn "publication recovery did not reach a terminal state"; return 1 ;;
    esac
    sync_exact_directory "$parent" "$parent_id" "publication recovery parent" \
        || { warn "publication recovery completion cannot be synchronized"; return 1; }
}

clear_final_publication_state() {
    [ -z "$FINAL_TRANSACTION" ] && [ -z "$FINAL_STAGE" ] \
        || die "cannot clear a live publication transaction"
    FINAL_DESTINATION=""
    FINAL_PARENT_ID=""
    FINAL_TRANSACTION_ID=""
    FINAL_STAGE_ID=""
    FINAL_OLD_ID=""
    FINAL_DEST_HAD_OLD=0
    FINAL_PUBLICATION_STATE=idle
}

atomic_install_dist() {
    local source="$1" destination="${2:-$FINAL_OUT_DIR}" parent base name atomic_status manifest_hash
    [ "$FINAL_PUBLICATION_STATE" = idle ] && [ -z "$FINAL_STAGE" ] \
        || die "a final-dist transaction is already active"
    parent="$(dirname "$destination")"
    base="$(basename "$destination")"
    recover_pending_publications "$parent" "$destination" \
        || die "cannot reconcile a prior final-dist transaction"
    clear_final_publication_state
    FINAL_DESTINATION="$destination"
    FINAL_PARENT_ID="$(assert_single_writer_publication_parent "$parent")" \
        || die "final-dist parent does not have one local writer"
    if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -d "$destination" ]; }; then
        die "existing dist is not a real directory"
    fi
    if [ -d "$destination" ]; then
        prepare_existing_dist_removal "$destination"
        FINAL_DEST_HAD_OLD=1
        FINAL_OLD_ID="$(stat -c '%d:%i' -- "$destination")" \
            || die "cannot record existing dist identity"
    else
        FINAL_DEST_HAD_OLD=0
        FINAL_OLD_ID=""
    fi
    FINAL_PUBLICATION_STATE=transaction-initializing
    FINAL_TRANSACTION="$(umask 077 && mktemp -d "$parent/.$base-release-transaction.XXXXXXXXXX")" \
        || die "cannot create private final-dist transaction directory"
    FINAL_TRANSACTION_ID="$(stat -c '%d:%i' -- "$FINAL_TRANSACTION")" \
        || die "cannot record final-dist transaction identity"
    [ "$(stat -c '%u:%g:%a' -- "$FINAL_TRANSACTION")" = "$(id -u):$(id -g):700" ] \
        || die "final-dist transaction is not current-user mode 0700"
    FINAL_STAGE="$FINAL_TRANSACTION/payload"
    install -d -m 0700 "$FINAL_STAGE"
    FINAL_STAGE_ID="$(stat -c '%d:%i' -- "$FINAL_STAGE")" \
        || die "cannot record final-dist staging identity"
    FINAL_PUBLICATION_STATE=staging
    for name in "${CANONICAL_ASSETS[@]}" SHA256SUMS; do
        install -m 0444 "$source/$name" "$FINAL_STAGE/$name"
    done
    strict_manifest_proof "$FINAL_STAGE"
    sync_staged_publication_payload \
        || die "cannot durably commit final-dist staging payload"
    manifest_hash="$(sha256sum "$FINAL_STAGE/SHA256SUMS" | awk '{print $1}')" \
        || die "cannot hash final-dist staging manifest"
    write_publication_record "$manifest_hash" \
        || die "cannot durably commit the final-dist transaction record"
    read_publication_record "$FINAL_TRANSACTION" "$base" "$FINAL_PARENT_ID" >/dev/null \
        || die "final-dist transaction record failed its post-commit proof"
    [ "$(path_identity "$FINAL_STAGE")" = "$FINAL_STAGE_ID" ] \
        || die "final-dist staging identity changed before exchange"
    if [ "$FINAL_DEST_HAD_OLD" -eq 1 ]; then
        [ "$(path_identity "$destination")" = "$FINAL_OLD_ID" ] \
            || die "existing dist identity changed before exchange"
        atomic_status=0
        FINAL_PUBLICATION_STATE=exchange-pending
        atomic_exchange_or_install "$FINAL_STAGE" "$destination" "$FINAL_STAGE_ID" "$FINAL_OLD_ID" \
            "$FINAL_PARENT_ID" "$FINAL_TRANSACTION_ID" \
            || atomic_status=$?
    else
        [ "$(path_identity "$destination")" = absent ] \
            || die "release destination appeared before exchange"
        atomic_status=0
        FINAL_PUBLICATION_STATE=exchange-pending
        atomic_exchange_or_install "$FINAL_STAGE" "$destination" "$FINAL_STAGE_ID" - \
            "$FINAL_PARENT_ID" "$FINAL_TRANSACTION_ID" \
            || atomic_status=$?
    fi
    if [ "$atomic_status" -ne 0 ]; then
        reconcile_final_publication \
            || die "atomic final-dist failure left an ambiguous exchange state"
        clear_final_publication_state
        die "atomic final-dist installation failed"
    fi
    reconcile_final_publication || die "cannot reconcile the completed final-dist exchange"
    [ "$FINAL_PUBLICATION_STATE" = published ] \
        || die "atomic helper returned without publishing the staged release"
    clear_final_publication_state
}

prepare_release_snapshots() {
    SOURCE_A="$WORKSPACE/pass-A/source"
    SOURCE_B="$WORKSPACE/pass-B/source"
    OUTPUT_A="$WORKSPACE/pass-A/outputs"
    OUTPUT_B="$WORKSPACE/pass-B/outputs"
    SET_A="$WORKSPACE/pass-A/release-set"
    SET_B="$WORKSPACE/pass-B/release-set"
    create_snapshot A "$SOURCE_A" "$OUTPUT_A" "$SET_A"
    create_snapshot B "$SOURCE_B" "$OUTPUT_B" "$SET_B"
    local version_a version_b epoch_a epoch_b cert_a cert_b
    version_a="$(run_child /usr/bin/bash --noprofile --norc "$SOURCE_A/scripts/fork-version.sh")" \
        || die "snapshot A version metadata is invalid"
    version_b="$(run_child /usr/bin/bash --noprofile --norc "$SOURCE_B/scripts/fork-version.sh")" \
        || die "snapshot B version metadata is invalid"
    [ "$version_a" = "$version_b" ] || die "snapshot version metadata differs"
    FORK_VER="$version_a"
    epoch_a="$(run_child /usr/bin/bash --noprofile --norc -c 'source "$1"; printf "%s" "$SOURCE_DATE_EPOCH_PIN"' _ "$SOURCE_A/scripts/pins.env")"
    epoch_b="$(run_child /usr/bin/bash --noprofile --norc -c 'source "$1"; printf "%s" "$SOURCE_DATE_EPOCH_PIN"' _ "$SOURCE_B/scripts/pins.env")"
    cert_a="$(run_child /usr/bin/bash --noprofile --norc -c 'source "$1"; printf "%s" "$ANDROID_SIGNING_CERT_SHA256"' _ "$SOURCE_A/scripts/pins.env")"
    cert_b="$(run_child /usr/bin/bash --noprofile --norc -c 'source "$1"; printf "%s" "$ANDROID_SIGNING_CERT_SHA256"' _ "$SOURCE_B/scripts/pins.env")"
    [ "$epoch_a" = "$epoch_b" ] && [ "$epoch_a" = "$SOURCE_DATE_EPOCH_PIN" ] \
        || die "snapshot reproducible-build epoch differs from the loaded pinned value"
    [ "$cert_a" = "$cert_b" ] && [ "$cert_a" = "$ANDROID_SIGNING_CERT_SHA256" ] \
        || die "snapshot Android certificate pin differs from the loaded pinned value"
    SOURCE_DATE_EPOCH_PIN="$epoch_a"
    ANDROID_SIGNING_CERT_SHA256="$cert_a"
    export SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN"
}

write_fixture_target() {
    local source="$1" target="$2" body="$3" script_target="$2"
    [ "$target" != windows ] || script_target=windows-vm
    install -d -m 0700 "$source/scripts"
    {
        printf '#!/usr/bin/env bash\nset -euo pipefail\n'
        printf '[ "${DOUBLE_BUILD:-}" = 0 ]\n'
        printf '[ "${DOCKER_HOST:-}" = unix:///var/run/docker.sock ]\n'
        printf '[ -n "${DOCKER_CONFIG:-}" ] && [ -f "$DOCKER_CONFIG/config.json" ]\n'
        printf '[ -z "${POISON_MARKER+x}" ] && [ -z "${BASH_ENV+x}" ] && [ -z "${GIT_CONFIG+x}" ] && [ -z "${DOCKER_CONTEXT+x}" ]\n'
        printf '[ -z "${ONLINE_DIR+x}" ]\n'
        printf '[ -n "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ]\n'
        printf 'fixture_online="$RUSTDESK_RELEASE_ONLINE_SNAPSHOT/online"\n'
        printf '[ "$fixture_online" = "${RELEASE_FIXTURE_ONLINE:?}" ]\n'
        printf '[ -r "$fixture_online/fixture-input" ]\n'
        printf 'docker fixture-probe >/dev/null\n'
        printf 'mkdir -p "$OUT_DIR"\n'
        printf 'printf "%%s|%%s|%%s|%%s\\n" "%s" "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" "$OUT_DIR" "$fixture_online" >> "$RELEASE_FIXTURE_LOG"\n' "$target"
        printf '%s\n' "$body"
    } > "$source/scripts/build-$script_target.sh"
    chmod 0700 "$source/scripts/build-$script_target.sh"
}

run_invalid_workspace_registration_self_test() (
    local fixture_root="$WORKSPACE/invalid-recorded-workspace"
    local moved_root="$WORKSPACE/invalid-moved-workspace"
    local fixture_source="$fixture_root/pass-A/source"
    local fixture_root_id="" query_status registration_safe=0 candidate
    cleanup_invalid_fixture() {
        local status=$? cleanup_failed=0
        trap - EXIT
        trap '' HUP INT TERM
        if [ -L "$fixture_root" ]; then
            [ "$(readlink -- "$fixture_root" 2>/dev/null)" = "$moved_root" ] \
                && rm -f -- "$fixture_root" \
                || cleanup_failed=1
        elif [ -e "$fixture_root" ] \
            && { [ ! -d "$fixture_root" ] || [ -L "$fixture_root" ] \
                || [ "$(stat -c '%d:%i' -- "$fixture_root" 2>/dev/null)" != "$fixture_root_id" ]; }; then
            cleanup_failed=1
        fi
        query_status=0
        worktree_path_is_registered "$fixture_source" || query_status=$?
        case "$query_status" in
            0)
                if git_closed -C "$REPO_ROOT" worktree remove --force --force "$fixture_source"; then
                    query_status=0
                    worktree_path_is_registered "$fixture_source" || query_status=$?
                    [ "$query_status" -eq 1 ] && registration_safe=1 || cleanup_failed=1
                else
                    cleanup_failed=1
                fi
                ;;
            1) registration_safe=1 ;;
            *) cleanup_failed=1 ;;
        esac
        if [ "$registration_safe" -eq 1 ]; then
            for candidate in "$fixture_root" "$moved_root"; do
                if [ -d "$candidate" ] && [ ! -L "$candidate" ]; then
                    [ -n "$fixture_root_id" ] \
                        && [ "$(stat -c '%d:%i' -- "$candidate" 2>/dev/null)" = "$fixture_root_id" ] \
                        && /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$candidate" \
                        && rm -rf -- "$candidate" \
                        && [ ! -e "$candidate" ] && [ ! -L "$candidate" ] \
                        || cleanup_failed=1
                elif [ -e "$candidate" ] || [ -L "$candidate" ]; then
                    cleanup_failed=1
                fi
            done
        fi
        [ "$cleanup_failed" -eq 0 ] || status=1
        exit "$status"
    }
    trap cleanup_invalid_fixture EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    install -d -m 0700 "$fixture_root/pass-A"
    fixture_root_id="$(stat -c '%d:%i' -- "$fixture_root")" \
        || die "invalid-workspace fixture cannot record its root identity"
    SOURCE_A="$fixture_source"
    SOURCE_B=""
    git_closed -C "$REPO_ROOT" worktree add --quiet --detach "$fixture_source" "$PINNED_HEAD" \
        || die "invalid-workspace fixture cannot create its registered worktree"
    mv -- "$fixture_root" "$moved_root" \
        || die "invalid-workspace fixture cannot move its recorded root"
    ln -s "$moved_root" "$fixture_root" \
        || die "invalid-workspace fixture cannot replace its recorded root"
    WORKSPACE="$fixture_root"
    WORKSPACE_ID="$fixture_root_id"
    [ -L "$WORKSPACE" ] \
        || die "invalid-workspace fixture did not replace the recorded root with a symlink"
    if assert_snapshot_worktree_not_registered "$SOURCE_A" "snapshot A"; then
        die "invalid-workspace fixture accepted a surviving exact registration"
    fi
)

run_reset_self_test() {
    local sentinel sentinel_proof sentinel_registry_proof hostile_dir source_identity
    local locked_present locked_absent query_status original_source_b
    require_cmd git docker python3 sha256sum stat readlink find chmod
    PINNED_HEAD="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "reset self-test cannot resolve repository HEAD"
    PINNED_HEAD_SHORT="${PINNED_HEAD:0:12}"
    assert_release_source_state "reset self-test"
    create_workspace
    DEBIAN_IMAGE_ID="${DEB_BUILDER_IMAGE_ID:-}"
    [ -n "$DEBIAN_IMAGE_ID" ] || die "reset self-test has no pinned Debian image ID"
    docker_local version >/dev/null || die "reset self-test cannot reach the local Docker daemon"
    verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"
    SOURCE_A="$WORKSPACE/pass-A/source"
    OUTPUT_A="$WORKSPACE/pass-A/outputs"
    SET_A="$WORKSPACE/pass-A/release-set"
    create_snapshot A "$SOURCE_A" "$OUTPUT_A" "$SET_A"
    run_invalid_workspace_registration_self_test \
        || die "reset self-test did not inspect registration under an invalid workspace root"

    sentinel="$WORKSPACE/external-sentinel"
    printf 'outside-generated-tree\n' > "$sentinel"
    sentinel_proof="$(stat -c '%d:%i:%u:%g:%a' "$sentinel"):$(sha256sum "$sentinel" | awk '{print $1}')"
    sentinel_registry_proof="$(stat -c '%d:%i:%u:%g:%a:%Y:%Z' "$sentinel"):$(sha256sum "$sentinel" | awk '{print $1}')"
    ln -s "$sentinel" "$WORKSPACE/.git-worktree-registry"
    query_status=0
    worktree_path_is_registered "$SOURCE_A" || query_status=$?
    [ "$query_status" -eq 0 ] \
        || die "reset self-test could not query the exact registered worktree"
    [ "$(stat -c '%d:%i:%u:%g:%a:%Y:%Z' "$sentinel"):$(sha256sum "$sentinel" | awk '{print $1}')" = \
      "$sentinel_registry_proof" ] \
        || die "reset self-test worktree query followed its hostile fixed-name symlink"
    rm -f -- "$WORKSPACE/.git-worktree-registry"

    original_source_b="$SOURCE_B"
    locked_present="$WORKSPACE/locked-present"
    SOURCE_B="$locked_present"
    git_closed -C "$REPO_ROOT" worktree add --quiet --detach "$locked_present" "$PINNED_HEAD" \
        || die "reset self-test cannot create the present locked worktree"
    git_closed -C "$REPO_ROOT" worktree lock --reason initializing "$locked_present" \
        || die "reset self-test cannot lock the present worktree"
    remove_snapshot_worktree_if_registered "$locked_present" "snapshot B" \
        || die "reset self-test cannot remove the present locked worktree"
    [ ! -e "$locked_present" ] && [ ! -L "$locked_present" ] \
        || die "reset self-test retained the present locked worktree"
    SOURCE_B="$original_source_b"

    locked_absent="$WORKSPACE/locked-absent"
    SOURCE_B="$locked_absent"
    git_closed -C "$REPO_ROOT" worktree add --quiet --detach "$locked_absent" "$PINNED_HEAD" \
        || die "reset self-test cannot create the absent locked worktree"
    git_closed -C "$REPO_ROOT" worktree lock --reason initializing "$locked_absent" \
        || die "reset self-test cannot lock the absent worktree"
    rm -rf -- "$locked_absent"
    remove_snapshot_worktree_if_registered "$locked_absent" "snapshot B" \
        || die "reset self-test cannot remove the absent locked worktree registration"
    [ ! -e "$locked_absent" ] && [ ! -L "$locked_absent" ] \
        || die "reset self-test retained the absent locked worktree path"
    SOURCE_B="$original_source_b"

    install -d -m 0700 "$SOURCE_A/target/reset-hardlink"
    ln "$sentinel" "$SOURCE_A/target/reset-hardlink/external-hardlink"
    source_identity="$(recorded_private_tree_identity "$SOURCE_A")" \
        || die "reset self-test cannot resolve snapshot identity"
    if offline_normalize_exact_tree "$SOURCE_A" "$source_identity" "external-hardlink rejection fixture"; then
        die "reset self-test accepted an inode linked outside the snapshot"
    fi
    [ "$(stat -c '%d:%i:%u:%g:%a' "$sentinel"):$(sha256sum "$sentinel" | awk '{print $1}')" = "$sentinel_proof" ] \
        || die "reset self-test changed an external hardlink target before rejection"
    rm -rf -- "$SOURCE_A/target"
    assert_snapshot_exact "$SOURCE_A" "external-hardlink rejection fixture"
    if ! (
        docker_local run --rm --pull=never --network=none --read-only --user 0:0 \
            --cap-drop=ALL --cap-add=CHOWN \
            --security-opt no-new-privileges \
            --mount "type=bind,src=$SOURCE_A,dst=/fixture,bind-recursive=disabled" \
            "$DEBIAN_IMAGE_ID" /bin/sh -ceu '
                /bin/chown --no-dereference 0:0 /fixture
                /bin/chown --no-dereference 0:0 /fixture/flutter
                /bin/mkdir -p /fixture/target/reset-proof/locked /fixture/flutter/.dart_tool/reset-proof/locked
                printf target > /fixture/target/reset-proof/locked/marker
                printf flutter > /fixture/flutter/.dart_tool/reset-proof/locked/marker
                printf internal > /fixture/target/reset-proof/internal-a
                /bin/ln /fixture/target/reset-proof/internal-a /fixture/target/reset-proof/internal-b
                /bin/ln -s "$1" /fixture/target/reset-proof/external-link
                /bin/chmod 0000 /fixture/target/reset-proof/locked /fixture/flutter/.dart_tool/reset-proof/locked
                /bin/chown --no-dereference "$2" /fixture/flutter
                /bin/chown --no-dereference "$2" /fixture
            ' _ "$sentinel" "$(id -u):$(id -g)"
    ); then
        die "reset self-test could not create root-owned hostile generated state"
    fi
    hostile_dir="$SOURCE_A/target/reset-proof/locked"
    /usr/bin/python3 - "$hostile_dir" "$SOURCE_A/flutter/.dart_tool/reset-proof/locked" <<'PY'
import os
import stat
import sys

for path in sys.argv[1:]:
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0:
        raise SystemExit("reset self-test did not create both root-owned mode-0000 directories")
PY
    git_closed -C "$SOURCE_A" check-ignore -q target/reset-proof/locked \
        || die "reset self-test target fixture is not ignored generated state"
    git_closed -C "$SOURCE_A" check-ignore -q flutter/.dart_tool/reset-proof/locked \
        || die "reset self-test Flutter fixture is not ignored generated state"
    if git_closed -C "$SOURCE_A" clean -ffdx >/dev/null 2>"$WORKSPACE/negative-clean.log"; then
        die "reset self-test negative control removed inaccessible root-owned state"
    fi
    [ -d "$hostile_dir" ] \
        || die "reset self-test negative control did not preserve the hostile directory"
    [ -d "$SOURCE_A/flutter/.dart_tool/reset-proof/locked" ] \
        || die "reset self-test negative control did not preserve the hostile Flutter directory"

    reset_snapshot_build_state "$SOURCE_A" "root-owned reset self-test"
    [ ! -e "$SOURCE_A/target/reset-proof" ] \
        || die "reset self-test retained target generated state"
    [ ! -e "$SOURCE_A/flutter/.dart_tool/reset-proof" ] \
        || die "reset self-test retained Flutter generated state"
    [ "$(stat -c '%d:%i:%u:%g:%a' "$sentinel"):$(sha256sum "$sentinel" | awk '{print $1}')" = "$sentinel_proof" ] \
        || die "reset self-test followed or changed the external symlink target"
    assert_snapshot_exact "$SOURCE_A" "root-owned reset self-test final proof"
    RELEASE_SUCCESS_MESSAGE="build-release root-owned reset self-test: OK"
}

run_cleanup_missing_self_test() {
    PINNED_HEAD="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "cleanup-missing self-test cannot resolve repository HEAD"
    PINNED_HEAD_SHORT="${PINNED_HEAD:0:12}"
    assert_release_source_state "cleanup-missing self-test"
    create_workspace
    RELEASE_SUCCESS_MESSAGE="build-release cleanup-missing self-test: INVALID SUCCESS"
    rm -rf -- "$WORKSPACE"
    printf 'build-release cleanup-missing self-test: REACHED\n' >&2
}

clear_final_publication_fixture_state() {
    [ "$FIXTURE_MODE" -eq 1 ] || die "publication fixture state cannot be cleared in a release transaction"
    [ -z "$FINAL_TRANSACTION" ] && [ -z "$FINAL_STAGE" ] \
        || die "publication fixture cannot clear a live transaction"
    clear_final_publication_state
}

forget_final_publication_fixture_state() {
    [ "$FIXTURE_MODE" -eq 1 ] || die "publication fixture state cannot be forgotten in a release transaction"
    FINAL_DESTINATION=""
    FINAL_PARENT_ID=""
    FINAL_TRANSACTION=""
    FINAL_TRANSACTION_ID=""
    FINAL_STAGE=""
    FINAL_STAGE_ID=""
    FINAL_OLD_ID=""
    FINAL_DEST_HAD_OLD=0
    FINAL_PUBLICATION_STATE=idle
}

stage_publication_fixture() {
    local source="$1" destination="$2" parent base name manifest_hash
    parent="$(dirname "$destination")"
    base="$(basename "$destination")"
    FINAL_DESTINATION="$destination"
    FINAL_PARENT_ID="$(assert_single_writer_publication_parent "$parent")" \
        || die "publication fixture parent is not single-writer"
    if [ -d "$destination" ] && [ ! -L "$destination" ]; then
        FINAL_DEST_HAD_OLD=1
        FINAL_OLD_ID="$(stat -c '%d:%i' "$destination")"
    else
        FINAL_DEST_HAD_OLD=0
        FINAL_OLD_ID=""
    fi
    FINAL_PUBLICATION_STATE=transaction-initializing
    FINAL_TRANSACTION="$(mktemp -d "$parent/.$base-release-transaction.XXXXXXXXXX")"
    FINAL_TRANSACTION_ID="$(stat -c '%d:%i' "$FINAL_TRANSACTION")"
    FINAL_STAGE="$FINAL_TRANSACTION/payload"
    install -d -m 0700 "$FINAL_STAGE"
    FINAL_STAGE_ID="$(stat -c '%d:%i' "$FINAL_STAGE")"
    FINAL_PUBLICATION_STATE=staging
    for name in "${CANONICAL_ASSETS[@]}" SHA256SUMS; do
        install -m 0444 "$source/$name" "$FINAL_STAGE/$name"
    done
    strict_manifest_proof "$FINAL_STAGE"
    sync_staged_publication_payload \
        || die "publication fixture payload durability proof failed"
    manifest_hash="$(sha256sum "$FINAL_STAGE/SHA256SUMS" | awk '{print $1}')"
    write_publication_record "$manifest_hash"
    read_publication_record "$FINAL_TRANSACTION" "$base" "$FINAL_PARENT_ID" >/dev/null \
        || die "publication fixture record failed its durable proof"
    FINAL_PUBLICATION_STATE=exchange-pending
}

run_publication_reconciliation_self_test() {
    local source="$1" parent destination prior_id staged_id transaction transaction_id
    local stale_worktree stale_status original_source_b
    [ "$FIXTURE_MODE" -eq 1 ] || die "publication reconciliation fixture requires fixture mode"
    parent="$WORKSPACE/publication-reconciliation"
    install -d -m 0700 "$parent"

    destination="$parent/first-publication"
    atomic_install_dist "$source" "$destination"
    prove_published_dist "$destination" \
        || die "first-publication fixture did not install the exact set"
    recover_pending_publications "$parent" "$destination" \
        || die "first-publication terminal state was not idempotent"
    clear_final_publication_fixture_state

    destination="$parent/no-clobber"
    stage_publication_fixture "$source" "$destination"
    transaction="$FINAL_TRANSACTION"
    if atomic_exchange_or_install "$FINAL_STAGE" "$destination" "$FINAL_STAGE_ID" - \
        "$FINAL_PARENT_ID" "$FINAL_TRANSACTION_ID" create-destination-after-check \
        >/dev/null 2>&1; then
        die "no-clobber fixture replaced a destination that appeared after the absence check"
    fi
    [ "$(path_identity "$FINAL_STAGE")" = "$FINAL_STAGE_ID" ] \
        && [ -d "$destination" ] && [ ! -L "$destination" ] \
        || die "no-clobber fixture did not preserve both namespace entries"
    rmdir "$destination" || die "no-clobber fixture destination is not the injected empty directory"
    forget_final_publication_fixture_state
    recover_pending_publications "$parent" "$destination" \
        || die "no-clobber fixture could not roll back after the conflict disappeared"
    [ "$(path_identity "$destination")" = absent ] \
        && [ "$(path_identity "$transaction")" = absent ] \
        || die "no-clobber fixture did not recover to the absent prior state"
    clear_final_publication_fixture_state

    destination="$parent/incomplete"
    install -d -m 0700 "$destination"
    printf 'prior\n' > "$destination/prior"
    prior_id="$(stat -c '%d:%i' "$destination")"
    FINAL_DESTINATION="$destination"
    FINAL_PARENT_ID="$(assert_single_writer_publication_parent "$parent")"
    FINAL_PUBLICATION_STATE=transaction-initializing
    FINAL_TRANSACTION="$(mktemp -d "$parent/.incomplete-release-transaction.XXXXXXXXXX")"
    install -d -m 0700 "$FINAL_TRANSACTION/payload"
    forget_final_publication_fixture_state
    recover_pending_publications "$parent" "$destination" \
        || die "incomplete transaction restart fixture could not recover"
    [ "$(path_identity "$destination")" = "$prior_id" ] \
        && [ -f "$destination/prior" ] \
        || die "incomplete transaction restart fixture changed the prior destination"
    clear_final_publication_fixture_state

    destination="$parent/before-exchange"
    install -d -m 0700 "$destination"
    printf 'prior\n' > "$destination/prior"
    prior_id="$(stat -c '%d:%i' "$destination")"
    stage_publication_fixture "$source" "$destination"
    transaction="$FINAL_TRANSACTION"
    forget_final_publication_fixture_state
    recover_pending_publications "$parent" "$destination" \
        || die "pre-exchange restart fixture could not recover"
    [ "$(path_identity "$destination")" = "$prior_id" ] \
        && [ -f "$destination/prior" ] && [ "$(path_identity "$transaction")" = absent ] \
        || die "pre-exchange restart fixture changed the prior destination"
    clear_final_publication_fixture_state

    destination="$parent/after-exchange"
    install -d -m 0700 "$destination"
    printf 'prior\n' > "$destination/prior"
    stage_publication_fixture "$source" "$destination"
    staged_id="$FINAL_STAGE_ID"
    transaction="$FINAL_TRANSACTION"
    atomic_exchange_or_install "$FINAL_STAGE" "$destination" "$FINAL_STAGE_ID" "$FINAL_OLD_ID" \
        "$FINAL_PARENT_ID" "$FINAL_TRANSACTION_ID" \
        || die "post-exchange interruption fixture could not perform the exchange"
    forget_final_publication_fixture_state
    recover_pending_publications "$parent" "$destination" \
        || die "post-exchange restart fixture could not recover"
    [ "$(path_identity "$destination")" = "$staged_id" ] \
        && [ "$(path_identity "$transaction")" = absent ] \
        || die "post-exchange restart fixture did not commit the published set"
    prove_published_dist "$destination" \
        || die "post-exchange restart fixture did not preserve the published set"
    clear_final_publication_fixture_state
    recover_pending_publications "$parent" "$destination" \
        || die "post-exchange terminal recovery was not idempotent"
    clear_final_publication_fixture_state

    destination="$parent/discard-restart"
    install -d -m 0700 "$destination"
    printf 'prior\n' > "$destination/prior"
    prior_id="$(stat -c '%d:%i' "$destination")"
    stage_publication_fixture "$source" "$destination"
    transaction_id="$FINAL_TRANSACTION_ID"
    commit_registered_final_transaction_discard "$transaction_id" \
        || die "discard restart fixture could not commit terminal state"
    transaction="$FINAL_TRANSACTION"
    forget_final_publication_fixture_state
    recover_pending_publications "$parent" "$destination" \
        || die "discard restart fixture could not recover"
    [ "$(path_identity "$destination")" = "$prior_id" ] \
        && [ -f "$destination/prior" ] && [ "$(path_identity "$transaction")" = absent ] \
        || die "discard restart fixture did not remove terminal state"
    clear_final_publication_fixture_state

    destination="$parent/discard-removal-gap"
    install -d -m 0700 "$destination"
    printf 'prior\n' > "$destination/prior"
    prior_id="$(stat -c '%d:%i' "$destination")"
    (
        local stop_status=0
        stage_publication_fixture "$source" "$destination"
        commit_registered_final_transaction_discard "$FINAL_TRANSACTION_ID" \
            || die "discard-removal gap fixture could not commit terminal state"
        PUBLICATION_FIXTURE_STOP_AFTER_DISCARD_REMOVAL=1
        remove_registered_final_transaction "$FINAL_TRANSACTION_ID" || stop_status=$?
        [ "$stop_status" -eq 75 ] \
            || die "discard-removal gap fixture did not stop before parent synchronization"
    )
    forget_final_publication_fixture_state
    recover_pending_publications "$parent" "$destination" \
        || die "discard-removal gap restart could not synchronize the observed absence"
    [ "$(path_identity "$destination")" = "$prior_id" ] && [ -f "$destination/prior" ] \
        || die "discard-removal gap restart changed the prior destination"
    clear_final_publication_fixture_state

    destination="$parent/stale-worktree-and-publication"
    install -d -m 0700 "$destination"
    printf 'prior\n' > "$destination/prior"
    stage_publication_fixture "$source" "$destination"
    staged_id="$FINAL_STAGE_ID"
    atomic_exchange_or_install "$FINAL_STAGE" "$destination" "$FINAL_STAGE_ID" "$FINAL_OLD_ID" \
        "$FINAL_PARENT_ID" "$FINAL_TRANSACTION_ID" \
        || die "combined restart fixture could not perform the exchange"
    stale_worktree="$WORKSPACE/interrupted-release-worktree"
    original_source_b="$SOURCE_B"
    SOURCE_B="$stale_worktree"
    git_closed -C "$REPO_ROOT" worktree add --quiet --detach "$stale_worktree" HEAD \
        || die "combined restart fixture could not create a stale registered worktree"
    forget_final_publication_fixture_state
    recover_pending_publications "$parent" "$destination" \
        || die "combined restart fixture did not reconcile publication before stale-worktree refusal"
    [ "$(path_identity "$destination")" = "$staged_id" ] \
        || die "combined restart fixture did not commit the record-bound destination"
    stale_status=0
    assert_no_stale_release_worktrees >/dev/null 2>&1 || stale_status=$?
    [ "$stale_status" -ne 0 ] \
        || die "combined restart fixture did not reject the stale release worktree"
    remove_snapshot_worktree_if_registered "$stale_worktree" "snapshot B" \
        || die "combined restart fixture could not remove the stale registered worktree"
    SOURCE_B="$original_source_b"
    assert_no_stale_release_worktrees \
        || die "combined restart fixture retained the stale registered worktree"
    clear_final_publication_fixture_state
}

run_self_test() {
    local fixture_bin final_fixture expected_lines query_status
    FIXTURE_MODE=1
    PINNED_HEAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    PINNED_HEAD_SHORT=aaaaaaaaaaaa
    FORK_VER=1.4.7-hardened.6
    query_git_worktree_registry self-test \
        || die "release self-test rejected the Git worktree registry parser fixtures"
    query_status=0
    query_git_worktree_registry self-test-unexpected >/dev/null 2>&1 || query_status=$?
    [ "$query_status" -eq 2 ] \
        || die "release self-test misclassified an unexpected registry exception"
    query_status=0
    query_git_worktree_registry self-test-unexpected-after-spawn >/dev/null 2>&1 \
        || query_status=$?
    [ "$query_status" -eq 2 ] \
        || die "release self-test retained a producer after an unexpected registry exception"
    create_workspace
    fixture_bin="$WORKSPACE/bin"
    install -d -m 0700 "$fixture_bin"
    FIXTURE_LOG="$WORKSPACE/invocations.log"
    : > "$FIXTURE_LOG"
    {
        printf '#!/usr/bin/env bash\n'
        printf '[ "$1" = fixture-probe ]\n'
    } > "$fixture_bin/docker"
    chmod 0700 "$fixture_bin/docker"
    printf '{}\n' > "$DOCKER_CONFIG_DIR/config.json"
    CHILD_PATH="$fixture_bin:$SAFE_PATH"
    ONLINE_SNAPSHOT_PARENT="$WORKSPACE/online-input"
    HOST_KEYSTORE="$WORKSPACE/key.jks"
    HOST_KEYSTORE_PASS_FILE="$WORKSPACE/pass"
    HOST_GOLDEN="$WORKSPACE/golden.qcow2"
    DEBIAN_IMAGE_ID="sha256:$(printf '1%.0s' {1..64})"
    ANDROID_IMAGE_ID="sha256:$(printf '2%.0s' {1..64})"
    WINDOWS_IMAGE_ID="sha256:$(printf '3%.0s' {1..64})"
    SOURCE_A="$WORKSPACE/pass-A/source"
    SOURCE_B="$WORKSPACE/pass-B/source"
    OUTPUT_A="$WORKSPACE/pass-A/outputs"
    OUTPUT_B="$WORKSPACE/pass-B/outputs"
    SET_A="$WORKSPACE/pass-A/release-set"
    SET_B="$WORKSPACE/pass-B/release-set"
    install -d -m 0700 "$SOURCE_A" "$SOURCE_B" "$OUTPUT_A" "$OUTPUT_B" "$SET_A" "$SET_B" \
        "$ONLINE_SNAPSHOT_PARENT" "$ONLINE_SNAPSHOT_PARENT/online"
    printf 'fixture-online-input\n' > "$ONLINE_SNAPSHOT_PARENT/online/fixture-input"
    chmod 0400 "$ONLINE_SNAPSHOT_PARENT/online/fixture-input"
    chmod 0500 "$ONLINE_SNAPSHOT_PARENT/online"
    FIXTURE_ONLINE_DIGEST="$(sha256sum "$ONLINE_SNAPSHOT_PARENT/online/fixture-input" | awk '{print $1}')"
    assert_release_online_snapshot "fixture setup"
    write_fixture_target "$SOURCE_A" debian 'printf debian > "$OUT_DIR/rustdesk-x86_64.deb"'
    write_fixture_target "$SOURCE_A" android 'printf android > "$OUT_DIR/rustdesk-arm64.apk"'
    write_fixture_target "$SOURCE_A" windows 'printf windows-exe > "$OUT_DIR/rustdesk-setup.exe"; printf windows-msi > "$OUT_DIR/rustdesk.msi"'
    cp -a "$SOURCE_A/scripts/." "$SOURCE_B/scripts/"
    export POISON_MARKER=present BASH_ENV=/does/not/exist GIT_CONFIG=/does/not/exist DOCKER_CONTEXT=hostile
    build_snapshot A "$SOURCE_A" "$OUTPUT_A" "$SET_A"
    build_snapshot B "$SOURCE_B" "$OUTPUT_B" "$SET_B"
    unset POISON_MARKER BASH_ENV GIT_CONFIG DOCKER_CONTEXT
    expected_lines=6
    [ "$(wc -l < "$FIXTURE_LOG")" -eq "$expected_lines" ] \
        || die "release self-test did not execute exactly six target commands"
    [ "$(awk -F'|' '{print $2}' "$FIXTURE_LOG" | sort -u | wc -l)" -eq 2 ] \
        || die "release self-test did not use two independent snapshots"
    [ "$(awk -F'|' '{print $3}' "$FIXTURE_LOG" | sort -u | wc -l)" -eq 6 ] \
        || die "release self-test target outputs are not distinct"
    [ "$(awk -F'|' '{print $4}' "$FIXTURE_LOG" | sort -u | wc -l)" -eq 1 ] \
        || die "release self-test did not give every target the same online snapshot"
    [ "$(awk -F'|' 'NR == 1 { print $4 }' "$FIXTURE_LOG")" = "$ONLINE_SNAPSHOT_PARENT/online" ] \
        || die "release self-test target online path is not the transaction snapshot"
    if (
        run_snapshot_consumer "mutation fixture" /usr/bin/bash --noprofile --norc -c \
            'chmod 0600 "$1/fixture-input"; printf mutated > "$1/fixture-input"' \
            _ "$ONLINE_SNAPSHOT_PARENT/online"
    ) >/dev/null 2>&1; then
        die "release self-test accepted an online snapshot mutation by a consumer"
    fi
    chmod 0600 "$ONLINE_SNAPSHOT_PARENT/online/fixture-input"
    printf 'fixture-online-input\n' > "$ONLINE_SNAPSHOT_PARENT/online/fixture-input"
    chmod 0400 "$ONLINE_SNAPSHOT_PARENT/online/fixture-input"
    assert_release_online_snapshot "fixture mutation recovery"
    compare_snapshots
    cp -a "$SET_A/." "$WORKSPACE/release-final"
    SET_A="$WORKSPACE/release-final"
    write_manifest "$SET_A"
    FINAL_OUT_DIR_FIXTURE="$WORKSPACE/final-dist"
    for name in "${CANONICAL_ASSETS[@]}" SHA256SUMS; do
        [ -f "$SET_A/$name" ] || die "release self-test manifest omitted $name"
    done
    strict_manifest_proof "$SET_A"
    assert_single_writer_publication_parent "$REPO_ROOT" >/dev/null \
        || die "release self-test rejected the canonical dist parent"
    run_publication_reconciliation_self_test "$SET_A"
    install -d -m 0700 "$FINAL_OUT_DIR_FIXTURE"
    printf stale > "$FINAL_OUT_DIR_FIXTURE/noncanonical-old-file"
    atomic_install_dist "$SET_A" "$FINAL_OUT_DIR_FIXTURE"
    strict_manifest_proof "$FINAL_OUT_DIR_FIXTURE"
    RELEASE_SUCCESS_MESSAGE="build-release self-test: OK"
}

main() {
    if [ "$SELF_TEST" -eq 1 ]; then
        run_self_test
        return 0
    fi
    if [ "$SELF_TEST_RESET" -eq 1 ]; then
        run_reset_self_test
        return 0
    fi
    if [ "$SELF_TEST_CLEANUP_MISSING" -eq 1 ]; then
        run_cleanup_missing_self_test
        return 0
    fi
    PINNED_HEAD="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "cannot resolve repository HEAD"
    PINNED_HEAD_SHORT="${PINNED_HEAD:0:12}"
    export SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN"
    create_workspace
    release_preflight
    if [ "$DOCTOR" -eq 1 ]; then
        RELEASE_SUCCESS_MESSAGE="DOCTOR OK: clean local master equals live origin/master"
        return 0
    fi
    prepare_release_snapshots
    build_snapshot A "$SOURCE_A" "$OUTPUT_A" "$SET_A"
    build_snapshot B "$SOURCE_B" "$OUTPUT_B" "$SET_B"
    run_snapshot_consumer "final APK certificate proof" run_child \
        RUSTDESK_RELEASE_ONLINE_SNAPSHOT="$ONLINE_SNAPSHOT_PARENT" \
        RELEASE_SRC_COMMIT="$PINNED_HEAD" RELEASE_DOCKER_IMAGE_ID="$ANDROID_IMAGE_ID" \
        /usr/bin/bash --noprofile --norc "$SOURCE_A/scripts/build-android.sh" \
        --verify-apk "$SET_A/rustdesk-arm64.apk" \
        || die "final APK certificate proof failed"
    reset_snapshot_build_state "$SOURCE_A" "after final APK certificate proof"
    compare_snapshots
    write_manifest "$SET_A"
    strict_manifest_proof "$SET_A"
    assert_snapshot_exact "$SOURCE_B" "before final dist installation"
    assert_release_source_state "before final dist installation"
    assert_origin_identity
    assert_live_origin_master "before final dist installation"
    assert_release_online_snapshot "before final dist installation"
    atomic_install_dist "$SET_A"
    RELEASE_SUCCESS_MESSAGE="RELEASE OK: four artifacts match across independent snapshots at $PINNED_HEAD_SHORT"
}

main
