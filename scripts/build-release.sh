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
SELF_TEST_SOURCE_STATE=0
EXPECTED_SOURCE_COMMIT=""
for argument in "$@"; do
    case "$argument" in
        --doctor) DOCTOR=1 ;;
        --self-test) SELF_TEST=1 ;;
        --self-test-reset) SELF_TEST_RESET=1 ;;
        --self-test-cleanup-missing) SELF_TEST_CLEANUP_MISSING=1 ;;
        --self-test-source-state=*)
            SELF_TEST_SOURCE_STATE=1
            EXPECTED_SOURCE_COMMIT="${argument#*=}"
            ;;
        -h|--help) printf 'usage: %s [--doctor|--self-test|--self-test-reset|--self-test-cleanup-missing|--self-test-source-state=COMMIT]\n' "${0##*/}"; exit 0 ;;
        *) die "unknown argument '$argument'" ;;
    esac
done
[ "$((DOCTOR + SELF_TEST + SELF_TEST_RESET + SELF_TEST_CLEANUP_MISSING + SELF_TEST_SOURCE_STATE))" -le 1 ] \
    || die "build-release operating modes are mutually exclusive"
if [ "$SELF_TEST_SOURCE_STATE" -eq 1 ]; then
    [[ "$EXPECTED_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || die "--self-test-source-state requires an exact lowercase 40-hex commit"
elif [ -n "$EXPECTED_SOURCE_COMMIT" ]; then
    die "source-state commit was supplied outside source-state mode"
fi

readonly FINAL_OUT_DIR="$REPO_ROOT/dist"
readonly DOCKER_HOST_URI=unix:///var/run/docker.sock
readonly PRIVATE_TREE_CLOSURE_SOURCE="$SCRIPT_DIR/verify-private-tree-closure.py"
readonly FINALIZE_RELEASE_SET_SOURCE="$SCRIPT_DIR/finalize-release-set.py"
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
FINALIZE_RELEASE_SET_PROBE=""
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
PUBLICATION_LOCK_FD=""
FINAL_PUBLICATION_RECONCILIATION=0
RELEASE_SUCCESS_MESSAGE=""
CHILD_PATH="$SAFE_PATH"

git_closed() {
    command git --no-replace-objects -c core.hooksPath=/dev/null "$@"
}

assert_git_object_authority() {
    local repository="${1:-$REPO_ROOT}" common_dir grafts alternates shallow replacements
    common_dir="$(git_closed -C "$repository" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
        || die "cannot resolve repository common Git directory"
    grafts="$common_dir/info/grafts"
    alternates="$common_dir/objects/info/alternates"
    shallow="$common_dir/shallow"
    [ ! -e "$grafts" ] && [ ! -L "$grafts" ] || die "Git grafts are forbidden for release builds"
    [ ! -e "$alternates" ] && [ ! -L "$alternates" ] || die "Git object alternates are forbidden for release builds"
    [ ! -e "$shallow" ] && [ ! -L "$shallow" ] || die "shallow Git history is forbidden for release builds"
    [ "$(git_closed -C "$repository" rev-parse --is-shallow-repository 2>/dev/null)" = false ] \
        || die "release Git authority is shallow or cannot prove complete history"
    replacements="$(git_closed -C "$repository" for-each-ref --format='%(refname)' refs/replace 2>/dev/null)" \
        || die "cannot inspect Git replacement refs"
    [ -z "$replacements" ] || die "Git replacement refs are forbidden for release builds"
}

assert_exact_checkout_state() {
    local phase="$1" current dirt sparse index_flags
    current="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "$phase: cannot resolve HEAD"
    [ "$current" = "$PINNED_HEAD" ] || die "$phase: HEAD changed"
    assert_git_object_authority
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

assert_release_source_state() {
    local phase="$1" branch
    branch="$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet --short HEAD 2>/dev/null)" \
        || die "$phase: release checkout is detached"
    [ "$branch" = master ] || die "$phase: release branch must be master"
    assert_exact_checkout_state "$phase"
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
    local source_hash private_hash commit_hash publisher_source_hash publisher_private_hash
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
    FINALIZE_RELEASE_SET_PROBE="$WORKSPACE/finalize-release-set.py"
    [ -f "$FINALIZE_RELEASE_SET_SOURCE" ] && [ ! -L "$FINALIZE_RELEASE_SET_SOURCE" ] \
        || die "final release publisher source is not a regular file"
    install -m 0500 "$FINALIZE_RELEASE_SET_SOURCE" "$FINALIZE_RELEASE_SET_PROBE"
    publisher_source_hash="$(sha256sum "$FINALIZE_RELEASE_SET_SOURCE" | awk '{print $1}')"
    publisher_private_hash="$(sha256sum "$FINALIZE_RELEASE_SET_PROBE" | awk '{print $1}')"
    [ "$publisher_private_hash" = "$publisher_source_hash" ] \
        || die "final release publisher copy differs from its source"
    if [ "$SELF_TEST" -eq 0 ]; then
        commit_hash="$(git_closed -C "$REPO_ROOT" show \
            "$PINNED_HEAD:scripts/finalize-release-set.py" | sha256sum | awk '{print $1}')" \
            || die "cannot read final release publisher from the pinned commit"
        [ "$publisher_private_hash" = "$commit_hash" ] \
            || die "final release publisher differs from the pinned commit"
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
    local path="$1" expected_identity="$2" role="$3" resolved observed uid gid
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
            --cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=CHOWN \
            --security-opt no-new-privileges \
            --ulimit nofile=131328:131328 \
            --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled" \
            --mount "type=bind,src=$PRIVATE_TREE_CLOSURE_PROBE,dst=/probe.py,readonly" \
            "$DEBIAN_IMAGE_ID" /usr/bin/python3 -I -S /probe.py \
            --normalize-root /cleanup --expected-identity "$expected_identity" \
            --owner "$uid" --group "$gid"
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
    [ "$(stat -c '%d:%i:%u:%g:%a' "$source")" = \
      "$expected:$(id -u):$(id -g):700" ] \
        || die "$phase: snapshot root identity/owner/mode differs after normalization"
}

normalize_workspace_access() {
    offline_normalize_exact_tree "$WORKSPACE" "$WORKSPACE_ID" "release workspace" \
        || return 1
    [ "$(stat -c '%d:%i:%u:%g:%a' "$WORKSPACE")" = \
      "$WORKSPACE_ID:$(id -u):$(id -g):700" ]
}

cleanup_release_workspace() {
    local status=$? cleanup_failed=0 workspace_state=none
    trap - EXIT
    trap '' HUP INT TERM
    if [ "$WINDOWS_UNSAFE" -eq 1 ] || [ "$KEEP_WORKSPACE" -eq 1 ]; then
        printf 'build-release: preserving private workspace for Windows reconciliation: %s\n' "$WORKSPACE" >&2
        exit "$status"
    fi
    if [ "$FINAL_PUBLICATION_RECONCILIATION" -eq 1 ]; then
        reconcile_final_publication || cleanup_failed=1
    fi
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
        if [ "$FIXTURE_MODE" -eq 0 ] && [ -n "$DEBIAN_IMAGE_ID" ] \
            && [ "$workspace_state" = valid ] && [ "$cleanup_failed" -eq 0 ]; then
            normalize_workspace_access || cleanup_failed=1
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
            if ! /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" \
                --remove-scratch-root "$WORKSPACE" --expected-identity "$WORKSPACE_ID"; then
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
    FINAL_PUBLICATION_RECONCILIATION=1
    recover_pending_publications "$REPO_ROOT" "$FINAL_OUT_DIR" \
        || die "release preflight cannot reconcile a prior publication transaction"
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
    local source="$1" phase="$2" current dirt ignored expected common remotes sparse index_flags
    expected="$(recorded_private_tree_identity "$source")" \
        || die "$phase: snapshot identity is unavailable"
    [ "$(stat -c '%d:%i:%u:%g:%a' "$source" 2>/dev/null)" = \
      "$expected:$(id -u):$(id -g):700" ] \
        || die "$phase: snapshot root identity/owner/mode differs"
    current="$(git_closed -C "$source" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "$phase: cannot resolve snapshot HEAD"
    [ "$current" = "$PINNED_HEAD" ] || die "$phase: snapshot commit changed"
    common="$(git_closed -C "$source" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
        || die "$phase: cannot resolve snapshot Git directory"
    [ "$common" = "$source/.git" ] && [ -d "$common" ] && [ ! -L "$common" ] \
        || die "$phase: snapshot Git authority is not private"
    assert_git_object_authority "$source"
    remotes="$(git_closed -C "$source" remote 2>/dev/null)" \
        || die "$phase: cannot inspect snapshot remotes"
    [ -z "$remotes" ] || die "$phase: snapshot retains a remote"
    sparse="$(git_closed -C "$source" config --local --no-includes --bool core.sparseCheckout 2>/dev/null || true)"
    [ "$sparse" != true ] || die "$phase: sparse snapshot checkout is forbidden"
    index_flags="$(git_closed -C "$source" ls-files -v 2>/dev/null)" \
        || die "$phase: cannot inspect snapshot index flags"
    if printf '%s\n' "$index_flags" | awk 'substr($0,1,1) != "H" { found=1 } END { exit found ? 0 : 1 }'; then
        die "$phase: snapshot has assume-unchanged, skip-worktree, or noncanonical index flags"
    fi
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
    local label="$1" source="$2" output="$3" set_dir="$4" common identity
    case "$label" in
        A|B) ;;
        *) die "unknown release snapshot label: $label" ;;
    esac
    install -d -m 0700 "$(dirname "$source")" "$output" "$set_dir"
    git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$source" \
        || die "cannot create private release snapshot $label repository"
    git_closed -C "$source" checkout --quiet --detach "$PINNED_HEAD" \
        || die "cannot check out release snapshot $label at the pinned commit"
    git_closed -C "$source" remote remove origin \
        || die "cannot detach release snapshot $label from its source repository"
    [ -z "$(git_closed -C "$source" remote 2>/dev/null)" ] \
        || die "release snapshot $label retains a remote"
    common="$(git_closed -C "$source" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
        || die "cannot resolve release snapshot $label Git directory"
    [ "$common" = "$source/.git" ] && [ -d "$common" ] && [ ! -L "$common" ] \
        || die "release snapshot $label does not own a private Git directory"
    assert_git_object_authority "$source"
    git_closed -C "$source" fsck --full --strict --no-reflogs >/dev/null \
        || die "release snapshot $label private object database is invalid"
    chmod 0700 "$source" \
        || die "cannot set release snapshot $label root mode"
    [ "$(stat -c '%u:%a' "$source")" = "$(id -u):700" ] \
        || die "release snapshot $label is not current-UID mode 0700"
    identity="$(stat -c '%d:%i' -- "$source")" \
        || die "cannot record release snapshot $label identity"
    case "$label" in
        A) SOURCE_A_ID="$identity" ;;
        B) SOURCE_B_ID="$identity" ;;
    esac
    /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$source" \
        || die "release snapshot $label crosses a mount boundary"
    /usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE" --inode-root "$source" \
        || die "release snapshot $label contains an inode linked outside its private repository"
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
entries = []
with os.scandir(directory) as inventory:
    for entry in inventory:
        if len(entries) >= len(expected) + 1:
            raise SystemExit(f"release set has too many entries: {directory}")
        entries.append(entry)
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

publication_tool() {
    /usr/bin/python3 -I -S "$FINALIZE_RELEASE_SET_PROBE" "$@"
}

prove_published_dist() {
    local destination="$1"
    publication_tool --verify --path "$destination" \
        --commit "$PINNED_HEAD" --version "$FORK_VER" --epoch "$SOURCE_DATE_EPOCH_PIN"
}

recover_pending_publications() {
    local parent="$1" destination="$2" base
    [ "$(dirname "$destination")" = "$parent" ] \
        || { warn "publication destination escaped its parent"; return 1; }
    base="$(basename "$destination")"
    publication_tool --recover --parent "$parent" --destination "$base"
}

reconcile_final_publication() {
    [ -n "$FINALIZE_RELEASE_SET_PROBE" ] || return 0
    [ -f "$FINALIZE_RELEASE_SET_PROBE" ] && [ ! -L "$FINALIZE_RELEASE_SET_PROBE" ] \
        || { warn "final release publisher authority is unavailable"; return 1; }
    recover_pending_publications "$REPO_ROOT" "$FINAL_OUT_DIR"
}

atomic_install_dist() {
    local source="$1" destination="${2:-$FINAL_OUT_DIR}" parent base
    parent="$(dirname "$destination")"
    base="$(basename "$destination")"
    publication_tool --publish --parent "$parent" --destination "$base" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN"
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

run_reset_self_test() {
    local fixture_repo sentinel sentinel_proof hostile_dir source_identity
    require_cmd git docker python3 sha256sum stat readlink find chmod
    PINNED_HEAD="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "reset self-test cannot resolve repository HEAD"
    PINNED_HEAD_SHORT="${PINNED_HEAD:0:12}"
    assert_exact_checkout_state "reset self-test"
    create_workspace
    fixture_repo="$WORKSPACE/fixture-repository"
    git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$fixture_repo" \
        || die "reset self-test cannot clone its private Git authority"
    REPO_ROOT="$fixture_repo"
    [ "$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" = "$PINNED_HEAD" ] \
        || die "reset self-test private Git authority is not at the exact source commit"
    assert_git_object_authority
    DEBIAN_IMAGE_ID="${DEB_BUILDER_IMAGE_ID:-}"
    [ -n "$DEBIAN_IMAGE_ID" ] || die "reset self-test has no pinned Debian image ID"
    docker_local version >/dev/null || die "reset self-test cannot reach the local Docker daemon"
    verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"
    SOURCE_A="$WORKSPACE/pass-A/source"
    OUTPUT_A="$WORKSPACE/pass-A/outputs"
    SET_A="$WORKSPACE/pass-A/release-set"
    create_snapshot A "$SOURCE_A" "$OUTPUT_A" "$SET_A"

    sentinel="$WORKSPACE/external-sentinel"
    printf 'outside-generated-tree\n' > "$sentinel"
    sentinel_proof="$(stat -c '%d:%i:%u:%g:%a' "$sentinel"):$(sha256sum "$sentinel" | awk '{print $1}')"

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
                printf special > /fixture/target/reset-proof/special-mode
                /bin/chmod 6755 /fixture/target/reset-proof/special-mode
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

    offline_normalize_exact_tree "$SOURCE_A" "$source_identity" \
        "retained-authority normalization transition fixture" \
        || die "reset self-test could not normalize hostile generated state"
    /usr/bin/python3 - "$SOURCE_A" "$hostile_dir" \
        "$SOURCE_A/flutter/.dart_tool/reset-proof/locked" \
        "$SOURCE_A/target/reset-proof/special-mode" "$(id -u)" "$(id -g)" <<'PY'
import os
import stat
import sys

root, target_directory, flutter_directory, special, owner, group = sys.argv[1:]
owner = int(owner)
group = int(group)
for path, mode in (
    (root, 0o700),
    (target_directory, 0o700),
    (flutter_directory, 0o700),
    (special, 0o755),
):
    metadata = os.lstat(path)
    if (
        metadata.st_uid != owner
        or metadata.st_gid != group
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise SystemExit("reset self-test retained-authority normalization differs")
PY
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
    assert_exact_checkout_state "cleanup-missing self-test"
    create_workspace
    RELEASE_SUCCESS_MESSAGE="build-release cleanup-missing self-test: INVALID SUCCESS"
    rm -rf -- "$WORKSPACE"
    printf 'build-release cleanup-missing self-test: REACHED\n' >&2
}

run_source_state_self_test() {
    PINNED_HEAD="$EXPECTED_SOURCE_COMMIT"
    PINNED_HEAD_SHORT="${PINNED_HEAD:0:12}"
    assert_exact_checkout_state "source-state self-test"
    log "build-release source-state self-test: OK"
}

run_publication_reconciliation_self_test() {
    local source="$1" parent destination point status base transaction payload prior_id
    local held substitute preserved reserved token writable writable_proof
    local category malformed output
    [ "$FIXTURE_MODE" -eq 1 ] || die "publication reconciliation fixture requires fixture mode"
    writable="$WORKSPACE/publication-writable-parent"
    install -d -m 0770 "$writable"
    writable_proof="$(stat -c '%d:%i:%u:%g:%a:%Y:%Z' "$writable")"
    if publication_tool --recover --parent "$writable" --destination rejected \
        >/dev/null 2>&1; then
        die "publication accepted a group-writable parent"
    fi
    [ "$(stat -c '%d:%i:%u:%g:%a:%Y:%Z' "$writable")" = "$writable_proof" ] \
        && [ -z "$(find "$writable" -mindepth 1 -maxdepth 1 -print -quit)" ] \
        || die "publication changed a rejected group-writable parent"
    rmdir "$writable"
    parent="$WORKSPACE/publication-reconciliation"
    install -d -m 0700 "$parent"

    destination="$parent/first-publication"
    atomic_install_dist "$source" "$destination"
    prove_published_dist "$destination" \
        || die "first-publication fixture did not install the exact set"

    destination="$parent/unbound-initial-payload"
    atomic_install_dist "$source" "$destination"
    prior_id="$(stat -c '%d:%i' "$destination")"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after payload-created \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "unbound-payload fixture did not stop after creation"
    base="$(basename "$destination")"
    payload="$(find "$parent" -maxdepth 1 -type d -name ".$base-release-payload.*" -print -quit)"
    transaction="$(find "$parent" -maxdepth 1 -type f -name ".$base-release-transaction.*" -print -quit)"
    [ -n "$payload" ] && [ -n "$transaction" ] \
        || die "unbound-payload fixture did not preserve both identities"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery deleted an unbound initializing payload"
    fi
    [ -d "$payload" ] && [ -f "$transaction" ] \
        && [ "$(stat -c '%d:%i' "$destination")" = "$prior_id" ] \
        || die "unbound-payload rejection changed recorded state"
    rmdir "$payload"
    recover_pending_publications "$parent" "$destination" \
        || die "unbound-payload fixture could not reconcile after exact removal"

    destination="$parent/no-clobber-race"
    substitute="$parent/no-clobber-race-substitute"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after prepared \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "no-clobber race fixture did not stop at prepared"
    atomic_install_dist "$source" "$substitute"
    mv -- "$substitute" "$destination"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted a raced first destination"
    fi
    base="$(basename "$destination")"
    transaction="$(find "$parent" -maxdepth 1 -type f -name ".$base-release-transaction.*" -print -quit)"
    payload="$(find "$parent" -maxdepth 1 -type d -name ".$base-release-payload.*" -print -quit)"
    [ -n "$transaction" ] && [ -n "$payload" ] && [ -d "$destination" ] \
        || die "no-clobber race rejection changed ambiguous state"
    mv -- "$destination" "$substitute"
    recover_pending_publications "$parent" "$destination" \
        || die "no-clobber race fixture could not roll back after exact restoration"
    prove_published_dist "$substitute" \
        || die "no-clobber race fixture changed the substitute release"

    for point in staging prepared rollback-record exchange cleanup-record payload-removal; do
        destination="$parent/first-restart-$point"
        status=0
        publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
            --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
            --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after "$point" \
            >/dev/null 2>&1 || status=$?
        [ "$status" -eq 75 ] \
            || die "first-publication restart fixture did not stop at $point"
        recover_pending_publications "$parent" "$destination" \
            || die "first-publication restart fixture could not recover after $point"
        if [ "$point" = staging ] || [ "$point" = prepared ] || [ "$point" = rollback-record ]; then
            [ ! -e "$destination" ] && [ ! -L "$destination" ] \
                || die "first-publication pre-exchange recovery at $point did not roll back the uncommitted set"
        else
            prove_published_dist "$destination" \
                || die "first-publication restart fixture did not commit the exact set after $point"
        fi
        base="$(basename "$destination")"
        transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-*" -print -quit)"
        [ -z "$transaction" ] \
            || die "first-publication restart fixture retained transaction state after $point"
    done

    for point in staging prepared rollback-record exchange cleanup-record payload-removal; do
        destination="$parent/restart-$point"
        atomic_install_dist "$source" "$destination"
        prior_id="$(stat -c '%d:%i' "$destination")"
        status=0
        publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
            --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
            --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after "$point" \
            >/dev/null 2>&1 || status=$?
        [ "$status" -eq 75 ] \
            || die "publication restart fixture did not stop at $point"
        if [ "$point" = exchange ]; then
            base="$(basename "$destination")"
            payload="$(find "$parent" -maxdepth 1 -type d \
                -name ".$base-release-payload.*" -print -quit)"
            [ -n "$payload" ] && [ "$(stat -c '%d:%i' "$payload")" = "$prior_id" ] \
                || die "publication exchange fixture lost the exact displaced prior release"
        fi
        recover_pending_publications "$parent" "$destination" \
            || die "publication restart fixture could not recover after $point"
        prove_published_dist "$destination" \
            || die "publication restart fixture did not retain an exact release after $point"
        if [ "$point" = staging ] || [ "$point" = prepared ] || [ "$point" = rollback-record ]; then
            [ "$(stat -c '%d:%i' "$destination")" = "$prior_id" ] \
                || die "publication pre-exchange recovery at $point did not restore the exact prior destination"
        else
            [ "$(stat -c '%d:%i' "$destination")" != "$prior_id" ] \
                || die "publication committed recovery retained the prior destination identity"
        fi
        base="$(basename "$destination")"
        transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-*" -print -quit)"
        [ -z "$transaction" ] \
            || die "publication restart fixture retained transaction state after $point"
    done

    destination="$parent/partial-rollback"
    atomic_install_dist "$source" "$destination"
    prior_id="$(stat -c '%d:%i' "$destination")"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after rollback-record \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] \
        || die "partial-rollback fixture did not stop after durable rollback authorization"
    base="$(basename "$destination")"
    payload="$(find "$parent" -maxdepth 1 -type d -name ".$base-release-payload.*" -print -quit)"
    [ -n "$payload" ] || die "partial-rollback fixture has no recorded payload"
    chmod 0700 "$payload"
    rm -f -- "$payload/${CANONICAL_ASSETS[0]}"
    recover_pending_publications "$parent" "$destination" \
        || die "partial-rollback fixture could not resume payload deletion"
    prove_published_dist "$destination" \
        || die "partial-rollback fixture did not preserve the prior release"
    [ "$(stat -c '%d:%i' "$destination")" = "$prior_id" ] \
        || die "partial-rollback fixture changed the prior release identity"
    transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-*" -print -quit)"
    [ -z "$transaction" ] \
        || die "partial-rollback fixture retained transaction state"

    destination="$parent/incomplete-prepared"
    atomic_install_dist "$source" "$destination"
    prior_id="$(stat -c '%d:%i' "$destination")"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after prepared \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "incomplete-prepared fixture did not stop at prepared"
    base="$(basename "$destination")"
    payload="$(find "$parent" -maxdepth 1 -type d -name ".$base-release-payload.*" -print -quit)"
    [ -n "$payload" ] || die "incomplete-prepared fixture has no recorded payload"
    held="$parent/incomplete-prepared-held"
    chmod 0700 "$payload"
    mv -- "$payload/${CANONICAL_ASSETS[0]}" "$held"
    chmod 0555 "$payload"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted an incomplete prepared payload"
    fi
    [ "$(stat -c '%d:%i' "$destination")" = "$prior_id" ] && [ -f "$held" ] \
        || die "incomplete-prepared rejection changed the prior or held payload state"
    chmod 0700 "$payload"
    mv -- "$held" "$payload/${CANONICAL_ASSETS[0]}"
    chmod 0555 "$payload"
    recover_pending_publications "$parent" "$destination" \
        || die "incomplete-prepared fixture could not recover after exact restoration"
    [ "$(stat -c '%d:%i' "$destination")" = "$prior_id" ] \
        || die "incomplete-prepared fixture changed the prior release identity"

    destination="$parent/invalid-existing"
    install -d -m 0700 "$destination"
    printf 'preserve invalid destination\n' > "$destination/unexpected"
    chmod 0400 "$destination/unexpected"
    preserved="$(stat -c '%d:%i:%u:%g:%a:%s' "$destination/unexpected"):$(sha256sum "$destination/unexpected" | awk '{print $1}')"
    if atomic_install_dist "$source" "$destination" >/dev/null 2>&1; then
        die "publication replaced an invalid existing destination"
    fi
    [ "$(stat -c '%d:%i:%u:%g:%a:%s' "$destination/unexpected"):$(sha256sum "$destination/unexpected" | awk '{print $1}')" = "$preserved" ] \
        || die "publication changed an invalid existing destination before rejection"
    base="$(basename "$destination")"
    transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-*" -print -quit)"
    [ -z "$transaction" ] \
        || die "invalid existing destination created publication transaction state"

    destination="$parent/reserved-namespace"
    base="$(basename "$destination")"
    token="$(printf 'a%.0s' {1..64})"
    reserved="$parent/.$base-release-obsolete.$token"
    printf 'reserved namespace fixture\n' > "$reserved"
    chmod 0400 "$reserved"
    preserved="$(stat -c '%d:%i:%u:%g:%a:%s' "$reserved"):$(sha256sum "$reserved" | awk '{print $1}')"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted an unknown reserved namespace entry"
    fi
    [ "$(stat -c '%d:%i:%u:%g:%a:%s' "$reserved"):$(sha256sum "$reserved" | awk '{print $1}')" = "$preserved" ] \
        || die "publication recovery changed an unknown reserved namespace entry"
    rm -f -- "$reserved"

    for category in transaction next payload; do
        malformed="$parent/.$base-release-$category.$token.suffix"
        printf 'malformed reserved namespace fixture\n' > "$malformed"
        chmod 0400 "$malformed"
        preserved="$(stat -c '%d:%i:%u:%g:%a:%s' "$malformed"):$(sha256sum "$malformed" | awk '{print $1}')"
        status=0
        output="$(recover_pending_publications "$parent" "$destination" 2>&1)" || status=$?
        [ "$status" -eq 1 ] \
            && printf '%s\n' "$output" | /usr/bin/grep -qF \
                'publication namespace contains a noncanonical reserved name' \
            || die "publication recovery did not classify malformed $category state exactly"
        [ "$(stat -c '%d:%i:%u:%g:%a:%s' "$malformed"):$(sha256sum "$malformed" | awk '{print $1}')" = "$preserved" ] \
            || die "publication recovery changed malformed $category state"
        rm -f -- "$malformed"
    done

    destination="$parent/wrong-payload-token"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after staging \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "wrong-payload-token fixture did not stop at staging"
    base="$(basename "$destination")"
    transaction="$(find "$parent" -maxdepth 1 -type f -name ".$base-release-transaction.*" -print -quit)"
    payload="$(find "$parent" -maxdepth 1 -type d -name ".$base-release-payload.*" -print -quit)"
    [ -n "$transaction" ] && [ -n "$payload" ] \
        || die "wrong-payload-token fixture lacks bound transaction state"
    wrong_token="$(printf 'e%.0s' {1..64})"
    wrong_payload="$parent/.$base-release-payload.$wrong_token"
    if [ "$wrong_payload" = "$payload" ]; then
        wrong_token="$(printf 'f%.0s' {1..64})"
        wrong_payload="$parent/.$base-release-payload.$wrong_token"
    fi
    mv -- "$payload" "$wrong_payload"
    preserved="$(stat -c '%d:%i:%u:%g:%a' "$transaction"):$(sha256sum "$transaction" | awk '{print $1}'):$(stat -c '%d:%i:%u:%g:%a' "$wrong_payload")"
    status=0
    output="$(recover_pending_publications "$parent" "$destination" 2>&1)" || status=$?
    [ "$status" -eq 1 ] \
        && printf '%s\n' "$output" | /usr/bin/grep -qF \
            'publication payload belongs to another transaction' \
        || die "publication recovery did not reject a canonical wrong-token payload"
    [ "$(stat -c '%d:%i:%u:%g:%a' "$transaction"):$(sha256sum "$transaction" | awk '{print $1}'):$(stat -c '%d:%i:%u:%g:%a' "$wrong_payload")" = "$preserved" ] \
        || die "wrong-token payload rejection changed transaction state"
    mv -- "$wrong_payload" "$payload"
    recover_pending_publications "$parent" "$destination" \
        || die "wrong-payload-token fixture could not recover after exact restoration"
    [ ! -e "$destination" ] \
        && [ -z "$(find "$parent" -maxdepth 1 -name ".$base-release-*" -print -quit)" ] \
        || die "wrong-payload-token fixture retained recovered state"

    destination="$parent/wrong-next-token"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after staging \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "wrong-next-token fixture did not stop at staging"
    base="$(basename "$destination")"
    transaction="$(find "$parent" -maxdepth 1 -type f -name ".$base-release-transaction.*" -print -quit)"
    [ -n "$transaction" ] || die "wrong-next-token fixture lacks a transaction record"
    token="${transaction##*.}"
    wrong_token="$(printf 'e%.0s' {1..64})"
    [ "$wrong_token" != "$token" ] || wrong_token="$(printf 'f%.0s' {1..64})"
    next="$parent/.$base-release-next.$wrong_token"
    cp -- "$transaction" "$next"
    chmod 0400 "$next"
    preserved="$(stat -c '%d:%i:%u:%g:%a:%s' "$transaction"):$(sha256sum "$transaction" | awk '{print $1}'):$(stat -c '%d:%i:%u:%g:%a:%s' "$next"):$(sha256sum "$next" | awk '{print $1}')"
    status=0
    output="$(recover_pending_publications "$parent" "$destination" 2>&1)" || status=$?
    [ "$status" -eq 1 ] \
        && printf '%s\n' "$output" | /usr/bin/grep -qF \
            'publication next record belongs to another transaction' \
        || die "publication recovery did not reject a canonical wrong-token next record"
    [ "$(stat -c '%d:%i:%u:%g:%a:%s' "$transaction"):$(sha256sum "$transaction" | awk '{print $1}'):$(stat -c '%d:%i:%u:%g:%a:%s' "$next"):$(sha256sum "$next" | awk '{print $1}')" = "$preserved" ] \
        || die "wrong-token next-record rejection changed transaction state"
    rm -f -- "$next"
    recover_pending_publications "$parent" "$destination" \
        || die "wrong-next-token fixture could not recover after exact restoration"
    [ ! -e "$destination" ] \
        && [ -z "$(find "$parent" -maxdepth 1 -name ".$base-release-*" -print -quit)" ] \
        || die "wrong-next-token fixture retained recovered state"

    destination="$parent/multiple-records"
    base="$(basename "$destination")"
    printf '{}\n' > "$parent/.$base-release-transaction.$(printf 'b%.0s' {1..64})"
    printf '{}\n' > "$parent/.$base-release-transaction.$(printf 'c%.0s' {1..64})"
    chmod 0400 "$parent/.$base-release-transaction."*
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted multiple active transaction records"
    fi
    [ "$(find "$parent" -maxdepth 1 -name ".$base-release-transaction.*" | wc -l)" -eq 2 ] \
        || die "multiple-record rejection changed ambiguous transaction state"
    rm -f -- "$parent/.$base-release-transaction."*

    destination="$parent/oversized-record"
    base="$(basename "$destination")"
    transaction="$parent/.$base-release-transaction.$(printf 'd%.0s' {1..64})"
    /usr/bin/python3 - "$transaction" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
try:
    os.write(descriptor, b"x" * 4097)
finally:
    os.close(descriptor)
PY
    preserved="$(stat -c '%d:%i:%u:%g:%a:%s' "$transaction"):$(sha256sum "$transaction" | awk '{print $1}')"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted an oversized transaction record"
    fi
    [ "$(stat -c '%d:%i:%u:%g:%a:%s' "$transaction"):$(sha256sum "$transaction" | awk '{print $1}')" = "$preserved" ] \
        || die "oversized-record rejection changed ambiguous transaction state"
    rm -f -- "$transaction"

    destination="$parent/missing-prior"
    atomic_install_dist "$source" "$destination"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after exchange \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "missing-prior fixture did not stop after exchange"
    base="$(basename "$destination")"
    payload="$(find "$parent" -maxdepth 1 -type d -name ".$base-release-payload.*" -print -quit)"
    [ -n "$payload" ] || die "missing-prior fixture has no displaced prior set"
    held="$parent/held-missing-prior"
    mv -- "$payload" "$held"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted a missing displaced prior set"
    fi
    transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-transaction.*" -print -quit)"
    [ -n "$transaction" ] && [ -d "$held" ] \
        || die "missing-prior rejection changed ambiguous transaction state"
    mv -- "$held" "$payload"
    recover_pending_publications "$parent" "$destination" \
        || die "missing-prior fixture could not recover after exact restoration"

    destination="$parent/destination-aba"
    substitute="$parent/destination-aba-substitute"
    atomic_install_dist "$source" "$destination"
    atomic_install_dist "$source" "$substitute"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after exchange \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "destination-ABA fixture did not stop after exchange"
    held="$parent/held-destination-aba"
    mv -- "$destination" "$held"
    mv -- "$substitute" "$destination"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted a content-equal replacement destination"
    fi
    base="$(basename "$destination")"
    transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-transaction.*" -print -quit)"
    [ -n "$transaction" ] && [ -d "$held" ] \
        || die "destination-ABA rejection changed ambiguous transaction state"
    mv -- "$destination" "$substitute"
    mv -- "$held" "$destination"
    recover_pending_publications "$parent" "$destination" \
        || die "destination-ABA fixture could not recover after exact restoration"

    destination="$parent/corrupt-mode"
    atomic_install_dist "$source" "$destination"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after exchange \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "publication mode-corruption fixture did not stop after exchange"
    chmod 0644 "$destination/${CANONICAL_ASSETS[0]}"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted a writable published artifact"
    fi
    base="$(basename "$destination")"
    transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-transaction.*" -print -quit)"
    [ -n "$transaction" ] || die "publication mode rejection discarded its durable transaction"
    chmod 0444 "$destination/${CANONICAL_ASSETS[0]}"
    recover_pending_publications "$parent" "$destination" \
        || die "publication mode-corruption fixture could not recover after restoration"

    destination="$parent/corrupt-root-mode"
    atomic_install_dist "$source" "$destination"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after exchange \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "publication root-mode fixture did not stop after exchange"
    chmod 0755 "$destination"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted a writable release root"
    fi
    base="$(basename "$destination")"
    transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-transaction.*" -print -quit)"
    [ -n "$transaction" ] || die "publication root-mode rejection discarded its durable transaction"
    chmod 0555 "$destination"
    recover_pending_publications "$parent" "$destination" \
        || die "publication root-mode fixture could not recover after restoration"

    destination="$parent/corrupt-special-type"
    atomic_install_dist "$source" "$destination"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after exchange \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "publication special-type fixture did not stop after exchange"
    held="$parent/held-special-type"
    chmod 0700 "$destination"
    mv -- "$destination/${CANONICAL_ASSETS[0]}" "$held"
    /usr/bin/python3 - "$destination/${CANONICAL_ASSETS[0]}" <<'PY'
import os
import sys

os.mkfifo(sys.argv[1], 0o444)
PY
    chmod 0555 "$destination"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted a special release entry"
    fi
    base="$(basename "$destination")"
    transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-transaction.*" -print -quit)"
    [ -n "$transaction" ] && [ -p "$destination/${CANONICAL_ASSETS[0]}" ] \
        || die "publication special-type rejection changed ambiguous state"
    chmod 0700 "$destination"
    rm -f -- "$destination/${CANONICAL_ASSETS[0]}"
    mv -- "$held" "$destination/${CANONICAL_ASSETS[0]}"
    chmod 0555 "$destination"
    recover_pending_publications "$parent" "$destination" \
        || die "publication special-type fixture could not recover after restoration"

    destination="$parent/corrupt-hardlink"
    atomic_install_dist "$source" "$destination"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after exchange \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "publication hardlink fixture did not stop after exchange"
    ln "$destination/${CANONICAL_ASSETS[0]}" "$parent/hardlink-escape"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted a multiply-linked published artifact"
    fi
    base="$(basename "$destination")"
    transaction="$(find "$parent" -maxdepth 1 -name ".$base-release-transaction.*" -print -quit)"
    [ -n "$transaction" ] && [ "$(stat -c '%h' "$destination/${CANONICAL_ASSETS[0]}")" -eq 2 ] \
        || die "publication hardlink rejection changed ambiguous state"
    rm -f -- "$parent/hardlink-escape"
    recover_pending_publications "$parent" "$destination" \
        || die "publication hardlink fixture could not recover after restoration"

    destination="$parent/corrupt-xattr"
    atomic_install_dist "$source" "$destination"
    status=0
    publication_tool --publish --parent "$parent" --destination "$(basename "$destination")" \
        --source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER" \
        --epoch "$SOURCE_DATE_EPOCH_PIN" --stop-after exchange \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 75 ] || die "publication xattr fixture did not stop after exchange"
    chmod 0644 "$destination/${CANONICAL_ASSETS[0]}"
    /usr/bin/python3 - "$destination/${CANONICAL_ASSETS[0]}" <<'PY'
import os
import sys
os.setxattr(sys.argv[1], "user.rustdesk-publication-fixture", b"rejected")
PY
    chmod 0444 "$destination/${CANONICAL_ASSETS[0]}"
    if recover_pending_publications "$parent" "$destination" >/dev/null 2>&1; then
        die "publication recovery accepted an artifact extended attribute"
    fi
    chmod 0644 "$destination/${CANONICAL_ASSETS[0]}"
    /usr/bin/python3 - "$destination/${CANONICAL_ASSETS[0]}" <<'PY'
import os
import sys
os.removexattr(sys.argv[1], "user.rustdesk-publication-fixture")
PY
    chmod 0444 "$destination/${CANONICAL_ASSETS[0]}"
    recover_pending_publications "$parent" "$destination" \
        || die "publication xattr fixture could not recover after restoration"
    prove_published_dist "$destination" \
        || die "publication reconciliation fixture final proof failed"
}

run_self_test() {
    local fixture_bin fixture_repo final_fixture expected_lines
    FIXTURE_MODE=1
    FORK_VER=1.4.7-hardened.6
    create_workspace
    fixture_repo="$WORKSPACE/fixture-repository"
    git_closed init --quiet --initial-branch=master "$fixture_repo" \
        || die "release self-test cannot initialize its private Git authority"
    printf 'fixture repository\n' > "$fixture_repo/source"
    git_closed -C "$fixture_repo" add -- source \
        || die "release self-test cannot stage its private Git fixture"
    git_closed -C "$fixture_repo" -c user.name=fixture -c user.email=fixture.invalid \
        commit --quiet -m fixture \
        || die "release self-test cannot commit its private Git fixture"
    REPO_ROOT="$fixture_repo"
    PINNED_HEAD="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || die "release self-test cannot resolve its private Git commit"
    PINNED_HEAD_SHORT="${PINNED_HEAD:0:12}"
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
    SOURCE_A_ID="$(stat -c '%d:%i' -- "$SOURCE_A")" \
        || die "release self-test cannot record snapshot A identity"
    SOURCE_B_ID="$(stat -c '%d:%i' -- "$SOURCE_B")" \
        || die "release self-test cannot record snapshot B identity"
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
    run_publication_reconciliation_self_test "$SET_A"
    atomic_install_dist "$SET_A" "$FINAL_OUT_DIR_FIXTURE"
    atomic_install_dist "$SET_A" "$FINAL_OUT_DIR_FIXTURE"
    prove_published_dist "$FINAL_OUT_DIR_FIXTURE"
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
    if [ "$SELF_TEST_SOURCE_STATE" -eq 1 ]; then
        run_source_state_self_test
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
    assert_snapshot_exact "$SOURCE_B" "before final dist installation"
    assert_release_source_state "before final dist installation"
    assert_origin_identity
    assert_live_origin_master "before final dist installation"
    assert_release_online_snapshot "before final dist installation"
    atomic_install_dist "$SET_A"
    RELEASE_SUCCESS_MESSAGE="RELEASE OK: four artifacts match across independent snapshots at $PINNED_HEAD_SHORT"
}

main
