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
for argument in "$@"; do
    case "$argument" in
        --doctor) DOCTOR=1 ;;
        --self-test) SELF_TEST=1 ;;
        -h|--help) printf 'usage: %s [--doctor|--self-test]\n' "${0##*/}"; exit 0 ;;
        *) die "unknown argument '$argument'" ;;
    esac
done
[ "$DOCTOR" -eq 0 ] || [ "$SELF_TEST" -eq 0 ] || die "--doctor and --self-test are mutually exclusive"

readonly FINAL_OUT_DIR="$REPO_ROOT/dist"
readonly DOCKER_HOST_URI=unix:///var/run/docker.sock
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
DOCKER_CONFIG_DIR=""
SOURCE_A=""
SOURCE_B=""
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

create_workspace() {
    WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-release.XXXXXXXXXX)" \
        || die "cannot create private release workspace"
    chmod 0700 "$WORKSPACE"
    [ "$(stat -c '%u:%a' "$WORKSPACE")" = "$(id -u):700" ] \
        || die "release workspace is not current-UID mode 0700"
    DOCKER_CONFIG_DIR="$WORKSPACE/docker-config"
    install -d -m 0700 "$DOCKER_CONFIG_DIR"
    printf '{}\n' > "$DOCKER_CONFIG_DIR/config.json"
    chmod 0600 "$DOCKER_CONFIG_DIR/config.json"
    assert_release_docker_config
    trap cleanup_release_workspace EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
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

offline_reown_path() {
    local path="$1"
    [ -e "$path" ] || return 0
    [ -n "$DEBIAN_IMAGE_ID" ] || die "cannot repair generated ownership without the pinned Debian image ID"
    docker_local run --rm --network=none --user 0:0 \
        --mount "type=bind,src=$path,dst=/cleanup" \
        "$DEBIAN_IMAGE_ID" chown -R "$(id -u):$(id -g)" /cleanup \
        || die "offline ownership repair failed for $path"
}

cleanup_release_workspace() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ "$WINDOWS_UNSAFE" -eq 1 ] || [ "$KEEP_WORKSPACE" -eq 1 ]; then
        printf 'build-release: preserving private workspace for Windows reconciliation: %s\n' "$WORKSPACE" >&2
        exit "$status"
    fi
    if [ -n "$WORKSPACE" ] && [ -d "$WORKSPACE" ]; then
        if [ "$FIXTURE_MODE" -eq 0 ]; then
            [ -z "$SOURCE_A" ] || offline_reown_path "$SOURCE_A"
            [ -z "$SOURCE_B" ] || offline_reown_path "$SOURCE_B"
            [ -z "$SOURCE_A" ] || git_closed -C "$REPO_ROOT" worktree remove --force "$SOURCE_A" || status=1
            [ -z "$SOURCE_B" ] || git_closed -C "$REPO_ROOT" worktree remove --force "$SOURCE_B" || status=1
            git_closed -C "$REPO_ROOT" worktree prune || status=1
        fi
        if ! chmod -R u+rwX "$WORKSPACE" 2>/dev/null; then
            status=1
        fi
        rm -rf -- "$WORKSPACE" || status=1
    fi
    exit "$status"
}

release_preflight() {
    local working_pins_hash commit_pins_hash
    require_cmd cmp git docker python3 sha256sum stat readlink install find date /usr/bin/grep
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
    local source="$1" phase="$2" current dirt
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
}

create_snapshot() {
    local label="$1" source="$2" output="$3" set_dir="$4"
    install -d -m 0700 "$(dirname "$source")" "$output" "$set_dir"
    git_closed -C "$REPO_ROOT" worktree add --quiet --detach "$source" "$PINNED_HEAD" \
        || die "cannot create detached release snapshot $label"
    chmod 0700 "$source"
    [ "$(stat -c '%u:%a' "$source")" = "$(id -u):700" ] \
        || die "release snapshot $label is not current-UID mode 0700"
    assert_snapshot_exact "$source" "snapshot $label creation"
}

reset_snapshot_build_state() {
    local source="$1" label="$2"
    git_closed -C "$source" clean -ffdx >/dev/null \
        || die "$label: cannot remove prior generated build state"
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
    run_snapshot_consumer "$label complete release verification" \
        run_child ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online" \
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN" ALLOW_DIRTY_TREE=0 \
        RELEASE_SRC_COMMIT="$PINNED_HEAD" \
        /usr/bin/bash --noprofile --norc "$source/scripts/verify-release.sh" \
        || die "$label: complete release verification failed"
    assert_snapshot_exact "$source" "$label after verification"
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
            [ "$FIXTURE_MODE" -eq 1 ] || offline_reown_path "$source"
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
        [ "$FIXTURE_MODE" -eq 1 ] || reset_snapshot_build_state "$source" "$label before $target"
        log "$label: building $target"
        invoke_target "$label" "$target" "$source" "$output/$target" "$set_dir"
        if [ "$FIXTURE_MODE" -eq 0 ]; then
            assert_snapshot_exact "$source" "$label after $target"
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

atomic_exchange_or_install() {
    python3 - "$1" "$2" <<'PY'
import ctypes
import errno
import os
import stat
import sys

source = os.fsencode(sys.argv[1])
destination = os.fsencode(sys.argv[2])
source_stat = os.lstat(source)
if not stat.S_ISDIR(source_stat.st_mode):
    raise SystemExit("release staging path is not a directory")
try:
    destination_stat = os.lstat(destination)
except FileNotFoundError:
    os.rename(source, destination)
else:
    if not stat.S_ISDIR(destination_stat.st_mode):
        raise SystemExit("existing dist is not a real directory")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, source, -100, destination, 2) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
PY
}

atomic_install_dist() {
    local source="$1" destination="${2:-$FINAL_OUT_DIR}" stage parent base name
    parent="$(dirname "$destination")"
    base="$(basename "$destination")"
    stage="$(umask 077 && mktemp -d "$parent/.$base-release-stage.XXXXXXXXXX")" \
        || die "cannot create private final-dist staging directory"
    for name in "${CANONICAL_ASSETS[@]}" SHA256SUMS; do
        install -m 0444 "$source/$name" "$stage/$name"
    done
    strict_manifest_proof "$stage"
    chmod 0555 "$stage"
    if [ -e "$destination" ]; then
        [ -d "$destination" ] && [ ! -L "$destination" ] \
            || die "existing dist is not a real directory"
        [ "$FIXTURE_MODE" -eq 1 ] || offline_reown_path "$destination"
        chmod -R u+rwX "$destination"
    fi
    atomic_exchange_or_install "$stage" "$destination" \
        || die "atomic final-dist installation failed"
    if [ -e "$stage" ]; then
        chmod -R u+rwX "$stage" \
            || die "cannot make the displaced dist removable"
        rm -rf -- "$stage" || die "cannot remove atomically displaced dist directory"
    fi
    strict_manifest_proof "$destination"
    [ "$(stat -c '%a' "$destination")" = 555 ] || die "final dist directory is not immutable mode 0555"
    for name in "${CANONICAL_ASSETS[@]}" SHA256SUMS; do
        [ "$(stat -c '%a' "$destination/$name")" = 444 ] \
            || die "final dist file is not immutable mode 0444: $name"
    done
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

run_self_test() {
    local fixture_bin final_fixture expected_lines
    FIXTURE_MODE=1
    PINNED_HEAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    PINNED_HEAD_SHORT=aaaaaaaaaaaa
    FORK_VER=1.4.7-hardened.6
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
    install -d -m 0700 "$FINAL_OUT_DIR_FIXTURE"
    printf stale > "$FINAL_OUT_DIR_FIXTURE/noncanonical-old-file"
    atomic_install_dist "$SET_A" "$FINAL_OUT_DIR_FIXTURE"
    strict_manifest_proof "$FINAL_OUT_DIR_FIXTURE"
    log "build-release self-test: OK"
}

main() {
    if [ "$SELF_TEST" -eq 1 ]; then
        run_self_test
        return 0
    fi
    PINNED_HEAD="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "cannot resolve repository HEAD"
    PINNED_HEAD_SHORT="${PINNED_HEAD:0:12}"
    export SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN"
    create_workspace
    release_preflight
    if [ "$DOCTOR" -eq 1 ]; then
        log "DOCTOR OK: clean local master equals live origin/master"
        return 0
    fi
    prepare_release_snapshots
    build_snapshot A "$SOURCE_A" "$OUTPUT_A" "$SET_A"
    build_snapshot B "$SOURCE_B" "$OUTPUT_B" "$SET_B"
    compare_snapshots
    write_manifest "$SET_A"
    strict_manifest_proof "$SET_A"
    run_snapshot_consumer "final APK certificate proof" run_child \
        RUSTDESK_RELEASE_ONLINE_SNAPSHOT="$ONLINE_SNAPSHOT_PARENT" \
        RELEASE_SRC_COMMIT="$PINNED_HEAD" RELEASE_DOCKER_IMAGE_ID="$ANDROID_IMAGE_ID" \
        /usr/bin/bash --noprofile --norc "$SOURCE_A/scripts/build-android.sh" \
        --verify-apk "$SET_A/rustdesk-arm64.apk" \
        || die "final APK certificate proof failed"
    assert_snapshot_exact "$SOURCE_A" "after final APK certificate proof"
    assert_snapshot_exact "$SOURCE_B" "before final dist installation"
    assert_release_source_state "before final dist installation"
    assert_origin_identity
    assert_live_origin_master "before final dist installation"
    assert_release_online_snapshot "before final dist installation"
    atomic_install_dist "$SET_A"
    log "RELEASE OK: four artifacts match across independent snapshots at $PINNED_HEAD_SHORT"
}

main
