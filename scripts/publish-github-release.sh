#!/usr/bin/env -S -i /usr/bin/bash --noprofile --norc
set -euo pipefail

readonly PUBLISH_ENV_MARKER_VALUE=rustdesk-publish-env-v1
readonly SAFE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
readonly GITHUB_API_VERSION=2026-03-10
readonly NETWORK_TIMEOUT_SECONDS=1800
readonly EXPECTED_REPO_SLUG=BigBIueWhale/rustdesk_fork
readonly EXPECTED_REPO_ID=1268555599
readonly EXPECTED_OWNER_LOGIN=BigBIueWhale
readonly EXPECTED_OWNER_ID=85248530
readonly EXPECTED_PUBLISHER_LOGIN=BigBIueWhale
readonly EXPECTED_PUBLISHER_ID=85248530

forbidden_inherited_name() {
    case "$1" in
        BASH_ENV|ENV|CDPATH|PYTHONPATH|PYTHONHOME|HARNESS_PREFIX|GIT_*|DOCKER_*|BUILDKIT_*|COMPOSE_*|\
        CC|CXX|CPP|AR|AS|LD|NM|OBJCOPY|OBJDUMP|RANLIB|READELF|STRIP|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|\
        RUST*|CARGO*|FLUTTER*|ANDROID*|JAVA_HOME|GRADLE_*|SOURCE_DATE_EPOCH|DOUBLE_BUILD|OUT_DIR|\
        ALLOW_DIRTY_TREE|WINDOWS_*|RELEASE_*|VCPKG_*|X_VCPKG_*|TMPDIR|GH_*|GITHUB_*|LD_*|\
        LIBRARY_PATH|CPATH|C_INCLUDE_PATH|CPLUS_INCLUDE_PATH|PKG_CONFIG*|MAKEFLAGS|NINJAFLAGS|\
        SHELLOPTS|BASHOPTS|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|all_proxy|no_proxy)
            return 0 ;;
        *) return 1 ;;
    esac
}

bootstrap_closed_environment() {
    local name uid passwd_entry safe_home
    if [ "${RUSTDESK_PUBLISH_ENV_MARKER:-}" != "$PUBLISH_ENV_MARKER_VALUE" ]; then
        while IFS= read -r name; do
            forbidden_inherited_name "$name" \
                && { printf 'publish-release: forbidden inherited environment variable: %s\n' "$name" >&2; exit 1; }
        done < <(compgen -e)
        uid="$(/usr/bin/id -u)"
        passwd_entry="$(/usr/bin/getent passwd "$uid")" \
            || { printf 'publish-release: cannot resolve current user home\n' >&2; exit 1; }
        safe_home="$(printf '%s\n' "$passwd_entry" | /usr/bin/awk -F: 'NF == 7 { print $6 }')"
        [ -n "$safe_home" ] && [ -d "$safe_home" ] \
            || { printf 'publish-release: current user home is invalid\n' >&2; exit 1; }
        exec /usr/bin/env -i \
            HOME="$safe_home" PATH="$SAFE_PATH" LC_ALL=C LANG=C TZ=UTC \
            RUSTDESK_PUBLISH_ENV_MARKER="$PUBLISH_ENV_MARKER_VALUE" \
            /usr/bin/bash --noprofile --norc "$0" "$@"
    fi
    while IFS= read -r name; do
        case "$name" in
            HOME|PATH|LC_ALL|LANG|TZ|RUSTDESK_PUBLISH_ENV_MARKER|PWD|SHLVL|_) ;;
            *) printf 'publish-release: closed environment contains unexpected variable: %s\n' "$name" >&2; exit 1 ;;
        esac
    done < <(compgen -e)
}

bootstrap_closed_environment "$@"
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0
export GIT_NO_REPLACE_OBJECTS=1

PRERELEASE=1
SELF_TEST=0
for argument in "$@"; do
    case "$argument" in
        --final) PRERELEASE=0 ;;
        --self-test) SELF_TEST=1 ;;
        -h|--help) printf 'usage: %s [--final|--self-test]\n' "${0##*/}"; exit 0 ;;
        *) die "unknown argument '$argument'" ;;
    esac
done
[ "$PRERELEASE" -eq 1 ] || [ "$SELF_TEST" -eq 0 ] || die "--final and --self-test are mutually exclusive"

readonly SOURCE_DIST="$REPO_ROOT/dist"
readonly -a CANONICAL_ASSETS=(
    rustdesk-x86_64.deb
    rustdesk-arm64.apk
    rustdesk-setup.exe
    rustdesk.msi
)
readonly -a PUBLICATION_ASSETS=(
    rustdesk-x86_64.deb
    rustdesk-arm64.apk
    rustdesk-setup.exe
    rustdesk.msi
    SHA256SUMS
)

HEAD_FULL=""
FORK_VER=""
REPO_SLUG=""
ORIGIN_URL=""
PINNED_ORIGIN_URL=""
TAG=""
TITLE=""
WORKSPACE=""
METADATA_DIR=""
ARTIFACT_DIR=""
NOTES_FILE=""
GH_BIN=gh
GIT_BIN=git
TRANSACTION_STATE=local-only
FIXTURE_MODE=0
NETWORK_REPO=""
GH_CONFIG_SNAPSHOT=""
GH_CONFIG_DIGEST=""
RELEASE_ID=""
UPLOAD_URL=""

git_closed() {
    GH_CONFIG_DIR="$GH_CONFIG_SNAPSHOT" GH_HOST=github.com GH_NO_UPDATE_NOTIFIER=1 \
    "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
        -c credential.helper= \
        -c "credential.helper=!$GH_BIN auth git-credential" \
        -c credential.useHttpPath=true \
        "$@"
}

git_network() {
    GH_CONFIG_DIR="$GH_CONFIG_SNAPSHOT" GH_HOST=github.com GH_NO_UPDATE_NOTIFIER=1 \
    timeout --foreground --signal=TERM --kill-after=30s "${NETWORK_TIMEOUT_SECONDS}s" \
        "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
        -c credential.helper= \
        -c "credential.helper=!$GH_BIN auth git-credential" \
        -c credential.useHttpPath=true \
        "$@"
}

assert_gh_config_snapshot() {
    local digest
    [ -n "$GH_CONFIG_SNAPSHOT" ] && [ -d "$GH_CONFIG_SNAPSHOT" ] && [ ! -L "$GH_CONFIG_SNAPSHOT" ] \
        || die "private GitHub CLI configuration is absent"
    [ "$(stat -c '%u:%a' "$GH_CONFIG_SNAPSHOT" 2>/dev/null)" = "$(id -u):500" ] \
        || die "private GitHub CLI configuration is not current-UID mode 0500"
    python3 - "$GH_CONFIG_SNAPSHOT" "$(id -u)" <<'PY'
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
uid = int(sys.argv[2])
entries = list(os.scandir(root))
if {entry.name for entry in entries} != {"config.yml", "hosts.yml"} or len(entries) != 2:
    raise SystemExit("private GitHub CLI configuration file set changed")
for entry in entries:
    metadata = entry.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid:
        raise SystemExit("private GitHub CLI configuration contains a non-owned regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o400 or metadata.st_nlink != 1:
        raise SystemExit("private GitHub CLI configuration file is mutable or hardlinked")
PY
    digest="$(cd "$GH_CONFIG_SNAPSHOT" && sha256sum config.yml hosts.yml | sha256sum | awk '{print $1}')" \
        || die "cannot hash private GitHub CLI configuration"
    [ "$digest" = "$GH_CONFIG_DIGEST" ] || die "private GitHub CLI configuration bytes changed"
}

gh_closed() {
    local status
    assert_gh_config_snapshot
    if GH_CONFIG_DIR="$GH_CONFIG_SNAPSHOT" GH_HOST=github.com GH_NO_UPDATE_NOTIFIER=1 \
        timeout --foreground --signal=TERM --kill-after=30s "${NETWORK_TIMEOUT_SECONDS}s" \
        "$GH_BIN" "$@"; then
        status=0
    else
        status=$?
    fi
    assert_gh_config_snapshot
    return "$status"
}

gh_api() {
    gh_closed api --hostname github.com \
        -H 'Accept: application/vnd.github+json' \
        -H "X-GitHub-Api-Version: $GITHUB_API_VERSION" \
        "$@"
}

cleanup_publication_workspace() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ] && [ "$TRANSACTION_STATE" != local-only ]; then
        printf 'publish-release: remote state is %s for %s; no remote object was deleted. Reconcile the uniqueness tags and numeric release state before retrying.\n' \
            "$TRANSACTION_STATE" "$TAG" >&2
    fi
    if [ -n "$WORKSPACE" ] && [ -d "$WORKSPACE" ]; then
        if ! chmod -R u+rwX "$WORKSPACE" 2>/dev/null; then
            status=1
        fi
        rm -rf -- "$WORKSPACE" || status=1
    fi
    exit "$status"
}

create_private_workspace() {
    WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-publish.XXXXXXXXXX)" \
        || die "cannot create private publication workspace"
    chmod 0700 "$WORKSPACE"
    [ "$(stat -c '%u:%a' "$WORKSPACE")" = "$(id -u):700" ] \
        || die "publication workspace is not current-UID mode 0700"
    METADATA_DIR="$WORKSPACE/metadata"
    ARTIFACT_DIR="$WORKSPACE/artifacts"
    GH_CONFIG_SNAPSHOT="$WORKSPACE/gh-config"
    install -d -m 0700 "$METADATA_DIR/scripts" "$ARTIFACT_DIR" "$GH_CONFIG_SNAPSHOT"
    trap cleanup_publication_workspace EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

initialize_gh_config_snapshot() {
    local source="$HOME/.config/gh/hosts.yml"
    python3 - "$source" "$GH_CONFIG_SNAPSHOT/hosts.yml" "$(id -u)" <<'PY'
import os
import stat
import sys

source, destination, uid_text = sys.argv[1:]
uid = int(uid_text)
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(source, flags)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != uid:
        raise SystemExit("GitHub authentication source is not a current-UID regular file")
    if stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1:
        raise SystemExit("GitHub authentication source must be mode 0600 and non-hardlinked")
    if before.st_size <= 0 or before.st_size > 1024 * 1024:
        raise SystemExit("GitHub authentication source has an invalid size")
    chunks = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 65536))
        if not chunk:
            raise SystemExit("GitHub authentication source changed length while read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise SystemExit("GitHub authentication source grew while read")
    after = os.fstat(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ):
        raise SystemExit("GitHub authentication source changed while read")
finally:
    os.close(descriptor)

output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    output_flags |= os.O_NOFOLLOW
output = os.open(destination, output_flags, 0o600)
try:
    data = b"".join(chunks)
    offset = 0
    while offset < len(data):
        offset += os.write(output, data[offset:])
    os.fsync(output)
finally:
    os.close(output)
PY
    {
        printf 'version: 1\n'
        printf 'git_protocol: https\n'
        printf 'prompt: disabled\n'
        printf 'http_unix_socket: ""\n'
        printf 'telemetry: disabled\n'
    } > "$GH_CONFIG_SNAPSHOT/config.yml"
    chmod 0400 "$GH_CONFIG_SNAPSHOT/config.yml" "$GH_CONFIG_SNAPSHOT/hosts.yml"
    chmod 0500 "$GH_CONFIG_SNAPSHOT"
    GH_CONFIG_DIGEST="$(cd "$GH_CONFIG_SNAPSHOT" && sha256sum config.yml hosts.yml | sha256sum | awk '{print $1}')" \
        || die "cannot pin private GitHub CLI configuration"
    assert_gh_config_snapshot
    gh_closed auth status --hostname github.com >/dev/null \
        || die "private GitHub CLI authentication snapshot is not valid for github.com"
}

assert_github_identity() {
    local phase="$1" identity
    identity="$(printf '%s' "$phase" | sha256sum | awk '{print $1}')"
    gh_api user --method GET > "$WORKSPACE/github-user-$identity.json" \
        || die "$phase: cannot query the authenticated GitHub principal"
    gh_api "repos/$REPO_SLUG" --method GET > "$WORKSPACE/github-repository-$identity.json" \
        || die "$phase: cannot query the GitHub repository identity"
    python3 - "$WORKSPACE/github-user-$identity.json" "$WORKSPACE/github-repository-$identity.json" \
        "$EXPECTED_PUBLISHER_LOGIN" "$EXPECTED_PUBLISHER_ID" "$EXPECTED_REPO_SLUG" "$EXPECTED_REPO_ID" \
        "$EXPECTED_OWNER_LOGIN" "$EXPECTED_OWNER_ID" "$ORIGIN_URL" <<'PY'
import json
import sys
from pathlib import Path

def object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(f"duplicate JSON key: {key}")
        value[key] = item
    return value

def reject_nonfinite(value):
    raise SystemExit(f"non-finite JSON number: {value}")

def read(path):
    value = json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=object_without_duplicates,
        parse_constant=reject_nonfinite,
    )
    if not isinstance(value, dict):
        raise SystemExit("GitHub identity response is not an object")
    return value

user = read(sys.argv[1])
repository = read(sys.argv[2])
publisher_login, publisher_id, slug, repo_id, owner_login, owner_id, origin = sys.argv[3:]
if type(user.get("login")) is not str or type(user.get("id")) is not int or type(user.get("type")) is not str:
    raise SystemExit("authenticated GitHub principal schema is hostile")
if user["login"] != publisher_login or user["id"] != int(publisher_id) or user["type"] != "User":
    raise SystemExit("authenticated GitHub principal is not the authorized publisher")
required = {"id": int, "full_name": str, "clone_url": str, "default_branch": str,
            "owner": dict, "permissions": dict, "archived": bool, "disabled": bool}
for key, expected in required.items():
    if key not in repository or type(repository[key]) is not expected:
        raise SystemExit(f"GitHub repository field {key} has a hostile or missing type")
owner = repository["owner"]
permissions = repository["permissions"]
if type(owner.get("login")) is not str or type(owner.get("id")) is not int or type(owner.get("type")) is not str:
    raise SystemExit("GitHub repository owner schema is hostile")
if type(permissions.get("push")) is not bool or permissions["push"] is not True:
    raise SystemExit("authenticated publisher lacks repository push permission")
if repository["id"] != int(repo_id) or repository["full_name"] != slug:
    raise SystemExit("GitHub repository numeric or canonical identity differs from the pinned repository")
if owner["login"] != owner_login or owner["id"] != int(owner_id) or owner["type"] != "User":
    raise SystemExit("GitHub repository owner differs from the pinned owner")
if repository["clone_url"] != origin or repository["default_branch"] != "master":
    raise SystemExit("GitHub repository clone URL or default branch differs from the release contract")
if repository["archived"] or repository["disabled"]:
    raise SystemExit("GitHub repository is archived or disabled")
PY
}

assert_immutable_release_policy() {
    local phase="$1" identity policy_file
    identity="$(printf '%s' "$phase" | sha256sum | awk '{print $1}')"
    policy_file="$WORKSPACE/immutable-release-policy-$identity.json"
    gh_api "repos/$REPO_SLUG/immutable-releases" --method GET > "$policy_file" \
        || die "$phase: repository immutable-release policy is unavailable or disabled"
    python3 - "$policy_file" <<'PY'
import json
import sys
from pathlib import Path

def object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(f"duplicate JSON key: {key}")
        value[key] = item
    return value

def reject_nonfinite(value):
    raise SystemExit(f"non-finite JSON number: {value}")

value = json.loads(
    Path(sys.argv[1]).read_text(encoding="utf-8"),
    object_pairs_hook=object_without_duplicates,
    parse_constant=reject_nonfinite,
)
if not isinstance(value, dict) or set(value) != {"enabled", "enforced_by_owner"}:
    raise SystemExit("immutable-release policy schema is hostile")
if value["enabled"] is not True or type(value["enforced_by_owner"]) is not bool:
    raise SystemExit("repository immutable releases are not enabled")
PY
}

assert_no_git_object_substitution() {
    local common_dir grafts alternates replacements
    common_dir="$(git_closed -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
        || die "cannot resolve repository common Git directory"
    grafts="$common_dir/info/grafts"
    alternates="$common_dir/objects/info/alternates"
    [ ! -e "$grafts" ] && [ ! -L "$grafts" ] || die "Git grafts are forbidden for publication"
    [ ! -e "$alternates" ] && [ ! -L "$alternates" ] || die "Git object alternates are forbidden for publication"
    replacements="$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace 2>/dev/null)" \
        || die "cannot inspect Git replacement refs"
    [ -z "$replacements" ] || die "Git replacement refs are forbidden for publication"
}

acquire_publication_lock() {
    local common_dir runtime_dir identity lock_path
    common_dir="$(git_closed -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
        || die "cannot resolve repository common Git directory"
    [ -d "$common_dir" ] && [ ! -L "$common_dir" ] || die "Git common directory is not a real directory"
    runtime_dir="/run/user/$(id -u)"
    [ -d "$runtime_dir" ] && [ ! -L "$runtime_dir" ] \
        && [ "$(stat -c '%u:%a' "$runtime_dir")" = "$(id -u):700" ] \
        || die "publication lock runtime directory is not current-UID mode 0700"
    identity="$(printf '%s' "$common_dir" | sha256sum | awk '{print $1}')"
    lock_path="$runtime_dir/rustdesk-release-publication-$identity.lock"
    umask 077
    if [ ! -e "$lock_path" ] && [ ! -L "$lock_path" ]; then
        (set -o noclobber; : > "$lock_path") 2>/dev/null \
            || die "cannot create publication lock without following an existing path"
    fi
    [ -f "$lock_path" ] && [ ! -L "$lock_path" ] \
        && [ "$(stat -c '%u:%a:%h' "$lock_path")" = "$(id -u):600:1" ] \
        || die "publication lock is not a current-UID mode-0600 file"
    exec 9<>"$lock_path"
    flock -n 9 || die "another release publication transaction holds $lock_path"
}

derive_origin_repository() {
    local hostile fetch_output push_output
    local -a fetch_urls=() push_urls=()
    hostile="$(git_closed -C "$REPO_ROOT" config --local --no-includes --name-only --get-regexp \
        '^(include\.|includeif\.|url\.|http\.|credential\.|core\.(gitproxy|sshcommand)$|remote\.origin\.(proxy|receivepack|uploadpack)$)' \
        2>/dev/null || true)"
    [ -z "$hostile" ] || die "repository-local Git transport rewriting is forbidden for publication"
    fetch_output="$(git_closed -C "$REPO_ROOT" config --local --no-includes --get-all remote.origin.url 2>/dev/null)" \
        || die "cannot read the raw origin URL from repository-local configuration"
    mapfile -t fetch_urls <<< "$fetch_output"
    if push_output="$(git_closed -C "$REPO_ROOT" config --local --no-includes --get-all remote.origin.pushurl 2>/dev/null)"; then
        mapfile -t push_urls <<< "$push_output"
    elif [ $? -ne 1 ]; then
        die "cannot read the raw origin push URL from repository-local configuration"
    fi
    [ "${#fetch_urls[@]}" -eq 1 ] || die "origin must have exactly one fetch URL"
    if [ "${#push_urls[@]}" -eq 0 ]; then
        push_urls=("${fetch_urls[0]}")
    fi
    [ "${#push_urls[@]}" -eq 1 ] || die "origin must have at most one explicit push URL"
    if [ -n "$PINNED_ORIGIN_URL" ] && [ "${fetch_urls[0]}" != "$PINNED_ORIGIN_URL" ]; then
        die "origin URL changed during publication"
    fi
    PINNED_ORIGIN_URL="${fetch_urls[0]}"
    ORIGIN_URL="$PINNED_ORIGIN_URL"
    [ "${push_urls[0]}" = "$ORIGIN_URL" ] || die "origin fetch and push URLs differ"
    if [[ "$ORIGIN_URL" =~ ^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\.git$ ]]; then
        REPO_SLUG="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
    else
        die "origin must be one canonical https://github.com/OWNER/REPO.git URL"
    fi
    [ "$REPO_SLUG" = "$EXPECTED_REPO_SLUG" ] \
        || die "origin is not the pinned release repository $EXPECTED_REPO_SLUG"
}

assert_publication_source() {
    local phase="$1" current branch dirt sparse index_flags
    current="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "$phase: cannot resolve HEAD"
    [ "$current" = "$HEAD_FULL" ] || die "$phase: HEAD changed"
    branch="$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet --short HEAD 2>/dev/null)" \
        || die "$phase: checkout is detached"
    [ "$branch" = master ] || die "$phase: checkout is not master"
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
    assert_no_git_object_substitution
    derive_origin_repository
}

assert_live_origin_master() {
    local phase="$1" output sha ref extra
    local -a rows
    [ -d "$NETWORK_REPO" ] || die "$phase: private network Git repository is absent"
    output="$(git_network -C "$NETWORK_REPO" ls-remote --exit-code "$ORIGIN_URL" refs/heads/master 2>/dev/null)" \
        || die "$phase: cannot read live origin/master"
    mapfile -t rows <<< "$output"
    [ "${#rows[@]}" -eq 1 ] || die "$phase: live origin/master returned ${#rows[@]} rows"
    IFS=$'\t' read -r sha ref extra <<< "${rows[0]}"
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] && [ "$ref" = refs/heads/master ] && [ -z "$extra" ] \
        || die "$phase: live origin/master response is malformed"
    [ "$sha" = "$HEAD_FULL" ] || die "$phase: live origin/master is $sha, expected $HEAD_FULL"
}

initialize_network_repo() {
    NETWORK_REPO="$WORKSPACE/network.git"
    git_closed init --bare --quiet "$NETWORK_REPO" \
        || die "cannot initialize private network Git repository"
    git_network -C "$NETWORK_REPO" fetch --quiet --no-tags "$ORIGIN_URL" \
        "+refs/heads/master:refs/release/master" \
        || die "cannot fetch live origin/master into the private network repository"
    [ "$(git_closed -C "$NETWORK_REPO" rev-parse --verify 'refs/release/master^{commit}')" = "$HEAD_FULL" ] \
        || die "private network repository master differs from the pinned local commit"
}

assert_exact_file_set() {
    local directory="$1"
    python3 - "$directory" "${PUBLICATION_ASSETS[@]}" <<'PY'
import os
import stat
import sys
from pathlib import Path

directory = Path(sys.argv[1])
expected = set(sys.argv[2:])
metadata = directory.lstat()
if not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit(f"release set is not a real directory: {directory}")
entries = list(os.scandir(directory))
if {entry.name for entry in entries} != expected or len(entries) != len(expected):
    raise SystemExit(f"release set is not the exact five-file set: {directory}")
for entry in entries:
    metadata = entry.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise SystemExit(f"release entry is not a regular non-empty file: {entry.name!r}")
PY
}

strict_manifest_proof() {
    local directory="$1" expected_header actual_header line name hash index
    local -a checksums
    assert_exact_file_set "$directory"
    [ "$(wc -l < "$directory/SHA256SUMS")" -eq 9 ] \
        || die "SHA256SUMS must have exactly nine lines"
    expected_header="$(printf '%s\n' \
        '# rustdesk-fork release manifest v1' \
        "# fork-version: $FORK_VER" \
        "# commit: $HEAD_FULL" \
        "# source-date-epoch: $SOURCE_DATE_EPOCH_PIN" \
        '# reproducibility: independent-snapshots-a-equals-b')"
    actual_header="$(head -n 5 "$directory/SHA256SUMS")"
    [ "$actual_header" = "$expected_header" ] || die "SHA256SUMS metadata does not match the pinned commit"
    mapfile -t checksums < <(tail -n +6 "$directory/SHA256SUMS")
    [ "${#checksums[@]}" -eq 4 ] || die "SHA256SUMS checksum count is invalid"
    for index in "${!CANONICAL_ASSETS[@]}"; do
        line="${checksums[index]}"
        name="${CANONICAL_ASSETS[index]}"
        hash="${line%%  *}"
        [[ "$hash" =~ ^[0-9a-f]{64}$ ]] && [ "$line" = "$hash  $name" ] \
            || die "SHA256SUMS entry is not canonical for $name"
    done
    (cd "$directory" && sha256sum -c --strict --status SHA256SUMS) \
        || die "release artifact checksums do not verify"
}

snapshot_commit_file() {
    local path="$1" destination="$2"
    git_closed -C "$REPO_ROOT" show "$HEAD_FULL:$path" > "$destination" \
        || die "cannot snapshot $path from $HEAD_FULL"
    chmod 0400 "$destination"
}

create_immutable_snapshot() {
    local snapshot_epoch
    snapshot_commit_file FORK_VERSION "$METADATA_DIR/FORK_VERSION"
    snapshot_commit_file Cargo.toml "$METADATA_DIR/Cargo.toml"
    snapshot_commit_file CHANGELOG.md "$METADATA_DIR/CHANGELOG.md"
    snapshot_commit_file scripts/fork-version.sh "$METADATA_DIR/scripts/fork-version.sh"
    snapshot_commit_file scripts/pins.env "$METADATA_DIR/scripts/pins.env"
    chmod 0500 "$METADATA_DIR/scripts/fork-version.sh"
    snapshot_epoch="$(/usr/bin/bash --noprofile --norc -c 'source "$1"; printf "%s" "$SOURCE_DATE_EPOCH_PIN"' _ "$METADATA_DIR/scripts/pins.env")" \
        || die "pinned commit reproducible-build epoch is invalid"
    [[ "$snapshot_epoch" =~ ^[0-9]+$ ]] || die "pinned commit reproducible-build epoch is malformed"
    SOURCE_DATE_EPOCH_PIN="$snapshot_epoch"
    FORK_VER="$(/usr/bin/bash --noprofile --norc "$METADATA_DIR/scripts/fork-version.sh")" \
        || die "pinned commit version metadata is invalid"
    python3 - "$SOURCE_DIST" "$ARTIFACT_DIR" "$(id -u)" "${PUBLICATION_ASSETS[@]}" <<'PY'
import os
import stat
import sys

source, destination, uid_text, *expected_order = sys.argv[1:]
uid = int(uid_text)
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    directory_flags |= os.O_NOFOLLOW
source_fd = os.open(source, directory_flags)
try:
    source_metadata = os.fstat(source_fd)
    if source_metadata.st_uid != uid or stat.S_IMODE(source_metadata.st_mode) != 0o555:
        raise SystemExit("dist is not a current-UID mode-0555 directory")
    names = os.listdir(source_fd)
    if set(names) != set(expected_order) or len(names) != len(expected_order):
        raise SystemExit("dist is not the exact five-file publication set")
    for name in expected_order:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        input_fd = os.open(name, flags, dir_fd=source_fd)
        try:
            before = os.fstat(input_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != uid:
                raise SystemExit(f"dist/{name} is not a current-UID regular file")
            if stat.S_IMODE(before.st_mode) != 0o444 or before.st_nlink != 1 or before.st_size <= 0:
                raise SystemExit(f"dist/{name} is mutable, hardlinked, or empty")
            output_path = os.path.join(destination, name)
            output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                output_flags |= os.O_NOFOLLOW
            output_fd = os.open(output_path, output_flags, 0o400)
            try:
                remaining = before.st_size
                while remaining:
                    chunk = os.read(input_fd, min(remaining, 1024 * 1024))
                    if not chunk:
                        raise SystemExit(f"dist/{name} changed length while copied")
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(output_fd, chunk[offset:])
                    remaining -= len(chunk)
                if os.read(input_fd, 1):
                    raise SystemExit(f"dist/{name} grew while copied")
                os.fsync(output_fd)
            finally:
                os.close(output_fd)
            after = os.fstat(input_fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                raise SystemExit(f"dist/{name} changed while copied")
        finally:
            os.close(input_fd)
    current = os.stat(source, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (source_metadata.st_dev, source_metadata.st_ino):
        raise SystemExit("dist directory path changed while copied")
finally:
    os.close(source_fd)
PY
    strict_manifest_proof "$ARTIFACT_DIR"
    chmod 0500 "$METADATA_DIR" "$ARTIFACT_DIR"
}

write_release_notes() {
    local notes_body built_at commit_url
    notes_body="$(awk '/^## / { count++ } count == 1 { print } count >= 2 { exit }' "$METADATA_DIR/CHANGELOG.md")"
    [ -n "$notes_body" ] || die "pinned CHANGELOG.md has no current release section"
    built_at="$(git_closed -C "$REPO_ROOT" show -s --format=%cI "$HEAD_FULL")"
    commit_url="https://github.com/$REPO_SLUG/commit/$HEAD_FULL"
    NOTES_FILE="$WORKSPACE/release-notes.md"
    {
        printf '**Built from commit [`%s`](%s)** (%s).\n\n' "$HEAD_FULL" "$commit_url" "$built_at"
        printf '%s\n\n' "$notes_body"
        printf '### Verify\n\n'
        printf 'All four artifacts matched across two independent exact-commit build snapshots. Verify the downloaded files with:\n\n'
        printf '```text\nsha256sum -c SHA256SUMS\n```\n'
    } > "$NOTES_FILE"
    chmod 0400 "$NOTES_FILE"
}

write_release_payload() {
    local destination="$1" draft="$2"
    python3 - "$destination" "$TAG" "$HEAD_FULL" "$TITLE" "$NOTES_FILE" "$draft" "$PRERELEASE" <<'PY'
import json
import os
import sys
from pathlib import Path

destination, tag, commit, title, notes, draft, prerelease = sys.argv[1:]
payload = {
    "tag_name": tag,
    "target_commitish": commit,
    "name": title,
    "body": Path(notes).read_text(encoding="utf-8"),
    "draft": draft == "1",
    "prerelease": prerelease == "1",
    "make_latest": "false",
}
descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
}

validate_release_json() {
    local json_file="$1" expected_draft="$2" expected_asset_count="$3" expected_id="${4:-}"
    local identity
    local -a fields=()
    identity="$(python3 - "$json_file" "$TAG" "$TITLE" "$NOTES_FILE" "$HEAD_FULL" "$PRERELEASE" \
        "$expected_draft" "$expected_asset_count" "$ARTIFACT_DIR" "$REPO_SLUG" "$expected_id" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

(json_path, tag, title, notes_path, commit, prerelease, draft, asset_count,
 artifact_dir, repository, expected_id) = sys.argv[1:]

def object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(f"duplicate JSON key: {key}")
        value[key] = item
    return value

def reject_nonfinite(value):
    raise SystemExit(f"non-finite JSON number: {value}")

try:
    value = json.loads(
        Path(json_path).read_text(encoding="utf-8"),
        object_pairs_hook=object_without_duplicates,
        parse_constant=reject_nonfinite,
    )
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"malformed GitHub release JSON: {exc}")
if not isinstance(value, dict):
    raise SystemExit("GitHub release response must be an object")
required = {
    "id": int, "tag_name": str, "name": str, "body": str, "draft": bool,
    "prerelease": bool, "target_commitish": str, "immutable": bool, "assets": list,
    "url": str, "assets_url": str, "upload_url": str, "html_url": str,
    "created_at": str,
}
for key, expected_type in required.items():
    if key not in value or type(value[key]) is not expected_type:
        raise SystemExit(f"GitHub release field {key} has a hostile or missing type")
release_id = value["id"]
if release_id <= 0 or (expected_id and release_id != int(expected_id)):
    raise SystemExit("GitHub release numeric ID differs from the transaction")
expected_body = Path(notes_path).read_text(encoding="utf-8")
if value["tag_name"] != tag or value["name"] != title or value["body"] != expected_body:
    raise SystemExit("GitHub release identity, title, or body differs from the immutable snapshot")
if value["target_commitish"] != commit:
    raise SystemExit("GitHub release target_commitish differs from the pinned commit")
if value["prerelease"] is not (prerelease == "1") or value["draft"] is not (draft == "1"):
    raise SystemExit("GitHub release draft/prerelease state differs from the transaction")
if value["immutable"] is not (draft == "0"):
    raise SystemExit("GitHub release immutability contradicts its publication state")
published = value.get("published_at")
if (draft == "1" and published is not None) or (draft == "0" and type(published) is not str):
    raise SystemExit("GitHub release publication timestamp contradicts draft state")
api_base = f"https://api.github.com/repos/{repository}/releases/{release_id}"
if value["url"] != api_base or value["assets_url"] != f"{api_base}/assets":
    raise SystemExit("GitHub release API URLs differ from its numeric ID")
expected_upload = f"https://uploads.github.com/repos/{repository}/releases/{release_id}/assets{{?name,label}}"
if value["upload_url"] != expected_upload:
    raise SystemExit("GitHub release upload URL differs from its numeric ID")
if value["html_url"] != f"https://github.com/{repository}/releases/tag/{tag}":
    raise SystemExit("GitHub release HTML URL differs from its tag")
assets = value["assets"]
if len(assets) != int(asset_count):
    raise SystemExit("GitHub release embedded asset count is not exact")
expected_names = {path.name for path in Path(artifact_dir).iterdir()}
seen = set()
for asset in assets:
    if not isinstance(asset, dict):
        raise SystemExit("GitHub release asset schema is hostile or malformed")
    for key, expected_type in {"id": int, "name": str, "size": int, "state": str, "digest": str}.items():
        if key not in asset or type(asset[key]) is not expected_type:
            raise SystemExit(f"GitHub release asset field {key} has a hostile type")
    name = asset["name"]
    path = Path(artifact_dir) / name
    if name in seen or name not in expected_names or asset["id"] <= 0 or asset["size"] <= 0:
        raise SystemExit("GitHub release asset identity is invalid")
    if asset["state"] != "uploaded" or asset["size"] != path.stat().st_size:
        raise SystemExit("GitHub release asset size or state differs from the immutable local asset")
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    if asset["digest"] != digest:
        raise SystemExit("GitHub release asset server digest differs from the immutable local asset")
    seen.add(name)
if assets and seen != expected_names:
    raise SystemExit("GitHub release asset names are not the exact five-file set")
print(release_id)
print(value["upload_url"])
PY
)" || return 1
    mapfile -t fields <<< "$identity"
    [ "${#fields[@]}" -eq 2 ] && [[ "${fields[0]}" =~ ^[1-9][0-9]*$ ]] \
        || return 1
    if [ -n "$RELEASE_ID" ] && [ "$RELEASE_ID" != "${fields[0]}" ]; then
        return 1
    fi
    RELEASE_ID="${fields[0]}"
    UPLOAD_URL="${fields[1]}"
}

validate_asset_json() {
    local json_file="$1" expected_name="$2"
    python3 - "$json_file" "$expected_name" "$ARTIFACT_DIR/$expected_name" "$REPO_SLUG" "$TAG" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

json_path, expected_name, local_path, repository, tag = sys.argv[1:]
def object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(f"duplicate JSON key: {key}")
        value[key] = item
    return value
def reject_nonfinite(value):
    raise SystemExit(f"non-finite JSON number: {value}")
value = json.loads(
    Path(json_path).read_text(encoding="utf-8"),
    object_pairs_hook=object_without_duplicates,
    parse_constant=reject_nonfinite,
)
if not isinstance(value, dict):
    raise SystemExit("GitHub asset response must be an object")
required = {"id": int, "name": str, "state": str, "content_type": str, "size": int, "digest": str,
            "url": str, "browser_download_url": str, "download_count": int}
for key, expected in required.items():
    if key not in value or type(value[key]) is not expected:
        raise SystemExit(f"GitHub asset field {key} has a hostile or missing type")
path = Path(local_path)
asset_id = value["id"]
if asset_id <= 0 or value["name"] != expected_name or value["state"] != "uploaded":
    raise SystemExit("GitHub asset identity or state is invalid")
if value["content_type"] != "application/octet-stream" or value["size"] != path.stat().st_size:
    raise SystemExit("GitHub asset content type or size differs from upload")
if value["digest"] != "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest():
    raise SystemExit("GitHub asset server digest differs from upload")
if value["url"] != f"https://api.github.com/repos/{repository}/releases/assets/{asset_id}":
    raise SystemExit("GitHub asset API URL differs from its numeric ID")
if value["browser_download_url"] != f"https://github.com/{repository}/releases/download/{tag}/{expected_name}":
    raise SystemExit("GitHub asset download URL differs from its release identity")
if value["download_count"] < 0:
    raise SystemExit("GitHub asset download count is invalid")
print(asset_id)
PY
}

list_remote_assets() {
    local phase="$1" expected_count="$2" json_file mapping_file
    json_file="$WORKSPACE/assets-$phase.json"
    mapping_file="$WORKSPACE/assets-$phase.tsv"
    gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID/assets?per_page=100" --method GET --paginate > "$json_file" \
        || die "$phase: cannot exhaustively enumerate release assets by numeric release ID"
    python3 - "$json_file" "$mapping_file" "$expected_count" "$ARTIFACT_DIR" "$REPO_SLUG" "$TAG" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

json_path, mapping_path, expected_count_text, artifact_dir, repository, tag = sys.argv[1:]
text = Path(json_path).read_text(encoding="utf-8")

def dict_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value

def reject_nonfinite(value):
    raise ValueError(f"non-finite JSON number: {value}")

decoder = json.JSONDecoder(
    object_pairs_hook=dict_without_duplicates,
    parse_constant=reject_nonfinite,
)

pages = []
offset = 0
while True:
    while offset < len(text) and text[offset].isspace():
        offset += 1
    if offset == len(text):
        break
    page, offset = decoder.raw_decode(text, offset)
    if not isinstance(page, list) or len(page) > 100:
        raise SystemExit("GitHub asset page is not a bounded JSON array")
    pages.append(page)
if not pages:
    raise SystemExit("GitHub asset pagination returned no JSON page")
assets = [asset for page in pages for asset in page]
expected_count = int(expected_count_text)
expected_order = ["rustdesk-x86_64.deb", "rustdesk-arm64.apk", "rustdesk-setup.exe", "rustdesk.msi", "SHA256SUMS"]
expected_names = set() if expected_count == 0 else set(expected_order)
if expected_count not in (0, 5) or len(assets) != expected_count:
    raise SystemExit("GitHub release asset count is not exact")
seen_names = set()
seen_ids = set()
mapping = {}
for asset in assets:
    if not isinstance(asset, dict):
        raise SystemExit("GitHub asset inventory entry is not an object")
    required = {"id": int, "name": str, "state": str, "content_type": str, "size": int, "digest": str,
                "url": str, "browser_download_url": str, "download_count": int}
    for key, expected in required.items():
        if key not in asset or type(asset[key]) is not expected:
            raise SystemExit(f"GitHub asset inventory field {key} has a hostile type")
    asset_id, name = asset["id"], asset["name"]
    if asset_id <= 0 or asset_id in seen_ids or name in seen_names or name not in expected_names:
        raise SystemExit("GitHub asset inventory identity is duplicate or unexpected")
    path = Path(artifact_dir) / name
    if asset["state"] != "uploaded" or asset["content_type"] != "application/octet-stream":
        raise SystemExit("GitHub asset inventory contains a non-uploaded or mistyped asset")
    if asset["size"] != path.stat().st_size or asset["size"] <= 0:
        raise SystemExit("GitHub release asset size differs from the immutable local asset")
    if asset["digest"] != "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest():
        raise SystemExit("GitHub release asset server digest differs from the immutable local asset")
    if asset["url"] != f"https://api.github.com/repos/{repository}/releases/assets/{asset_id}":
        raise SystemExit("GitHub asset inventory API URL differs from its numeric ID")
    if asset["browser_download_url"] != f"https://github.com/{repository}/releases/download/{tag}/{name}":
        raise SystemExit("GitHub asset inventory download URL differs from its release identity")
    if asset["download_count"] < 0:
        raise SystemExit("GitHub asset inventory download count is invalid")
    seen_ids.add(asset_id)
    seen_names.add(name)
    mapping[name] = asset_id
if seen_names != expected_names:
    raise SystemExit("GitHub asset inventory is not the exact expected name set")
descriptor = os.open(mapping_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    for name in expected_order:
        if name in mapping:
            stream.write(f"{name}\t{mapping[name]}\n")
PY
    printf '%s' "$mapping_file"
}

download_and_verify_remote_assets() {
    local phase="$1" directory mapping name asset_id local_hash remote_hash
    mapping="$(list_remote_assets "$phase-download-inventory" 5)"
    directory="$WORKSPACE/download-$phase"
    install -d -m 0700 "$directory"
    while IFS=$'\t' read -r name asset_id; do
        [[ "$asset_id" =~ ^[1-9][0-9]*$ ]] || die "$phase: validated asset mapping is malformed"
        gh_api "repos/$REPO_SLUG/releases/assets/$asset_id" --method GET \
            -H 'Accept: application/octet-stream' > "$directory/$name" \
            || die "$phase: cannot download $name by numeric asset ID"
        chmod 0400 "$directory/$name"
        local_hash="$(sha256sum "$ARTIFACT_DIR/$name" | awk '{print $1}')"
        remote_hash="$(sha256sum "$directory/$name" | awk '{print $1}')"
        [ "$remote_hash" = "$local_hash" ] || die "$phase: remote digest differs for $name"
    done < "$mapping"
    assert_exact_file_set "$directory"
    strict_manifest_proof "$directory"
}

view_and_validate_release() {
    local phase="$1" expected_draft="$2" expected_assets="$3" json_file
    [ -n "$RELEASE_ID" ] || die "$phase: release numeric ID is absent"
    json_file="$WORKSPACE/view-$phase.json"
    gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method GET > "$json_file" \
        || die "$phase: cannot query release by numeric ID"
    validate_release_json "$json_file" "$expected_draft" "$expected_assets" "$RELEASE_ID" \
        || die "$phase: GitHub release response is invalid"
    list_remote_assets "$phase-inventory" "$expected_assets" >/dev/null
}

upload_release_asset() {
    local name="$1" response asset_id expected_upload
    expected_upload="https://uploads.github.com/repos/$REPO_SLUG/releases/$RELEASE_ID/assets{?name,label}"
    [ "$UPLOAD_URL" = "$expected_upload" ] || die "release upload URL changed before $name"
    response="$WORKSPACE/upload-$name.json"
    TRANSACTION_STATE="asset-upload-requested:$name"
    gh_api "${UPLOAD_URL%\{\?name,label\}}?name=$name" --method POST \
        -H 'Content-Type: application/octet-stream' --input "$ARTIFACT_DIR/$name" > "$response" \
        || die "asset upload failed or became uncertain for $name; the draft is retained"
    asset_id="$(validate_asset_json "$response" "$name")" \
        || die "asset upload response is invalid for $name; the draft is retained"
    [[ "$asset_id" =~ ^[1-9][0-9]*$ ]] || die "asset upload returned an invalid numeric ID for $name"
    TRANSACTION_STATE="asset-uploaded:$name:$asset_id"
}

final_publication_barrier() {
    if [ "$FIXTURE_MODE" -eq 0 ]; then
        assert_publication_source "final pre-publication barrier"
        assert_github_identity "final pre-publication barrier"
        assert_immutable_release_policy "final pre-publication barrier"
        assert_live_origin_master "final pre-publication barrier"
        assert_remote_uniqueness_refs
        strict_manifest_proof "$ARTIFACT_DIR"
        strict_release_inventory "$RELEASE_ID" 1
    else
        printf 'final pre-publication barrier\n' >> "$PUBLISH_STUB_LOG"
        assert_immutable_release_policy "fixture final pre-publication barrier"
    fi
    view_and_validate_release final-barrier 1 5
    download_and_verify_remote_assets final-barrier
}

run_draft_publication_transaction() {
    local create_payload publish_payload create_response publish_response name
    create_payload="$WORKSPACE/create-release.json"
    publish_payload="$WORKSPACE/publish-release.json"
    create_response="$WORKSPACE/create-release-response.json"
    publish_response="$WORKSPACE/publish-release-response.json"
    write_release_payload "$create_payload" 1
    write_release_payload "$publish_payload" 0

    TRANSACTION_STATE=draft-create-requested
    gh_api "repos/$REPO_SLUG/releases" --method POST --input "$create_payload" > "$create_response" \
        || die "draft creation failed or became uncertain after uniqueness-ref publication"
    TRANSACTION_STATE=draft-create-response-unvalidated
    validate_release_json "$create_response" 1 0 \
        || die "draft creation response is invalid"
    TRANSACTION_STATE="draft-created:$RELEASE_ID"
    view_and_validate_release draft-created 1 0

    for name in "${PUBLICATION_ASSETS[@]}"; do
        upload_release_asset "$name"
    done
    TRANSACTION_STATE="draft-assets-uploaded:$RELEASE_ID"
    view_and_validate_release draft-uploaded 1 5
    download_and_verify_remote_assets draft
    final_publication_barrier

    TRANSACTION_STATE="publish-requested:$RELEASE_ID"
    gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method PATCH --input "$publish_payload" > "$publish_response" \
        || die "verified draft publication failed or became uncertain"
    TRANSACTION_STATE="published-response-unvalidated:$RELEASE_ID"
    validate_release_json "$publish_response" 0 5 "$RELEASE_ID" \
        || die "published release response is invalid"
    view_and_validate_release published 0 5
    download_and_verify_remote_assets published
    TRANSACTION_STATE="published-verified:$RELEASE_ID"
}

strict_release_inventory() {
    local list_json="$WORKSPACE/releases.json" inventory_file="$WORKSPACE/release-inventory.tsv"
    local confirm_json="$WORKSPACE/releases-confirm.json" owned_id="${1:-}" owned_draft="${2:-}"
    local encoded release_id tag view_json resolved conflict owned_seen=0
    if [ -n "$owned_id" ]; then
        [[ "$owned_id" =~ ^[1-9][0-9]*$ ]] && [[ "$owned_draft" =~ ^[01]$ ]] \
            || die "owned release inventory expectation is malformed"
    fi
    gh_api "repos/$REPO_SLUG/releases?per_page=100" --method GET --paginate > "$list_json" \
        || die "cannot exhaustively enumerate releases, including drafts"
    gh_api "repos/$REPO_SLUG/releases?per_page=100" --method GET --paginate > "$confirm_json" \
        || die "cannot repeat the exhaustive release inventory"
    cmp -s "$list_json" "$confirm_json" || die "GitHub release inventory changed between exhaustive passes"
    python3 - "$list_json" > "$inventory_file" <<'PY'
import base64
import json
import sys
from pathlib import Path

def object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value

def reject_nonfinite(value):
    raise ValueError(f"non-finite JSON number: {value}")

text = Path(sys.argv[1]).read_text(encoding="utf-8")
decoder = json.JSONDecoder(
    object_pairs_hook=object_without_duplicates,
    parse_constant=reject_nonfinite,
)
pages = []
offset = 0
while True:
    while offset < len(text) and text[offset].isspace():
        offset += 1
    if offset == len(text):
        break
    page, offset = decoder.raw_decode(text, offset)
    if not isinstance(page, list) or len(page) > 100:
        raise SystemExit("GitHub release page is not a bounded JSON array")
    pages.append(page)
if not pages:
    raise SystemExit("GitHub release pagination returned no JSON page")
seen_ids = set()
seen_tags = set()
for release in (item for page in pages for item in page):
    if not isinstance(release, dict) or type(release.get("id")) is not int or type(release.get("tag_name")) is not str:
        raise SystemExit("GitHub release-list entry has a hostile identity schema")
    release_id, tag = release["id"], release["tag_name"]
    if release_id <= 0 or not tag or release_id in seen_ids or tag in seen_tags:
        raise SystemExit("GitHub release-list identity is duplicate or invalid")
    seen_ids.add(release_id)
    seen_tags.add(tag)
    encoded = base64.b64encode(tag.encode("utf-8")).decode("ascii")
    print(f"{encoded}\t{release_id}")
PY

    git_network -C "$NETWORK_REPO" fetch --quiet --force --prune --no-tags "$ORIGIN_URL" \
        '+refs/tags/*:refs/tags/*' || die "cannot fetch the complete remote tag namespace"
    while IFS=$'\t' read -r encoded release_id; do
        [ -n "$encoded" ] || continue
        tag="$(printf '%s' "$encoded" | base64 --decode)" || die "cannot decode a validated release tag"
        [[ "$release_id" =~ ^[1-9][0-9]*$ ]] || die "release inventory numeric ID is malformed"
        git_closed check-ref-format "refs/tags/$tag" >/dev/null \
            || die "GitHub returned a release tag that is not a valid Git ref"
        resolved="$(git_closed -C "$NETWORK_REPO" rev-parse --verify "refs/tags/$tag^{commit}" 2>/dev/null)" \
            || die "release tag $tag does not resolve to a commit"
        view_json="$WORKSPACE/existing-$release_id.json"
        gh_api "repos/$REPO_SLUG/releases/$release_id" --method GET > "$view_json" \
            || die "cannot inspect existing release by numeric ID $release_id"
        if [ -n "$owned_id" ] && [ "$release_id" = "$owned_id" ]; then
            [ "$tag" = "$TAG" ] && [ "$resolved" = "$HEAD_FULL" ] \
                || die "owned release inventory identity differs from the pinned transaction"
            validate_release_json "$view_json" "$owned_draft" 5 "$owned_id" \
                || die "owned release inventory response is invalid"
            owned_seen=$((owned_seen + 1))
            continue
        fi
        conflict="$(python3 - "$view_json" "$release_id" "$tag" "$TAG" "$TITLE" "$FORK_VER" "$HEAD_FULL" "$resolved" <<'PY'
import json
import sys
from pathlib import Path

def object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(f"duplicate JSON key: {key}")
        value[key] = item
    return value

def reject_nonfinite(value):
    raise SystemExit(f"non-finite JSON number: {value}")

value = json.loads(
    Path(sys.argv[1]).read_text(encoding="utf-8"),
    object_pairs_hook=object_without_duplicates,
    parse_constant=reject_nonfinite,
)
if not isinstance(value, dict):
    raise SystemExit("existing release response is not an object")
required = {"id": int, "tag_name": str, "draft": bool, "prerelease": bool, "target_commitish": str, "assets": list}
for key, expected in required.items():
    if key not in value or type(value[key]) is not expected:
        raise SystemExit(f"existing release field {key} has a hostile type")
name = value.get("name")
body = value.get("body")
if name is not None and type(name) is not str:
    raise SystemExit("existing release name has a hostile type")
if body is not None and type(body) is not str:
    raise SystemExit("existing release body has a hostile type")
release_id, existing_tag, expected_tag, expected_title, version, head, resolved = sys.argv[2:]
if value["id"] != int(release_id) or value["tag_name"] != existing_tag:
    raise SystemExit("release numeric ID or tag differs from the enumerated release")
if existing_tag == expected_tag:
    print(f"release tag {expected_tag} already exists")
elif name == expected_title or f"## {version} " in (body or ""):
    print(f"fork version {version} already exists in release {existing_tag}")
elif resolved == head:
    print(f"commit {head} is already released as {existing_tag}")
PY
        )" || die "existing release schema is invalid"
        [ -z "$conflict" ] || die "$conflict"
    done < "$inventory_file"
    if [ -n "$owned_id" ]; then
        [ "$owned_seen" -eq 1 ] || die "owned release is missing or duplicated in exhaustive inventory"
    else
        git_closed -C "$NETWORK_REPO" rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1 \
            && die "remote release tag already exists: $TAG"
    fi
    return 0
}

push_atomic_uniqueness_refs() {
    git_closed -C "$NETWORK_REPO" update-ref "refs/tags/$TAG" "$HEAD_FULL" "" \
        || die "cannot create the private release tag ref"
    TRANSACTION_STATE=uniqueness-refs-push-requested
    git_network -C "$NETWORK_REPO" push --atomic "$ORIGIN_URL" "refs/tags/$TAG" \
        || die "atomic remote uniqueness-ref creation failed; reconcile the local/remote tag before retrying"
    TRANSACTION_STATE=uniqueness-ref-pushed
}

assert_remote_uniqueness_refs() {
    local output sha ref extra
    local -a rows=()
    output="$(git_network -C "$NETWORK_REPO" ls-remote --exit-code "$ORIGIN_URL" \
        "refs/tags/$TAG" 2>/dev/null)" \
        || die "cannot verify the remote uniqueness ref"
    mapfile -t rows <<< "$output"
    [ "${#rows[@]}" -eq 1 ] || die "remote uniqueness-ref query did not return exactly one ref"
    local seen_release=0
    for row in "${rows[@]}"; do
        IFS=$'\t' read -r sha ref extra <<< "$row"
        [ "$sha" = "$HEAD_FULL" ] && [ -z "$extra" ] \
            || die "remote uniqueness ref does not resolve to the pinned commit"
        case "$ref" in
            "refs/tags/$TAG") seen_release=$((seen_release + 1)) ;;
            *) die "remote uniqueness query returned an unexpected ref" ;;
        esac
    done
    [ "$seen_release" -eq 1 ] || die "remote uniqueness ref is duplicated or missing"
}

write_stub_gh() {
    local destination="$1"
    cat > "$destination" <<'PY'
#!/usr/bin/env python3
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

args = sys.argv[1:]
state = Path(os.environ["PUBLISH_STUB_STATE"])
log = Path(os.environ["PUBLISH_STUB_LOG"])
if os.environ.get("GH_HOST") != "github.com":
    raise SystemExit("missing exact GitHub host binding")
if os.environ.get("GH_CONFIG_DIR") != os.environ.get("PUBLISH_STUB_GH_CONFIG"):
    raise SystemExit("missing private GitHub CLI configuration binding")
if not args or args.pop(0) != "api":
    raise SystemExit("publisher used a non-REST GitHub CLI command")
method = "GET"
headers = []
input_path = None
paginate = False
endpoint = None
index = 0
while index < len(args):
    item = args[index]
    if item in ("--hostname", "-H", "--method", "--input"):
        if index + 1 >= len(args):
            raise SystemExit(f"missing value for {item}")
        value = args[index + 1]
        if item == "--hostname" and value != "github.com":
            raise SystemExit("wrong GitHub API hostname")
        elif item == "-H":
            headers.append(value)
        elif item == "--method":
            method = value
        else:
            input_path = value
        index += 2
    elif item == "--paginate":
        paginate = True
        index += 1
    elif endpoint is None:
        endpoint = item
        index += 1
    else:
        raise SystemExit(f"unsupported gh api argument: {item}")
if endpoint is None:
    raise SystemExit("missing REST endpoint")
if "Accept: application/vnd.github+json" not in headers:
    raise SystemExit("missing GitHub JSON Accept header")
if "X-GitHub-Api-Version: 2026-03-10" not in headers:
    raise SystemExit("missing pinned GitHub API version")
with log.open("a", encoding="utf-8") as handle:
    handle.write(f"api {method} {endpoint}\n")
remote = state / "assets"
remote.mkdir(exist_ok=True)
metadata_path = state / "metadata.json"
ids_path = state / "asset-ids.json"
ids = json.loads(ids_path.read_text(encoding="utf-8")) if ids_path.exists() else {}
repository = "fixture-owner/fixture-repo"
release_id = 71

def asset_object(name):
    path = remote / name
    asset_id = ids[name]
    tag = json.loads(metadata_path.read_text(encoding="utf-8"))["tag_name"]
    size = path.stat().st_size
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    hostile = os.environ.get("PUBLISH_STUB_HOSTILE", "")
    if hostile == "asset-size":
        size = str(size)
    elif hostile == "asset-digest":
        digest = "sha256:" + "0" * 64
    return {
        "id": asset_id,
        "name": name,
        "label": None,
        "state": "uploaded",
        "content_type": "application/octet-stream",
        "size": size,
        "digest": digest,
        "download_count": 0,
        "url": f"https://api.github.com/repos/{repository}/releases/assets/{asset_id}",
        "browser_download_url": f"https://github.com/{repository}/releases/download/{tag}/{name}",
    }

def release_object():
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["assets"] = [asset_object(name) for name in sorted(ids)]
    hostile = os.environ.get("PUBLISH_STUB_HOSTILE")
    if hostile == "release-id":
        metadata["id"] = True
    elif hostile == "nonfinite-json":
        metadata["future_metric"] = float("nan")
    return metadata

release_collection = f"repos/{repository}/releases"
if endpoint == f"repos/{repository}/immutable-releases" and method == "GET":
    print(json.dumps({"enabled": True, "enforced_by_owner": False}))
elif endpoint == f"{release_collection}?per_page=100" and method == "GET":
    if not paginate:
        raise SystemExit("release inventory was not exhaustive")
    print("[]", end="")
elif endpoint == release_collection and method == "POST":
    if input_path is None or metadata_path.exists():
        raise SystemExit("invalid draft creation")
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    if payload.get("draft") is not True or payload.get("make_latest") != "false":
        raise SystemExit("release was not created as an explicit draft")
    tag = payload["tag_name"]
    metadata = {
        "id": release_id,
        "tag_name": tag,
        "target_commitish": payload["target_commitish"],
        "name": payload["name"],
        "body": payload["body"],
        "draft": True,
        "prerelease": payload["prerelease"],
        "immutable": False,
        "created_at": "2026-07-13T00:00:00Z",
        "published_at": None,
        "url": f"https://api.github.com/repos/{repository}/releases/{release_id}",
        "assets_url": f"https://api.github.com/repos/{repository}/releases/{release_id}/assets",
        "upload_url": f"https://uploads.github.com/repos/{repository}/releases/{release_id}/assets{{?name,label}}",
        "html_url": f"https://github.com/{repository}/releases/tag/{tag}",
    }
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    print(json.dumps(release_object()))
elif endpoint == f"{release_collection}/{release_id}" and method == "GET":
    print(json.dumps(release_object()))
elif endpoint == f"{release_collection}/{release_id}" and method == "PATCH":
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    if payload.get("draft") is not False or payload.get("make_latest") != "false":
        raise SystemExit("release publication payload is invalid")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    for key in ("tag_name", "target_commitish", "name", "body", "draft", "prerelease"):
        metadata[key] = payload[key]
    metadata["published_at"] = "2026-07-13T01:00:00Z"
    metadata["immutable"] = True
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    print(json.dumps(release_object()))
elif endpoint == f"{release_collection}/{release_id}/assets?per_page=100" and method == "GET":
    if not paginate:
        raise SystemExit("asset inventory was not exhaustive")
    assets = [asset_object(name) for name in sorted(ids)]
    split = min(2, len(assets))
    print(json.dumps(assets[:split]) + (json.dumps(assets[split:]) if assets else ""), end="")
elif endpoint.startswith(f"https://uploads.github.com/repos/{repository}/releases/{release_id}/assets?") and method == "POST":
    query = parse_qs(urlparse(endpoint).query, strict_parsing=True)
    if set(query) != {"name"} or len(query["name"]) != 1 or input_path is None:
        raise SystemExit("asset upload query is invalid")
    name = query["name"][0]
    if name in ids or Path(input_path).name != name:
        raise SystemExit("asset upload identity is duplicate or mismatched")
    shutil.copyfile(input_path, remote / name)
    ids[name] = 100 + len(ids)
    ids_path.write_text(json.dumps(ids), encoding="utf-8")
    print(json.dumps(asset_object(name)))
elif endpoint.startswith(f"repos/{repository}/releases/assets/") and method == "GET":
    asset_id = int(endpoint.rsplit("/", 1)[1])
    matches = [name for name, value in ids.items() if value == asset_id]
    if len(matches) != 1 or "Accept: application/octet-stream" not in headers:
        raise SystemExit("numeric asset download is invalid")
    data = (remote / matches[0]).read_bytes()
    if os.environ.get("PUBLISH_STUB_HOSTILE") == "download-bytes":
        data += b"corruption"
    sys.stdout.buffer.write(data)
else:
    raise SystemExit(f"unsupported stub gh api call: {method} {endpoint}")
PY
    chmod 0700 "$destination"
}

write_stub_git() {
    local destination="$1"
    cat > "$destination" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
joined=" $* "
case "$joined" in
    *" rev-parse -q --verify refs/tags/"*) exit 1 ;;
    *" update-ref refs/tags/"*) exit 0 ;;
    *" fetch --quiet --force --prune --no-tags "*) exit 0 ;;
    *" push --atomic "*)
        printf 'git push --atomic\n' >> "$PUBLISH_STUB_LOG"
        exit 0
        ;;
    *" ls-remote --exit-code "*)
        printf '%s\t%s\n' \
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
            refs/tags/fork-version-1.4.7-hardened.6-commit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        exit 0
        ;;
    *) printf 'unexpected stub git invocation: %s\n' "$*" >&2; exit 1 ;;
esac
SH
    chmod 0700 "$destination"
}

run_self_test() {
    local stub_bin order_log name json_file barrier_line patch_line
    FIXTURE_MODE=1
    create_private_workspace
    stub_bin="$WORKSPACE/bin"
    install -d -m 0700 "$stub_bin" "$WORKSPACE/stub-state"
    order_log="$WORKSPACE/order.log"
    : > "$order_log"
    write_stub_gh "$stub_bin/gh"
    write_stub_git "$stub_bin/git"
    GH_BIN="$stub_bin/gh"
    GIT_BIN="$stub_bin/git"
    NETWORK_REPO="$WORKSPACE/network.git"
    ORIGIN_URL=https://github.com/fixture-owner/fixture-repo.git
    REPO_SLUG=fixture-owner/fixture-repo
    HEAD_FULL=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    FORK_VER=1.4.7-hardened.6
    TAG=fork-version-1.4.7-hardened.6-commit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    TITLE='RustDesk Hardened Fork 1.4.7-hardened.6'
    {
        printf 'version: 1\n'
        printf 'git_protocol: https\n'
        printf 'prompt: disabled\n'
        printf 'http_unix_socket: ""\n'
        printf 'telemetry: disabled\n'
    } > "$GH_CONFIG_SNAPSHOT/config.yml"
    printf 'github.com:\n  oauth_token: fixture\n' > "$GH_CONFIG_SNAPSHOT/hosts.yml"
    chmod 0400 "$GH_CONFIG_SNAPSHOT/config.yml" "$GH_CONFIG_SNAPSHOT/hosts.yml"
    chmod 0500 "$GH_CONFIG_SNAPSHOT"
    GH_CONFIG_DIGEST="$(cd "$GH_CONFIG_SNAPSHOT" && sha256sum config.yml hosts.yml | sha256sum | awk '{print $1}')"
    export PUBLISH_STUB_STATE="$WORKSPACE/stub-state" PUBLISH_STUB_LOG="$order_log" \
        PUBLISH_STUB_GH_CONFIG="$GH_CONFIG_SNAPSHOT"
    for name in "${CANONICAL_ASSETS[@]}"; do printf '%s\n' "$name" > "$ARTIFACT_DIR/$name"; chmod 0400 "$ARTIFACT_DIR/$name"; done
    {
        printf '# rustdesk-fork release manifest v1\n'
        printf '# fork-version: %s\n' "$FORK_VER"
        printf '# commit: %s\n' "$HEAD_FULL"
        printf '# source-date-epoch: %s\n' "$SOURCE_DATE_EPOCH_PIN"
        printf '# reproducibility: independent-snapshots-a-equals-b\n'
        (cd "$ARTIFACT_DIR" && sha256sum "${CANONICAL_ASSETS[@]}")
    } > "$ARTIFACT_DIR/SHA256SUMS"
    chmod 0400 "$ARTIFACT_DIR/SHA256SUMS"
    NOTES_FILE="$WORKSPACE/notes.md"
    printf 'fixture notes\n' > "$NOTES_FILE"
    chmod 0400 "$NOTES_FILE"
    strict_manifest_proof "$ARTIFACT_DIR"
    strict_release_inventory
    assert_immutable_release_policy "publisher self-test"
    push_atomic_uniqueness_refs
    assert_remote_uniqueness_refs
    run_draft_publication_transaction
    [ "$(grep -c '^api POST https://uploads.github.com/' "$order_log")" -eq 5 ] \
        || die "publisher self-test did not upload exactly five numeric-release assets"
    [ "$(grep -c '^api PATCH repos/fixture-owner/fixture-repo/releases/71$' "$order_log")" -eq 1 ] \
        || die "publisher self-test did not make exactly one numeric release publication"
    barrier_line="$(grep -n '^final pre-publication barrier$' "$order_log" | cut -d: -f1)"
    patch_line="$(grep -n '^api PATCH repos/fixture-owner/fixture-repo/releases/71$' "$order_log" | cut -d: -f1)"
    [[ "$barrier_line" =~ ^[0-9]+$ ]] && [[ "$patch_line" =~ ^[0-9]+$ ]] && [ "$barrier_line" -lt "$patch_line" ] \
        || die "publisher self-test publication bypassed the final barrier"
    export PUBLISH_STUB_HOSTILE=asset-size
    json_file="$WORKSPACE/hostile.json"
    gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method GET > "$json_file"
    if validate_release_json "$json_file" 0 5 >/dev/null 2>&1; then
        die "publisher self-test accepted a hostile asset schema"
    fi
    export PUBLISH_STUB_HOSTILE=asset-digest
    if (trap - EXIT HUP INT TERM; view_and_validate_release hostile-digest 0 5) >/dev/null 2>&1; then
        die "publisher self-test accepted a hostile server digest"
    fi
    export PUBLISH_STUB_HOSTILE=release-id
    gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method GET > "$WORKSPACE/hostile-id.json"
    if validate_release_json "$WORKSPACE/hostile-id.json" 0 5 "$RELEASE_ID" >/dev/null 2>&1; then
        die "publisher self-test accepted a hostile numeric release ID"
    fi
    export PUBLISH_STUB_HOSTILE=nonfinite-json
    gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method GET > "$WORKSPACE/hostile-nonfinite.json"
    if validate_release_json "$WORKSPACE/hostile-nonfinite.json" 0 5 "$RELEASE_ID" >/dev/null 2>&1; then
        die "publisher self-test accepted a non-finite JSON number"
    fi
    export PUBLISH_STUB_HOSTILE=download-bytes
    if (trap - EXIT HUP INT TERM; download_and_verify_remote_assets hostile-download) >/dev/null 2>&1; then
        die "publisher self-test accepted hostile downloaded bytes"
    fi
    unset PUBLISH_STUB_HOSTILE
    log "publish-github-release self-test: OK"
}

main() {
    if [ "$SELF_TEST" -eq 1 ]; then
        run_self_test
        return 0
    fi
    require_cmd git gh python3 sha256sum flock base64 timeout
    acquire_publication_lock
    HEAD_FULL="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "cannot resolve repository HEAD"
    create_private_workspace
    initialize_gh_config_snapshot
    assert_publication_source "publication preflight"
    assert_github_identity "publication preflight"
    assert_immutable_release_policy "publication preflight"
    initialize_network_repo
    assert_live_origin_master "publication preflight"
    [ -d "$SOURCE_DIST" ] && [ ! -L "$SOURCE_DIST" ] \
        && [ "$(stat -c '%a' "$SOURCE_DIST")" = 555 ] \
        || die "dist must be the immutable mode-0555 output of build-release.sh"
    create_immutable_snapshot
    TAG="fork-version-$FORK_VER-commit-$HEAD_FULL"
    TITLE="RustDesk Hardened Fork $FORK_VER"
    git_closed check-ref-format "refs/tags/$TAG" >/dev/null || die "release tag is not a valid Git ref"
    write_release_notes
    strict_release_inventory
    assert_publication_source "immediately before publication"
    assert_immutable_release_policy "immediately before publication"
    assert_live_origin_master "immediately before publication"
    strict_manifest_proof "$ARTIFACT_DIR"
    push_atomic_uniqueness_refs
    assert_remote_uniqueness_refs
    run_draft_publication_transaction
    assert_publication_source "publication completion"
    assert_github_identity "publication completion"
    assert_immutable_release_policy "publication completion"
    assert_live_origin_master "publication completion"
    assert_remote_uniqueness_refs
    strict_manifest_proof "$ARTIFACT_DIR"
    strict_release_inventory "$RELEASE_ID" 0
    log "release publication verified: $TAG ($TRANSACTION_STATE)"
}

main
