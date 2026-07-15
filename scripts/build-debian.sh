#!/usr/bin/env bash
# scripts/build-debian.sh — Debian x86_64 .deb build (R-B7/B8/B9, §12.1, §17).
#
# Reproduces upstream 1.4.7's OFFICIAL .deb build (R-B7: inherited, not reinvented)
# inside a digest-pinned ubuntu:18.04 container — upstream's own glibc baseline
# (run-on-arch-action) — with EXACTLY two deltas and no others: no code-signing,
# and it runs off GitHub-hosted runners (R-B2). The build is offline
# (--network=none) against the SHA-verified ./online cache (R-B10).
#
# One mode, the good one (R-B9): validate the EXACT pinned env, then abort; fail
# loud; no fallbacks; pin every version from pins.env; verify the artifact.
#
# NOT run as part of "fork creation" — a checked-in build artifact.
set -euo pipefail

if [ -n "${ONLINE_DIR+x}" ]; then
    printf 'build-debian: ONLINE_DIR is not an operator override; release snapshots use RUSTDESK_RELEASE_ONLINE_SNAPSHOT\n' >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
# The §3.2 x64-linux feature set minus hwcodec: CPU-only VP8/VP9.
FEATURES="--flutter --unix-file-copy-paste"
# Determinism (R-B2): SOURCE_DATE_EPOCH is a FIXED pinned epoch (SOURCE_DATE_EPOCH_PIN in pins.env),
# NOT a commit date — so the .deb depends only on the source tree; build.rs honours it. (An
# operator override, `export SOURCE_DATE_EPOCH=...`, still wins.)
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$SOURCE_DATE_EPOCH_PIN}"
# The pinned .deb build image: the digest-pinned ubuntu:18.04 baseline + the system
# build-deps, baked by online-fetch.sh (the ONE networked step) via Dockerfile.deb-builder.
# The compile then runs inside it with --network=none.
IMAGE_ID="${DEB_BUILDER_IMAGE_ID:-}"
BUILD_UID="$(id -u)"
BUILD_GID="$(id -g)"
RELEASE_CHILD=0
ONLINE_SNAPSHOT_PARENT=""
OWNED_WORKSPACE=""

case "${DOCKER_HOST:-unix:///var/run/docker.sock}" in
    unix:///var/run/docker.sock) export DOCKER_HOST=unix:///var/run/docker.sock ;;
    *) die "Docker must use the local unix:///var/run/docker.sock daemon" ;;
esac
for variable in DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS; do
    [ -z "${!variable+x}" ] || die "$variable must not influence a Debian build"
done

cleanup_owned_workspace() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$OWNED_WORKSPACE" ] && [ -d "$OWNED_WORKSPACE" ]; then
        if ! chmod -R u+rwX "$OWNED_WORKSPACE" 2>/dev/null \
            || ! rm -rf -- "$OWNED_WORKSPACE"; then
            status=1
        fi
    fi
    exit "$status"
}

trap cleanup_owned_workspace EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

assert_private_directory() {
    local path="$1" label="$2" resolved metadata
    case "$path" in
        /*) ;;
        *) die "$label must be an absolute path" ;;
    esac
    [ -d "$path" ] && [ ! -L "$path" ] || die "$label must be a real directory"
    resolved="$(readlink -f -- "$path" 2>/dev/null)" || die "$label cannot be resolved"
    [ "$resolved" = "$path" ] || die "$label must be a canonical non-symlinked path"
    metadata="$(stat -c '%u:%a' -- "$path" 2>/dev/null)" || die "$label is absent"
    [ "$metadata" = "$BUILD_UID:700" ] || die "$label must be a current-UID mode-0700 directory"
}

assert_private_docker_config() {
    local config_dir="${DOCKER_CONFIG:-}" metadata
    [ -n "$config_dir" ] || die "release child is missing its private Docker configuration"
    assert_private_directory "$config_dir" "release Docker configuration"
    [ -f "$config_dir/config.json" ] && [ ! -L "$config_dir/config.json" ] \
        || die "release Docker config.json must be a non-symlink regular file"
    metadata="$(stat -c '%u:%a:%h' -- "$config_dir/config.json" 2>/dev/null)" \
        || die "release Docker config.json is absent"
    [ "$metadata" = "$BUILD_UID:600:1" ] \
        || die "release Docker config.json must be a current-UID mode-0600 non-hardlinked file"
    cmp -s "$config_dir/config.json" <(printf '{}\n') \
        || die "Docker config.json must equal the empty canonical configuration"
}

assert_private_online_snapshot() {
    local parent="$1" online bad
    assert_private_directory "$parent" "online snapshot parent"
    online="$parent/online"
    [ -d "$online" ] && [ ! -L "$online" ] || die "online snapshot tree must be a real directory"
    [ "$(stat -c '%u:%a' -- "$online" 2>/dev/null)" = "$BUILD_UID:500" ] \
        || die "online snapshot tree must be a current-UID mode-0500 directory"
    bad="$(find "$online" \( ! -uid "$BUILD_UID" -o \
        \( \( -type f -o -type d \) -perm /0222 \) \) -print -quit)" \
        || die "cannot inspect online snapshot ownership and modes"
    [ -z "$bad" ] || die "online snapshot contains a writable or differently owned path: $bad"
    verify_private_online_snapshot "$parent"
}

prepare_execution_contract() {
    local current
    if [ -n "${RELEASE_SRC_COMMIT:-}" ]; then
        RELEASE_CHILD=1
        [[ "$RELEASE_SRC_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
            || die "RELEASE_SRC_COMMIT must be one full lowercase commit ID"
        current="$(git -c core.hooksPath=/dev/null -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
            || die "cannot resolve release-child source commit"
        [ "$current" = "$RELEASE_SRC_COMMIT" ] || die "release-child source commit does not equal HEAD"
        [ -n "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ] \
            || die "release child requires RUSTDESK_RELEASE_ONLINE_SNAPSHOT"
        [ -n "${RELEASE_DOCKER_IMAGE_ID:-}" ] \
            || die "release child requires RELEASE_DOCKER_IMAGE_ID"
        assert_private_docker_config
        ONLINE_SNAPSHOT_PARENT="$RUSTDESK_RELEASE_ONLINE_SNAPSHOT"
    else
        [ -z "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ] \
            || die "RUSTDESK_RELEASE_ONLINE_SNAPSHOT is release-internal"
        [ -z "${RELEASE_DOCKER_IMAGE_ID:-}" ] \
            || die "RELEASE_DOCKER_IMAGE_ID is release-internal"
        [ -z "${DOCKER_CONFIG+x}" ] || die "DOCKER_CONFIG must not influence a direct Debian build"
        OWNED_WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-debian-build.XXXXXXXXXX)" \
            || die "cannot create private Debian build workspace"
        chmod 0700 "$OWNED_WORKSPACE"
        install -d -m 0700 "$OWNED_WORKSPACE/docker-config"
        printf '{}\n' > "$OWNED_WORKSPACE/docker-config/config.json"
        chmod 0600 "$OWNED_WORKSPACE/docker-config/config.json"
        export DOCKER_CONFIG="$OWNED_WORKSPACE/docker-config"
        assert_private_docker_config
    fi
}

resolve_image() {
    require_pinned_builder_image deb-builder "$IMAGE_ID"
    if [ "$RELEASE_CHILD" -eq 1 ] && [ "$RELEASE_DOCKER_IMAGE_ID" != "$IMAGE_ID" ]; then
        die "release Debian image ID does not equal DEB_BUILDER_IMAGE_ID"
    fi
}

activate_online_snapshot() {
    if [ "$RELEASE_CHILD" -eq 0 ]; then
        require_online_complete
        ONLINE_SNAPSHOT_PARENT="$OWNED_WORKSPACE/online-input"
        create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    fi
    assert_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"
}

verify_active_online_snapshot() {
    assert_private_docker_config
    assert_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
}

preflight() {
    require_cmd cmp docker git python3 dpkg-deb find install readlink stat
    assert_repo_state
    assert_clean_worktree
    assert_source_date_epoch
    prepare_execution_contract
    resolve_image
    activate_online_snapshot
    # §12.3 / R-B10 (trust nobody): re-verify the exact ./online tarballs this offline build extracts
    # against their pins BEFORE building — a corrupt cache or a stray version-renamed tarball dies here.
    verify_online_shas \
        "rust-${RUST_VERSION}.tar.xz"       "${SHA256_RUST_1_75}" \
        "flutter-${FLUTTER_VERSION}.tar.xz" "${SHA256_FLUTTER_3_24_5}" \
        "llvm-${LLVM_VERSION}.tar.xz"       "${SHA256_LLVM_15_0_6}"
    case "$SHA256_BASEIMAGE_UBUNTU_1804" in *"${SHA_PENDING}"*) die "the ubuntu:18.04 base digest is the R-B12 sentinel — record it in pins.env first" ;; esac
    log "preflight OK — building $FEATURES in $IMAGE_ID, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

verify_deb_control_scripts() {
    local deb="$1"
    local tmp_control
    tmp_control="$(mktemp -d)"
    dpkg-deb -e "$deb" "$tmp_control"
    for script in preinst postinst prerm postrm; do
        [ -f "$tmp_control/$script" ] \
          && [ ! -L "$tmp_control/$script" ] \
          && [ "$(stat -c '%a:%h' "$tmp_control/$script" 2>/dev/null)" = "755:1" ] || {
            rm -rf "$tmp_control"
            die "built .deb control script $script is not a mode-0755 non-hardlinked regular file"
        }
        cmp -s "$REPO_ROOT/res/DEBIAN/$script" "$tmp_control/$script" || {
            rm -rf "$tmp_control"
            die "built .deb control script $script differs from res/DEBIAN/$script"
        }
    done
    local masked
    masked="$(grep -RInE '\|\|[[:space:]]*true|deb-systemd-(invoke|helper).*\|\|' "$tmp_control" || true)"
    if [ -n "$masked" ]; then
        printf '%s\n' "$masked" >&2
        rm -rf "$tmp_control"
        die "built .deb maintainer scripts mask lifecycle failure"
    fi
    python3 "$SCRIPT_DIR/verify-debian-maintainer-scripts.py" --scripts-dir "$tmp_control" || {
        rm -rf "$tmp_control"
        die "built .deb maintainer scripts fail lifecycle semantics"
    }
    rm -rf "$tmp_control"
}

# build_one PROFILE FEATURES: run upstream's build.py in the pinned container,
# network removed, ./online mounted read-only. Emits target/release + the .deb.
build_one() {
    local profile="$1" features="$2" tag="rustdesk-fork-harness-deb-$1"
    log "building profile '$profile' (features: $features)"
    # HONESTY GATE (the af8746f class): build.py renames the freshly built package to
    # $REPO_ROOT/rustdesk-<version>.deb, and the post-build step copies whatever
    # rustdesk-*.deb it finds there. A PRIOR run leaves one behind (root-owned), so if a
    # build fails WITHOUT producing a new one, that STALE .deb would be picked up and shipped
    # as a false success. Remove any pre-existing rustdesk-*.deb up front (these are
    # git-ignored artifacts) so the gate below can ONLY find a package THIS run produced.
    rm -f "$REPO_ROOT"/rustdesk-*.deb
    verify_active_online_snapshot
    if ! docker run --rm \
        --name "$tag" \
        --network=none \
        --user "$BUILD_UID:$BUILD_GID" \
        -e SOURCE_DATE_EPOCH \
        -e RUSTDESK_CANARY_OFFLINE=1 \
        -v "$REPO_ROOT:/src" \
        -v "$ONLINE_DIR:/online:ro" \
        -w /src \
        "$IMAGE_ID" \
        bash -euo pipefail -c '
            # The container is the pinned, immutable template (R-B8): everything
            # comes from /online (R-B5a), nothing is fetched (--network=none).
            TC=/tmp/tc; mkdir -p "$TC"
            # Extract the pinned toolchains from the ./online tarballs that
            # online-fetch.sh materialized (Rust 1.75, Flutter 3.24.5, NDK, LLVM 15,
            # vcpkg snapshot) and put their bins on PATH. vcpkg then builds the
            # native set offline from res/vcpkg overlay ports.
            # rust-1.* (NOT rust-*) so the glob does not also grab the android cross-std
            # online/rust-std-1.75-aarch64-linux-android.tar.xz (added for the .apk build).
            for t in /online/rust-1.*.tar.xz /online/flutter-*.tar.xz /online/llvm-*.tar.xz; do
                [ -e "$t" ] && tar -C "$TC" -xf "$t"
            done
            # Rust: the standalone tarball extracts to rust-1.75.0-.../ with an install.sh
            # (there is no top-level bin/) — install it to a prefix. LLVM: the tarball is
            # clang+llvm-15.0.6-.../ — point bindgen at its libclang.
            "$TC"/rust-1.*/install.sh --prefix="$TC/rustinstall" --disable-ldconfig \
                --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
            LLVM_ROOT="$(echo "$TC"/clang+llvm-*)"
            export LIBCLANG_PATH="$LLVM_ROOT/lib"
            # The native codecs (vpx/yuv/opus) come from the vcpkg overlay tree that
            # online-fetch'\''s stage_vcpkg_natives built (R-R1 pinned, x64-linux static).
            # scrap + magnum-opus link them from VCPKG_ROOT/installed/x64-linux (the shipped
            # feature set has linux-pkg-config OFF, so build.rs find_package needs VCPKG_ROOT).
            export VCPKG_ROOT=/online/vcpkg
            [ -d "$VCPKG_ROOT/installed/x64-linux/lib" ] || { echo "[FATAL] /online/vcpkg/installed/x64-linux missing -- run online-fetch.sh (stage_vcpkg_natives)"; exit 1; }
            export CARGO_PROFILE_RELEASE_RPATH=false
            # Use a build-time CARGO_HOME so the vendored/offline config does NOT
            # overwrite the repo'\''s TRACKED .cargo/config.toml (which carries the
            # windows/macos rustflags); cargo merges CARGO_HOME/config.toml with it.
            export CARGO_HOME=/tmp/cargo-home
            mkdir -p "$CARGO_HOME"
            # The pre-built FRB codegen tool is staged at /online/frb-tool/bin by
            # online-fetch'\''s build_frb_codegen (built FOR ubuntu:18.04 there).
            export PATH="$TC/flutter/bin:$TC/rustinstall/bin:/online/frb-tool/bin:$CARGO_HOME/bin:$PATH"
            # Shadow `flutter` with the offline shim (scripts/flutter-offline-shim.sh): the
            # flutter wrapper drives `pub` ONLINE (it refreshes pub security advisories, which
            # _TypeError against the read-only offline cache → rc=1), so route `flutter pub
            # {run,get}` (FRB ffigen + any implicit get) to `dart --offline`; `flutter build
            # linux` passes through to the real flutter ($REAL_FLUTTER) unchanged.
            export REAL_FLUTTER="$TC/flutter/bin/flutter"
            SHIM=/tmp/flutter-shim; mkdir -p "$SHIM"
            cp /src/scripts/flutter-offline-shim.sh "$SHIM/flutter"; chmod +x "$SHIM/flutter"
            export PATH="$SHIM:$PATH"
            # Wire cargo to the vendored, lockfile-pinned crate set (R-B10) so the
            # --locked build resolves from ./online/cargo-vendor, never the network.
            # The vendor_cargo step captured the AUTHORITATIVE [source.*] map (the cargo
            # vendor output: [source.crates-io] replace-with="vendored-sources", every
            # git-dep source, and [source.vendored-sources]). Use it verbatim (rewrite its
            # directory to /online/cargo-vendor) + ONLY add [net] offline. Do NOT also
            # hand-write a [source.crates-io] -- that duplicates the table and cargo (incl.
            # cargo-metadata, which FRB codegen runs) rejects it (duplicate key crates-io).
            cat > "$CARGO_HOME/config.toml" <<CFG
[net]
offline = true
CFG
            [ -f /online/cargo-vendor-config.toml ] || { echo "[FATAL] /online/cargo-vendor-config.toml missing -- run online-fetch.sh"; exit 1; }
            sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" \
                /online/cargo-vendor-config.toml >> "$CARGO_HOME/config.toml"
            # Flutter pub OFFLINE from the staged cache (online-fetch stage_pub_cache).
            # Fix git "dubious ownership" on the root-owned flutter SDK + the git-dep clones,
            # set PUB_CACHE, and pre-resolve the project --offline (the committed pubspec.lock
            # pins it) so the .dart_tool exists -- then FRB build_runner + flutter build use it
            # without auto-running a networked pub get.
            export HOME=/tmp/buildhome; mkdir -p "$HOME"
            git config --global --add safe.directory "*"
            export PUB_CACHE=/online/pub-cache
            [ -d "$PUB_CACHE" ] || { echo "[FATAL] /online/pub-cache missing -- run online-fetch.sh (stage_pub_cache)"; exit 1; }
            pub_lock_before="$(sha256sum flutter/pubspec.lock | awk "{print \$1}")"
            # Resolve the project: dart pub get --offline reads straight from PUB_CACHE and
            # skips advisories (validated against the staged cache). It is the ONLINE flutter
            # wrapper pub get that refreshes pub security advisories and _TypeErrors against the
            # read-only offline cache → rc=1; `--offline` (here and the flutter injection below)
            # avoids that advisories fetch entirely.
            export CI=true   # non-interactive flutter (suppress the fresh-HOME first-run prompt)
            ( cd flutter && dart pub get --offline )
            # Pre-resolve the flutter SDK'\''s OWN tool package (packages/flutter_tools) OFFLINE before
            # ANY `flutter` invocation: the cold tarball ships it UNRESOLVED, and the first `flutter ...`
            # would otherwise re-resolve it IN-PROCESS + ONLINE (pub.dev + the advisories _TypeError).
            # Its deps are staged in PUB_CACHE by stage_pub_cache. Must precede the injection + build below.
            ( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline )
            # Plugin injection (R-B7), mirroring build-windows.ps1:107-110. `dart pub get`
            # resolves the project (writes .dart_tool) but does NOT run flutter'\''s plugin
            # injection, which is what (re)generates flutter/linux/flutter/generated_plugins.cmake
            # + flutter/linux/flutter/ephemeral/.plugin_symlinks/* + flutter/.flutter-plugins{,-dependencies}.
            # The git-ignored ephemeral symlinks are stale across runs -- a prior build wrote them
            # pointing at /root/.pub-cache (its PUB_CACHE), so under THIS build'\''s PUB_CACHE=/online/pub-cache
            # they DANGLE and `flutter build linux` CMake-aborts: "add_subdirectory given source
            # flutter/ephemeral/.plugin_symlinks/<plugin>/linux which is not an existing directory"
            # (generated_plugins.cmake:23). Run the FLUTTER-level pub get to re-inject them against the
            # current PUB_CACHE. Use $REAL_FLUTTER (NOT the shim, which routes `pub get`->`dart pub get`
            # and so SKIPS injection) with --offline: only the ONLINE wrapper pub get refreshes the
            # advisories that _TypeError on the read-only cache; `flutter pub get --offline` resolves
            # straight from PUB_CACHE WITHOUT advisories (proven: "Got dependencies!", rc=0), so the
            # injection runs clean offline. The regenerated symlinks resolve under /online/pub-cache and
            # each <plugin>/linux exists. (.flutter-plugins-dependencies carries a wall-clock date_created,
            # but it is git-ignored build-input metadata referenced by nothing in build/linux/.../bundle/,
            # so it never reaches the .deb payload -- R-B2 unaffected, enforced by the DOUBLE_BUILD A==B gate.)
            # R-B9 idempotency: DELETE the stale ephemeral symlinks FIRST. `flutter pub get` does NOT
            # overwrite an existing (dangling) symlink, so if a prior build (even from another session)
            # left flutter/linux/flutter/ephemeral/.plugin_symlinks/* pointing at its own PUB_CACHE, the
            # re-injection below is SKIPPED and `flutter build linux` CMake-aborts on every plugin
            # ("<plugin>/linux is not an existing directory"). Removing them forces a clean re-inject
            # against the current PUB_CACHE. Git-ignored build-input metadata (never in the .deb
            # payload), regenerated identically by both double-build passes, so A==B is unaffected.
            # This makes the build safe to re-run on a non-pristine tree (R-B9 "re-running is safe").
            rm -rf flutter/linux/flutter/ephemeral/.plugin_symlinks \
                   flutter/.flutter-plugins-dependencies flutter/.flutter-plugins
            ( cd flutter && "$REAL_FLUTTER" pub get --offline )
            pub_lock_after="$(sha256sum flutter/pubspec.lock | awk "{print \$1}")"
            [ "$pub_lock_before" = "$pub_lock_after" ] || {
                echo "[FATAL] flutter/pubspec.lock changed during offline pub resolution" >&2
                git --no-pager diff -- flutter/pubspec.lock || true
                exit 1
            }
            # FRB codegen first (R-B7: the uncommitted generated_bridge.dart /
            # bridge_generated.rs every build job needs), then upstream build.py
            # with the §3.2 x64-linux features.
            # --llvm-compiler-opts: give ffigen'\''s libclang the clang BUILTIN-header dir so it
            # can resolve <stdbool.h>. Without it ffigen emits "[SEVERE] stdbool.h not found" and
            # DEGRADES every bool-returning binding (e.g. mainPeerHasPassword) to a raw
            # NativeFunction<Int...> → the flutter `kernel_snapshot` Dart compile then fails.
            flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
                --dart-output ./flutter/lib/generated_bridge.dart \
                --llvm-path "$LLVM_ROOT" \
                --llvm-compiler-opts="-I$(echo "$LLVM_ROOT"/lib/clang/*/include)"
            python3 ./build.py '"$features"'
        '; then
        verify_active_online_snapshot
        die "Debian build container failed for profile $profile"
    fi
    verify_active_online_snapshot
    mkdir -p "$OUT_DIR"
    # build.py fails loud (system2 → sys.exit(-1)) on any step, so a non-zero docker run already
    # aborts under set -e. This is the second line of defence: with the stale .deb purged above,
    # a missing rustdesk-*.deb now unambiguously means build.py did NOT emit one (e.g. flutter
    # build linux failed) -- fail loud rather than ship nothing/something stale.
    local deb
    deb="$(ls -1 "$REPO_ROOT"/rustdesk-*.deb 2>/dev/null | head -1 || true)"
    [ -n "$deb" ] && [ -f "$deb" ] || die "no rustdesk-*.deb produced — build.py did not emit a package (flutter build linux likely failed); see the build output above"
    cp "$deb" "$OUT_DIR/rustdesk-${profile}.deb"
    python3 "$SCRIPT_DIR/verify-debian-package-authority.py" --repo "$REPO_ROOT" --deb "$OUT_DIR/rustdesk-${profile}.deb"
    python3 "$SCRIPT_DIR/verify-polkit-policy.py" --repo "$REPO_ROOT" --deb "$OUT_DIR/rustdesk-${profile}.deb"
    verify_deb_control_scripts "$OUT_DIR/rustdesk-${profile}.deb"
    sha256sum "$OUT_DIR/rustdesk-${profile}.deb" | tee "$OUT_DIR/rustdesk-${profile}.deb.sha256"
}

main() {
    preflight
    # The one .deb — viewer and --server in a single binary, role by argv (R-R2b/R-B1).
    build_one x86_64 "$FEATURES"

    # Double-build determinism (R-B2): a second build of identical source MUST
    # produce a byte-identical SHA-256, or the recorded-SHA bar is unfalsifiable.
    if [ "${DOUBLE_BUILD:-1}" = "1" ]; then
        local first; first="$(awk '{print $1}' "$OUT_DIR/rustdesk-x86_64.deb.sha256")"
        OUT_DIR="$OUT_DIR/_rebuild" build_one x86_64 "$FEATURES"
        local second; second="$(awk '{print $1}' "$OUT_DIR/_rebuild/rustdesk-x86_64.deb.sha256")"
        [ "$first" = "$second" ] || die "double-build SHA mismatch ($first vs $second) — fix BUILD_DATE/SOURCE_DATE_EPOCH determinism (R-B2)"
        log "double-build determinism OK: $first"
    fi

    log "build-debian.sh complete: $OUT_DIR/rustdesk-x86_64.deb"
}

main "$@"
