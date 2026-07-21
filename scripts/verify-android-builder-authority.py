#!/usr/bin/env python3
"""Validate the Android APK builder's private-source and container authority."""

import argparse
import pathlib
from typing import Dict, NamedTuple, Tuple


class AuthorityError(Exception):
    pass


class Mutation(NamedTuple):
    source: str
    old: str
    new: str
    label: str


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError("missing {}".format(label))


def require_count(source: str, token: str, count: int, label: str) -> None:
    observed = source.count(token)
    if observed != count:
        raise AuthorityError("{} count is {}, expected {}".format(label, observed, count))


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {}".format(label))


def validate(sources: Dict[str, str]) -> None:
    build = sources["build"]
    checker = sources["checker"]
    inner = sources["inner"]

    for token, label in (
        ('export PATH=/usr/bin:/bin', "closed host command path"),
        ('readonly DOCKER_BIN=/usr/bin/docker', "fixed Docker client"),
        ('readonly PYTHON_BIN=/usr/bin/python3', "fixed Python interpreter"),
        ('mktemp -d /tmp/rustdesk-android-build.XXXXXXXXXX', "private random workspace"),
        ('SOURCE_COMMIT="$current"', "exact source commit capture"),
        ('mode not in (b"100644", b"100755")', "regular-file-only commit inventory"),
        ('archive --format=tar "$SOURCE_COMMIT"', "commit-object source archive"),
        ('SOURCE_AUTHORITY_ROOT="$OWNED_WORKSPACE/source-authority"', "immutable source authority"),
        ('BUILD_SOURCE_ROOT="$OWNED_WORKSPACE/source-build"', "private writable source"),
        ('chmod -R a=rX "$SOURCE_AUTHORITY_ROOT"', "canonical read-only source authority modes"),
        ('prepare_build_source() {', "fresh writable-source constructor"),
        ('Android writable source path was not freshly absent', "fresh writable-source precondition"),
        ('chmod -R u=rwX,go=rX "$BUILD_SOURCE_ROOT"', "canonical writable source modes"),
        ('--reference "$SOURCE_AUTHORITY_ROOT" --candidate "$BUILD_SOURCE_ROOT" --allow-extras', "post-build source comparator wiring"),
        ('remove_build_source() {', "writable-source cleanup"),
        ('private Android writable source survived cleanup', "writable-source cleanup postcondition"),
        ('the Android artifact builder accepts only an exact clean commit', "dirty-build refusal"),
        ('android_docker_run() {', "single container-confinement wrapper"),
        ('"$DOCKER_BIN" run --rm --pull=never --network=none --read-only', "no-pull/networkless/read-only root"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ('--cap-drop=ALL --security-opt=no-new-privileges', "capability and privilege confinement"),
        ('--pids-limit=32 --memory=512m --memory-swap=512m --cpus=1', "keytool resource bounds"),
        ('--pids-limit=512 --memory=12g --memory-swap=12g --cpus=4', "build resource bounds"),
        ('--pids-limit=128 --memory=4g --memory-swap=4g --cpus=2', "signing/verifier resource bounds"),
        ('--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g', "bounded executable build scratch"),
        ('--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=2g', "bounded non-executable verification scratch"),
        ('source=$BUILD_SOURCE_ROOT,target=/src"', "private writable build mount"),
        ('source=$SOURCE_AUTHORITY_ROOT/scripts/android-apk-build.sh,target=/authority/android-apk-build.sh,readonly', "immutable inner build script"),
        ('source=$pass_output,target=/out"', "private signing output mount"),
        ('source=$KEYSTORE,target=/ks/keystore.jks,readonly', "read-only keystore mount"),
        ('source=$KEYSTORE_PASS_FILE,target=/ks/pass,readonly', "read-only keystore-password mount"),
        ('target=/checks/verify-android-apk-manifest.py,readonly', "immutable manifest verifier"),
        ('target=/checks/verify-android-mobile-key-artifact.py,readonly', "immutable mobile-key verifier"),
        ('install -m 0400 "$pass_output/rustdesk-arm64.apk" "$OUT_DIR/rustdesk-arm64.apk"', "host-side final APK publication"),
        ('cmp -s "$pass_output/rustdesk-arm64.apk" "$OUT_DIR/rustdesk-arm64.apk"', "final publication byte comparison"),
        ('published Android APK differs from the verified private artifact', "final publication byte proof"),
        ('sha256sum -c rustdesk-arm64.apk.sha256', "published checksum proof"),
        ('prepare_pass_output "$pass_a"', "private first pass"),
        ('prepare_pass_output "$pass_b"', "private second pass"),
        ('publish_apk "$pass_a"', "verified pass-A publication"),
    ):
        require(build, token, label)

    require_count(build, "if ! android_docker_run", 3, "fallible build/sign/verify container launches")
    require_count(build, 'info="$(android_docker_run', 1, "fallible keytool container launch")
    require_count(build, "    prepare_build_source\n", 1, "fresh source per build-pass call")
    require_count(build, "    remove_build_source\n", 1, "build-source cleanup call")
    require_count(build, 'verify-android-build-source.py"', 2, "initial and post-build source comparisons")
    require_count(build, "source=$KEYSTORE,target=/ks/keystore.jks,readonly", 2, "read-only keystore mounts")
    require_count(build, "source=$KEYSTORE_PASS_FILE,target=/ks/pass,readonly", 2, "read-only password mounts")
    require_count(build, "target=/checks/verify-android-apk-manifest.py,readonly", 2, "immutable manifest-checker mounts")
    require_count(build, "target=/checks/verify-android-mobile-key-artifact.py,readonly", 2, "immutable mobile-key-checker mounts")
    if build.count("verify_build_source_unchanged") != 3:
        raise AuthorityError("source identity is not checked before and after build consumption")
    if build.count("--pids-limit=128 --memory=4g --memory-swap=4g --cpus=2") != 2:
        raise AuthorityError("signing and verification do not each carry explicit resource bounds")

    for token, label in (
        ('export ANDROID_USER_HOME=/tmp/android-user-home', "explicit Android preferences scratch"),
        ('Android user home was not freshly absent', "fresh Android preferences precondition"),
        ('install -d -m 0700 "$ANDROID_USER_HOME"', "private Android preferences constructor"),
        ('Android user home is not private to the build identity', "Android preferences mode/owner postcondition"),
        ('prepare_offline_gradle_cache() {', "deferred Gradle-cache constructor"),
        ('tar -C "$TC" -xf /online/rust-1.75.tar.xz', "pinned Rust installer extraction"),
        ('tar -C "$TC" -xf /online/rust-std-1.75-aarch64-linux-android.tar.xz', "pinned Android std extraction"),
        ('rm -rf -- "$RUST_INSTALLER_ROOT" "$ANDROID_STD_INSTALLER_ROOT"', "consumed Rust-installer retirement"),
        ('consumed Rust installer payload survived scratch retirement', "Rust-installer retirement postcondition"),
        ('tar -C "$TC" -xf /online/flutter-3.24.5.tar.xz', "pinned Flutter extraction"),
        ('tar -C "$TC" -xf /online/llvm-15.0.6.tar.xz', "pinned LLVM extraction"),
        ('rm -rf -- "$LLVM_ROOT"', "consumed LLVM retirement"),
        ('consumed LLVM payload survived scratch retirement', "LLVM retirement postcondition"),
        ('unset LIBCLANG_PATH BINDGEN_EXTRA_CLANG_ARGS', "retired LLVM environment"),
        ('prepare_offline_gradle_cache\ncd flutter && flutter build apk', "late Gradle projection before packaging"),
        ('commandLine("cargo", "metadata", "--format-version", "1")', "Gradle Cargo-metadata consumer"),
    ):
        require(inner, token, label)

    require_count(inner, 'android-gradle-cache.py materialize', 1, "single Gradle-cache projection")
    require_count(inner, 'rm -rf -- "$RUST_INSTALLER_ROOT" "$ANDROID_STD_INSTALLER_ROOT"', 1, "single Rust-installer retirement")
    require_count(inner, 'rm -rf -- "$LLVM_ROOT"', 1, "single LLVM retirement")
    require_count(inner, 'prepare_offline_gradle_cache\n', 1, "single deferred Gradle-cache call")

    ordered_tokens = (
        'export ANDROID_USER_HOME=/tmp/android-user-home',
        'install -d -m 0700 "$ANDROID_USER_HOME"',
        '"$ANDROID_STD_INSTALLER_ROOT/install.sh"',
        'rm -rf -- "$RUST_INSTALLER_ROOT" "$ANDROID_STD_INSTALLER_ROOT"',
        'tar -C "$TC" -xf /online/flutter-3.24.5.tar.xz',
        'tar -C "$TC" -xf /online/llvm-15.0.6.tar.xz',
        'flutter_rust_bridge_codegen --rust-input',
        'bash ./flutter/ndk_arm64.sh',
        'rm -rf -- "$LLVM_ROOT"',
        'prepare_offline_gradle_cache\n',
        'cd flutter && flutter build apk',
    )
    positions = tuple(inner.index(token) for token in ordered_tokens)
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError("Android scratch consumers and retirement phases are misordered")

    for token, label in (
        ('$REPO_ROOT:/src', "real repository bind"),
        ('source=$REPO_ROOT,target=/src', "real repository mount"),
        ('$OUT_DIR:/out', "final output directory bind"),
        ('source=$OUT_DIR,target=/out', "final output directory mount"),
        ('--name rustdesk-fork-harness-apk', "daemon-global fixed container name"),
        ('--privileged', "privileged container"),
        ('--cap-add', "added container capability"),
        ('--pid=host', "host PID namespace"),
        ('--network=host', "host network namespace"),
        ('source=/var/run/docker.sock', "Docker socket mount"),
        ('/var/run/docker.sock:/var/run/docker.sock', "Docker socket volume"),
        ('docker build', "image build fallback"),
        ('docker pull', "image pull fallback"),
    ):
        forbid(build, token, label)

    for token, label in (
        ('getattr(os, "O_NOFOLLOW", 0)', "descriptor no-follow open"),
        ('before.st_nlink != 1', "hardlink refusal"),
        ('identity_before != identity_after', "stable-read identity proof"),
        ('reference_digest != candidate_digest', "exact byte comparison"),
        ('reference_root_mode != REFERENCE_DIRECTORY_MODE', "canonical authority-root mode"),
        ('candidate_root_mode != CANDIDATE_DIRECTORY_MODE', "canonical writable-root mode"),
        ('reference_mode != REFERENCE_DIRECTORY_MODE', "canonical authority-directory mode"),
        ('candidate_mode != CANDIDATE_DIRECTORY_MODE', "canonical writable-directory mode"),
        ('reference file has noncanonical mode', "canonical authority-file mode"),
        ('candidate_mode != expected_candidate_mode', "canonical writable-file mode"),
        ('if not allow_extras:', "initial extra-input control"),
        ('candidate source contains an extra input', "initial extra-input refusal"),
        ('allow_extras=args.allow_extras', "post-build generated-output allowance"),
        ('candidate source is missing', "missing-input refusal"),
        ('expect_failure(reference, candidate, "changed directory type")', "directory-type negative test"),
        ('expect_failure(reference, candidate, "hardlink substitution")', "hardlink negative test"),
        ('expect_failure(reference, candidate, "group-writable reference root")', "authority-root-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable candidate root")', "writable-root-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable reference directory")', "authority-directory-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable candidate directory")', "writable-directory-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable reference source")', "authority-file-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable candidate source")', "writable-file-mode negative test"),
        ('expect_failure(reference, candidate, "changed executable mode")', "executable-mode negative test"),
        ('self_test()', "source comparator self-test"),
    ):
        require(checker, token, label)

    require(
        sources["verify"],
        'python3 scripts/verify-android-build-source.py --self-test',
        "source-comparator self-test wiring",
    )
    require(
        sources["verify"],
        'python3 scripts/verify-android-builder-authority.py --repo . --self-test',
        "shared verifier wiring",
    )
    require(sources["requirements"], '<span class="id">R-S11bj</span>', "R-S11bj requirement")
    require(sources["requirements"], '<span class="id">R-S11bk</span>', "R-S11bk requirement")
    require(sources["requirements"], '<span class="id">R-S11bl</span>', "R-S11bl requirement")
    require(sources["requirements"], '<span class="id">R-S11bm</span>', "R-S11bm requirement")
    require(sources["requirements"], '<tr><td>199</td>', "Appendix C #199 disposition")
    require(sources["requirements"], '<tr><td>200</td>', "Appendix C #200 disposition")
    require(sources["requirements"], '<tr><td>201</td>', "Appendix C #201 disposition")
    require(sources["requirements"], '<tr><td>202</td>', "Appendix C #202 disposition")
    require(
        sources["hardening"],
        'R-S11bj/R-S11e-76 — Android APK builder container and source authority',
        "hardening ledger row",
    )
    require(
        sources["hardening"],
        'R-S11bk/R-S11e-77 — Android exact-commit snapshot mode authority',
        "snapshot-mode hardening ledger row",
    )
    require(
        sources["hardening"],
        'R-S11bl/R-S11e-78 — Android bounded scratch lifecycle',
        "scratch-lifecycle hardening ledger row",
    )
    require(
        sources["hardening"],
        'R-S11bm/R-S11e-79 — Android tool preferences scratch ownership',
        "Android-preferences hardening ledger row",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("build", "--rm --pull=never --network=none --read-only", "--rm --network=none --read-only", "pull fallback"),
    Mutation("build", "--rm --pull=never --network=none --read-only", "--rm --pull=never --read-only", "network isolation"),
    Mutation("build", "--rm --pull=never --network=none --read-only", "--rm --pull=never --network=none", "read-only root"),
    Mutation("build", '--user "$BUILD_UID:$BUILD_GID"', '--user 0:0', "nonroot identity"),
    Mutation("build", "--cap-drop=ALL --security-opt=no-new-privileges", "--security-opt=no-new-privileges", "capability drop"),
    Mutation("build", "--cap-drop=ALL --security-opt=no-new-privileges", "--cap-drop=ALL", "no-new-privileges"),
    Mutation("build", "--pids-limit=512 --memory=12g --memory-swap=12g --cpus=4", "--memory=12g --memory-swap=12g --cpus=4", "build PID bound"),
    Mutation("build", "--pids-limit=512 --memory=12g --memory-swap=12g --cpus=4", "--pids-limit=512 --memory=12g --memory-swap=12g", "build CPU bound"),
    Mutation("inner", 'export ANDROID_USER_HOME=/tmp/android-user-home', 'export ANDROID_USER_HOME=/home/ubuntu/.android', "Android preferences scratch selection"),
    Mutation("inner", 'install -d -m 0700 "$ANDROID_USER_HOME"', 'mkdir -p "$ANDROID_USER_HOME"', "private Android preferences constructor"),
    Mutation("inner", 'Android user home was not freshly absent', 'pre-existing Android user home accepted', "fresh Android preferences precondition"),
    Mutation("inner", 'Android user home is not private to the build identity', 'non-private Android user home accepted', "Android preferences owner/mode postcondition"),
    Mutation("inner", 'rm -rf -- "$RUST_INSTALLER_ROOT" "$ANDROID_STD_INSTALLER_ROOT"', 'true # consumed Rust installers retained', "Rust-installer retirement"),
    Mutation("inner", 'consumed Rust installer payload survived scratch retirement', 'consumed Rust installer payload accepted', "Rust-installer retirement postcondition"),
    Mutation("inner", 'rm -rf -- "$LLVM_ROOT"', 'true # consumed LLVM retained', "LLVM retirement"),
    Mutation("inner", 'consumed LLVM payload survived scratch retirement', 'consumed LLVM payload accepted', "LLVM retirement postcondition"),
    Mutation("inner", 'prepare_offline_gradle_cache\ncd flutter && flutter build apk', 'cd flutter && flutter build apk', "late Gradle projection"),
    Mutation("inner", 'unset LIBCLANG_PATH BINDGEN_EXTRA_CLANG_ARGS', 'true # stale LLVM environment retained', "LLVM environment retirement"),
    Mutation("inner", 'commandLine("cargo", "metadata", "--format-version", "1")', 'commandLine("true")', "Gradle Cargo-metadata consumer"),
    Mutation("build", "source=$BUILD_SOURCE_ROOT,target=/src", "source=$REPO_ROOT,target=/src", "real source bind"),
    Mutation("build", "source=$pass_output,target=/out", "source=$OUT_DIR,target=/out", "final output bind"),
    Mutation("build", 'archive --format=tar "$SOURCE_COMMIT"', 'archive --format=tar HEAD~1', "source commit binding"),
    Mutation("build", 'mode not in (b"100644", b"100755")', 'mode not in (b"100644", b"100755", b"120000")', "regular-only source tree"),
    Mutation("build", 'chmod -R a=rX "$SOURCE_AUTHORITY_ROOT"', 'chmod -R a=rwX "$SOURCE_AUTHORITY_ROOT"', "canonical immutable source modes"),
    Mutation("build", 'chmod -R u=rwX,go=rX "$BUILD_SOURCE_ROOT"', 'chmod -R u=rwX,g=rwX,o=rX "$BUILD_SOURCE_ROOT"', "canonical writable source modes"),
    Mutation("build", "    prepare_build_source\n", "    true # fresh source construction removed\n", "fresh build source"),
    Mutation("build", "    verify_build_source_unchanged\n    # The docker run built", "    true # post-build source comparison removed\n    # The docker run built", "post-build source comparison"),
    Mutation("build", "    remove_build_source\n", "    true # build-source cleanup removed\n", "build-source cleanup"),
    Mutation("build", 'source=$pass_output,target=/out" \\\n        --mount "type=bind,source=$KEYSTORE,target=/ks/keystore.jks,readonly', 'source=$pass_output,target=/out" \\\n        --mount "type=bind,source=$KEYSTORE,target=/ks/keystore.jks', "keystore read-only mount"),
    Mutation("build", 'source=$resolved,target=/verify/app.apk,readonly" \\\n        --mount "type=bind,source=$SOURCE_AUTHORITY_ROOT/scripts/verify-android-apk-manifest.py,target=/checks/verify-android-apk-manifest.py,readonly', 'source=$resolved,target=/verify/app.apk,readonly" \\\n        --mount "type=bind,source=$SOURCE_AUTHORITY_ROOT/scripts/verify-android-apk-manifest.py,target=/checks/verify-android-apk-manifest.py', "manifest checker read-only mount"),
    Mutation("build", 'publish_apk "$pass_a"', 'publish_apk "$pass_b"', "pass-A publication"),
    Mutation("build", 'cmp -s "$pass_output/rustdesk-arm64.apk" "$OUT_DIR/rustdesk-arm64.apk"', 'true # publication comparison removed', "publication byte comparison"),
    Mutation("build", "sha256sum -c rustdesk-arm64.apk.sha256", "true # published checksum not checked", "published checksum proof"),
    Mutation("checker", 'flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)', 'flags = os.O_RDONLY', "source no-follow open"),
    Mutation("checker", "if reference_digest != candidate_digest:", "if False:", "source digest comparison"),
    Mutation("checker", "if before.st_nlink != 1:", "if False:", "source hardlink refusal"),
    Mutation("checker", "if reference_root_mode != REFERENCE_DIRECTORY_MODE:", "if False:", "canonical authority-root comparison"),
    Mutation("checker", "if candidate_root_mode != CANDIDATE_DIRECTORY_MODE:", "if False:", "canonical writable-root comparison"),
    Mutation("checker", "if reference_mode != REFERENCE_DIRECTORY_MODE:", "if False:", "canonical authority-directory comparison"),
    Mutation("checker", "if candidate_mode != CANDIDATE_DIRECTORY_MODE:", "if False:", "canonical writable-directory comparison"),
    Mutation("checker", 'raise SourceError("reference file has noncanonical mode: {}".format(relative))', "expected_candidate_mode = CANDIDATE_FILE_MODE", "canonical authority-file comparison"),
    Mutation("checker", "if candidate_mode != expected_candidate_mode:", "if False:", "canonical file-mode comparison"),
    Mutation("checker", "if not allow_extras:", "if False:", "initial extra-input refusal"),
    Mutation("checker", 'expect_failure(reference, candidate, "hardlink substitution")', 'validate(reference, candidate) # hardlink negative test removed', "hardlink negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable reference root")', 'validate(reference, candidate) # authority-root-mode negative test removed', "authority-root-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable candidate root")', 'validate(reference, candidate) # writable-root-mode negative test removed', "writable-root-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable reference directory")', 'validate(reference, candidate) # authority-directory-mode negative test removed', "authority-directory-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable candidate directory")', 'validate(reference, candidate) # writable-directory-mode negative test removed', "writable-directory-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable reference source")', 'validate(reference, candidate) # authority-file-mode negative test removed', "authority-file-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable candidate source")', 'validate(reference, candidate) # writable-file-mode negative test removed', "writable-file-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "changed executable mode")', 'validate(reference, candidate) # executable-mode negative test removed', "executable-mode negative test"),
    Mutation("verify", "python3 scripts/verify-android-build-source.py --self-test", "true # Android source comparator self-test removed", "source-comparator self-test wiring"),
    Mutation("verify", "python3 scripts/verify-android-builder-authority.py --repo . --self-test", "true # Android builder authority verifier removed", "shared gate wiring"),
    Mutation("requirements", '<span class="id">R-S11bj</span>', '<span class="id">R-S11bj-disabled</span>', "requirement"),
    Mutation("requirements", '<span class="id">R-S11bk</span>', '<span class="id">R-S11bk-disabled</span>', "snapshot-mode requirement"),
    Mutation("requirements", '<span class="id">R-S11bl</span>', '<span class="id">R-S11bl-disabled</span>', "scratch-lifecycle requirement"),
    Mutation("requirements", '<span class="id">R-S11bm</span>', '<span class="id">R-S11bm-disabled</span>', "Android-preferences requirement"),
    Mutation("requirements", '<tr><td>199</td>', '<tr><td>199-disabled</td>', "Appendix disposition"),
    Mutation("requirements", '<tr><td>200</td>', '<tr><td>200-disabled</td>', "snapshot-mode Appendix disposition"),
    Mutation("requirements", '<tr><td>201</td>', '<tr><td>201-disabled</td>', "scratch-lifecycle Appendix disposition"),
    Mutation("requirements", '<tr><td>202</td>', '<tr><td>202-disabled</td>', "Android-preferences Appendix disposition"),
    Mutation("hardening", 'R-S11bj/R-S11e-76 — Android APK builder container and source authority', 'R-S11bj/R-S11e-76 — Android APK builder ambient authority', "ledger"),
    Mutation("hardening", 'R-S11bk/R-S11e-77 — Android exact-commit snapshot mode authority', 'R-S11bk/R-S11e-77 — Android archive umask authority', "snapshot-mode ledger"),
    Mutation("hardening", 'R-S11bl/R-S11e-78 — Android bounded scratch lifecycle', 'R-S11bl/R-S11e-78 — Android unbounded scratch lifecycle', "scratch-lifecycle ledger"),
    Mutation("hardening", 'R-S11bm/R-S11e-79 — Android tool preferences scratch ownership', 'R-S11bm/R-S11e-79 — Android tool preferences ambient ownership', "Android-preferences ledger"),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        if original.count(mutation.old) != 1:
            raise AuthorityError(
                "mutation '{}' expected one source token, found {}".format(
                    mutation.label, original.count(mutation.old)
                )
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation survived: {}".format(mutation.label))


def read_regular(repo: pathlib.Path, relative: str) -> str:
    path = repo / relative
    if path.is_symlink() or not path.is_file():
        raise AuthorityError("required source is not a regular file: {}".format(relative))
    return path.read_text(encoding="utf-8")


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "build": read_regular(repo, "scripts/build-android.sh"),
        "inner": read_regular(repo, "scripts/android-apk-build.sh")
        + read_regular(repo, "flutter/android/app/build.gradle"),
        "checker": read_regular(repo, "scripts/verify-android-build-source.py"),
        "verify": read_regular(repo, "scripts/verify.sh"),
        "requirements": read_regular(repo, "requirements.html"),
        "hardening": read_regular(repo, "HARDENING_STATUS.md"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    repo = pathlib.Path(args.repo).resolve()
    sources = load_sources(repo)
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "ANDROID-BUILDER-AUTHORITY: private exact-commit source, phased bounded scratch and Android preferences, private signing output, and four confined launches are GREEN ({} mutations)".format(
            len(MUTATIONS) if args.self_test else 0
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (AuthorityError, OSError, UnicodeError) as error:
        raise SystemExit("verify-android-builder-authority: {}".format(error))
