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
        ('chmod -R a-w "$SOURCE_AUTHORITY_ROOT"', "read-only source authority"),
        ('prepare_build_source() {', "fresh writable-source constructor"),
        ('Android writable source path was not freshly absent', "fresh writable-source precondition"),
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
        ('reference_exec != candidate_exec', "executable-mode comparison"),
        ('if not allow_extras:', "initial extra-input control"),
        ('candidate source contains an extra input', "initial extra-input refusal"),
        ('allow_extras=args.allow_extras', "post-build generated-output allowance"),
        ('candidate source is missing', "missing-input refusal"),
        ('expect_failure(reference, candidate, "changed directory type")', "directory-type negative test"),
        ('expect_failure(reference, candidate, "hardlink substitution")', "hardlink negative test"),
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
    require(sources["requirements"], '<tr><td>199</td>', "Appendix C #199 disposition")
    require(
        sources["hardening"],
        'R-S11bj/R-S11e-76 — Android APK builder container and source authority',
        "hardening ledger row",
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
    Mutation("build", "source=$BUILD_SOURCE_ROOT,target=/src", "source=$REPO_ROOT,target=/src", "real source bind"),
    Mutation("build", "source=$pass_output,target=/out", "source=$OUT_DIR,target=/out", "final output bind"),
    Mutation("build", 'archive --format=tar "$SOURCE_COMMIT"', 'archive --format=tar HEAD~1', "source commit binding"),
    Mutation("build", 'mode not in (b"100644", b"100755")', 'mode not in (b"100644", b"100755", b"120000")', "regular-only source tree"),
    Mutation("build", 'chmod -R a-w "$SOURCE_AUTHORITY_ROOT"', 'chmod -R u+w "$SOURCE_AUTHORITY_ROOT"', "immutable source authority"),
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
    Mutation("checker", "if not allow_extras:", "if False:", "initial extra-input refusal"),
    Mutation("checker", 'expect_failure(reference, candidate, "hardlink substitution")', 'validate(reference, candidate) # hardlink negative test removed', "hardlink negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "changed executable mode")', 'validate(reference, candidate) # executable-mode negative test removed', "executable-mode negative test"),
    Mutation("verify", "python3 scripts/verify-android-build-source.py --self-test", "true # Android source comparator self-test removed", "source-comparator self-test wiring"),
    Mutation("verify", "python3 scripts/verify-android-builder-authority.py --repo . --self-test", "true # Android builder authority verifier removed", "shared gate wiring"),
    Mutation("requirements", '<span class="id">R-S11bj</span>', '<span class="id">R-S11bj-disabled</span>', "requirement"),
    Mutation("requirements", '<tr><td>199</td>', '<tr><td>199-disabled</td>', "Appendix disposition"),
    Mutation("hardening", 'R-S11bj/R-S11e-76 — Android APK builder container and source authority', 'R-S11bj/R-S11e-76 — Android APK builder ambient authority', "ledger"),
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
        "ANDROID-BUILDER-AUTHORITY: private exact-commit source, private signing output, and four confined launches are GREEN ({} mutations)".format(
            len(MUTATIONS) if args.self_test else 0
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (AuthorityError, OSError, UnicodeError) as error:
        raise SystemExit("verify-android-builder-authority: {}".format(error))
