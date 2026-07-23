#!/usr/bin/env python3
"""Validate the Apple source-conformance verifier's input and container authority."""

import argparse
import hashlib
import pathlib
import re
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


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    positions = []
    cursor = 0
    for token in tokens:
        position = source.find(token, cursor)
        if position < 0:
            raise AuthorityError("{} is missing {!r}".format(label, token))
        positions.append(position)
        cursor = position + len(token)
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise AuthorityError("{} is incomplete or misordered".format(label))


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError("{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError("{} end is missing".format(label))
    return source[begin : finish + len(end)]


def forbid_container_authority(source: str, label: str) -> None:
    for token, description in (
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--network host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--pid host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--ipc host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--uts host", "host UTS namespace"),
        ("--publish", "published port"),
        ("--expose", "exposed port"),
        ("/var/run/docker.sock:/var/run/docker.sock", "Docker socket volume"),
        ("source=/var/run/docker.sock", "Docker socket mount"),
    ):
        forbid(source, token, "{} {}".format(label, description))
    if re.search(r"(?:^|\s)-p(?:\s|=)", source):
        raise AuthorityError("forbidden {} short published port".format(label))


def validate(sources: Dict[str, str]) -> None:
    apple = sources["apple"]
    pins = sources["pins"]
    dockerfile_digest = hashlib.sha256(
        sources["dockerfile"].encode("utf-8")
    ).hexdigest()
    require(
        pins,
        'SHA256_APPLE_CHECK_DOCKERFILE="{}"'.format(dockerfile_digest),
        "Apple acquisition-recipe content pin",
    )

    for token, label in (
        ("readonly DOCKER_BIN=/usr/bin/docker", "fixed Docker client"),
        ("readonly APPLE_DOCKER_HOST=unix:///var/run/docker.sock", "fixed local Docker endpoint"),
        ('readonly APPLE_DOCKER_CONFIG="$APPLE_CHECK_TMP/docker-config"',
         "private Docker configuration path"),
        ('[ "$BUILD_UID" -ne 0 ] || die "refusing host or container-root execution"',
         "host-root refusal"),
        ('[ "$BUILD_GID" -ne 0 ] || die "refusing a root primary group"',
         "root-primary-group refusal"),
        ('[ "$(stat -c \'%u:%g:%a:%h\' -- "$DOCKER_BIN")" = "0:0:755:1" ]',
         "trusted Docker client metadata"),
        ('[ -S /var/run/docker.sock ]', "fixed Docker socket type"),
        ("for name in DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
         "caller Docker authority rejection"),
        ('[ -z "${APPLE_TARGET:-}" ] && [ -z "${APPLE_TARGETS:-}" ]',
         "target override rejection"),
        ('[ -z "${MACOS_SDK_DIR:-}" ]', "SDK override rejection"),
        ('env -i \\\n    PATH=/usr/bin:/bin', "closed Docker client environment"),
        ('--host "$APPLE_DOCKER_HOST"', "explicit Docker endpoint"),
        ('--config "$APPLE_DOCKER_CONFIG"', "explicit Docker configuration"),
        ('[ "$(cat "$APPLE_DOCKER_CONFIG/config.json")" = "{}" ]',
         "empty Docker configuration bytes"),
        ("readonly SELECTED_APPLE_TARGETS=(\n  aarch64-apple-darwin\n"
         "  x86_64-apple-darwin\n  aarch64-apple-ios\n)",
         "exact three-target matrix"),
        ('readonly IMG="$APPLE_CHECK_IMAGE_ID"', "immutable image selection"),
        ('[[ "$IMG" =~ ^sha256:[0-9a-f]{64}$ ]]', "content-ID syntax"),
        ('IMAGE_ID="$(apple_docker image inspect --format \'{{.Id}}\' "$IMG")"',
         "local exact-image inspection"),
        ('[ "$IMAGE_ID" = "$IMG" ]', "exact-image equality"),
        ('[ "$(sha256sum scripts/Dockerfile.apple-check',
         "reviewed acquisition-recipe pin"),
        ('archive_current_source >"$APPLE_SOURCE_ARCHIVE"', "private source snapshot"),
        ('SOURCE_DIGEST="$(sha256sum "$APPLE_SOURCE_ARCHIVE"', "source precondition digest"),
        ('chmod -R a-w "$APPLE_SOURCE"', "read-only source snapshot"),
        ("snapshot-subtree-create", "private vendor snapshot"),
        ('--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"', "vendor closure pin"),
        ("sed 's#directory = .*#directory = \"/vendor\"#' online/cargo-vendor-config.toml",
         "private Cargo source map"),
        ('chmod 0400 "$APPLE_CARGO_CONFIG"', "read-only Cargo source map"),
        ('"${APPLE_READ_RUN[@]}" python3 -', "confined metadata parser"),
        ("cargo +1.81.0 check --locked --offline --config /tmp/cargo-config.toml",
         "locked offline Apple cross-check"),
        ('SOURCE_DIGEST_AFTER="$(archive_current_source | sha256sum',
         "real-source postcondition digest"),
        ('[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]',
         "real-source stability proof"),
        ('FINAL_IMAGE_ID="$(apple_docker image inspect --format \'{{.Id}}\' "$IMAGE_ID")"',
         "final exact-image inspection"),
        ('[ "$FINAL_IMAGE_ID" = "$IMAGE_ID" ]', "final exact-image equality"),
        ("verify_apple_docker_authority\n\n", "final Docker authority proof"),
    ):
        require(apple, token, label)

    require_count(apple, "snapshot-subtree-create", 1, "vendor snapshot creation")
    require_count(
        apple,
        '--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"',
        2,
        "vendor create/final verification",
    )
    require_count(apple, "APPLE_READ_RUN=(", 1, "metadata launch definition")
    require_count(apple, "COMMON_CHECK=(", 1, "cross-check launch definition")
    require_count(apple, '"${APPLE_READ_RUN[@]}"', 1, "metadata launch use")
    require_count(apple, '"${COMMON_CHECK[@]}"', 1, "matrix launch site")
    require_count(apple, "apple_docker run", 3, "complete Docker run inventory")

    require_order(
        apple,
        (
            'install -d -m 0700 "$APPLE_DOCKER_CONFIG"',
            'IMAGE_ID="$(apple_docker image inspect',
            'archive_current_source >"$APPLE_SOURCE_ARCHIVE"',
            "snapshot-subtree-create",
            "apple_docker run --rm --pull=never",
            "APPLE_READ_RUN=(",
            "COMMON_CHECK=(",
            '"${APPLE_READ_RUN[@]}" python3 -',
            'for target in "${SELECTED_APPLE_TARGETS[@]}"; do',
            '"${COMMON_CHECK[@]}"',
            "verify-subtree",
            'SOURCE_DIGEST_AFTER="$(archive_current_source',
            'FINAL_IMAGE_ID="$(apple_docker image inspect',
            "verify_apple_docker_authority",
        ),
        "Apple verifier setup, execution, and postconditions",
    )

    preflight = extract(
        apple,
        "apple_docker run --rm --pull=never --network=none --read-only",
        "' >\"$IMAGE_PREFLIGHT_OUT\" 2>\"$IMAGE_PREFLIGHT_ERR\"",
        "image preflight",
    )
    for token, label in (
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=32", "PID ceiling"),
        ("--memory=256m", "memory ceiling"),
        ("--memory-swap=256m", "no-swap expansion"),
        ("--cpus=1", "CPU ceiling"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m", "bounded scratch"),
        ('"$IMAGE_ID"', "exact image"),
    ):
        require(preflight, token, "preflight {}".format(label))
    forbid(preflight, "--mount ", "preflight host mount")
    forbid_container_authority(preflight, "preflight")

    read_run = extract(apple, "APPLE_READ_RUN=(", '  "$IMAGE_ID")', "metadata parser launch")
    for token, label in (
        ("--pull=never", "no-pull policy"),
        ("--network=none", "networkless policy"),
        ("--read-only", "read-only root"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=64", "PID ceiling"),
        ("--memory=512m", "memory ceiling"),
        ("--memory-swap=512m", "no-swap expansion"),
        ("--cpus=1", "CPU ceiling"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m", "bounded scratch"),
        ('--mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"',
         "read-only private source"),
    ):
        require(read_run, token, "metadata parser {}".format(label))
    require_count(read_run, "--mount ", 1, "metadata parser mount inventory")
    forbid_container_authority(read_run, "metadata parser")

    cross = extract(apple, "COMMON_CHECK=(", "  --workdir /work)", "cross-check launch")
    for token, label in (
        ("--pull=never", "no-pull policy"),
        ("--network=none", "networkless policy"),
        ("--read-only", "read-only root"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=512", "PID ceiling"),
        ("--memory=12g", "memory ceiling"),
        ("--memory-swap=12g", "no-swap expansion"),
        ("--cpus=4", "CPU ceiling"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g", "bounded scratch"),
        ('--mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"',
         "read-only private source"),
        ('--mount "type=bind,source=$APPLE_VENDOR,target=/vendor,readonly"',
         "read-only private vendor"),
        ('--mount "type=bind,source=$APPLE_TARGET,target=/build"', "private target"),
        ('--mount "type=bind,source=$APPLE_CARGO_CONFIG,target=/tmp/cargo-config.toml,readonly"',
         "read-only Cargo source map"),
        ("--env CARGO_NET_OFFLINE=true", "Cargo offline policy"),
        ("--env RUSTUP_TOOLCHAIN=1.81.0", "exact Apple toolchain"),
    ):
        require(cross, token, "cross-check {}".format(label))
    require_count(cross, "--mount ", 4, "cross-check mount inventory")
    forbid_container_authority(cross, "cross-check")

    for token, label in (
        ("docker build", "image build fallback"),
        ("docker pull", "image pull fallback"),
        ("\nBASE_IMG=", "mutable base tag"),
        ("\nIMG=rd-apple-check", "mutable Apple tag"),
        ("rd-cargo-cache", "persistent Cargo cache"),
        ("rd-git-cache", "persistent Git cache"),
        ("rd-apple-target", "persistent target cache"),
        ('$REPO:/work', "real checkout short bind"),
        ("source=$REPO,target=/work", "real checkout bind"),
        ("source=$REPO/online", "real online tree bind"),
        ("source=$MACOS_SDK_DIR", "caller SDK bind"),
        ("source=$SDK_DIR", "ambient SDK bind"),
        ("rustfmt --emit", "undeclared rustfmt pseudo-gate"),
    ):
        forbid(apple, token, label)

    for token, label in (
        ('APPLE_CHECK_IMAGE_ID="sha256:', "Apple image content pin"),
        ('SHA256_APPLE_CHECK_DOCKERFILE="', "Apple acquisition-recipe pin"),
        ('SHA256_APPLE_CHECK_CARGO="', "Apple Cargo binary pin"),
        ('SHA256_APPLE_CHECK_RUSTC="', "Apple rustc binary pin"),
        ('SHA256_APPLE_CHECK_DPKG_MANIFEST="', "Apple package-manifest pin"),
    ):
        require(pins, token, label)

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-apple-verifier-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(sources["requirements"], '<span class="id">R-S11ci</span>', "R-S11ci requirement")
    require(sources["requirements"], "<tr><td>228</td>", "Appendix C #228 disposition")
    require(
        sources["hardening"],
        "R-S11ci/R-S11e-101 — Apple conformance verifier authority",
        "hardening-ledger disposition",
    )
    require(
        sources["workspace"],
        '"apple_verifier_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        sources["workspace"],
        "Apple conformance focused authority verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("apple", "readonly DOCKER_BIN=/usr/bin/docker", "DOCKER_BIN=docker",
             "fixed Docker client"),
    Mutation("apple", "readonly APPLE_DOCKER_HOST=unix:///var/run/docker.sock",
             "readonly APPLE_DOCKER_HOST=tcp://127.0.0.1:2375", "fixed local Docker endpoint"),
    Mutation("apple", '"$BUILD_UID" -ne 0', '"$BUILD_UID" -ge 0', "host-root refusal"),
    Mutation("apple", '"$BUILD_GID" -ne 0', '"$BUILD_GID" -ge 0', "root-group refusal"),
    Mutation("apple", "env -i \\\n    PATH=/usr/bin:/bin", "env \\\n    PATH=\"$PATH\"",
             "closed Docker client environment"),
    Mutation("apple", "--host \"$APPLE_DOCKER_HOST\"", "--host \"$DOCKER_HOST\"",
             "explicit Docker endpoint"),
    Mutation("apple", "--config \"$APPLE_DOCKER_CONFIG\"", "--config \"$HOME/.docker\"",
             "private Docker configuration"),
    Mutation("apple", '[ "$(cat "$APPLE_DOCKER_CONFIG/config.json")" = "{}" ]', "true",
             "empty Docker configuration proof"),
    Mutation("apple", "  x86_64-apple-darwin\n  aarch64-apple-ios",
             "  x86_64-apple-darwin", "exact three-target matrix"),
    Mutation("apple", 'readonly IMG="$APPLE_CHECK_IMAGE_ID"', "readonly IMG=rd-apple-check",
             "immutable image selection"),
    Mutation("apple", '[ "$IMAGE_ID" = "$IMG" ]', "true", "image identity equality"),
    Mutation("apple", "archive_current_source >\"$APPLE_SOURCE_ARCHIVE\"",
             "tar -cf \"$APPLE_SOURCE_ARCHIVE\" .", "private source snapshot"),
    Mutation("apple", "chmod -R a-w \"$APPLE_SOURCE\"", "chmod -R a+w \"$APPLE_SOURCE\"",
             "read-only source snapshot"),
    Mutation("apple", "snapshot-subtree-create", "verify-subtree", "private vendor snapshot"),
    Mutation(
        "apple",
        '  --mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"\n'
        '  --mount "type=bind,source=$APPLE_VENDOR,target=/vendor,readonly"',
        '  --mount "type=bind,source=$APPLE_SOURCE,target=/work"\n'
        '  --mount "type=bind,source=$APPLE_VENDOR,target=/vendor,readonly"',
        "read-only source mount",
    ),
    Mutation("apple", 'target=/vendor,readonly"', 'target=/vendor"', "read-only vendor mount"),
    Mutation("apple", 'target=/tmp/cargo-config.toml,readonly"',
             'target=/tmp/cargo-config.toml"', "read-only Cargo source map"),
    Mutation(
        "apple",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=always --network=none --read-only",
        "no-pull policy",
    ),
    Mutation(
        "apple",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=host --read-only",
        "networkless policy",
    ),
    Mutation(
        "apple",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none",
        "read-only root",
    ),
    Mutation(
        "apple",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n"
        '  --user "$BUILD_UID:$BUILD_GID"',
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n"
        "  --user 0:0",
        "numeric nonroot identity",
    ),
    Mutation(
        "apple",
        'COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n'
        '  --user "$BUILD_UID:$BUILD_GID"\n'
        "  --cap-drop=ALL --security-opt=no-new-privileges",
        'COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n'
        '  --user "$BUILD_UID:$BUILD_GID"\n'
        "  --cap-drop=NET_RAW --security-opt=no-new-privileges",
        "complete capability drop",
    ),
    Mutation(
        "apple",
        'COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n'
        '  --user "$BUILD_UID:$BUILD_GID"\n'
        "  --cap-drop=ALL --security-opt=no-new-privileges",
        'COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n'
        '  --user "$BUILD_UID:$BUILD_GID"\n'
        "  --cap-drop=ALL --security-opt=seccomp=unconfined",
        "no-new-privileges",
    ),
    Mutation("apple", "--pids-limit=512", "--pids-limit=-1", "cross-check PID ceiling"),
    Mutation("apple", "--memory=12g", "--memory=0", "cross-check memory ceiling"),
    Mutation("apple", "--memory-swap=12g", "--memory-swap=-1", "cross-check no-swap policy"),
    Mutation("apple", "--cpus=4", "--cpus=0", "cross-check CPU ceiling"),
    Mutation("apple", "size=2g", "size=20g", "cross-check scratch bound"),
    Mutation("apple", "--env CARGO_NET_OFFLINE=true", "--env CARGO_NET_OFFLINE=false",
             "Cargo offline policy"),
    Mutation("apple", "check --locked --offline --config", "check --config",
             "locked offline Cargo check"),
    Mutation("apple", '[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]', "true",
             "real-source stability proof"),
    Mutation("apple", '[ "$FINAL_IMAGE_ID" = "$IMAGE_ID" ]', "true",
             "final image stability proof"),
    Mutation("pins", 'APPLE_CHECK_IMAGE_ID="sha256:', 'APPLE_CHECK_IMAGE_ID="tag:',
             "Apple image content pin"),
    Mutation(
        "dockerfile",
        "This is an acquisition recipe only",
        "This is an unreviewed acquisition recipe",
        "Apple acquisition-recipe content pin",
    ),
    Mutation("verify", "/usr/bin/python3 -I -S scripts/verify-apple-verifier-authority.py --repo . --self-test",
             "true # Apple verifier authority gate removed", "shared focused-verifier wiring"),
    Mutation("requirements", '<span class="id">R-S11ci</span>',
             '<span class="id">R-S11ci-disabled</span>', "R-S11ci requirement"),
    Mutation("requirements", "<tr><td>228</td>", "<tr><td>228-disabled</td>",
             "Appendix C #228 disposition"),
    Mutation("hardening", "R-S11ci/R-S11e-101 — Apple conformance verifier authority",
             "R-S11ci/R-S11e-101 — Apple ambient verifier authority",
             "hardening-ledger disposition"),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
        "dockerfile": (repo / "scripts/Dockerfile.apple-check").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(encoding="utf-8"),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        if count != 1:
            raise AuthorityError(
                "mutation target for {} occurs {} times".format(mutation.label, count)
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation was accepted: {}".format(mutation.label))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "verify-apple-verifier-authority: OK"
        + (" ({} mutations)".format(len(MUTATIONS)) if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print("verify-apple-verifier-authority: {}".format(error))
        raise SystemExit(1)
