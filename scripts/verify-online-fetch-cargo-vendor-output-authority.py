#!/usr/bin/env python3
"""Bind Cargo vendoring to exact inputs, private outputs, and offline resolution."""

from __future__ import annotations

import argparse
import ast
import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


def fail(message: str) -> None:
    raise VerificationError(message)


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        fail(f"{label} is absent: {token!r}")


def require_absent(source: str, token: str, label: str) -> None:
    if token in source:
        fail(f"{label} remains: {token!r}")


def require_count(source: str, token: str, expected: int, label: str) -> None:
    actual = source.count(token)
    if actual != expected:
        fail(f"{label} count is {actual}, expected {expected}: {token!r}")


def require_order(source: str, tokens: Sequence[str], label: str) -> None:
    cursor = 0
    for token in tokens:
        position = source.find(token, cursor)
        if position < 0:
            fail(f"{label} lacks ordered token: {token!r}")
        cursor = position + len(token)


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        fail(f"{label} start cardinality differs")
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        fail(f"{label} end is absent")
    return source[begin:finish]


def pin(source: str, name: str) -> str:
    match = re.search(
        rf'^{re.escape(name)}="([^"]+)"',
        source,
        flags=re.MULTILINE,
    )
    if match is None:
        fail(f"{name} is not one canonical quoted pin")
    return match.group(1)


def validate(sources: Mapping[str, str]) -> None:
    shell = sources["shell"]
    helper = sources["helper"]
    pins = sources["pins"]
    verify = sources["verify"]
    workspace = sources["workspace"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]

    try:
        ast.parse(helper)
    except SyntaxError as error:
        fail(f"Cargo vendor output helper does not parse: {error}")

    expected_pins = {
        "SHA256_ONLINE_CLOSURE_V1": (
            "ab9d1b9e467dbc7723f809eb7d7e905ca5b9285fe00f8572e96c2490fe0ffc66"
        ),
        "SHA256_CARGO_VENDOR_CLOSURE_V1": (
            "fb63f7daefc2c26fb73c04a7d77e9cb8a7658e3c899352e851bb1ebbacdc8c04"
        ),
        "SHA256_CARGO_VENDOR_CONFIG": (
            "18a946aa319d64fa07e9616801981b1794c01764f9d870090de593cec412d62f"
        ),
        "SIZE_CARGO_VENDOR_CONFIG": "4393",
        "CARGO_VENDOR_FILES_V1": "50926",
        "CARGO_VENDOR_DIRECTORIES_V1": "12144",
        "CARGO_VENDOR_CONTENT_BYTES_V1": "2299420401",
        "SHA256_RUST_1_75": (
            "6bf166ddcad545aa26aa2d12a186454d7697133b52b7fbbd271ce3ee1ecfedc6"
        ),
        "DEB_BUILDER_IMAGE_ID": (
            "sha256:6766564c65b0daead7d7031fcf0ff9ec8becab6ef9e3f9a7efd9f02f1b893776"
        ),
    }
    for name, expected in expected_pins.items():
        if pin(pins, name) != expected:
            fail(f"{name} differs from the reviewed Cargo vendor contract")

    lifecycle = extract(
        shell,
        "cargo_vendor_output_tool() {",
        "\n}\n\n# ── Fixed archive transactions",
        "Cargo vendor lifecycle",
    )
    for token, label in (
        (
            '"$GRADLE_SOURCE_AUTHORITY/scripts/online-cargo-vendor-output.py"',
            "committed helper authority",
        ),
        ("cargo_vendor_output_args() {", "closed output contract"),
        ("--source-commit", "source commit binding"),
        ("--source-tree", "source tree binding"),
        ("--source-archive-sha256", "source archive binding"),
        ("--builder", "immutable builder binding"),
        ("--rust-sha256", "Rust archive binding"),
        ("--vendor-sha256", "vendor closure binding"),
        ("--config-sha256", "source-map binding"),
        (
            '--config-vendor-path "$REPO_ROOT/online/cargo-vendor"',
            "canonical source-map destination binding",
        ),
        ("--config-size", "source-map size binding"),
        ("--files", "vendor file-count binding"),
        ("--directories", "vendor directory-count binding"),
        ("--content-bytes", "vendor byte-count binding"),
        ("retire_cargo_vendor_output_staging() {", "private retirement"),
        ("recover_cargo_vendor_output_staging() {", "restart recovery"),
        ('candidate="${staging}.tree"', "same-parent candidate"),
        (
            "verify_cargo_vendor_source_unchanged() {",
            "source postcondition",
        ),
        ("prepare_gradle_source", "exact committed snapshot"),
        ("retire_gradle_source_build", "writable source retirement"),
        (
            "local producer_status=0 source_status=0 input_status=0",
            "independent producer/source/input status",
        ),
        (
            "local output_status=0 semantic_status=0 publication_status=0",
            "independent output/semantic/publication status",
        ),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive lock"),
        (
            "$ONLINE_DIR/.rustdesk-cargo-vendor.XXXXXXXXXX",
            "unpredictable same-filesystem transaction",
        ),
        ("cargo_vendor_output_tool prepare", "transaction preparation"),
        (
            "source=$GRADLE_SOURCE_AUTHORITY,target=/source,readonly,bind-recursive=disabled",
            "exact read-only source mount",
        ),
        (
            "source=$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz,target=/inputs/rust.tar.xz,readonly",
            "exact read-only Rust mount",
        ),
        (
            "source=$candidate,target=/outputs/vendor",
            "private vendor output mount",
        ),
        (
            "source=$staging/raw-config.toml,target=/outputs/raw-config.toml",
            "private raw-config output mount",
        ),
        (
            "cargo vendor --locked --versioned-dirs",
            "locked versioned producer",
        ),
        (
            "--manifest-path /source/Cargo.toml /outputs/vendor",
            "exact producer endpoints",
        ),
        ("cargo_vendor_output_tool verify", "host structural verification"),
        (
            "online_docker_run_cargo_semantic",
            "networkless semantic container",
        ),
        (
            "source=$candidate,target=/vendor,readonly,bind-recursive=disabled",
            "sealed semantic vendor mount",
        ),
        (
            "source=$staging/cargo-vendor-config.toml,target=/inputs/config.toml,readonly",
            "sealed semantic source-map mount",
        ),
        (
            "cargo fetch --offline --locked --manifest-path /source/Cargo.toml",
            "offline lockfile resolution",
        ),
        (
            "cargo_vendor_output_tool authorize",
            "semantic authorization",
        ),
        ("cargo_vendor_output_tool publish", "checked publication"),
        (
            '[ "$semantic_status" -eq 0 ]',
            "semantic publication barrier",
        ),
    ):
        require(lifecycle, token, label)

    for token, label in (
        ("require_cmd cargo", "ambient host Cargo authority"),
        ('cd "$REPO_ROOT" && cargo vendor', "live-checkout Cargo execution"),
        (
            "source=$REPO_ROOT,target=/source",
            "live-checkout container mount",
        ),
        (
            "source=$ONLINE_DIR,target=/online",
            "broad online producer mount",
        ),
        (
            "target=/outputs/cargo-vendor",
            "direct permanent-name output",
        ),
        (
            '> "$ONLINE_DIR/cargo-vendor-config.toml"',
            "direct permanent config write",
        ),
        ("mv \"$candidate\"", "unchecked shell publication"),
        ("rm -rf \"$ONLINE_DIR/cargo-vendor", "destructive final replacement"),
    ):
        require_absent(lifecycle, token, label)

    require_count(
        lifecycle,
        "online_docker_run \\\n",
        1,
        "networked Cargo vendor producer",
    )
    require_count(
        lifecycle,
        "online_docker_run_cargo_semantic \\\n",
        1,
        "networkless Cargo semantic consumer",
    )
    require_count(
        lifecycle,
        "source=$candidate,target=/outputs/vendor",
        1,
        "writable vendor output",
    )
    require_count(
        lifecycle,
        "source=$staging/raw-config.toml,target=/outputs/raw-config.toml",
        1,
        "writable config output",
    )
    require_count(
        lifecycle,
        "source=$GRADLE_SOURCE_AUTHORITY,target=/source,readonly,bind-recursive=disabled",
        2,
        "exact source mounts",
    )
    require_count(
        lifecycle,
        "source=$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz,target=/inputs/rust.tar.xz,readonly",
        2,
        "exact Rust mounts",
    )
    require_order(
        lifecycle,
        (
            "prepare_gradle_source",
            "retire_gradle_source_build",
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "recover_cargo_vendor_output_staging",
            "/usr/bin/mktemp -d",
            "cargo_vendor_output_tool prepare",
            "online_docker_run",
            "verify_cargo_vendor_source_unchanged",
            "cargo_vendor_output_tool verify",
            "online_docker_run_cargo_semantic",
            "verify_cargo_vendor_source_unchanged",
            "cargo_vendor_output_tool authorize",
            "cargo_vendor_output_tool publish",
            "retire_cargo_vendor_output_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "prepare-produce-verify-resolve-authorize-publish-retire order",
    )

    semantic_profile = extract(
        shell,
        "online_docker_run_cargo_semantic() {",
        "\n}\n\n# Exact archive acquisition",
        "Cargo semantic container profile",
    )
    for token in (
        "--pull=never",
        "--network=none",
        "--read-only",
        '--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"',
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--memory=4g",
        "--memory-swap=4g",
        "--cpus=2",
        "--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=4g",
    ):
        require(semantic_profile, token, f"Cargo semantic profile {token}")
    for token in ("--network=bridge", "--privileged", "--user 0", "--pid=host"):
        require_absent(semantic_profile, token, "Cargo semantic authority widening")

    main = extract(shell, "main() {", '\n}\n\nmain "$@"', "main acquisition order")
    require_order(
        main,
        ("load_builder_images", "stage_fixed_archives", "vendor_cargo"),
        "Rust archive before Cargo vendoring",
    )

    for token, label in (
        ('FORMAT = "rustdesk-cargo-vendor-output-v1"', "versioned helper state"),
        ('STATE_NAME = "state.jsonl"', "append-only state journal"),
        ('TREE_SUFFIX = ".tree"', "same-parent sealed candidate"),
        (
            "if uid == 0 or gid == 0 or (os.geteuid(), os.getegid()) != (uid, gid):",
            "non-root exact identity",
        ),
        ("reject_mount_at_or_below", "nested-mount refusal"),
        ("descriptor_mount_id", "mount identity"),
        ("os.O_NOFOLLOW", "descriptor no-follow authority"),
        (
            'if metadata.st_nlink != 1:\n'
            '            fail(f"Cargo vendor entry has an external hardlink: {label}")',
            "external-hardlink refusal",
        ),
        ("os.listxattr", "extended-attribute refusal"),
        (
            "or os.listxattr(descriptor)\n"
            '        ):\n'
            '            fail("Cargo vendor state journal metadata is unsafe")',
            "journal extended-attribute refusal",
        ),
        ("MAX_FILES = 60_000", "bounded files"),
        ("MAX_DIRECTORIES = 15_000", "bounded directories"),
        ("MAX_CONTENT_BYTES = 3 * 1024**3", "bounded content"),
        (
            "if (root_metadata.st_uid, root_metadata.st_gid) != owner:",
            "exact current-user vendor ownership",
        ),
        ("allowed = {0o500}", "sealed vendor directory mode"),
        ("allowed = {0o400, 0o500}", "sealed vendor file modes"),
        ("else {0o400, 0o500}", "sealed traversed vendor file modes"),
        (
            "or (metadata.st_uid, metadata.st_gid) != (uid, gid)\n"
            "            or stat.S_IMODE(metadata.st_mode) != 0o400",
            "sealed current-user config metadata",
        ),
        ("run_provenance(root, contract.vendor_sha256)", "exact closure pin"),
        ("canonical_config_bytes", "canonical source-map transform"),
        ("Cargo vendor raw config has ambiguous", "ambiguous source-map refusal"),
        ("phase_dispositions", "phase/disposition binding"),
        (
            "Cargo vendor state did not make one exact forward transition",
            "journal transition closure",
        ),
        ("os.O_APPEND", "append-only journal open"),
        ("os.fsync", "durable publication"),
        ("RENAME_NOREPLACE = 1", "no-clobber rename"),
        ("renameat2(online_fd, candidate.name, online_fd, VENDOR_NAME)", "same-parent rename"),
        (
            'if latest["phase"] in ("prepared", "verified")',
            "unauthorized recovery discard",
        ),
        ("publish(online, staging, uid, gid, contract)", "authorized recovery"),
        (
            "validate_final_vendor(online, uid, gid, contract)",
            "occupied vendor validation",
        ),
        (
            "validate_final_config(online_fd, online, uid, gid, contract)",
            "occupied config validation",
        ),
        ("self-test", "runtime helper fixtures"),
    ):
        require(helper, token, label)

    require_order(
        helper,
        (
            '"authorized"',
            '"publishing"',
            "renameat2(online_fd, candidate.name, online_fd, VENDOR_NAME)",
            '"vendor-published"',
            "renameat2(staging_fd, CONFIG_NAME, online_fd, CONFIG_NAME)",
            '"complete"',
        ),
        "vendor-before-config publication",
    )
    for token, label in (
        ("os.replace(", "overwrite publication"),
        ("shutil.copy", "path-copy publication"),
        ("subprocess.run([\"cargo", "helper Cargo execution"),
        ("os.system(", "shell execution"),
    ):
        require_absent(helper, token, label)

    require(
        verify,
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-cargo-vendor-output-authority.py --repo . --self-test",
        "verify.sh focused-gate integration",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/online-cargo-vendor-output.py self-test",
        "verify.sh helper-fixture integration",
    )
    require(
        workspace,
        "/usr/bin/python3 -I -S "
        "scripts/verify-online-fetch-cargo-vendor-output-authority.py "
        "--repo . --self-test",
        "workspace focused-gate integration",
    )
    require(
        workspace,
        "/usr/bin/python3 -I -S scripts/online-cargo-vendor-output.py self-test",
        "workspace helper-fixture integration",
    )
    require(
        requirements,
        '<span class="id">R-S11cw</span>',
        "normative Cargo vendor requirement",
    )
    require(requirements, "R-S11e-115", "Cargo vendor enforcement requirement")
    require(
        hardening,
        "R-S11cw/R-S11e-115 — exact Cargo vendor acquisition-output authority",
        "Cargo vendor hardening ledger entry",
    )


def mutations() -> Sequence[Mutation]:
    return (
        Mutation(
            "shell",
            "stage_fixed_archives\n    vendor_cargo",
            "vendor_cargo\n    stage_fixed_archives",
            "pre-archive vendoring",
        ),
        Mutation(
            "shell",
            "online_docker_run_cargo_semantic() {\n"
            "    online_docker run --rm --pull=never --network=none --read-only",
            "online_docker_run_cargo_semantic() {\n"
            "    online_docker run --rm --pull=never --network=bridge --read-only",
            "semantic networking",
        ),
        Mutation(
            "shell",
            "online_docker_run_cargo_semantic() {\n"
            "    online_docker run --rm --pull=never --network=none --read-only \\\n"
            '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
            "        --cap-drop=ALL --security-opt=no-new-privileges",
            "online_docker_run_cargo_semantic() {\n"
            "    online_docker run --rm --pull=never --network=none --read-only \\\n"
            '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
            "        --security-opt=no-new-privileges",
            "capability widening",
        ),
        Mutation(
            "shell",
            "source=$GRADLE_SOURCE_AUTHORITY,target=/source,readonly,bind-recursive=disabled",
            "source=$REPO_ROOT,target=/source",
            "live source mount",
        ),
        Mutation(
            "shell",
            "source=$candidate,target=/outputs/vendor",
            "source=$ONLINE_DIR,target=/online",
            "broad online output",
        ),
        Mutation(
            "shell",
            "cargo fetch --offline --locked --manifest-path /source/Cargo.toml",
            "cargo fetch --locked --manifest-path /source/Cargo.toml",
            "online semantic resolution",
        ),
        Mutation(
            "shell",
            "cargo_vendor_output_tool authorize",
            "true # authorization removed",
            "missing authorization",
        ),
        Mutation(
            "shell",
            "verify_cargo_vendor_source_unchanged || source_status=$?",
            "true # source postcondition removed",
            "missing source postcondition",
        ),
        Mutation(
            "helper",
            "RENAME_NOREPLACE = 1",
            "RENAME_NOREPLACE = 0",
            "clobbering rename",
        ),
        Mutation(
            "helper",
            'if metadata.st_nlink != 1:\n'
            '            fail(f"Cargo vendor entry has an external hardlink: {label}")',
            'if metadata.st_nlink < 1:\n'
            '            fail(f"Cargo vendor entry has an external hardlink: {label}")',
            "hardlink acceptance",
        ),
        Mutation(
            "helper",
            "or os.listxattr(descriptor)\n"
            '        ):\n'
            '            fail("Cargo vendor state journal metadata is unsafe")',
            "or False\n"
            '        ):\n'
            '            fail("Cargo vendor state journal metadata is unsafe")',
            "xattr acceptance",
        ),
        Mutation(
            "helper",
            "if (root_metadata.st_uid, root_metadata.st_gid) != owner:",
            "if False:",
            "foreign final ownership acceptance",
        ),
        Mutation(
            "helper",
            "allowed = {0o500}",
            "allowed = {0o500, 0o700, 0o755}",
            "writable final directory acceptance",
        ),
        Mutation(
            "helper",
            "allowed = {0o400, 0o500}",
            "allowed = {0o400, 0o500, 0o600, 0o644}",
            "writable final file acceptance",
        ),
        Mutation(
            "helper",
            "else {0o400, 0o500}",
            "else {0o400, 0o500, 0o600, 0o644}",
            "writable traversed final file acceptance",
        ),
        Mutation(
            "helper",
            "or (metadata.st_uid, metadata.st_gid) != (uid, gid)\n"
            "            or stat.S_IMODE(metadata.st_mode) != 0o400",
            "or False\n"
            "            or False",
            "writable or foreign final config acceptance",
        ),
        Mutation(
            "helper",
            'if latest["phase"] in ("prepared", "verified"):',
            'if latest["phase"] == "prepared":',
            "verified-state publication authority",
        ),
        Mutation(
            "pins",
            'CARGO_VENDOR_FILES_V1="50926"',
            'CARGO_VENDOR_FILES_V1="50925"',
            "file-count drift",
        ),
        Mutation(
            "verify",
            "verify-online-fetch-cargo-vendor-output-authority.py",
            "verify-online-fetch-cargo-vendor-output-disabled.py",
            "verify integration removal",
        ),
        Mutation(
            "workspace",
            "/usr/bin/python3 -I -S scripts/online-cargo-vendor-output.py self-test",
            "/usr/bin/python3 -I -S scripts/online-cargo-vendor-output.py disabled",
            "workspace fixture removal",
        ),
        Mutation(
            "requirements",
            '<span class="id">R-S11cw</span>',
            '<span class="id">R-S11cw-disabled</span>',
            "normative contract removal",
        ),
        Mutation(
            "hardening",
            "R-S11cw/R-S11e-115 — exact Cargo vendor acquisition-output authority",
            "R-S11cw-disabled/R-S11e-115 — ambient Cargo vendor authority",
            "ledger contract removal",
        ),
    )


def self_test(sources: Mapping[str, str]) -> None:
    validate(sources)
    rejected = 0
    for mutation in mutations():
        candidate = copy.deepcopy(dict(sources))
        count = candidate[mutation.source].count(mutation.old)
        if count < 1:
            fail(
                f"self-test mutation anchor is absent for {mutation.label}: "
                f"{mutation.old!r}"
            )
        candidate[mutation.source] = candidate[mutation.source].replace(
            mutation.old,
            mutation.new,
            1,
        )
        try:
            validate(candidate)
        except VerificationError:
            rejected += 1
        else:
            fail(f"self-test accepted mutation: {mutation.label}")
    print(f"cargo-vendor-authority self-test: PASS ({rejected} mutations)")


def load(repo: Path) -> Mapping[str, str]:
    paths = {
        "shell": repo / "scripts/online-fetch.sh",
        "helper": repo / "scripts/online-cargo-vendor-output.py",
        "pins": repo / "scripts/pins.env",
        "verify": repo / "scripts/verify.sh",
        "workspace": repo / "scripts/verify-verifier-workspace.py",
        "requirements": repo / "requirements.html",
        "hardening": repo / "HARDENING_STATUS.md",
    }
    return {
        name: path.read_text(encoding="utf-8")
        for name, path in paths.items()
    }


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args(argv)
    sources = load(arguments.repo.resolve())
    if arguments.self_test:
        self_test(sources)
    else:
        validate(sources)
        print("cargo-vendor-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(tuple(__import__("sys").argv[1:])))
    except (OSError, VerificationError) as error:
        print(f"[FATAL] {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
