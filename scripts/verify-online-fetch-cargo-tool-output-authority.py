#!/usr/bin/env python3
"""Validate checked publication of network-acquired Cargo-installed tools."""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
from dataclasses import dataclass
from typing import Dict, Tuple


class AuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError("missing {}: {!r}".format(label, token))


def require_absent(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {} remains: {!r}".format(label, token))


def require_count(source: str, token: str, expected: int, label: str) -> None:
    actual = source.count(token)
    if actual != expected:
        raise AuthorityError(
            "{} count is {}, expected {}: {!r}".format(label, actual, expected, token)
        )


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        if found < 0:
            raise AuthorityError("{} is missing ordered token {!r}".format(label, token))
        position = found


def extract_between(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError("{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError("{} end is absent".format(label))
    return source[begin:finish]


def pin_value(source: str, name: str) -> str:
    match = re.search(
        r'^{}="([^"]+)"'.format(re.escape(name)),
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AuthorityError("{} is not one canonical quoted pin".format(name))
    return match.group(1)


def validate(sources: Dict[str, str]) -> None:
    shell = sources["shell"]
    helper = sources["helper"]
    pins = sources["pins"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    workspace = sources["workspace"]
    try:
        ast.parse(helper)
    except SyntaxError as error:
        raise AuthorityError("Cargo-tool output helper does not parse: {}".format(error)) from error

    if pin_value(pins, "RUST_VERSION") != "1.75":
        raise AuthorityError("Cargo-tool output authority requires exact Rust 1.75")
    if pin_value(pins, "FLUTTER_RUST_BRIDGE_VERSION") != "1.80.1":
        raise AuthorityError("Cargo-tool output authority requires exact FRB 1.80.1")
    if pin_value(pins, "CARGO_NDK_VERSION") != "3.1.2":
        raise AuthorityError("Cargo-tool output authority requires exact cargo-ndk 3.1.2")
    if re.search(
        r'^SHA256_RUST_1_75="[0-9a-f]{64}"',
        pins,
        re.MULTILINE,
    ) is None:
        raise AuthorityError("Rust 1.75 archive does not have one canonical SHA-256 pin")

    for token, label in (
        ("readonly FLOCK_BIN=/usr/bin/flock", "fixed transaction-lock client"),
        ("cargo_tool_output_tool() {", "fixed Cargo-tool output helper"),
        ("cargo_tool_output_semantic_args() {", "closed semantic argument mapper"),
        ("retire_cargo_tool_output_staging() {", "private staging retirement"),
        ("recover_cargo_tool_output_staging() {", "reserved-state recovery"),
        ("stage_cargo_installed_tool() {", "closed producer funnel"),
        ('"frb:$DEB_BUILDER_IMAGE_ID")', "FRB immutable-builder binding"),
        ('"cargo-ndk:$ANDROID_BUILDER_IMAGE_ID")', "cargo-ndk immutable-builder binding"),
        ("package=flutter_rust_bridge_codegen", "exact FRB package"),
        ("features=uuid", "exact FRB feature"),
        ("package=cargo-ndk", "exact cargo-ndk package"),
        ("features=", "empty cargo-ndk feature set"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive output transaction"),
        ('"$ONLINE_DIR/.rustdesk-cargo-tool-$kind.XXXXXXXXXX"',
         "unpredictable same-filesystem staging"),
        ("cargo_tool_output_tool prepare", "bounded transaction preparation"),
        ('--env CARGO_TOOL_PACKAGE="$package"', "closed package environment"),
        ('--env CARGO_TOOL_BINARY="$binary"', "closed binary environment"),
        ('--env CARGO_TOOL_VERSION="$tool_version"', "closed version environment"),
        ('--env CARGO_TOOL_FEATURES="$features"', "closed feature environment"),
        ('source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled',
         "read-only nonrecursive input closure"),
        ('source=$staging/output,target=/outputs/tool', "single private writable output"),
        ('archive="/online/rust-${RUST_VERSION}.tar.xz"', "exact Rust archive input"),
        ('--version "$CARGO_TOOL_VERSION"', "exact Cargo version request"),
        ("--locked", "packaged lockfile enforcement"),
        ("--root /outputs/tool", "private Cargo install root"),
        ('--bin "$CARGO_TOOL_BINARY"', "single expected binary"),
        ("--target x86_64-unknown-linux-gnu", "exact host target"),
        ("--profile release", "exact Cargo profile"),
        ('install_args+=(--features "$CARGO_TOOL_FEATURES")', "closed optional feature"),
        ("cargo_tool_output_tool verify", "output postcondition"),
        ("cargo_tool_output_tool publish", "checked no-clobber publication"),
        ("retire_cargo_tool_output_staging", "reconciled private retirement"),
        ('[ "$status" -eq 0 ] && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ]',
         "three-verdict publication barrier"),
        ('stage_cargo_installed_tool frb "$builder"', "typed FRB producer"),
        ('stage_cargo_installed_tool cargo-ndk "$builder"', "typed cargo-ndk producer"),
    ):
        require(shell, token, label)

    lifecycle = extract_between(
        shell,
        "stage_cargo_installed_tool() {",
        "\n}\n\n# ── The FRB codegen tool",
        "Cargo-tool output lifecycle",
    )
    require_count(lifecycle, "online_docker_run ", 1, "Cargo-tool container launch")
    require_count(lifecycle, "target=/online", 1, "Cargo-tool online input mount")
    require_count(lifecycle, "target=/outputs/tool", 1, "Cargo-tool output mount")
    require_count(lifecycle, "--locked", 1, "Cargo-tool packaged lockfile enforcement")
    require_count(
        lifecycle,
        '"$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75"',
        2,
        "pre/post Rust archive verification",
    )
    for token, label in (
        ('source=$ONLINE_DIR,target=/online"', "broad writable online mount"),
        ("--root /online/", "direct final Cargo install root"),
        ("/online/frb-tool", "direct FRB publication"),
        ("/online/cargo-ndk-tool", "direct cargo-ndk publication"),
        ("rm -rf \"$ONLINE_DIR/$destination\"", "destructive destination replacement"),
    ):
        require_absent(lifecycle, token, label)
    require_order(
        lifecycle,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "verify_sha256",
            "recover_cargo_tool_output_staging",
            "check-complete",
            "/usr/bin/mktemp -d",
            "cargo_tool_output_tool prepare",
            "online_docker_run",
            ") || input_status=$?",
            "restore-private-directory-modes.py",
            "cargo_tool_output_tool verify",
            "cargo_tool_output_tool publish",
            "retire_cargo_tool_output_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "Cargo-tool checked output transaction",
    )

    for token, label in (
        ('STATE_NAME = ".rustdesk-cargo-tool-output-state-v1"',
         "bounded transaction record"),
        ("TREE_LIMITS = (16, 4, 512 * 1024**2, 512 * 1024**2)",
         "closed output bounds"),
        ("FORBIDDEN_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX",
         "set-id/sticky mode-bit closure"),
        ('REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"',
         "exact registry identity"),
        ('destination="frb-tool"', "FRB destination"),
        ('package="flutter_rust_bridge_codegen"', "FRB package metadata"),
        ('features=("uuid",)', "FRB feature metadata"),
        ('destination="cargo-ndk-tool"', "cargo-ndk destination"),
        ('package="cargo-ndk"', "cargo-ndk package metadata"),
        ("features=()", "cargo-ndk feature metadata"),
        ("reject_descendant_mounts(canonical)", "descendant-mount rejection"),
        ("os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW", "no-follow stable reads"),
        ("stable_metadata(before_file) != stable_metadata(after_file)",
         "stable content reads"),
        ("if metadata.st_nlink != 1:\n"
         '                    fail(f"Cargo tool file is multiply linked: {child_relative}")',
         "external-hardlink rejection"),
        ("Cargo tool output contains a symlink", "symlink rejection"),
        ("Cargo tool output contains a special file", "special-file rejection"),
        ("Cargo tool output has foreign ownership", "owner rejection"),
        ("Cargo tool file is group/world writable", "writable-file rejection"),
        ("if metadata.st_mode & FORBIDDEN_MODE_BITS:",
         "set-id/sticky mode-bit predicate"),
        ("if attributes:", "extended-attribute predicate"),
        ("carries set-id/sticky mode bits", "set-id/sticky mode-bit rejection"),
        ("carries extended attributes", "extended-attribute rejection"),
        ("read_regular_prefix(binary, 64, TREE_LIMITS[3])", "bounded ELF header read"),
        ('ident[:7] != b"\\x7fELF\\x02\\x01\\x01"', "64-bit little-endian ELF gate"),
        ("machine != 62", "x86-64 ELF machine gate"),
        ('set(top_level) != {".crates.toml", ".crates2.json", "bin"}',
         "exact Cargo-root inventory"),
        ("set(binaries) != {spec.binary}", "single binary inventory"),
        ('required = {\n        "version_req": f"={tool_version}"',
         "exact Cargo version metadata"),
        ('"bins": [spec.binary],\n        "features": list(spec.features)',
         "exact Cargo feature metadata"),
        ('"profile": "release"', "release metadata"),
        ('"target": "x86_64-unknown-linux-gnu"', "target metadata"),
        ('"target": "x86_64-unknown-linux-gnu",\n        "rustc": RUSTC_1_75_DETAILS',
         "compiler metadata"),
        ("crates_json != canonical_json", "canonical Cargo JSON bytes"),
        ("sync_tree(output)", "output durability barrier"),
        ("RENAME_NOREPLACE = 1", "no-clobber publication primitive"),
        ('renameat2(staging_fd, "output", online_fd, spec.destination, RENAME_NOREPLACE)',
         "descriptor-relative publication"),
        ("Cargo tool publication rollback also failed", "rollback failure preservation"),
        ('return "unpublished"', "unpublished restart classification"),
        ('return "published"', "published restart classification"),
        ("state is incoherent and was preserved", "ambiguous-state refusal"),
        ("self-test did not classify completed Cargo tool publication",
         "completed recovery fixture"),
        ("self-test accepted an occupied Cargo tool destination",
         "destination race fixture"),
        ("self-test accepted wrong Cargo installation metadata",
         "metadata negative fixture"),
        ("self-test accepted a symlinked Cargo tool output", "symlink negative fixture"),
        ("self-test accepted a hardlinked Cargo tool output", "hardlink negative fixture"),
        ("self-test accepted extended attributes in Cargo tool output",
         "extended-attribute negative fixture"),
        ("self-test accepted set-id mode bits in Cargo tool output",
         "set-id negative fixture"),
    ):
        require(helper, token, label)
    require_order(
        helper,
        (
            "verify_staged(",
            "sync_tree(output)",
            'renameat2(staging_fd, "output", online_fd, spec.destination, RENAME_NOREPLACE)',
            "published Cargo tool identity postcondition failed",
            "validate_semantics(",
        ),
        "checked one-name publication",
    )

    require(
        verify,
        "/usr/bin/python3 -I -S scripts/online-cargo-tool-output.py self-test",
        "transaction self-test wiring",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-cargo-tool-output-authority.py --repo . --self-test",
        "focused verifier wiring",
    )
    require(requirements, '<span class="id">R-S11cm</span>', "R-S11cm requirement")
    require(requirements, "<tr><td>232</td>", "Appendix C #232 disposition")
    require(
        hardening,
        "R-S11cm/R-S11e-105 — networked Cargo-tool acquisition-output authority",
        "hardening-ledger disposition",
    )
    require(
        workspace,
        '"online_fetch_cargo_tool_output_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        workspace,
        "Online-fetch Cargo-tool output authority focused verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation(
        "shell",
        '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \\\n'
        '        || die "another Cargo tool output transaction already owns the online root"',
        "true # Cargo-tool transaction lock removed",
        "exclusive transaction lock",
    ),
    Mutation("shell", '"frb:$DEB_BUILDER_IMAGE_ID")',
             '"frb:"*)', "FRB immutable builder binding"),
    Mutation("shell", '"cargo-ndk:$ANDROID_BUILDER_IMAGE_ID")',
             '"cargo-ndk:"*)', "cargo-ndk immutable builder binding"),
    Mutation("shell", 'stage_cargo_installed_tool frb "$builder"',
             'stage_cargo_installed_tool frb "ubuntu:latest"', "typed FRB producer"),
    Mutation("shell", 'stage_cargo_installed_tool cargo-ndk "$builder"',
             'stage_cargo_installed_tool cargo-ndk "ubuntu:latest"',
             "typed cargo-ndk producer"),
    Mutation(
        "shell",
        '--mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \\\n'
        '        --mount "type=bind,source=$staging/output,target=/outputs/tool"',
        '--mount "type=bind,source=$ONLINE_DIR,target=/online" \\\n'
        '        --mount "type=bind,source=$staging/output,target=/outputs/tool"',
        "read-only online input",
    ),
    Mutation("shell", 'source=$staging/output,target=/outputs/tool',
             'source=$ONLINE_DIR,target=/outputs/tool', "private writable output"),
    Mutation("shell", 'archive="/online/rust-${RUST_VERSION}.tar.xz"',
             'archive="$(find /online -name \"rust-*.tar.xz\" -print -quit)"',
             "exact Rust archive"),
    Mutation("shell", '--version "$CARGO_TOOL_VERSION"',
             "--version '*'", "exact Cargo version request"),
    Mutation(
        "shell",
        '--version "$CARGO_TOOL_VERSION"\n'
        "                --locked\n"
        "                --root /outputs/tool",
        '--version "$CARGO_TOOL_VERSION"\n'
        "                --offline\n"
        "                --root /outputs/tool",
        "packaged lockfile enforcement",
    ),
    Mutation("shell", "--root /outputs/tool",
             "--root /online/frb-tool", "private install root"),
    Mutation("shell", '--bin "$CARGO_TOOL_BINARY"',
             "--bins", "single expected binary"),
    Mutation("shell", "--target x86_64-unknown-linux-gnu",
             "--target \"$HOST\"", "exact Cargo target"),
    Mutation("shell", "--profile release",
             "--profile dev", "exact Cargo profile"),
    Mutation(
        "shell",
        '[ "$status" -eq 0 ] && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ]',
        '[ "$status" -eq 0 ]',
        "publication verdict barrier",
    ),
    Mutation("shell", "cargo_tool_output_tool verify \\\n",
             "cargo_tool_output_tool accept \\\n", "output postcondition"),
    Mutation("helper", "reject_descendant_mounts(canonical)",
             "return # descendant mounts accepted", "mount-closure enforcement"),
    Mutation(
        "helper",
        "if metadata.st_nlink != 1:\n"
        '                    fail(f"Cargo tool file is multiply linked: {child_relative}")',
        "if metadata.st_nlink < 1:\n"
        '                    fail(f"Cargo tool file is multiply linked: {child_relative}")',
        "hardlink rejection",
    ),
    Mutation("helper", "Cargo tool output contains a symlink",
             "Cargo tool output accepts a symlink", "symlink rejection"),
    Mutation("helper", "Cargo tool output contains a special file",
             "Cargo tool output accepts a special file", "special-file rejection"),
    Mutation("helper", "if metadata.st_mode & FORBIDDEN_MODE_BITS:",
             "if False:", "set-id/sticky mode-bit rejection"),
    Mutation("helper", "if attributes:",
             "if False:", "extended-attribute rejection"),
    Mutation("helper", "read_regular_prefix(binary, 64, TREE_LIMITS[3])",
             "read_regular(binary, TREE_LIMITS[3])", "bounded ELF header read"),
    Mutation("helper", "machine != 62",
             "machine == 0", "x86-64 ELF identity"),
    Mutation(
        "helper",
        'required = {\n        "version_req": f"={tool_version}"',
        'required = {\n        "version_req": None',
        "Cargo version metadata",
    ),
    Mutation(
        "helper",
        '"bins": [spec.binary],\n        "features": list(spec.features)',
        '"bins": [spec.binary],\n        "features": []',
        "Cargo feature metadata",
    ),
    Mutation(
        "helper",
        '"target": "x86_64-unknown-linux-gnu",\n        "rustc": RUSTC_1_75_DETAILS',
        '"target": "x86_64-unknown-linux-gnu",\n        "rustc": install.get("rustc")',
        "compiler metadata",
    ),
    Mutation("helper", "crates_json != canonical_json",
             "False", "canonical JSON bytes"),
    Mutation("helper", "sync_tree(output)",
             "pass # output not synchronized", "output durability barrier"),
    Mutation(
        "helper",
        'renameat2(staging_fd, "output", online_fd, spec.destination, RENAME_NOREPLACE)',
        "os.replace(output, destination)",
        "no-clobber publication",
    ),
    Mutation("helper", "Cargo tool publication rollback also failed",
             "Cargo tool publication rollback omitted", "publication rollback"),
    Mutation("helper", "state is incoherent and was preserved",
             "state was discarded", "ambiguous-state refusal"),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-cargo-tool-output-authority.py --repo . --self-test",
        "true # Cargo-tool output authority gate removed",
        "focused verifier wiring",
    ),
    Mutation("requirements", '<span class="id">R-S11cm</span>',
             '<span class="id">R-S11cm-disabled</span>', "R-S11cm requirement"),
    Mutation("requirements", "<tr><td>232</td>",
             "<tr><td>232-disabled</td>", "Appendix C #232 disposition"),
    Mutation(
        "hardening",
        "R-S11cm/R-S11e-105 — networked Cargo-tool acquisition-output authority",
        "R-S11cm/R-S11e-105 — ambient Cargo-tool output authority",
        "hardening disposition",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (repo / "scripts/online-cargo-tool-output.py").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(
            encoding="utf-8"
        ),
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
    value = argparse.ArgumentParser()
    value.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    value.add_argument("--self-test", action="store_true")
    arguments = value.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
        print(
            "verify-online-fetch-cargo-tool-output-authority: PASS "
            "({} mutations rejected)".format(len(MUTATIONS))
        )
    else:
        print("verify-online-fetch-cargo-tool-output-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, AuthorityError) as error:
        raise SystemExit(
            "verify-online-fetch-cargo-tool-output-authority: {}".format(error)
        )
