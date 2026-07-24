#!/usr/bin/env python3
"""Validate checked publication of the network-acquired libyuv distfile."""

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
            "{} count is {}, expected {}: {!r}".format(
                label, actual, expected, token
            )
        )


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        if found < 0:
            raise AuthorityError(
                "{} is missing ordered token {!r}".format(label, token)
            )
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
        raise AuthorityError(
            "libyuv output helper does not parse: {}".format(error)
        ) from error

    commit = pin_value(pins, "LIBYUV_COMMIT")
    digest = pin_value(pins, "SHA512_LIBYUV")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise AuthorityError("LIBYUV_COMMIT is not one lowercase full Git object ID")
    if re.fullmatch(r"[0-9a-f]{128}", digest) is None:
        raise AuthorityError("SHA512_LIBYUV is not one lowercase SHA-512 pin")

    for token, label in (
        ("readonly FLOCK_BIN=/usr/bin/flock", "fixed transaction-lock client"),
        ("libyuv_distfile_output_tool() {", "fixed output helper"),
        ("libyuv_distfile_output_args() {", "closed output argument mapper"),
        ("retire_libyuv_distfile_staging() {", "private staging retirement"),
        ("recover_libyuv_distfile_staging() {", "reserved-state recovery"),
        ("stage_vcpkg_distfiles() {", "libyuv producer lifecycle"),
        ('local builder="$DEB_BUILDER_IMAGE_ID"', "immutable Debian builder"),
        ("require_online_fetch_builder_image deb-builder \"$builder\"",
         "loaded image verification"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
         "exclusive output transaction"),
        ('"$ONLINE_DIR/.rustdesk-libyuv-distfile.XXXXXXXXXX"',
         "unpredictable same-filesystem staging"),
        ("libyuv_distfile_output_tool prepare", "transaction preparation"),
        ('--env LIBYUV_COMMIT="$LIBYUV_COMMIT"', "exact commit environment"),
        ('--env SHA512_LIBYUV="$SHA512_LIBYUV"', "exact digest environment"),
        ('source=$staging/output,target=/outputs/libyuv.tar.gz',
         "single writable file mount"),
        ("https://chromium.googlesource.com/libyuv/libyuv",
         "fixed libyuv origin"),
        ('git cat-file -e "${LIBYUV_COMMIT}^{commit}"',
         "exact commit-object proof"),
        ('archive --format=tar "$LIBYUV_COMMIT"', "exact Git archive request"),
        ("| gzip -n > /outputs/libyuv.tar.gz", "timestamp-free gzip output"),
        ('[ "$got" = "$SHA512_LIBYUV" ]', "producer-side SHA-512 check"),
        ("libyuv_distfile_output_tool verify", "host output postcondition"),
        ("libyuv_distfile_output_tool publish", "checked publication"),
        ("retire_libyuv_distfile_staging", "reconciled private retirement"),
        ('[ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]',
         "independent publication barrier"),
    ):
        require(shell, token, label)

    lifecycle = extract_between(
        shell,
        "stage_vcpkg_distfiles() {",
        "\n}\n\n# ── The vcpkg-built native codecs",
        "libyuv output lifecycle",
    )
    require_count(lifecycle, "online_docker_run ", 1, "libyuv producer launch")
    require_count(
        lifecycle,
        "target=/outputs/libyuv.tar.gz",
        1,
        "libyuv writable output mount",
    )
    require_count(
        lifecycle,
        "https://chromium.googlesource.com/libyuv/libyuv",
        2,
        "fixed shallow/full Git origin",
    )
    require(lifecycle, 'local builder="$DEB_BUILDER_IMAGE_ID"',
            "libyuv immutable Debian builder")
    for token, label in (
        ("target=/online", "online input mount"),
        ("source=$ONLINE_DIR", "broad online mount"),
        ("/online/libyuv-", "direct final-name output"),
        ("rm -f \"$ONLINE_DIR/libyuv-", "destructive final-name removal"),
        ("mv \"$staging/output\"", "unchecked shell publication"),
    ):
        require_absent(lifecycle, token, label)
    require_order(
        lifecycle,
        (
            "stage_libvpx_distfiles",
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "recover_libyuv_distfile_staging",
            "check-complete",
            "/usr/bin/mktemp -d",
            "libyuv_distfile_output_tool prepare",
            "online_docker_run",
            "libyuv_distfile_output_tool verify",
            '[ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]',
            "libyuv_distfile_output_tool publish",
            "retire_libyuv_distfile_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "checked libyuv output transaction",
    )

    for token, label in (
        ('STATE_NAME = ".rustdesk-libyuv-distfile-state-v1"',
         "bounded transaction record"),
        ("MAX_ARCHIVE_BYTES = 64 * 1024 * 1024\nMAX_STATE_BYTES = 4096",
         "archive byte bound"),
        ("COMMIT_PATTERN = re.compile(r\"[0-9a-f]{40}\\Z\")",
         "full commit grammar"),
        ("SHA512_PATTERN = re.compile(r\"[0-9a-f]{128}\\Z\")",
         "SHA-512 grammar"),
        ("reject_mount_at_or_below(staging)", "private mount closure"),
        ("os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW",
         "no-follow stable read"),
        ("stable_file_metadata(before) != stable_file_metadata(after)",
         "stable content read"),
        ("if metadata.st_nlink != 1:\n"
         '        fail("libyuv archive has a hardlink outside its single-file output")',
         "external-hardlink rejection"),
        ("if list_xattrs(archive):\n"
         '        fail("libyuv archive carries extended attributes")',
         "extended-attribute rejection"),
        ("if hashlib.sha512(data).hexdigest() != expected_sha512:\n"
         '        fail("libyuv archive SHA-512 does not match its pin")',
         "host digest rejection"),
        ("historical root-owned libyuv archive is not mode 0644",
         "closed historical compatibility"),
        ("os.fchmod(descriptor, 0o400)", "read-only candidate sealing"),
        ("os.fsync(descriptor)", "file durability"),
        ("fsync_directory(staging)", "staging-directory durability"),
        ("RENAME_NOREPLACE = 1", "no-clobber publication primitive"),
        ("renameat2(\n            staging_fd,\n            \"output\",\n            online_fd,",
         "descriptor-relative publication"),
        ("libyuv archive publication rollback also failed",
         "rollback failure preservation"),
        ('return "unpublished"', "unpublished recovery"),
        ('return "published"', "published recovery"),
        ('return "unpublished-destination-occupied"',
         "destination-race recovery"),
        ('return "unprepared-state-write"',
         "interrupted state-write recovery"),
        ("state is incoherent and was preserved", "ambiguous-state refusal"),
        ("self-test did not classify completed libyuv publication",
         "completed recovery fixture"),
        ("self-test accepted a wrong libyuv archive digest",
         "digest negative fixture"),
        ("self-test accepted an occupied libyuv destination",
         "destination-race fixture"),
        ("self-test accepted a symlinked libyuv output",
         "symlink negative fixture"),
        ("self-test accepted a hardlinked libyuv output",
         "hardlink negative fixture"),
        ("self-test did not classify an interrupted libyuv state write",
         "interrupted state-write fixture"),
        ("self-test accepted extended attributes on libyuv output",
         "extended-attribute negative fixture"),
    ):
        require(helper, token, label)
    require_order(
        helper,
        (
            "validate_archive(",
            "os.fchmod(descriptor, 0o400)",
            "validate_archive(",
            "def publish(",
            "os.fsync(descriptor)",
            "fsync_directory(staging)",
            "renameat2(",
            "validate_archive(",
        ),
        "validate-seal-publish-postcheck order",
    )

    require(
        verify,
        "/usr/bin/python3 -I -S scripts/online-libyuv-distfile-output.py self-test",
        "transaction self-test wiring",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-libyuv-output-authority.py --repo . --self-test",
        "focused verifier wiring",
    )
    require(requirements, '<span class="id">R-S11co</span>', "R-S11co requirement")
    require(requirements, "<tr><td>242</td>", "Appendix C #242 disposition")
    require(
        hardening,
        "R-S11co/R-S11e-107 — networked libyuv distfile output authority",
        "hardening-ledger disposition",
    )
    require(
        workspace,
        '"online_fetch_libyuv_output_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        workspace,
        "Online-fetch libyuv output authority focused verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation(
        "shell",
        '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \\\n'
        '        || die "another libyuv distfile output transaction already owns the online root"',
        "true # libyuv transaction lock removed",
        "exclusive transaction lock",
    ),
    Mutation(
        "shell",
        "stage_vcpkg_distfiles() {\n"
        "    stage_libvpx_distfiles\n"
        '    local builder="$DEB_BUILDER_IMAGE_ID"',
        "stage_vcpkg_distfiles() {\n"
        "    stage_libvpx_distfiles\n"
        '    local builder="ubuntu:latest"',
        "immutable builder binding",
    ),
    Mutation(
        "shell",
        '--mount "type=bind,source=$staging/output,target=/outputs/libyuv.tar.gz"',
        '--mount "type=bind,source=$ONLINE_DIR,target=/online" \\\n'
        '        --mount "type=bind,source=$staging/output,target=/outputs/libyuv.tar.gz"',
        "online mount absence",
    ),
    Mutation(
        "shell",
        "source=$staging/output,target=/outputs/libyuv.tar.gz",
        "source=$ONLINE_DIR,target=/outputs/libyuv.tar.gz",
        "single writable output",
    ),
    Mutation(
        "shell",
        "git remote add origin https://chromium.googlesource.com/libyuv/libyuv",
        'git remote add origin "$LIBYUV_ORIGIN"',
        "fixed Git origin",
    ),
    Mutation(
        "shell",
        'git cat-file -e "${LIBYUV_COMMIT}^{commit}"',
        "true # exact commit proof removed",
        "exact commit proof",
    ),
    Mutation(
        "shell",
        'archive --format=tar "$LIBYUV_COMMIT"',
        "archive --format=tar HEAD",
        "exact archive request",
    ),
    Mutation(
        "shell",
        "| gzip -n > /outputs/libyuv.tar.gz",
        "| gzip > /outputs/libyuv.tar.gz",
        "deterministic gzip",
    ),
    Mutation(
        "shell",
        '[ "$got" = "$SHA512_LIBYUV" ]',
        '[ -n "$got" ]',
        "producer digest check",
    ),
    Mutation(
        "shell",
        '[ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]',
        '[ "$status" -eq 0 ]',
        "publication verdict barrier",
    ),
    Mutation(
        "shell",
        "libyuv_distfile_output_tool verify \\\n",
        "libyuv_distfile_output_tool accept \\\n",
        "host output postcondition",
    ),
    Mutation(
        "helper",
        "reject_mount_at_or_below(staging)",
        "return # private mount accepted",
        "staging mount closure",
    ),
    Mutation(
        "helper",
        "if metadata.st_nlink != 1:\n"
        '        fail("libyuv archive has a hardlink outside its single-file output")',
        "if metadata.st_nlink < 1:\n"
        '        fail("libyuv archive has a hardlink outside its single-file output")',
        "external-hardlink rejection",
    ),
    Mutation(
        "helper",
        "if list_xattrs(archive):",
        "if False:",
        "extended-attribute rejection",
    ),
    Mutation(
        "helper",
        "hashlib.sha512(data).hexdigest() != expected_sha512",
        "False",
        "host SHA-512 validation",
    ),
    Mutation(
        "helper",
        "MAX_ARCHIVE_BYTES = 64 * 1024 * 1024",
        "MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024",
        "archive size bound",
    ),
    Mutation(
        "helper",
        "os.fchmod(descriptor, 0o400)",
        "os.fchmod(descriptor, 0o600)",
        "read-only sealing",
    ),
    Mutation(
        "helper",
        "stable_file_metadata(before) != stable_file_metadata(after)",
        "False",
        "stable file read",
    ),
    Mutation(
        "helper",
        "os.fsync(descriptor)\n    finally:\n        os.close(descriptor)\n"
        "    fsync_directory(staging)",
        "pass # file durability removed\n    finally:\n        os.close(descriptor)\n"
        "    fsync_directory(staging)",
        "file durability barrier",
    ),
    Mutation(
        "helper",
        "renameat2(\n            staging_fd,\n            \"output\",\n            online_fd,",
        "os.replace(\n            output,\n            destination,\n            #",
        "descriptor-relative no-clobber publication",
    ),
    Mutation(
        "helper",
        "libyuv archive publication rollback also failed",
        "libyuv archive publication rollback omitted",
        "publication rollback",
    ),
    Mutation(
        "helper",
        "state is incoherent and was preserved",
        "state was discarded",
        "ambiguous-state refusal",
    ),
    Mutation(
        "helper",
        'return "unprepared-state-write"',
        'return "unprepared-output"',
        "interrupted state-write recovery",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-libyuv-output-authority.py --repo . --self-test",
        "true # libyuv output authority gate removed",
        "focused verifier wiring",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11co</span>',
        '<span class="id">R-S11co-disabled</span>',
        "R-S11co requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>242</td>",
        "<tr><td>242-disabled</td>",
        "Appendix C #242 disposition",
    ),
    Mutation(
        "hardening",
        "R-S11co/R-S11e-107 — networked libyuv distfile output authority",
        "R-S11co/R-S11e-107 — ambient libyuv distfile output authority",
        "hardening disposition",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (repo / "scripts/online-libyuv-distfile-output.py").read_text(
            encoding="utf-8"
        ),
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
                "mutation target for {} occurs {} times".format(
                    mutation.label, count
                )
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
    arguments = parser.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
        print(
            "verify-online-fetch-libyuv-output-authority: PASS "
            "({} mutations rejected)".format(len(MUTATIONS))
        )
    else:
        print("verify-online-fetch-libyuv-output-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, AuthorityError) as error:
        raise SystemExit(
            "verify-online-fetch-libyuv-output-authority: {}".format(error)
        )
