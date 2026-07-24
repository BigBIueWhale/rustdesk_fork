#!/usr/bin/env python3
"""Validate checked extraction and publication of the pinned Android NDK."""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
from dataclasses import dataclass


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
        raise AuthorityError(f"missing {label}: {token!r}")


def require_absent(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError(f"forbidden {label} remains: {token!r}")


def require_count(source: str, token: str, expected: int, label: str) -> None:
    actual = source.count(token)
    if actual != expected:
        raise AuthorityError(
            f"{label} count is {actual}, expected {expected}: {token!r}"
        )


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        if found < 0:
            raise AuthorityError(f"{label} is missing ordered token {token!r}")
        position = found


def extract_between(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError(f"{label} start cardinality differs")
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError(f"{label} end is absent")
    return source[begin:finish]


def pin_value(source: str, name: str) -> str:
    match = re.search(
        rf'^{re.escape(name)}="([^"]+)"',
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AuthorityError(f"{name} is not one canonical quoted pin")
    return match.group(1)


def validate(sources: dict[str, str]) -> None:
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
            f"Android NDK output helper does not parse: {error}"
        ) from error

    if pin_value(pins, "ANDROID_NDK_VERSION") != "r28c":
        raise AuthorityError("Android NDK version is not the audited r28c pin")
    if (
        pin_value(pins, "SHA256_ANDROID_NDK_R28C")
        != "dfb20d396df28ca02a8c708314b814a4d961dc9074f9a161932746f815aa552f"
    ):
        raise AuthorityError("Android NDK archive digest differs from the audited pin")
    if re.fullmatch(
        r"sha256:[0-9a-f]{64}",
        pin_value(pins, "ANDROID_BUILDER_IMAGE_ID"),
    ) is None:
        raise AuthorityError("Android builder is not one immutable image ID")

    offline_run = extract_between(
        shell,
        "online_docker_run_offline() {",
        "\n}\n\nif [ -e \"$ONLINE_DIR\" ]",
        "networkless archive launch funnel",
    )
    for token, label in (
        ("--pull=never --network=none --read-only", "network and rootfs removal"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges", "privilege removal"),
        (
            "--pids-limit=512 --memory=4g --memory-swap=4g --cpus=2",
            "resource ceilings",
        ),
        (
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
            "bounded non-executable scratch",
        ),
    ):
        require(offline_run, token, label)
    for token, label in (
        ("online_docker_run_offline() {", "networkless container funnel"),
        ("android_ndk_output_tool() {", "fixed transaction helper"),
        ("android_ndk_output_args() {", "closed transaction argument mapper"),
        ("retire_android_ndk_output_staging() {", "private retirement"),
        ("recover_android_ndk_output_staging() {", "restart recovery"),
    ):
        require(shell, token, label)

    lifecycle = extract_between(
        shell,
        "stage_android_ndk() {",
        "\n}\n\n# ── The vcpkg-built arm64-android native codecs",
        "Android NDK lifecycle",
    )
    for token, label in (
        ('local builder="$ANDROID_BUILDER_IMAGE_ID"', "immutable builder"),
        ('verify_sha256 "$archive" "$SHA256_ANDROID_NDK_R28C"', "archive precheck"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive transaction"),
        (
            'recover_android_ndk_output_staging "$builder"',
            "reserved-state recovery",
        ),
        (
            "$ONLINE_DIR/.rustdesk-android-ndk.XXXXXXXXXX",
            "unpredictable same-filesystem staging",
        ),
        ("android_ndk_output_tool prepare", "transaction preparation"),
        ("online_docker_run_offline", "networkless extractor launch"),
        (
            "source=$archive,target=/inputs/android-ndk.zip,readonly",
            "exact read-only archive input",
        ),
        (
            "source=$SCRIPT_DIR/online-android-ndk-output.py,"
            "target=/authority/online-android-ndk-output.py,readonly",
            "exact read-only helper input",
        ),
        (
            "source=$staging/output,target=/outputs/android-ndk",
            "sole writable output",
        ),
        (
            '[ ! -f "$archive" ] || [ -L "$archive" ]',
            "archive type postcondition",
        ),
        (
            '/usr/bin/sha256sum -- "$archive"',
            "archive digest postcondition",
        ),
        ("android_ndk_output_tool verify", "independent host postcondition"),
        ("android_ndk_output_tool publish", "checked publication"),
        (
            '"$staging" "$staging_id" "$builder"',
            "identity-bound private retirement",
        ),
    ):
        require(lifecycle, token, label)
    require_count(lifecycle, "--mount ", 3, "Android NDK mount inventory")
    require_count(
        lifecycle,
        "source=$staging/output,target=/outputs/android-ndk",
        1,
        "Android NDK writable output mount",
    )
    for token, label in (
        ("source=$ONLINE_DIR,target=/online", "broad online-tree mount"),
        ("source=/,target=", "host-root mount"),
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--publish", "published port"),
        ("--device", "host device"),
        ("docker.sock", "Docker socket mount"),
        ("unzip ", "host archive extraction"),
        (".ndk-tmp", "legacy shared temporary tree"),
        ('rm -rf "$ONLINE_DIR/android-ndk"', "destructive final removal"),
        ('mv "$ONLINE_DIR/.ndk-tmp', "unchecked shell publication"),
    ):
        require_absent(lifecycle, token, label)
    require_order(
        lifecycle,
        (
            "require_online_fetch_builder_image",
            'verify_sha256 "$archive"',
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "recover_android_ndk_output_staging",
            "check-complete",
            "/usr/bin/mktemp -d",
            "android_ndk_output_tool prepare",
            "online_docker_run_offline",
            "sha256sum -- \"$archive\"",
            "android_ndk_output_tool verify",
            '[ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]',
            "android_ndk_output_tool publish",
            "retire_android_ndk_output_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "validate-seal-publish-retire order",
    )

    for token, label in (
        (
            'STATE_NAME = ".rustdesk-android-ndk-output-state-v1"',
            "bounded transaction state",
        ),
        ('"r28c": NdkSpec("r28c", "28.2.13676358", "android-ndk-r28c")',
         "closed release specification"),
        ("MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024", "archive byte bound"),
        ("MAX_ENTRIES = 10000\n", "entry-count bound"),
        ("MAX_TOTAL_BYTES = 3 * 1024 * 1024 * 1024", "expanded byte bound"),
        ("MAX_FILE_BYTES = 256 * 1024 * 1024", "member byte bound"),
        ("MAX_DEPTH = 20", "path-depth bound"),
        ("if info.orig_filename != info.filename:", "NUL-truncation rejection"),
        ("not raw.isascii()", "closed archive-name alphabet"),
        ('component in ("", ".", "..")', "path traversal rejection"),
        ("if relative in entries:", "duplicate output rejection"),
        ("if info.create_system != 3:", "Unix type authority"),
        ("if info.flag_bits & ~0x2:", "encryption and flag rejection"),
        (
            "info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)",
            "closed compression set",
        ),
        ("else:\n            fail(f\"Android NDK archive contains a special member",
         "special-member rejection"),
        (
            "Android NDK archive member lacks an explicit real parent",
            "explicit-directory requirement",
        ),
        ("validate_symlink_graph(entries)", "bounded symlink graph validation"),
        (
            "Android NDK archive symlink escapes its exact root",
            "symlink escape rejection",
        ),
        (
            "Android NDK source.properties does not match the pinned revision",
            "release-metadata binding",
        ),
        (
            "os.O_CREAT\n                | os.O_EXCL\n"
            "                | os.O_CLOEXEC\n                | os.O_NOFOLLOW",
            "no-clobber file extraction",
        ),
        (
            "allow_root_mount=True",
            "exact extractor-root mount allowance",
        ),
        (
            "(mountpoint == encoded and not allow_root)\n"
            "            or mountpoint.startswith(prefix)",
            "nested-mount rejection",
        ),
        ("if set(observed) != set(entries):", "exact output inventory"),
        (
            "if expected != actual:",
            "every-byte archive comparison",
        ),
        (
            "not stat.S_ISREG(before.st_mode) or before.st_nlink != 1",
            "external-hardlink rejection",
        ),
        ("if list_xattrs(path):", "extended-attribute rejection"),
        ("seal_and_sync_tree(candidate, entries)", "candidate sealing"),
        ("os.fsync(descriptor)", "file and directory durability"),
        ("RENAME_NOREPLACE = 1", "no-clobber publication primitive"),
        (
            'renameat2(\n            output_fd,\n            spec.root,\n'
            '            online_fd,\n            "android-ndk",\n'
            "            RENAME_NOREPLACE,",
            "descriptor-relative publication",
        ),
        (
            "Android NDK publication rollback also failed",
            "rollback failure preservation",
        ),
        (
            'return "verified-unpublished-destination-occupied"',
            "destination-race recovery",
        ),
        ('return "unprepared-state-write"', "interrupted state-write recovery"),
        (
            "Android NDK output transaction state is incoherent and was preserved",
            "ambiguous-state refusal",
        ),
        (
            "self-test accepted Android NDK archive path traversal",
            "path traversal fixture",
        ),
        (
            "self-test accepted an escaping Android NDK symlink",
            "symlink escape fixture",
        ),
        (
            "self-test accepted a duplicate Android NDK output path",
            "duplicate output fixture",
        ),
        (
            "self-test accepted a special Android NDK archive member",
            "special member fixture",
        ),
        (
            "self-test accepted an externally hardlinked Android NDK output",
            "hardlink fixture",
        ),
        (
            "self-test did not classify an interrupted Android NDK state write",
            "interrupted state-write fixture",
        ),
        (
            "self-test accepted extended attributes in Android NDK output",
            "extended-attribute fixture",
        ),
        (
            "if arguments.uid <= 0 or arguments.gid <= 0:",
            "root transaction refusal",
        ),
        (
            "if uid <= 0 or gid <= 0:\n"
            '        fail("Android NDK extraction refuses root UID or GID")',
            "root extractor refusal",
        ),
    ):
        require(helper, token, label)
    require_count(
        helper,
        "allow_root_mount=True",
        2,
        "extractor-only root mount allowances",
    )
    require_order(
        helper,
        (
            "def verify_staged(",
            'profile="raw"',
            "seal_and_sync_tree(candidate, entries)",
            'profile="private-sealed"',
            "def publish(",
            'renameat2(\n            output_fd,\n            spec.root,',
            "os.chmod(destination, 0o555",
            'profile="sealed"',
        ),
        "validate-seal-publish-postcheck order",
    )

    require(
        verify,
        "/usr/bin/python3 -I -S scripts/online-android-ndk-output.py self-test",
        "transaction self-test wiring",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S "
        "scripts/verify-online-fetch-android-ndk-output-authority.py "
        "--repo . --self-test",
        "focused verifier wiring",
    )
    require(requirements, '<span class="id">R-S11cq</span>', "R-S11cq requirement")
    require(requirements, "<tr><td>244</td>", "Appendix C #244 disposition")
    require(
        hardening,
        "R-S11cq/R-S11e-109 — Android NDK extraction and output authority",
        "hardening-ledger disposition",
    )
    require(
        workspace,
        '"online_fetch_android_ndk_output_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        workspace,
        "Online-fetch Android NDK output authority focused verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS = (
    Mutation("pins", 'ANDROID_NDK_VERSION="r28c"', 'ANDROID_NDK_VERSION="latest"',
             "closed release version"),
    Mutation(
        "pins",
        'SHA256_ANDROID_NDK_R28C="dfb20d396df28ca02a8c708314b814a4d961dc9074f9a161932746f815aa552f"',
        'SHA256_ANDROID_NDK_R28C="0fb20d396df28ca02a8c708314b814a4d961dc9074f9a161932746f815aa552f"',
        "exact archive digest",
    ),
    Mutation(
        "shell",
        "online_docker_run_offline() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only",
        "online_docker_run_offline() {\n"
        "    online_docker run --rm --pull=always --network=bridge",
        "networkless no-pull launch",
    ),
    Mutation(
        "shell",
        "--cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=512 --memory=4g --memory-swap=4g --cpus=2",
        "--cap-drop=NET_RAW --security-opt=seccomp=unconfined \\\n"
        "        --pids-limit=512 --memory=4g --memory-swap=4g --cpus=2",
        "privilege removal",
    ),
    Mutation("shell", "--pids-limit=512 --memory=4g --memory-swap=4g --cpus=2",
             "--pids-limit=-1 --memory=0 --memory-swap=-1 --cpus=0",
             "resource ceilings"),
    Mutation(
        "shell",
        "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
        "--tmpfs /tmp:rw,exec,mode=1777",
        "bounded non-executable scratch",
    ),
    Mutation(
        "shell",
        "source=$archive,target=/inputs/android-ndk.zip,readonly",
        "source=$ONLINE_DIR,target=/online",
        "exact archive input",
    ),
    Mutation(
        "shell",
        "source=$staging/output,target=/outputs/android-ndk",
        "source=$ONLINE_DIR,target=/outputs/android-ndk",
        "sole writable output",
    ),
    Mutation("shell", "android_ndk_output_tool verify",
             "true # Android NDK output verification removed",
             "independent output postcondition"),
    Mutation("shell", "android_ndk_output_tool publish",
             "mv \"$staging/output/android-ndk-r28c\" \"$ONLINE_DIR/android-ndk\"",
             "checked publication"),
    Mutation("helper", "MAX_ENTRIES = 10000\n", "MAX_ENTRIES = 1000000\n",
             "entry-count bound"),
    Mutation("helper", "MAX_TOTAL_BYTES = 3 * 1024 * 1024 * 1024",
             "MAX_TOTAL_BYTES = 30 * 1024 * 1024 * 1024",
             "expanded byte bound"),
    Mutation("helper", "not raw.isascii()", "False", "closed archive-name alphabet"),
    Mutation("helper", 'component in ("", ".", "..")',
             'component in ("", ".")', "path traversal rejection"),
    Mutation("helper", "if relative in entries:", "if False:",
             "duplicate output rejection"),
    Mutation("helper", "if info.create_system != 3:", "if False:",
             "Unix type authority"),
    Mutation("helper", "if info.flag_bits & ~0x2:", "if False:",
             "encrypted flag rejection"),
    Mutation(
        "helper",
        "info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)",
        "False",
        "closed compression set",
    ),
    Mutation("helper", "validate_symlink_graph(entries)",
             "return entries # symlink graph skipped", "symlink graph validation"),
    Mutation(
        "helper",
        "(mountpoint == encoded and not allow_root)\n"
        "            or mountpoint.startswith(prefix)",
        "mountpoint == encoded and not allow_root",
        "nested-mount rejection",
    ),
    Mutation("helper", "if set(observed) != set(entries):", "if False:",
             "exact output inventory"),
    Mutation("helper", "if expected != actual:", "if len(expected) != len(actual):",
             "every-byte comparison"),
    Mutation(
        "helper",
        "not stat.S_ISREG(before.st_mode) or before.st_nlink != 1",
        "not stat.S_ISREG(before.st_mode) or before.st_nlink < 1",
        "external-hardlink rejection",
    ),
    Mutation("helper", "if list_xattrs(path):", "if False:",
             "extended-attribute rejection"),
    Mutation("helper", "seal_and_sync_tree(candidate, entries)",
             "return # candidate sealing removed", "candidate sealing"),
    Mutation("helper", "RENAME_NOREPLACE = 1", "RENAME_NOREPLACE = 0",
             "no-clobber publication"),
    Mutation("helper", "os.chmod(destination, 0o555, follow_symlinks=False)",
             "os.chmod(destination, 0o755, follow_symlinks=False)",
             "published sealing"),
    Mutation(
        "helper",
        "if arguments.uid <= 0 or arguments.gid <= 0:",
        "if arguments.uid < 0 or arguments.gid < 0:",
        "root transaction refusal",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S "
        "scripts/verify-online-fetch-android-ndk-output-authority.py "
        "--repo . --self-test",
        "true # Android NDK authority gate removed",
        "focused verifier wiring",
    ),
    Mutation("requirements", '<span class="id">R-S11cq</span>',
             '<span class="id">R-S11cq-disabled</span>', "R-S11cq requirement"),
    Mutation("requirements", "<tr><td>244</td>", "<tr><td>244-disabled</td>",
             "Appendix C #244 disposition"),
    Mutation(
        "hardening",
        "R-S11cq/R-S11e-109 — Android NDK extraction and output authority",
        "R-S11cq/R-S11e-109 — unchecked Android NDK extraction",
        "hardening-ledger disposition",
    ),
)


def load_sources(repo: pathlib.Path) -> dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (repo / "scripts/online-android-ndk-output.py").read_text(
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


def run_mutations(sources: dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        if count != 1:
            raise AuthorityError(
                f"mutation target for {mutation.label} occurs {count} times"
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(
            mutation.old,
            mutation.new,
            1,
        )
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError(f"mutation was accepted: {mutation.label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
    suffix = f" ({len(MUTATIONS)} mutations)" if arguments.self_test else ""
    print(f"verify-online-fetch-android-ndk-output-authority: OK{suffix}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print(f"verify-online-fetch-android-ndk-output-authority: {error}")
        raise SystemExit(1)
