#!/usr/bin/env python3
"""Check the load-bearing Android NDK extraction/publication boundary."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re


class AuthorityError(RuntimeError):
    pass


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError(f"missing {label}: {token!r}")


def forbid(source: str, token: str, label: str) -> None:
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
        position = source.find(token, position + 1)
        if position < 0:
            raise AuthorityError(f"{label} is missing ordered token {token!r}")


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError(f"{label} start cardinality differs")
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError(f"{label} end is absent")
    return source[begin:finish]


def pin(source: str, name: str) -> str:
    match = re.search(rf'^{re.escape(name)}="([^"]+)"', source, re.MULTILINE)
    if match is None:
        raise AuthorityError(f"{name} is not one canonical quoted pin")
    return match.group(1)


def validate(repo: Path) -> None:
    shell = (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8")
    helper = (repo / "scripts/online-android-ndk-output.py").read_text(
        encoding="utf-8"
    )
    pins = (repo / "scripts/pins.env").read_text(encoding="utf-8")
    verify = (repo / "scripts/verify.sh").read_text(encoding="utf-8")
    try:
        ast.parse(helper)
    except SyntaxError as error:
        raise AuthorityError(f"Android NDK output helper does not parse: {error}") from error

    if pin(pins, "ANDROID_NDK_VERSION") != "r28c":
        raise AuthorityError("Android NDK version is not the audited r28c pin")
    if (
        pin(pins, "SHA256_ANDROID_NDK_R28C")
        != "dfb20d396df28ca02a8c708314b814a4d961dc9074f9a161932746f815aa552f"
    ):
        raise AuthorityError("Android NDK archive digest differs from the audited pin")
    if re.fullmatch(
        r"sha256:[0-9a-f]{64}", pin(pins, "ANDROID_BUILDER_IMAGE_ID")
    ) is None:
        raise AuthorityError("Android builder is not one immutable image ID")

    offline_run = extract(
        shell,
        "online_docker_run_offline() {",
        '        "$@"\n}',
        "networkless archive launch funnel",
    )
    for token, label in (
        ("--pull=never --network=none --read-only", "network and rootfs removal"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges", "privilege removal"),
        ("--pids-limit=512 --memory=4g --memory-swap=4g --cpus=2", "resource limits"),
        (
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
            "bounded non-executable scratch",
        ),
    ):
        require(offline_run, token, label)

    lifecycle = extract(
        shell,
        "stage_android_ndk() {",
        "\n}\n\n# ── The vcpkg-built arm64-android native codecs",
        "Android NDK lifecycle",
    )
    for token, label in (
        ('local builder="$ANDROID_BUILDER_IMAGE_ID"', "immutable builder"),
        ('verify_sha256 "$archive" "$SHA256_ANDROID_NDK_R28C"', "archive precheck"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive lock"),
        ('recover_android_ndk_output_staging "$builder"', "reserved-state recovery"),
        ("$ONLINE_DIR/.rustdesk-android-ndk.XXXXXXXXXX", "private staging"),
        ("android_ndk_output_tool prepare", "transaction preparation"),
        ("online_docker_run_offline", "networkless extractor"),
        (
            "source=$archive,target=/inputs/android-ndk.zip,readonly",
            "read-only archive input",
        ),
        (
            "source=$SCRIPT_DIR/online-android-ndk-output.py,"
            "target=/authority/online-android-ndk-output.py,readonly",
            "read-only helper input",
        ),
        ("source=$staging/output,target=/outputs/android-ndk", "sole writable output"),
        ('[ ! -f "$archive" ] || [ -L "$archive" ]', "archive type postcheck"),
        ('/usr/bin/sha256sum -- "$archive"', "archive digest postcheck"),
        ("android_ndk_output_tool verify", "host output validation"),
        (
            '[ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]; then',
            "independent verdict barrier",
        ),
        ("android_ndk_output_tool publish", "checked publication"),
        ("retire_android_ndk_output_staging", "private retirement"),
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
        ("--publish", "published port"),
        ("--device", "host device"),
        ("docker.sock", "Docker socket mount"),
        ("unzip ", "host archive extraction"),
        (".ndk-tmp", "legacy shared staging"),
        ('rm -rf "$ONLINE_DIR/android-ndk"', "destructive final removal"),
    ):
        forbid(lifecycle, token, label)
    require_order(
        lifecycle,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "recover_android_ndk_output_staging",
            "check-complete",
            "/usr/bin/mktemp -d",
            "android_ndk_output_tool prepare",
            "online_docker_run_offline",
            'sha256sum -- "$archive"',
            "android_ndk_output_tool verify",
            '[ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]',
            "android_ndk_output_tool publish",
            "retire_android_ndk_output_staging",
        ),
        "checked extraction and publication transaction",
    )

    for token, label in (
        ('STATE_NAME = ".rustdesk-android-ndk-output-state-v1"', "transaction state"),
        ('"verified": False', "unverified initial state"),
        ('payload["verified"] = True', "verified selection"),
        ('payload["tree_digest"] = digest', "selected tree digest"),
        ('"r28c": NdkSpec("r28c", "28.2.13676358", "android-ndk-r28c")', "release"),
        ("MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024", "archive bound"),
        ("MAX_ENTRIES = 10000\n", "entry bound"),
        ("MAX_TOTAL_BYTES = 3 * 1024 * 1024 * 1024", "expanded byte bound"),
        ('component in ("", ".", "..")', "path traversal refusal"),
        ("if relative in entries:", "duplicate path refusal"),
        ("if info.flag_bits & ~0x2:", "archive flag refusal"),
        ("validate_symlink_graph(entries)", "symlink graph validation"),
        ("if set(observed) != set(entries):", "exact output inventory"),
        ("if expected != actual:", "every-byte comparison"),
        ("if list_xattrs(path):", "extended-attribute refusal"),
        ("seal_and_sync_tree(candidate, entries)", "candidate sealing"),
        ("RENAME_NOREPLACE = 1", "no-clobber publication"),
        ("def transition_root_mode(", "descriptor-bound root transition"),
        ('return "published-after-root-seal"', "interrupted root-seal recovery"),
        ('root / "post-rename-root-seal-recovery"', "root-seal recovery fixture"),
        ('root / "post-rename-changed"', "changed moved-tree fixture"),
        (
            "Android NDK output transaction state is incoherent and was preserved",
            "ambiguous-state refusal",
        ),
        ("if arguments.uid <= 0 or arguments.gid <= 0:", "root refusal"),
    ):
        require(helper, token, label)
    require_count(helper, "allow_root_mount=True", 2, "extractor root-mount allowances")

    publication = extract(helper, "def publish(", "\n\ndef optional_identity(", "publication")
    forbid(publication, "os.chmod(destination", "pathname root-mode mutation")
    require_order(
        publication,
        (
            "verify_staged(",
            "load_state(",
            'renameat2(\n            output_fd,\n            spec.root,',
            "transition_root_mode(",
            "compare_output(",
            "restore_private_root_mode(",
        ),
        "verify-select-publish-seal-postcheck-rollback sequence",
    )
    transition = extract(
        helper,
        "def transition_root_mode(",
        "\n\ndef restore_private_root_mode(",
        "root mode transition",
    )
    for token, label in (
        ("descriptor = open_directory(path)", "directory descriptor acquisition"),
        ("before = os.fstat(descriptor)", "pre-transition descriptor identity"),
        ("identity(before) != expected_identity", "expected inode binding"),
        ("(before.st_uid, before.st_gid) != (uid, gid)", "owner binding"),
        ("stat.S_IMODE(before.st_mode) != before_mode", "source mode binding"),
        ("os.fchmod(descriptor, after_mode)", "descriptor mode transition"),
        ("os.fsync(descriptor)", "transition durability"),
        ("after = os.fstat(descriptor)", "post-transition identity"),
    ):
        require(transition, token, label)
    recovery = extract(helper, "def recover(", "\n\ndef make_zip_info(", "recovery")
    forbid(recovery, "os.chmod(destination", "recovery pathname mode mutation")
    require_order(
        recovery,
        (
            'if not payload["verified"]:',
            "private_candidate == expected",
            "live_candidate == expected",
            "compare_output(",
            "transition_root_mode(",
            "compare_output(",
            'return "published-after-root-seal"',
        ),
        "verified-inode recovery sequence",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/online-android-ndk-output.py self-test",
        "filesystem transaction self-test wiring",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S "
        "scripts/verify-online-fetch-android-ndk-output-authority.py --repo .",
        "focused source gate wiring",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    arguments = parser.parse_args()
    validate(arguments.repo.resolve())
    print("verify-online-fetch-android-ndk-output-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        raise SystemExit(
            f"verify-online-fetch-android-ndk-output-authority: FAIL: {error}"
        )
