#!/usr/bin/env python3
"""Bind the fixed SHA-256 archive acquisition/publication authority."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


FILES = {
    "shell": Path("scripts/online-fetch.sh"),
    "helper": Path("scripts/online-fixed-archive-output.py"),
    "pins": Path("scripts/pins.env"),
    "verify": Path("scripts/verify.sh"),
    "requirements": Path("requirements.html"),
    "ledger": Path("HARDENING_STATUS.md"),
}

EXPECTED_SIZES = {
    "SIZE_ANDROID_CMDLINE_TOOLS": "174244366",
    "SIZE_ANDROID_NDK_R28C": "722261334",
    "SIZE_FRB_1_80_1": "1288919",
    "SIZE_FLUTTER_3_24_5": "693186548",
    "SIZE_FLUTTER_WIN_3_24_5": "1033788155",
    "SIZE_LLVM_15_0_6": "817102112",
    "SIZE_LLVM_WIN_15_0_6": "290951930",
    "SIZE_OLEFILE_0_47": "114565",
    "SIZE_PYTHON_WIN_3_11_9": "26216840",
    "SIZE_RUST_1_75": "156249584",
    "SIZE_RUST_STD_ANDROID_1_75": "22986424",
    "SIZE_VCPKG_120DEAC3": "4723233",
    "SIZE_GIT_WIN_2_45_2": "68131584",
    "SIZE_RUST_MSVC_1_75": "222101369",
}

EXPECTED_SHA256 = {
    "SHA256_ANDROID_CMDLINE_TOOLS": "a66d5ef0238fc0162e9c1446602ce0dd41702d4dd7a94d2ce42d12b7f80baf7e",
    "SHA256_ANDROID_NDK_R28C": "dfb20d396df28ca02a8c708314b814a4d961dc9074f9a161932746f815aa552f",
    "SHA256_FRB_1_80_1": "5c1494e79024de228a9f383c8e52e45b042cd0cf24f4b0f47ee4d5448938b336",
    "SHA256_FLUTTER_3_24_5": "a7c82f551a9eae018e078f6bb186171e5a77920d35a3d75a61d9a593d0a9e4ae",
    "SHA256_FLUTTER_WIN_3_24_5": "b8a7485acd3c6fb23a76b7ac09f89e8d93d62fbff7147c6f5f8c5686d949eeac",
    "SHA256_LLVM_15_0_6": "38bc7f5563642e73e69ac5626724e206d6d539fbef653541b34cae0ba9c3f036",
    "SHA256_LLVM_WIN_15_0_6": "22e2f2c38be4c44db7a1e9da5e67de2a453c5b4be9cf91e139592a63877ac0a2",
    "SHA256_OLEFILE_0_47": "543c7da2a7adadf21214938bb79c83ea12b473a4b6ee4ad4bf854e7715e13d1f",
    "SHA256_PYTHON_WIN_3_11_9": "5ee42c4eee1e6b4464bb23722f90b45303f79442df63083f05322f1785f5fdde",
    "SHA256_RUST_1_75": "6bf166ddcad545aa26aa2d12a186454d7697133b52b7fbbd271ce3ee1ecfedc6",
    "SHA256_RUST_STD_ANDROID_1_75": "6225fa73cf98fc11e83e14b7021391678fcb4a71b7c2b7db05a0793240ea2945",
    "SHA256_VCPKG_120DEAC3": "f3b1ec711fa1ba291efd75e27983898a37be15760dfe129a406448fa7377b31d",
    "SHA256_GIT_WIN_2_45_2": "ce022a6a19e58bbbd4823f51cf798b006b4a683b93b0616a7bb5beeee901da98",
    "SHA256_RUST_MSVC_1_75": "c090304864698576114cda578d43da2c81abaf9263efddf1bfc9ea5900cda07f",
}

EXPECTED_MANIFEST = (
    (
        "android-cmdline-tools.zip",
        "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_BUILD}_latest.zip",
        "$SIZE_ANDROID_CMDLINE_TOOLS",
        "$SHA256_ANDROID_CMDLINE_TOOLS",
        "dl.google.com",
    ),
    (
        "android-ndk-${ANDROID_NDK_VERSION}.zip",
        "https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip",
        "$SIZE_ANDROID_NDK_R28C",
        "$SHA256_ANDROID_NDK_R28C",
        "dl.google.com",
    ),
    (
        "flutter-${FLUTTER_VERSION}.tar.xz",
        "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz",
        "$SIZE_FLUTTER_3_24_5",
        "$SHA256_FLUTTER_3_24_5",
        "storage.googleapis.com",
    ),
    (
        "flutter-windows-${FLUTTER_VERSION}.zip",
        "https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${FLUTTER_VERSION}-stable.zip",
        "$SIZE_FLUTTER_WIN_3_24_5",
        "$SHA256_FLUTTER_WIN_3_24_5",
        "storage.googleapis.com",
    ),
    (
        "frb-${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz",
        "https://github.com/fzyzcjy/flutter_rust_bridge/archive/refs/tags/v${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz",
        "$SIZE_FRB_1_80_1",
        "$SHA256_FRB_1_80_1",
        "github.com,codeload.github.com,release-assets.githubusercontent.com,objects.githubusercontent.com",
    ),
    (
        "llvm-${LLVM_VERSION}.tar.xz",
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz",
        "$SIZE_LLVM_15_0_6",
        "$SHA256_LLVM_15_0_6",
        "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com",
    ),
    (
        "llvm-windows-${LLVM_VERSION}.exe",
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/LLVM-${LLVM_VERSION}-win64.exe",
        "$SIZE_LLVM_WIN_15_0_6",
        "$SHA256_LLVM_WIN_15_0_6",
        "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com",
    ),
    (
        "olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl",
        "https://files.pythonhosted.org/packages/17/d3/b64c356a907242d719fc668b71befd73324e47ab46c8ebbbede252c154b2/olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl",
        "$SIZE_OLEFILE_0_47",
        "$SHA256_OLEFILE_0_47",
        "files.pythonhosted.org",
    ),
    (
        "python-windows-${PYTHON_VERSION}.exe",
        "https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-amd64.exe",
        "$SIZE_PYTHON_WIN_3_11_9",
        "$SHA256_PYTHON_WIN_3_11_9",
        "www.python.org,python.org",
    ),
    (
        "rust-${RUST_VERSION}.tar.xz",
        "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-unknown-linux-gnu.tar.xz",
        "$SIZE_RUST_1_75",
        "$SHA256_RUST_1_75",
        "static.rust-lang.org",
    ),
    (
        "rust-std-${RUST_VERSION}-aarch64-linux-android.tar.xz",
        "https://static.rust-lang.org/dist/2023-12-28/rust-std-${RUST_VERSION}.0-aarch64-linux-android.tar.xz",
        "$SIZE_RUST_STD_ANDROID_1_75",
        "$SHA256_RUST_STD_ANDROID_1_75",
        "static.rust-lang.org",
    ),
    (
        "vcpkg-${VCPKG_BASELINE}.tar.gz",
        "https://github.com/microsoft/vcpkg/archive/${VCPKG_BASELINE}.tar.gz",
        "$SIZE_VCPKG_120DEAC3",
        "$SHA256_VCPKG_120DEAC3",
        "github.com,codeload.github.com,release-assets.githubusercontent.com,objects.githubusercontent.com",
    ),
    (
        "win/Git-2.45.2-64-bit.exe",
        "https://github.com/git-for-windows/git/releases/download/v2.45.2.windows.1/Git-2.45.2-64-bit.exe",
        "$SIZE_GIT_WIN_2_45_2",
        "$SHA256_GIT_WIN_2_45_2",
        "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com",
    ),
    (
        "win/rust-${RUST_VERSION}.0-x86_64-pc-windows-msvc.msi",
        "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-pc-windows-msvc.msi",
        "$SIZE_RUST_MSVC_1_75",
        "$SHA256_RUST_MSVC_1_75",
        "static.rust-lang.org",
    ),
)


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def require_all(text: str, needles: tuple[str, ...], label: str) -> None:
    for needle in needles:
        require(needle in text, f"{label} is missing {needle!r}")


def function_block(text: str, name: str) -> str:
    marker = f"{name}() {{"
    start = text.find(marker)
    require(start >= 0, f"online-fetch is missing {name}")
    next_function = re.search(r"(?m)^[a-zA-Z_][a-zA-Z0-9_]*\(\) \{", text[start + len(marker) :])
    if next_function is None:
        return text[start:]
    return text[start : start + len(marker) + next_function.start()]


def verify_sources(sources: Mapping[str, str]) -> None:
    shell = sources["shell"]
    helper = sources["helper"]
    pins = sources["pins"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    ledger = sources["ledger"]

    require("fetch_verify()" not in shell, "legacy host SHA-256 downloader remains")
    require("fetch_toolchains()" not in shell, "legacy toolchain downloader remains")
    require("fetch_windows_toolchains()" not in shell, "legacy Windows downloader remains")
    require("fetch_vcpkg()" not in shell, "legacy vcpkg downloader remains")
    manifest_start = shell.find("readonly -a FIXED_ARCHIVE_ARGS=(")
    require(manifest_start >= 0, "fixed archive manifest declaration is absent")
    manifest_end = shell.find("\n)\n", manifest_start)
    require(manifest_end >= 0, "fixed archive manifest terminator is absent")
    manifest = shell[manifest_start : manifest_end + 3]
    require(manifest.count("--entry\n") == 14, "fixed archive manifest is not exactly 14 entries")
    positions = []
    for entry in EXPECTED_MANIFEST:
        snippet = "\n".join(f'    "{field}"' for field in entry)
        require(manifest.count(snippet) == 1, f"fixed archive manifest entry changed: {entry[0]}")
        positions.append(manifest.index(snippet))
    require(positions == sorted(positions), "fixed archive manifest order changed")
    for variable, size in EXPECTED_SIZES.items():
        require(
            pins.count(f'{variable}="{size}"') == 1,
            f"exact archive size pin changed: {variable}",
        )
        require(manifest.count(f'"${variable}"') == 1, f"size pin is not consumed once: {variable}")
    for variable, digest in EXPECTED_SHA256.items():
        require(
            pins.count(f'{variable}="{digest}"') == 1,
            f"exact archive digest pin changed: {variable}",
        )
        require(manifest.count(f'"${variable}"') == 1, f"digest pin is not consumed once: {variable}")
    require_all(
        shell,
        (
            'readonly FIXED_ARCHIVE_HELPER="$SCRIPT_DIR/online-fixed-archive-output.py"',
            "readonly -a FIXED_ARCHIVE_ARGS=(",
            "reconcile_fixed_archive_transactions",
            "if ! shopt -q nullglob; then",
            'transactions=("$ONLINE_DIR"/.rustdesk-fixed-archives.*)',
            '/usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-fixed-archives.XXXXXXXXXX"',
            '/usr/bin/python3 -I -S "$FIXED_ARCHIVE_HELPER" "$command"',
            '/usr/bin/sha256sum "$FIXED_ARCHIVE_HELPER" | /usr/bin/awk',
            'fixed_archive_tool prepare "$staging"',
            'fixed_archive_tool verify "$staging"',
            'fixed_archive_tool publish "$staging"',
            'fixed_archive_tool reconcile "$staging"',
            'exec {lock_fd}<"$ONLINE_DIR"',
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            '"$FLOCK_BIN" --unlock "$lock_fd"',
            '--remove-private-root "$staging" --expected-identity "$expected_identity"',
            'source=$FIXED_ARCHIVE_HELPER,target=/online-fixed-archive-output.py,readonly',
            'source=$staging/state.json,target=/state.json,readonly',
            'source=$staging/output,target=/outputs"',
            '"$builder" \\\n        /usr/bin/python3 -I -S /online-fixed-archive-output.py acquire',
            '--builder-id "$builder" --helper-sha256 "$helper_sha256"',
            "stage_fixed_archives",
            "require_windows_operator_toolchain",
        ),
        "fixed archive shell transaction",
    )
    require(
        shell.count('--builder-id "$builder" --helper-sha256 "$helper_sha256"') == 2,
        "host and container do not share the exact builder/helper binding",
    )
    stage = function_block(shell, "stage_fixed_archives")
    require(
        'source=$ONLINE_DIR,target=' not in stage,
        "fixed archive producer receives the online root",
    )
    require("--privileged" not in stage and "--cap-add" not in stage, "archive stage widens privilege")
    require("-p " not in stage and "--publish" not in stage, "archive stage publishes a port")
    main = function_block(shell, "main")
    require(main.count("stage_fixed_archives") == 1, "main does not invoke one fixed archive stage")
    require(
        main.index("load_builder_images") < main.index("stage_fixed_archives") < main.index("build_frb_codegen"),
        "fixed archive stage ordering changed",
    )

    require_all(
        helper,
        (
            'FORMAT = "rustdesk-fixed-archive-output-v1"',
            "MAX_REDIRECTS = 5",
            "CHUNK_SIZE = 1024 * 1024",
            "if len(specs) != 14:",
            'parsed.scheme != "https"',
            "urllib.request.ProxyHandler({})",
            "BoundedRedirectHandler(spec.redirect_hosts)",
            'response.headers.get("Content-Encoding")',
            'response.headers.get("Content-Length")',
            'response.headers.get("Transfer-Encoding")',
            'transfer_encoding.strip().lower() != "chunked"',
            "int(length) != spec.size",
            "total > spec.size",
            "digest.hexdigest() != spec.sha256",
            "os.O_CREAT",
            "os.O_EXCL",
            "os.O_NOFOLLOW",
            "class MissingPathError(ContractError):",
            "except MissingPathError:",
            "os.fchmod(descriptor, 0o400)",
            "os.fsync(descriptor)",
            "if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:",
            "os.listxattr(descriptor)",
            "descriptor_mount_id(descriptor) != descriptor_mount_id(root_fd)",
            "RENAME_NOREPLACE = 1",
            "renameat2(",
            '"prepared", "verified", "publishing", "complete"',
            "regular_file_sha256(Path(__file__)) != helper_sha256",
            "archive acquisition refuses root UID or GID",
            "validate_publication_layout(",
            "archive destination race was not byte-identical",
            "self-test accepted a redirect outside the host allowlist",
            "self-test accepted an occupied wrong archive destination",
            "self-test accepted an unsafe nested archive parent as missing",
            "self-test accepted a response without admitted length framing",
        ),
        "fixed archive helper",
    )
    require(
        helper.count('parsed.scheme != "https"') == 2,
        "initial and redirected URL HTTPS checks are not both present",
    )
    require(
        helper.count("except MissingPathError:") == 2,
        "missing and unsafe parent paths are not distinguished at both decision points",
    )
    require(
        "os.O_WRONLY\n                | os.O_CREAT\n                | os.O_EXCL\n                | os.O_CLOEXEC\n                | os.O_NOFOLLOW"
        in helper,
        "archive download does not use the exact exclusive no-follow create mask",
    )
    require(
        helper.count("validate_publication_layout(") == 2,
        "publication layout validator definition/call wiring changed",
    )
    require(
        'if os.listxattr(descriptor):\n                fail(f"archive has extended attributes: {spec.name}")'
        in helper,
        "published archive xattr rejection changed",
    )
    require(
        "os.replace(" not in helper and "shutil.move" not in helper,
        "fixed archive helper has an overwrite publication primitive",
    )
    require(
        "urllib.request.urlopen" not in helper,
        "fixed archive helper bypasses its proxy/redirect-closed opener",
    )
    require_all(
        verify,
        (
            "verify-online-fetch-fixed-archive-authority.py",
            "online-fixed-archive-output.py self-test",
        ),
        "shared verifier wiring",
    )
    require(
        '<span class="id">R-S11cs</span>' in requirements,
        "requirements omit the normative R-S11cs block",
    )
    require("<td>246</td>" in requirements, "Appendix C omits item 246")
    require("R-S11cs/R-S11e-111" in ledger, "hardening ledger omits R-S11e-111")


@dataclass(frozen=True)
class Mutation:
    file: str
    old: str
    new: str
    label: str


MUTATIONS = (
    Mutation(
        "shell",
        "fetch_verify_sha512() {",
        "fetch_verify() {\n    :\n}\n\nfetch_verify_sha512() {",
        "legacy downloader absence",
    ),
    Mutation("shell", "--entry\n", "--entry-removed\n", "manifest entry count"),
    Mutation("shell", "stage_fixed_archives", "stage_fixed_archives_removed", "stage wiring"),
    Mutation("shell", "target=/online-fixed-archive-output.py,readonly", "target=/online-fixed-archive-output.py", "helper read-only mount"),
    Mutation("shell", "target=/state.json,readonly", "target=/state.json", "state read-only mount"),
    Mutation("shell", "target=/outputs\"", "target=/outputs,readonly\"", "sole output write mount"),
    Mutation("shell", "--builder-id \"$builder\"", "--builder-id sha256:bad", "builder binding"),
    Mutation("shell", "fixed_archive_tool publish", "fixed_archive_tool publish_removed", "publication"),
    Mutation(
        "shell",
        '--remove-private-root "$staging" --expected-identity "$expected_identity"',
        '--inspect-private-root "$staging" --expected-identity "$expected_identity"',
        "identity-bound retirement",
    ),
    Mutation(
        "shell",
        'transactions=("$ONLINE_DIR"/.rustdesk-fixed-archives.*)',
        "transactions=()",
        "complete stale-transaction inventory",
    ),
    Mutation("pins", 'SIZE_RUST_1_75="156249584"', 'SIZE_RUST_1_75="156249585"', "length pin"),
    Mutation(
        "pins",
        'SHA256_RUST_1_75="6bf166ddcad545aa26aa2d12a186454d7697133b52b7fbbd271ce3ee1ecfedc6"',
        'SHA256_RUST_1_75="7bf166ddcad545aa26aa2d12a186454d7697133b52b7fbbd271ce3ee1ecfedc6"',
        "digest pin",
    ),
    Mutation(
        "shell",
        "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-unknown-linux-gnu.tar.xz",
        "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-aarch64-unknown-linux-gnu.tar.xz",
        "manifest URL mapping",
    ),
    Mutation(
        "shell",
        "www.python.org,python.org",
        "www.python.org,python.org,example.invalid",
        "manifest redirect-host mapping",
    ),
    Mutation("helper", "if len(specs) != 14:", "if len(specs) < 1:", "closed manifest count"),
    Mutation("helper", 'parsed.scheme != "https"', 'parsed.scheme not in ("http", "https")', "HTTPS only"),
    Mutation("helper", "urllib.request.ProxyHandler({})", "urllib.request.ProxyHandler()", "ambient proxy removal"),
    Mutation("helper", "MAX_REDIRECTS = 5", "MAX_REDIRECTS = 6", "redirect bound"),
    Mutation("helper", 'response.headers.get("Content-Length")', 'response.headers.get("X-Length")', "length header"),
    Mutation(
        "helper",
        'response.headers.get("Transfer-Encoding")',
        'response.headers.get("X-Transfer-Encoding")',
        "chunked response framing",
    ),
    Mutation("helper", "int(length) != spec.size", "False", "exact response length"),
    Mutation("helper", "digest.hexdigest() != spec.sha256", "False", "download digest"),
    Mutation(
        "helper",
        "os.O_WRONLY\n                | os.O_CREAT\n                | os.O_EXCL",
        "os.O_WRONLY\n                | os.O_CREAT",
        "exclusive file creation",
    ),
    Mutation(
        "helper",
        "| os.O_CLOEXEC\n                | os.O_NOFOLLOW,\n                0o600,",
        "| os.O_CLOEXEC,\n                0o600,",
        "no-follow file creation",
    ),
    Mutation(
        "helper",
        "except MissingPathError:",
        "except ContractError:",
        "missing versus unsafe parent distinction",
    ),
    Mutation("helper", "os.fchmod(descriptor, 0o400)", "os.fchmod(descriptor, 0o666)", "candidate sealing"),
    Mutation(
        "helper",
        "if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:",
        "if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink < 1:",
        "hardlink rejection",
    ),
    Mutation(
        "helper",
        'if os.listxattr(descriptor):\n                fail(f"archive has extended attributes: {spec.name}")',
        'if False:\n                fail(f"archive has extended attributes: {spec.name}")',
        "xattr rejection",
    ),
    Mutation("helper", "RENAME_NOREPLACE = 1", "RENAME_NOREPLACE = 0", "no-clobber primitive"),
    Mutation("helper", "regular_file_sha256(Path(__file__)) != helper_sha256", "False", "helper byte binding"),
    Mutation("helper", "archive acquisition refuses root UID or GID", "archive acquisition root accepted", "root refusal"),
    Mutation(
        "helper",
        "def validate_publication_layout(",
        "def validate_publication_layout_removed(",
        "recovery layout",
    ),
    Mutation("verify", "online-fixed-archive-output.py self-test", "online-fixed-archive-output.py skipped-test", "self-test wiring"),
    Mutation(
        "requirements",
        '<span class="id">R-S11cs</span>',
        '<span class="id">R-S11cs-removed</span>',
        "normative requirement",
    ),
    Mutation("requirements", "<td>246</td>", "<td>246-removed</td>", "Appendix disposition"),
    Mutation(
        "ledger",
        "R-S11cs/R-S11e-111",
        "R-S11cs-removed/R-S11e-111",
        "ledger disposition",
    ),
)


def run_mutations(sources: Mapping[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.file]
        require(mutation.old in original, f"mutation anchor missing: {mutation.label}")
        changed = dict(sources)
        changed[mutation.file] = original.replace(mutation.old, mutation.new, 1)
        try:
            verify_sources(changed)
        except VerificationError:
            continue
        raise VerificationError(f"mutation was not rejected: {mutation.label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = {name: path.read_text(encoding="utf-8") for name, path in FILES.items()}
    verify_sources(sources)
    if args.self_test:
        run_mutations(sources)
        print(f"fixed archive authority mutations: PASS ({len(MUTATIONS)})")
    else:
        print("fixed archive authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        raise SystemExit(1)
