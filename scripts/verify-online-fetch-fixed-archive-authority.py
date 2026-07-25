#!/usr/bin/env python3
"""Bind fixed toolchain, Dart, WiX, vcpkg, and Debian image acquisition authority."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit


FILES = {
    "shell": Path("scripts/online-fetch.sh"),
    "helper": Path("scripts/online-fixed-archive-output.py"),
    "pins": Path("scripts/pins.env"),
    "vcpkg_manifest": Path("res/vcpkg/libvpx/fixed-archive-acquisition-v1.txt"),
    "windows_tools": Path("res/vcpkg/libvpx/windows-tools.sha512"),
    "systemd_smoke": Path("scripts/smoke-debian-systemd-lifecycle.sh"),
    "verify": Path("scripts/verify.sh"),
    "requirements": Path("requirements.html"),
    "ledger": Path("HARDENING_STATUS.md"),
}

EXPECTED_VCPKG_MANIFEST_SHA256 = (
    "c90310083a22b9da7cebb9412275f3a551dd03f146fcf7f25fed84ab633b5a8f"
)
EXPECTED_SYSTEMD_IMAGE_NAME = (
    "debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2"
)
EXPECTED_SYSTEMD_IMAGE_SIZE = "346882048"
EXPECTED_SYSTEMD_IMAGE_SHA256 = (
    "b49303d83f5f69ff55fdf8c16b883b5714bc5332d37a6f6b8a94da42ad5b0999"
)
EXPECTED_SYSTEMD_IMAGE_SHA512 = (
    "6c2607f1846ee86040830c87d0b723f0967da3e884ea4673d9db4aa8eee13a4b"
    "7c663524bfa42082c16fc6919f3aa1bf425c004d07ff06c53a319ad0c42647bb"
)
EXPECTED_DART_AUDIT_MANIFEST = (
    (
        "dart-audit-inputs/Pub-all.zip",
        (
            "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o/"
            "Pub%2Fall.zip?alt=media&generation=${OSV_DB_PUB_GENERATION}"
        ),
        "$OSV_DB_PUB_SIZE",
        "$OSV_DB_PUB_SHA256",
        "storage.googleapis.com",
    ),
    (
        "dart-audit-inputs/osv-scanner",
        (
            "https://github.com/google/osv-scanner/releases/download/"
            "v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"
        ),
        "$OSV_SCANNER_SIZE",
        "$OSV_SCANNER_SHA256",
        (
            "github.com,release-assets.githubusercontent.com,"
            "objects.githubusercontent.com"
        ),
    ),
)

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

EXPECTED_WIX_MANIFEST = (
    (
        "wix-nuget-packages/wixtoolset.firewall.wixext.${WIX_NUGET_VERSION}.nupkg",
        "https://api.nuget.org/v3-flatcontainer/wixtoolset.firewall.wixext/${WIX_NUGET_VERSION}/wixtoolset.firewall.wixext.${WIX_NUGET_VERSION}.nupkg",
        "$SIZE_WIX_NUGET_FIREWALL",
        "$SHA256_WIX_NUGET_FIREWALL",
        "api.nuget.org",
    ),
    (
        "wix-nuget-packages/wixtoolset.heat.${WIX_NUGET_VERSION}.nupkg",
        "https://api.nuget.org/v3-flatcontainer/wixtoolset.heat/${WIX_NUGET_VERSION}/wixtoolset.heat.${WIX_NUGET_VERSION}.nupkg",
        "$SIZE_WIX_NUGET_HEAT",
        "$SHA256_WIX_NUGET_HEAT",
        "api.nuget.org",
    ),
    (
        "wix-nuget-packages/wixtoolset.netfx.wixext.${WIX_NUGET_VERSION}.nupkg",
        "https://api.nuget.org/v3-flatcontainer/wixtoolset.netfx.wixext/${WIX_NUGET_VERSION}/wixtoolset.netfx.wixext.${WIX_NUGET_VERSION}.nupkg",
        "$SIZE_WIX_NUGET_NETFX",
        "$SHA256_WIX_NUGET_NETFX",
        "api.nuget.org",
    ),
    (
        "wix-nuget-packages/wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg",
        "https://api.nuget.org/v3-flatcontainer/wixtoolset.sdk/${WIX_NUGET_VERSION}/wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg",
        "$SIZE_WIX_NUGET_SDK",
        "$SHA256_WIX_NUGET_SDK",
        "api.nuget.org",
    ),
    (
        "wix-nuget-packages/wixtoolset.ui.wixext.${WIX_NUGET_VERSION}.nupkg",
        "https://api.nuget.org/v3-flatcontainer/wixtoolset.ui.wixext/${WIX_NUGET_VERSION}/wixtoolset.ui.wixext.${WIX_NUGET_VERSION}.nupkg",
        "$SIZE_WIX_NUGET_UI",
        "$SHA256_WIX_NUGET_UI",
        "api.nuget.org",
    ),
    (
        "wix-nuget-packages/wixtoolset.util.wixext.${WIX_NUGET_VERSION}.nupkg",
        "https://api.nuget.org/v3-flatcontainer/wixtoolset.util.wixext/${WIX_NUGET_VERSION}/wixtoolset.util.wixext.${WIX_NUGET_VERSION}.nupkg",
        "$SIZE_WIX_NUGET_UTIL",
        "$SHA256_WIX_NUGET_UTIL",
        "api.nuget.org",
    ),
)

EXPECTED_WIX_PINS = {
    "FIREWALL": (
        "330923",
        "d722cd6d5d262736fc9220fa1d287147c244fd5c2b21065bf192935d8e45d8e3",
    ),
    "HEAT": (
        "5018595",
        "6c137c6a7d6b724169ff47832d080bf75009f24cda656d5644585031ebbe66d8",
    ),
    "NETFX": (
        "1577895",
        "e09e0e121c482cba3e77521f83f9820f232dd0ab65199f66398efdef3f7b2e46",
    ),
    "SDK": (
        "18626823",
        "917009bef10f430ee72c4401f70ffcb36562a53f41ea027b8dcacba5e9886a6f",
    ),
    "UI": (
        "793813",
        "313cc0a9b2c2e90661a6ab56f46a08ce551ed64673cbef95ceab6508690147a1",
    ),
    "UTIL": (
        "891963",
        "b63e40584d3b5ceb23607586ad720ae0288bad2c8699a0a07cd3260591d1292e",
    ),
}


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
    vcpkg_manifest = sources["vcpkg_manifest"]
    windows_tools = sources["windows_tools"]
    systemd_smoke = sources["systemd_smoke"]
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
    dart_manifest_start = shell.find("readonly -a DART_AUDIT_FIXED_INPUT_ARGS=(")
    require(
        dart_manifest_start >= 0,
        "Dart advisory fixed-input manifest declaration is absent",
    )
    dart_manifest_end = shell.find("\n)\n", dart_manifest_start)
    require(
        dart_manifest_end >= 0,
        "Dart advisory fixed-input manifest terminator is absent",
    )
    dart_manifest = shell[dart_manifest_start : dart_manifest_end + 3]
    require(
        dart_manifest.count("--entry\n") == 2,
        "Dart advisory fixed-input manifest is not exactly two entries",
    )
    dart_positions = []
    for entry in EXPECTED_DART_AUDIT_MANIFEST:
        snippet = "\n".join(f'    "{field}"' for field in entry)
        require(
            dart_manifest.count(snippet) == 1,
            f"Dart advisory fixed-input manifest entry changed: {entry[0]}",
        )
        dart_positions.append(dart_manifest.index(snippet))
    require(
        dart_positions == sorted(dart_positions),
        "Dart advisory fixed-input manifest order changed",
    )
    for name, value in (
        ("OSV_SCANNER_SIZE", "56676514"),
        (
            "OSV_SCANNER_SHA256",
            "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0",
        ),
        ("OSV_DB_PUB_SIZE", "19448"),
        (
            "OSV_DB_PUB_SHA256",
            "5fdd3db5059b4f935a507385cb93cab3c35ba3d632332a5c8f5deb604f95a5c0",
        ),
        ("OSV_DB_PUB_GENERATION", "1783494617999513"),
    ):
        require(
            pins.count(f'{name}="{value}"') == 1,
            f"Dart advisory fixed-input pin changed: {name}",
        )
        if name == "OSV_DB_PUB_GENERATION":
            require(
                dart_manifest.count("${OSV_DB_PUB_GENERATION}") == 1,
                "Dart advisory database generation is not consumed once",
            )
        else:
            require(
                dart_manifest.count(f'"${name}"') == 1,
                f"Dart advisory fixed-input pin is not consumed once: {name}",
            )
    wix_manifest_start = shell.find("readonly -a WIX_NUGET_FIXED_ARCHIVE_ARGS=(")
    require(wix_manifest_start >= 0, "WiX fixed-package manifest declaration is absent")
    wix_manifest_end = shell.find("\n)\n", wix_manifest_start)
    require(wix_manifest_end >= 0, "WiX fixed-package manifest terminator is absent")
    wix_manifest = shell[wix_manifest_start : wix_manifest_end + 3]
    require(
        wix_manifest.count("--entry\n") == 6,
        "WiX fixed-package manifest is not exactly six entries",
    )
    wix_positions = []
    for entry in EXPECTED_WIX_MANIFEST:
        snippet = "\n".join(f'    "{field}"' for field in entry)
        require(
            wix_manifest.count(snippet) == 1,
            f"WiX fixed-package manifest entry changed: {entry[0]}",
        )
        wix_positions.append(wix_manifest.index(snippet))
    require(wix_positions == sorted(wix_positions), "WiX package manifest order changed")
    require(
        pins.count('WIX_NUGET_VERSION="4.0.5"') == 1,
        "WiX package version pin changed",
    )
    for suffix, (size, digest) in EXPECTED_WIX_PINS.items():
        size_variable = f"SIZE_WIX_NUGET_{suffix}"
        digest_variable = f"SHA256_WIX_NUGET_{suffix}"
        require(
            pins.count(f'{size_variable}="{size}"') == 1,
            f"WiX package size pin changed: {size_variable}",
        )
        require(
            pins.count(f'{digest_variable}="{digest}"') == 1,
            f"WiX package digest pin changed: {digest_variable}",
        )
        require(
            wix_manifest.count(f'"${size_variable}"') == 1
            and wix_manifest.count(f'"${digest_variable}"') == 1,
            f"WiX package pins are not each consumed once: {suffix}",
        )
    systemd_manifest_start = shell.find("readonly -a SYSTEMD_SMOKE_IMAGE_ARGS=(")
    require(systemd_manifest_start >= 0, "systemd image manifest declaration is absent")
    systemd_manifest_end = shell.find("\n)\n", systemd_manifest_start)
    require(systemd_manifest_end >= 0, "systemd image manifest terminator is absent")
    systemd_manifest = shell[systemd_manifest_start : systemd_manifest_end + 3]
    expected_systemd_manifest = "\n".join(
        (
            '    --entry',
            '    "$SYSTEMD_SMOKE_IMAGE_NAME"',
            '    "https://cloud.debian.org/images/cloud/bookworm/'
            '${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}/$SYSTEMD_SMOKE_IMAGE_NAME"',
            '    "$SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE"',
            '    "$SHA256_DEBIAN_SYSTEMD_SMOKE_IMAGE"',
            '    "cloud.debian.org,laotzu.ftp.acc.umu.se"',
        )
    )
    require(
        systemd_manifest.count("--entry\n") == 1
        and systemd_manifest.count(expected_systemd_manifest) == 1,
        "systemd image manifest is not the exact one-entry acquisition profile",
    )
    require(
        shell.count(f'readonly SYSTEMD_SMOKE_IMAGE_NAME="{EXPECTED_SYSTEMD_IMAGE_NAME}"') == 1,
        "systemd image destination is not derived exactly from the dated build pin",
    )
    require(
        pins.count(
            f'SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE="{EXPECTED_SYSTEMD_IMAGE_SIZE}"'
        )
        == 1,
        "systemd image exact size pin changed",
    )
    require(
        pins.count(
            f'SHA256_DEBIAN_SYSTEMD_SMOKE_IMAGE="{EXPECTED_SYSTEMD_IMAGE_SHA256}"'
        )
        == 1,
        "systemd image acquisition SHA-256 pin changed",
    )
    require(
        pins.count(
            f'SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE="{EXPECTED_SYSTEMD_IMAGE_SHA512}"'
        )
        == 1,
        "systemd image publisher SHA-512 pin changed",
    )
    require(
        hashlib.sha256(vcpkg_manifest.encode("utf-8")).hexdigest()
        == EXPECTED_VCPKG_MANIFEST_SHA256,
        "vcpkg fixed-archive acquisition manifest bytes changed",
    )
    require(
        pins.count(
            f'SHA256_VCPKG_FIXED_ARCHIVE_ACQUISITION="{EXPECTED_VCPKG_MANIFEST_SHA256}"'
        )
        == 1,
        "vcpkg fixed-archive acquisition manifest pin changed",
    )
    vcpkg_records = [line.split("|") for line in vcpkg_manifest.splitlines()]
    require(
        len(vcpkg_records) == 33 and all(len(record) == 5 for record in vcpkg_records),
        "vcpkg fixed-archive acquisition manifest is not exactly 33 five-field records",
    )
    vcpkg_names = [record[0] for record in vcpkg_records]
    require(vcpkg_names == sorted(vcpkg_names), "vcpkg archive manifest is not sorted")
    require(len(set(vcpkg_names)) == 33, "vcpkg archive manifest repeats a destination")
    require(
        vcpkg_names[0] == "vcpkg-distfiles/libvpx-v1.15.2.tar.gz",
        "vcpkg archive manifest source destination changed",
    )
    for name, size, digest, url, hosts_raw in vcpkg_records:
        require(size.isdigit() and 0 < int(size) <= 2_000_000_000, f"bad size: {name}")
        require(
            re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            f"bad acquisition SHA-256: {name}",
        )
        parsed_url = urlsplit(url)
        hosts = hosts_raw.split(",")
        require(
            parsed_url.scheme == "https"
            and parsed_url.hostname in hosts
            and 1 <= len(hosts) <= 4
            and len(hosts) == len(set(hosts)),
            f"bad URL/host contract: {name}",
        )
    canonical_tool_names = {
        line.split()[1]
        for line in windows_tools.splitlines()
        if len(line.split()) == 2
    }
    acquisition_tool_names = {
        name.removeprefix("vcpkg-distfiles/windows-tools/")
        for name in vcpkg_names[1:]
    }
    require(
        len(canonical_tool_names) == 32
        and acquisition_tool_names == canonical_tool_names,
        "vcpkg acquisition manifest and SHA-512 consumer manifest names differ",
    )
    require_all(
        shell,
        (
            'readonly FIXED_ARCHIVE_HELPER="$SCRIPT_DIR/online-fixed-archive-output.py"',
            'readonly VCPKG_FIXED_ARCHIVE_MANIFEST="$REPO_ROOT/res/vcpkg/libvpx/fixed-archive-acquisition-v1.txt"',
            "readonly -a FIXED_ARCHIVE_ARGS=(",
            "readonly -a DART_AUDIT_FIXED_INPUT_ARGS=(",
            "readonly -a WIX_NUGET_FIXED_ARCHIVE_ARGS=(",
            "readonly -a SYSTEMD_SMOKE_IMAGE_ARGS=(",
            "load_vcpkg_fixed_archive_manifest",
            "reconcile_archive_bundle_transactions",
            "if ! shopt -q nullglob; then",
            'transactions=("$root"/"$prefix".*)',
            '/usr/bin/mktemp -d "$root/$prefix.XXXXXXXXXX"',
            '/usr/bin/python3 -I -S "$FIXED_ARCHIVE_HELPER" "$command"',
            '/usr/bin/sha256sum "$FIXED_ARCHIVE_HELPER" | /usr/bin/awk',
            'archive_bundle_tool "$kind" "$root" prepare "$staging"',
            'archive_bundle_tool "$kind" "$root" verify "$staging"',
            'archive_bundle_tool "$kind" "$root" publish "$staging"',
            'archive_bundle_tool "$kind" "$root" reconcile "$staging"',
            'dart-audit) archive_args=("${DART_AUDIT_FIXED_INPUT_ARGS[@]}")',
            'exec {lock_fd}<"$root"',
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            '"$FLOCK_BIN" --unlock "$lock_fd"',
            '--remove-private-root "$staging" --expected-identity "$expected_identity"',
            'source=$FIXED_ARCHIVE_HELPER,target=/online-fixed-archive-output.py,readonly',
            'source=$staging/state.json,target=/state.json,readonly',
            'source=$staging/output,target=/outputs"',
            '"$builder" \\\n        /usr/bin/python3 -I -S /online-fixed-archive-output.py acquire',
            '--builder-id "$builder" --helper-sha256 "$helper_sha256"',
            "stage_fixed_archives",
            "stage_dart_audit_inputs",
            "stage_vcpkg_fixed_archives",
            'stage_archive_bundle dart-audit "$ONLINE_DIR" .rustdesk-dart-audit-inputs',
            'stage_archive_bundle toolchain "$ONLINE_DIR" .rustdesk-fixed-archives',
            'stage_archive_bundle wix "$ONLINE_DIR" .rustdesk-wix-nuget-packages',
            'stage_archive_bundle vcpkg "$ONLINE_DIR" .rustdesk-vcpkg-fixed-archives',
            'stage_archive_bundle systemd "$state_dir" .rustdesk-debian-systemd-image',
            "require_windows_operator_toolchain",
        ),
        "fixed archive shell transaction",
    )
    require(
        shell.count('--builder-id "$builder" --helper-sha256 "$helper_sha256"') == 2,
        "host and container do not share the exact builder/helper binding",
    )
    stage = function_block(shell, "stage_archive_bundle")
    require(
        'source=$root,target=' not in stage and 'source=$ONLINE_DIR,target=' not in stage,
        "fixed archive producer receives a publication root",
    )
    require("--privileged" not in stage and "--cap-add" not in stage, "archive stage widens privilege")
    require("-p " not in stage and "--publish" not in stage, "archive stage publishes a port")
    main = function_block(shell, "main")
    require_all(
        main,
        (
            'if [ "${1:-}" != "--debian-systemd-smoke-image" ]; then',
            "prepare_online_root",
        ),
        "systemd image online-root separation",
    )
    require(main.count("stage_fixed_archives") == 1, "main does not invoke one fixed archive stage")
    require(
        main.index("load_builder_images") < main.index("stage_fixed_archives") < main.index("build_frb_codegen"),
        "fixed archive stage ordering changed",
    )
    libvpx_stage = function_block(shell, "stage_libvpx_distfiles")
    require(
        libvpx_stage.count("stage_vcpkg_fixed_archives") == 1,
        "libvpx distfile stage does not invoke one fixed vcpkg archive transaction",
    )
    require(
        "fetch_verify_sha512()" not in shell
        and "curl -fsSL" not in libvpx_stage
        and ".part\" \"$tool_url\"" not in libvpx_stage,
        "legacy host SHA-512 codec downloader remains reachable",
    )
    systemd_fetch = function_block(shell, "fetch_debian_systemd_smoke_image")
    require_all(
        systemd_fetch,
        (
            '[ -d "$harness_state" ] && [ ! -L "$harness_state" ]',
            '"$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700"',
            'stage_archive_bundle systemd "$state_dir" .rustdesk-debian-systemd-image',
            'verify_sha512 "$dest" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"',
            '"$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1"',
            '"$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:444:1"',
        ),
        "systemd image transaction",
    )
    require(
        "curl " not in systemd_fetch
        and ".part" not in systemd_fetch
        and "rm -f" not in systemd_fetch
        and "\nmv " not in systemd_fetch
        and "\nchmod " not in systemd_fetch,
        "legacy host systemd image download/publication remains reachable",
    )
    require_all(
        systemd_smoke,
        (
            'IMAGE_METADATA="$(stat -c \'%u:%g:%a:%h\' "$IMAGE")"',
            '"$(id -u):$(id -g):400:1"',
            '"$(id -u):$(id -g):444:1"',
            'verify_sha512 "$IMAGE" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"',
            'qemu-img check -q "$IMAGE"',
        ),
        "systemd image independent consumer",
    )

    require_all(
        helper,
        (
            'FORMAT = "rustdesk-fixed-archive-output-v1"',
            "MAX_REDIRECTS = 5",
            "CHUNK_SIZE = 1024 * 1024",
            "DOWNLOAD_TIMEOUT_SECONDS = 120",
            "SYSTEMD_IMAGE_DOWNLOAD_TIMEOUT_SECONDS = 300",
            "def download_timeout_seconds(spec: ArchiveSpec) -> int:",
            "timeout=download_timeout_seconds(spec)",
            "if len(specs) == 1:",
            "if len(specs) == 2:",
            "if len(specs) == 6:",
            "if len(specs) == 14:",
            "if len(specs) == 33:",
            "is_debian_systemd_image_name(names[0])",
            "the one-entry systemd image manifest has a noncanonical destination",
            "if is_debian_systemd_image_name(spec.name):",
            "root_profiles: set[tuple[int, int, int]] = set()",
            "validate_manifest_shape(specs)",
            "exactly 32 windows-tools/ archives",
            'char in "._+~-"',
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
            "self-test accepted an unsafe vcpkg archive parent",
            "systemd-image self-test publication omitted its image",
            "systemd-image self-test rejected historical mode-0444 output",
            "systemd-image self-test accepted writable published output",
            "systemd-image self-test lost its bounded large-image timeout",
            "archive self-test widened the ordinary download timeout",
            "vcpkg self-test publication omitted an archive",
            "WiX self-test publication omitted a package",
            "Dart-audit self-test publication omitted an input",
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
        helper.count("if is_debian_systemd_image_name(spec.name):") == 2,
        "systemd image timeout and metadata predicates are not both singular",
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
    require(
        '<span class="id">R-S11ct</span>' in requirements,
        "requirements omit the normative R-S11ct block",
    )
    require(
        '<span class="id">R-S11cu</span>' in requirements,
        "requirements omit the normative R-S11cu block",
    )
    require(
        "exactly <code>cloud.debian.org</code> and the currently reviewed "
        "Debian-selected final host <code>laotzu.ftp.acc.umu.se</code>"
        in requirements,
        "requirements omit the exact systemd image redirect-host boundary",
    )
    require("<td>246</td>" in requirements, "Appendix C omits item 246")
    require("<td>247</td>" in requirements, "Appendix C omits item 247")
    require("<td>248</td>" in requirements, "Appendix C omits item 248")
    require("R-S11cs/R-S11e-111" in ledger, "hardening ledger omits R-S11e-111")
    require("R-S11ct/R-S11e-112" in ledger, "hardening ledger omits R-S11e-112")
    require("R-S11cu/R-S11e-113" in ledger, "hardening ledger omits R-S11e-113")


@dataclass(frozen=True)
class Mutation:
    file: str
    old: str
    new: str
    label: str


MUTATIONS = (
    Mutation(
        "shell",
        "stage_vcpkg_fixed_archives() {",
        "fetch_verify_sha512() {\n    :\n}\n\nstage_vcpkg_fixed_archives() {",
        "legacy downloader absence",
    ),
    Mutation("shell", "--entry\n", "--entry-removed\n", "manifest entry count"),
    Mutation(
        "shell",
        (
            "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o/"
            "Pub%2Fall.zip?alt=media&generation=${OSV_DB_PUB_GENERATION}"
        ),
        "https://osv-vulnerabilities.storage.googleapis.com/Pub/all.zip",
        "Dart advisory generation-bound database URL",
    ),
    Mutation(
        "pins",
        'OSV_SCANNER_SIZE="56676514"',
        'OSV_SCANNER_SIZE="56676515"',
        "Dart advisory scanner length pin",
    ),
    Mutation(
        "helper",
        "if len(specs) == 2:",
        "if len(specs) == 3:",
        "closed Dart advisory input profile",
    ),
    Mutation(
        "shell",
        'dart-audit) archive_args=("${DART_AUDIT_FIXED_INPUT_ARGS[@]}")',
        'dart-audit) archive_args=("${FIXED_ARCHIVE_ARGS[@]}")',
        "Dart advisory acquisition profile dispatch",
    ),
    Mutation(
        "shell",
        "    stage_fixed_archives\n",
        "    stage_archives_removed\n",
        "stage wiring",
    ),
    Mutation("shell", "target=/online-fixed-archive-output.py,readonly", "target=/online-fixed-archive-output.py", "helper read-only mount"),
    Mutation("shell", "target=/state.json,readonly", "target=/state.json", "state read-only mount"),
    Mutation("shell", "target=/outputs\"", "target=/outputs,readonly\"", "sole output write mount"),
    Mutation("shell", "--builder-id \"$builder\"", "--builder-id sha256:bad", "builder binding"),
    Mutation(
        "shell",
        'archive_bundle_tool "$kind" "$root" publish',
        'archive_bundle_tool "$kind" "$root" publish_removed',
        "publication",
    ),
    Mutation(
        "shell",
        '--remove-private-root "$staging" --expected-identity "$expected_identity"',
        '--inspect-private-root "$staging" --expected-identity "$expected_identity"',
        "identity-bound retirement",
    ),
    Mutation(
        "shell",
        'transactions=("$root"/"$prefix".*)',
        "transactions=()",
        "complete stale-transaction inventory",
    ),
    Mutation("pins", 'SIZE_RUST_1_75="156249584"', 'SIZE_RUST_1_75="156249585"', "length pin"),
    Mutation(
        "pins",
        'SIZE_WIX_NUGET_SDK="18626823"',
        'SIZE_WIX_NUGET_SDK="18626824"',
        "WiX package length pin",
    ),
    Mutation(
        "pins",
        'SHA256_WIX_NUGET_SDK="917009bef10f430ee72c4401f70ffcb36562a53f41ea027b8dcacba5e9886a6f"',
        'SHA256_WIX_NUGET_SDK="a17009bef10f430ee72c4401f70ffcb36562a53f41ea027b8dcacba5e9886a6f"',
        "WiX package digest pin",
    ),
    Mutation(
        "shell",
        "https://api.nuget.org/v3-flatcontainer/wixtoolset.sdk/${WIX_NUGET_VERSION}/wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg",
        "https://api.nuget.org/v3-flatcontainer/wixtoolset.sdk/4.0.4/wixtoolset.sdk.4.0.4.nupkg",
        "WiX package URL mapping",
    ),
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
    Mutation(
        "vcpkg_manifest",
        "26fcd3db88045dee380e581862a6ef106f49b74b6396ee95c2993a260b4636aa",
        "36fcd3db88045dee380e581862a6ef106f49b74b6396ee95c2993a260b4636aa",
        "vcpkg acquisition manifest bytes",
    ),
    Mutation(
        "pins",
        f'SHA256_VCPKG_FIXED_ARCHIVE_ACQUISITION="{EXPECTED_VCPKG_MANIFEST_SHA256}"',
        'SHA256_VCPKG_FIXED_ARCHIVE_ACQUISITION="bad"',
        "vcpkg acquisition manifest pin",
    ),
    Mutation(
        "windows_tools",
        "  msys2-bash-5.2.037-2-x86_64.pkg.tar.zst",
        "  msys2-bash-5.2.037-3-x86_64.pkg.tar.zst",
        "SHA-512 consumer/acquisition name equality",
    ),
    Mutation(
        "shell",
        "stage_vcpkg_fixed_archives\n",
        "stage_vcpkg_archives_removed\n",
        "vcpkg transaction invocation",
    ),
    Mutation(
        "helper",
        "if len(specs) == 33:",
        "if len(specs) == 32:",
        "closed vcpkg manifest count",
    ),
    Mutation(
        "helper",
        "if len(specs) == 6:",
        "if len(specs) == 5:",
        "closed WiX manifest count",
    ),
    Mutation(
        "helper",
        "if len(specs) == 1:",
        "if len(specs) == 2:",
        "closed systemd image manifest count",
    ),
    Mutation(
        "helper",
        "if is_debian_systemd_image_name(spec.name):\n"
        "                    current_profiles = {",
        "if False:\n"
        "                    current_profiles = {",
        "systemd image read-only metadata profiles",
    ),
    Mutation(
        "pins",
        f'SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE="{EXPECTED_SYSTEMD_IMAGE_SIZE}"',
        'SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE="346882049"',
        "systemd image length pin",
    ),
    Mutation(
        "pins",
        f'SHA256_DEBIAN_SYSTEMD_SMOKE_IMAGE="{EXPECTED_SYSTEMD_IMAGE_SHA256}"',
        'SHA256_DEBIAN_SYSTEMD_SMOKE_IMAGE="bad"',
        "systemd image acquisition digest pin",
    ),
    Mutation(
        "shell",
        'stage_archive_bundle systemd "$state_dir" .rustdesk-debian-systemd-image',
        'stage_archive_bundle systemd "$ONLINE_DIR" .rustdesk-debian-systemd-image',
        "systemd image publication namespace",
    ),
    Mutation(
        "shell",
        "cloud.debian.org,laotzu.ftp.acc.umu.se",
        "cloud.debian.org",
        "systemd image exact redirect-host set",
    ),
    Mutation(
        "shell",
        'if [ "${1:-}" != "--debian-systemd-smoke-image" ]; then',
        'if [ -n "${1:-}" ]; then',
        "systemd image online-root separation",
    ),
    Mutation(
        "systemd_smoke",
        'verify_sha512 "$IMAGE" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"',
        "true # publisher digest bypassed",
        "systemd image downstream SHA-512 proof",
    ),
    Mutation(
        "helper",
        'char in "._+~-"',
        'char in "._+-"',
        "canonical tilde-bearing tool name",
    ),
    Mutation(
        "helper",
        "DOWNLOAD_TIMEOUT_SECONDS = 120",
        "DOWNLOAD_TIMEOUT_SECONDS = 300",
        "ordinary archive I/O timeout",
    ),
    Mutation(
        "helper",
        "SYSTEMD_IMAGE_DOWNLOAD_TIMEOUT_SECONDS = 300",
        "SYSTEMD_IMAGE_DOWNLOAD_TIMEOUT_SECONDS = 301",
        "systemd image I/O timeout",
    ),
    Mutation(
        "helper",
        "timeout=download_timeout_seconds(spec)",
        "timeout=DOWNLOAD_TIMEOUT_SECONDS",
        "profile-specific I/O timeout selection",
    ),
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
        "requirements",
        '<span class="id">R-S11ct</span>',
        '<span class="id">R-S11ct-removed</span>',
        "vcpkg normative requirement",
    ),
    Mutation("requirements", "<td>247</td>", "<td>247-removed</td>", "vcpkg Appendix disposition"),
    Mutation(
        "requirements",
        '<span class="id">R-S11cu</span>',
        '<span class="id">R-S11cu-removed</span>',
        "systemd image normative requirement",
    ),
    Mutation(
        "requirements",
        "Debian-selected final host <code>laotzu.ftp.acc.umu.se</code>",
        "ambient Debian mirror set",
        "systemd image normative redirect-host boundary",
    ),
    Mutation(
        "requirements",
        "<td>248</td>",
        "<td>248-removed</td>",
        "systemd image Appendix disposition",
    ),
    Mutation(
        "ledger",
        "R-S11cs/R-S11e-111",
        "R-S11cs-removed/R-S11e-111",
        "ledger disposition",
    ),
    Mutation(
        "ledger",
        "R-S11ct/R-S11e-112",
        "R-S11ct-removed/R-S11e-112",
        "vcpkg ledger disposition",
    ),
    Mutation(
        "ledger",
        "R-S11cu/R-S11e-113",
        "R-S11cu-removed/R-S11e-113",
        "systemd image ledger disposition",
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
