#!/usr/bin/env python3
"""Verify the exact signed WiX package acquisition and consumption authority."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


FILES = {
    "pins": Path("scripts/pins.env"),
    "fetch": Path("scripts/online-fetch.sh"),
    "fixed_helper": Path("scripts/online-fixed-archive-output.py"),
    "retire_helper": Path("scripts/online-wix-nuget-retire.py"),
    "lib": Path("scripts/lib.sh"),
    "vm": Path("scripts/build-windows-vm.sh"),
    "offline_manifest": Path("scripts/windows-offline-manifest.py"),
    "guest": Path("scripts/build-windows.ps1"),
    "project": Path("res/msi/Package/Package.wixproj"),
    "lock": Path("res/msi/Package/packages.lock.json"),
    "verify": Path("scripts/verify.sh"),
    "requirements": Path("requirements.html"),
    "ledger": Path("HARDENING_STATUS.md"),
}

VERSION = "4.0.5"
RUNTIME_IDENTIFIERS = ("win", "win-arm64", "win-x64", "win-x86")
AUTHOR_CERT = "0DB368BC1A5A9E19CC9E036B490B7C4A4D3DFB941C0781B4F22F218BE0B54986"
REPOSITORY_CERT = "5A2901D6ADA3D18260B9C6DFE2133C95D74B9EEF6AE0E5DC334C8454D1477DF4"
LEGACY_SIX = (
    "54038393",
    "62afa1543d52461ee0b80334c4c3a1d6bf1b54d94f3cd745869102ed613f3b58",
)
LEGACY_EIGHT = (
    "71249853",
    "0f76c469cd2171f3bf7913828851a2cb22c10a7e0be8bf73ef99a791a6cd1190",
)
PACKAGES = (
    (
        "wixtoolset.firewall.wixext",
        "FIREWALL",
        "330923",
        "d722cd6d5d262736fc9220fa1d287147c244fd5c2b21065bf192935d8e45d8e3",
        "f/+ibqHhUbeXV6g5o7Q2rAYxO83fJcude3N/aonc/8WhFQuN4re91IYYCM3gihEVbIoUbOR2088LMhlFy9DW9g==",
    ),
    (
        "wixtoolset.heat",
        "HEAT",
        "5018595",
        "6c137c6a7d6b724169ff47832d080bf75009f24cda656d5644585031ebbe66d8",
        "Ec4D2SNJVOy415p1twmQ5qGdInRz48SzRZTbBKTLF/NWSlueo4pcHPKLiHVSH7Kc4++vK4aAG2PYohkkySosYg==",
    ),
    (
        "wixtoolset.netfx.wixext",
        "NETFX",
        "1577895",
        "e09e0e121c482cba3e77521f83f9820f232dd0ab65199f66398efdef3f7b2e46",
        "IOEU+CcIP8Yxii6hQjzF9ZO0XIQ3cVokt8mjIrFOD7me15lOZyQKBPJnVVsH8F/q3YA4gjgVQ8t7b4KcC0Nmhw==",
    ),
    (
        "wixtoolset.sdk",
        "SDK",
        "18626823",
        "917009bef10f430ee72c4401f70ffcb36562a53f41ea027b8dcacba5e9886a6f",
        None,
    ),
    (
        "wixtoolset.ui.wixext",
        "UI",
        "793813",
        "313cc0a9b2c2e90661a6ab56f46a08ce551ed64673cbef95ceab6508690147a1",
        "9j0qQ0cZ6GdI5bdYPHuhafqmrhbHKoni1zIqv3hPBdLt4YK5xhQJavTpwRdb1FwrW9KIi5ItI3RkTet41v/97A==",
    ),
    (
        "wixtoolset.util.wixext",
        "UTIL",
        "891963",
        "b63e40584d3b5ceb23607586ad720ae0288bad2c8699a0a07cd3260591d1292e",
        "56tA3Dt0DiAVgg0SeFmWXuIs6LxUZ4gPgbc22LysPhjRKo0dtPcXufDcIXTop0iI5ZMy5K5FtqIXosO0MrhIeQ==",
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


def shell_function(text: str, name: str) -> str:
    marker = f"{name}() {{"
    start = text.find(marker)
    require(start >= 0, f"shell source is missing {name}")
    match = re.search(
        r"(?m)^[A-Za-z_][A-Za-z0-9_]*\(\) \{",
        text[start + len(marker) :],
    )
    if match is None:
        return text[start:]
    return text[start : start + len(marker) + match.start()]


def verify_lock(text: str) -> None:
    try:
        lock = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"WiX lock file is not JSON: {exc}") from exc
    require(
        isinstance(lock, dict) and set(lock) == {"version", "dependencies"},
        "WiX lock file top-level schema is not exact",
    )
    require(lock["version"] == 1, "WiX lock file version changed")
    dependencies = lock["dependencies"]
    expected_targets = {"native,Version=v0.0"} | {
        f"native,Version=v0.0/{runtime}" for runtime in RUNTIME_IDENTIFIERS
    }
    require(
        isinstance(dependencies, dict) and set(dependencies) == expected_targets,
        "WiX lock target schema changed",
    )
    for runtime in RUNTIME_IDENTIFIERS:
        require(
            dependencies[f"native,Version=v0.0/{runtime}"] == {},
            f"WiX lock runtime graph changed: {runtime}",
        )
    records = dependencies["native,Version=v0.0"]
    expected_names = {
        {
            "wixtoolset.firewall.wixext": "WixToolset.Firewall.wixext",
            "wixtoolset.heat": "WixToolset.Heat",
            "wixtoolset.netfx.wixext": "WixToolset.Netfx.wixext",
            "wixtoolset.ui.wixext": "WixToolset.UI.wixext",
            "wixtoolset.util.wixext": "WixToolset.Util.wixext",
        }[package]
        for package, _, _, _, content_hash in PACKAGES
        if content_hash is not None
    }
    require(
        isinstance(records, dict) and set(records) == expected_names,
        "WiX lock file is not the exact five direct PackageReferences",
    )
    for package, _, _, _, content_hash in PACKAGES:
        if content_hash is None:
            continue
        display = {
            "wixtoolset.firewall.wixext": "WixToolset.Firewall.wixext",
            "wixtoolset.heat": "WixToolset.Heat",
            "wixtoolset.netfx.wixext": "WixToolset.Netfx.wixext",
            "wixtoolset.ui.wixext": "WixToolset.UI.wixext",
            "wixtoolset.util.wixext": "WixToolset.Util.wixext",
        }[package]
        require(
            records[display]
            == {
                "type": "Direct",
                "requested": f"[{VERSION}, {VERSION}]",
                "resolved": VERSION,
                "contentHash": content_hash,
            },
            f"WiX lock authority changed: {display}",
        )


def verify_sources(sources: Mapping[str, str]) -> None:
    pins = sources["pins"]
    fetch = sources["fetch"]
    fixed_helper = sources["fixed_helper"]
    retire = sources["retire_helper"]
    lib = sources["lib"]
    vm = sources["vm"]
    offline = sources["offline_manifest"]
    guest = sources["guest"]
    project = sources["project"].lstrip("\ufeff")
    verify = sources["verify"]
    requirements = sources["requirements"]
    ledger = sources["ledger"]

    require(pins.count(f'WIX_NUGET_VERSION="{VERSION}"') == 1, "WiX version pin changed")
    require(
        pins.count(f'WIX_NUGET_AUTHOR_CERT_SHA256="{AUTHOR_CERT}"') == 1,
        "WiX author certificate pin changed",
    )
    require(
        pins.count(f'WIX_NUGET_REPOSITORY_CERT_SHA256="{REPOSITORY_CERT}"') == 1,
        "NuGet repository certificate pin changed",
    )
    for package, suffix, size, digest, _ in PACKAGES:
        require(
            pins.count(f'SIZE_WIX_NUGET_{suffix}="{size}"') == 1,
            f"WiX size pin changed: {package}",
        )
        require(
            pins.count(f'SHA256_WIX_NUGET_{suffix}="{digest}"') == 1,
            f"WiX digest pin changed: {package}",
        )
    for label, (size, digest) in (
        ("SIX", LEGACY_SIX),
        ("EIGHT", LEGACY_EIGHT),
    ):
        require(
            pins.count(f'SIZE_WIX_NUGET_LEGACY_{label}="{size}"') == 1
            and pins.count(f'SHA256_WIX_NUGET_LEGACY_{label}="{digest}"') == 1,
            f"known legacy WiX archive identity changed: {label}",
        )
    require(
        re.search(r"(?m)^SHA256_WIX_NUGET=", pins) is None,
        "ambiguous expanded-cache WiX pin remains",
    )

    manifest_start = fetch.find("readonly -a WIX_NUGET_FIXED_ARCHIVE_ARGS=(")
    require(manifest_start >= 0, "WiX fixed-package manifest is absent")
    manifest_end = fetch.find("\n)\n", manifest_start)
    require(manifest_end >= 0, "WiX fixed-package manifest is unterminated")
    manifest = fetch[manifest_start : manifest_end + 3]
    require(manifest.count("--entry\n") == 6, "WiX acquisition manifest is not six entries")
    positions: list[int] = []
    for package, suffix, _, _, _ in PACKAGES:
        name = f"wix-nuget-packages/{package}.${{WIX_NUGET_VERSION}}.nupkg"
        url = (
            f"https://api.nuget.org/v3-flatcontainer/{package}/"
            f"${{WIX_NUGET_VERSION}}/{package}.${{WIX_NUGET_VERSION}}.nupkg"
        )
        snippet = "\n".join(
            (
                "    --entry",
                f'    "{name}"',
                f'    "{url}"',
                f'    "$SIZE_WIX_NUGET_{suffix}"',
                f'    "$SHA256_WIX_NUGET_{suffix}"',
                '    "api.nuget.org"',
            )
        )
        require(manifest.count(snippet) == 1, f"WiX acquisition entry changed: {package}")
        positions.append(manifest.index(snippet))
    require(positions == sorted(positions), "WiX acquisition manifest is not sorted")
    stage = shell_function(fetch, "stage_windows_wix_nuget")
    require_all(
        stage,
        (
            'stage_archive_bundle wix "$ONLINE_DIR" .rustdesk-wix-nuget-packages',
            '"$WIX_NUGET_RETIRE_HELPER" retire',
            '--online "$ONLINE_DIR"',
            '--uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"',
            "--legacy-six-size",
            "--legacy-six-sha256",
            "--legacy-eight-size",
            "--legacy-eight-sha256",
        ),
        "WiX acquisition stage",
    )
    require(
        stage.index("stage_archive_bundle wix") < stage.index('"$WIX_NUGET_RETIRE_HELPER" retire'),
        "legacy cache can retire before all six exact packages are durable",
    )
    require(
        "curl " not in stage and "dotnet " not in stage and "wix-nuget.tar.gz" not in stage,
        "WiX stage retains an ad-hoc downloader, SDK producer, or expanded-cache consumer",
    )
    main = shell_function(fetch, "main")
    require_all(
        main,
        (
            "--wix-nuget-packages)",
            'load_builder_images\n            stage_windows_wix_nuget',
        ),
        "scoped WiX acquisition mode",
    )
    require(
        "mcr.microsoft.com/dotnet/sdk:8.0" not in fetch,
        "mutable .NET SDK WiX producer remains",
    )

    require_all(
        fixed_helper,
        (
            "if len(specs) == 6:",
            "the WiX manifest is not the exact sorted six-package 4.0.5 source",
            "def test_wix_specs()",
            "WiX self-test publication omitted a package",
        ),
        "common fixed-archive WiX profile",
    )
    require_all(
        retire,
        (
            'LEGACY_NAME = "wix-nuget.tar.gz"',
            'STAGING_PREFIX = ".rustdesk-wix-nuget-retire."',
            "RENAME_NOREPLACE = 1",
            "def descriptor_mount_id(",
            "os.O_NOFOLLOW",
            "before.st_nlink != 1",
            "os.listxattr(descriptor)",
            "fcntl.LOCK_EX | fcntl.LOCK_NB",
            "stat.S_IMODE(root.st_mode) != 0o700",
            "os.listxattr(root_fd)",
            "allowed_modes={0o644}",
            "renameat2(",
            "os.fsync(root_fd)",
            "WiX retirement refuses root UID or GID",
            "obsolete WiX cache archive has an unknown size and was preserved",
            "self-test accepted an unknown legacy archive",
            "self-test accepted an exact legacy archive in a nonhistorical mode",
            "self-test accepted a nonprivate online root",
            "self-test did not recover exact interrupted retirement staging",
        ),
        "legacy WiX retirement helper",
    )
    for package, _, _, _, _ in PACKAGES:
        require(
            retire.count(f'"wix-nuget-packages/{package}.{VERSION}.nupkg"') == 1,
            f"retirement helper inventory changed: {package}",
        )
    require(
        "os.replace(" not in retire
        and "shutil.rmtree" not in retire
        and "Path.unlink(" not in retire,
        "legacy WiX retirement has an overwrite or path-recursive deletion primitive",
    )

    for package, suffix, _, _, _ in PACKAGES:
        path = f'"wix-nuget-packages/{package}.${{WIX_NUGET_VERSION}}.nupkg"'
        require(
            lib.count(f"{path} \"$SHA256_WIX_NUGET_{suffix}\"") == 1,
            f"online closure verification omits exact WiX package: {package}",
        )
    require(
        "wix-nuget.tar.gz" not in lib and "$SHA256_WIX_NUGET\"" not in lib,
        "online closure still consumes expanded WiX cache authority",
    )

    require("WIX_NUGET_ROOT" not in vm, "Windows host harness retains extracted WiX state")
    require("extract_wix_nuget() {" not in vm, "Windows host harness still extracts WiX")
    require("wix-nuget.tar.gz" not in vm, "Windows host harness still consumes WiX tar state")
    preflight = shell_function(vm, "preflight")
    media = shell_function(vm, "build_offline_media")
    manifest_writer = shell_function(vm, "write_offline_manifest")
    wix_validator = shell_function(vm, "verify_wix_nuget_packages")
    require_all(
        wix_validator,
        (
            'local root="$ONLINE_DIR/wix-nuget-packages"',
            "must contain exactly six entries",
            "stat -c '%s'",
            'verify_sha256 "$file" "$expected_sha"',
        ),
        "host WiX source validator",
    )
    require(preflight.count("verify_wix_nuget_packages") == 1, "preflight omits WiX validation")
    require(
        '--wix-root "$ONLINE_DIR/wix-nuget-packages"' in manifest_writer,
        "offline manifest does not bind the read-only WiX source",
    )
    require_all(
        media,
        (
            '--mount "type=bind,source=$ONLINE_DIR,target=/online,readonly"',
            "/wix-nuget-packages=/online/wix-nuget-packages",
            'cmp -s "$manifest" "$after"',
        ),
        "offline WiX media materialization",
    )
    require(
        "windows_helper_small_run" not in media and "/wix-nuget=" not in media,
        "offline media recreates or grafts expanded WiX cache state",
    )
    require_all(
        offline,
        (
            'Mapping("wix-nuget-packages", wix_root, wix_root)',
            'require_real_directory(wix_root, "WiX local-package source")',
            '"wix-nuget-packages/package/content"',
        ),
        "offline manifest WiX mapping",
    )
    require('Mapping("wix-nuget",' not in offline, "old WiX media namespace remains")

    for package, _, size, digest, _ in PACKAGES:
        require(
            guest.count(f"Name = '{package}.{VERSION}.nupkg'") == 1
            and guest.count(f"Size = [Int64]{size}") == 1
            and guest.count(f"Sha256 = '{digest}'") == 1,
            f"Windows guest exact package authority changed: {package}",
        )
    require_all(
        guest,
        (
            f"$WIX_VERSION     = '{VERSION}'",
            f"$WIX_AUTHOR_CERT_SHA256 = '{AUTHOR_CERT}'",
            f"$WIX_REPOSITORY_CERT_SHA256 = '{REPOSITORY_CERT}'",
            "function Assert-WixPackageSource",
            "function Assert-WixGlobalPackages",
            "$wixSrc = Join-Path $offline 'wix-nuget-packages'",
            "Assert-WixPackageSource $wixSrc",
            "[void](Get-OrdinaryPathItem $env:TEMP $false)",
            '$wixPkgs = Join-Path $env:TEMP "rustdesk-wix-nuget-$($env:RUSTDESK_BUILD_RUN_ID)"',
            'if (Test-Path -LiteralPath $wixPkgs) {\n'
            '        Die ".msi: run-scoped WiX global-packages path is already occupied: $wixPkgs"\n'
            "    }\n"
            "    New-Item -ItemType Directory -Path $wixPkgs | Out-Null",
            "run-scoped WiX global-packages path is already occupied",
            "$env:NUGET_PACKAGES = $wixPkgs",
            "$env:NUGET_CERT_REVOCATION_MODE = 'offline'",
            "$env:DOTNET_NUGET_SIGNATURE_VERIFICATION = 'true'",
            "$nugetCfg = Join-Path $SRC 'res\\msi\\NuGet.Config'",
            'if (Test-Path -LiteralPath $nugetCfg) {\n'
            '        Die ".msi: run-scoped WiX NuGet config path is already occupied: $nugetCfg"\n'
            "    }",
            "run-scoped WiX NuGet config path is already occupied",
            "[IO.FileMode]::CreateNew",
            "$nugetConfigStream.Flush($true)",
            "$nugetCfgBefore = (Get-FileHash",
            '<add key="signatureValidationMode" value="require" />',
            '<add key="offline-wix" value="$wixSourceXml" />',
            '<package pattern="WixToolset.*" />',
            'fingerprint="$WIX_AUTHOR_CERT_SHA256"',
            'fingerprint="$WIX_REPOSITORY_CERT_SHA256"',
            "$wixLockBefore = (Get-FileHash",
            "-p:RestoreLockedMode=true",
            "-p:RestorePackagesWithLockFile=true",
            "-p:RestoreNoCache=true",
            "-p:NuGetAudit=false",
            "Assert-WixGlobalPackages $wixPkgs",
            "$nugetCfgAfter = (Get-FileHash",
            "run-scoped NuGet configuration changed during locked offline restore",
            "$wixLockAfter = (Get-FileHash",
            "committed NuGet lock file changed during locked offline restore",
        ),
        "Windows guest signed locked WiX restore",
    )
    require(
        guest.count("Assert-WixPackageSource $wixSrc") == 2,
        "Windows guest does not validate the WiX source both before and after restore",
    )
    msi_start = guest.find("# --- the WiX v4 .msi")
    msi_end = guest.find("if (-not (Test-Path -LiteralPath $msiBuiltOut", msi_start)
    require(msi_start >= 0 and msi_end > msi_start, "WiX guest build block is unavailable")
    msi_block = guest[msi_start:msi_end]
    require(
        "Copy-Item" not in msi_block
        and "Remove-Item" not in msi_block
        and "Set-Content" not in msi_block
        and "wix-nuget.tar.gz" not in msi_block
        and "https://api.nuget.org/v3/index.json" in msi_block,
        "WiX guest restore copies derived cache state or lacks exact signer metadata",
    )
    require(
        '<packageSources>\n    <clear />' in msi_block,
        "WiX guest restore retains ambient package sources",
    )

    require(
        project.count(f'<Project Sdk="WixToolset.Sdk/{VERSION}">') == 1,
        "WiX SDK project pin changed",
    )
    require(
        project.count("<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>") == 1
        and project.count("<RestoreLockedMode>true</RestoreLockedMode>") == 1,
        "WiX project does not require its lock",
    )
    require(
        project.count(
            "<RuntimeIdentifiers>win;win-arm64;win-x64;win-x86</RuntimeIdentifiers>"
        )
        == 1,
        "WiX project runtime graph is not exact",
    )
    for package, _, _, _, content_hash in PACKAGES:
        if content_hash is None:
            continue
        display = {
            "wixtoolset.firewall.wixext": "WixToolset.Firewall.wixext",
            "wixtoolset.heat": "WixToolset.Heat",
            "wixtoolset.netfx.wixext": "WixToolset.Netfx.wixext",
            "wixtoolset.ui.wixext": "WixToolset.UI.wixext",
            "wixtoolset.util.wixext": "WixToolset.Util.wixext",
        }[package]
        require(
            project.count(
                f'<PackageReference Include="{display}" Version="[{VERSION}]" />'
            )
            == 1,
            f"WiX PackageReference is not exact: {display}",
        )
    verify_lock(sources["lock"])

    require_all(
        verify,
        (
            "online-wix-nuget-retire.py self-test",
            "verify-wix-nuget-authority.py --repo . --self-test",
        ),
        "top-level WiX verifier wiring",
    )
    require(
        '<span class="id">R-S11cz</span>' in requirements
        and "R-S11e-118" in requirements
        and "<td>253</td>" in requirements,
        "requirements omit exact signed WiX package authority",
    )
    require(
        "R-S11cz/R-S11e-118" in ledger,
        "hardening ledger omits exact signed WiX package evidence",
    )


@dataclass(frozen=True)
class Mutation:
    file: str
    old: str
    new: str
    label: str


MUTATIONS = (
    Mutation(
        "pins",
        'SIZE_WIX_NUGET_SDK="18626823"',
        'SIZE_WIX_NUGET_SDK="18626824"',
        "package length",
    ),
    Mutation(
        "pins",
        f'WIX_NUGET_AUTHOR_CERT_SHA256="{AUTHOR_CERT}"',
        'WIX_NUGET_AUTHOR_CERT_SHA256="BAD"',
        "author signer",
    ),
    Mutation(
        "fetch",
        "https://api.nuget.org/v3-flatcontainer/wixtoolset.sdk/",
        "https://example.invalid/v3-flatcontainer/wixtoolset.sdk/",
        "acquisition URL",
    ),
    Mutation(
        "fetch",
        "stage_archive_bundle wix \"$ONLINE_DIR\"",
        "stage_archive_bundle toolchain \"$ONLINE_DIR\"",
        "closed acquisition profile",
    ),
    Mutation(
        "fetch",
        '"$WIX_NUGET_RETIRE_HELPER" retire',
        '"$WIX_NUGET_RETIRE_HELPER" skip',
        "legacy retirement",
    ),
    Mutation(
        "fixed_helper",
        "if len(specs) == 6:",
        "if len(specs) == 5:",
        "six-package fixed manifest",
    ),
    Mutation(
        "retire_helper",
        "RENAME_NOREPLACE = 1",
        "RENAME_NOREPLACE = 0",
        "no-clobber retirement",
    ),
    Mutation(
        "retire_helper",
        "before.st_nlink != 1",
        "before.st_nlink < 1",
        "retirement hardlink refusal",
    ),
    Mutation(
        "lib",
        '"wix-nuget-packages/wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg" "$SHA256_WIX_NUGET_SDK"',
        '"wix-nuget-packages/wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg" "$SHA256_WIX_NUGET_UI"',
        "closure digest mapping",
    ),
    Mutation(
        "vm",
        "/wix-nuget-packages=/online/wix-nuget-packages",
        "/wix-nuget-packages=/online/pub-cache",
        "offline media mapping",
    ),
    Mutation(
        "offline_manifest",
        'Mapping("wix-nuget-packages", wix_root, wix_root)',
        'Mapping("wix-nuget", wix_root, wix_root)',
        "offline manifest namespace",
    ),
    Mutation(
        "guest",
        '<add key="signatureValidationMode" value="require" />',
        '<add key="signatureValidationMode" value="accept" />',
        "signature requirement",
    ),
    Mutation(
        "guest",
        "-p:RestoreLockedMode=true",
        "-p:RestoreLockedMode=false",
        "locked restore",
    ),
    Mutation(
        "guest",
        "Assert-WixPackageSource $wixSrc",
        "Write-Host $wixSrc",
        "source validation",
    ),
    Mutation(
        "guest",
        'if (Test-Path -LiteralPath $wixPkgs) {\n'
        '        Die ".msi: run-scoped WiX global-packages path is already occupied: $wixPkgs"',
        'if ($false) {\n'
        '        Die ".msi: run-scoped WiX global-packages path is already occupied: $wixPkgs"',
        "fresh run-scoped cache",
    ),
    Mutation(
        "guest",
        'if (Test-Path -LiteralPath $nugetCfg) {\n'
        '        Die ".msi: run-scoped WiX NuGet config path is already occupied: $nugetCfg"',
        'if ($false) {\n'
        '        Die ".msi: run-scoped WiX NuGet config path is already occupied: $nugetCfg"',
        "fresh run-scoped config",
    ),
    Mutation(
        "guest",
        "$nugetCfg = Join-Path $SRC 'res\\msi\\NuGet.Config'",
        '$nugetCfg = Join-Path $env:TEMP "rustdesk-wix-nuget.config"',
        "solution-level SDK resolver config",
    ),
    Mutation(
        "guest",
        "[IO.FileMode]::CreateNew",
        "[IO.FileMode]::Create",
        "no-clobber run-scoped config creation",
    ),
    Mutation(
        "retire_helper",
        "stat.S_IMODE(root.st_mode) != 0o700",
        "stat.S_IMODE(root.st_mode) != 0o777",
        "private locked online root",
    ),
    Mutation(
        "retire_helper",
        "allowed_modes={0o644}",
        "allowed_modes={0o600, 0o644}",
        "single historical legacy mode",
    ),
    Mutation(
        "project",
        'Version="[4.0.5]"',
        'Version="4.0.5"',
        "exact PackageReference",
    ),
    Mutation(
        "project",
        "<RuntimeIdentifiers>win;win-arm64;win-x64;win-x86</RuntimeIdentifiers>",
        "<RuntimeIdentifiers>win-x64</RuntimeIdentifiers>",
        "exact Windows runtime graph",
    ),
    Mutation(
        "lock",
        '"resolved": "4.0.5"',
        '"resolved": "4.0.4"',
        "lock resolution",
    ),
    Mutation(
        "lock",
        '"native,Version=v0.0/win-x64": {}',
        '"native,Version=v0.0/linux-x64": {}',
        "Windows runtime lock graph",
    ),
    Mutation(
        "verify",
        "online-wix-nuget-retire.py self-test",
        "online-wix-nuget-retire.py skipped-test",
        "retirement self-test wiring",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11cz</span>',
        '<span class="id">R-S11cz-removed</span>',
        "normative requirement",
    ),
    Mutation(
        "ledger",
        "R-S11cz/R-S11e-118",
        "R-S11cz-removed/R-S11e-118",
        "evidence ledger",
    ),
)


def run_mutations(sources: Mapping[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.file]
        require(mutation.old in original, f"mutation anchor is absent: {mutation.label}")
        changed = dict(sources)
        changed[mutation.file] = original.replace(mutation.old, mutation.new, 1)
        try:
            verify_sources(changed)
        except VerificationError:
            continue
        raise VerificationError(f"mutation was not rejected: {mutation.label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    sources = {
        name: (repo / path).read_text(encoding="utf-8")
        for name, path in FILES.items()
    }
    verify_sources(sources)
    if args.self_test:
        run_mutations(sources)
        print(f"WiX NuGet authority mutations: PASS ({len(MUTATIONS)})")
    else:
        print("WiX NuGet authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        raise SystemExit(1)
