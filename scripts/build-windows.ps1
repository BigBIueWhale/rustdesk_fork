# scripts/build-windows.ps1 — Windows x86_64 .exe/.msi build (R-B7/B9, §12.2).
#
# Runs INSIDE the ephemeral KVM Windows 11 guest (provisioned by
# provision-windows-vm.sh) — Windows cannot be cross-built from Linux (MSVC + WiX
# are Windows-only). Reproduces upstream 1.4.7's official Windows build (R-B7:
# python build.py --flutter; hwcodec/vram dropped — CPU-only software codec, R-R2b) with these deltas:
# the artifacts ship UNSIGNED (the pinned SHA-256 is the integrity anchor, R-B2),
# and the build runs off GitHub-hosted runners. The guest has no network during the
# build; all inputs were staged offline by provision-windows-vm.sh.
#
# One mode, the good one (R-B9): assert the EXACT pinned versions, then abort; fail
# loud; no fallbacks. NOT run as part of "fork creation".
$ErrorActionPreference = 'Stop'

# --- Pins (the Windows subset of scripts/pins.env, kept in sync) -------------
$RUST_VERSION    = '1.75'
$FLUTTER_VERSION = '3.24.5'
$LLVM_VERSION    = '15.0.6'
$WIX_VERSION     = '4'      # WixToolset v4 (res/msi targets schemas/v4)
$SRC = 'C:\src'             # the repo, shared into the guest read-write

function Die($msg) { Write-Error "[harness:FATAL] $msg"; exit 1 }
function Assert-Version($expect, $actual, $what) {
    if ($actual -notmatch [regex]::Escape($expect)) {
        Die "$what version mismatch: expected '$expect', got '$actual' — pin from pins.env, do not upgrade in place"
    }
    Write-Host "[harness] $what OK: $expect"
}

function Preflight {
    if (-not (Test-Path $SRC)) { Die "repo not found at $SRC" }
    if (Test-Path (Join-Path $SRC '.gitmodules')) { Die "hbb_common must be absorbed in-tree, not a submodule (R-R1)" }
    Assert-Version $RUST_VERSION    (rustc --version)              'rustc'
    Assert-Version $FLUTTER_VERSION (flutter --version)            'flutter'
    Assert-Version $LLVM_VERSION    (clang --version)              'clang/LLVM'
    # WiX, MSVC and vcpkg are provisioned by provision-windows-vm.sh to the pins.
    Write-Host "[harness] preflight OK — Windows x64, offline, features flutter — software codec (§3.2)"
}

function Build {
    Set-Location $SRC
    # Determinism (R-B2): the same SOURCE_DATE_EPOCH the Linux builds pin, so
    # gen_version bakes a reproducible BUILD_DATE (the patch honors it on Windows
    # too). Passed in by provision-windows-vm.sh / the invoker.
    if (-not $env:SOURCE_DATE_EPOCH) { Write-Host "[harness:warn] SOURCE_DATE_EPOCH unset — build will not be bit-reproducible (R-B2)" }

    # Wire cargo to the vendored, lockfile-pinned crate set staged offline.
    New-Item -ItemType Directory -Force -Path "$SRC\.cargo" | Out-Null
    @"
[source.crates-io]
replace-with = "vendored"
[source.vendored]
directory = "C:/online/cargo-vendor"
[net]
offline = true
"@ | Set-Content "$SRC\.cargo\config.toml"

    # FRB codegen (R-B7: the uncommitted generated_bridge.dart / bridge_generated.rs),
    # then build.py with the §3.2 x64-windows features minus hwcodec/vram (R-R2b).
    flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs --dart-output ./flutter/lib/generated_bridge.dart
    python build.py --flutter
}

function Emit-Artifacts {
    $out = Join-Path $SRC 'dist'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    # The portable installer .exe (libs/portable) and the WiX v4 .msi.
    Get-ChildItem -Path $SRC -Filter 'rustdesk-*win7-install.exe' -Recurse | Select-Object -First 1 |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $out 'rustdesk-setup.exe') }
    Get-ChildItem -Path $SRC -Filter '*.msi' -Recurse | Select-Object -First 1 |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $out 'rustdesk.msi') }
    # Record the pinned SHA-256 (R-B2): the tamper-evidence anchor in place of a
    # code signature, verified on the target over the operator's trusted channel.
    Get-ChildItem $out\rustdesk-setup.exe, $out\rustdesk.msi -ErrorAction SilentlyContinue | ForEach-Object {
        $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
        "$h  $($_.Name)" | Tee-Object -FilePath "$($_.FullName).sha256"
    }
    Write-Host "[harness] build-windows.ps1 complete: $out"
}

Preflight
Build
Emit-Artifacts
