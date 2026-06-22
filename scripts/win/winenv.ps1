# scripts/win/winenv.ps1 -- initialize the reproducible Windows build environment
# in the CURRENT PowerShell session. Dot-source it:   . scripts\win\winenv.ps1
#
# ASCII-ONLY by design: PowerShell 5.x reads a BOM-less .ps1 as ANSI, so any
# non-ASCII byte in a string literal corrupts parsing. Keep it 7-bit clean.
#
# Runs INSIDE the ephemeral KVM Windows 11 guest (provision-windows-vm.sh, spec
# 12.2). Every path matches what provision-windows-guest.ps1 installs, so the
# environment is identical on any clone of this repo -- no "latest", no in-place
# drift (R-B9). It establishes, in order:
#   1. MSVC toolchain (cl/link, INCLUDE, LIB) from VS BuildTools vcvars64.bat
#   2. vcpkg native deps (classic mode, static triplet): aom libvpx libyuv opus jpeg
#      (the R-R2b CPU-only software-codec set -- NO ffmpeg, NO mfx-dispatch/hwcodec)
#   3. libclang for bindgen determinism (LLVM, pins.env)
#   4. cargo + git on PATH (prepended so the pins win)
#
# crt-static (.cargo/config.toml: -Ctarget-feature=+crt-static) is what makes the
# vcpkg build-crate resolve the x64-windows-STATIC libs -- do not remove it.
$ErrorActionPreference = 'Stop'

$VsBuildTools = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'
$Vcvars       = Join-Path $VsBuildTools 'VC\Auxiliary\Build\vcvars64.bat'
$VcpkgRoot    = 'C:\vcpkg'
$LlvmBin      = 'C:\Program Files\LLVM\bin'
$CargoBin     = Join-Path $env:USERPROFILE '.cargo\bin'
$GitCmd       = 'C:\Program Files\Git\cmd'

if (-not (Test-Path $Vcvars))    { throw ("[winenv] vcvars64.bat missing at {0} -- run provision-windows-guest.ps1" -f $Vcvars) }
if (-not (Test-Path $VcpkgRoot)) { throw ("[winenv] vcpkg missing at {0} -- run provision-windows-guest.ps1" -f $VcpkgRoot) }
if (-not (Test-Path $LlvmBin))   { throw ("[winenv] LLVM missing at {0} -- run provision-windows-guest.ps1" -f $LlvmBin) }

# 1. Import the full MSVC environment vcvars64.bat exports (INCLUDE, LIB, PATH, ...).
#    cmd runs the batch, dumps `set`, and we splice every KEY=VALUE into env:.
cmd /c "`"$Vcvars`" >nul 2>&1 && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path ("env:" + $matches[1]) -Value $matches[2] }
}
if (-not $env:VCToolsInstallDir) { throw "[winenv] vcvars64.bat did not populate the MSVC env" }

# 2. vcpkg: classic static libs; the vcpkg crate resolves VCPKG_ROOT\installed\triplet.
$env:VCPKG_ROOT            = $VcpkgRoot
$env:VCPKG_DEFAULT_TRIPLET = 'x64-windows-static'

# 3. libclang for bindgen (magnum-opus and friends).
$env:LIBCLANG_PATH = $LlvmBin

# 4. cargo + git + llvm on PATH.
$env:Path = "$CargoBin;$GitCmd;$LlvmBin;" + $env:Path

Write-Host ("[winenv] ready: MSVC {0} | vcpkg {1} | LLVM | cargo" -f $env:VCToolsInstallDir, $env:VCPKG_DEFAULT_TRIPLET)
