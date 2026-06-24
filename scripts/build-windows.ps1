# scripts/build-windows.ps1 -- Windows x86_64 .exe/.msi build (R-B7/B9, sec12.2).
#
# Runs INSIDE the ephemeral KVM Windows 11 guest (provisioned by
# provision-windows-vm.sh) -- Windows cannot be cross-built from Linux (MSVC + WiX
# are Windows-only). Reproduces upstream 1.4.7's official Windows build (R-B7:
# python build.py --flutter; hwcodec/vram dropped -- CPU-only software codec, R-R2b) with these deltas:
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
    # $actual may be a MULTI-LINE command capture: `flutter --version` and `clang --version` return a PSObject[]
    # of lines. `-notmatch` over an array returns the non-matching ELEMENTS (a truthy list), so the check tripped
    # even though one line carries the version (rustc's single-line output happened to pass). Flatten first.
    $actual = ($actual | Out-String)
    if ($actual -notmatch [regex]::Escape($expect)) {
        Die "$what version mismatch: expected '$expect', got '$actual' -- pin from pins.env, do not upgrade in place"
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
    Write-Host "[harness] preflight OK -- Windows x64, offline, features flutter -- software codec (sec3.2)"
}

function Build {
    Set-Location $SRC
    # Determinism (R-B2): the same SOURCE_DATE_EPOCH the Linux builds pin, so
    # gen_version bakes a reproducible BUILD_DATE (the patch honors it on Windows
    # too). Passed in by provision-windows-vm.sh / the invoker.
    if (-not $env:SOURCE_DATE_EPOCH) { Write-Host "[harness:warn] SOURCE_DATE_EPOCH unset -- build will not be bit-reproducible (R-B2)" }
    # R-B2 PE determinism: /Brepro makes the MSVC linker stamp a CONTENT-HASH into the PE TimeDateStamp instead
    # of the wall-clock build time. Inject it via the LINK env var, which EVERY link.exe invocation in the build
    # honors -- rustc's link (librustdesk.dll + rustdesk-portable-packer.exe), the flutter runner (rustdesk.exe),
    # and the plugin DLLs. Without it those PE timestamps drift every build, and since the portable packer
    # brotli-compresses the flutter build dir INTO the final .exe, the deltas amplify across ~97% of it (proved:
    # build#1 4a7dbe4d vs build#2 7e08ce99, identical source). SOURCE_DATE_EPOCH only fixes the gen_version
    # BUILD_DATE string, not PE headers -- both are needed for R-B2.
    $env:LINK = '/Brepro'
    Write-Host "[harness] R-B2: LINK=/Brepro (reproducible PE TimeDateStamp across rustc + flutter MSVC links)"

    # --- locate the OFFLINE UDF media (cargo-vendor + its source map + pub-cache), attached by
    # build-windows-vm.sh; drive letters are dynamic, so detect by content. -----------------------
    $offline = (Get-PSDrive -PSProvider FileSystem |
                Where-Object { Test-Path (Join-Path $_.Root 'cargo-vendor-config.toml') } |
                Select-Object -First 1).Root
    if (-not $offline) { Die 'OFFLINE media not attached (no drive has cargo-vendor-config.toml)' }
    Write-Host "[harness] offline caches on $offline (cargo-vendor + pub-cache)"

    # --- cargo: a build-time CARGO_HOME wired to the vendored crate set (R-B10). DON'T touch the
    # repo's TRACKED .cargo/config.toml (it carries the windows rustflags); cargo MERGES this over it.
    # The AUTHORITATIVE [source.*] map is cargo-vendor-config.toml (crates-io + every rustdesk git
    # dep); rewrite its `directory =` to the vendor drive + prepend [net] offline -- like build-debian.
    $env:CARGO_HOME = 'C:\cargo-home'
    New-Item -ItemType Directory -Force -Path $env:CARGO_HOME | Out-Null
    $vendorDir = (Join-Path $offline 'cargo-vendor') -replace '\\','/'
    $cargoCfg  = "[net]`r`noffline = true`r`n"
    $cargoCfg += ((Get-Content (Join-Path $offline 'cargo-vendor-config.toml') -Raw) -replace 'directory = .*', "directory = `"$vendorDir`"")
    Set-Content -Encoding ASCII -Path (Join-Path $env:CARGO_HOME 'config.toml') -Value $cargoCfg

    # --- pub: PUB_CACHE on the attached cache; pre-resolve the project OFFLINE. TWO steps:
    # (1) `dart pub get --offline` -- the proven Dart-level resolve (writes .dart_tool/package_config.json;
    #     the build-log shows "Got dependencies!" with no advisory/handshake error, so --offline is clean here).
    # (2) `flutter pub get --offline` -- the FLUTTER-level pub get, which ALSO runs flutter's plugin injection
    #     and so GENERATES flutter/windows/flutter/generated_plugins.cmake (+ generated_plugin_registrant).
    # `flutter build windows` is shimmed with --no-pub below to dodge its ONLINE in-build pub get, so the
    # injection MUST happen here -- otherwise the windows runner CMake aborts: "could not find requested file:
    # flutter/generated_plugins.cmake" (CMakeLists.txt:71). We keep the bare `dart pub get` as the proven base
    # and add the flutter one only for the injection; both are --offline + CI=true. `flutter` here is the REAL
    # flutter (the --no-pub shim is not on PATH until below). The golden's flutter_tools is pre-resolved.
    $env:PUB_CACHE = (Join-Path $offline 'pub-cache')
    $env:CI = 'true'
    $env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
    git config --global --add safe.directory '*'
    Push-Location (Join-Path $SRC 'flutter')
    & dart pub get --offline
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "dart pub get --offline (project) failed ($LASTEXITCODE) -- pub-cache may lack a windows-only package" }
    & flutter pub get --offline
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "flutter pub get --offline (plugin injection) failed ($LASTEXITCODE) -- generated_plugins.cmake will be absent; the flutter wrapper may have reached pub.dev for advisories" }
    Pop-Location

    # --- the flutter offline shim: build.py runs `flutter build windows --release`, whose IN-PROCESS
    # pub get drives ONLINE; shadow `flutter` earlier on PATH with a shim that appends --no-pub to
    # `build` (the project is already resolved above). FRB is NOT run here -- the bridges are
    # pre-generated on the host (frb-codegen.sh) + shipped on the BUILD CD into $SRC (R-B7). ---------
    $shim = 'C:\flutter-shim'
    New-Item -ItemType Directory -Force -Path $shim | Out-Null
    $env:REAL_FLUTTER = 'C:\flutter\bin\flutter.bat'
    @'
@echo off
if /I "%~1"=="build" (
    "%REAL_FLUTTER%" %* --no-pub
) else (
    "%REAL_FLUTTER%" %*
)
'@ | Set-Content -Encoding ASCII (Join-Path $shim 'flutter.bat')
    $env:PATH = "$shim;$env:PATH"

    # --- the sec3.2 x64-windows build: CPU-only software codec, no hwcodec/vram (R-R2b) ---
    # Under $ErrorActionPreference='Stop' a NATIVE command's non-zero exit does NOT auto-throw, so check
    # $LASTEXITCODE explicitly -- otherwise a failed build (e.g. "Python was not found" -> exit 9009) slips
    # through and Emit-Artifacts reports "complete" with no .exe.
    python build.py --flutter
    if ($LASTEXITCODE -ne 0) { Die "build.py --flutter failed (exit $LASTEXITCODE) -- Python missing/not on PATH, or the cargo/flutter build errored (see above)" }

    # --- the WiX v4 .msi (R-B7/B9) -- a SEPARATE step: build.py only runs the portable packer (the .exe),
    # so this mirrors upstream's flutter-build.yml "Build msi" (preprocess.py --arp -d <dist>; restore;
    # msbuild msi.sln). NO .NET SDK needed -- VS msbuild + .NET Framework (golden) + the WiX NuGet build it.
    # OFFLINE: the WiX NuGet set (WixToolset.Sdk + the 5 .wixext + DUtil/WcaUtil) is staged on the OFFLINE
    # UDF CD at $offline\wix-nuget; copy it to a WRITABLE global-packages dir (UDF is read-only; NuGet writes
    # there) and force an offline restore via a <clear/>-sources NuGet.config + NUGET_PACKAGES, so msbuild
    # resolves WixToolset.Sdk/4.0.5 from the cache with no network. preprocess.py reads the dist's
    # rustdesk.exe (--build-date/--version), so it runs against the real flutter dist build.py just produced.
    $wixSrc = Join-Path $offline 'wix-nuget'
    if (-not (Test-Path (Join-Path $wixSrc 'wixtoolset.sdk'))) { Die ".msi: OFFLINE media lacks wix-nuget\wixtoolset.sdk (staged WiX NuGet cache) -- run online-fetch.sh stage_windows_wix_nuget" }
    $wixPkgs = 'C:\wix-nuget'
    if (Test-Path $wixPkgs) { Remove-Item -Recurse -Force $wixPkgs }
    New-Item -ItemType Directory -Force -Path $wixPkgs | Out-Null
    Copy-Item -Recurse -Force (Join-Path $wixSrc '*') $wixPkgs
    $env:NUGET_PACKAGES = $wixPkgs                       # the MSBuild-SDK resolver reads this to find WixToolset.Sdk
    $nugetCfg = Join-Path $env:TEMP 'offline-nuget.config'
    @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <config><add key="globalPackagesFolder" value="$wixPkgs" /></config>
  <packageSources><clear /></packageSources>
</configuration>
"@ | Set-Content -Encoding UTF8 $nugetCfg
    $msiDist = Join-Path $SRC 'flutter\build\windows\x64\runner\Release'
    if (-not (Test-Path (Join-Path $msiDist 'rustdesk.exe'))) { Die ".msi: flutter dist (rustdesk.exe) not at $msiDist -- build.py --flutter should produce it" }
    # msbuild lives in the VS install dir, NOT on PATH by default (the golden has no CI "Add MSBuild to
    # PATH" step). Locate it via vswhere (-products * so it finds BuildTools, not just full VS) + prepend.
    $vsw = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    $vsPath = (& $vsw -products * -latest -property installationPath 2>$null | Select-Object -First 1)
    if (-not $vsPath) { Die ".msi: vswhere found no VS install (need VS BuildTools with MSBuild)" }
    $msbuildDir = Join-Path $vsPath 'MSBuild\Current\Bin'
    if (-not (Test-Path (Join-Path $msbuildDir 'MSBuild.exe'))) { Die ".msi: MSBuild.exe not under $msbuildDir" }
    $env:PATH = "$msbuildDir;$env:PATH"
    Push-Location (Join-Path $SRC 'res\msi')
    python preprocess.py --arp -d $msiDist
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "res/msi/preprocess.py --arp failed ($LASTEXITCODE)" }
    msbuild msi.sln -t:restore -p:RestoreConfigFile=$nugetCfg -p:Configuration=Release -p:Platform=x64
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "msbuild -t:restore (WiX NuGet, OFFLINE from $wixPkgs) failed ($LASTEXITCODE) -- staged cache incomplete, or the SDK resolver wanted the network" }
    msbuild msi.sln -p:RestoreConfigFile=$nugetCfg -p:Configuration=Release -p:Platform=x64 /p:TargetVersion=Windows10
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "msbuild msi.sln (WiX .msi build) failed ($LASTEXITCODE)" }
    Pop-Location
    $msiOut = Join-Path $SRC 'res\msi\Package\bin\x64\Release\en-us\Package.msi'
    if (-not (Test-Path $msiOut)) { Die ".msi: expected output not produced at $msiOut" }
    Write-Host "[harness] .msi built (R-B7): $msiOut"
}

function Emit-Artifacts {
    $out = Join-Path $SRC 'dist'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    # The portable installer .exe (libs/portable) and the WiX v4 .msi. build.py's
    # build_flutter_windows renames the portable packer to rustdesk-<version>-install.exe (NOT a
    # "win7" variant), so the filter must be rustdesk-*install.exe or Emit-Artifacts finds nothing.
    Get-ChildItem -Path $SRC -Filter 'rustdesk-*install.exe' -Recurse | Select-Object -First 1 |
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
