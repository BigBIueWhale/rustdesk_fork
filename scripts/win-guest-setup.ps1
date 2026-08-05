# scripts/win-guest-setup.ps1 -- provisions the sec12.2 Win11 build guest's toolchain (R-B8).
#
# Run ONCE inside the guest at first logon (autounattend.xml FirstLogonCommands) while the VM
# still has network (the golden-template build is the one networked guest step -- like the
# android stage_gradle). It installs EXACTLY the pinned toolchain from the toolchains CD that
# provision-windows-vm.sh attaches (the ./online windows artifacts), then the per-build VM is a
# throwaway CoW overlay run --network=none (build-windows.ps1).
#
# Pinned set (pins.env): Rust 1.75 (MSVC), Flutter 3.24.5 (windows), LLVM 15.0.6 (windows),
# VS Build Tools (MSVC + Win SDK), vcpkg @120deac3, Git. The vcpkg x64-windows natives are
# warmed against res/vcpkg; the WiX v4 NuGet closure is staged on the per-build OFFLINE media
# by scripts/online-fetch.sh and consumed by scripts/build-windows.ps1.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Log($m) { Write-Host "[guest-setup] $m" }
function Die($m) { Write-Error "[guest-setup:FATAL] $m"; exit 1 }

# A reliable transcript -- the FirstLogonCommands Tee to guest-setup-log.txt proved unreadable;
# read this post-mortem via libguestfs (virt-cat C:\setup-transcript.txt) to see where setup stopped.
try { Start-Transcript -Path 'C:\setup-transcript.txt' -Force | Out-Null } catch { }
Log "win-guest-setup starting; FS drives: $((Get-PSDrive -PSProvider FileSystem).Name -join ',')"

# --- locate the toolchains CD (the drive holding the staged ./online windows artifacts) ------
$tc = (Get-PSDrive -PSProvider FileSystem |
       Where-Object { Test-Path (Join-Path $_.Root 'flutter-windows-3.24.5.zip') } |
       Select-Object -First 1).Root
if (-not $tc) { Die 'toolchains CD not found (no drive has flutter-windows-3.24.5.zip)' }
Log "toolchains media: $tc"
$win = Join-Path $tc 'win'          # the captured installers (Git, rust-msvc.msi, rustup)

# --- Git -------------------------------------------------------------------------------------
Log 'installing Git'
Start-Process -Wait -FilePath (Join-Path $win 'Git-2.45.2-64-bit.exe') `
    -ArgumentList '/VERYSILENT','/NORESTART','/SUPPRESSMSGBOXES','/SP-'

# --- Rust 1.75 (x86_64-pc-windows-msvc), offline .msi ----------------------------------------
Log 'installing Rust 1.75 (MSVC)'
Start-Process -Wait -FilePath msiexec.exe `
    -ArgumentList '/i',(Join-Path $win 'rust-1.75.0-x86_64-pc-windows-msvc.msi'),'/quiet','/norestart'

# --- VS Build Tools (MSVC + Windows SDK) from the offline layout ------------------------------
Log 'installing VS Build Tools (MSVC + Windows SDK) from the offline layout'
$vsdir = 'C:\vslayout'
New-Item -ItemType Directory -Force -Path $vsdir | Out-Null
tar -xf (Join-Path $tc 'vs-buildtools.layout.tar') -C $vsdir
$vsexe = Get-ChildItem -Path $vsdir -Recurse -Filter 'vs_*.exe' | Select-Object -First 1
if (-not $vsexe) { Die 'vs_buildtools bootstrapper not found in the layout' }
Start-Process -Wait -FilePath $vsexe.FullName -ArgumentList @(
    '--quiet','--wait','--norestart','--nocache','--noUpdateInstaller',
    '--add','Microsoft.VisualStudio.Workload.VCTools',
    '--add','Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
    '--add','Microsoft.VisualStudio.Component.Windows11SDK.22621',
    '--includeRecommended')

# --- LLVM/clang 15.0.6 (libclang for FRB/bindgen determinism) --------------------------------
Log 'installing LLVM 15.0.6'
Start-Process -Wait -FilePath (Join-Path $tc 'llvm-windows-15.0.6.exe') -ArgumentList '/S'

# --- Python 3.11.9 (build.py orchestrator + libs/portable/generate.py brotli) -----------------
Log 'installing Python 3.11.9 (+ brotli for the portable packer)'
$pyExit = (Start-Process -Wait -PassThru -FilePath (Join-Path $tc 'python-windows-3.11.9.exe') `
    -ArgumentList '/quiet','InstallAllUsers=1','PrependPath=1','Include_test=0','Include_pip=1').ExitCode
if ($pyExit -ne 0) { Die "Python install failed (exit $pyExit)" }
$pyExe = 'C:\Program Files\Python311\python.exe'
if (-not (Test-Path $pyExe)) { Die 'Python install did not land python.exe at C:\Program Files\Python311' }
# build.py shells out to `python3 ./generate.py` (a unix-ism); Windows Python ships python.exe NOT python3.exe
# (pip3.exe IS created by the installer). Copy one so the build's `python3` resolves.
Copy-Item $pyExe (Join-Path (Split-Path $pyExe) 'python3.exe') -Force
# brotli is the ONLY non-stdlib import in libs/portable/generate.py (requirements.txt = just `brotli`). Install
# it NOW (the provision is networked) so the OFFLINE per-build's `pip3 install -r requirements.txt` is a
# "Requirement already satisfied" no-op (no network needed at build time).
$pipExit = (Start-Process -Wait -PassThru -NoNewWindow -FilePath $pyExe -ArgumentList '-m','pip','install','brotli').ExitCode
if ($pipExit -ne 0) { Die "pip install brotli failed (exit $pipExit)" }

# --- Flutter 3.24.5 (windows) ----------------------------------------------------------------
Log 'extracting Flutter 3.24.5 (windows) -> C:\flutter'
Expand-Archive -Force -Path (Join-Path $tc 'flutter-windows-3.24.5.zip') -DestinationPath 'C:\'

# Precache the windows ENGINE artifacts NOW, while the provision guest still has network. The
# per-build VM runs --network=none, so `flutter build windows` would otherwise fetch the engine
# (flutter_windows.dll, the C++ wrapper, ...) from the network and fail offline. This is the windows
# analogue of build-debian relying on the linux engine being in the SDK tarball. First-run flutter
# also resolves its OWN flutter_tools package ONLINE here -> baked into the golden, so the offline
# per-build skips that networked re-resolution (build-debian pre-resolves flutter_tools per build).
Log 'precaching the Flutter windows engine (+ warming flutter_tools) -- networked provision step'
$env:CI = 'true'                               # CRITICAL: fully non-interactive flutter. Without it the
                                               # FIRST flutter run prints the analytics/first-run banner and
                                               # BLOCKS on stdin in the headless guest (the prior hang: ~2% CPU
                                               # / 0 disk forever). FLUTTER_SUPPRESS_ANALYTICS alone does NOT
                                               # suppress the banner; CI=true makes it non-blocking. A docker
                                               # test confirmed precache --windows finishes in ~22s with CI=true.
$env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
# git + flutter/dart MUST be on THIS process's PATH now: the persistent machine PATH is set later in
# this script, and a mid-script install does not retro-add to the running process. flutter precache
# also shells out to `git` against the SDK checkout, so git must resolve here.
$env:PATH = "C:\Program Files\Git\cmd;C:\flutter\bin;$env:PATH"
git config --global --add safe.directory '*'   # avoid git "dubious ownership" on the SDK checkout
# Pre-place the windows flutter ENGINE from the OFFLINE staged tarball, then let `flutter precache
# --windows` RECONCILE it. NOTE: the linux-staged engine does NOT fully satisfy the WINDOWS flutter's
# freshness check -- its stamp logic differs from the linux flutter that produced the staging (which
# docker-verified the staging as a 0-download), so precache here RE-FETCHES the engine over slirp. We
# cannot skip this: `flutter build windows` re-runs the very same artifact cache.updateAll, so a
# placed-but-unreconciled engine would just make the OFFLINE per-build try to download too. The fetch is
# large for slirp -- it moves in ~15 MB/s bursts with stalls between -- so allow 30min (a 5min bound Died
# the provision twice; a probe showed it still climbing at 1398 MiB when the 5min fired = slow, not
# wedged). bsdtar (Windows 10+) auto-detects the gzip.
Log 'placing the offline-staged windows flutter engine, then reconciling via precache'
tar -xf (Join-Path $tc 'flutter-windows-engine.tar.gz') -C 'C:\flutter'
if (-not (Test-Path 'C:\flutter\bin\cache\artifacts\engine\windows-x64')) { Die 'engine extraction failed -- windows-x64 absent after tar (gzip/CD issue)' }
# * The first-run flutter_tools `pub get` is what STALLED the provision over slirp -- it makes ~98 pub.dev
# package-METADATA round-trips (NOT the engine: the SDK zip already ships the windows engine + a
# windows-sdk.stamp matching engine.version, so the engine tarball above is a redundant byte-identical
# overlay). The zip ALSO bundles the resolved deps in its pub cache, so resolve flutter_tools OFFLINE here
# -> zero pub.dev traffic -> config + precache run fully offline. CONFIRMED in the rdwinvm SSH VM: with this
# offline resolve, `flutter precache --windows -v` makes 0 pub.dev calls (vs 98 that wedged >30min before).
# Pre-place the FULL flutter_tools hosted pub cache (incl. its DEV deps: test 1.25.7, test_core, test_api,
# fake_async, ...) BEFORE the offline resolve. The SDK zip's BUNDLED cache ships only flutter_tools'
# RUNTIME deps, so `dart pub get --offline` over it alone fails "Because flutter_tools depends on test
# 1.25.7 which doesn't match any versions, version solving failed". online-fetch stage_flutter_pub_cache
# staged the complete closure (hosted/ + hosted-hashes/) deterministically; extract it into the builder's
# pub cache so the resolve below finds every dep with ZERO pub.dev traffic. (Internal layout begins at
# hosted/ -> it lands as ...\Pub\Cache\hosted\pub.dev\...; bsdtar on Win10+ auto-detects the gzip.)
Log 'pre-placing the staged flutter_tools pub cache (the DEV deps the SDK-bundled cache lacks)'
$pc = "$env:LOCALAPPDATA\Pub\Cache"
New-Item -ItemType Directory -Force -Path $pc | Out-Null
tar -xf (Join-Path $tc 'flutter-pub-cache.tar.gz') -C $pc
if (-not (Test-Path (Join-Path $pc 'hosted\pub.dev\test-1.25.7'))) { Die 'flutter_tools pub cache extraction failed -- test-1.25.7 absent after tar; the offline resolve would fail "version solving failed"' }
Log "flutter_tools pub cache extracted to $pc"

# STAMP the staged advisory cache FRESH. The staged flutter-pub-cache.tar.gz includes pub's metadata cache
# (hosted\pub.dev\.cache\), incl. the security-ADVISORY cache (archive-advisories.json + http-advisories.json).
# `dart pub get` refreshes the advisory cache whenever it is older than pub's TTL -- and the deterministic
# staging tar pins EVERY file's mtime to 2023-11 (R-B12 byte-reproducibility), so the extracted advisory cache
# reads as EXPIRED. dart then re-fetches it from pub.dev, and a fresh-Win11 guest's HTTPS handshake to pub.dev
# FAILS ("Handshake error in client (OS Error: ...)") -> the resolve dies (exit 69). This ONE fatal advisory
# fetch killed EVERY provision at the flutter_tools resolve. FIX: stamp the advisory cache to NOW so dart treats
# it as fresh and NEVER reaches pub.dev. VERIFIED in the rdwinvm SSH VM: extract + touch .cache + :443 blocked
# -> "Got dependencies!", rc=0 (touching only *-advisories.json suffices -- the *-versions.json listings are
# tolerated stale under --offline -- but stamping the whole .cache dir is belt-and-suspenders + cheap).
$advCache = Join-Path $pc 'hosted\pub.dev\.cache'
if (-not (Test-Path $advCache)) { Die 'staged pub cache lacks hosted\pub.dev\.cache -- the advisory cache is absent; dart would re-fetch it and the fresh-Win11 TLS to pub.dev would kill the resolve' }
Get-ChildItem $advCache -File | ForEach-Object { $_.LastWriteTime = Get-Date }
Log 'stamped the staged advisory cache fresh (severs the resolve from pub.dev''s advisory fetch)'

Log 'resolving flutter_tools OFFLINE (0 pub.dev traffic: complete staged cache + fresh advisory stamp)'
# Run dart via Start-Process: a CHILD process whose stderr goes to the console, never this script's `*>&1 | Tee`
# pipeline (where, under ErrorActionPreference=Stop, a native stderr line becomes a FATAL NativeCommandError --
# the original provision killer; a command-level 2>&1 does NOT prevent it, Start-Process does). -Wait is
# REQUIRED for a reliable .ExitCode (-PassThru+WaitForExit yields $null -> `-ne 0` always true; verified on
# rdwinvm: -Wait -PassThru -> rc=7). A genuine hang is caught by the 130m provision wait.
$pg = Start-Process 'C:\flutter\bin\cache\dart-sdk\bin\dart.exe' `
    -ArgumentList 'pub','get','--offline','--enforce-lockfile','--directory','C:\flutter\packages\flutter_tools' -Wait -PassThru -NoNewWindow
if ($pg.ExitCode -ne 0) { Die "flutter_tools offline pub get failed (exit $($pg.ExitCode)) -- the staged pub cache is incomplete OR the advisory-cache stamp did not take (dart re-fetched from pub.dev, unreachable on a fresh-Win11 guest)" }
# config enables the windows desktop; precache reconciles the (already-present, offline-staged) engine.
$cfg = Start-Process 'C:\flutter\bin\flutter.bat' -ArgumentList 'config','--no-analytics','--enable-windows-desktop' -Wait -PassThru -NoNewWindow
if ($cfg.ExitCode -ne 0) { Die "flutter config failed (exit $($cfg.ExitCode))" }
$pc = Start-Process 'C:\flutter\bin\flutter.bat' -ArgumentList 'precache','--windows' -Wait -PassThru -NoNewWindow
if ($pc.ExitCode -ne 0) { Die "flutter precache --windows failed (exit $($pc.ExitCode))" }

# --- vcpkg @120deac3 -------------------------------------------------------------------------
Log 'extracting + bootstrapping vcpkg @120deac3 -> C:\vcpkg'
tar -xf (Join-Path $tc 'vcpkg-120deac3062162151622ca4860575a33844ba10b.tar.gz') -C 'C:\'
Rename-Item 'C:\vcpkg-120deac3062162151622ca4860575a33844ba10b' 'C:\vcpkg' -ErrorAction SilentlyContinue
& 'C:\vcpkg\bootstrap-vcpkg.bat' -disableMetrics
if ($LASTEXITCODE -ne 0) { Die "vcpkg bootstrap failed (exit $LASTEXITCODE)" }

# --- verified vcpkg offline inputs ------------------------------------------------------------
# Custom RustDesk overlay sources and libvpx's Windows helper tools come from the same hash-pinned
# online capture used by the other target builders. Keep ordinary vcpkg origin access available for
# baseline ports whose URL + SHA512 are owned by vcpkg, but make both custom codecs consume the exact
# local capture and pre-seed every libvpx acquisition helper into VCPKG_DOWNLOADS.
$src = (Get-PSDrive -PSProvider FileSystem |
        Where-Object { Test-Path (Join-Path $_.Root 'res\vcpkg') } | Select-Object -First 1).Root
if (-not $src) { Die 'PROVISION media not found (no drive has res\vcpkg); refusing an incomplete native warm' }
$ports = Join-Path $src 'res\vcpkg'
$distfilesMedia = Join-Path $tc 'vcpkg-distfiles'
if (-not (Test-Path -LiteralPath $distfilesMedia -PathType Container)) {
    Die 'toolchains media lacks the verified vcpkg-distfiles directory'
}
$distfiles = 'C:\vcpkg-distfiles'
$downloads = 'C:\vcpkg-build-downloads'
foreach ($directory in @($distfiles, $downloads)) {
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
    New-Item -ItemType Directory -Path $directory | Out-Null
}
$distfileSpecs = @(
    @('libvpx-v1.15.2.tar.gz', '824fe8719e4115ec359ae0642f5e1cea051d458f09eb8c24d60858cf082f66e411215e23228173ab154044bafbdfbb2d93b589bb726f55b233939b91f928aae0'),
    @('libvpx-d5f35ac8d93cba7f7a3f7ddb8f9dc8bd28f785e1.patch', '2980e0504e207047d55e6c98dcc55c2a3c06315b4ec04d59c42d786657e03ba0e1c73a0718ac6635990aac25fc642b204a1d56e13501ce2bd9625996ad0310d8'),
    @('libyuv-0faf8dd0e004520a61a603a4d2996d5ecc80dc3f.tar.gz', 'be6b343ab6c62e8f2d1571fedf25f5facbf7cd7fe8e1cc4949dab7549ad15f962c91ea43bf567785e54382d7689514f6b66d61bd56b3f38ba54ef51c5fd0da9b')
)
foreach ($spec in $distfileSpecs) {
    $name = $spec[0]
    $expectedHash = $spec[1]
    $source = Join-Path $distfilesMedia $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { Die "verified vcpkg distfile is missing: $name" }
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA512).Hash.ToLowerInvariant() -ne $expectedHash) {
        Die "verified vcpkg distfile SHA512 mismatch: $name"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $distfiles $name)
    Copy-Item -LiteralPath $source -Destination (Join-Path $downloads $name)
}
$nativeKeySource = Join-Path $distfilesMedia 'libvpx-native-key.txt'
if (-not (Test-Path -LiteralPath $nativeKeySource -PathType Leaf)) { Die 'libvpx native key is missing' }
$nativeKey = (Get-Content -LiteralPath $nativeKeySource -Raw).Trim()
if ($nativeKey -notmatch '^[0-9a-f]{64}$') { Die "libvpx native key is malformed: $nativeKey" }
Copy-Item -LiteralPath $nativeKeySource -Destination (Join-Path $distfiles 'libvpx-native-key.txt')

$toolManifest = Join-Path $ports 'libvpx\windows-tools.sha512'
$toolMedia = Join-Path $distfilesMedia 'windows-tools'
$toolEntries = Get-Content -LiteralPath $toolManifest | Where-Object { $_ -notmatch '^\s*$' }
if ($toolEntries.Count -ne 32) { Die "libvpx Windows tool manifest must contain exactly 32 entries, found $($toolEntries.Count)" }
foreach ($entry in $toolEntries) {
    $toolMatch = [regex]::Match($entry, '^([0-9a-f]{128})  ([A-Za-z0-9._~+-]+)$')
    if (-not $toolMatch.Success) { Die "malformed libvpx Windows tool manifest entry: $entry" }
    $toolHash = $toolMatch.Groups[1].Value
    $toolName = $toolMatch.Groups[2].Value
    $toolSource = Join-Path $toolMedia $toolName
    if (-not (Test-Path -LiteralPath $toolSource -PathType Leaf)) { Die "offline libvpx build tool missing: $toolName" }
    if ((Get-FileHash -LiteralPath $toolSource -Algorithm SHA512).Hash.ToLowerInvariant() -ne $toolHash) {
        Die "offline libvpx build tool SHA512 mismatch: $toolName"
    }
    $cacheName = $toolName
    if ($toolName -ceq 'mingw-w64-x86_64-pkgconf-1~2.4.3-1-any.pkg.tar.zst') {
        $cacheName = "msys2-$toolName"
    } elseif ($toolName -ceq '7zr.exe') {
        $cacheName = "$($toolHash.Substring(0, 8))-$toolName"
    }
    Copy-Item -LiteralPath $toolSource -Destination (Join-Path $downloads $cacheName)
}
$env:RUSTDESK_VCPKG_DISTFILES_DIR = $distfiles
$env:VCPKG_KEEP_ENV_VARS = 'RUSTDESK_VCPKG_DISTFILES_DIR'
$env:VCPKG_BINARY_SOURCES = 'clear'
$env:VCPKG_DOWNLOADS = $downloads
Log 'verified and staged the offline libvpx/libyuv acquisition closure'

# --- machine PATH + env (so build-windows.ps1's Preflight version asserts pass) ---------------
Log 'setting machine PATH + env'
$llvmBin = 'C:\Program Files\LLVM\bin'
$cargoBin = "$env:USERPROFILE\.cargo\bin"               # rust .msi also adds its own; belt + suspenders
$add = @('C:\flutter\bin', $llvmBin, 'C:\vcpkg', $cargoBin, 'C:\Program Files\Git\cmd')
$cur = [Environment]::GetEnvironmentVariable('Path','Machine')
[Environment]::SetEnvironmentVariable('Path', ($cur + ';' + ($add -join ';')), 'Machine')
[Environment]::SetEnvironmentVariable('LIBCLANG_PATH', $llvmBin, 'Machine')
[Environment]::SetEnvironmentVariable('VCPKG_ROOT', 'C:\vcpkg', 'Machine')

# --- vcpkg sec3.2 x64-windows natives -- warm them into the golden (the per-build is --network=none) ----
Log "building the vcpkg x64-windows-static natives (overlay-ports $ports) -- slow (~30-60min)"
# Start-Process -Wait -PassThru (native-stderr decoupling as the dart resolve above + the -Wait the
# reliable-ExitCode quirk demands): vcpkg writes progress/warnings to stderr; under autounattend's
# `*>&1 | Tee` + ErrorActionPreference=Stop a benign warning would be a fatal NativeCommandError. A CHILD
# process's stderr goes to the console, never this script's pipeline. Judge by ExitCode. A genuine hang is
# caught by the 130m provision wait.
$vp = Start-Process 'C:\vcpkg\vcpkg.exe' -ArgumentList 'install',"--overlay-ports=$ports",'--triplet','x64-windows-static','libvpx','libyuv','opus','libjpeg-turbo','cpu-features' -Wait -PassThru -NoNewWindow
if ($vp.ExitCode -ne 0) { Die "vcpkg install of the x64-windows natives failed (exit $($vp.ExitCode))" }
# WiX NuGet is intentionally per-build media, not golden-template state:
# scripts/build-windows.ps1 verifies the signed packages in
# OFFLINE\wix-nuget-packages and restores them into a fresh writable
# NUGET_PACKAGES directory.

# --- per-build harness: persistent auto-login + a logon task that runs the build CD's run-build.ps1 ----
# A per-build is a throwaway CoW clone of this golden + a BUILD CD (the repo's run-build.ps1) + an OUTPUT
# disk. On its boot the golden auto-logins and this task fires golden-logon.ps1, which -- ONLY when an OUTPUT
# disk is attached (so provisioning + ordinary boots no-op) -- runs run-build.ps1 off the CD. Keeping the
# build logic on the CD means it changes without re-provisioning; only this tiny launcher is baked in.
Log 'installing the per-build logon harness (persistent auto-login + build task)'
$builderAccount = Get-LocalUser -Name 'builder'
$builderAccount | Set-LocalUser -PasswordNeverExpires $true
$builderAccount = Get-LocalUser -Name 'builder'
if ($null -ne $builderAccount.PasswordExpires) {
    Die 'the dedicated builder password is still configured to expire'
}
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $winlogon 'AutoAdminLogon'  '1'
Set-ItemProperty $winlogon 'DefaultUserName' 'builder'
Set-ItemProperty $winlogon 'DefaultPassword' 'RustdeskBuild!1'
Remove-ItemProperty $winlogon 'AutoLogonCount' -ErrorAction SilentlyContinue   # persistent, not N-limited
@'
# golden-logon.ps1 -- runs at every logon; only acts for a per-build (an OUTPUT disk present).
$out = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.FileSystemLabel -eq "OUTPUT" }
if (-not $out) { exit 0 }
$rb = Get-PSDrive -PSProvider FileSystem | ForEach-Object { Join-Path $_.Root "run-build.ps1" } |
      Where-Object { Test-Path $_ } | Select-Object -First 1
if ($rb) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $rb }
'@ | Set-Content -Encoding ASCII 'C:\golden-logon.ps1'
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\golden-logon.ps1'
$trg = New-ScheduledTaskTrigger -AtLogOn -User 'builder'
Register-ScheduledTask -TaskName 'RustdeskPerBuild' -Action $act -Trigger $trg -RunLevel Highest `
    -User 'builder' -Password 'RustdeskBuild!1' -Force | Out-Null

@'
rustdesk-windows-golden-v2
builder-password-never-expires=true
setup-complete=true
'@ | Set-Content -Encoding ASCII 'C:\guest-setup-done.txt'
Log 'guest toolchain provisioning complete -- shutting down (this powered-off image IS the golden)'
# Shut down so provision-windows-vm.sh's `virt-install --wait` returns and the golden is the
# clean, provisioned baseline. A failed setup leaves NO marker + never shuts down -> the wait
# times out and C:\guest-setup-log.txt (teed by autounattend) shows where it stopped.
Stop-Computer -Force
