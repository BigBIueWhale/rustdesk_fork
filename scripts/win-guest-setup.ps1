# scripts/win-guest-setup.ps1 -- provisions the sec12.2 Win11 build guest's toolchain (R-B8).
#
# Run ONCE inside the no-NIC guest at first logon (autounattend.xml FirstLogonCommands).
# Install the pinned toolchain from the toolchains CD attached by provision-windows-vm.sh;
# missing offline inputs fail provisioning. Per-build guests are disposable no-NIC overlays.
#
# Pinned set (pins.env): Rust 1.75 (MSVC), Flutter 3.24.5 (windows), LLVM 15.0.6 (windows),
# VS Build Tools (MSVC + Win SDK), vcpkg @120deac3, Git. The vcpkg x64-windows natives are
# warmed against res/vcpkg; the WiX v4 NuGet closure is staged on the per-build OFFLINE media
# by scripts/online-fetch.sh and consumed by scripts/build-windows.ps1.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Log($m) { Write-Host "[guest-setup] $m" }
function Die($m) { Write-Error "[guest-setup:FATAL] $m"; exit 1 }

function Invoke-SetupProcess {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$ArgumentList
    )
    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList `
        -Wait -PassThru -NoNewWindow -ErrorAction Stop
    try {
        if ($null -eq $process -or $null -eq $process.ExitCode -or $process.ExitCode -ne 0) {
            throw "[guest-setup:FATAL] $FilePath failed (exit $($process.ExitCode)); this single-pass setup accepts only exit zero"
        }
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

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
Invoke-SetupProcess -FilePath (Join-Path $win 'Git-2.45.2-64-bit.exe') `
    -ArgumentList '/VERYSILENT','/NORESTART','/SUPPRESSMSGBOXES','/SP-'

# --- Rust 1.75 (x86_64-pc-windows-msvc), offline .msi ----------------------------------------
Log 'installing Rust 1.75 (MSVC)'
Invoke-SetupProcess -FilePath 'C:\Windows\System32\msiexec.exe' `
    -ArgumentList '/i',(Join-Path $win 'rust-1.75.0-x86_64-pc-windows-msvc.msi'),'/quiet','/norestart'

# --- VS Build Tools (MSVC + Windows SDK) from the offline layout ------------------------------
Log 'installing VS Build Tools (MSVC + Windows SDK) from the offline layout'
$vsdir = 'C:\vslayout'
New-Item -ItemType Directory -Force -Path $vsdir | Out-Null
Invoke-SetupProcess -FilePath 'C:\Windows\System32\tar.exe' `
    -ArgumentList '-xf',(Join-Path $tc 'vs-buildtools.layout.tar'),'-C',$vsdir
$vsexe = @(Get-ChildItem -Path $vsdir -Recurse -File -Filter 'vs_buildtools.exe')
if ($vsexe.Count -ne 1) { Die 'the offline layout must contain exactly one vs_buildtools.exe' }
Invoke-SetupProcess -FilePath $vsexe[0].FullName -ArgumentList @(
    '--quiet','--wait','--norestart','--nocache','--noUpdateInstaller','--noWeb',
    '--add','Microsoft.VisualStudio.Workload.VCTools',
    '--add','Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
    '--add','Microsoft.VisualStudio.Component.Windows11SDK.22621',
    '--includeRecommended')

# --- LLVM/clang 15.0.6 (libclang for FRB/bindgen determinism) --------------------------------
Log 'installing LLVM 15.0.6'
Invoke-SetupProcess -FilePath (Join-Path $tc 'llvm-windows-15.0.6.exe') -ArgumentList '/S'

# --- Python 3.11.9 (build.py and PE/MSI canonicalizers) --------------------------------------
Log 'installing Python 3.11.9'
Invoke-SetupProcess -FilePath (Join-Path $tc 'python-windows-3.11.9.exe') `
    -ArgumentList '/quiet','InstallAllUsers=1','PrependPath=1','Include_test=0','Include_pip=1'
$pyExe = 'C:\Program Files\Python311\python.exe'
if (-not (Test-Path $pyExe)) { Die 'Python install did not land python.exe at C:\Program Files\Python311' }
# Canonicalization helpers use python3; Windows Python ships python.exe. Both aliases must
# resolve to the same pinned installation.
Copy-Item $pyExe (Join-Path (Split-Path $pyExe) 'python3.exe') -Force

# --- Flutter 3.24.5 (windows) ----------------------------------------------------------------
Log 'extracting Flutter 3.24.5 (windows) -> C:\flutter'
Expand-Archive -Force -Path (Join-Path $tc 'flutter-windows-3.24.5.zip') -DestinationPath 'C:\'

# Both provisioning and per-build guests have no NIC. Place the captured engine and complete
# flutter_tools package cache before resolving the lock and reconciling engine stamps offline.
Log 'preparing the offline Flutter windows engine and flutter_tools'
$env:CI = 'true'                               # suppress interactive first-run prompts
$env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
# git + flutter/dart MUST be on THIS process's PATH now: the persistent machine PATH is set later in
# this script, and a mid-script install does not retro-add to the running process. flutter precache
# also shells out to `git` against the SDK checkout, so git must resolve here.
$env:PATH = "C:\Program Files\Git\cmd;C:\flutter\bin;$env:PATH"
Invoke-SetupProcess -FilePath 'C:\Program Files\Git\cmd\git.exe' `
    -ArgumentList 'config','--global','--add','safe.directory','C:/flutter'
Log 'placing the offline-staged windows flutter engine, then reconciling via precache'
Invoke-SetupProcess -FilePath 'C:\Windows\System32\tar.exe' `
    -ArgumentList '-xf',(Join-Path $tc 'flutter-windows-engine.tar.gz'),'-C','C:\flutter'
if (-not (Test-Path 'C:\flutter\bin\cache\artifacts\engine\windows-x64')) { Die 'engine extraction failed -- windows-x64 absent after tar (gzip/CD issue)' }
# The SDK's bundled cache lacks flutter_tools development dependencies. The captured complete
# closure starts at hosted/ and hosted-hashes/ and lands in the builder's Pub cache.
Log 'pre-placing the staged flutter_tools pub cache (the DEV deps the SDK-bundled cache lacks)'
$pc = "$env:LOCALAPPDATA\Pub\Cache"
New-Item -ItemType Directory -Force -Path $pc | Out-Null
Invoke-SetupProcess -FilePath 'C:\Windows\System32\tar.exe' `
    -ArgumentList '-xf',(Join-Path $tc 'flutter-pub-cache.tar.gz'),'-C',$pc
if (-not (Test-Path (Join-Path $pc 'hosted\pub.dev\test-1.25.7'))) { Die 'flutter_tools pub cache extraction failed -- test-1.25.7 absent after tar; the offline resolve would fail "version solving failed"' }
Log "flutter_tools pub cache extracted to $pc"

# The exact 95-package projection deliberately excludes hosted\pub.dev\.cache. That metadata is
# time-varying and an old-but-present advisory response can make Pub apply its TTL and attempt a
# refresh even during an offline resolve. Absence is therefore part of the pinned archive contract,
# and the separate networkless semantic replay proves this exact package/hash closure resolves the
# flutter_tools lock without it. Reject ambient or reintroduced metadata instead of manufacturing
# freshness by changing timestamps inside the golden.
$metadataCache = Join-Path $pc 'hosted\pub.dev\.cache'
if (Test-Path -LiteralPath $metadataCache) { Die 'staged flutter_tools Pub cache unexpectedly contains hosted metadata; exact metadata-free projection required' }
Log 'verified the staged flutter_tools Pub cache is metadata-free'

Log 'resolving flutter_tools OFFLINE (0 pub.dev traffic: complete staged package closure, no hosted metadata cache)'
Invoke-SetupProcess -FilePath 'C:\flutter\bin\cache\dart-sdk\bin\dart.exe' `
    -ArgumentList 'pub','get','--offline','--enforce-lockfile','--directory','C:\flutter\packages\flutter_tools'
# config enables the windows desktop; precache reconciles the (already-present, offline-staged) engine.
Invoke-SetupProcess -FilePath 'C:\flutter\bin\flutter.bat' -ArgumentList 'config','--no-analytics','--enable-windows-desktop'
Invoke-SetupProcess -FilePath 'C:\flutter\bin\flutter.bat' -ArgumentList 'precache','--windows'

# --- vcpkg @120deac3 -------------------------------------------------------------------------
Log 'extracting + bootstrapping vcpkg @120deac3 -> C:\vcpkg'
Invoke-SetupProcess -FilePath 'C:\Windows\System32\tar.exe' `
    -ArgumentList '-xf',(Join-Path $tc 'vcpkg-120deac3062162151622ca4860575a33844ba10b.tar.gz'),'-C','C:\'
Rename-Item 'C:\vcpkg-120deac3062162151622ca4860575a33844ba10b' 'C:\vcpkg'
Invoke-SetupProcess -FilePath 'C:\vcpkg\bootstrap-vcpkg.bat' -ArgumentList '-disableMetrics'

# --- verified vcpkg offline inputs ------------------------------------------------------------
# Custom RustDesk overlay sources and libvpx's Windows helper tools come from the same hash-pinned
# online capture used by the other target builders. All ports must resolve from staged downloads
# in the no-NIC guest; both custom codecs consume the exact local capture and every libvpx
# acquisition helper is pre-seeded into VCPKG_DOWNLOADS.
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
Invoke-SetupProcess -FilePath 'C:\vcpkg\vcpkg.exe' -ArgumentList 'install',"--overlay-ports=$ports",'--triplet','x64-windows-static','libvpx','libyuv','opus','libjpeg-turbo','cpu-features'
# WiX NuGet is intentionally per-build media, not golden-template state:
# scripts/build-windows.ps1 verifies the signed packages in
# OFFLINE\wix-nuget-packages and restores them into a fresh writable
# NUGET_PACKAGES directory.

# --- per-build harness: persistent auto-login + an interactive logon task that runs run-build.ps1 ----
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
$principal = New-ScheduledTaskPrincipal -UserId 'builder' -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName 'RustdeskPerBuild' -Action $act -Trigger $trg `
    -Principal $principal -Force | Out-Null
$registeredTask = Get-ScheduledTask -TaskName 'RustdeskPerBuild'
if ($registeredTask.Principal.LogonType -cne 'Interactive' -or
    $registeredTask.Principal.UserId -notmatch '(^|\\)builder$' -or
    $registeredTask.Principal.RunLevel -cne 'Highest') {
    Die 'the per-build task is not bound to the interactive builder logon at its declared run level'
}

$receipt = "rustdesk-windows-golden-v4`r`nbuilder-password-never-expires=true`r`nbuilder-logon-task=interactive`r`nsetup-complete=true`r`n"
[IO.File]::WriteAllBytes('C:\guest-setup-done.txt', [Text.Encoding]::ASCII.GetBytes($receipt))
Log 'guest toolchain provisioning complete -- shutting down (this powered-off image IS the golden)'
# Shut down so provision-windows-vm.sh's `virt-install --wait` returns and the golden is the
# clean, provisioned baseline. A failed setup leaves NO marker + never shuts down -> the wait
# times out and C:\guest-setup-log.txt (teed by autounattend) shows where it stopped.
Stop-Computer -Force
