# scripts/win-guest-setup.ps1 -- provisions the sec12.2 Win11 build guest's toolchain (R-B8).
#
# Run ONCE inside the guest at first logon (autounattend.xml FirstLogonCommands) while the VM
# still has network (the golden-template build is the one networked guest step -- like the
# android stage_gradle). It installs EXACTLY the pinned toolchain from the toolchains CD that
# provision-windows-vm.sh attaches (the ./online windows artifacts), then the per-build VM is a
# throwaway CoW overlay run --network=none (build-windows.ps1).
#
# Pinned set (pins.env): Rust 1.75 (MSVC), Flutter 3.24.5 (windows), LLVM 15.0.6 (windows),
# VS Build Tools (MSVC + Win SDK), vcpkg @120deac3, Git. WiX v4 + the vcpkg x64-windows natives
# are NuGet/vcpkg sets warmed against the repo (res/msi, res/vcpkg) -- see the TODO at the end.
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
# Bound each flutter step (Start-Process + WaitForExit) so a stalled first-run/CDN fetch fails LOUD +
# fast, never the silent 90-min poll timeout the unbounded `&` calls caused. precache pulls ~780MB of
# windows engine over the golden's slirp NAT (the same NAT that warmed the vcpkg natives), so give it a
# generous window.
$cfg = Start-Process 'C:\flutter\bin\flutter.bat' -ArgumentList 'config','--no-analytics','--enable-windows-desktop' -PassThru -NoNewWindow
if (-not $cfg.WaitForExit(300000)) { try { $cfg.Kill() } catch {}; Die 'flutter config timed out (>5min)' }
$pc = Start-Process 'C:\flutter\bin\flutter.bat' -ArgumentList 'precache','--windows' -PassThru -NoNewWindow
if (-not $pc.WaitForExit(1500000)) { try { $pc.Kill() } catch {}; Die 'flutter precache --windows timed out (>25min)' }
if ($pc.ExitCode -ne 0) { Die "flutter precache --windows failed (exit $($pc.ExitCode))" }

# --- vcpkg @120deac3 -------------------------------------------------------------------------
Log 'extracting + bootstrapping vcpkg @120deac3 -> C:\vcpkg'
tar -xf (Join-Path $tc 'vcpkg-120deac3062162151622ca4860575a33844ba10b.tar.gz') -C 'C:\'
Rename-Item 'C:\vcpkg-120deac3062162151622ca4860575a33844ba10b' 'C:\vcpkg' -ErrorAction SilentlyContinue
& 'C:\vcpkg\bootstrap-vcpkg.bat' -disableMetrics

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
# Find the SRC CD (the committed repo that provision-windows-vm.sh mounts) for the overlay ports.
$src = (Get-PSDrive -PSProvider FileSystem |
        Where-Object { Test-Path (Join-Path $_.Root 'res\vcpkg') } | Select-Object -First 1).Root
if ($src) {
    $ports = Join-Path $src 'res\vcpkg'
    Log "building the vcpkg x64-windows-static natives (overlay-ports $ports) -- slow (~30-60min)"
    & 'C:\vcpkg\vcpkg.exe' install --overlay-ports="$ports" --triplet x64-windows-static `
        aom libvpx libyuv opus libjpeg-turbo cpu-features
    if ($LASTEXITCODE -ne 0) { Die "vcpkg install of the x64-windows natives failed (exit $LASTEXITCODE)" }
} else {
    Log 'WARN: no SRC CD (res\vcpkg) found -- skipped the vcpkg-native warm; the offline build cannot link codecs'
}
# TODO (milestone 2, the .msi): warm the WiX v4 NuGet set -- needs .NET (add the VS .NET workload) +
# `dotnet restore res/msi/Package/Package.wixproj` into the global NuGet cache for the offline build.

# --- per-build harness: persistent auto-login + a logon task that runs the build CD's run-build.ps1 ----
# A per-build is a throwaway CoW clone of this golden + a BUILD CD (the repo's run-build.ps1) + an OUTPUT
# disk. On its boot the golden auto-logins and this task fires golden-logon.ps1, which -- ONLY when an OUTPUT
# disk is attached (so provisioning + ordinary boots no-op) -- runs run-build.ps1 off the CD. Keeping the
# build logic on the CD means it changes without re-provisioning; only this tiny launcher is baked in.
Log 'installing the per-build logon harness (persistent auto-login + build task)'
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

New-Item -ItemType File -Force -Path 'C:\guest-setup-done.txt' | Out-Null
Log 'guest toolchain provisioning complete -- shutting down (this powered-off image IS the golden)'
# Shut down so provision-windows-vm.sh's `virt-install --wait` returns and the golden is the
# clean, provisioned baseline. A failed setup leaves NO marker + never shuts down -> the wait
# times out and C:\guest-setup-log.txt (teed by autounattend) shows where it stopped.
Stop-Computer -Force
