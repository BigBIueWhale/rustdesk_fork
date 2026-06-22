# scripts/win/cargo-check.ps1 -- type-check the rustdesk crate for the Windows
# target INSIDE the spec-12.2 guest. This is a CORRECTNESS gate, not a release build.
#
# ASCII-ONLY (see winenv.ps1 for why).
#
# Why it exists: the Linux verify.sh compiles only cfg(not(windows)) code. A whole
# class of fork edits -- the R-X8/R-X9/R-X4 cfg(windows) excisions, plus every
# audio / IPC / clipboard / input path under #[cfg(windows)] -- is invisible to it.
# This closes that blind spot the only way Windows can be type-checked: on Windows.
# (It already caught 5 real regressions the import-excision refactors introduced.)
#
# Usage in the guest:
#   powershell -ExecutionPolicy Bypass -File scripts\win\cargo-check.ps1 [-Features flutter]
#
#   -Features flutter : the SHIPPED Windows config (spec 3.2). Needs the FRB bridge
#                       (src/bridge_generated.rs) staged first -- build-windows.ps1
#                       / flutter_rust_bridge_codegen generates it.
#   -Features inline  : the sciter config. NOT shipped on Windows; its `inline`
#                       module is generated only for the sciter UI and will be
#                       absent here -- used only to exercise the non-UI cfg(windows)
#                       code without the FRB bridge.
param(
    [string]$Features = 'flutter',
    [string]$Src = 'C:\src',
    [string]$LogDir = 'C:\tools'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'winenv.ps1')

Set-Location $Src
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$log = Join-Path $LogDir 'cargo-check.log'

Write-Host "[cargo-check] cargo check --target x86_64-pc-windows-msvc --features $Features"
cargo check --target x86_64-pc-windows-msvc --features $Features 2>&1 | Tee-Object -FilePath $log
$rc = $LASTEXITCODE
"CARGO_CHECK_RC=$rc" | Set-Content (Join-Path $LogDir 'cargo-check.rc')

if ($rc -ne 0) {
    Write-Host "[cargo-check] FAILED (rc=$rc)"
    Write-Host "[cargo-check] error sites:"
    Select-String -Path $log -Pattern 'error\[' -Context 0,1 | ForEach-Object {
        $_.Line; if ($_.Context.PostContext) { '  ' + $_.Context.PostContext[0] }
    }
    exit $rc
}
Write-Host "[cargo-check] OK -- cfg(windows) type-checks clean for --features $Features"
