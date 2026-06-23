# scripts/run-build.ps1 -- the per-build job. Lives at the BUILD CD root; the golden's RustdeskPerBuild
# logon task (via C:\golden-logon.ps1) runs it when an OUTPUT disk is attached (i.e. only for a per-build,
# never during provisioning or a normal boot). Copies the committed repo off the BUILD CD into a writable
# C:\src, runs build-windows.ps1 (cargo + flutter + the portable installer), writes the artifacts to the
# OUTPUT disk the host reads, then shuts down so build-windows-vm.sh's wait returns. (R-B7/B9, sec12.2.)
$ErrorActionPreference = 'Continue'
$out = ((Get-Volume | Where-Object { $_.FileSystemLabel -eq 'OUTPUT' } | Select-Object -First 1).DriveLetter) + ':'
$cd  = (Get-PSDrive -PSProvider FileSystem | Where-Object { Test-Path (Join-Path $_.Root 'build.py') } | Select-Object -First 1).Root

# Flushed progress markers to the OUTPUT disk: each phase appends one line (Out-File flushes + closes), so even
# if the build stalls or the VM is force-destroyed the host can read run-build-progress.txt and see how far it
# got -- Start-Transcript (below) BUFFERS and loses its tail on a hard power-off, which made the first stall
# undiagnosable. $out is resolved before any marker so a wrong OUTPUT-letter is itself visible (out=:).
function Mark($m) { try { "$(Get-Date -Format o) $m" | Out-File -Append -Encoding ascii "$out\run-build-progress.txt" } catch { } }
Mark "RUN-BUILD START out=$out cd=$cd"

# Windows Defender real-time scanning throttles the big OFFLINE repo copy + the cargo-vendor reads (thousands
# of small crate files) to a crawl -- the build is fully offline from PINNED inputs, so there is nothing to
# scan for. Disable it + exclude the build dirs (best-effort; the logon task runs elevated, RunLevel Highest).
try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue } catch { }
try { Add-MpPreference -ExclusionPath C:\src, C:\cargo-home -ErrorAction SilentlyContinue } catch { }
Mark "defender-off"

try { Start-Transcript -Path "$out\build-log.txt" -Force | Out-Null } catch { }
try {
    Remove-Item -Recurse -Force C:\src -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force C:\src | Out-Null
    Copy-Item -Recurse "$($cd)*" C:\src
    # The BUILD CD is a read-only ISO; Copy-Item carries the read-only attribute onto every copied file, so the
    # build cannot rewrite tracked files -- `dart pub get` Dies "Cannot open file pubspec.lock (Access is
    # denied)" (after resolving fine), and cargo would hit Cargo.lock the same way. Clear read-only recursively.
    Get-ChildItem C:\src -Recurse -File -Force | Where-Object { $_.IsReadOnly } | ForEach-Object { $_.IsReadOnly = $false }
    Mark "copied-repo-to-C:\src (read-only cleared)"
    # R-B2 determinism: build-windows-vm.sh stamps the BUILD CD with SOURCE_DATE_EPOCH; build-windows.ps1
    # reads it so gen_version bakes a reproducible BUILD_DATE.
    if (Test-Path "$($cd).source_date_epoch") {
        $env:SOURCE_DATE_EPOCH = (Get-Content "$($cd).source_date_epoch" -Raw).Trim()
    }
    Set-Location C:\src
    Mark "running build-windows.ps1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\src\scripts\build-windows.ps1
    Mark "build-windows.ps1 exit=$LASTEXITCODE"
    if (Test-Path C:\src\dist) { Copy-Item C:\src\dist\* "$out\" -Force -ErrorAction SilentlyContinue }
    Mark "artifacts-copied"
} catch {
    "RUN-BUILD ERROR: $_" | Out-File -Append "$out\build-log.txt"
    Mark "ERROR $_"
} finally {
    try { Stop-Transcript | Out-Null } catch { }
    Mark "shutting-down"
    Stop-Computer -Force
}
