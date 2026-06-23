# scripts/run-build.ps1 -- the per-build job. Lives at the BUILD CD root; the golden's RustdeskPerBuild
# logon task (via C:\golden-logon.ps1) runs it when an OUTPUT disk is attached (i.e. only for a per-build,
# never during provisioning or a normal boot). Copies the committed repo off the BUILD CD into a writable
# C:\src, runs build-windows.ps1 (cargo + flutter + the portable installer), writes the artifacts to the
# OUTPUT disk the host reads, then shuts down so build-windows-vm.sh's wait returns. (R-B7/B9, sec12.2.)
$ErrorActionPreference = 'Continue'
$out = ((Get-Volume | Where-Object { $_.FileSystemLabel -eq 'OUTPUT' } | Select-Object -First 1).DriveLetter) + ':'
$cd  = (Get-PSDrive -PSProvider FileSystem | Where-Object { Test-Path (Join-Path $_.Root 'build.py') } | Select-Object -First 1).Root
try { Start-Transcript -Path "$out\build-log.txt" -Force | Out-Null } catch { }
try {
    Remove-Item -Recurse -Force C:\src -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force C:\src | Out-Null
    Copy-Item -Recurse "$($cd)*" C:\src
    # R-B2 determinism: build-windows-vm.sh stamps the BUILD CD with SOURCE_DATE_EPOCH; build-windows.ps1
    # reads it so gen_version bakes a reproducible BUILD_DATE.
    if (Test-Path "$($cd).source_date_epoch") {
        $env:SOURCE_DATE_EPOCH = (Get-Content "$($cd).source_date_epoch" -Raw).Trim()
    }
    Set-Location C:\src
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\src\scripts\build-windows.ps1
    if (Test-Path C:\src\dist) { Copy-Item C:\src\dist\* "$out\" -Force -ErrorAction SilentlyContinue }
} catch {
    "RUN-BUILD ERROR: $_" | Out-File -Append "$out\build-log.txt"
} finally {
    try { Stop-Transcript | Out-Null } catch { }
    Stop-Computer -Force
}
