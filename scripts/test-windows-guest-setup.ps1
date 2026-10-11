# Execute only inside a disposable no-NIC Windows guest. This runs the exact production
# process-completion function, without installing tools or executing the setup's top level.
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'the guest setup process fixture requires Windows'
}
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'win-guest-setup.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "guest setup parse failed: $parseErrors" }
$functions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-SetupProcess'
}, $false))
if ($functions.Count -ne 1) { throw 'expected exactly one production Invoke-SetupProcess' }
$launchers = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ieq 'Start-Process'
}, $true))
if ($launchers.Count -ne 1 -or
    $launchers[0].Extent.StartOffset -lt $functions[0].Extent.StartOffset -or
    $launchers[0].Extent.EndOffset -gt $functions[0].Extent.EndOffset) {
    throw 'native setup must use the sole checked Start-Process launcher'
}
. ([scriptblock]::Create($functions[0].Extent.Text))

$directory = Join-Path ([IO.Path]::GetTempPath()) ('setup-process-' + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $directory | Out-Null
try {
    foreach ($code in @(0, 7, 3010, 1641)) {
        $marker = Join-Path $directory "complete-$code.txt"
        $failed = $false
        try {
            Invoke-SetupProcess -FilePath 'C:\Windows\System32\cmd.exe' `
                -ArgumentList '/d','/c',"exit /b $code"
        } catch {
            if ($code -eq 0 -or $_.Exception.Message -notlike "*failed (exit $code)*") { throw }
            $failed = $true
        }
        if (-not $failed) { [IO.File]::WriteAllText($marker, 'complete') }
        if ($failed -ne ($code -ne 0) -or
            (Test-Path -LiteralPath $marker) -ne ($code -eq 0)) {
            throw "incorrect setup continuation for native exit $code"
        }
    }
    $marker = Join-Path $directory 'complete-missing.txt'
    $failed = $false
    try {
        Invoke-SetupProcess -FilePath (Join-Path $directory 'missing.exe') -ArgumentList '/test'
    } catch { $failed = $true }
    if (-not $failed) { [IO.File]::WriteAllText($marker, 'complete') }
    if (-not $failed -or (Test-Path -LiteralPath $marker)) {
        throw 'missing executable incorrectly allowed setup continuation'
    }
} finally {
    Remove-Item -LiteralPath $directory -Recurse -Force
}
Write-Host 'WINDOWS_SETUP_PROCESS=pass cases=5 scope=process-exit-status installers=unexecuted'
