# scripts/build-windows.ps1 -- Windows x86_64 .exe/.msi build (R-B7/B9, sec12.2).
#
# Runs INSIDE the ephemeral KVM Windows 11 guest (provisioned by
# provision-windows-vm.sh) -- Windows cannot be cross-built from Linux (MSVC + WiX
# are Windows-only). Reproduces upstream 1.4.7's official Windows build (R-B7:
# python build.py --flutter; hwcodec/vram dropped -- CPU-only software codec,
# R-R2b) with these deltas:
# the artifacts ship UNSIGNED (the pinned SHA-256 is the integrity anchor, R-B2),
# and the build runs off GitHub-hosted runners. The guest has no network during the
# build; all inputs were staged offline by provision-windows-vm.sh.
#
# One mode, the good one (R-B9): assert the EXACT pinned versions, then abort; fail
# loud; no fallbacks. NOT run as part of "fork creation".
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Pins (the Windows subset of scripts/pins.env, kept in sync) -------------
$RUST_VERSION    = '1.75'
$FLUTTER_VERSION = '3.24.5'
$LLVM_VERSION    = '15.0.6'
$LLVM_RC_EXE     = 'C:\Program Files\LLVM\bin\llvm-rc.exe'
$LLVM_READOBJ_EXE = 'C:\Program Files\LLVM\bin\llvm-readobj.exe'
$LLVM_RC_SHA256  = 'f1c4e01ae6214be7e1326e6290ee96b3cd7d36e690f400a16b5e33ad3aa36f29'
$PYTHON_VERSION  = '3.11.9'
$PYTHON_EXE      = 'C:\Program Files\Python311\python.exe'
$OLEFILE_SHA256  = '543c7da2a7adadf21214938bb79c83ea12b473a4b6ee4ad4bf854e7715e13d1f'
$WIX_VERSION     = '4'      # WixToolset v4 (res/msi targets schemas/v4)
$SRC = $env:RUSTDESK_SOURCE_ROOT
$script:OFFLINE = $null
$VCPKG_BASELINE = '120deac3062162151622ca4860575a33844ba10b'
$LIBVPX_SOURCE_REF = 'v1.15.2'
$LIBVPX_SOURCE_SHA512 = '824fe8719e4115ec359ae0642f5e1cea051d458f09eb8c24d60858cf082f66e411215e23228173ab154044bafbdfbb2d93b589bb726f55b233939b91f928aae0'
$LIBVPX_FIX_COMMIT = 'd5f35ac8d93cba7f7a3f7ddb8f9dc8bd28f785e1'
$LIBVPX_PATCH_SHA512 = '2980e0504e207047d55e6c98dcc55c2a3c06315b4ec04d59c42d786657e03ba0e1c73a0718ac6635990aac25fc642b204a1d56e13501ce2bd9625996ad0310d8'

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

function Get-OrdinaryPathItem([string]$Path, [bool]$RequireLeaf) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -cne $Path) { Die "path is not canonical: $Path" }
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrEmpty($root)) { Die "path has no volume root: $Path" }
    $current = $root
    foreach ($component in @($full.Substring($root.Length) -split '\\' | Where-Object { $_.Length -gt 0 })) {
        $current = Join-Path $current $component
        if (-not (Test-Path -LiteralPath $current)) { Die "path component is absent: $current" }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Die "path traverses a reparse point: $current"
        }
    }
    $result = Get-Item -LiteralPath $full -Force
    if ($RequireLeaf -and $result.PSIsContainer) { Die "path is not a file: $Path" }
    if (-not $RequireLeaf -and -not $result.PSIsContainer) { Die "path is not a directory: $Path" }
    return $result
}

function Get-JsonInt64([object]$Value, [string]$Description) {
    if ($null -eq $Value -or -not ($Value -is [int] -or $Value -is [long])) {
        throw "$Description is not a JSON integer"
    }
    return [Int64]$Value
}

function Assert-PowerShellSourceParsing {
    foreach ($relative in @('scripts\run-build.ps1', 'scripts\build-windows.ps1')) {
        $path = Join-Path $SRC $relative
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        if ($null -eq $ast -or $errors.Count -ne 0) {
            $messages = @($errors | ForEach-Object { $_.Message }) -join '; '
            Die "PowerShell 5.1 source parse failed for ${relative}: $messages"
        }
    }
}

function Read-MsiRows($Database, [string]$Sql, [string[]]$Kinds) {
    $view = $null
    $viewClosed = $false
    $rows = New-Object 'System.Collections.Generic.List[object]'
    try {
        $view = $Database.GetType().InvokeMember(
            'OpenView',
            [System.Reflection.BindingFlags]::InvokeMethod,
            $null,
            $Database,
            @($Sql)
        )
        [void]$view.GetType().InvokeMember(
            'Execute',
            [System.Reflection.BindingFlags]::InvokeMethod,
            $null,
            $view,
            @()
        )
        while ($true) {
            $record = $view.GetType().InvokeMember(
                'Fetch',
                [System.Reflection.BindingFlags]::InvokeMethod,
                $null,
                $view,
                @()
            )
            if ($null -eq $record) { break }
            try {
                $values = [object[]]::new($Kinds.Count)
                for ($index = 0; $index -lt $Kinds.Count; $index++) {
                    $kind = $Kinds[$index]
                    $member = if ($kind -ceq 'integer') { 'IntegerData' } elseif ($kind -ceq 'string') { 'StringData' } else { throw "unknown MSI field kind: $kind" }
                    $value = $record.GetType().InvokeMember(
                        $member,
                        [System.Reflection.BindingFlags]::GetProperty,
                        $null,
                        $record,
                        @($index + 1)
                    )
                    if ($kind -ceq 'integer') {
                        if ($null -eq $value -or -not ($value -is [int] -or $value -is [long]) -or
                            [Int64]$value -eq [Int32]::MinValue) {
                            throw "MSI query returned a null or non-integral value at field $($index + 1)"
                        }
                    } elseif ($value -isnot [string]) {
                        throw "MSI query returned a non-string value at field $($index + 1)"
                    }
                    $values[$index] = $value
                }
                [void]$rows.Add([PSCustomObject]@{ Values = $values })
            } finally {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
            }
        }
        [void]$view.GetType().InvokeMember(
            'Close',
            [System.Reflection.BindingFlags]::InvokeMethod,
            $null,
            $view,
            @()
        )
        $viewClosed = $true
    } finally {
        if ($null -ne $view) {
            if (-not $viewClosed) {
                try {
                    [void]$view.GetType().InvokeMember('Close', [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, @())
                } catch {
                    [Console]::Error.WriteLine("MSI VIEW CLEANUP FAILURE: $($_.Exception.Message)")
                }
            }
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        }
    }
    return $rows.ToArray()
}

function Get-MsiStreamSha256($Database, [string]$Name, [Int64]$ExpectedSize) {
    if ($Name -cnotmatch '^[A-Za-z_][A-Za-z0-9_.]{0,61}$' -or $ExpectedSize -le 0) {
        Die 'MSI embedded cabinet stream name or expected size is invalid'
    }
    $view = $null
    $record = $null
    $sha = [Security.Cryptography.SHA256]::Create()
    $viewClosed = $false
    try {
        $sql = "SELECT ``Data`` FROM ``_Streams`` WHERE ``Name`` = '$Name'"
        $view = $Database.GetType().InvokeMember(
            'OpenView',
            [System.Reflection.BindingFlags]::InvokeMethod,
            $null,
            $Database,
            @($sql)
        )
        [void]$view.GetType().InvokeMember('Execute', [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, @())
        $record = $view.GetType().InvokeMember('Fetch', [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, @())
        if ($null -eq $record) { Die "MSI embedded cabinet stream is absent: $Name" }
        $sizeValue = $record.GetType().InvokeMember(
            'DataSize',
            [System.Reflection.BindingFlags]::GetProperty,
            $null,
            $record,
            @(1)
        )
        if ($null -eq $sizeValue -or -not ($sizeValue -is [int] -or $sizeValue -is [long])) {
            throw 'MSI embedded cabinet stream size is not an integer'
        }
        $size = [Int64]$sizeValue
        if ($size -ne $ExpectedSize) { Die "MSI embedded cabinet stream size is $size, expected $ExpectedSize" }
        $encoding = [Text.Encoding]::GetEncoding(
            28591,
            [Text.EncoderFallback]::ExceptionFallback,
            [Text.DecoderFallback]::ExceptionFallback
        )
        $remaining = $size
        while ($remaining -gt 0) {
            $count = [Math]::Min([Int64](1024 * 1024), $remaining)
            $chunk = $record.GetType().InvokeMember(
                'ReadStream',
                [System.Reflection.BindingFlags]::InvokeMethod,
                $null,
                $record,
                @(1, [int]$count, 1)
            )
            if ($chunk -isnot [string]) { throw 'MSI embedded cabinet stream returned a non-string chunk' }
            $bytes = $encoding.GetBytes($chunk)
            if ($bytes.Length -le 0 -or $bytes.Length -gt $remaining) {
                Die 'MSI embedded cabinet stream returned an invalid chunk length'
            }
            [void]$sha.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)
            $remaining -= $bytes.Length
        }
        $extra = $record.GetType().InvokeMember(
            'ReadStream',
            [System.Reflection.BindingFlags]::InvokeMethod,
            $null,
            $record,
            @(1, 1, 1)
        )
        if ($null -ne $extra) {
            if ($extra -isnot [string]) { throw 'MSI embedded cabinet stream returned an invalid EOF result' }
            if ($extra.Length -ne 0) { Die 'MSI embedded cabinet stream exceeds its declared size' }
        }
        $second = $view.GetType().InvokeMember('Fetch', [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, @())
        if ($null -ne $second) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($second)
            Die "MSI embedded cabinet stream is duplicated: $Name"
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
        $digest = (($sha.Hash | ForEach-Object { $_.ToString('x2') }) -join '')
        [void]$view.GetType().InvokeMember('Close', [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, @())
        $viewClosed = $true
        return $digest
    } finally {
        if ($null -ne $record) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
        if ($null -ne $view) {
            if (-not $viewClosed) {
                try {
                    [void]$view.GetType().InvokeMember('Close', [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, @())
                } catch {
                    [Console]::Error.WriteLine("MSI VIEW CLEANUP FAILURE: $($_.Exception.Message)")
                }
            }
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        }
        $sha.Dispose()
    }
}

function Assert-PythonToolchain {
    if (-not (Test-Path -LiteralPath $PYTHON_EXE -PathType Leaf)) {
        Die "pinned Python executable is absent: $PYTHON_EXE"
    }
    $pythonItem = Get-OrdinaryPathItem $PYTHON_EXE $true
    $pythonDirectory = Split-Path -Parent $PYTHON_EXE
    $python3 = Join-Path $pythonDirectory 'python3.exe'
    if (-not (Test-Path -LiteralPath $python3 -PathType Leaf)) { Die 'pinned Python python3.exe companion is absent' }
    $python3Item = Get-OrdinaryPathItem $python3 $true
    if ((Get-FileHash -LiteralPath $pythonItem.FullName -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $python3Item.FullName -Algorithm SHA256).Hash) {
        Die 'pinned Python executables are not byte-identical'
    }
    $env:PATH = "$pythonDirectory;$env:PATH"
    foreach ($commandName in @('python.exe', 'python3.exe')) {
        $command = Get-Command $commandName -CommandType Application -ErrorAction Stop | Select-Object -First 1
        $expected = if ($commandName -ceq 'python.exe') { $PYTHON_EXE } else { $python3 }
        if ($command.Source -cne $expected) {
            Die "$commandName resolved to $($command.Source), expected $expected"
        }
    }
    foreach ($executable in @($PYTHON_EXE, $python3)) {
        $reported = ((& $executable --version 2>&1) | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $reported -cne "Python $PYTHON_VERSION") {
            Die "Python version mismatch for ${executable}: expected Python $PYTHON_VERSION, got '$reported'"
        }
    }
    & $PYTHON_EXE -I -c "import brotli, os; p=os.path.normcase(os.path.abspath(brotli.__file__)); root=os.path.normcase(os.path.abspath(r'C:\Program Files\Python311\Lib\site-packages'))+os.sep; assert p.startswith(root), p"
    if ($LASTEXITCODE -ne 0) {
        Die "Python brotli module is absent from the pinned Python installation ($LASTEXITCODE)"
    }
}

function Assert-BuildIdentity {
    $requiredEnvironment = @(
        'RUSTDESK_SOURCE_ROOT',
        'RUSTDESK_SOURCE_COMMIT',
        'RUSTDESK_SOURCE_TREE',
        'RUSTDESK_SOURCE_MANIFEST_SHA256',
        'RUSTDESK_OFFLINE_MANIFEST_SHA256',
        'RUSTDESK_FORK_VERSION',
        'RUSTDESK_BUILD_RUN_ID',
        'RUSTDESK_TARGET',
        'SOURCE_DATE_EPOCH'
    )
    foreach ($name in $requiredEnvironment) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrEmpty($value)) {
            Die "required build identity environment variable is absent: $name"
        }
        if ($value.IndexOfAny([char[]]@(0, 10, 13)) -ge 0) {
            Die "build identity environment variable contains a control character: $name"
        }
    }
    if ($env:RUSTDESK_SOURCE_COMMIT -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
        Die 'RUSTDESK_SOURCE_COMMIT is not canonical'
    }
    if ($env:RUSTDESK_SOURCE_TREE -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
        Die 'RUSTDESK_SOURCE_TREE is not canonical'
    }
    foreach ($name in @('RUSTDESK_SOURCE_MANIFEST_SHA256', 'RUSTDESK_OFFLINE_MANIFEST_SHA256')) {
        if ([Environment]::GetEnvironmentVariable($name) -cnotmatch '^[0-9a-f]{64}$') {
            Die "$name is not canonical"
        }
    }
    if ($env:RUSTDESK_FORK_VERSION -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+-hardened\.[0-9]+$') {
        Die 'RUSTDESK_FORK_VERSION is not canonical'
    }
    if ($env:RUSTDESK_BUILD_RUN_ID -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[AB]$') {
        Die 'RUSTDESK_BUILD_RUN_ID is not canonical'
    }
    if ($env:RUSTDESK_TARGET -cne 'windows-x86_64') {
        Die 'RUSTDESK_TARGET is not windows-x86_64'
    }
    if ($env:SOURCE_DATE_EPOCH -cnotmatch '^[0-9]+$') {
        Die 'SOURCE_DATE_EPOCH is not canonical'
    }

    if (-not (Test-Path -LiteralPath $SRC -PathType Container)) {
        Die "source root is not a directory: $SRC"
    }
    [void](Get-OrdinaryPathItem $SRC $false)

    $identityPath = Join-Path $SRC '.source-identity.json'
    $manifestPath = Join-Path $SRC '.source-manifest.json'
    foreach ($required in @($identityPath, $manifestPath, (Join-Path $SRC '.source-date-epoch'), (Join-Path $SRC '.build-run-id'))) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            Die "required source identity file is absent: $required"
        }
        [void](Get-OrdinaryPathItem $required $true)
    }
    $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
    $expectedFields = @(
        'base_manifest_sha256',
        'build_run_id',
        'fork_version',
        'format',
        'frb_manifest_sha256',
        'offline_manifest_sha256',
        'source_commit',
        'source_date_epoch',
        'source_manifest_sha256',
        'source_mode',
        'source_tree',
        'target'
    ) | Sort-Object
    $actualFields = @($identity.PSObject.Properties.Name | Sort-Object)
    if (($actualFields -join ',') -cne ($expectedFields -join ',') -or
        $identity.format -isnot [string] -or
        $identity.format -cne 'rustdesk-windows-source-identity-v1') {
        Die 'source identity schema is not exact'
    }
    foreach ($name in $expectedFields) {
        if ($identity.$name -isnot [string]) {
            Die "source identity field is not a JSON string: $name"
        }
    }
    $comparisons = @{
        source_commit = $env:RUSTDESK_SOURCE_COMMIT
        source_tree = $env:RUSTDESK_SOURCE_TREE
        source_manifest_sha256 = $env:RUSTDESK_SOURCE_MANIFEST_SHA256
        offline_manifest_sha256 = $env:RUSTDESK_OFFLINE_MANIFEST_SHA256
        fork_version = $env:RUSTDESK_FORK_VERSION
        build_run_id = $env:RUSTDESK_BUILD_RUN_ID
        target = $env:RUSTDESK_TARGET
        source_date_epoch = $env:SOURCE_DATE_EPOCH
    }
    foreach ($name in $comparisons.Keys) {
        if ($identity.$name -cne $comparisons[$name]) {
            Die "source identity does not match environment: $name"
        }
    }
    if ($identity.source_mode -cnotin @('head', 'worktree')) {
        Die 'source identity mode is invalid'
    }
    foreach ($name in @('base_manifest_sha256', 'frb_manifest_sha256')) {
        if ($identity.$name -cnotmatch '^[0-9a-f]{64}$') {
            Die "source identity hash is malformed: $name"
        }
    }
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($manifestHash -cne $env:RUSTDESK_SOURCE_MANIFEST_SHA256) {
        Die 'source manifest hash changed after guest verification'
    }
    if ((Get-Content -LiteralPath (Join-Path $SRC '.source-date-epoch') -Raw) -cne "$($env:SOURCE_DATE_EPOCH)$([char]10)") {
        Die 'source-date-epoch stamp is not exact'
    }
    if ((Get-Content -LiteralPath (Join-Path $SRC '.build-run-id') -Raw) -cne "$($env:RUSTDESK_BUILD_RUN_ID)$([char]10)") {
        Die 'build-run-id stamp is not exact'
    }
    if ((Get-Content -LiteralPath (Join-Path $SRC 'FORK_VERSION') -Raw) -cne "$($env:RUSTDESK_FORK_VERSION)$([char]10)") {
        Die 'FORK_VERSION does not exactly match the source identity'
    }

    $offlineDrives = @(
        Get-PSDrive -PSProvider FileSystem |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.Root '.offline-input-manifest.json') -PathType Leaf }
    )
    if ($offlineDrives.Count -ne 1) {
        Die "OFFLINE media count is $($offlineDrives.Count), expected exactly one"
    }
    $script:OFFLINE = $offlineDrives[0].Root
    $offlineManifest = Join-Path $script:OFFLINE '.offline-input-manifest.json'
    $offlineHash = (Get-FileHash -LiteralPath $offlineManifest -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($offlineHash -cne $env:RUSTDESK_OFFLINE_MANIFEST_SHA256) {
        Die 'OFFLINE media manifest does not match source identity'
    }
    Write-Host "[harness] source identity OK: commit=$($env:RUSTDESK_SOURCE_COMMIT) tree=$($env:RUSTDESK_SOURCE_TREE)"
}

function Assert-DeterministicWindowsResource {
    $cargo = Get-Content -LiteralPath (Join-Path $SRC 'Cargo.toml') -Raw
    $buildRs = Get-Content -LiteralPath (Join-Path $SRC 'build.rs') -Raw
    $portableCargo = Get-Content -LiteralPath (Join-Path $SRC 'libs\portable\Cargo.toml') -Raw
    $portableBuild = Get-Content -LiteralPath (Join-Path $SRC 'libs\portable\build.rs') -Raw
    $producer = Get-Content -LiteralPath (Join-Path $SRC 'res\windows_resource.rs') -Raw
    foreach ($manifest in @($cargo, $portableCargo)) {
        if ($manifest -match '(?m)^\[package[.]metadata[.]winres\]$' -or
            $manifest -match '(?m)^winres\s*=') {
            Die 'Windows resource metadata would be emitted through nondeterministic winres HashMap iteration'
        }
    }
    foreach ($source in @($buildRs, $portableBuild, $producer)) {
        if ($source.Contains('winres::WindowsResource') -or
            $source.Contains('.set_icon(') -or
            $source.Contains('.set_manifest_file(') -or
            $source.Contains('.set_resource_file(')) {
            Die 'Windows resource build returned to a winres-generated or Microsoft-RC path'
        }
    }
    if (-not $buildRs.Contains('windows_resource::compile(version, &resource_root)') -or
        -not $portableBuild.Contains('windows_resource::compile(env!("CARGO_PKG_VERSION"), resource_root)')) {
        Die 'root and portable crates do not share the ordered Windows resource producer'
    }
    if ([regex]::Matches($producer, [regex]::Escape('.parse::<u16>()?;')).Count -ne 3) {
        Die 'Windows resource version must have exactly three bounded numeric components'
    }
    foreach ($required in @(
        'env::var_os("RUSTDESK_LLVM_RC")',
        'Command::new(&llvm_rc)',
        '.arg("-no-preprocess")',
        '.arg("-C65001")',
        'println!("cargo:rustc-link-lib=dylib=resource")',
        'LLVM resource compiler changed its ordered RC input'
    )) {
        if (-not $producer.Contains($required)) { Die "Windows resource producer lacks: $required" }
    }
    $ordered = @(
        'VALUE "FileDescription", "RustDesk Remote Desktop"',
        'VALUE "FileVersion", "{version}"',
        'VALUE "LegalCopyright", "Copyright © 2025 Purslane Ltd. All rights reserved."',
        'VALUE "OriginalFilename", "rustdesk.exe"',
        'VALUE "ProductName", "RustDesk"',
        'VALUE "ProductVersion", "{version}"',
        'VALUE "Translation", 0x0409, 0x04b0',
        '1 ICON "res/icon.ico"',
        '1 24 "res/manifest.xml"'
    )
    $position = -1
    foreach ($required in $ordered) {
        $position = $producer.IndexOf($required, $position + 1, [StringComparison]::Ordinal)
        if ($position -lt 0) {
            Die "Windows resource entry is absent or out of canonical order: $required"
        }
    }
}

function Find-ByteSequence([byte[]]$Bytes, [byte[]]$Needle, [int]$Start) {
    if ($Needle.Length -eq 0 -or $Start -lt 0) { return -1 }
    for ($offset = $Start; $offset -le $Bytes.Length - $Needle.Length; $offset++) {
        $matches = $true
        for ($index = 0; $index -lt $Needle.Length; $index++) {
            if ($Bytes[$offset + $index] -ne $Needle[$index]) {
                $matches = $false
                break
            }
        }
        if ($matches) { return $offset }
    }
    return -1
}

function Get-SingleCompiledWindowsResource([string]$PackageName) {
    $buildRoot = Join-Path $SRC 'target\release\build'
    $candidates = @(
        Get-ChildItem -LiteralPath $buildRoot -Directory | Where-Object { $_.Name -clike "${PackageName}-*" } |
            ForEach-Object { Join-Path $_.FullName 'out\resource.lib' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    )
    if ($candidates.Count -ne 1) {
        Die "compiled Windows resource count for $PackageName is $($candidates.Count), expected exactly one"
    }
    [void](Get-OrdinaryPathItem $candidates[0] $true)
    return $candidates[0]
}

function Assert-CompiledWindowsResource([string]$Path, [string]$Description) {
    $item = Get-OrdinaryPathItem $Path $true
    if ($item.Length -le 32 -or $item.Length -gt 1048576) {
        Die "$Description compiled resource size is outside the bounded contract: $($item.Length)"
    }
    $bytes = [IO.File]::ReadAllBytes($Path)
    $previous = -1
    foreach ($key in @('FileDescription', 'FileVersion', 'LegalCopyright', 'OriginalFilename', 'ProductName', 'ProductVersion')) {
        $needle = [Text.Encoding]::Unicode.GetBytes($key + [char]0)
        $position = Find-ByteSequence $bytes $needle 0
        if ($position -le $previous) { Die "$Description compiled VERSIONINFO key is absent or out of order: $key" }
        if ((Find-ByteSequence $bytes $needle ($position + 2)) -ne -1) {
            Die "$Description compiled VERSIONINFO key is duplicated: $key"
        }
        $previous = $position
    }
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $readobj = (& $LLVM_READOBJ_EXE $Path 2>&1 | Out-String)
        $readobjExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($readobjExit -ne 0) { Die "$Description compiled resource is rejected by llvm-readobj (exit $readobjExit)" }
    foreach ($marker in @(
        'Resource type (int): VERSIONINFO (ID 16)',
        'Resource type (int): ICON (ID 3)',
        'Resource type (int): GROUP_ICON (ID 14)',
        'Resource type (int): MANIFEST (ID 24)'
    )) {
        if (-not $readobj.Contains($marker)) { Die "$Description compiled resource lacks: $marker" }
    }
    if ([regex]::Matches($readobj, 'Resource type \(int\): VERSIONINFO \(ID 16\)').Count -ne 1 -or
        [regex]::Matches($readobj, 'Resource type \(int\): GROUP_ICON \(ID 14\)').Count -ne 1 -or
        [regex]::Matches($readobj, 'Resource type \(int\): MANIFEST \(ID 24\)').Count -ne 1) {
        Die "$Description compiled resource has a non-canonical singleton resource count"
    }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "[harness] $Description compiled resource OK: sha256=$hash"
}

function Get-CargoPackageVersion([string]$ManifestPath) {
    $contents = Get-Content -LiteralPath $ManifestPath -Raw
    $matches = [regex]::Matches($contents, '(?m)^version = "([0-9]+[.][0-9]+[.][0-9]+)"$')
    if ($matches.Count -ne 1) { Die "Cargo package version count is $($matches.Count), expected one: $ManifestPath" }
    return $matches[0].Groups[1].Value
}

function Assert-WindowsExecutableVersionInfo([string]$Path, [string]$Version, [string]$Description) {
    $versionInfo = (Get-OrdinaryPathItem $Path $true).VersionInfo
    $expected = [ordered]@{
        FileDescription = 'RustDesk Remote Desktop'
        FileVersion = $Version
        LegalCopyright = "Copyright $([char]0x00A9) 2025 Purslane Ltd. All rights reserved."
        OriginalFilename = 'rustdesk.exe'
        ProductName = 'RustDesk'
        ProductVersion = $Version
    }
    foreach ($entry in $expected.GetEnumerator()) {
        $actual = [string]$versionInfo.PSObject.Properties[$entry.Key].Value
        if ($actual -cne [string]$entry.Value) {
            Die "$Description VERSIONINFO mismatch for $($entry.Key): $actual"
        }
    }
}

function Assert-MachineCredentialDesign {
    $config = Get-Content -LiteralPath (Join-Path $SRC 'libs\hbb_common\src\config.rs') -Raw
    $platform = Get-Content -LiteralPath (Join-Path $SRC 'src\platform\windows.rs') -Raw
    $ipc = Get-Content -LiteralPath (Join-Path $SRC 'src\ipc.rs') -Raw
    $auth = Get-Content -LiteralPath (Join-Path $SRC 'src\ipc\auth.rs') -Raw
    $password = Get-Content -LiteralPath (Join-Path $SRC 'src\ipc\password.rs') -Raw
    $core = Get-Content -LiteralPath (Join-Path $SRC 'src\core_main.rs') -Raw
    $folders = Get-Content -LiteralPath (Join-Path $SRC 'res\msi\Package\Components\Folders.wxs') -Raw
    $package = Get-Content -LiteralPath (Join-Path $SRC 'res\msi\Package\Package.wxs') -Raw

    foreach ($required in @('NtCreateFile', 'RootDirectory = parent', 'FILE_OPEN_REPARSE_POINT', 'NtSetInformationFile', 'NtFlushBuffersFile', 'GetVolumeInformationByHandleW', 'FlushFileBuffers', 'verify_machine_root_handle', 'windows_machine_config::store')) {
        if (-not $config.Contains($required)) { Die "machine credential root gate missing Config primitive: $required" }
    }
    if ($config -match '(?i)ServiceProfiles|LocalService|systemprofile') {
        Die 'machine credential root must not depend on a Windows service profile'
    }
    foreach ($required in @('FOLDERID_ProgramData', 'SERVICE_OWNED_SERVER_ARG', 'initialize_windows_service_owned_root')) {
        if (-not $platform.Contains($required)) { Die "machine credential root gate missing Windows role/root binding: $required" }
    }
    foreach ($required in @('SensitivePassword', 'begin_password_mutation', 'windows_credential_client_decision', 'windows_credential_queue_uncertainty_status', 'windows_credential_lost_reply_stop_and_apply_remain_consistent', 'windows_credential_operation_bound_failures_remain_terminal_during_recovery')) {
        if (-not $ipc.Contains($required)) { Die "machine credential secret-lifetime gate missing: $required" }
    }
    foreach ($required in @('REQUEST_HEADER_BYTES: usize = 36', 'STATUS_FRAME_BYTES: usize = 32', 'ACK_FRAME_BYTES: usize = 28', 'FixedSensitiveBody', 'try_reserve_exact', 'zeroize_sensitive_bytes', 'SensitiveStackBytes', 'encode_ack', 'decode_ack')) {
        if (-not $password.Contains($required)) { Die "raw password protocol gate missing: $required" }
    }
    $passwordTests = $password.IndexOf("`n#[cfg(test)]`nmod tests {")
    if ($passwordTests -lt 0) { Die 'raw password protocol test boundary is missing' }
    $passwordProduction = $password.Substring(0, $passwordTests)
    foreach ($forbidden in @('BytesCodec', 'Framed<', 'serde_json', 'Serialize for SensitivePassword', 'Deserialize for SensitivePassword')) {
        if ($passwordProduction.Contains($forbidden)) { Die "raw password protocol depends on forbidden generic framing/serialization: $forbidden" }
    }
    foreach ($required in @('classify_during_shutdown', 'windows_credential_queue_uncertainty_status', 'FILE_FLAG_FIRST_PIPE_INSTANCE', 'PIPE_REJECT_REMOTE_CLIENTS', 'WINDOWS_SENSITIVE_PIPE_MAX_INSTANCES: u32 = 1', 'preauthorize_windows_sensitive_pipe_client', 'windows_sensitive_pipe_kernel_sddl', 'pipe.ensure_kernel_dacl_retained().and_then', 'GetSecurityInfo', 'ipc::password::decode_ack', 'windows-sensitive-ipc-client-supervisor', 'Ok(worker) => match worker.join()')) {
        if (-not $platform.Contains($required)) { Die "machine credential finality gate missing: $required" }
    }
    if ($platform -notmatch 'GENERIC_READ\.0\s*\|\s*FILE_WRITE_DATA\.0\s*\|\s*FILE_WRITE_ATTRIBUTES\.0') {
        Die 'Windows sensitive pipe client lacks the exact message-mode access rights'
    }
    foreach ($required in @('PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE', 'stable_active_session_principal', 'windows_sensitive_pipe_security_at_deadline', 'preauthorize_windows_sensitive_pipe_client')) {
        if (-not $auth.Contains($required)) { Die "Windows sensitive peer proof gate missing: $required" }
    }
    $handlerStart = $platform.IndexOf('fn handle_windows_sensitive_password_pipe')
    $handlerEnd = $platform.IndexOf('pub(crate) fn start_windows_sensitive_password_listener', $handlerStart)
    if ($handlerStart -lt 0 -or $handlerEnd -le $handlerStart) { Die 'Windows sensitive password handler boundary is missing' }
    $handler = $platform.Substring($handlerStart, $handlerEnd - $handlerStart)
    $handlerOrder = @(
        'ipc::preauthorize_windows_sensitive_pipe_client(',
        'pipe.read_message(&mut header_bytes.0',
        'ipc::authorize_windows_sensitive_pipe_client(',
        'pipe.read_message(request.body_mut()',
        'proof.revalidate(pipe.handle.0, deadline)',
        'requests.try_send(request)',
        'pipe.write_message(&response.0',
        'ipc::password::decode_ack'
    ) | ForEach-Object { $handler.IndexOf($_) }
    if ($handlerOrder -contains -1) { Die 'Windows sensitive password handler is missing an authority/wire stage' }
    for ($i = 1; $i -lt $handlerOrder.Count; $i++) {
        if ($handlerOrder[$i - 1] -ge $handlerOrder[$i]) { Die 'Windows sensitive password authority/wire stages are out of order' }
    }
    $proofStart = $auth.IndexOf('impl WindowsSensitivePipeClientProof')
    $proofEnd = $auth.IndexOf('pub(crate) fn preauthorize_windows_sensitive_pipe_client', $proofStart)
    if ($proofStart -lt 0 -or $proofEnd -le $proofStart) { Die 'Windows final client proof boundary is missing' }
    $proof = $auth.Substring($proofStart, $proofEnd - $proofStart)
    $proofOrder = @('self.process.fresh_identity()', 'self.process.live_token_proof()', 'windows_named_pipe_client_token_proof', 'windows_sensitive_pipe_security_at_deadline') | ForEach-Object { $proof.IndexOf($_) }
    if ($proofOrder -contains -1) { Die 'Windows final client proof is missing a required live sample' }
    for ($i = 1; $i -lt $proofOrder.Count; $i++) {
        if ($proofOrder[$i - 1] -ge $proofOrder[$i]) { Die 'Windows final client proof samples are out of order' }
    }
    foreach ($required in @('SensitivePassword::new', 'SensitivePasswordInput', 'zeroize_sensitive_bytes', 'confirmation.zeroize()', 'set_permanent_password_sensitive')) {
        if (-not $core.Contains($required)) { Die "password CLI secret-lifetime gate missing: $required" }
    }
    foreach ($required in @('App.MachineConfigFolder', 'O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')) {
        if (-not $folders.Contains($required)) { Die "MSI machine credential root gate missing: $required" }
    }
    if (-not $package.Contains('<ComponentRef Id="App.MachineConfigFolder" />')) {
        Die 'MSI machine credential root component is not installed by the product feature'
    }
    if (-not $package.Contains('InstallerVersion="500"')) {
        Die 'MSI machine credential root requires Windows Installer 5.0 MsiLockPermissionsEx support'
    }
    Write-Host '[harness] machine credential root/secret source gates OK'
}

function Get-LibvpxNativeKey($root) {
    $overlayRoot = (Get-Item -LiteralPath (Join-Path $root 'res\vcpkg\libvpx')).FullName
    $lines = @(
        "VCPKG_BASELINE=$VCPKG_BASELINE",
        "LIBVPX_SOURCE_REF=$LIBVPX_SOURCE_REF",
        "SHA512_LIBVPX_SOURCE=$LIBVPX_SOURCE_SHA512",
        "LIBVPX_FIX_COMMIT=$LIBVPX_FIX_COMMIT",
        "SHA512_LIBVPX_PATCH=$LIBVPX_PATCH_SHA512"
    )
    $files = Get-ChildItem -LiteralPath $overlayRoot -Recurse -File | ForEach-Object {
        [PSCustomObject]@{
            FullName = $_.FullName
            Relative = ('res/vcpkg/libvpx/' + $_.FullName.Substring($overlayRoot.Length + 1).Replace('\','/'))
        }
    } | Sort-Object -Property Relative -CaseSensitive
    foreach ($file in $files) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines += "$hash  $($file.Relative)"
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function Preflight {
    Assert-BuildIdentity
    Assert-PowerShellSourceParsing
    Assert-DeterministicWindowsResource
    if (Test-Path (Join-Path $SRC '.gitmodules')) { Die "hbb_common must be absorbed in-tree, not a submodule (R-R1)" }
    Assert-Version $RUST_VERSION    (rustc --version)              'rustc'
    Assert-Version $RUST_VERSION    (cargo --version)              'cargo'
    Assert-Version $FLUTTER_VERSION (flutter --version)            'flutter'
    Assert-Version $LLVM_VERSION    (clang --version)              'clang/LLVM'
    if (Test-Path Env:RUSTDESK_LLVM_RC) {
        if ($env:RUSTDESK_LLVM_RC -cne $LLVM_RC_EXE) { Die 'inherited RUSTDESK_LLVM_RC is not the pinned path' }
    }
    $llvmRc = Get-OrdinaryPathItem $LLVM_RC_EXE $true
    $llvmReadobj = Get-OrdinaryPathItem $LLVM_READOBJ_EXE $true
    if ($llvmRc.VersionInfo.ProductVersion -cne $LLVM_VERSION -or
        $llvmRc.VersionInfo.FileVersion -cne $LLVM_VERSION -or
        $llvmReadobj.VersionInfo.ProductVersion -cne $LLVM_VERSION -or
        $llvmReadobj.VersionInfo.FileVersion -cne $LLVM_VERSION) {
        Die 'LLVM resource tools do not carry the pinned 15.0.6 file/product version'
    }
    $llvmRcHash = (Get-FileHash -LiteralPath $LLVM_RC_EXE -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($llvmRcHash -cne $LLVM_RC_SHA256) { Die "llvm-rc digest mismatch: $llvmRcHash" }
    $env:RUSTDESK_LLVM_RC = $LLVM_RC_EXE
    Assert-PythonToolchain
    Assert-MachineCredentialDesign
    # WiX, MSVC and vcpkg are provisioned by provision-windows-vm.sh to the pins.
    Write-Host "[harness] preflight OK -- Windows x64, offline, features flutter -- software codec (sec3.2)"
}

function Build {
    Set-Location $SRC
    $msiDist = Join-Path $SRC 'flutter\build\windows\x64\runner\Release'
    $msiBuiltOut = Join-Path $SRC 'res\msi\Package\bin\x64\Release\en-us\Package.msi'
    $canonicalMsiDir = Join-Path $SRC 'target\canonical-msi'
    $msiCanonicalizerInput = Join-Path $canonicalMsiDir 'canonicalizer-input.msi'
    $msiOut = Join-Path $canonicalMsiDir 'rustdesk.msi'
    $msiContract = Join-Path $canonicalMsiDir 'cabinet-contract.json'
    $rustLibrary = Join-Path $SRC 'target\release\librustdesk.dll'
    $setupOut = Join-Path $SRC 'target\release\rustdesk-portable-packer.exe'
    $setupPayloadDir = Join-Path $SRC 'target\rustdesk-setup-payload'
    $setupPayloadMsi = Join-Path $setupPayloadDir 'rustdesk-installer.msi'
    $legacyStagedMsi = Join-Path $msiDist 'rustdesk-installer.msi'
    $artifactDir = Join-Path $SRC 'dist'
    $staleFiles = @(
        $msiBuiltOut,
        $msiOut,
        $msiContract,
        $setupOut,
        $legacyStagedMsi,
        (Join-Path $artifactDir 'rustdesk-setup.exe'),
        (Join-Path $artifactDir 'rustdesk-setup.exe.sha256'),
        (Join-Path $artifactDir 'rustdesk.msi'),
        (Join-Path $artifactDir 'rustdesk.msi.sha256')
    )
    foreach ($path in $staleFiles) {
        if (Test-Path -LiteralPath $path) {
            [void](Get-OrdinaryPathItem $path $true)
            Remove-Item -LiteralPath $path -Force
        }
    }
    if (Test-Path -LiteralPath $canonicalMsiDir) {
        $canonicalItem = Get-OrdinaryPathItem $canonicalMsiDir $false
        if (@(Get-ChildItem -LiteralPath $canonicalMsiDir -Force).Count -ne 0) {
            Die "canonical MSI output directory is not an empty ordinary directory: $canonicalMsiDir"
        }
        Remove-Item -LiteralPath $canonicalMsiDir -Force
    }
    if (Test-Path -LiteralPath $setupPayloadDir) {
        [void](Get-OrdinaryPathItem $setupPayloadDir $false)
        Remove-Item -LiteralPath $setupPayloadDir -Recurse -Force
    }
    # R-B2 PE determinism: /Brepro makes the MSVC linker stamp a CONTENT-HASH into the PE TimeDateStamp instead
    # of the wall-clock build time. Inject it via the LINK env var, which EVERY link.exe invocation in the build
    # honors -- rustc's link (librustdesk.dll + rustdesk-portable-packer.exe), the flutter runner (rustdesk.exe),
    # and the plugin DLLs. Without it those PE timestamps drift every build, and since the portable packer
    # brotli-compresses the flutter build dir INTO the final .exe, the deltas amplify across ~97% of it (proved:
    # build#1 4a7dbe4d vs build#2 7e08ce99, identical source). SOURCE_DATE_EPOCH only fixes the build.rs
    # BUILD_DATE string, not PE headers -- both are needed for R-B2.
    $env:LINK = '/Brepro'
    Write-Host "[harness] R-B2: LINK=/Brepro (reproducible PE TimeDateStamp across rustc + flutter MSVC links)"

    # --- locate the OFFLINE UDF media (cargo-vendor + its source map + pub-cache), attached by
    # build-windows-vm.sh; drive letters are dynamic, so detect by content. -----------------------
    $offline = $script:OFFLINE
    if ([string]::IsNullOrEmpty($offline)) { Die 'OFFLINE media identity was not established during preflight' }
    Write-Host "[harness] offline caches on $offline (cargo-vendor + pub-cache)"

    $vpxMedia = Join-Path $offline 'vcpkg-distfiles'
    $vpxSource = Join-Path $vpxMedia "libvpx-$LIBVPX_SOURCE_REF.tar.gz"
    $vpxPatch = Join-Path $vpxMedia "libvpx-$LIBVPX_FIX_COMMIT.patch"
    $vpxKeyFile = Join-Path $vpxMedia 'libvpx-native-key.txt'
    foreach ($required in @($vpxSource, $vpxPatch, $vpxKeyFile)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { Die "offline libvpx input missing: $required" }
    }
    if ((Get-FileHash -LiteralPath $vpxSource -Algorithm SHA512).Hash.ToLowerInvariant() -ne $LIBVPX_SOURCE_SHA512) { Die 'offline libvpx source SHA512 mismatch' }
    if ((Get-FileHash -LiteralPath $vpxPatch -Algorithm SHA512).Hash.ToLowerInvariant() -ne $LIBVPX_PATCH_SHA512) { Die 'offline libvpx security patch SHA512 mismatch' }
    $expectedVpxKey = (Get-Content -LiteralPath $vpxKeyFile -Raw).Trim()
    if ($expectedVpxKey -notmatch '^[0-9a-f]{64}$') { Die "offline libvpx native key is malformed: $expectedVpxKey" }
    $actualVpxKey = Get-LibvpxNativeKey $SRC
    if ($actualVpxKey -ne $expectedVpxKey) { Die "libvpx overlay/source key mismatch: media=$expectedVpxKey source=$actualVpxKey" }

    $vpxDistfiles = 'C:\vcpkg-distfiles'
    if (Test-Path -LiteralPath $vpxDistfiles) { Remove-Item -LiteralPath $vpxDistfiles -Recurse -Force }
    New-Item -ItemType Directory -Path $vpxDistfiles | Out-Null
    Copy-Item -LiteralPath $vpxSource -Destination $vpxDistfiles
    Copy-Item -LiteralPath $vpxPatch -Destination $vpxDistfiles
    $env:RUSTDESK_VCPKG_DISTFILES_DIR = $vpxDistfiles
    $env:VCPKG_KEEP_ENV_VARS = 'RUSTDESK_VCPKG_DISTFILES_DIR'
    $env:VCPKG_BINARY_SOURCES = 'clear'
    $env:X_VCPKG_ASSET_SOURCES = 'clear;x-block-origin'
    $env:VCPKG_DOWNLOADS = 'C:\vcpkg-build-downloads'
    if (Test-Path -LiteralPath $env:VCPKG_DOWNLOADS) { Remove-Item -LiteralPath $env:VCPKG_DOWNLOADS -Recurse -Force }
    New-Item -ItemType Directory -Path $env:VCPKG_DOWNLOADS | Out-Null
    Copy-Item -LiteralPath $vpxSource -Destination (Join-Path $env:VCPKG_DOWNLOADS (Split-Path -Leaf $vpxSource))
    Copy-Item -LiteralPath $vpxPatch -Destination (Join-Path $env:VCPKG_DOWNLOADS (Split-Path -Leaf $vpxPatch))
    $vpxToolManifest = Join-Path $SRC 'res\vcpkg\libvpx\windows-tools.sha512'
    $vpxToolMedia = Join-Path $vpxMedia 'windows-tools'
    $toolEntries = Get-Content -LiteralPath $vpxToolManifest | Where-Object { $_ -notmatch '^\s*$' }
    if ($toolEntries.Count -ne 32) { Die "libvpx Windows tool manifest must contain exactly 32 entries, found $($toolEntries.Count)" }
    foreach ($entry in $toolEntries) {
        $toolMatch = [regex]::Match($entry, '^([0-9a-f]{128})  ([A-Za-z0-9._~+-]+)$')
        if (-not $toolMatch.Success) { Die "malformed libvpx Windows tool manifest entry: $entry" }
        $toolHash = $toolMatch.Groups[1].Value
        $toolName = $toolMatch.Groups[2].Value
        $toolSource = Join-Path $vpxToolMedia $toolName
        if (-not (Test-Path -LiteralPath $toolSource -PathType Leaf)) { Die "offline libvpx build tool missing: $toolName" }
        if ((Get-FileHash -LiteralPath $toolSource -Algorithm SHA512).Hash.ToLowerInvariant() -ne $toolHash) { Die "offline libvpx build tool SHA512 mismatch: $toolName" }
        $cacheName = $toolName
        if ($toolName -ceq 'mingw-w64-x86_64-pkgconf-1~2.4.3-1-any.pkg.tar.zst') {
            $cacheName = "msys2-$toolName"
        } elseif ($toolName -ceq '7zr.exe') {
            $cacheName = "$($toolHash.Substring(0, 8))-$toolName"
        }
        Copy-Item -LiteralPath $toolSource -Destination (Join-Path $env:VCPKG_DOWNLOADS $cacheName)
    }
    Write-Host '[harness] libvpx offline acquisition closure verified: 25 MSYS2 runtime packages + MinGW pkgconf + pinned NASM/CMake/Ninja/7-Zip/PowerShell Core tools'

    $vpxInstalledKey = 'C:\vcpkg\installed\x64-windows-static\.rustdesk-libvpx-native-key'
    $vpxLib = 'C:\vcpkg\installed\x64-windows-static\lib\vpx.lib'
    $vpxAbi = 'C:\vcpkg\installed\x64-windows-static\share\libvpx\vcpkg_abi_info.txt'
    Write-Host "[harness] rebuilding libvpx 1.15.2#1 from verified offline source + $LIBVPX_FIX_COMMIT"
    & 'C:\vcpkg\vcpkg.exe' remove --recurse 'libvpx:x64-windows-static' --classic
    if ($LASTEXITCODE -ne 0) { Die "vcpkg remove stale libvpx failed ($LASTEXITCODE)" }
    foreach ($stale in @(
        'C:\vcpkg\buildtrees\libvpx',
        'C:\vcpkg\packages\libvpx_x64-windows-static',
        'C:\vcpkg\installed\x64-windows-static\include\vpx',
        'C:\vcpkg\installed\x64-windows-static\lib\vpx.lib',
        'C:\vcpkg\installed\x64-windows-static\debug\lib\vpx.lib',
        'C:\vcpkg\installed\x64-windows-static\share\libvpx',
        'C:\vcpkg\installed\x64-windows-static\share\unofficial-libvpx',
        $vpxInstalledKey
    )) {
        if (Test-Path -LiteralPath $stale) {
            Remove-Item -LiteralPath $stale -Recurse -Force
        }
    }
    if ((Test-Path -LiteralPath $vpxLib -PathType Leaf) -or
        (Test-Path -LiteralPath $vpxAbi -PathType Leaf)) {
        Die 'stale compiled libvpx bytes remain after mandatory removal'
    }
    & 'C:\vcpkg\vcpkg.exe' install "--overlay-ports=$SRC\res\vcpkg" --triplet x64-windows-static libvpx --classic
    if ($LASTEXITCODE -ne 0) { Die "offline vcpkg libvpx rebuild failed ($LASTEXITCODE)" }
    if (-not (Test-Path -LiteralPath $vpxLib -PathType Leaf) -or
        -not (Test-Path -LiteralPath $vpxAbi -PathType Leaf)) {
        Die 'vcpkg reported success without a rebuilt libvpx library and ABI metadata'
    }
    Set-Content -LiteralPath $vpxInstalledKey -Value $expectedVpxKey -Encoding ASCII -NoNewline
    if ((Get-Content -LiteralPath $vpxInstalledKey -Raw).Trim() -ne $expectedVpxKey) { Die 'installed libvpx native key does not match the verified overlay/source key' }

    $olefileWheel = Join-Path $offline 'python-wheels\olefile-0.47-py2.py3-none-any.whl'
    if (-not (Test-Path -LiteralPath $olefileWheel -PathType Leaf)) { Die "offline olefile wheel missing: $olefileWheel" }
    $olefileItem = Get-OrdinaryPathItem $olefileWheel $true
    if ($olefileItem.Length -le 0) { Die 'offline olefile wheel is empty' }
    $olefileDigest = (Get-FileHash -LiteralPath $olefileWheel -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($olefileDigest -cne $OLEFILE_SHA256) {
        Die "offline olefile wheel SHA-256 mismatch: $olefileDigest"
    }
    $olefileProbe = @'
import os, sys, zipimport
wheel = os.path.normcase(os.path.abspath(sys.argv[1]))
sys.path.insert(0, wheel)
import olefile
loader = olefile.__loader__
if not isinstance(loader, zipimport.zipimporter):
    raise SystemExit('olefile did not load through the verified wheel')
if os.path.normcase(os.path.abspath(loader.archive)) != wheel:
    raise SystemExit('olefile loader archive is not the verified wheel')
if olefile.__version__ != '0.47':
    raise SystemExit('olefile version is not 0.47')
'@
    & $PYTHON_EXE -I -S -c $olefileProbe $olefileWheel
    if ($LASTEXITCODE -ne 0) { Die "verified olefile wheel import failed ($LASTEXITCODE)" }
    $isolatedOlefileRunner = @'
import os, runpy, sys, zipimport
wheel = os.path.normcase(os.path.abspath(sys.argv[1]))
script = sys.argv[2]
arguments = sys.argv[3:]
expected_options = ['--output', '--contract-out', '--fork-version', '--source-commit', '--source-tree', '--target']
if os.path.normcase(os.path.normpath(script)) != os.path.normcase(os.path.normpath(r'scripts\canonicalize-msi.py')):
    raise SystemExit('MSI canonicalizer script argument is not exact')
if len(arguments) != 13 or arguments[1::2] != expected_options or any(not argument for argument in arguments):
    raise SystemExit('MSI canonicalizer argument vector is not exact')
sys.path.insert(0, wheel)
import olefile
loader = olefile.__loader__
if not isinstance(loader, zipimport.zipimporter) or os.path.normcase(os.path.abspath(loader.archive)) != wheel:
    raise SystemExit('olefile authority escaped the verified wheel')
if olefile.__version__ != '0.47':
    raise SystemExit('olefile version is not 0.47')
sys.argv = [script] + arguments
runpy.run_path(script, run_name='__main__')
'@

    # --- cargo: a build-time CARGO_HOME wired to the vendored crate set (R-B10). DON'T touch the
    # repo's TRACKED .cargo/config.toml (it carries the windows rustflags); cargo MERGES this over it.
    # The AUTHORITATIVE [source.*] map is cargo-vendor-config.toml (crates-io + every rustdesk git
    # dep); rewrite its `directory =` to the vendor drive + prepend [net] offline -- like build-debian.
    $env:CARGO_HOME = 'C:\cargo-home'
    New-Item -ItemType Directory -Force -Path $env:CARGO_HOME | Out-Null
    # R-B2 (drive-letter determinism): the OFFLINE CD's drive letter is NON-DETERMINISTIC across builds
    # (build A enumerated it as E:, build B as F: -- Windows orders the attached SCSI/SATA media in a
    # varying sequence). cargo bakes the vendored-crate SOURCE PATHS into the PEs it compiles (panic
    # strings, #[track_caller] locations, debug info) -- and the .cargo/config.toml rustflags note above
    # confirms librustdesk.dll is exactly that cargo PE. So a drive-letter shift changes path bytes in
    # that DLL, which the portable packer brotli-amplifies into rustdesk-setup.exe AND WiX CAB-packs
    # into the .msi -> both differ build-to-build.
    # Copy the vendor to a FIXED path on C: (always the system drive) and point cargo there, so the
    # embedded source paths are byte-identical every build regardless of the CD's drive letter.
    $vendorDir = 'C:/cargo-vendor'
    if (Test-Path 'C:\cargo-vendor') { Remove-Item -Recurse -Force 'C:\cargo-vendor' }
    Write-Host "[harness] copying cargo-vendor from $offline to C:\cargo-vendor (R-B2: drive-letter-stable embedded paths)"
    Copy-Item -Recurse -Force (Join-Path $offline 'cargo-vendor') 'C:\cargo-vendor'
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
    $pubLock = Join-Path $SRC 'flutter\pubspec.lock'
    $pubLockBefore = (Get-FileHash -Algorithm SHA256 $pubLock).Hash
    Push-Location (Join-Path $SRC 'flutter')
    & dart pub get --offline
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "dart pub get --offline (project) failed ($LASTEXITCODE) -- pub-cache may lack a windows-only package" }
    & flutter pub get --offline
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "flutter pub get --offline (plugin injection) failed ($LASTEXITCODE) -- generated_plugins.cmake will be absent; the flutter wrapper may have reached pub.dev for advisories" }
    Pop-Location
    $pubLockAfter = (Get-FileHash -Algorithm SHA256 $pubLock).Hash
    if ($pubLockBefore -ne $pubLockAfter) { Die "flutter\pubspec.lock changed during offline pub resolution; regenerate/commit it under the pinned Flutter SDK" }

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

    # R-B10: arm the offline-build network canary (build.rs). The per-build VM is --network=none, so the
    # canary's probe connect fails (no-op) and the build proceeds; if the VM ever had network during a
    # build, the canary panics rather than risk a leaked compile-time fetch breaking R-B2 reproducibility.
    $env:RUSTDESK_CANARY_OFFLINE = '1'

    # Authoritative native-Windows runtime gate for the terminal-focused Rust library suite. Use the
    # same pinned cargo, offline vendor map, lockfile, and flutter feature set as the artifact build;
    # the broad terminal_ filter includes both terminal_helper and terminal_service tests.
    Write-Host "[harness] testing terminal Rust library suite -- Windows x64, cargo $RUST_VERSION, offline/locked, features flutter"
    cargo test --offline --locked --lib --features flutter --color never terminal_
    if ($LASTEXITCODE -ne 0) { Die "terminal Rust library suite failed (exit $LASTEXITCODE) -- Windows runtime tests must pass before build.py --flutter" }

    Write-Host "[harness] testing Windows service supervision Rust library suite -- Windows x64, cargo $RUST_VERSION, offline/locked, features flutter"
    cargo test --offline --locked --lib --features flutter --color never windows_service_
    if ($LASTEXITCODE -ne 0) { Die "Windows service supervision Rust library suite failed (exit $LASTEXITCODE) -- Windows runtime tests must pass before build.py --flutter" }

    cargo test --offline --locked --lib --features flutter --color never windows_credential_
    if ($LASTEXITCODE -ne 0) { Die "Windows credential state-machine suite failed (exit $LASTEXITCODE) -- Windows runtime tests must pass before build.py --flutter" }
    cargo test --offline --locked --lib --features flutter --color never windows_replica_
    if ($LASTEXITCODE -ne 0) { Die "Windows credential replica suite failed (exit $LASTEXITCODE) -- Windows runtime tests must pass before build.py --flutter" }
    cargo test --offline --locked -p hbb_common --lib --color never windows_service_owned_root
    if ($LASTEXITCODE -ne 0) { Die "Windows machine credential root suite failed (exit $LASTEXITCODE) -- Windows Config APIs must pass before build.py --flutter" }

    Write-Host "[harness] testing Windows SAS Rust library suite -- Windows x64, cargo $RUST_VERSION, offline/locked, features flutter"
    cargo test --offline --locked --lib --features flutter --color never windows_sas_
    if ($LASTEXITCODE -ne 0) { Die "Windows SAS Rust library suite failed (exit $LASTEXITCODE) -- Windows runtime tests must pass before build.py --flutter" }

    Write-Host "[harness] testing password finality and desktop input lifecycle -- Windows x64, cargo $RUST_VERSION, offline/locked, features flutter"
    cargo test --offline --locked --lib --features flutter --color never password_mutation
    if ($LASTEXITCODE -ne 0) { Die "Password mutation finality suite failed (exit $LASTEXITCODE) -- Windows runtime tests must pass before build.py --flutter" }
    cargo test --offline --locked --lib --features flutter --color never desktop_input_queue_tests
    if ($LASTEXITCODE -ne 0) { Die "Desktop input lifecycle suite failed (exit $LASTEXITCODE) -- Windows runtime tests must pass before build.py --flutter" }

    # --- the sec3.2 x64-windows build: CPU-only software codec, no hwcodec/vram (R-R2b) ---
    # Under $ErrorActionPreference='Stop' a NATIVE command's non-zero exit does NOT auto-throw, so check
    # $LASTEXITCODE explicitly -- otherwise a failed build (e.g. "Python was not found" -> exit 9009) slips
    # through and Emit-Artifacts reports "complete" with no .exe.
    & $PYTHON_EXE build.py --flutter
    if ($LASTEXITCODE -ne 0) { Die "build.py --flutter failed (exit $LASTEXITCODE) -- Python missing/not on PATH, or the cargo/flutter build errored (see above)" }
    $applicationResource = Get-SingleCompiledWindowsResource 'rustdesk'
    Assert-CompiledWindowsResource $applicationResource 'RustDesk library'
    $applicationVersion = Get-CargoPackageVersion (Join-Path $SRC 'Cargo.toml')
    Assert-WindowsExecutableVersionInfo $rustLibrary $applicationVersion 'RustDesk library'

    # --- the WiX v4 .msi (R-B7/B9) -- build it before the portable packer so the exact Package.msi
    # can be embedded in rustdesk-setup.exe. This mirrors upstream's flutter-build.yml "Build msi"
    # (preprocess.py --arp -d <dist>; restore; msbuild msi.sln). NO .NET SDK needed -- VS msbuild +
    # .NET Framework (golden) + the WiX NuGet build it.
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
    # The CustomActions.vcxproj (C++) uses the OLD packages.config NuGet format for WixToolset.DUtil +
    # WcaUtil (native), which `msbuild -t:restore` (PackageReference-only) does NOT restore -> the build
    # dies "references NuGet package(s) that are missing ... WixToolset.DUtil.4.0.5\build\...props". Populate
    # res/msi/packages/ DIRECTLY from the staged global-packages cache: the package contents are identical,
    # only the top-level folder name differs (wixtoolset.dutil/4.0.5 -> WixToolset.DUtil.4.0.5), which
    # satisfies the vcxproj's <Import ...> + <Error Condition="!Exists(...)"> packages.config checks.
    foreach ($p in @('WixToolset.DUtil','WixToolset.WcaUtil')) {
        $pSrc = Join-Path $wixPkgs ("{0}\4.0.5" -f $p.ToLower())
        if (-not (Test-Path $pSrc)) { Die ".msi: staged cache lacks $pSrc (the vcxproj packages.config dep)" }
        $pDst = Join-Path $SRC ("res\msi\packages\{0}.4.0.5" -f $p)
        New-Item -ItemType Directory -Force $pDst | Out-Null
        Copy-Item -Recurse -Force (Join-Path $pSrc '*') $pDst
    }
    $nugetCfg = Join-Path $env:TEMP 'offline-nuget.config'
    @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <config><add key="globalPackagesFolder" value="$wixPkgs" /></config>
  <packageSources><clear /></packageSources>
</configuration>
"@ | Set-Content -Encoding UTF8 $nugetCfg
    if (-not (Test-Path (Join-Path $msiDist 'rustdesk.exe') -PathType Leaf)) { Die ".msi: flutter dist (rustdesk.exe) not at $msiDist -- build.py --flutter should produce it" }
    # msbuild lives in the VS install dir, NOT on PATH by default (the golden has no CI "Add MSBuild to
    # PATH" step). Locate it via vswhere (-products * so it finds BuildTools, not just full VS) + prepend.
    $vsw = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    $vsPath = (& $vsw -products * -latest -property installationPath 2>$null | Select-Object -First 1)
    if (-not $vsPath) { Die ".msi: vswhere found no VS install (need VS BuildTools with MSBuild)" }
    $msbuildDir = Join-Path $vsPath 'MSBuild\Current\Bin'
    if (-not (Test-Path (Join-Path $msbuildDir 'MSBuild.exe'))) { Die ".msi: MSBuild.exe not under $msbuildDir" }
    $env:PATH = "$msbuildDir;$env:PATH"
    Push-Location (Join-Path $SRC 'res\msi')
    & $PYTHON_EXE preprocess.py --arp -d $msiDist
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "res/msi/preprocess.py --arp failed ($LASTEXITCODE)" }
    msbuild msi.sln -t:restore -p:RestoreConfigFile=$nugetCfg -p:Configuration=Release -p:Platform=x64
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "msbuild -t:restore (WiX NuGet, OFFLINE from $wixPkgs) failed ($LASTEXITCODE) -- staged cache incomplete, or the SDK resolver wanted the network" }
    msbuild msi.sln -p:RestoreConfigFile=$nugetCfg -p:Configuration=Release -p:Platform=x64 /p:TargetVersion=Windows10
    if ($LASTEXITCODE -ne 0) { Pop-Location; Die "msbuild msi.sln (WiX .msi build) failed ($LASTEXITCODE)" }
    Pop-Location
    if (-not (Test-Path -LiteralPath $msiBuiltOut -PathType Leaf)) { Die ".msi: expected output not produced at $msiBuiltOut" }
    $msiBuiltItem = Get-OrdinaryPathItem $msiBuiltOut $true
    if ($msiBuiltItem.Length -le 0) { Die ".msi: output is empty at $msiBuiltOut" }
    New-Item -ItemType Directory -Path $canonicalMsiDir | Out-Null
    $canonicalDirectoryItem = Get-OrdinaryPathItem $canonicalMsiDir $false
    if (@(Get-ChildItem -LiteralPath $canonicalMsiDir -Force).Count -ne 0) {
        Die 'canonical MSI output directory is not a fresh ordinary directory'
    }
    $msiBuiltHash = (Get-FileHash -LiteralPath $msiBuiltOut -Algorithm SHA256).Hash
    [IO.File]::Copy($msiBuiltOut, $msiCanonicalizerInput, $false)
    $msiCanonicalizerInputItem = Get-OrdinaryPathItem $msiCanonicalizerInput $true
    $msiCanonicalizerInputHash = (Get-FileHash -LiteralPath $msiCanonicalizerInput -Algorithm SHA256).Hash
    if ($msiCanonicalizerInputItem.Length -ne $msiBuiltItem.Length -or
        $msiCanonicalizerInputHash -cne $msiBuiltHash) {
        Die '.msi: distinct canonicalizer input copy does not match the WiX output'
    }
    $msiCanonicalizerArguments = @(
        'scripts\canonicalize-msi.py',
        $msiCanonicalizerInput,
        '--output',
        $msiOut,
        '--contract-out',
        $msiContract,
        '--fork-version',
        $env:RUSTDESK_FORK_VERSION,
        '--source-commit',
        $env:RUSTDESK_SOURCE_COMMIT,
        '--source-tree',
        $env:RUSTDESK_SOURCE_TREE,
        '--target',
        $env:RUSTDESK_TARGET
    )
    & $PYTHON_EXE -I -S -c $isolatedOlefileRunner $olefileWheel @msiCanonicalizerArguments
    if ($LASTEXITCODE -ne 0) { Die ".msi: pre-embed canonicalization failed ($LASTEXITCODE)" }
    if ((Get-FileHash -LiteralPath $msiBuiltOut -Algorithm SHA256).Hash -cne $msiBuiltHash -or
        (Get-FileHash -LiteralPath $msiCanonicalizerInput -Algorithm SHA256).Hash -cne $msiBuiltHash) {
        Die '.msi: WiX output or canonicalizer input changed during canonicalization'
    }
    Remove-Item -LiteralPath $msiCanonicalizerInput -Force
    if (Test-Path -LiteralPath $msiCanonicalizerInput) {
        Die '.msi: canonicalizer input was not removed after verification'
    }
    foreach ($canonicalOutput in @($msiOut, $msiContract)) {
        if (-not (Test-Path -LiteralPath $canonicalOutput -PathType Leaf) -or
            (Get-OrdinaryPathItem $canonicalOutput $true).Length -le 0) {
            Die "canonical MSI output is absent, empty, or a reparse point: $canonicalOutput"
        }
    }
    $installer = $null
    $database = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase([string]$msiOut, [int]0)
        if ($null -eq $database) { Die ".msi: Windows Installer could not open $msiOut as an MSI database" }
        $cabinetContract = Get-Content -LiteralPath $msiContract -Raw | ConvertFrom-Json
        $contractFields = @($cabinetContract.PSObject.Properties.Name | Sort-Object)
        if (($contractFields -join ',') -cne 'cabinet_sha256,cabinet_size,files,format' -or
            $cabinetContract.format -isnot [string] -or
            $cabinetContract.format -cne 'rustdesk-msi-cabinet-contract-v1' -or
            $cabinetContract.cabinet_sha256 -isnot [string] -or
            $cabinetContract.cabinet_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $cabinetContract.files -isnot [Array]) {
            Die 'canonical MSI cabinet contract schema is not exact'
        }
        $cabinetSize = Get-JsonInt64 $cabinetContract.cabinet_size 'canonical cabinet size'
        if ($cabinetSize -le 0 -or $cabinetSize -gt [Int32]::MaxValue) {
            Die 'canonical MSI cabinet size is outside the Windows Installer stream range'
        }
        $contractFiles = $cabinetContract.files
        if ($contractFiles.Count -le 0 -or $contractFiles.Count -gt 32767) {
            Die 'canonical MSI cabinet contract file count is invalid'
        }
        $expectedOffset = [Int64]0
        for ($index = 0; $index -lt $contractFiles.Count; $index++) {
            $entry = $contractFiles[$index]
            $entryFields = @($entry.PSObject.Properties.Name | Sort-Object)
            if (($entryFields -join ',') -cne 'folder,id,offset,sequence,size' -or $entry.id -isnot [string]) {
                Die "canonical MSI cabinet contract entry is invalid at sequence $($index + 1)"
            }
            $folder = Get-JsonInt64 $entry.folder "canonical cabinet folder at sequence $($index + 1)"
            $sequence = Get-JsonInt64 $entry.sequence "canonical cabinet sequence $($index + 1)"
            $offset = Get-JsonInt64 $entry.offset "canonical cabinet offset at sequence $($index + 1)"
            $size = Get-JsonInt64 $entry.size "canonical cabinet size at sequence $($index + 1)"
            if ($folder -ne 0 -or $sequence -ne ($index + 1) -or $offset -ne $expectedOffset -or
                $size -lt 0 -or $size -gt [UInt32]::MaxValue -or
                $entry.id -cnotmatch '^[A-Za-z_][A-Za-z0-9_.]{0,71}$' -or
                $expectedOffset -gt ([Int64][UInt32]::MaxValue - $size)) {
                Die "canonical MSI cabinet contract entry is invalid at sequence $($index + 1)"
            }
            $expectedOffset += $size
        }

        $mediaRows = @(Read-MsiRows $database 'SELECT `DiskId`, `LastSequence`, `Cabinet` FROM `Media` ORDER BY `DiskId`' @('integer', 'integer', 'string'))
        if ($mediaRows.Count -ne 1 -or
            [Int64]$mediaRows[0].Values[0] -ne 1 -or
            [Int64]$mediaRows[0].Values[1] -ne $contractFiles.Count) {
            Die 'MSI Media table does not describe one exact all-files cabinet'
        }
        $zeroRows = @(Read-MsiRows $database "SELECT ``File`` FROM ``File`` WHERE ``File`` = '__rustdesk_absent__'" @('string'))
        if ($zeroRows.Count -ne 0) { Die 'MSI query zero-row behavior is invalid' }
        $cabinetReference = $mediaRows[0].Values[2]
        if ($cabinetReference -cnotmatch '^#[A-Za-z_][A-Za-z0-9_.]{0,61}$') {
            Die 'MSI Media table cabinet is not one canonical case-sensitive embedded stream reference'
        }
        $cabinetStream = $cabinetReference.Substring(1)
        $cabinetDigest = Get-MsiStreamSha256 $database $cabinetStream $cabinetSize
        if ($cabinetDigest -cne $cabinetContract.cabinet_sha256) {
            Die 'MSI Media/_Streams cabinet bytes do not match the structurally validated cabinet'
        }

        $fileRows = @(Read-MsiRows $database 'SELECT `File`, `FileSize`, `Sequence` FROM `File` ORDER BY `Sequence`' @('string', 'integer', 'integer'))
        if ($fileRows.Count -ne $contractFiles.Count) {
            Die 'MSI File table count does not match the cabinet contract'
        }
        for ($index = 0; $index -lt $contractFiles.Count; $index++) {
            $row = $fileRows[$index].Values
            $entry = $contractFiles[$index]
            if ($row[0] -cne $entry.id -or
                [Int64]$row[1] -ne (Get-JsonInt64 $entry.size 'canonical cabinet File size') -or
                [Int64]$row[2] -ne (Get-JsonInt64 $entry.sequence 'canonical cabinet File sequence')) {
                Die "MSI File table does not match cabinet order/id/size at sequence $($index + 1)"
            }
        }
    } catch {
        Die ".msi: Windows Installer validation failed for ${msiOut}: $($_.Exception.Message)"
    } finally {
        if ($null -ne $database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
        if ($null -ne $installer) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
    }
    Write-Host "[harness] .msi built (R-B7): $msiOut"

    # Generate from a dedicated one-file payload directory. The packer output is deleted before
    # invocation, so a failed cargo build cannot be mistaken for this build's setup.exe.
    $packExit = $null
    try {
        if (Test-Path -LiteralPath $setupPayloadDir) { Die ".msi: unexpected payload directory already exists at $setupPayloadDir" }
        New-Item -ItemType Directory -Path $setupPayloadDir | Out-Null
        Copy-Item -LiteralPath $msiOut -Destination $setupPayloadMsi
        $sourceMsiHash = (Get-FileHash -LiteralPath $msiOut -Algorithm SHA256).Hash
        $payloadMsiHash = (Get-FileHash -LiteralPath $setupPayloadMsi -Algorithm SHA256).Hash
        if ($sourceMsiHash -ne $payloadMsiHash) { Die ".msi: setup payload copy hash mismatch at $setupPayloadMsi" }
        $env:CARGO_NET_OFFLINE = 'true'
        Push-Location (Join-Path $SRC 'libs\portable')
        try {
            & $PYTHON_EXE .\generate.py -f $setupPayloadDir -o . -e $setupPayloadMsi
            $packExit = $LASTEXITCODE
        } finally {
            Pop-Location
        }
    } finally {
        if (Test-Path -LiteralPath $setupPayloadDir) {
            $payloadItem = Get-Item -LiteralPath $setupPayloadDir -Force
            if (-not $payloadItem.PSIsContainer -or ($payloadItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                Die "refusing to remove non-directory or reparse setup payload path: $setupPayloadDir"
            }
            Remove-Item -LiteralPath $setupPayloadDir -Recurse -Force
        }
    }
    if ($packExit -ne 0) { Die "libs/portable/generate.py failed (exit $packExit)" }
    if (-not (Test-Path -LiteralPath $setupOut -PathType Leaf)) { Die "portable packer did not produce $setupOut" }
    if ((Get-Item -LiteralPath $setupOut).Length -le 0) { Die "portable packer produced an empty file at $setupOut" }
    $portableResource = Get-SingleCompiledWindowsResource 'rustdesk-portable-packer'
    Assert-CompiledWindowsResource $portableResource 'RustDesk portable packer'
    $portableVersion = Get-CargoPackageVersion (Join-Path $SRC 'libs\portable\Cargo.toml')
    Assert-WindowsExecutableVersionInfo $setupOut $portableVersion 'RustDesk portable packer'
    $applicationResourceHash = (Get-FileHash -LiteralPath $applicationResource -Algorithm SHA256).Hash
    $portableResourceHash = (Get-FileHash -LiteralPath $portableResource -Algorithm SHA256).Hash
    if ($applicationVersion -cne $portableVersion -or $applicationResourceHash -cne $portableResourceHash) {
        Die 'root and portable crates did not emit one exact compiled Windows resource'
    }
    Write-Host "[harness] setup bootstrapper built with embedded MSI: $setupOut"
}

function Emit-Artifacts {
    $out = Join-Path $SRC 'dist'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $setup = Join-Path $SRC 'target\release\rustdesk-portable-packer.exe'
    $msi = Join-Path $SRC 'target\canonical-msi\rustdesk.msi'
    $setupPayloadDir = Join-Path $SRC 'target\rustdesk-setup-payload'
    if (Test-Path -LiteralPath $setupPayloadDir) { Die "temporary setup payload was not removed: $setupPayloadDir" }
    if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) { Die "setup bootstrapper missing at exact output path $setup" }
    if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { Die "MSI missing at exact output path $msi" }
    Copy-Item -LiteralPath $setup -Destination (Join-Path $out 'rustdesk-setup.exe')
    Copy-Item -LiteralPath $msi -Destination (Join-Path $out 'rustdesk.msi')
    # Record the pinned SHA-256 (R-B2): the tamper-evidence anchor in place of a
    # code signature, verified on the target over the operator's trusted channel.
    foreach ($artifact in @((Join-Path $out 'rustdesk-setup.exe'), (Join-Path $out 'rustdesk.msi'))) {
        $item = Get-Item -LiteralPath $artifact
        $h = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLower()
        "$h  $($item.Name)" | Tee-Object -FilePath "$artifact.sha256"
    }
    Write-Host "[harness] build-windows.ps1 complete: $out"
}

Preflight
Build
Emit-Artifacts
