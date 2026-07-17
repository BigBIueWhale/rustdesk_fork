$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail([string]$Message) {
    throw "[harness:FATAL] $Message"
}

function Get-OneDrive([string]$Marker, [string]$Description) {
    $matches = @(
        Get-PSDrive -PSProvider FileSystem |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.Root $Marker) -PathType Leaf }
    )
    if ($matches.Count -ne 1) {
        Fail "$Description drive count is $($matches.Count), expected exactly one"
    }
    return $matches[0].Root
}

function Assert-Hex([string]$Value, [int[]]$Lengths, [string]$Description) {
    if ($Value -cnotmatch '^[0-9a-f]+$' -or $Lengths -notcontains $Value.Length) {
        Fail "$Description is not canonical lowercase hexadecimal"
    }
}

function Get-JsonInt64([object]$Value, [string]$Description) {
    if ($null -eq $Value -or -not ($Value -is [int] -or $Value -is [long])) {
        Fail "$Description is not a JSON integer"
    }
    return [Int64]$Value
}

function Assert-SafeRelativePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or [IO.Path]::IsPathRooted($Path)) {
        Fail "source manifest has an empty or rooted path"
    }
    if ($Path.Contains('\') -or $Path.Contains(':') -or $Path.Contains(',') -or
        $Path.StartsWith('/') -or $Path.EndsWith('/')) {
        Fail "source manifest path is not canonical: $Path"
    }
    $components = @($Path.Split('/'))
    foreach ($component in $components) {
        if ([string]::IsNullOrEmpty($component) -or $component -ceq '.' -or $component -ceq '..' -or
            $component.EndsWith(' ') -or $component.EndsWith('.')) {
            Fail "source manifest path has an invalid component: $Path"
        }
        foreach ($character in $component.ToCharArray()) {
            $value = [int]$character
            if ($value -lt 0x20 -or $value -gt 0x7e -or '<>"|?*'.Contains($character)) {
                Fail "source manifest path contains a Win32-forbidden character: $Path"
            }
        }
        if ($component -imatch '^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$') {
            Fail "source manifest path uses a reserved Win32 device name: $Path"
        }
    }
    $reserved = @(
        '.source-manifest.json',
        '.source-identity.json',
        '.source-date-epoch',
        '.build-run-id',
        '.source-manifest.json.tmp',
        '.source-identity.json.tmp',
        'run-build.ps1'
    )
    $rootComponent = $components[0]
    foreach ($name in $reserved) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals($rootComponent, $name) -and
            -not ($components.Count -eq 1 -and [StringComparer]::Ordinal.Equals($Path, 'run-build.ps1'))) {
            Fail "source manifest path occupies a generated namespace: $Path"
        }
    }
}

function Assert-SourceManifest([string]$Root, [string]$ExpectedHash) {
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "source root is not a regular directory: $Root"
    }
    $manifestPath = Join-Path $Root '.source-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Fail "source manifest is missing at $manifestPath"
    }
    $actualHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $ExpectedHash) {
        Fail "source manifest hash mismatch: $actualHash != $ExpectedHash"
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $topLevel = @($manifest.PSObject.Properties.Name | Sort-Object)
    if (($topLevel -join ',') -cne 'files,format' -or
        $manifest.format -isnot [string] -or
        $manifest.format -cne 'rustdesk-windows-source-manifest-v1' -or
        $manifest.files -isnot [Array]) {
        Fail 'source manifest schema is not exact'
    }
    $declared = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $declaredInsensitive = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $expectedDirectories = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($entry in @($manifest.files)) {
        $properties = @($entry.PSObject.Properties.Name | Sort-Object)
        if (($properties -join ',') -cne 'path,sha256,size') {
            Fail 'source manifest file entry schema is not exact'
        }
        if ($entry.path -isnot [string] -or $entry.sha256 -isnot [string]) {
            Fail 'source manifest path or digest is not a JSON string'
        }
        $relative = $entry.path
        Assert-SafeRelativePath $relative
        Assert-Hex $entry.sha256 @(64) "source hash for $relative"
        if (-not $declared.Add($relative) -or -not $declaredInsensitive.Add($relative)) {
            Fail "source manifest has a duplicate or Windows case-colliding path: $relative"
        }
        $declaredSize = Get-JsonInt64 $entry.size "source size for $relative"
        if ($declaredSize -lt 0) {
            Fail "source manifest has a negative size: $relative"
        }
        $native = $relative.Replace('/', '\')
        $path = Join-Path $Root $native
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Fail "source manifest file is missing: $relative"
        }
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "source manifest file is a reparse point: $relative"
        }
        if ($item.Length -ne $declaredSize) {
            Fail "source manifest size mismatch: $relative"
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -cne $entry.sha256) {
            Fail "source manifest hash mismatch: $relative"
        }
        $components = $relative.Split('/')
        for ($index = 1; $index -lt $components.Count; $index++) {
            [void]$expectedDirectories.Add(($components[0..($index - 1)] -join '/'))
        }
    }
    if ($declared.Count -eq 0) {
        Fail 'source manifest contains no files'
    }

    $excluded = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($name in @('.source-manifest.json', '.source-identity.json', '.source-date-epoch', '.build-run-id')) {
        [void]$excluded.Add($name)
    }
    $actual = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $actualDirectories = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($directory in Get-ChildItem -LiteralPath $Root -Recurse -Directory -Force) {
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "copied source contains a directory reparse point: $($directory.FullName)"
        }
        $relative = $directory.FullName.Substring($Root.TrimEnd('\').Length + 1).Replace('\', '/')
        [void]$actualDirectories.Add($relative)
    }
    foreach ($file in Get-ChildItem -LiteralPath $Root -Recurse -File -Force) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "copied source contains a reparse point: $($file.FullName)"
        }
        $relative = $file.FullName.Substring($Root.TrimEnd('\').Length + 1).Replace('\', '/')
        if (-not $excluded.Contains($relative)) {
            [void]$actual.Add($relative)
        }
    }
    if ($actual.Count -ne $declared.Count) {
        Fail 'source manifest file count does not match the copied tree'
    }
    foreach ($relative in $actual) {
        if (-not $declared.Contains($relative)) {
            Fail "copied source has an undeclared file: $relative"
        }
    }
    if ($actualDirectories.Count -ne $expectedDirectories.Count) {
        Fail 'source manifest directory count does not match the copied tree'
    }
    foreach ($relative in $actualDirectories) {
        if (-not $expectedDirectories.Contains($relative)) {
            Fail "copied source has an undeclared directory: $relative"
        }
    }
}

function Assert-OfflineManifest([string]$Root, [string]$ExpectedHash) {
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "OFFLINE root is not a regular directory: $Root"
    }
    $manifestPath = Join-Path $Root '.offline-input-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Fail "OFFLINE manifest is missing at $manifestPath"
    }
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
    if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'OFFLINE manifest is a reparse point'
    }
    $actualHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $ExpectedHash) {
        Fail "OFFLINE manifest hash mismatch: $actualHash != $ExpectedHash"
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $topLevel = @($manifest.PSObject.Properties.Name | Sort-Object)
    if (($topLevel -join ',') -cne 'directories,files,format' -or
        $manifest.format -isnot [string] -or
        $manifest.format -cne 'rustdesk-windows-offline-manifest-v2' -or
        $manifest.directories -isnot [Array] -or
        $manifest.files -isnot [Array]) {
        Fail 'OFFLINE manifest schema is not exact'
    }

    $declaredDirectories = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $declaredDirectoriesInsensitive = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($relative in @($manifest.directories)) {
        if ($relative -isnot [string]) {
            Fail 'OFFLINE manifest directory is not a JSON string'
        }
        Assert-SafeRelativePath $relative
        if (-not $declaredDirectories.Add($relative) -or
            -not $declaredDirectoriesInsensitive.Add($relative)) {
            Fail "OFFLINE manifest has a duplicate or Windows case-colliding directory: $relative"
        }
        $components = @($relative.Split('/'))
        if ($components.Count -gt 1) {
            $parent = $components[0..($components.Count - 2)] -join '/'
            if (-not $declaredDirectories.Contains($parent)) {
                Fail "OFFLINE manifest directory has an undeclared parent: $relative"
            }
        }
        $path = Join-Path $Root $relative.Replace('/', '\')
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            Fail "OFFLINE manifest directory is missing: $relative"
        }
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "OFFLINE manifest directory is a reparse point: $relative"
        }
    }

    $declaredFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $caseFileIdentity = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($manifest.files)) {
        $properties = @($entry.PSObject.Properties.Name | Sort-Object)
        if (($properties -join ',') -cne 'path,sha256,size') {
            Fail 'OFFLINE manifest file entry schema is not exact'
        }
        if ($entry.path -isnot [string] -or $entry.sha256 -isnot [string]) {
            Fail 'OFFLINE manifest path or digest is not a JSON string'
        }
        $relative = $entry.path
        Assert-SafeRelativePath $relative
        if ([StringComparer]::OrdinalIgnoreCase.Equals($relative, '.offline-input-manifest.json')) {
            Fail 'OFFLINE manifest declares its generated manifest path as an input'
        }
        Assert-Hex $entry.sha256 @(64) "OFFLINE hash for $relative"
        $declaredSize = Get-JsonInt64 $entry.size "OFFLINE size for $relative"
        if ($declaredSize -lt 0) {
            Fail "OFFLINE manifest has a negative size: $relative"
        }
        if (-not $declaredFiles.Add($relative) -or $declaredDirectoriesInsensitive.Contains($relative)) {
            Fail "OFFLINE manifest has a duplicate or file/directory-colliding path: $relative"
        }
        $fingerprint = "$($entry.sha256):$declaredSize"
        if ($caseFileIdentity.ContainsKey($relative)) {
            if ($caseFileIdentity[$relative] -cne $fingerprint) {
                Fail "OFFLINE manifest has a Windows case collision with different bytes: $relative"
            }
        } else {
            $caseFileIdentity.Add($relative, $fingerprint)
        }
        $components = @($relative.Split('/'))
        if ($components.Count -gt 1) {
            $parent = $components[0..($components.Count - 2)] -join '/'
            if (-not $declaredDirectories.Contains($parent)) {
                Fail "OFFLINE manifest file has an undeclared parent: $relative"
            }
        }
        $path = Join-Path $Root $relative.Replace('/', '\')
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Fail "OFFLINE manifest file is missing: $relative"
        }
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "OFFLINE manifest file is a reparse point: $relative"
        }
        if ($item.Length -ne $declaredSize) {
            Fail "OFFLINE manifest size mismatch: $relative"
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -cne $entry.sha256) {
            Fail "OFFLINE manifest hash mismatch: $relative"
        }
    }
    if ($declaredDirectories.Count -eq 0 -or $declaredFiles.Count -eq 0) {
        Fail 'OFFLINE manifest contains no directories or files'
    }

    $actualDirectories = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($directory in Get-ChildItem -LiteralPath $Root -Recurse -Directory -Force) {
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "OFFLINE media contains a directory reparse point: $($directory.FullName)"
        }
        $relative = $directory.FullName.Substring($Root.TrimEnd('\').Length + 1).Replace('\', '/')
        if (-not $actualDirectories.Add($relative)) {
            Fail "OFFLINE media enumerated a duplicate directory: $relative"
        }
    }
    $actualFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($file in Get-ChildItem -LiteralPath $Root -Recurse -File -Force) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "OFFLINE media contains a file reparse point: $($file.FullName)"
        }
        $relative = $file.FullName.Substring($Root.TrimEnd('\').Length + 1).Replace('\', '/')
        if (-not [StringComparer]::Ordinal.Equals($relative, '.offline-input-manifest.json') -and
            -not $actualFiles.Add($relative)) {
            Fail "OFFLINE media enumerated a duplicate file: $relative"
        }
    }
    if ($actualDirectories.Count -ne $declaredDirectories.Count -or
        $actualFiles.Count -ne $declaredFiles.Count) {
        Fail 'OFFLINE media path counts do not match its manifest'
    }
    foreach ($relative in $actualDirectories) {
        if (-not $declaredDirectories.Contains($relative)) {
            Fail "OFFLINE media has an undeclared directory: $relative"
        }
    }
    foreach ($relative in $actualFiles) {
        if (-not $declaredFiles.Contains($relative)) {
            Fail "OFFLINE media has an undeclared file: $relative"
        }
    }
}

$out = $null
$transcriptStarted = $false

function Mark([string]$Message) {
    "$(Get-Date -Format o) $Message" |
        Out-File -LiteralPath (Join-Path $out 'run-build-progress.txt') -Append -Encoding ascii
}

try {
    $outputRoots = @(
        Get-Volume |
            Where-Object { $_.FileSystemLabel -eq 'OUTPUT' -and $null -ne $_.DriveLetter } |
            ForEach-Object { "$($_.DriveLetter):\" }
    )
    if ($outputRoots.Count -ne 1) {
        Fail "OUTPUT volume count is $($outputRoots.Count), expected exactly one"
    }
    $out = $outputRoots[0]
    $sourceMedia = Get-OneDrive '.source-identity.json' 'BUILD source'
    $offlineMedia = Get-OneDrive '.offline-input-manifest.json' 'OFFLINE'
    Mark "RUN-BUILD START out=$out source=$sourceMedia offline=$offlineMedia"
    Start-Transcript -Path (Join-Path $out 'build-log.txt') -Force | Out-Null
    $transcriptStarted = $true

    $identityPath = Join-Path $sourceMedia '.source-identity.json'
    $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
    $identityFields = @($identity.PSObject.Properties.Name | Sort-Object)
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
    if (($identityFields -join ',') -cne ($expectedFields -join ',') -or
        $identity.format -isnot [string] -or
        $identity.format -cne 'rustdesk-windows-source-identity-v1') {
        Fail 'source identity schema is not exact'
    }
    foreach ($field in $expectedFields) {
        if ($identity.$field -isnot [string]) {
            Fail "source identity field is not a JSON string: $field"
        }
    }
    Assert-Hex $identity.source_commit @(40, 64) 'source commit'
    Assert-Hex $identity.source_tree @(40, 64) 'source tree'
    foreach ($field in @('base_manifest_sha256', 'frb_manifest_sha256', 'offline_manifest_sha256', 'source_manifest_sha256')) {
        Assert-Hex $identity.$field @(64) $field
    }
    if ([string]$identity.source_mode -cnotin @('head', 'worktree')) {
        Fail 'source mode is not canonical'
    }
    if ([string]$identity.fork_version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+-hardened\.[0-9]+$') {
        Fail 'FORK_VERSION is not canonical'
    }
    if ([string]$identity.source_date_epoch -cnotmatch '^[0-9]+$') {
        Fail 'SOURCE_DATE_EPOCH is not canonical'
    }
    if ([string]$identity.target -cne 'windows-x86_64') {
        Fail 'source target is not windows-x86_64'
    }
    if ([string]$identity.build_run_id -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[AB]$') {
        Fail 'build run ID is not canonical'
    }
    $identityHash = (Get-FileHash -LiteralPath $identityPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $epochRaw = Get-Content -LiteralPath (Join-Path $sourceMedia '.source-date-epoch') -Raw
    if ($epochRaw -cne "$($identity.source_date_epoch)$([char]10)") {
        Fail 'source-date-epoch stamp does not exactly match source identity'
    }
    $runIdRaw = Get-Content -LiteralPath (Join-Path $sourceMedia '.build-run-id') -Raw
    if ($runIdRaw -cne "$($identity.build_run_id)$([char]10)") {
        Fail 'build-run-id stamp does not exactly match source identity'
    }
    Assert-OfflineManifest $offlineMedia ([string]$identity.offline_manifest_sha256)
    Mark "offline-verified manifest=$($identity.offline_manifest_sha256)"
    Assert-SourceManifest $sourceMedia ([string]$identity.source_manifest_sha256)

    $legacySource = 'C:\src'
    if (Test-Path -LiteralPath $legacySource) {
        $legacyItem = Get-Item -LiteralPath $legacySource -Force
        if (-not $legacyItem.PSIsContainer -or
            ($legacyItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail 'legacy C:\src is not a removable regular directory'
        }
        foreach ($entry in Get-ChildItem -LiteralPath $legacySource -Recurse -Force) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail "legacy C:\src contains a reparse point: $($entry.FullName)"
            }
        }
        Remove-Item -LiteralPath $legacySource -Recurse -Force
    }
    if (Test-Path -LiteralPath $legacySource) {
        Fail 'legacy C:\src was not fully removed'
    }

    $buildParent = 'C:\rustdesk-build'
    if (-not (Test-Path -LiteralPath $buildParent)) {
        New-Item -ItemType Directory -Path $buildParent | Out-Null
    }
    $parentItem = Get-Item -LiteralPath $buildParent -Force
    if (-not $parentItem.PSIsContainer -or
        ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'C:\rustdesk-build is not a regular directory'
    }
    # Both reproducibility passes run on fresh golden-image overlays. Keep the authenticated
    # per-pass build_run_id in the source identity, but compile from one absent-checked path so
    # MSVC/Rust/PDB source paths cannot make otherwise identical artifacts pass-specific.
    $source = Join-Path $buildParent 'source'
    if (Test-Path -LiteralPath $source) {
        Fail "stable source directory already exists: $source"
    }
    New-Item -ItemType Directory -Path $source | Out-Null
    Get-ChildItem -LiteralPath $sourceMedia -Force |
        Copy-Item -Destination $source -Recurse -Force
    Get-ChildItem -LiteralPath $source -Recurse -File -Force |
        Where-Object { $_.IsReadOnly } |
        ForEach-Object { $_.IsReadOnly = $false }
    Assert-SourceManifest $source ([string]$identity.source_manifest_sha256)
    $copiedIdentityHash = (Get-FileHash -LiteralPath (Join-Path $source '.source-identity.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($copiedIdentityHash -cne $identityHash) {
        Fail 'copied source identity differs from BUILD media'
    }

    $env:RUSTDESK_SOURCE_ROOT = $source
    $env:RUSTDESK_SOURCE_COMMIT = [string]$identity.source_commit
    $env:RUSTDESK_SOURCE_TREE = [string]$identity.source_tree
    $env:RUSTDESK_SOURCE_MANIFEST_SHA256 = [string]$identity.source_manifest_sha256
    $env:RUSTDESK_OFFLINE_MANIFEST_SHA256 = [string]$identity.offline_manifest_sha256
    $env:RUSTDESK_FORK_VERSION = [string]$identity.fork_version
    $env:RUSTDESK_BUILD_RUN_ID = [string]$identity.build_run_id
    $env:RUSTDESK_TARGET = [string]$identity.target
    $env:SOURCE_DATE_EPOCH = [string]$identity.source_date_epoch
    Mark "source-verified commit=$($identity.source_commit) tree=$($identity.source_tree) manifest=$($identity.source_manifest_sha256)"

    Set-Location $source
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $source 'scripts\build-windows.ps1')
    $buildExit = $LASTEXITCODE
    Mark "build-windows.ps1 exit=$buildExit"
    if ($buildExit -ne 0) {
        Fail "build-windows.ps1 failed with exit $buildExit"
    }
    $dist = Join-Path $source 'dist'
    foreach ($name in @('rustdesk-setup.exe', 'rustdesk-setup.exe.sha256', 'rustdesk.msi', 'rustdesk.msi.sha256')) {
        $artifact = Join-Path $dist $name
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
            Fail "validated guest artifact is missing: $name"
        }
        Copy-Item -LiteralPath $artifact -Destination (Join-Path $out $name) -Force
    }
    Mark 'artifacts-copied'
} catch {
    $failure = $_.Exception.Message
    [Console]::Error.WriteLine("RUN-BUILD ERROR: $failure")
    if ($null -ne $out) {
        try {
            "RUN-BUILD ERROR: $failure" |
                Out-File -LiteralPath (Join-Path $out 'build-log.txt') -Append -Encoding ascii
        } catch {
            [Console]::Error.WriteLine("RUN-BUILD ERROR LOG FAILURE: $($_.Exception.Message)")
        }
        try {
            Mark "ERROR $failure"
        } catch {
            [Console]::Error.WriteLine("RUN-BUILD PROGRESS FAILURE: $($_.Exception.Message)")
        }
    }
} finally {
    if ($transcriptStarted) {
        try {
            Stop-Transcript | Out-Null
        } catch {
            [Console]::Error.WriteLine("RUN-BUILD TRANSCRIPT-CLOSE FAILURE: $($_.Exception.Message)")
        }
    }
    if ($null -ne $out) {
        try {
            Mark 'shutting-down'
        } catch {
            [Console]::Error.WriteLine("RUN-BUILD SHUTDOWN-MARKER FAILURE: $($_.Exception.Message)")
        }
    }
    Stop-Computer -Force
}
