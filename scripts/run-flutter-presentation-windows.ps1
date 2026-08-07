$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

function Fail([string]$Message) {
    throw "[windows-presentation-runner:FATAL] $Message"
}

function Get-OneSourceRoot {
    $matches = @(
        Get-PSDrive -PSProvider FileSystem |
            Where-Object {
                Test-Path -LiteralPath (Join-Path $_.Root '.presentation-source-manifest.json') -PathType Leaf
            }
    )
    if ($matches.Count -ne 1) {
        Fail "presentation SOURCE drive count is $($matches.Count), expected exactly one"
    }
    return $matches[0].Root
}

function Get-OneOutputRoot {
    $matches = @(
        Get-Volume |
            Where-Object { $_.FileSystemLabel -ceq 'OUTPUT' -and $null -ne $_.DriveLetter } |
            ForEach-Object { "$($_.DriveLetter):\" }
    )
    if ($matches.Count -ne 1) {
        Fail "OUTPUT volume count is $($matches.Count), expected exactly one"
    }
    return $matches[0]
}

function Write-Ascii([string]$Path, [string]$Value) {
    [IO.File]::WriteAllText($Path, $Value, [Text.Encoding]::ASCII)
}

function Copy-ProbeState([string]$State, [string]$Output) {
    if (-not (Test-Path -LiteralPath $State -PathType Container)) {
        return
    }
    $destination = Join-Path $Output 'windows-presentation-state'
    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Recurse -Force
    }
    Copy-Item -LiteralPath $State -Destination $destination -Recurse -Force
}

$outputRoot = $null
$workRoot = $null
$stateDirectory = $null
$runnerSucceeded = $false
try {
    $sourceRoot = Get-OneSourceRoot
    $outputRoot = Get-OneOutputRoot
    Write-Ascii (Join-Path $outputRoot 'windows-presentation-progress.txt') "source-found`r`n"

    $manifestPath = Join-Path $sourceRoot '.presentation-source-manifest.json'
    $manifestHelper = Join-Path $sourceRoot 'scripts\windows-presentation-source-manifest.py'
    $python = 'C:\Program Files\Python311\python.exe'
    foreach ($path in @($manifestHelper, $python)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Fail "required source verifier is absent: $path"
        }
    }
    $verify = Start-Process -FilePath $python `
        -ArgumentList @('-I', '-B', $manifestHelper, '--root', $sourceRoot, '--manifest', $manifestPath, '--verify') `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $outputRoot 'windows-presentation-source-verify.stdout.txt') `
        -RedirectStandardError (Join-Path $outputRoot 'windows-presentation-source-verify.stderr.txt')
    if ($verify.ExitCode -ne 0) {
        Fail "exact presentation source verification failed with exit $($verify.ExitCode)"
    }
    $manifest = [IO.File]::ReadAllText($manifestPath, [Text.Encoding]::ASCII) | ConvertFrom-Json
    if ($manifest.format -cne 'rustdesk-windows-presentation-source-v1' -or
        $manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        $manifest.source_tree -cnotmatch '^[0-9a-f]{40}$') {
        Fail 'presentation source identity is malformed after verification'
    }
    Add-Content -LiteralPath (Join-Path $outputRoot 'windows-presentation-progress.txt') `
        -Value 'source-verified' -Encoding ASCII

    $workRoot = "C:\RustDeskPresentationProbe-$([Guid]::NewGuid().ToString('N'))"
    $stateDirectory = Join-Path $workRoot 'state'
    $appRoot = Join-Path $workRoot 'app'
    New-Item -ItemType Directory -Path $workRoot, $stateDirectory, $appRoot | Out-Null
    $env:CI = 'true'
    $env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
    $env:PUB_ENVIRONMENT = 'rustdesk_windows_presentation_probe'
    $env:PATH = "C:\flutter\bin;C:\Program Files\Git\cmd;$env:PATH"
    $env:PUB_CACHE = Join-Path $env:LOCALAPPDATA 'Pub\Cache'
    foreach ($package in @(
        'characters-1.3.0',
        'collection-1.18.0',
        'material_color_utilities-0.11.1',
        'meta-1.15.0',
        'plugin_platform_interface-2.1.8',
        'url_launcher_platform_interface-2.3.2',
        'url_launcher_windows-3.1.4',
        'vector_math-2.1.4'
    )) {
        $packagePath = Join-Path $env:PUB_CACHE "hosted\pub.dev\$package"
        if (-not (Test-Path -LiteralPath $packagePath -PathType Container)) {
            Fail "pinned golden pub cache lacks $package"
        }
        $packageItem = Get-Item -LiteralPath $packagePath -Force
        if (($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "pinned golden pub-cache package is a reparse point: $package"
        }
    }

    $flutter = 'C:\flutter\bin\flutter.bat'
    if (-not (Test-Path -LiteralPath $flutter -PathType Leaf)) {
        Fail 'pinned Flutter executable is absent'
    }
    $flutterVersion = Start-Process -FilePath $flutter -ArgumentList @('--version', '--machine') `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $outputRoot 'windows-presentation-flutter-version.json') `
        -RedirectStandardError (Join-Path $outputRoot 'windows-presentation-flutter-version.stderr.txt')
    if ($flutterVersion.ExitCode -ne 0) {
        Fail "flutter version probe failed with exit $($flutterVersion.ExitCode)"
    }

    $create = Start-Process -FilePath $flutter `
        -ArgumentList @(
            'create', '--platforms=windows', '--no-pub',
            '--project-name=rustdesk_presentation_probe',
            '--org=com.rustdesk.probe', $appRoot
        ) -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $outputRoot 'windows-presentation-create.stdout.txt') `
        -RedirectStandardError (Join-Path $outputRoot 'windows-presentation-create.stderr.txt')
    if ($create.ExitCode -ne 0) {
        Fail "flutter create failed with exit $($create.ExitCode)"
    }

    Copy-Item -LiteralPath (Join-Path $sourceRoot 'scripts\flutter-presentation-probe-windows.dart') `
        -Destination (Join-Path $appRoot 'lib\main.dart') -Force
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'flutter\lib\models\presentation_recovery.dart') `
        -Destination (Join-Path $appRoot 'lib\presentation_recovery.dart') -Force
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'scripts\flutter-presentation-probe-windows-pubspec.yaml') `
        -Destination (Join-Path $appRoot 'pubspec.yaml') -Force
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'scripts\flutter-presentation-d3d11-preflight-windows.cpp') `
        -Destination (Join-Path $appRoot 'windows\runner\d3d11_preflight.cpp') -Force
    Add-Content -LiteralPath (Join-Path $appRoot 'windows\runner\CMakeLists.txt') -Encoding ASCII -Value @'

add_executable(rustdesk_d3d11_preflight WIN32
  "d3d11_preflight.cpp"
)
apply_standard_settings(rustdesk_d3d11_preflight)
target_compile_definitions(rustdesk_d3d11_preflight PRIVATE "NOMINMAX")
target_link_libraries(rustdesk_d3d11_preflight PRIVATE d3d11 dxgi dwmapi user32 gdi32)
install(TARGETS rustdesk_d3d11_preflight RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}"
  COMPONENT Runtime)
'@
    $thirdParty = Join-Path $appRoot 'third_party'
    New-Item -ItemType Directory -Path $thirdParty | Out-Null
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'flutter\third_party\texture_rgba_renderer') `
        -Destination (Join-Path $thirdParty 'texture_rgba_renderer') -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'third_party\desktop_multi_window') `
        -Destination (Join-Path $thirdParty 'desktop_multi_window') -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'third_party\window_size') `
        -Destination (Join-Path $thirdParty 'window_size') -Recurse -Force

    $resolve = Start-Process -FilePath $flutter -ArgumentList @('pub', 'get', '--offline') `
        -WorkingDirectory $appRoot -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $outputRoot 'windows-presentation-pub.stdout.txt') `
        -RedirectStandardError (Join-Path $outputRoot 'windows-presentation-pub.stderr.txt')
    if ($resolve.ExitCode -ne 0) {
        Fail "offline Flutter dependency resolution failed with exit $($resolve.ExitCode)"
    }
    Copy-Item -LiteralPath (Join-Path $appRoot 'pubspec.lock') `
        -Destination (Join-Path $outputRoot 'windows-presentation-pubspec.lock') -Force

    $build = Start-Process -FilePath $flutter -ArgumentList @('build', 'windows', '--release', '--no-pub') `
        -WorkingDirectory $appRoot -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $outputRoot 'windows-presentation-build.stdout.txt') `
        -RedirectStandardError (Join-Path $outputRoot 'windows-presentation-build.stderr.txt')
    if ($build.ExitCode -ne 0) {
        Fail "native Windows Flutter probe build failed with exit $($build.ExitCode)"
    }
    Add-Content -LiteralPath (Join-Path $outputRoot 'windows-presentation-progress.txt') `
        -Value 'probe-built' -Encoding ASCII

    $releaseRoot = Join-Path $appRoot 'build\windows\x64\runner\Release'
    $executable = Join-Path $releaseRoot 'rustdesk_presentation_probe.exe'
    $pluginDll = Join-Path $releaseRoot 'texture_rgba_renderer_plugin.dll'
    $d3d11Preflight = Join-Path $releaseRoot 'rustdesk_d3d11_preflight.exe'
    foreach ($path in @($executable, $pluginDll, $d3d11Preflight)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Fail "native probe output is absent: $path"
        }
    }
    $d3d11PreflightOutput = Join-Path $outputRoot 'windows-presentation-d3d11-preflight.json'
    $d3d11PreflightRun = Start-Process -FilePath $d3d11Preflight -PassThru `
        -WorkingDirectory $releaseRoot `
        -RedirectStandardOutput $d3d11PreflightOutput `
        -RedirectStandardError (Join-Path $outputRoot 'windows-presentation-d3d11-preflight.stderr.txt')
    $d3d11PreflightExit = $null
    try {
        if (-not $d3d11PreflightRun.WaitForExit(30000)) {
            try {
                $d3d11PreflightRun.Kill()
                if (-not $d3d11PreflightRun.WaitForExit(5000)) {
                    Fail 'native D3D11 preflight did not exit after exact-process termination'
                }
            } catch {
                Fail "native D3D11 preflight timeout cleanup failed: $($_.Exception.Message)"
            }
            Fail 'native D3D11 preflight exceeded 30 seconds'
        }
        $d3d11PreflightRun.WaitForExit()
        $d3d11PreflightRun.Refresh()
        $d3d11PreflightExit = $d3d11PreflightRun.ExitCode
    } finally {
        $d3d11PreflightRun.Dispose()
    }
    if ($null -eq $d3d11PreflightExit -or $d3d11PreflightExit -isnot [int]) {
        Fail 'native D3D11 preflight produced no typed exit status'
    }
    if ($d3d11PreflightExit -ne 0) {
        Fail "native D3D11 preflight failed with exit $d3d11PreflightExit"
    }
    $d3d11Result = [IO.File]::ReadAllText($d3d11PreflightOutput, [Text.Encoding]::UTF8) | ConvertFrom-Json
    $rootProperties = @($d3d11Result.PSObject.Properties.Name)
    if (($rootProperties -join ',') -cne 'format,default_adapter,warp' -or
        $d3d11Result.format -cne 'rustdesk-windows-d3d11-preflight-v1') {
        Fail 'native D3D11 preflight result is malformed'
    }
    $attemptProperties = @(
        'name', 'window_hresult', 'factory_hresult', 'adapter_hresult',
        'device_hresult', 'swap_chain_hresult', 'window_association_hresult',
        'back_buffer_hresult', 'render_target_hresult', 'present_hresult',
        'dwm_flush_hresult', 'feature_level', 'adapter_flags',
        'adapter_description', 'desktop_pixel', 'pixel_matches'
    )
    $hresultProperties = @(
        'window_hresult', 'factory_hresult', 'adapter_hresult', 'device_hresult',
        'swap_chain_hresult', 'window_association_hresult', 'back_buffer_hresult',
        'render_target_hresult', 'present_hresult', 'dwm_flush_hresult'
    )
    $attempts = @(
        [PSCustomObject]@{
            Attempt = $d3d11Result.default_adapter
            ExpectedName = 'default-adapter'
        },
        [PSCustomObject]@{
            Attempt = $d3d11Result.warp
            ExpectedName = 'warp'
        }
    )
    foreach ($entry in $attempts) {
        $attempt = $entry.Attempt
        $expectedName = $entry.ExpectedName
        $actualProperties = @($attempt.PSObject.Properties.Name)
        if (($actualProperties -join ',') -cne ($attemptProperties -join ',') -or
            $attempt.name -cne $expectedName -or
            $attempt.feature_level -cnotmatch '^0x[0-9A-F]{8}$' -or
            $attempt.desktop_pixel -cnotmatch '^0x[0-9A-F]{8}$' -or
            $attempt.adapter_flags -is [bool] -or
            ($attempt.adapter_flags -isnot [int] -and $attempt.adapter_flags -isnot [long]) -or
            $attempt.adapter_flags -lt 0 -or $attempt.adapter_flags -gt 4294967295 -or
            $attempt.adapter_description -isnot [string] -or
            $attempt.pixel_matches -isnot [bool]) {
            Fail "native D3D11 $expectedName preflight result is malformed"
        }
        foreach ($property in $hresultProperties) {
            if ($attempt.$property -cnotmatch '^0x[0-9A-F]{8}$') {
                Fail "native D3D11 $expectedName preflight HRESULT is malformed: $property"
            }
        }
    }
    Add-Content -LiteralPath (Join-Path $outputRoot 'windows-presentation-progress.txt') `
        -Value 'd3d11-preflight' -Encoding ASCII
    $controller = Join-Path $sourceRoot 'scripts\flutter-presentation-probe-windows-controller.ps1'
    $focusSink = Join-Path $sourceRoot 'scripts\flutter-presentation-probe-windows-focus-sink.ps1'
    $controllerRun = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $controller,
            '-StateDirectory', $stateDirectory,
            '-Executable', $executable,
            '-FocusSinkScript', $focusSink,
            '-OutputDirectory', $outputRoot,
            '-SourceCommit', [string]$manifest.source_commit,
            '-SourceTree', [string]$manifest.source_tree
        ) -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $outputRoot 'windows-presentation-controller.stdout.txt') `
        -RedirectStandardError (Join-Path $outputRoot 'windows-presentation-controller.stderr.txt')
    Copy-ProbeState $stateDirectory $outputRoot
    if ($controllerRun.ExitCode -ne 0) {
        Fail "native Windows presentation controller failed with exit $($controllerRun.ExitCode)"
    }
    $result = Join-Path $outputRoot 'windows-presentation-result.json'
    if (-not (Test-Path -LiteralPath $result -PathType Leaf)) {
        Fail 'native Windows presentation result is absent'
    }
    Add-Content -LiteralPath (Join-Path $outputRoot 'windows-presentation-progress.txt') `
        -Value 'probe-passed' -Encoding ASCII
    $runnerSucceeded = $true
} catch {
    if ($null -ne $outputRoot) {
        try {
            Write-Ascii (Join-Path $outputRoot 'windows-presentation-runner-failure.txt') `
                "$($_.Exception.GetType().FullName): $($_.Exception.Message)`r`n"
            if ($null -ne $stateDirectory) {
                Copy-ProbeState $stateDirectory $outputRoot
            }
        } catch {
            Write-Error 'could not persist the presentation runner failure'
        }
    }
    Write-Error $_
} finally {
    if ($runnerSucceeded -and $null -ne $workRoot -and (Test-Path -LiteralPath $workRoot)) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
    Stop-Computer -Force
}
