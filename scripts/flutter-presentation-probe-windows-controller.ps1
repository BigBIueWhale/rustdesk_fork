param(
    [Parameter(Mandatory = $true)][string]$StateDirectory,
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$FocusSinkScript,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$SourceCommit,
    [Parameter(Mandatory = $true)][string]$SourceTree
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class PresentationProbeNative {
    public delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr parameter);

    [StructLayout(LayoutKind.Sequential)]
    public struct Rect {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);

    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hwnd, int command);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetClassName(IntPtr hwnd, StringBuilder className, int maximumCount);

    [DllImport("user32.dll")]
    public static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll")]
    public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);

    [DllImport("user32.dll")]
    private static extern IntPtr GetDC(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern int ReleaseDC(IntPtr hwnd, IntPtr dc);

    [DllImport("gdi32.dll")]
    private static extern uint GetPixel(IntPtr dc, int x, int y);

    [DllImport("dwmapi.dll")]
    public static extern int DwmFlush();

    public static IntPtr[] VisibleWindowsForProcess(uint expectedProcessId) {
        var windows = new List<IntPtr>();
        EnumWindows(delegate(IntPtr hwnd, IntPtr parameter) {
            uint processId;
            GetWindowThreadProcessId(hwnd, out processId);
            if (processId == expectedProcessId && IsWindowVisible(hwnd)) {
                windows.Add(hwnd);
            }
            return true;
        }, IntPtr.Zero);
        return windows.ToArray();
    }

    public static uint DesktopPixel(int x, int y) {
        IntPtr dc = GetDC(IntPtr.Zero);
        if (dc == IntPtr.Zero) {
            throw new InvalidOperationException("GetDC returned null");
        }
        try {
            uint value = GetPixel(dc, x, y);
            if (value == 0xffffffffU) {
                throw new InvalidOperationException("GetPixel returned CLR_INVALID");
            }
            return value;
        } finally {
            if (ReleaseDC(IntPtr.Zero, dc) == 0) {
                throw new InvalidOperationException("ReleaseDC failed");
            }
        }
    }

    public static string WindowClass(IntPtr hwnd) {
        var value = new StringBuilder(256);
        if (GetClassName(hwnd, value, value.Capacity) == 0) {
            throw new InvalidOperationException("GetClassName returned zero");
        }
        return value.ToString();
    }
}
'@

function Fail([string]$Message) {
    throw "[windows-presentation-controller:FATAL] $Message"
}

function Get-MonotonicMilliseconds {
    return [long](([Diagnostics.Stopwatch]::GetTimestamp() * 1000.0) / [Diagnostics.Stopwatch]::Frequency)
}

function Get-MarkerPath([string]$Name) {
    if ($Name -cnotmatch '^[a-z0-9-]+$') {
        Fail "marker name is malformed: $Name"
    }
    return Join-Path $StateDirectory $Name
}

function Wait-Marker(
    [string]$Name,
    [string]$Expected,
    [int]$TimeoutMilliseconds = 30000,
    [Diagnostics.Process]$OwnedProcess = $null
) {
    $path = Get-MarkerPath $Name
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if ($null -ne $OwnedProcess -and $OwnedProcess.HasExited) {
            Fail "owned process $($OwnedProcess.Id) exited while waiting for marker $Name"
        }
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $value = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
            if ($value -cne $Expected) {
                Fail "marker $Name has unexpected contents"
            }
            return
        }
        Start-Sleep -Milliseconds 20
    }
    Fail "timed out waiting for marker $Name"
}

function Publish-Marker([string]$Name, [string]$Value) {
    $path = Get-MarkerPath $Name
    $temporary = Join-Path $StateDirectory ".$Name.$PID.tmp"
    $bytes = [Text.Encoding]::ASCII.GetBytes($Value)
    $published = $false
    try {
        $stream = [IO.File]::Open(
            $temporary,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        [IO.File]::Move($temporary, $path)
        $published = $true
    } finally {
        if (-not $published -and (Test-Path -LiteralPath $temporary -PathType Leaf)) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Wait-ProcessWindow([Diagnostics.Process]$Process, [int]$TimeoutMilliseconds = 30000) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if ($Process.HasExited) {
            Fail "process $($Process.Id) exited before its window appeared"
        }
        $windows = @([PresentationProbeNative]::VisibleWindowsForProcess([uint32]$Process.Id))
        if ($windows.Count -eq 1) {
            return [IntPtr]$windows[0]
        }
        if ($windows.Count -gt 1) {
            Fail "process $($Process.Id) owns more than one visible top-level window"
        }
        Start-Sleep -Milliseconds 20
    }
    Fail "timed out waiting for process $($Process.Id) window"
}

function Wait-Iconic([IntPtr]$Window, [bool]$Expected, [int]$TimeoutMilliseconds = 15000) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if ([PresentationProbeNative]::IsIconic($Window) -eq $Expected) {
            return
        }
        Start-Sleep -Milliseconds 20
    }
    Fail "window iconic state did not become $Expected"
}

function Wait-Foreground([IntPtr]$Window, [int]$TimeoutMilliseconds = 15000) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if ([PresentationProbeNative]::GetForegroundWindow() -eq $Window) {
            return
        }
        [void][PresentationProbeNative]::SetForegroundWindow($Window)
        Start-Sleep -Milliseconds 20
    }
    Fail 'the expected window did not become foreground'
}

function Get-WindowColors([IntPtr]$Window) {
    $rect = New-Object PresentationProbeNative+Rect
    if (-not [PresentationProbeNative]::GetWindowRect($Window, [ref]$rect)) {
        Fail 'GetWindowRect failed'
    }
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    if ($width -lt 300 -or $height -lt 240) {
        Fail "probe window is unexpectedly small: ${width}x${height}"
    }
    [void][PresentationProbeNative]::DwmFlush()
    $colors = @()
    foreach ($point in @(@(35, 35), @(65, 35), @(35, 65), @(65, 65))) {
        $x = $rect.Left + [int](($width * $point[0]) / 100)
        $y = $rect.Top + [int](($height * $point[1]) / 100)
        $pixel = [PresentationProbeNative]::DesktopPixel($x, $y)
        $colors += [ordered]@{
            red = [int]($pixel -band 0xff)
            green = [int](($pixel -shr 8) -band 0xff)
            blue = [int](($pixel -shr 16) -band 0xff)
        }
    }
    return @($colors)
}

function Test-Color([object[]]$Colors, [string]$Expected) {
    $matches = 0
    foreach ($color in $Colors) {
        $matchesCurrent = switch ($Expected) {
            'white' { $color.red -ge 220 -and $color.green -ge 220 -and $color.blue -ge 220 }
            'green' { $color.red -le 40 -and $color.green -ge 220 -and $color.blue -le 40 }
            'magenta' { $color.red -ge 220 -and $color.green -le 40 -and $color.blue -ge 220 }
            default { Fail "unknown expected color: $Expected" }
        }
        if ($matchesCurrent) {
            $matches++
        }
    }
    return $matches -ge 3
}

function Probe-Color([IntPtr]$Window, [string]$Expected, [int]$TimeoutMilliseconds) {
    $started = Get-MonotonicMilliseconds
    $deadline = $started + $TimeoutMilliseconds
    $last = @()
    do {
        $last = @(Get-WindowColors $Window)
        if (Test-Color $last $Expected) {
            return [ordered]@{
                visible = $true
                elapsed_ms = (Get-MonotonicMilliseconds) - $started
                samples = $last
            }
        }
        Start-Sleep -Milliseconds 20
    } while ((Get-MonotonicMilliseconds) -lt $deadline)
    return [ordered]@{
        visible = $false
        elapsed_ms = $TimeoutMilliseconds
        samples = $last
    }
}

function Require-Color([IntPtr]$Window, [string]$Expected, [int]$TimeoutMilliseconds) {
    $result = Probe-Color $Window $Expected $TimeoutMilliseconds
    if (-not $result.visible) {
        Fail "timed out waiting for $Expected compositor pixels"
    }
    return $result
}

function Stop-OwnedProcess([Diagnostics.Process]$Process) {
    if ($null -eq $Process -or $Process.HasExited) {
        return
    }
    $Process.Kill()
    if (-not $Process.WaitForExit(10000)) {
        Fail "owned process $($Process.Id) did not exit after Kill"
    }
}

function Write-Json([string]$Path, [object]$Value) {
    $json = ($Value | ConvertTo-Json -Depth 12 -Compress) + "`n"
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
}

foreach ($path in @($StateDirectory, $OutputDirectory)) {
    if (-not [IO.Path]::IsPathRooted($path) -or -not (Test-Path -LiteralPath $path -PathType Container)) {
        Fail "required directory is absent or not absolute: $path"
    }
}
foreach ($path in @($Executable, $FocusSinkScript)) {
    if (-not [IO.Path]::IsPathRooted($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Fail "required file is absent or not absolute: $path"
    }
}
if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$' -or $SourceTree -cnotmatch '^[0-9a-f]{40}$') {
    Fail 'source identity is malformed'
}

$app = $null
$focusSink = $null
$resultPath = Join-Path $OutputDirectory 'windows-presentation-result.json'
try {
    $appStdout = Join-Path $OutputDirectory 'windows-presentation-app.stdout.txt'
    $appStderr = Join-Path $OutputDirectory 'windows-presentation-app.stderr.txt'
    $app = Start-Process -FilePath $Executable -ArgumentList @($StateDirectory) `
        -WorkingDirectory (Split-Path -Parent $Executable) -PassThru `
        -RedirectStandardOutput $appStdout -RedirectStandardError $appStderr
    Wait-Marker 'window-role' "desktop-multi-window-subwindow`n" -OwnedProcess $app
    Wait-Marker 'window-admitted' "secondary-visible`n" -OwnedProcess $app
    $window = Wait-ProcessWindow $app
    $windowClass = [PresentationProbeNative]::WindowClass($window)
    if ($windowClass -cne 'RustdeskMultiWindow') {
        Fail "visible probe window class is $windowClass, expected RustdeskMultiWindow"
    }
    Wait-Marker 'initial-submitted' "white`n"
    $initial = Require-Color $window 'white' 15000

    Publish-Marker 'arm-1' "arm`n"
    Wait-Marker 'armed-1' "armed`n"
    if (-not [PresentationProbeNative]::ShowWindowAsync($window, 6)) {
        Fail 'ShowWindowAsync(SW_MINIMIZE) failed'
    }
    Wait-Iconic $window $true
    Publish-Marker 'hidden-1' "hidden`n"
    Wait-Marker 'updated-1' "frames=128`n"
    Start-Sleep -Milliseconds 1000
    if (-not [PresentationProbeNative]::ShowWindowAsync($window, 9)) {
        Fail 'ShowWindowAsync(SW_RESTORE) failed'
    }
    Wait-Iconic $window $false
    Wait-Foreground $window
    Wait-Marker 'rearm-requested-1' "requested`n"
    $cycle1Before = Probe-Color $window 'green' 1000
    Publish-Marker 'allow-rearm-1' "allow`n"
    $cycle1AllowedAt = Get-MonotonicMilliseconds
    Wait-Marker 'renotified-1' "accepted`n"
    $cycle1After = Require-Color $window 'green' 2500
    $cycle1VisibleAt = Get-MonotonicMilliseconds
    if (($cycle1VisibleAt - $cycle1AllowedAt) -gt 2500) {
        Fail 'minimize/restore presentation recovery exceeded 2500ms'
    }
    Publish-Marker 'displayed-1' "displayed`n"

    Publish-Marker 'arm-2' "arm`n"
    Wait-Marker 'armed-2' "armed`n"
    $focusSink = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $FocusSinkScript) `
        -NoNewWindow -PassThru
    $focusWindow = Wait-ProcessWindow $focusSink
    $focusWindowClass = [PresentationProbeNative]::WindowClass($focusWindow)
    if (-not $focusWindowClass.StartsWith('WindowsForms10.Window.', [StringComparison]::Ordinal)) {
        Fail "visible focus-sink window class is $focusWindowClass, expected WindowsForms10.Window.*"
    }
    Wait-Foreground $focusWindow
    Publish-Marker 'hidden-2' "hidden`n"
    Wait-Marker 'updated-2' "frames=128`n"
    Start-Sleep -Milliseconds 1000
    $cycle2WhileBlurred = Probe-Color $window 'magenta' 1000

    $rect = New-Object PresentationProbeNative+Rect
    if (-not [PresentationProbeNative]::GetWindowRect($window, [ref]$rect)) {
        Fail 'GetWindowRect failed before guest pointer injection'
    }
    $clickX = $rect.Left + [int](($rect.Right - $rect.Left) / 2)
    $clickY = $rect.Top + [int](($rect.Bottom - $rect.Top) / 2)
    if (-not [PresentationProbeNative]::SetCursorPos($clickX, $clickY)) {
        Fail 'SetCursorPos failed'
    }
    [PresentationProbeNative]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
    [PresentationProbeNative]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
    Wait-Foreground $window
    Wait-Marker 'pointer-down-2' "delivered`n"
    Wait-Marker 'rearm-requested-2' "requested`n"
    $cycle2Before = Probe-Color $window 'magenta' 1000
    Publish-Marker 'allow-rearm-2' "allow`n"
    $cycle2AllowedAt = Get-MonotonicMilliseconds
    Wait-Marker 'renotified-2' "accepted`n"
    $cycle2After = Require-Color $window 'magenta' 2500
    $cycle2VisibleAt = Get-MonotonicMilliseconds
    if (($cycle2VisibleAt - $cycle2AllowedAt) -gt 2500) {
        Fail 'focus-return presentation recovery exceeded 2500ms'
    }
    Publish-Marker 'displayed-2' "displayed`n"
    Wait-Marker 'app-finished' "ok`n"
    if (-not $app.WaitForExit(15000)) {
        Fail 'probe app did not exit after reporting completion'
    }
    if ($app.ExitCode -ne 0) {
        Fail "probe app exited with code $($app.ExitCode)"
    }

    $result = [ordered]@{
        format = 'rustdesk-windows-presentation-result-v1'
        verdict = 'pass'
        source_commit = $SourceCommit
        source_tree = $SourceTree
        real_windows_flutter_engine = $true
        production_event_window_class = 'RustdeskMultiWindow'
        real_desktop_multi_window_events = $true
        real_desktop_compositor_pixels = $true
        real_guest_pointer_input = $true
        no_guest_network_interface_expected = $true
        recovery_limit_ms = 2500
        initial = $initial
        cycles = @(
            [ordered]@{
                name = 'minimize-restore'
                queued_frames = 128
                visible_before_explicit_rearm = [bool]$cycle1Before.visible
                before_rearm_probe = $cycle1Before
                after_rearm = $cycle1After
                allowed_to_visible_ms = $cycle1VisibleAt - $cycle1AllowedAt
            },
            [ordered]@{
                name = 'focus-loss-real-pointer-return'
                queued_frames = 128
                visible_while_blurred = [bool]$cycle2WhileBlurred.visible
                visible_before_explicit_rearm = [bool]$cycle2Before.visible
                before_rearm_probe = $cycle2Before
                after_rearm = $cycle2After
                allowed_to_visible_ms = $cycle2VisibleAt - $cycle2AllowedAt
                pointer_down_delivered = $true
            }
        )
    }
    Write-Json $resultPath $result
    Write-Host 'WINDOWS_PRESENTATION_CONTROLLER_OK'
} catch {
    $failure = [ordered]@{
        format = 'rustdesk-windows-presentation-result-v1'
        verdict = 'fail'
        source_commit = $SourceCommit
        source_tree = $SourceTree
        error_type = $_.Exception.GetType().FullName
        error = $_.Exception.Message
    }
    try {
        Write-Json $resultPath $failure
    } catch {
        Write-Error 'could not write the controller failure result'
    }
    throw
} finally {
    Stop-OwnedProcess $focusSink
    Stop-OwnedProcess $app
}
