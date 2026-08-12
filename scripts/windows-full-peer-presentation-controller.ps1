param(
    [Parameter(Mandatory = $true)][string]$ProbeBundle,
    [Parameter(Mandatory = $true)][string]$FixtureScript,
    [Parameter(Mandatory = $true)][string]$FocusSinkScript,
    [Parameter(Mandatory = $true)][string]$StateDirectory,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$SourceCommit,
    [Parameter(Mandatory = $true)][string]$SourceTree
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class FullPeerPresentationNative {
    public delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr parameter);

    [StructLayout(LayoutKind.Sequential)]
    public struct Rect {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TcpRowOwnerPid {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KeyboardInput {
        public ushort VirtualKey;
        public ushort ScanCode;
        public uint Flags;
        public uint Time;
        public UIntPtr ExtraInfo;
    }

    [StructLayout(LayoutKind.Explicit, Size = 32)]
    public struct InputUnion {
        [FieldOffset(0)] public KeyboardInput Keyboard;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Input {
        public uint Type;
        public InputUnion Union;
    }

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern bool IsWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool MoveWindow(IntPtr hwnd, int x, int y, int width, int height, bool repaint);

    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hwnd, int command);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetClassName(IntPtr hwnd, StringBuilder className, int maximumCount);

    [DllImport("user32.dll")]
    private static extern IntPtr GetDC(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern int ReleaseDC(IntPtr hwnd, IntPtr dc);

    [DllImport("gdi32.dll")]
    private static extern uint GetPixel(IntPtr dc, int x, int y);

    [DllImport("dwmapi.dll")]
    public static extern int DwmFlush();

    [DllImport("user32.dll")]
    public static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint count, Input[] inputs, int size);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table, ref uint size, bool order, uint addressFamily, int tableClass, uint reserved);

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

    public static uint ProcessIdForWindow(IntPtr hwnd) {
        uint processId;
        GetWindowThreadProcessId(hwnd, out processId);
        return processId;
    }

    public static string WindowClass(IntPtr hwnd) {
        var value = new StringBuilder(256);
        if (GetClassName(hwnd, value, value.Capacity) == 0) {
            throw new InvalidOperationException("GetClassName returned zero");
        }
        return value.ToString();
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

    private static ushort Port(uint value) {
        ushort narrowed = (ushort)value;
        return (ushort)((narrowed >> 8) | (narrowed << 8));
    }

    public static string[] TcpRowsForPort(ushort port) {
        const uint AF_INET = 2;
        const uint ERROR_INSUFFICIENT_BUFFER = 122;
        const int TCP_TABLE_OWNER_PID_ALL = 5;
        uint size = 0;
        uint status = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER || size < 4) {
            throw new InvalidOperationException("GetExtendedTcpTable sizing failed: " + status);
        }
        IntPtr buffer = Marshal.AllocHGlobal((int)size);
        try {
            status = GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (status != 0) {
                throw new InvalidOperationException("GetExtendedTcpTable failed: " + status);
            }
            uint count = (uint)Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf(typeof(TcpRowOwnerPid));
            var rows = new List<string>();
            long current = buffer.ToInt64() + 4;
            for (uint index = 0; index < count; index++, current += rowSize) {
                var row = (TcpRowOwnerPid)Marshal.PtrToStructure(new IntPtr(current), typeof(TcpRowOwnerPid));
                ushort local = Port(row.LocalPort);
                ushort remote = Port(row.RemotePort);
                if (local == port || remote == port) {
                    string localAddress = new System.Net.IPAddress(BitConverter.GetBytes(row.LocalAddr)).ToString();
                    string remoteAddress = new System.Net.IPAddress(BitConverter.GetBytes(row.RemoteAddr)).ToString();
                    rows.Add(row.State + ":" + localAddress + ":" + local + ":" + remoteAddress + ":" + remote + ":" + row.OwningPid);
                }
            }
            rows.Sort(StringComparer.Ordinal);
            return rows.ToArray();
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static void SendUnicode(string value) {
        const uint INPUT_KEYBOARD = 1;
        const uint KEYEVENTF_KEYUP = 2;
        const uint KEYEVENTF_UNICODE = 4;
        var inputs = new Input[value.Length * 2];
        for (int index = 0; index < value.Length; index++) {
            inputs[index * 2] = new Input {
                Type = INPUT_KEYBOARD,
                Union = new InputUnion {
                    Keyboard = new KeyboardInput { ScanCode = value[index], Flags = KEYEVENTF_UNICODE }
                }
            };
            inputs[index * 2 + 1] = new Input {
                Type = INPUT_KEYBOARD,
                Union = new InputUnion {
                    Keyboard = new KeyboardInput { ScanCode = value[index], Flags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP }
                }
            };
        }
        uint inserted = SendInput((uint)inputs.Length, inputs, Marshal.SizeOf(typeof(Input)));
        if (inserted != inputs.Length) {
            throw new InvalidOperationException("SendInput Unicode insertion failed: " + inserted + "/" + inputs.Length);
        }
    }

    public static void SendVirtualKey(ushort virtualKey) {
        const uint INPUT_KEYBOARD = 1;
        const uint KEYEVENTF_KEYUP = 2;
        var inputs = new Input[] {
            new Input {
                Type = INPUT_KEYBOARD,
                Union = new InputUnion { Keyboard = new KeyboardInput { VirtualKey = virtualKey } }
            },
            new Input {
                Type = INPUT_KEYBOARD,
                Union = new InputUnion { Keyboard = new KeyboardInput { VirtualKey = virtualKey, Flags = KEYEVENTF_KEYUP } }
            }
        };
        uint inserted = SendInput((uint)inputs.Length, inputs, Marshal.SizeOf(typeof(Input)));
        if (inserted != inputs.Length) {
            throw new InvalidOperationException("SendInput virtual-key insertion failed: " + inserted + "/" + inputs.Length);
        }
    }
}
'@

function Fail([string]$Message) {
    throw "[windows-full-peer-controller:FATAL] $Message"
}

function Get-MonotonicMilliseconds {
    return [long](([Diagnostics.Stopwatch]::GetTimestamp() * 1000.0) / [Diagnostics.Stopwatch]::Frequency)
}

function Wait-FileValue(
    [string]$Path,
    [string]$Expected,
    [int]$TimeoutMilliseconds,
    [Diagnostics.Process]$OwnedProcess = $null
) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if ($null -ne $OwnedProcess -and $OwnedProcess.HasExited) {
            Fail "owned process $($OwnedProcess.Id) exited while waiting for $Path"
        }
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try {
                $value = [IO.File]::ReadAllText($Path, [Text.Encoding]::ASCII)
                if ($value -ceq $Expected) {
                    return
                }
            } catch [IO.IOException] {
            }
        }
        Start-Sleep -Milliseconds 20
    }
    Fail "timed out waiting for exact state at $Path"
}

function Wait-FileIntegerAtLeast(
    [string]$Path,
    [Int64]$Minimum,
    [int]$TimeoutMilliseconds,
    [Diagnostics.Process]$OwnedProcess
) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if ($OwnedProcess.HasExited) {
            Fail "owned process $($OwnedProcess.Id) exited while waiting for $Path"
        }
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try {
                $value = [IO.File]::ReadAllText($Path, [Text.Encoding]::ASCII)
                if ($value -cmatch '^(0|[1-9][0-9]*)\n$' -and [Int64]$Matches[1] -ge $Minimum) {
                    return
                }
            } catch [IO.IOException] {
            }
        }
        Start-Sleep -Milliseconds 20
    }
    Fail "timed out waiting for integer state at $Path to reach $Minimum"
}

function Write-AtomicAscii([string]$Path, [string]$Value) {
    $temporary = "$Path.$PID.$([Guid]::NewGuid().ToString('N')).tmp"
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
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporary, $Path, $null)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
        $published = $true
    } finally {
        if (-not $published -and (Test-Path -LiteralPath $temporary -PathType Leaf)) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Wait-ProcessWindow(
    [Diagnostics.Process]$Process,
    [string]$ExpectedClassPrefix,
    [int]$TimeoutMilliseconds = 30000
) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if ($Process.HasExited) {
            Fail "process $($Process.Id) exited before its window appeared"
        }
        foreach ($window in @([FullPeerPresentationNative]::VisibleWindowsForProcess([uint32]$Process.Id))) {
            if ([FullPeerPresentationNative]::WindowClass($window).StartsWith(
                $ExpectedClassPrefix,
                [StringComparison]::Ordinal
            )) {
                return [IntPtr]$window
            }
        }
        Start-Sleep -Milliseconds 20
    }
    Fail "timed out waiting for process $($Process.Id) window class prefix $ExpectedClassPrefix"
}

function Get-ProbeProcessIds([string]$Executable, [int[]]$ExcludedIds) {
    $canonical = [IO.Path]::GetFullPath($Executable)
    return @(
        Get-Process -Name 'rustdesk' -ErrorAction SilentlyContinue |
            Where-Object {
                try {
                    [IO.Path]::GetFullPath($_.Path) -ceq $canonical -and
                        $ExcludedIds -notcontains $_.Id
                } catch {
                    $false
                }
            } |
            Sort-Object -Property Id |
            ForEach-Object { [int]$_.Id }
    )
}

function Wait-ProbeWindowClass(
    [string]$Executable,
    [int[]]$ExcludedIds,
    [string]$ExpectedClassPrefix,
    [int]$TimeoutMilliseconds = 30000
) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        foreach ($processId in @(Get-ProbeProcessIds $Executable $ExcludedIds)) {
            foreach ($window in @([FullPeerPresentationNative]::VisibleWindowsForProcess([uint32]$processId))) {
                if ([FullPeerPresentationNative]::WindowClass($window).StartsWith(
                    $ExpectedClassPrefix,
                    [StringComparison]::Ordinal
                )) {
                    return [IntPtr]$window
                }
            }
        }
        Start-Sleep -Milliseconds 20
    }
    Fail "timed out waiting for probe window class prefix $ExpectedClassPrefix"
}

function Wait-Foreground([IntPtr]$Window, [int]$TimeoutMilliseconds = 15000) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if ([FullPeerPresentationNative]::GetForegroundWindow() -eq $Window) {
            return
        }
        [void][FullPeerPresentationNative]::SetForegroundWindow($Window)
        Start-Sleep -Milliseconds 20
    }
    Fail 'expected window did not become foreground'
}

function Wait-Iconic([IntPtr]$Window, [bool]$Expected, [int]$TimeoutMilliseconds = 15000) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if ([FullPeerPresentationNative]::IsIconic($Window) -eq $Expected) {
            return
        }
        Start-Sleep -Milliseconds 20
    }
    Fail "viewer iconic state did not become $Expected"
}

function Invoke-RedirectedPassword(
    [string]$Executable,
    [string]$Password,
    [int]$TimeoutSeconds
) {
    $deadline = (Get-MonotonicMilliseconds) + ($TimeoutSeconds * 1000)
    $lastExit = $null
    do {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $Executable
        $start.Arguments = '--password-stdin'
        $start.WorkingDirectory = Split-Path -Parent $Executable
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardInput = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        try {
            if (-not $process.Start()) { Fail 'password provisioning process did not start' }
            $process.StandardInput.WriteLine($Password)
            $process.StandardInput.Close()
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(10000)) {
                try { $process.Kill() } finally { [void]$process.WaitForExit(5000) }
                Fail 'one password provisioning attempt exceeded ten seconds'
            }
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if ($stdout.Contains($Password) -or $stderr.Contains($Password)) {
                Fail 'password provisioning echoed the synthetic credential'
            }
            $lastExit = [int]$process.ExitCode
            if ($lastExit -eq 0 -and $stdout.Replace("`r`n", "`n") -ceq "Done!`n" -and
                $stderr.Length -eq 0) {
                return
            }
        } finally {
            $process.Dispose()
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-MonotonicMilliseconds) -lt $deadline)
    Fail "password provisioning did not reach the parked server IPC endpoint (last exit=$lastExit)"
}

function Clear-SensitiveString([ref]$Value) {
    if ($null -ne $Value.Value) {
        $Value.Value = ''
    }
}

function Find-PasswordEdit([IntPtr]$Window, [int]$TimeoutMilliseconds = 30000) {
    $deadline = (Get-MonotonicMilliseconds) + $TimeoutMilliseconds
    $root = [Windows.Automation.AutomationElement]::FromHandle($Window)
    if ($null -eq $root) { Fail 'viewer automation root is unavailable' }
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        $edits = $root.FindAll(
            [Windows.Automation.TreeScope]::Descendants,
            [Windows.Automation.Condition]::TrueCondition
        ) | Where-Object {
            $_.Current.ControlType -eq [Windows.Automation.ControlType]::Edit -and
            $_.Current.IsEnabled -and $_.Current.IsKeyboardFocusable -and
            $_.Current.IsPassword
        }
        if (@($edits).Count -eq 1) {
            return $edits[0]
        }
        if (@($edits).Count -gt 1) {
            Fail 'viewer exposes more than one enabled password edit'
        }
        Start-Sleep -Milliseconds 50
    }
    Fail 'timed out waiting for the real viewer password dialog'
}

function Get-Rgb([int]$X, [int]$Y) {
    $pixel = [FullPeerPresentationNative]::DesktopPixel($X, $Y)
    return [ordered]@{
        red = [int]($pixel -band 0xff)
        green = [int](($pixel -shr 8) -band 0xff)
        blue = [int](($pixel -shr 16) -band 0xff)
    }
}

function Get-ColorDistance([object]$Left, [object]$Right) {
    return [Math]::Abs([int]$Left.red - [int]$Right.red) +
        [Math]::Abs([int]$Left.green - [int]$Right.green) +
        [Math]::Abs([int]$Left.blue - [int]$Right.blue)
}

$palette = [ordered]@{
    teal = [ordered]@{ red = 0; green = 238; blue = 238 }
    orange = [ordered]@{ red = 255; green = 96; blue = 0 }
    violet = [ordered]@{ red = 176; green = 0; blue = 255 }
    lime = [ordered]@{ red = 96; green = 255; blue = 0 }
    pink = [ordered]@{ red = 255; green = 0; blue = 128 }
    azure = [ordered]@{ red = 0; green = 128; blue = 255 }
}

function Find-RemoteFixtureRect([IntPtr]$ViewerWindow, [string]$ColorName) {
    $windowRect = New-Object FullPeerPresentationNative+Rect
    if (-not [FullPeerPresentationNative]::GetWindowRect($ViewerWindow, [ref]$windowRect)) {
        Fail 'GetWindowRect failed while locating remote fixture'
    }
    $target = $palette[$ColorName]
    $best = $null
    [void][FullPeerPresentationNative]::DwmFlush()
    $scanRight = [Math]::Min($windowRect.Right - 80, $windowRect.Left + 450)
    $scanBottom = [Math]::Min($windowRect.Bottom - 80, $windowRect.Top + 450)
    for ($y = $windowRect.Top + 40; $y -lt $scanBottom; $y += 12) {
        for ($x = $windowRect.Left + 8; $x -lt $scanRight; $x += 12) {
            $first = Get-Rgb $x $y
            if ((Get-ColorDistance $first $target) -gt 90) { continue }
            $second = Get-Rgb ($x + 48) ($y + 48)
            $third = Get-Rgb ($x + 80) ($y + 80)
            $score = (Get-ColorDistance $first $target) +
                (Get-ColorDistance $second $target) +
                (Get-ColorDistance $third $target)
            if ($score -le 180 -and ($null -eq $best -or $score -lt $best.score)) {
                $best = [ordered]@{ x = $x; y = $y; score = $score }
            }
        }
    }
    if ($null -eq $best) {
        return $null
    }
    return [ordered]@{
        left = [int]$best.x
        top = [int]$best.y
        sample_x = [int]($best.x + 48)
        sample_y = [int]($best.y + 48)
    }
}

function Wait-RemoteColor(
    [IntPtr]$ViewerWindow,
    [string]$ColorName,
    [int]$TimeoutMilliseconds,
    [object]$KnownRect = $null
) {
    $started = Get-MonotonicMilliseconds
    $deadline = $started + $TimeoutMilliseconds
    $target = $palette[$ColorName]
    $last = $null
    while ((Get-MonotonicMilliseconds) -lt $deadline) {
        if (-not [FullPeerPresentationNative]::IsWindow($ViewerWindow)) {
            Fail 'viewer window disappeared while waiting for a remote frame'
        }
        [void][FullPeerPresentationNative]::DwmFlush()
        if ($null -eq $KnownRect) {
            $KnownRect = Find-RemoteFixtureRect $ViewerWindow $ColorName
        }
        if ($null -ne $KnownRect) {
            $last = Get-Rgb ([int]$KnownRect.sample_x) ([int]$KnownRect.sample_y)
            if ((Get-ColorDistance $last $target) -le 90) {
                return [ordered]@{
                    elapsed_ms = (Get-MonotonicMilliseconds) - $started
                    sample = $last
                    fixture_rect = $KnownRect
                }
            }
        }
        Start-Sleep -Milliseconds 20
    }
    Fail "timed out waiting for remote $ColorName pixels; last=$($last | ConvertTo-Json -Compress)"
}

function Set-FixtureColor([Int64]$Sequence, [string]$ColorName, [Diagnostics.Process]$Fixture) {
    $command = Join-Path $StateDirectory 'command.txt'
    $applied = Join-Path $StateDirectory 'applied.txt'
    Write-AtomicAscii $command "$Sequence $ColorName`n"
    Wait-FileValue $applied "$Sequence $ColorName`n" 5000 $Fixture
}

function Get-ExactTcpSession([int]$ServerPid, [int[]]$ViewerPids) {
    $rows = @([FullPeerPresentationNative]::TcpRowsForPort(21118))
    $liveRows = @($rows | Where-Object {
        $state = [int]$_.Split(':')[0]
        $state -eq 2 -or $state -eq 5
    })
    $serverListeners = @($liveRows | Where-Object {
        $parts = $_.Split(':')
        [int]$parts[0] -eq 2 -and $parts[1] -ceq '127.0.0.1' -and
            [int]$parts[2] -eq 21118 -and $parts[3] -ceq '0.0.0.0' -and
            [int]$parts[4] -eq 0 -and [int]$parts[5] -eq $ServerPid
    })
    $serverEstablished = @($liveRows | Where-Object {
        $parts = $_.Split(':')
        [int]$parts[0] -eq 5 -and $parts[1] -ceq '127.0.0.1' -and
            [int]$parts[2] -eq 21118 -and $parts[3] -ceq '127.0.0.1' -and
            [int]$parts[5] -eq $ServerPid
    })
    $viewerEstablished = @($liveRows | Where-Object {
        $parts = $_.Split(':')
        [int]$parts[0] -eq 5 -and $parts[1] -ceq '127.0.0.1' -and
            $parts[3] -ceq '127.0.0.1' -and [int]$parts[4] -eq 21118 -and
            $ViewerPids -contains [int]$parts[5]
    })
    if ($liveRows.Count -ne 3 -or $serverListeners.Count -ne 1 -or
        $serverEstablished.Count -ne 1 -or $viewerEstablished.Count -ne 1) {
        Fail "expected one exact established loopback peer session, rows=$($rows -join ',')"
    }
    return [ordered]@{
        listener_row = $serverListeners[0]
        server_row = $serverEstablished[0]
        viewer_row = $viewerEstablished[0]
    }
}

function Assert-TcpSessionUnchanged(
    [object]$Expected,
    [Diagnostics.Process]$ServerProcess,
    [Diagnostics.Process]$ViewerProcess
) {
    if ($ServerProcess.HasExited -or $ViewerProcess.HasExited) {
        Fail 'the exact server or viewer process generation exited during the peer transaction'
    }
    $current = Get-ExactTcpSession $ServerProcess.Id @($ViewerProcess.Id)
    if ($current.listener_row -cne $Expected.listener_row -or
        $current.server_row -cne $Expected.server_row -or
        $current.viewer_row -cne $Expected.viewer_row) {
        Fail 'the peer TCP session changed; reconnect is not valid presentation-recovery evidence'
    }
}

function Stop-OwnedProcess([Diagnostics.Process]$Process) {
    if ($null -eq $Process -or $Process.HasExited) { return }
    & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID ([string]$Process.Id) /T /F | Out-Null
    if ($LASTEXITCODE -ne 0 -and -not $Process.HasExited) {
        Fail "taskkill failed for owned process tree $($Process.Id) (exit=$LASTEXITCODE)"
    }
    if (-not $Process.WaitForExit(10000)) {
        Fail "owned process $($Process.Id) did not exit after termination"
    }
}

function Write-Json([string]$Path, [object]$Value) {
    $json = ($Value | ConvertTo-Json -Depth 12 -Compress) + "`n"
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
}

foreach ($path in @($ProbeBundle, $StateDirectory, $OutputDirectory)) {
    if (-not [IO.Path]::IsPathRooted($path) -or -not (Test-Path -LiteralPath $path -PathType Container)) {
        Fail "required directory is absent or not absolute: $path"
    }
}
foreach ($path in @($FixtureScript, $FocusSinkScript)) {
    if (-not [IO.Path]::IsPathRooted($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Fail "required script is absent or not absolute: $path"
    }
}
if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$' -or $SourceTree -cnotmatch '^[0-9a-f]{40}$') {
    Fail 'source identity is malformed'
}

$executable = Join-Path $ProbeBundle 'rustdesk.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    Fail "probe executable is absent: $executable"
}

$passwordBytes = New-Object byte[] 24
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $random.GetBytes($passwordBytes)
} finally {
    $random.Dispose()
}
$password = [Convert]::ToBase64String($passwordBytes)
[Array]::Clear($passwordBytes, 0, $passwordBytes.Length)

$fixture = $null
$server = $null
$viewer = $null
$viewerOwnedProcesses = @()
$viewerTcpProcess = $null
$focusSink = $null
$probeProcessAuthorityEstablished = $false
$resultPath = Join-Path $OutputDirectory 'windows-full-peer-presentation-result.json'
try {
    $preexistingProbePids = @(Get-ProbeProcessIds $executable @())
    if ($preexistingProbePids.Count -ne 0) {
        Fail "probe bundle already has a live RustDesk process: $($preexistingProbePids -join ',')"
    }
    $preexistingPortRows = @([FullPeerPresentationNative]::TcpRowsForPort(21118))
    if ($preexistingPortRows.Count -ne 0) {
        Fail "TCP port 21118 was not initially empty: $($preexistingPortRows -join ',')"
    }
    $probeProcessAuthorityEstablished = $true

    $fixture = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $FixtureScript,
        '-StateDirectory', $StateDirectory
    ) -PassThru -NoNewWindow
    Wait-FileValue (Join-Path $StateDirectory 'ready.txt') "ready`n" 15000 $fixture
    $fixtureWindow = Wait-ProcessWindow $fixture 'WindowsForms10.Window.'

    $serverStdout = Join-Path $OutputDirectory 'windows-full-peer-server.stdout.txt'
    $serverStderr = Join-Path $OutputDirectory 'windows-full-peer-server.stderr.txt'
    $server = Start-Process -FilePath $executable -ArgumentList @('--server') `
        -WorkingDirectory $ProbeBundle -PassThru `
        -RedirectStandardOutput $serverStdout -RedirectStandardError $serverStderr
    [void]$server.Handle
    Invoke-RedirectedPassword $executable $password 60
    $listenerDeadline = (Get-MonotonicMilliseconds) + 30000
    do {
        if ($server.HasExited) { Fail 'probe server exited before listener admission' }
        $rows = @([FullPeerPresentationNative]::TcpRowsForPort(21118))
        $listeners = @($rows | Where-Object {
            $parts = $_.Split(':')
            [int]$parts[0] -eq 2 -and $parts[1] -ceq '127.0.0.1' -and
                [int]$parts[2] -eq 21118 -and [int]$parts[5] -eq $server.Id
        })
        if ($listeners.Count -eq 1 -and $rows.Count -eq 1) { break }
        Start-Sleep -Milliseconds 50
    } while ((Get-MonotonicMilliseconds) -lt $listenerDeadline)
    if ($listeners.Count -ne 1 -or $rows.Count -ne 1) {
        Fail "probe server did not expose only its exact loopback listener: $($rows -join ',')"
    }

    $viewerStdout = Join-Path $OutputDirectory 'windows-full-peer-viewer.stdout.txt'
    $viewerStderr = Join-Path $OutputDirectory 'windows-full-peer-viewer.stderr.txt'
    $viewer = Start-Process -FilePath $executable -ArgumentList @('--connect', '127.0.0.1') `
        -WorkingDirectory $ProbeBundle -PassThru `
        -RedirectStandardOutput $viewerStdout -RedirectStandardError $viewerStderr
    [void]$viewer.Handle
    $viewerWindow = Wait-ProbeWindowClass $executable @($server.Id) 'RustdeskMultiWindow' 30000
    if (-not [FullPeerPresentationNative]::MoveWindow($viewerWindow, 420, 0, 900, 760, $true)) {
        Fail 'could not position the real viewer window'
    }
    Wait-Foreground $viewerWindow
    $passwordEdit = Find-PasswordEdit $viewerWindow
    $passwordEdit.SetFocus()
    [FullPeerPresentationNative]::SendUnicode($password)
    [FullPeerPresentationNative]::SendVirtualKey(0x0d)
    Clear-SensitiveString ([ref]$password)

    Set-FixtureColor 1 'teal' $fixture
    $initial = Wait-RemoteColor $viewerWindow 'teal' 30000
    $remoteRect = $initial.fixture_rect
    $viewerWindowPid = [int][FullPeerPresentationNative]::ProcessIdForWindow($viewerWindow)
    $viewerPids = @(Get-ProbeProcessIds $executable @($server.Id))
    if ($viewerPids.Count -eq 0) { Fail 'real viewer process family is empty after authentication' }
    $session = Get-ExactTcpSession $server.Id $viewerPids
    $viewerTcpPid = [int]$session.viewer_row.Split(':')[5]
    if ($viewerTcpPid -ne $viewerWindowPid) {
        Fail 'the real viewer window process is not the exact TCP-owning process generation'
    }
    foreach ($viewerPid in $viewerPids) {
        $owned = [Diagnostics.Process]::GetProcessById($viewerPid)
        [void]$owned.Handle
        if ($owned.HasExited -or
            [IO.Path]::GetFullPath($owned.Path) -cne [IO.Path]::GetFullPath($executable)) {
            $owned.Dispose()
            Fail "viewer process identity changed during admission: $viewerPid"
        }
        $viewerOwnedProcesses += $owned
    }
    $viewerTcpMatches = @($viewerOwnedProcesses | Where-Object { $_.Id -eq $viewerTcpPid })
    if ($viewerTcpMatches.Count -ne 1) {
        Fail 'the exact TCP-owning viewer process handle is not unique'
    }
    $viewerTcpProcess = $viewerTcpMatches[0]

    $focusSink = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $FocusSinkScript,
        '-X', '0', '-Y', '420'
    ) -NoNewWindow -PassThru
    $focusWindow = Wait-ProcessWindow $focusSink 'WindowsForms10.Window.'
    Wait-Foreground $focusWindow

    $unfocused = @()
    $sequence = [Int64]1
    $colorCycle = @('orange', 'violet', 'lime', 'pink', 'azure', 'teal')
    $unfocusedStarted = Get-MonotonicMilliseconds
    for ($index = 0; $index -lt 120; $index++) {
        $color = $colorCycle[$index % $colorCycle.Count]
        $sequence++
        Set-FixtureColor $sequence $color $fixture
        $observation = Wait-RemoteColor $viewerWindow $color 2500 $remoteRect
        if ($observation.elapsed_ms -gt 2500) {
            Fail "unfocused presentation update exceeded 2500ms: $color"
        }
        Assert-TcpSessionUnchanged $session $server $viewerTcpProcess
        if ([FullPeerPresentationNative]::GetForegroundWindow() -ne $focusWindow) {
            Fail 'real viewer or another window stole focus during the sustained unfocused stimulus'
        }
        $unfocused += [ordered]@{
            sequence = $index + 1
            color = $color
            elapsed_ms = $observation.elapsed_ms
            sample = $observation.sample
        }
        Start-Sleep -Milliseconds 500
    }
    $unfocusedDuration = (Get-MonotonicMilliseconds) - $unfocusedStarted
    if ($unfocusedDuration -lt 60000) {
        Fail 'sustained unfocused presentation stimulus did not last at least sixty seconds'
    }

    [void][FullPeerPresentationNative]::ShowWindowAsync($viewerWindow, 6)
    Wait-Iconic $viewerWindow $true
    $minimizedChanges = 0
    $minimizedStarted = Get-MonotonicMilliseconds
    for ($index = 0; $index -lt 20; $index++) {
        $color = $colorCycle[$index % $colorCycle.Count]
        $sequence++
        Set-FixtureColor $sequence $color $fixture
        $minimizedChanges++
        Start-Sleep -Milliseconds 500
    }
    $sequence++
    Set-FixtureColor $sequence 'lime' $fixture
    $minimizedChanges++
    Start-Sleep -Milliseconds 500
    $minimizedDuration = (Get-MonotonicMilliseconds) - $minimizedStarted
    if ($minimizedDuration -lt 10000) {
        Fail 'minimized presentation stimulus did not last at least ten seconds'
    }
    Assert-TcpSessionUnchanged $session $server $viewerTcpProcess
    $restoreStarted = Get-MonotonicMilliseconds
    [void][FullPeerPresentationNative]::ShowWindowAsync($viewerWindow, 9)
    Wait-Iconic $viewerWindow $false
    Wait-Foreground $viewerWindow
    $restoredQueuedFrame = Wait-RemoteColor $viewerWindow 'lime' 2500 $remoteRect
    $restoreElapsed = (Get-MonotonicMilliseconds) - $restoreStarted
    if ($restoreElapsed -gt 2500) {
        Fail 'real viewer minimize/restore presentation recovery exceeded 2500ms'
    }
    Assert-TcpSessionUnchanged $session $server $viewerTcpProcess
    $sequence++
    Set-FixtureColor $sequence 'azure' $fixture
    $postRestoreFrame = Wait-RemoteColor $viewerWindow 'azure' 2500 $remoteRect
    Assert-TcpSessionUnchanged $session $server $viewerTcpProcess

    $viewerRect = New-Object FullPeerPresentationNative+Rect
    if (-not [FullPeerPresentationNative]::GetWindowRect($viewerWindow, [ref]$viewerRect)) {
        Fail 'GetWindowRect failed before remote pointer proof'
    }
    if (-not [FullPeerPresentationNative]::SetCursorPos($viewerRect.Right - 80, $viewerRect.Bottom - 80)) {
        Fail 'SetCursorPos failed while parking the local pointer inside the viewer'
    }
    Start-Sleep -Milliseconds 250
    $moveBefore = 0
    $movePath = Join-Path $StateDirectory 'move-count.txt'
    if (Test-Path -LiteralPath $movePath -PathType Leaf) {
        $moveBefore = [Int64]([IO.File]::ReadAllText($movePath, [Text.Encoding]::ASCII).Trim())
    }
    $pointerX = [int]$remoteRect.sample_x
    $pointerY = [int]$remoteRect.sample_y
    if ($pointerX -lt $viewerRect.Left -or $pointerX -ge $viewerRect.Right -or
        $pointerY -lt $viewerRect.Top -or $pointerY -ge $viewerRect.Bottom) {
        Fail 'remote fixture sample is not inside the real viewer window'
    }
    if ($pointerX -ge 0 -and $pointerX -lt 384 -and
        $pointerY -ge 0 -and $pointerY -lt 384) {
        Fail 'local pointer stimulus overlaps the controlled source fixture'
    }
    if (-not [FullPeerPresentationNative]::SetCursorPos($pointerX, $pointerY)) {
        Fail 'SetCursorPos failed before remote input proof'
    }
    Wait-FileIntegerAtLeast $movePath ($moveBefore + 1) 5000 $fixture
    Assert-TcpSessionUnchanged $session $server $viewerTcpProcess

    $result = [ordered]@{
        format = 'rustdesk-windows-full-peer-presentation-result-v1'
        verdict = 'pass'
        source_commit = $SourceCommit
        source_tree = $SourceTree
        real_rustdesk_viewer = $true
        real_rustdesk_controlled_server = $true
        actual_capture_encode_keyed_transport_decode_flutter_texture = $true
        test_only_loopback_listener_feature = $true
        listener = '127.0.0.1:21118'
        no_guest_network_interface_expected = $true
        uninterrupted_tcp_session = $true
        tcp_session = $session
        password_typed_into_real_viewer_dialog = $true
        remote_input_delivered = $true
        recovery_limit_ms = 2500
        initial = $initial
        sustained_unfocused_duration_ms = $unfocusedDuration
        unfocused_updates = $unfocused
        minimize_restore = [ordered]@{
            queued_source_changes = $minimizedChanges
            minimized_duration_ms = $minimizedDuration
            queued_final_color = 'lime'
            restored_to_queued_final_ms = $restoreElapsed
            queued_final_observation = $restoredQueuedFrame
            post_restore_color = 'azure'
            post_restore_fresh_update_ms = $postRestoreFrame.elapsed_ms
            post_restore_observation = $postRestoreFrame
        }
    }
    Write-Json $resultPath $result
    Write-Host 'WINDOWS_FULL_PEER_PRESENTATION_CONTROLLER_OK'
} catch {
    $failure = [ordered]@{
        format = 'rustdesk-windows-full-peer-presentation-result-v1'
        verdict = 'fail'
        source_commit = $SourceCommit
        source_tree = $SourceTree
        error_type = $_.Exception.GetType().FullName
        error = $_.Exception.Message
    }
    try { Write-Json $resultPath $failure } catch {}
    throw
} finally {
    Clear-SensitiveString ([ref]$password)
    $cleanupFailures = New-Object 'System.Collections.Generic.List[string]'
    $ownedProcesses = @($focusSink) + @($viewerOwnedProcesses) + @($viewer, $server, $fixture)
    foreach ($ownedProcess in $ownedProcesses) {
        try {
            Stop-OwnedProcess $ownedProcess
        } catch {
            $cleanupFailures.Add($_.Exception.Message)
        }
    }
    foreach ($process in $ownedProcesses) {
        if ($null -ne $process) { [void]$process.Dispose() }
    }
    if ($probeProcessAuthorityEstablished) {
        foreach ($latePid in @(Get-ProbeProcessIds $executable @())) {
            $lateProcess = $null
            try {
                $lateProcess = [Diagnostics.Process]::GetProcessById($latePid)
                [void]$lateProcess.Handle
                Stop-OwnedProcess $lateProcess
            } catch {
                $cleanupFailures.Add($_.Exception.Message)
            } finally {
                if ($null -ne $lateProcess) { [void]$lateProcess.Dispose() }
            }
        }
    }
    if ($probeProcessAuthorityEstablished) {
        try {
            $survivingProbePids = @(Get-ProbeProcessIds $executable @())
            if ($survivingProbePids.Count -ne 0) {
                throw "probe bundle process survived exact cleanup: $($survivingProbePids -join ',')"
            }
            $liveRows = @([FullPeerPresentationNative]::TcpRowsForPort(21118) | Where-Object {
                $state = [int]$_.Split(':')[0]
                $state -eq 2 -or $state -eq 5
            })
            if ($liveRows.Count -ne 0) {
                throw "listener or established peer row survived exact process cleanup: $($liveRows -join ',')"
            }
        } catch {
            $cleanupFailures.Add($_.Exception.Message)
        }
    }
    if ($cleanupFailures.Count -ne 0) {
        throw "full-peer process cleanup failed: $($cleanupFailures -join '; ')"
    }
}
