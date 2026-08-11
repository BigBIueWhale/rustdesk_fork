# Exact installed-package/SCM credential transaction for the disposable, zero-NIC Windows build VM.
# This script is never run on the host. The main mode runs from the existing elevated interactive
# builder task inside a fresh CoW guest; the limited mode is invoked by a temporary least-privilege
# Task Scheduler task under that same interactive principal.
[CmdletBinding()]
param(
    [ValidateSet('Main', 'LimitedCredentialAttempt')]
    [string]$Mode = 'Main',
    [Parameter(Mandatory = $true)]
    [string]$ReceiptPath,
    [string]$InstalledExe,
    [string]$ProbeExe,
    [string]$PythonExe
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ServiceName = 'RustDesk'
$LimitedFixture = 'R-S11gj-Limited-Must-Fail-7x!'
$WrongImageFixture = 'R-S11gj-Wrong-Image-Must-Fail-8y!'
$FirstFixture = 'R-S11gj-First-Rotation-9z!'
$SecondFixture = 'R-S11gj-Second-Rotation-A0!'

function Fail([string]$Message) {
    throw "[installed-service-probe:FATAL] $Message"
}

function Get-OrdinaryPathItem([string]$Path, [bool]$RequireLeaf) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Fail 'path is empty' }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -cne $Path) { Fail "path is not canonical: $Path" }
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrEmpty($root)) { Fail "path has no volume root: $Path" }
    $current = $root
    foreach ($component in @($full.Substring($root.Length) -split '\\' | Where-Object { $_.Length -gt 0 })) {
        $current = Join-Path $current $component
        if (-not (Test-Path -LiteralPath $current)) { Fail "path component is absent: $current" }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "path traverses a reparse point: $current"
        }
    }
    $result = Get-Item -LiteralPath $full -Force
    if ($RequireLeaf -and $result.PSIsContainer) { Fail "path is not a file: $Path" }
    if (-not $RequireLeaf -and -not $result.PSIsContainer) { Fail "path is not a directory: $Path" }
    return $result
}

function Get-FileSha256([string]$Path) {
    [void](Get-OrdinaryPathItem $Path $true)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256([string]$Value) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        if ($null -ne $algorithm) { $algorithm.Dispose() }
    }
}

function Write-CanonicalJson([string]$Path, [object]$Value) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -cne $Path) { Fail "receipt path is not canonical: $Path" }
    $parent = [IO.Path]::GetDirectoryName($full)
    [void](Get-OrdinaryPathItem $parent $false)
    if (Test-Path -LiteralPath $full) { Fail "receipt path is occupied: $full" }
    $json = ($Value | ConvertTo-Json -Depth 10 -Compress) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = $null
    try {
        $stream = [IO.File]::Open(
            $full,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    [void](Get-OrdinaryPathItem $full $true)
}

$nativeSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace RustDeskInstalledServiceProbe {
    public sealed class ProcessProof {
        public uint ProcessId;
        public string ImagePath;
        public string UserSid;
        public bool Elevated;
        public ulong CreationTime;
    }

    public sealed class ServiceProof {
        public uint ServiceType;
        public uint StartType;
        public string BinaryPath;
        public string StartName;
        public uint State;
        public uint ProcessId;
        public ProcessProof Process;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct QUERY_SERVICE_CONFIG {
        internal uint ServiceType;
        internal uint StartType;
        internal uint ErrorControl;
        internal IntPtr BinaryPathName;
        internal IntPtr LoadOrderGroup;
        internal uint TagId;
        internal IntPtr Dependencies;
        internal IntPtr ServiceStartName;
        internal IntPtr DisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS_PROCESS {
        internal uint ServiceType;
        internal uint CurrentState;
        internal uint ControlsAccepted;
        internal uint Win32ExitCode;
        internal uint ServiceSpecificExitCode;
        internal uint CheckPoint;
        internal uint WaitHint;
        internal uint ProcessId;
        internal uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_ELEVATION {
        internal uint TokenIsElevated;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILETIME_VALUE {
        internal uint Low;
        internal uint High;
    }

    public static class Native {
        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint SERVICE_QUERY_CONFIG = 0x0001;
        private const uint SERVICE_QUERY_STATUS = 0x0004;
        private const int SC_STATUS_PROCESS_INFO = 0;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint TOKEN_QUERY = 0x0008;
        private const int TOKEN_ELEVATION_CLASS = 20;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int ERROR_INVALID_PARAMETER = 87;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManagerW(string machineName, string databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenServiceW(IntPtr manager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceConfigW(IntPtr service, IntPtr config, uint size, out uint needed);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceStatusEx(
            IntPtr service,
            int infoLevel,
            out SERVICE_STATUS_PROCESS status,
            uint size,
            out uint needed);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr token,
            int informationClass,
            out TOKEN_ELEVATION information,
            uint informationLength,
            out uint returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageNameW(
            IntPtr process,
            uint flags,
            StringBuilder imagePath,
            ref uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr process,
            out FILETIME_VALUE creation,
            out FILETIME_VALUE exit,
            out FILETIME_VALUE kernel,
            out FILETIME_VALUE user);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr value);

        private static void RequireHandle(IntPtr handle, string operation) {
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
            }
        }

        private static string WideString(IntPtr value) {
            return value == IntPtr.Zero ? String.Empty : Marshal.PtrToStringUni(value);
        }

        private static ulong FileTime(FILETIME_VALUE value) {
            return ((ulong)value.High << 32) | value.Low;
        }

        public static ProcessProof QueryProcess(uint processId) {
            IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            RequireHandle(process, "OpenProcess");
            IntPtr token = IntPtr.Zero;
            try {
                StringBuilder image = new StringBuilder(32768);
                uint imageLength = (uint)image.Capacity;
                if (!QueryFullProcessImageNameW(process, 0, image, ref imageLength)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryFullProcessImageNameW");
                }
                FILETIME_VALUE creation;
                FILETIME_VALUE exit;
                FILETIME_VALUE kernel;
                FILETIME_VALUE user;
                if (!GetProcessTimes(process, out creation, out exit, out kernel, out user)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcessTimes");
                }
                if (!OpenProcessToken(process, TOKEN_QUERY, out token)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken");
                }
                TOKEN_ELEVATION elevation;
                uint returned;
                if (!GetTokenInformation(
                    token,
                    TOKEN_ELEVATION_CLASS,
                    out elevation,
                    (uint)Marshal.SizeOf(typeof(TOKEN_ELEVATION)),
                    out returned)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation(TokenElevation)");
                }
                string sid;
                using (WindowsIdentity identity = new WindowsIdentity(token)) {
                    if (identity.User == null) {
                        throw new InvalidOperationException("process token has no user SID");
                    }
                    sid = identity.User.Value;
                }
                return new ProcessProof {
                    ProcessId = processId,
                    ImagePath = image.ToString(),
                    UserSid = sid,
                    Elevated = elevation.TokenIsElevated != 0,
                    CreationTime = FileTime(creation),
                };
            } finally {
                if (token != IntPtr.Zero) { CloseHandle(token); }
                CloseHandle(process);
            }
        }

        public static ProcessProof QueryCurrentProcess() {
            return QueryProcess((uint)Process.GetCurrentProcess().Id);
        }

        public static bool IsSameProcessGenerationLive(uint processId, ulong creationTime) {
            try {
                return QueryProcess(processId).CreationTime == creationTime;
            } catch (Win32Exception error) {
                if (error.NativeErrorCode == ERROR_INVALID_PARAMETER) { return false; }
                throw;
            }
        }

        public static ServiceProof QueryService(string serviceName) {
            IntPtr manager = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
            RequireHandle(manager, "OpenSCManagerW");
            IntPtr service = IntPtr.Zero;
            IntPtr buffer = IntPtr.Zero;
            try {
                service = OpenServiceW(manager, serviceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
                RequireHandle(service, "OpenServiceW");
                uint needed;
                if (QueryServiceConfigW(service, IntPtr.Zero, 0, out needed)) {
                    throw new InvalidOperationException("QueryServiceConfigW unexpectedly accepted a zero buffer");
                }
                if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 1048576) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryServiceConfigW(size)");
                }
                buffer = Marshal.AllocHGlobal((int)needed);
                if (!QueryServiceConfigW(service, buffer, needed, out needed)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryServiceConfigW");
                }
                QUERY_SERVICE_CONFIG config = (QUERY_SERVICE_CONFIG)Marshal.PtrToStructure(
                    buffer,
                    typeof(QUERY_SERVICE_CONFIG));
                SERVICE_STATUS_PROCESS status;
                uint returned;
                if (!QueryServiceStatusEx(
                    service,
                    SC_STATUS_PROCESS_INFO,
                    out status,
                    (uint)Marshal.SizeOf(typeof(SERVICE_STATUS_PROCESS)),
                    out returned)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryServiceStatusEx");
                }
                ProcessProof process = status.ProcessId == 0 ? null : QueryProcess(status.ProcessId);
                return new ServiceProof {
                    ServiceType = config.ServiceType,
                    StartType = config.StartType,
                    BinaryPath = WideString(config.BinaryPathName),
                    StartName = WideString(config.ServiceStartName),
                    State = status.CurrentState,
                    ProcessId = status.ProcessId,
                    Process = process,
                };
            } finally {
                if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); }
                if (service != IntPtr.Zero) { CloseServiceHandle(service); }
                CloseServiceHandle(manager);
            }
        }

        public static string[] ParseCommandLine(string commandLine) {
            if (String.IsNullOrEmpty(commandLine)) {
                throw new ArgumentException("command line is empty", "commandLine");
            }
            int count;
            IntPtr argv = CommandLineToArgvW(commandLine, out count);
            RequireHandle(argv, "CommandLineToArgvW");
            try {
                if (count <= 0 || count > 32) {
                    throw new InvalidOperationException("command line argument count is outside the probe bound");
                }
                List<string> values = new List<string>(count);
                for (int index = 0; index < count; index++) {
                    IntPtr value = Marshal.ReadIntPtr(argv, index * IntPtr.Size);
                    values.Add(Marshal.PtrToStringUni(value));
                }
                return values.ToArray();
            } finally {
                LocalFree(argv);
            }
        }
    }
}
'@

Add-Type -TypeDefinition $nativeSource -Language CSharp
Add-Type -AssemblyName System.ServiceProcess

function Invoke-RedirectedProcess {
    param(
        [string]$Path,
        [string]$Arguments,
        [AllowNull()][string]$InputLine,
        [int]$TimeoutSeconds
    )
    $item = Get-OrdinaryPathItem $Path $true
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 300) { Fail 'process timeout is outside the bound' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $item.FullName
    $start.Arguments = $Arguments
    $start.WorkingDirectory = $item.DirectoryName
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { Fail "process did not start: $Path" }
        if ($null -ne $InputLine) {
            $process.StandardInput.WriteLine($InputLine)
        }
        $process.StandardInput.Close()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } finally { [void]$process.WaitForExit(5000) }
            Fail "process exceeded its ${TimeoutSeconds}-second deadline: $Path $Arguments"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 65536 -or $stderr.Length -gt 65536) {
            Fail "process output exceeded the 64-KiB bound: $Path $Arguments"
        }
        return [PSCustomObject]@{
            ExitCode = [int]$process.ExitCode
            Stdout = [string]$stdout
            Stderr = [string]$stderr
        }
    } finally {
        $process.Dispose()
    }
}

function Assert-NoFixtureEcho([object]$Result, [string]$Fixture, [string]$Label) {
    if ($Result.Stdout.Contains($Fixture) -or $Result.Stderr.Contains($Fixture)) {
        Fail "$Label echoed the synthetic credential"
    }
}

function Invoke-PasswordMutation {
    param(
        [string]$Executable,
        [string]$Password,
        [bool]$ExpectSuccess,
        [string]$Label
    )
    $result = Invoke-RedirectedProcess $Executable '--password-stdin' $Password 60
    Assert-NoFixtureEcho $result $Password $Label
    $normalized = $result.Stdout.Replace("`r`n", "`n")
    if ($ExpectSuccess) {
        if ($result.ExitCode -ne 0 -or $normalized -cne "Done!`n" -or $result.Stderr.Length -ne 0) {
            Fail "$Label did not produce the exact successful password CLI result (exit=$($result.ExitCode))"
        }
    } else {
        if ($result.ExitCode -eq 0 -or $normalized -ceq "Done!`n") {
            Fail "$Label unexpectedly changed the service-owned credential"
        }
    }
    return $result
}

function Invoke-KeyProbe([string]$Password, [ValidateSet('ok', 'fail')][string]$Expectation) {
    [void](Get-OrdinaryPathItem $ProbeExe $true)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $last = $null
    do {
        $last = Invoke-RedirectedProcess $ProbeExe "127.0.0.1:21118 --password-stdin $Expectation" $Password 10
        Assert-NoFixtureEcho $last $Password "CPace $Expectation probe"
        if ($last.ExitCode -eq 0 -and $last.Stdout.Contains('probe_client: PASS')) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    Fail "CPace $Expectation probe did not reach its expected result (last exit=$($last.ExitCode))"
}

function Assert-SystemProcess([object]$Proof, [string]$ExpectedImage, [string]$Label) {
    if ($null -eq $Proof) { Fail "$Label has no process proof" }
    if (-not [string]::Equals($Proof.ImagePath, $ExpectedImage, [StringComparison]::OrdinalIgnoreCase)) {
        Fail "$Label image differs from the installed executable: $($Proof.ImagePath)"
    }
    if ($Proof.UserSid -cne 'S-1-5-18' -or -not $Proof.Elevated -or $Proof.CreationTime -eq 0) {
        Fail "$Label is not one exact elevated LocalSystem process generation"
    }
}

function Get-ExactServiceProof([string]$ExpectedExecutable) {
    $proof = [RustDeskInstalledServiceProbe.Native]::QueryService($ServiceName)
    $expectedBinary = "`"$ExpectedExecutable`" --service"
    if ($proof.ServiceType -ne 0x10 -or
        $proof.StartType -ne 2 -or
        $proof.BinaryPath -cne $expectedBinary -or
        $proof.StartName -cne 'LocalSystem' -or
        $proof.State -ne 4 -or
        $proof.ProcessId -eq 0) {
        Fail "SCM service configuration/status is not exact (type=$($proof.ServiceType), start=$($proof.StartType), binary=$($proof.BinaryPath), account=$($proof.StartName), state=$($proof.State), pid=$($proof.ProcessId))"
    }
    Assert-SystemProcess $proof.Process $ExpectedExecutable 'SCM supervisor'
    return $proof
}

function Get-ExactServiceChild([object]$ServiceProof, [string]$ExpectedExecutable) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $matches = @()
        foreach ($candidate in @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId = $($ServiceProof.ProcessId)")) {
            if ([string]::IsNullOrEmpty([string]$candidate.CommandLine)) { continue }
            $arguments = [RustDeskInstalledServiceProbe.Native]::ParseCommandLine([string]$candidate.CommandLine)
            if ($arguments.Count -ne 3 -or
                -not [string]::Equals($arguments[0], $ExpectedExecutable, [StringComparison]::OrdinalIgnoreCase) -or
                $arguments[1] -cne '--server' -or
                $arguments[2] -cne '--service-owned-server') {
                continue
            }
            $process = [RustDeskInstalledServiceProbe.Native]::QueryProcess([uint32]$candidate.ProcessId)
            Assert-SystemProcess $process $ExpectedExecutable 'service-owned server child'
            $matches += [PSCustomObject]@{
                ProcessId = [uint32]$candidate.ProcessId
                ParentProcessId = [uint32]$candidate.ParentProcessId
                CreationTime = [uint64]$process.CreationTime
            }
        }
        if ($matches.Count -eq 1) { return $matches[0] }
        if ($matches.Count -gt 1) { Fail 'SCM supervisor has multiple exact service-owned server children' }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    Fail 'SCM supervisor did not retain one exact service-owned server child'
}

function Quote-TaskArgument([string]$Value) {
    if ($Value.Contains('"') -or $Value.Contains("`r") -or $Value.Contains("`n")) {
        Fail 'Task Scheduler argument contains a forbidden character'
    }
    return '"' + $Value + '"'
}

function Invoke-LimitedTask([string]$ExpectedExecutable, [object]$MainToken, [string]$ProbeRoot) {
    $limitedReceipt = Join-Path $ProbeRoot 'limited-credential-result.json'
    if (Test-Path -LiteralPath $limitedReceipt) { Fail "limited receipt path is occupied: $limitedReceipt" }
    $scriptPath = [IO.Path]::GetFullPath($PSCommandPath)
    [void](Get-OrdinaryPathItem $scriptPath $true)
    $powerShellPath = [IO.Path]::Combine($PSHOME, 'powershell.exe')
    [void](Get-OrdinaryPathItem $powerShellPath $true)
    $userName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ([string]::IsNullOrWhiteSpace($userName)) { Fail 'current interactive account name is empty' }
    $taskName = "RustDeskInstalledProbe-$($env:RUSTDESK_BUILD_RUN_ID)"
    if ($taskName -cnotmatch '^RustDeskInstalledProbe-[0-9a-f-]{38}$') {
        Fail 'temporary Task Scheduler name is malformed'
    }
    $taskService = New-Object -ComObject 'Schedule.Service'
    $taskService.Connect()
    $folder = $taskService.GetFolder('\')
    $definition = $taskService.NewTask(0)
    $definition.RegistrationInfo.Description = 'RustDesk disposable installed-service least-privilege rejection probe'
    $definition.Principal.UserId = $userName
    $definition.Principal.LogonType = 3
    $definition.Principal.RunLevel = 0
    $definition.Settings.Enabled = $true
    $definition.Settings.Hidden = $true
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.ExecutionTimeLimit = 'PT2M'
    $action = $definition.Actions.Create(0)
    $action.Path = $powerShellPath
    $action.Arguments = @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        (Quote-TaskArgument $scriptPath),
        '-Mode',
        'LimitedCredentialAttempt',
        '-ReceiptPath',
        (Quote-TaskArgument $limitedReceipt),
        '-InstalledExe',
        (Quote-TaskArgument $ExpectedExecutable)
    ) -join ' '
    $registered = $null
    $registeredCreated = $false
    try {
        $registered = $folder.RegisterTaskDefinition($taskName, $definition, 2, $userName, $null, 3, $null)
        $registeredCreated = $true
        [void]$registered.Run($null)
        $deadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            Start-Sleep -Milliseconds 250
            $registered = $folder.GetTask($taskName)
            if ($registered.State -eq 3) { break }
            if ($registered.State -notin @(2, 4)) {
                Fail "least-privilege task entered unexpected state $($registered.State)"
            }
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($registered.State -ne 3) { Fail 'least-privilege task exceeded its deadline' }
        if ([int]$registered.LastTaskResult -ne 0) {
            Fail "least-privilege task failed with result $($registered.LastTaskResult)"
        }
        [void](Get-OrdinaryPathItem $limitedReceipt $true)
        $limited = Get-Content -LiteralPath $limitedReceipt -Raw | ConvertFrom-Json
        $fields = @($limited.PSObject.Properties.Name | Sort-Object)
        $expectedFields = @(
            'cli_exit_code',
            'cli_stderr_sha256',
            'cli_stdout_sha256',
            'elevated',
            'format',
            'rejected',
            'session_id',
            'user_sid'
        ) | Sort-Object
        if (($fields -join ',') -cne ($expectedFields -join ',') -or
            $limited.format -cne 'rustdesk-windows-limited-credential-probe-v1' -or
            $limited.user_sid -cne $MainToken.UserSid -or
            [int]$limited.session_id -ne [Diagnostics.Process]::GetCurrentProcess().SessionId -or
            $limited.elevated -ne $false -or
            $limited.rejected -ne $true -or
            [int]$limited.cli_exit_code -eq 0 -or
            [string]$limited.cli_stdout_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$limited.cli_stderr_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            Fail 'least-privilege credential receipt is not exact'
        }
        return $limited
    } finally {
        if ($registeredCreated) {
            try { $folder.DeleteTask($taskName, 0) } catch { Fail "temporary least-privilege task cleanup failed: $($_.Exception.Message)" }
        }
    }
}

function Invoke-LimitedCredentialAttempt {
    if ([string]::IsNullOrWhiteSpace($InstalledExe)) { Fail 'limited mode requires -InstalledExe' }
    $executable = (Get-OrdinaryPathItem ([IO.Path]::GetFullPath($InstalledExe)) $true).FullName
    $token = [RustDeskInstalledServiceProbe.Native]::QueryCurrentProcess()
    if ($token.Elevated) { Fail 'least-privilege Task Scheduler process unexpectedly has an elevated token' }
    $result = Invoke-PasswordMutation $executable $LimitedFixture $false 'least-privilege installed-image mutation'
    $receipt = [ordered]@{
        format = 'rustdesk-windows-limited-credential-probe-v1'
        user_sid = [string]$token.UserSid
        session_id = [int][Diagnostics.Process]::GetCurrentProcess().SessionId
        elevated = $false
        rejected = $true
        cli_exit_code = [int]$result.ExitCode
        cli_stdout_sha256 = Get-StringSha256 $result.Stdout
        cli_stderr_sha256 = Get-StringSha256 $result.Stderr
    }
    Write-CanonicalJson ([IO.Path]::GetFullPath($ReceiptPath)) $receipt
}

function Invoke-MainProbe {
    foreach ($name in @(
        'RUSTDESK_SOURCE_ROOT',
        'RUSTDESK_SOURCE_COMMIT',
        'RUSTDESK_SOURCE_TREE',
        'RUSTDESK_BUILD_RUN_ID',
        'RUSTDESK_TARGET'
    )) {
        if (-not (Test-Path "Env:$name") -or [string]::IsNullOrWhiteSpace((Get-Item "Env:$name").Value)) {
            Fail "required build identity environment variable is absent: $name"
        }
    }
    if ($env:RUSTDESK_SOURCE_COMMIT -cnotmatch '^[0-9a-f]{40}$' -or
        $env:RUSTDESK_SOURCE_TREE -cnotmatch '^[0-9a-f]{40}$' -or
        $env:RUSTDESK_BUILD_RUN_ID -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[AB]$' -or
        $env:RUSTDESK_TARGET -cne 'windows-x86_64') {
        Fail 'build identity environment is malformed'
    }
    $source = (Get-OrdinaryPathItem ([IO.Path]::GetFullPath($env:RUSTDESK_SOURCE_ROOT)) $false).FullName
    $receipt = [IO.Path]::GetFullPath($ReceiptPath)
    if (Test-Path -LiteralPath $receipt) { Fail "main receipt path is occupied: $receipt" }
    $python = (Get-OrdinaryPathItem ([IO.Path]::GetFullPath($PythonExe)) $true).FullName
    $probe = (Get-OrdinaryPathItem ([IO.Path]::GetFullPath($ProbeExe)) $true).FullName
    $script:ProbeExe = $probe
    $mainToken = [RustDeskInstalledServiceProbe.Native]::QueryCurrentProcess()
    if (-not $mainToken.Elevated -or $mainToken.CreationTime -eq 0) {
        Fail 'main installed-service probe is not running with the existing elevated builder token'
    }

    $dist = (Get-OrdinaryPathItem (Join-Path $source 'dist') $false).FullName
    $setupInput = (Get-OrdinaryPathItem (Join-Path $dist 'rustdesk-setup.exe') $true).FullName
    $msi = (Get-OrdinaryPathItem (Join-Path $dist 'rustdesk.msi') $true).FullName
    $builtExe = (Get-OrdinaryPathItem (Join-Path $source 'flutter\build\windows\x64\runner\Release\rustdesk.exe') $true).FullName
    $probeRoot = Join-Path $source 'target\windows-installed-service-probe'
    if (Test-Path -LiteralPath $probeRoot) { Fail "installed-service probe root is occupied: $probeRoot" }
    New-Item -ItemType Directory -Path $probeRoot | Out-Null
    $probeRoot = (Get-OrdinaryPathItem ([IO.Path]::GetFullPath($probeRoot)) $false).FullName
    $canonicalSetup = Join-Path $probeRoot 'rustdesk-setup.exe'
    $canonicalizer = (Get-OrdinaryPathItem (Join-Path $source 'scripts\canonicalize-pe.py') $true).FullName
    & $python -I -S $canonicalizer --output $canonicalSetup $setupInput
    if ($LASTEXITCODE -ne 0) { Fail "exact setup PE canonicalization failed with exit $LASTEXITCODE" }
    $canonicalSetup = (Get-OrdinaryPathItem ([IO.Path]::GetFullPath($canonicalSetup)) $true).FullName
    $setupSha256 = Get-FileSha256 $canonicalSetup
    $msiSha256 = Get-FileSha256 $msi

    $install = Invoke-RedirectedProcess $canonicalSetup '--silent-install' $null 300
    if ($install.ExitCode -ne 0) { Fail "canonical setup installation failed with exit $($install.ExitCode)" }

    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($programFiles)) { Fail 'Program Files known folder is empty' }
    $installRoot = [IO.Path]::GetFullPath((Join-Path $programFiles 'RustDesk'))
    [void](Get-OrdinaryPathItem $installRoot $false)
    $installed = (Get-OrdinaryPathItem (Join-Path $installRoot 'RustDesk.exe') $true).FullName
    $installedSha256 = Get-FileSha256 $installed
    $builtSha256 = Get-FileSha256 $builtExe
    if ($installedSha256 -cne $builtSha256) {
        Fail 'installed RustDesk executable bytes differ from the exact packaged build image'
    }

    $serviceBefore = Get-ExactServiceProof $installed
    $childBefore = Get-ExactServiceChild $serviceBefore $installed

    [void](Invoke-PasswordMutation $installed $FirstFixture $true 'first exact installed-image mutation')
    Invoke-KeyProbe $FirstFixture 'ok'

    $limited = Invoke-LimitedTask $installed $mainToken $probeRoot
    Invoke-KeyProbe $FirstFixture 'ok'
    Invoke-KeyProbe $LimitedFixture 'fail'

    $wrongRoot = Join-Path $probeRoot 'wrong-image'
    foreach ($entry in @(Get-ChildItem -LiteralPath $installRoot -Recurse -Force)) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "installed image tree contains a reparse point: $($entry.FullName)"
        }
    }
    Copy-Item -LiteralPath $installRoot -Destination $wrongRoot -Recurse
    $wrongExe = (Get-OrdinaryPathItem ([IO.Path]::GetFullPath((Join-Path $wrongRoot 'RustDesk.exe'))) $true).FullName
    if ((Get-FileSha256 $wrongExe) -cne $installedSha256) {
        Fail 'wrong-path negative fixture does not contain the exact installed executable bytes'
    }
    $wrongResult = Invoke-PasswordMutation $wrongExe $WrongImageFixture $false 'elevated copied-image mutation'
    Invoke-KeyProbe $FirstFixture 'ok'
    Invoke-KeyProbe $WrongImageFixture 'fail'

    [void](Invoke-PasswordMutation $installed $SecondFixture $true 'rotated exact installed-image mutation')
    Invoke-KeyProbe $SecondFixture 'ok'
    Invoke-KeyProbe $FirstFixture 'fail'

    $servicePreRestart = Get-ExactServiceProof $installed
    $childPreRestart = Get-ExactServiceChild $servicePreRestart $installed
    $controller = [System.ServiceProcess.ServiceController]::new($ServiceName)
    try {
        $controller.Refresh()
        if ($controller.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Fail 'SCM service was not running before the restart transaction'
        }
        $controller.Stop()
        $controller.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        $controller.Refresh()
        if ($controller.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Fail 'SCM service did not reach stopped finality'
        }
        if ([RustDeskInstalledServiceProbe.Native]::IsSameProcessGenerationLive(
                [uint32]$servicePreRestart.ProcessId,
                [uint64]$servicePreRestart.Process.CreationTime) -or
            [RustDeskInstalledServiceProbe.Native]::IsSameProcessGenerationLive(
                [uint32]$childPreRestart.ProcessId,
                [uint64]$childPreRestart.CreationTime)) {
            Fail 'SCM stop left the exact supervisor or retained child generation alive'
        }
        $controller.Start()
        $controller.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    } finally {
        $controller.Dispose()
    }

    $serviceAfter = Get-ExactServiceProof $installed
    $childAfter = Get-ExactServiceChild $serviceAfter $installed
    if (($serviceAfter.ProcessId -eq $servicePreRestart.ProcessId -and
            $serviceAfter.Process.CreationTime -eq $servicePreRestart.Process.CreationTime) -or
        ($childAfter.ProcessId -eq $childPreRestart.ProcessId -and
            $childAfter.CreationTime -eq $childPreRestart.CreationTime)) {
        Fail 'SCM restart reused an old supervisor or service-owned child generation'
    }
    Invoke-KeyProbe $SecondFixture 'ok'
    Invoke-KeyProbe $FirstFixture 'fail'

    $result = [ordered]@{
        format = 'rustdesk-windows-installed-service-probe-v1'
        source_commit = [string]$env:RUSTDESK_SOURCE_COMMIT
        source_tree = [string]$env:RUSTDESK_SOURCE_TREE
        build_run_id = [string]$env:RUSTDESK_BUILD_RUN_ID
        target = [string]$env:RUSTDESK_TARGET
        setup_sha256 = $setupSha256
        msi_sha256 = $msiSha256
        installed_exe_sha256 = $installedSha256
        built_exe_sha256 = $builtSha256
        installed_executable = $installed
        domain_network_interfaces = 0
        vnc_listen = '127.0.0.1'
        service_type = [int]$serviceAfter.ServiceType
        service_start_type = [int]$serviceAfter.StartType
        service_start_name = [string]$serviceAfter.StartName
        service_binary_path = [string]$serviceAfter.BinaryPath
        service_pid_before = [int64]$servicePreRestart.ProcessId
        service_creation_before = [uint64]$servicePreRestart.Process.CreationTime
        child_pid_before = [int64]$childPreRestart.ProcessId
        child_creation_before = [uint64]$childPreRestart.CreationTime
        service_pid_after = [int64]$serviceAfter.ProcessId
        service_creation_after = [uint64]$serviceAfter.Process.CreationTime
        child_pid_after = [int64]$childAfter.ProcessId
        child_creation_after = [uint64]$childAfter.CreationTime
        service_process_system = $true
        service_process_elevated = $true
        child_process_system = $true
        child_process_elevated = $true
        limited_same_principal = ([string]$limited.user_sid -ceq [string]$mainToken.UserSid)
        limited_same_session = ([int]$limited.session_id -eq [Diagnostics.Process]::GetCurrentProcess().SessionId)
        limited_token_elevated = $false
        limited_mutation_rejected = $true
        first_credential_preserved_after_limited_rejection = $true
        limited_fixture_rejected = $true
        copied_image_mutation_rejected = ($wrongResult.ExitCode -ne 0)
        first_credential_preserved_after_copied_image_rejection = $true
        copied_image_fixture_rejected = $true
        first_mutation_applied = $true
        first_credential_keyed_before_rotation = $true
        second_mutation_applied = $true
        second_credential_keyed_before_restart = $true
        first_credential_rejected_before_restart = $true
        scm_stop_retired_exact_generations = $true
        scm_restart_created_new_generations = $true
        second_credential_keyed_after_restart = $true
        first_credential_rejected_after_restart = $true
    }
    Write-CanonicalJson $receipt $result
    Write-Host '[installed-service-probe] exact installed SCM credential transaction passed'
}

try {
    if ($Mode -eq 'LimitedCredentialAttempt') {
        Invoke-LimitedCredentialAttempt
    } else {
        Invoke-MainProbe
    }
} catch {
    [Console]::Error.WriteLine("WINDOWS INSTALLED SERVICE PROBE ERROR: $($_.Exception.Message)")
    exit 1
}
