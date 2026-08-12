param(
    [Parameter(Mandatory = $true)][string]$StateDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

function Fail([string]$Message) {
    throw "[windows-full-peer-fixture:FATAL] $Message"
}

function Write-AtomicAscii([string]$Name, [string]$Value) {
    if ($Name -cnotmatch '^[a-z0-9-]+\.txt$') {
        Fail "invalid fixture state name: $Name"
    }
    $path = Join-Path $StateDirectory $Name
    $temporary = Join-Path $StateDirectory ".$Name.$PID.$([Guid]::NewGuid().ToString('N')).tmp"
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
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            [IO.File]::Replace($temporary, $path, $null)
        } else {
            [IO.File]::Move($temporary, $path)
        }
        $published = $true
    } finally {
        if (-not $published -and (Test-Path -LiteralPath $temporary -PathType Leaf)) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

if (-not [IO.Path]::IsPathRooted($StateDirectory) -or
    -not (Test-Path -LiteralPath $StateDirectory -PathType Container)) {
    Fail "fixture state directory is absent or not absolute: $StateDirectory"
}

$colors = @{
    teal = [Drawing.Color]::FromArgb(0, 238, 238)
    orange = [Drawing.Color]::FromArgb(255, 96, 0)
    violet = [Drawing.Color]::FromArgb(176, 0, 255)
    lime = [Drawing.Color]::FromArgb(96, 255, 0)
    pink = [Drawing.Color]::FromArgb(255, 0, 128)
    azure = [Drawing.Color]::FromArgb(0, 128, 255)
}

$form = New-Object Windows.Forms.Form
$form.Text = 'RustDesk Full Peer Presentation Fixture'
$form.StartPosition = [Windows.Forms.FormStartPosition]::Manual
$form.Location = New-Object Drawing.Point(0, 0)
$form.ClientSize = New-Object Drawing.Size(384, 384)
$form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::None
$form.TopMost = $true
$form.ShowInTaskbar = $true

$panel = New-Object Windows.Forms.Panel
$panel.Dock = [Windows.Forms.DockStyle]::Fill
$panel.BackColor = $colors.teal
$form.Controls.Add($panel)

$script:lastSequence = [Int64]-1
$script:moveCount = [Int64]0
$commandPath = Join-Path $StateDirectory 'command.txt'

$mouseMoveHandler = {
    $script:moveCount++
    Write-AtomicAscii 'move-count.txt' "$script:moveCount`n"
}
$panel.Add_MouseMove($mouseMoveHandler)

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 20
$timer.Add_Tick({
    if (-not (Test-Path -LiteralPath $commandPath -PathType Leaf)) {
        return
    }
    try {
        $command = [IO.File]::ReadAllText($commandPath, [Text.Encoding]::ASCII).Trim()
    } catch [IO.IOException] {
        return
    }
    if ($command -cnotmatch '^(0|[1-9][0-9]*) (teal|orange|violet|lime|pink|azure)$') {
        Fail 'fixture command is malformed'
    }
    $sequence = [Int64]$Matches[1]
    $name = [string]$Matches[2]
    if ($sequence -le $script:lastSequence) {
        return
    }
    $script:lastSequence = $sequence
    $panel.BackColor = $colors[$name]
    $panel.Refresh()
    Write-AtomicAscii 'applied.txt' "$sequence $name`n"
})

$form.Add_Shown({
    Write-AtomicAscii 'ready.txt' "ready`n"
    $timer.Start()
})
$form.Add_FormClosed({ $timer.Stop() })

[Windows.Forms.Application]::Run($form)
