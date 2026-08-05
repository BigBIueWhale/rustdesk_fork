$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

$form = New-Object System.Windows.Forms.Form
$form.Text = 'RustDesk Presentation Focus Sink'
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$form.Location = New-Object System.Drawing.Point(0, 0)
$form.Size = New-Object System.Drawing.Size(240, 140)
$form.TopMost = $true
$form.ShowInTaskbar = $true
$form.Add_Shown({
    $form.Activate()
    $form.Focus()
})
[System.Windows.Forms.Application]::Run($form)
