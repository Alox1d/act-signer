# Native WinForms regression check. Synthetic metadata only; no files or signing provider.
param(
    [string]$ModulePath = (Join-Path $PSScriptRoot 'ActSigner.UI.psm1'),
    [string]$ArtifactDirectory = (Join-Path $PSScriptRoot 'ui-test-artifacts')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Native Windows is required.' }
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) { throw 'Use powershell.exe -STA.' }
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[void][IO.Directory]::CreateDirectory($ArtifactDirectory)
$module = Import-Module $ModulePath -Force -PassThru
# These overrides live only in this imported module for this test process.
# Do not import Settings, CryptoPro, or the application entry point.
& $module {
    function script:Get-ActSignerSettings {
        [pscustomobject]@{ SourceRoot = 'C:\SyntheticActs'; SeparateOutputRoot = 'C:\SyntheticOutput'; SaveBesideSources = $false }
    }
    function script:Save-ActSignerSettings { param($SourceRoot, $SeparateOutputRoot, $SaveBesideSources) return $true }
}

$certificate = [pscustomobject]@{
    DisplayName = 'SYNTHETIC UI TEST'; Subject = 'CN=SYNTHETIC UI TEST'; Issuer = 'CN=SYNTHETIC TEST ISSUER'
    Thumbprint = '0000000000000000000000000000000000000000'; Source = 'Synthetic provider'; StoreKind = 'Synthetic'
    NotBefore = [datetime]'2026-01-01'; NotAfter = [datetime]'2030-01-01'
}
$items = @(for ($i = 0; $i -lt 20; $i++) {
    $relative = 'Synthetic-{0:D2}\Акт_оказанных_услуг.pdf' -f $i
    [pscustomobject]@{
        RelativePath = $relative; SourcePath = 'C:\SyntheticActs\' + $relative
        SignaturePath = 'C:\SyntheticOutput\' + $relative + '.my.sig'
        DocumentOutputPath = 'C:\SyntheticOutput\' + $relative; ExistingSignature = ($i -ge 16)
    }
})
$fixturePlan = [pscustomobject]@{
    Root = 'C:\SyntheticActs'; OutputRoot = 'C:\SyntheticOutput'; SeparateOutput = $true
    Items = $items; SkippedReparsePoints = @()
}
$certificateProvider = { [pscustomobject]@{ Certificates = @($certificate); Warnings = @() } }.GetNewClosure()
$planProvider = { param($SourceRoot, $DestinationRoot) return $fixturePlan }.GetNewClosure()
$state = @{ Phase = 0; Form = $null; Grid = $null; Controls = @(); Error = $null; Started = [datetime]::UtcNow }
$failures = New-Object 'System.Collections.Generic.List[string]'
$measurements = New-Object 'System.Collections.Generic.List[object]'
$assert = { param([bool]$Condition, [string]$Message) if (-not $Condition) { $failures.Add($Message) } }.GetNewClosure()
$walk = {
    param($Parent)
    $pending = New-Object 'System.Collections.Generic.Queue[System.Windows.Forms.Control]'
    $pending.Enqueue($Parent)
    while ($pending.Count -gt 0) {
        $control = $pending.Dequeue()
        $control
        foreach ($child in $control.Controls) { $pending.Enqueue($child) }
    }
}
$visibleRectangle = {
    param($Control)
    $rect = $Control.RectangleToScreen($Control.ClientRectangle)
    $ancestor = $Control.Parent
    while ($null -ne $ancestor) {
        $rect = [Drawing.Rectangle]::Intersect($rect, $ancestor.RectangleToScreen($ancestor.ClientRectangle))
        $ancestor = $ancestor.Parent
    }
    return $rect
}
$fullyVisible = {
    param($Control)
    $visible = & $visibleRectangle $Control
    return $Control.Visible -and $visible.Width -eq $Control.ClientSize.Width -and $visible.Height -eq $Control.ClientSize.Height
}.GetNewClosure()
$measure = {
    param([string]$Name, [int]$MinimumRows)
    $form = $state.Form
    $grid = $state.Grid
    $visible = & $visibleRectangle $grid
    $body = $grid.RectangleToScreen((New-Object Drawing.Rectangle(0, $grid.ColumnHeadersHeight, $grid.ClientSize.Width, [Math]::Max(0, $grid.ClientSize.Height - $grid.ColumnHeadersHeight))))
    $body = [Drawing.Rectangle]::Intersect($body, $visible)
    $fullRows = 0
    foreach ($row in $grid.Rows) {
        $rowRect = $grid.GetRowDisplayRectangle($row.Index, $false)
        if ($rowRect.Height -le 0) { continue }
        $rowRect = $grid.RectangleToScreen($rowRect)
        $intersection = [Drawing.Rectangle]::Intersect($body, $rowRect)
        if ($intersection.Height -eq $row.Height -and $intersection.Width -gt 0) { $fullRows++ }
    }
    $buttons = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and ($_.Text -eq 'Найти акты' -or $_.Text -eq 'Выбрать все новые' -or $_.Text -eq 'Снять выбор' -or $_ -eq $form.AcceptButton -or $_ -eq $form.CancelButton) })
    $buttonInfo = @($buttons | ForEach-Object { [pscustomobject]@{ Text = $_.Text; FullyVisible = [bool](& $fullyVisible $_); Enabled = $_.Enabled } })
    $measurements.Add([pscustomobject]@{
        Name = $Name; WindowWidth = $form.Width; WindowHeight = $form.Height
        ClientWidth = $form.ClientSize.Width; ClientHeight = $form.ClientSize.Height
        GridWidth = $grid.Width; GridHeight = $grid.Height; VisibleGridWidth = $visible.Width; VisibleGridHeight = $visible.Height
        VisibleBodyHeight = $body.Height; FullyVisibleRows = $fullRows; RequiredRows = $MinimumRows
        TotalRows = $grid.Rows.Count; Buttons = $buttonInfo
    })
    $bitmap = New-Object Drawing.Bitmap($form.Width, $form.Height)
    try {
        $form.DrawToBitmap($bitmap, (New-Object Drawing.Rectangle(0, 0, $bitmap.Width, $bitmap.Height)))
        $bitmap.Save((Join-Path $ArtifactDirectory ($Name + '.png')), [Drawing.Imaging.ImageFormat]::Png)
    }
    finally { $bitmap.Dispose() }
    & $assert ($fullRows -ge $MinimumRows) ($Name + ': only ' + $fullRows + ' complete act rows are visible; require ' + $MinimumRows + '.')
    & $assert ($buttonInfo.Count -eq 5) ($Name + ': expected five primary/selection buttons.')
    foreach ($button in $buttonInfo) { & $assert $button.FullyVisible ($Name + ': button is clipped: ' + $button.Text) }
}.GetNewClosure()

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 200
$timer.Add_Tick({
    try {
        if (([datetime]::UtcNow - $state.Started).TotalSeconds -gt 30) { throw 'UI test did not finish within 30 seconds.' }
        if ($state.Phase -eq 0) {
            $forms = @([System.Windows.Forms.Application]::OpenForms | Where-Object { $_ -is [System.Windows.Forms.Form] })
            if ($forms.Count -eq 0) { return }
            $form = $forms[0]
            $controls = @(& $walk $form)
            $grid = @($controls | Where-Object { $_ -is [System.Windows.Forms.DataGridView] -and $_.AccessibleName -eq 'Предварительный список актов' })
            if ($grid.Count -ne 1) { throw 'Expected one accessible act grid.' }
            $state.Form = $form; $state.Grid = $grid[0]; $state.Controls = $controls
            $form.WindowState = 'Normal'
            $form.Size = New-Object Drawing.Size(1000, 700)
            $find = @($controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -eq 'Найти акты' })[0]
            $find.PerformClick()
            & $assert ($state.Grid.Rows.Count -eq 20) 'The injected plan must populate all 20 acts.'
            $state.Phase = 1
            return
        }
        if ($state.Phase -eq 1) {
            & $measure '1000x700' 8
            $state.Form.Size = New-Object Drawing.Size(900, 600)
            $state.Phase = 2
            return
        }
        if ($state.Phase -eq 2) {
            & $measure '900x600' 5
            $grid = $state.Grid
            & $assert ($state.Form.AcceptButton.Enabled) 'Signing plan action must be enabled for a single synthetic cert and new acts.'
            $newRows = @($grid.Rows | Where-Object { [bool]$_.Cells[0].Value })
            & $assert ($newRows.Count -eq 16) 'Only the 16 new acts should initially be checked.'
            for ($i = 0; $i -lt $items.Count; $i++) {
                & $assert ([object]::ReferenceEquals($grid.Rows[$i].Tag, $items[$i])) ('Row Tag no longer maps to fixture item ' + $i)
                & $assert ([string]$grid.Rows[$i].Cells[1].Value -eq [string]$items[$i].RelativePath) ('Displayed path differs from row Tag at ' + $i)
                if ($i -ge 16) { & $assert $grid.Rows[$i].Cells[0].ReadOnly 'Existing signature checkbox must be read-only.' }
            }
            $clear = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -eq 'Снять выбор' })[0]
            $select = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -eq 'Выбрать все новые' })[0]
            $clear.PerformClick()
            & $assert (-not $state.Form.AcceptButton.Enabled) 'Zero checked acts must disable the plan action.'
            & $assert (@($grid.Rows | Where-Object { [bool]$_.Cells[0].Value }).Count -eq 0) 'Clear must uncheck all rows.'
            $select.PerformClick()
            & $assert (@($grid.Rows | Where-Object { [bool]$_.Cells[0].Value }).Count -eq 16) 'Select new must check only the new acts.'
            $clear.PerformClick()
            $grid.Rows[2].Cells[0].Value = $true
            $grid.Rows[7].Cells[0].Value = $true
            & $assert ($state.Form.AcceptButton.Text -eq 'Подписать 2 акта') 'Plan action must show the checkbox count.'
            # Show-ActSignerWindow only returns a plan. No signing/COM/PIN code is imported.
            $state.Phase = 3
            $timer.Stop()
            $state.Form.AcceptButton.PerformClick()
        }
    }
    catch {
        $state.Error = $_.Exception.ToString()
        $timer.Stop()
        foreach ($openForm in @([System.Windows.Forms.Application]::OpenForms)) { $openForm.Close() }
    }
}.GetNewClosure())

$result = $null
try {
    $timer.Start()
    $result = Show-ActSignerWindow -CertificateProvider $certificateProvider -PlanProvider $planProvider
    if ($null -ne $state.Error) { throw $state.Error }
    & $assert ($state.Phase -eq 3) 'All native UI phases must complete.'
    & $assert ($null -ne $result) 'The UI must return the selected plan.'
    if ($null -ne $result) {
        & $assert ($result.Plan.Items.Count -eq 2) 'Returned plan must contain exactly two checked acts.'
        & $assert ([object]::ReferenceEquals($result.Plan.Items[0], $items[2])) 'Returned first act must map to the row Tag.'
        & $assert ([object]::ReferenceEquals($result.Plan.Items[1], $items[7])) 'Returned second act must map to the row Tag.'
        & $assert ([object]::ReferenceEquals($result.CertificateInfo, $certificate)) 'Returned certificate must be the synthetic selection.'
        & $assert ([bool]$result.CopyOriginals) 'Separate-output choice must remain in the returned plan.'
    }
}
catch { $failures.Add($_.Exception.Message) }
finally {
    $timer.Stop(); $timer.Dispose()
    $report = [pscustomobject]@{ NativeWindows = $true; PowerShellVersion = $PSVersionTable.PSVersion.ToString(); Measurements = @($measurements.ToArray()); Failures = @($failures.ToArray()) }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ArtifactDirectory 'measurements.json') -Encoding UTF8
    Remove-Module $module -Force
}
foreach ($measurement in $measurements) { Write-Host ('MEASURE {0}: grid={1}x{2}, visible body={3}px, complete rows={4}' -f $measurement.Name, $measurement.GridWidth, $measurement.GridHeight, $measurement.VisibleBodyHeight, $measurement.FullyVisibleRows) }
if ($failures.Count -gt 0) { throw ('UI regression check failed:' + [Environment]::NewLine + ($failures.ToArray() -join [Environment]::NewLine)) }
Write-Host 'PASS: native Windows layout, checkbox counts, existing-signature protection, and selected plan mapping.'
