# Native WinForms regression check. Synthetic metadata only; no files or signing provider.
param(
    [string]$ModulePath = (Join-Path $PSScriptRoot 'ActSigner.UI.psm1'),
    [string]$ArtifactDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('CSPSigner-UI-' + [guid]::NewGuid().ToString('N')))
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
    function script:Save-ActSignerSettings { param($SourceRoot, $SeparateOutputRoot, $SaveBesideSources, $SignatureNaming) return $true }
}

$certificate = [pscustomobject]@{
    DisplayName = 'SYNTHETIC UI TEST'; Subject = 'CN=SYNTHETIC UI TEST'; Issuer = 'CN=SYNTHETIC TEST ISSUER'
    FileLabel = 'ivanov'; Thumbprint = '0000000000000000000000000000000000000000'; Source = 'Synthetic provider'; StoreKind = 'Synthetic'
    NotBefore = [datetime]'2026-01-01'; NotAfter = [datetime]'2030-01-01'
}
$items = @(for ($i = 0; $i -lt 20; $i++) {
    $relative = 'Synthetic-{0:D2}\Акт_оказанных_услуг.pdf' -f $i
    if($i -eq 4){$relative='old\backup.zip'}
    if($i -eq 5){$relative='old\backup.7z'}
    if($i -eq 6){$relative='old\backup.tar.gz'}
    [pscustomobject]@{
        RelativePath = $relative; SourcePath = 'C:\SyntheticActs\' + $relative
        SignaturePath = 'C:\SyntheticOutput\' + $relative + '.my.sig'
        DocumentOutputPath = 'C:\SyntheticOutput\' + $relative; ExistingSignature = ($i -ge 16)
        NeighborSignatureCount = $(if ($i -lt 4) { 2 } else { 0 })
    }
})
$fixturePlan = [pscustomobject]@{
    Root = 'C:\SyntheticActs'; OutputRoot = 'C:\SyntheticOutput'; SeparateOutput = $true
    Items = $items; SkippedReparsePoints = @()
}
$syntheticWarning = 'SYNTHETIC DIAGNOSTIC WARNING'
$syntheticReadError = 'SYNTHETIC CERTIFICATE READ FAILURE'
$certificateProvider = { [pscustomobject]@{ Certificates = @($certificate); Warnings = @($syntheticWarning) } }.GetNewClosure()
$providerCalls = @{ Count = 0; SourceRoot = ''; DestinationRoot = '' }
$planProvider = {
    param($SourceRoot, $DestinationRoot, $SignatureNaming, $SignerLabel, $SourceFiles, $Recurse)
    $providerCalls.SignatureNaming=$SignatureNaming; $providerCalls.SignerLabel=$SignerLabel
    $providerCalls.SourceFiles = @($SourceFiles); $providerCalls.Recurse = [bool]$Recurse
    $providerCalls.Count++
    $providerCalls.SourceRoot = [string]$SourceRoot
    $providerCalls.DestinationRoot = [string]$DestinationRoot
    return [pscustomobject]@{
        Root = $SourceRoot; OutputRoot = $DestinationRoot; SeparateOutput = ($SourceRoot -ne $DestinationRoot)
        Items = $fixturePlan.Items; SkippedReparsePoints = @(); AllFiles = $true; SourceFiles = @($SourceFiles); Recurse = [bool]$Recurse
    }
}.GetNewClosure()
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
    $requestedSize = $Name.Split('x')
    & $assert ($form.Width -eq [int]$requestedSize[0] -and $form.Height -eq [int]$requestedSize[1]) ($Name + ': actual outer form dimensions must equal the requested size, without MinimumSize expansion.')
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
    $buttons = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and ($_.Text -in @('Найти файлы','Обновить список') -or $_.Text -eq 'Выбрать файлы...' -or $_.Text -in @('Выбрать все доступные','Выбрать все') -or $_.Text -in @('Снять выбор','Снять все') -or $_ -eq $form.AcceptButton -or $_ -eq $form.CancelButton) })
    $buttonInfo = @($buttons | ForEach-Object { [pscustomobject]@{ Text = $_.Text; FullyVisible = [bool](& $fullyVisible $_); Enabled = $_.Enabled } })
    $namingBox = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.ComboBox] -and $_.AccessibleName -eq 'Signature filename format' })[0]
    $namingCaption = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Label] -and $_.Text -eq 'Имя подписи:' })[0]
    $captionTop = $namingCaption.PointToScreen([Drawing.Point]::Empty).Y
    $boxTop = $namingBox.PointToScreen([Drawing.Point]::Empty).Y
    & $assert ([Math]::Abs($captionTop - $boxTop) -lt 15) ($Name + ': filename convention caption must stay beside its selector when the toolbar wraps.')
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
    & $assert ($buttonInfo.Count -eq 6) ($Name + ': expected six primary/selection buttons.')
    foreach ($button in $buttonInfo) { & $assert $button.FullyVisible ($Name + ': button is clipped: ' + $button.Text) }
}.GetNewClosure()

$inspectDetails = {
    param([bool]$ReadFailure)
    $detailsButtons = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text.TrimEnd('.') -eq 'Подробнее' })
    if ($detailsButtons.Count -ne 1) { throw 'Expected one Details button.' }
    $detailsButton = $detailsButtons[0]
    & $assert ($detailsButton.Visible -and $detailsButton.Enabled) 'Details must remain available, including after certificate read failure.'
    $dialogState = @{ Dialog = $null; Error = $null; Seen = $false; Started = [datetime]::UtcNow }
    $dialogTimer = New-Object System.Windows.Forms.Timer
    $dialogTimer.Interval = 100
    $dialogTimer.Add_Tick({
        try {
            $dialogs = @([System.Windows.Forms.Application]::OpenForms | Where-Object { $_ -ne $state.Form })
            if ($dialogs.Count -eq 0) {
                if (([datetime]::UtcNow - $dialogState.Started).TotalSeconds -gt 5) { throw 'Details dialog did not appear.' }
                return
            }
            $dialog = $dialogs[0]
            $dialogState.Dialog = $dialog; $dialogState.Seen = $true
            & $assert $dialog.Modal 'Details must be modal.'
            & $assert ([object]::ReferenceEquals($dialog.Owner, $state.Form)) 'Details must be owned by the main form.'
            & $assert ($dialog.FormBorderStyle -eq [System.Windows.Forms.FormBorderStyle]::Sizable) 'Details must have a resizable border.'
            $texts = @((& $walk $dialog) | Where-Object { $_ -is [System.Windows.Forms.TextBox] -and $_.AccessibleName -eq 'Данные сертификата и диагностика' })
            & $assert ($texts.Count -eq 1) 'Details must expose the accessible certificate diagnostics text.'
            if ($texts.Count -eq 1) {
                $text = $texts[0]
                & $assert ($text.ReadOnly -and $text.Multiline) 'Certificate diagnostics must be a multiline read-only text box.'
                if ($ReadFailure) {
                    & $assert ($text.Text.Contains($syntheticReadError)) 'Details must retain the certificate read error.'
                    & $assert ($text.Text.Contains('Не удалось прочитать сертификаты.')) 'Details must explain the read failure.'
                }
                else {
                    foreach ($expected in @($certificate.Subject, $certificate.Issuer, $certificate.Thumbprint, $certificate.Source, $syntheticWarning)) {
                        & $assert ($text.Text.Contains([string]$expected)) ('Details omitted synthetic metadata: ' + $expected)
                    }
                }
                $originalSize = $dialog.Size
                $dialog.Size = New-Object Drawing.Size(($originalSize.Width + 40), ($originalSize.Height + 40))
                & $assert ($dialog.Width -gt $originalSize.Width -and $dialog.Height -gt $originalSize.Height) 'Details must accept a larger size.'
                & $assert ([bool](& $fullyVisible $text)) 'Details text must stay within the resized dialog.'
            }
            $close = $dialog.CancelButton
            & $assert ($null -ne $close -and $close -is [System.Windows.Forms.Button]) 'Details must assign its Close button as the Escape action.'
            & $assert ([object]::ReferenceEquals($dialog.AcceptButton, $close)) 'Details must assign the same Close button as its Enter action.'
            if ($null -ne $close) { & $assert ([bool](& $fullyVisible $close)) 'Details Close button must be visible.' }
            $dialogTimer.Stop()
            if ($null -ne $close) { $close.PerformClick() } else { $dialog.Close() }
        }
        catch {
            $dialogState.Error = $_.Exception.ToString()
            $dialogTimer.Stop()
            foreach ($dialog in @([System.Windows.Forms.Application]::OpenForms | Where-Object { $_ -ne $state.Form })) { $dialog.Close() }
        }
    }.GetNewClosure())
    try {
        $dialogTimer.Start()
        $detailsButton.PerformClick()
        if ($null -ne $dialogState.Error) { throw $dialogState.Error }
        & $assert $dialogState.Seen 'Details button must open a dialog.'
        if ($null -ne $dialogState.Dialog) { & $assert $dialogState.Dialog.IsDisposed 'Details dialog must be disposed after closing.' }
    }
    finally { $dialogTimer.Stop(); $dialogTimer.Dispose() }
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
            $grid = @($controls | Where-Object { $_ -is [System.Windows.Forms.DataGridView] -and $_.AccessibleName -eq 'Предварительный список файлов' })
            if ($grid.Count -ne 1) { throw 'Expected one accessible act grid.' }
            $state.Form = $form; $state.Grid = $grid[0]; $state.Controls = $controls
            & $assert ($form.Text.StartsWith('CSPSigner ')) 'The application window must show the new product name.'
            $form.WindowState = 'Normal'
            $form.Size = New-Object Drawing.Size(1000, 700)
            $find = @($controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -in @('Найти файлы','Обновить список') })[0]
            $naming=@($controls | Where-Object { $_ -is [System.Windows.Forms.ComboBox] -and $_.AccessibleName -eq 'Signature filename format' })
            & $assert ($naming.Count -eq 1) 'A persistent filename format choice must be available.'
            if($naming.Count -ne 1){throw 'Missing signature naming control'}
            & $assert ($naming[0].SelectedIndex -eq 0 -and $naming[0].Items.Count -eq 4) 'Default naming must retain the full filename and expose the three previous conventions.'
            $naming[0].SelectedIndex=2
            $find.PerformClick()
            & $assert ($providerCalls.SignatureNaming -ceq 'document_signer' -and $providerCalls.SignerLabel -ceq 'ivanov') 'The plan must use the selected format and selected certificate surname.'
            & $assert ($state.Grid.Rows.Count -eq 20) 'The injected plan must populate all 20 acts.'
            & $assert ([string]$state.Grid.Rows[0].Cells[2].Value -eq 'Проверить подписи (2)') 'Neighboring signatures must be visible as pending inspection.'
            & $assert ([bool]$state.Grid.Rows[0].Cells[0].Value -and -not $state.Grid.Rows[0].Cells[0].ReadOnly) 'Unverified neighboring files must not be treated as already-signed acts in the preview.'
            & $assert ($state.Grid.Rows[0].Cells[2].ToolTipText.Contains('выбранным сертификатом')) 'Pending inspection tooltip must explain the selected-certificate duplicate rule.'
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
            # A nested timer inspects the real owned modal while ShowDialog runs.
            $state.Phase = 20
            & $inspectDetails $false
            $output = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.TextBox] -and $_.AccessibleName -eq 'Папка для файлов и подписей' })[0]
            $beside = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.CheckBox] -and $_.Text -eq 'Сохранять рядом с исходниками' })[0]
            $find = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -in @('Найти файлы','Обновить список') })[0]
            if ($output.Parent -isnot [System.Windows.Forms.TableLayoutPanel]) { throw 'Separate-output field must be in its folder table.' }
            $outputRow = $output.Parent.GetRow($output)
            $outputControls = @($output.Parent.Controls | Where-Object { $output.Parent.GetRow($_) -eq $outputRow })
            & $assert ($outputControls.Count -ge 3) 'Expected output label, field, and browse button in the separate-output row.'
            $priorOutput = 'C:\SyntheticPreviousOutput'
            $output.Text = $priorOutput
            $find.PerformClick()
            & $assert ($state.Grid.Rows.Count -eq 20) 'Refind after editing the separate-output path must populate the plan.'
            $beside.Checked = $true
            & $assert ($state.Grid.Rows.Count -eq 0 -and -not $state.Form.AcceptButton.Enabled) 'Enabling beside-source mode must invalidate the old plan.'
            foreach ($control in $outputControls) { & $assert (-not $control.Visible) 'Separate-output controls must be hidden in beside-source mode.' }
            $find.PerformClick()
            & $assert ($providerCalls.DestinationRoot -eq $providerCalls.SourceRoot) 'Beside-source search must use the source as the destination.'
            & $assert ($state.Grid.Rows.Count -eq 20) 'Beside-source mode must support refinding the acts.'
            $beside.Checked = $false
            & $assert ($state.Grid.Rows.Count -eq 0 -and -not $state.Form.AcceptButton.Enabled) 'Restoring separate-output mode must invalidate the old plan.'
            foreach ($control in $outputControls) { & $assert $control.Visible 'Separate-output controls must reappear after restoring the mode.' }
            & $assert ($output.Text -eq $priorOutput) 'The prior separate-output path must survive a mode round trip.'
            & $assert $output.Enabled 'Restored separate-output field must be editable.'
            $find.PerformClick()
            & $assert ($providerCalls.DestinationRoot -eq $priorOutput) 'Refind must use the restored separate-output path.'
            & $assert ($state.Grid.Rows.Count -eq 20) 'Restored separate-output mode must support refinding.'
            $grid = $state.Grid
            & $assert ($state.Form.AcceptButton.Enabled) 'Signing plan action must be enabled for a single synthetic cert and new acts.'
            $newRows = @($grid.Rows | Where-Object { [bool]$_.Cells[0].Value })
            & $assert ($newRows.Count -eq 13) 'Folder discovery must preselect new documents while leaving three archives unchecked.'
            foreach($index in @(4,5,6)){& $assert (-not [bool]$grid.Rows[$index].Cells[0].Value) 'Archive files must stay visible without a default signing checkbox.'}
            for ($i = 0; $i -lt $items.Count; $i++) {
                & $assert ([object]::ReferenceEquals($grid.Rows[$i].Tag, $items[$i])) ('Row Tag no longer maps to fixture item ' + $i)
                & $assert ([string]$grid.Rows[$i].Cells[1].Value -eq [string]$items[$i].RelativePath) ('Displayed path differs from row Tag at ' + $i)
                if ($i -ge 16) { & $assert (-not $grid.Rows[$i].Cells[0].ReadOnly) 'Existing signature must remain selectable for key-free verification.' }
            }
            $clear = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -in @('Снять выбор','Снять все') })[0]
            $select = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -in @('Выбрать все доступные','Выбрать все') })[0]
            $grid.CurrentCell=$grid.Rows[2].Cells[1]
            $grid.ClearSelection()
            foreach($index in @(2,9,13)){$grid.Rows[$index].Selected=$true}
            & $assert ($grid.SelectedRows.Count -eq 3) 'Users must be able to highlight multiple file rows.'
            $key=[Windows.Forms.KeyEventArgs]::new([Windows.Forms.Keys]::Space)
            $onKey=$grid.GetType().GetMethod('OnKeyDown',[Reflection.BindingFlags]'Instance,NonPublic')
            [void]$onKey.Invoke($grid,[object[]]@($key))
            foreach($index in @(2,9,13)){& $assert (-not [bool]$grid.Rows[$index].Cells[0].Value) 'Space must remove checkboxes from every highlighted row.'}
            & $assert ([bool]$grid.Rows[3].Cells[0].Value -and [bool]$grid.Rows[14].Cells[0].Value) 'Group checkbox changes must leave unrelated rows unchanged.'
            $menu=$grid.ContextMenuStrip
            & $assert ($null -ne $menu) 'Highlighted rows must offer checkbox actions through their context menu.'
            if($null -ne $menu){
                $mark=@($menu.Items | Where-Object {$_.Text -eq 'Отметить выделенные'})
                $unmark=@($menu.Items | Where-Object {$_.Text -eq 'Снять галочки с выделенных'})
                & $assert ($mark.Count -eq 1 -and $unmark.Count -eq 1) 'The group menu must support both checking and unchecking.'
                if($mark.Count -eq 1 -and $unmark.Count -eq 1){
                    $mark[0].PerformClick()
                    foreach($index in @(2,9,13)){& $assert ([bool]$grid.Rows[$index].Cells[0].Value) 'The context menu must check every highlighted row.'}
                    $unmark[0].PerformClick()
                    foreach($index in @(2,9,13)){& $assert (-not [bool]$grid.Rows[$index].Cells[0].Value) 'The context menu must uncheck every highlighted row.'}
                    $mouse=[Windows.Forms.MouseEventArgs]::new([Windows.Forms.MouseButtons]::Right,1,0,0,0)
                    $cellMouse=[Windows.Forms.DataGridViewCellMouseEventArgs]::new(1,14,0,0,$mouse)
                    [void]$grid.GetType().GetMethod('OnCellMouseDown',[Reflection.BindingFlags]'Instance,NonPublic',$null,[type[]]@([Windows.Forms.DataGridViewCellMouseEventArgs]),$null).Invoke($grid,[object[]]@($cellMouse))
                    & $assert ($grid.SelectedRows.Count -eq 1 -and $grid.Rows[14].Selected) 'Right-clicking an unhighlighted file must target that file rather than the previous group.'
                    $unmark[0].PerformClick()
                    & $assert (-not [bool]$grid.Rows[14].Cells[0].Value -and [bool]$grid.Rows[3].Cells[0].Value) 'The context menu must act on its clicked file without changing unrelated files.'
                }
            }
            $clear.PerformClick()
            & $assert (-not $state.Form.AcceptButton.Enabled) 'Zero checked acts must disable the plan action.'
            & $assert (@($grid.Rows | Where-Object { [bool]$_.Cells[0].Value }).Count -eq 0) 'Clear must uncheck all rows.'
            $select.PerformClick()
            & $assert (@($grid.Rows | Where-Object { [bool]$_.Cells[0].Value }).Count -eq 20) 'Select all must include existing signatures for verification.'
            $clear.PerformClick()
            $grid.Rows[2].Cells[0].Value = $true
            $grid.Rows[19].Cells[0].Value = $true
            & $assert ($state.Form.AcceptButton.Text -eq 'Проверить и подписать (2)') 'Plan action must show the checkbox count.'
            $find.PerformClick()
            & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 2 -and [bool]$grid.Rows[2].Cells[0].Value -and [bool]$grid.Rows[19].Cells[0].Value) 'Refreshing an unchanged folder must retain the exact checked paths.'
            $clear.PerformClick();$grid.Rows[2].Cells[0].Value=$true;$grid.Rows[19].Cells[0].Value=$true
            # Show-ActSignerWindow only returns a plan. No signing/COM/PIN code is imported.
            $state.Phase = 3
            $timer.Stop()
            $state.Form.AcceptButton.PerformClick()
        }
        if ($state.Phase -eq 30) {
            $forms = @([System.Windows.Forms.Application]::OpenForms)
            if ($forms.Count -eq 0) { return }
            $state.Form = $forms[0]
            $state.Controls = @(& $walk $state.Form)
            $pick = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -eq 'Выбрать файлы...' })
            if ($pick.Count -ne 1) { throw 'A multi-file picker must be available beside folder discovery.' }
            $beside=@($state.Controls | Where-Object {$_ -is [Windows.Forms.CheckBox] -and $_.Text -eq 'Сохранять рядом с исходниками'})[0]
            $beside.Checked=$true
            $pick[0].PerformClick()
            $grid = @($state.Controls | Where-Object { $_ -is [System.Windows.Forms.DataGridView] })[0]
            & $assert ($grid.Rows.Count -eq 2) 'The file picker must plan only the two chosen files, excluding an unselected sibling.'
            if ($grid.Rows.Count -ne 2) { throw 'File picker selection was not used by the real planner.' }
            $plannedPaths = @($grid.Rows | ForEach-Object { $_.Tag.SourcePath } | Sort-Object)
            & $assert (($plannedPaths -join '|') -ceq (($pickedFiles | Sort-Object) -join '|')) 'The file picker must preserve exact chosen paths.'
            & $assert (@($grid.Rows | Where-Object { $_.Tag.SignaturePath.EndsWith('.docx_ivanov.sig') }).Count -eq 1) 'The new naming format must retain the document extension.'
            & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 2) 'Explicitly picked archives must be checked like explicitly picked documents.'
            $grid.Rows[1].Cells[0].Value = $false
            $refreshList=@($state.Controls | Where-Object {$_ -is [Windows.Forms.Button] -and $_.Text -in @('Найти файлы','Обновить список')})[0]
            $refreshList.PerformClick()
            & $assert ($grid.Rows.Count -eq 2 -and @($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 1) 'Refreshing explicit files must preserve their scope and checkboxes without adding an unselected sibling.'
            $state.Phase = 31
            $timer.Stop()
            $state.Form.AcceptButton.PerformClick()
        }
        if ($state.Phase -eq 40) {
            $forms=@([Windows.Forms.Application]::OpenForms)
            if($forms.Count -eq 0){return}
            $state.Form=$forms[0];$state.Controls=@(& $walk $state.Form)
            $source=@($state.Controls | Where-Object {$_ -is [Windows.Forms.TextBox] -and $_.AccessibleName -eq 'Папка с исходными файлами'})[0]
            $browse=@($source.Parent.Controls | Where-Object {$_ -is [Windows.Forms.Button] -and $source.Parent.GetRow($_) -eq 0})[0]
            $browse.PerformClick()
            $grid=@($state.Controls | Where-Object {$_ -is [Windows.Forms.DataGridView]})[0]
            & $assert ($grid.Rows.Count -eq 3) 'Confirming a source folder must populate its files without a separate find action.'
            & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 2) 'Automatic folder discovery must leave the archive unchecked and select both documents.'
            $source.Text=$folderRoot+'\.'
            & $assert ($grid.Rows.Count -eq 0) 'Editing a folder path must invalidate the previous preview.'
            $enter=[Windows.Forms.KeyEventArgs]::new([Windows.Forms.Keys]::Enter)
            [void]$source.GetType().GetMethod('OnKeyDown',[Reflection.BindingFlags]'Instance,NonPublic').Invoke($source,[object[]]@($enter))
            & $assert ($grid.Rows.Count -eq 3 -and $enter.Handled -and $enter.SuppressKeyPress) 'Enter in the source field must refresh the folder preview without falling through to the signing action.'
            & $assert ($state.Form.DialogResult -ne [Windows.Forms.DialogResult]::OK) 'Confirming a source path must not accept the signing plan.'
            $output=@($state.Controls | Where-Object {$_ -is [Windows.Forms.TextBox] -and $_.AccessibleName -eq 'Папка для файлов и подписей'})[0]
            $outputBrowse=@($output.Parent.Controls | Where-Object {$_ -is [Windows.Forms.Button] -and $output.Parent.GetRow($_) -eq $output.Parent.GetRow($output)})[0]
            $savesBefore=$preferenceCalls.Count
            $outputBrowse.PerformClick()
            & $assert ($preferenceCalls.Count -gt $savesBefore -and $preferenceCalls[$preferenceCalls.Count-1].SeparateOutputRoot -ceq $folderOutputRoot) 'Confirming an output folder must immediately save that preference.'
            $state.Phase=41;$timer.Stop();$state.Form.CancelButton.PerformClick()
            return
        }
        if ($state.Phase -eq 10) {
            $forms = @([System.Windows.Forms.Application]::OpenForms)
            if ($forms.Count -eq 0) { return }
            $state.Form = $forms[0]
            $state.Controls = @(& $walk $state.Form)
            $state.Phase = 11
            & $assert (-not $state.Form.AcceptButton.Enabled) 'A certificate read failure must leave signing unavailable.'
            & $inspectDetails $true
            $state.Phase = 12
            $timer.Stop()
            $state.Form.CancelButton.PerformClick()
        }
    }
    catch {
        $state.Error = $_.Exception.ToString()
        $timer.Stop()
        foreach ($openForm in @([System.Windows.Forms.Application]::OpenForms)) { $openForm.Close() }
    }
}.GetNewClosure())

$result = $null
# GetNewClosure creates a dynamic module whose unqualified function lookup can
# reach global scope. Install a process-local save stub there and restore it.
$priorGlobalSave = Get-Item -LiteralPath 'Function:\global:Save-ActSignerSettings' -ErrorAction SilentlyContinue
$priorGlobalSaveBlock = $null
if ($null -ne $priorGlobalSave) { $priorGlobalSaveBlock = $priorGlobalSave.ScriptBlock }
$preferenceCalls = New-Object 'System.Collections.Generic.List[object]'
$saveStub = {
    param([string]$SourceRoot, [string]$SeparateOutputRoot, [bool]$SaveBesideSources, [string]$SignatureNaming)
    $preferenceCalls.Add([pscustomobject]@{
        SourceRoot = $SourceRoot; SeparateOutputRoot = $SeparateOutputRoot; SaveBesideSources = $SaveBesideSources; SignatureNaming = $SignatureNaming
    })
    return $true
}.GetNewClosure()
Set-Item -LiteralPath 'Function:\global:Save-ActSignerSettings' -Value $saveStub
try {
    $timer.Start()
    $result = Show-ActSignerWindow -CertificateProvider $certificateProvider -PlanProvider $planProvider
    if ($null -ne $state.Error) { throw $state.Error }
    & $assert ($state.Phase -eq 3) 'All native UI phases must complete.'
    & $assert (@($preferenceCalls | Where-Object {$_.SignatureNaming -ceq 'document_signer'}).Count -gt 0) 'The selected filename format must be saved.'
    & $assert ($null -ne $result) 'The UI must return the selected plan.'
    if ($null -ne $result) {
        & $assert ($result.Plan.AllFiles -and $result.Plan.Recurse -and @($result.Plan.SourceFiles).Count -eq 0) 'Selected plans must retain the universal-file scope and recursion choice.'
        & $assert ($result.Plan.Items.Count -eq 2) 'Returned plan must contain exactly two checked acts.'
        & $assert ([object]::ReferenceEquals($result.Plan.Items[0], $items[2])) 'Returned first act must map to the row Tag.'
        & $assert ([object]::ReferenceEquals($result.Plan.Items[1], $items[19])) 'Returned second act must map to the row Tag.'
        & $assert ([object]::ReferenceEquals($result.CertificateInfo, $certificate)) 'Returned certificate must be the synthetic selection.'
        & $assert ([bool]$result.CopyOriginals) 'Separate-output choice must remain in the returned plan.'
        & $assert ($result.Plan.OutputRoot -eq 'C:\SyntheticPreviousOutput') 'The returned plan must retain the restored separate-output path.'
    }
    & $assert ($preferenceCalls.Count -gt 0) 'The process-local preference save stub must receive the synthetic mode changes.'
    $besideSaves = @($preferenceCalls | Where-Object { $_.SaveBesideSources -and $_.SourceRoot -eq 'C:\SyntheticActs' -and $_.SeparateOutputRoot -eq 'C:\SyntheticPreviousOutput' })
    $separateSaves = @($preferenceCalls | Where-Object { -not $_.SaveBesideSources -and $_.SourceRoot -eq 'C:\SyntheticActs' -and $_.SeparateOutputRoot -eq 'C:\SyntheticPreviousOutput' })
    & $assert ($besideSaves.Count -gt 0 -and $separateSaves.Count -gt 0) 'Synthetic preference saves must retain the prior output path in both modes.'
    # Exercise diagnostic failure only after completing the selected-plan assertions.
    $state.Phase = 10; $state.Form = $null; $state.Error = $null; $state.Started = [datetime]::UtcNow
    $failedCertificateProvider = { throw $syntheticReadError }.GetNewClosure()
    $timer.Start()
    $failureResult = Show-ActSignerWindow -CertificateProvider $failedCertificateProvider -PlanProvider $planProvider
    if ($null -ne $state.Error) { throw $state.Error }
    & $assert ($state.Phase -eq 12) 'Certificate read failure diagnostic scenario must complete.'
    & $assert ($null -eq $failureResult) 'Cancelling the diagnostic scenario must not return a signing plan.'
    Import-Module (Join-Path $PSScriptRoot 'ActSigner.Core.psm1') -Force -Global -DisableNameChecking
    $pickerRoot = Join-Path ([IO.Path]::GetTempPath()) ('cspsigner-ui-picker-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($pickerRoot)
    $pickedFiles = @((Join-Path $pickerRoot 'report.docx'), (Join-Path $pickerRoot 'sample.zip'))
    foreach ($file in $pickedFiles) { [IO.File]::WriteAllBytes($file, [byte[]]@(0,255,128,13,10)) }
    [IO.File]::WriteAllText((Join-Path $pickerRoot 'unselected.csv'), 'must remain unselected')
    [IO.File]::WriteAllBytes((Join-Path $pickerRoot 'sample.zip_ivanov.sig'),[byte[]]@(1,2,3))
    $state.Phase = 30; $state.Form = $null; $state.Error = $null; $state.Started = [datetime]::UtcNow
    try {
        $timer.Start()
        $pickerResult = Show-ActSignerWindow -CertificateProvider $certificateProvider -FilePickerProvider { return @($pickedFiles) + @($pickedFiles[0]) }.GetNewClosure()
        if ($null -ne $state.Error) { throw $state.Error }
        & $assert ($state.Phase -eq 31 -and $null -ne $pickerResult) 'The file-picker scenario must return a selected plan.'
        if ($null -ne $pickerResult) {
            & $assert ($pickerResult.Plan.AllFiles -and -not $pickerResult.Plan.Recurse) 'An explicit file plan must retain its universal nonrecursive scope.'
            & $assert ((@($pickerResult.Plan.SourceFiles | Sort-Object) -join '|') -ceq (($pickedFiles | Sort-Object) -join '|')) 'Checkbox filtering must retain the original explicit-file scope.'
            & $assert ($pickerResult.Plan.Items.Count -eq 1 -and $pickedFiles -contains $pickerResult.Plan.Items[0].SourcePath) 'Only the checked file may be returned for signing.'
        }
    }
    finally {
        if ([IO.Directory]::Exists($pickerRoot)) { Remove-Item -LiteralPath $pickerRoot -Recurse -Force }
    }
    $hasFolderPicker=(Get-Command Show-ActSignerWindow).Parameters.ContainsKey('FolderPickerProvider')
    & $assert $hasFolderPicker 'Folder selection must support the automatic discovery flow.'
    if($hasFolderPicker){
        $folderRoot=Join-Path ([IO.Path]::GetTempPath()) ('cspsigner-ui-folder-'+[guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($folderRoot)
        $folderOutputRoot=Join-Path $folderRoot 'output'
        [void][IO.Directory]::CreateDirectory($folderOutputRoot)
        try{
            foreach($name in @('report.docx','invoice.xml','backup.zip')){[IO.File]::WriteAllBytes((Join-Path $folderRoot $name),[byte[]]@(1,2,3))}
            $state.Phase=40;$state.Form=$null;$state.Error=$null;$state.Started=[datetime]::UtcNow
            $timer.Start()
            $folderResult=Show-ActSignerWindow -CertificateProvider $certificateProvider -FolderPickerProvider {param($Owner,$InitialDirectory,$ForOutput,$DocumentsRoot) if($ForOutput){return $folderOutputRoot};return $folderRoot}.GetNewClosure()
            if($null -ne $state.Error){throw $state.Error}
            & $assert ($state.Phase -eq 41 -and $null -eq $folderResult) 'The automatic folder-preview case must complete without signing.'
        }finally{Remove-Item -LiteralPath $folderRoot -Recurse -Force}
    }
}
catch { $failures.Add($_.Exception.Message) }
finally {
    $timer.Stop(); $timer.Dispose()
    if ($null -ne $priorGlobalSaveBlock) { Set-Item -LiteralPath 'Function:\global:Save-ActSignerSettings' -Value $priorGlobalSaveBlock }
    else { Remove-Item -LiteralPath 'Function:\global:Save-ActSignerSettings' -ErrorAction SilentlyContinue }
    $report = [pscustomobject]@{ NativeWindows = $true; PowerShellVersion = $PSVersionTable.PSVersion.ToString(); Measurements = @($measurements.ToArray()); SyntheticPreferenceSaveCalls = @($preferenceCalls.ToArray()); Failures = @($failures.ToArray()) }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ArtifactDirectory 'measurements.json') -Encoding UTF8
    Remove-Module $module -Force
}
foreach ($measurement in $measurements) { Write-Host ('MEASURE {0}: grid={1}x{2}, visible body={3}px, complete rows={4}' -f $measurement.Name, $measurement.GridWidth, $measurement.GridHeight, $measurement.VisibleBodyHeight, $measurement.FullyVisibleRows) }
if ($failures.Count -gt 0) { throw ('UI regression check failed:' + [Environment]::NewLine + ($failures.ToArray() -join [Environment]::NewLine)) }
Write-Host 'PASS: native Windows layout, grouped checkbox actions, archive defaults, automatic folder discovery, exact refresh scope, selected plan mapping and certificate diagnostics.'
