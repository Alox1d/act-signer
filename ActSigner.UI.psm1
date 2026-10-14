# Windows PowerShell 5.1. The window only discovers certificates and builds a plan.
Set-StrictMode -Version 2.0

function Get-ActCertificateDetailsText {
    param(
        [AllowNull()][object]$CertificateInfo,
        [int]$CertificateCount = 0,
        [string[]]$Warnings = @(),
        [string]$ReadError = ''
    )
    $lines = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($ReadError)) {
        $lines.Add('Не удалось прочитать сертификаты.')
        $lines.Add($ReadError)
        $lines.Add('После устранения причины нажмите Обновить.')
    }
    elseif ($null -eq $CertificateInfo) {
        if ($CertificateCount -gt 1) {
            $lines.Add('Выберите свой сертификат из списка. Подписант не выбирается автоматически, если сертификатов несколько.')
        }
        elseif ($CertificateCount -eq 0) {
            $lines.Add('Сертификаты, подходящие для подписи, не найдены.')
            $lines.Add('Нажмите Обновить, чтобы повторить поиск.')
        }
        else { $lines.Add('Сертификат для подписи не выбран.') }
    }
    else {
        $validFrom = [string]$CertificateInfo.NotBefore
        $validTo = [string]$CertificateInfo.NotAfter
        try { $validFrom = ([datetime]$CertificateInfo.NotBefore).ToString('dd.MM.yyyy HH:mm') } catch { }
        try { $validTo = ([datetime]$CertificateInfo.NotAfter).ToString('dd.MM.yyyy HH:mm') } catch { }
        $lines.Add('Владелец: ' + [string]$CertificateInfo.Subject)
        $lines.Add('Издатель: ' + [string]$CertificateInfo.Issuer)
        $lines.Add('Отпечаток: ' + [string]$CertificateInfo.Thumbprint)
        $lines.Add(('Действует: с {0} по {1}' -f $validFrom, $validTo))
        $lines.Add('Источник: ' + [string]$CertificateInfo.Source)
    }
    $messages = @($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($messages.Count -gt 0) {
        # Keep diagnostic messages first in the details dialog.
        return ((@('Диагностика:') + $messages + @('') + $lines.ToArray()) -join [Environment]::NewLine)
    }
    return ($lines.ToArray() -join [Environment]::NewLine)
}

function Show-ActSignerWindow {
    [CmdletBinding()]
    param(
        [scriptblock]$CertificateProvider,
        [scriptblock]$PlanProvider,
        [scriptblock]$FilePickerProvider,
        [scriptblock]$FolderPickerProvider
    )

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Окно подписания работает только в Windows.'
    }
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
        throw 'Для окна подписания нужен режим STA. Запустите приложение через его файл запуска.'
    }

    $null = Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    $null = Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    [System.Windows.Forms.Application]::EnableVisualStyles()

    if ($null -eq $CertificateProvider) {
        $CertificateProvider = { Get-ActCertificates }
    }
    if ($null -eq $PlanProvider) {
        $PlanProvider = {
            param($SourceRoot, $DestinationRoot, $SignatureNaming, $SignerLabel, $SourceFiles, $Recurse)
            $scope = @{}
            if (@($SourceFiles).Count -gt 0) { $scope.SourceFiles = [string[]]$SourceFiles }
            Get-ActPlan -Root $SourceRoot -OutputRoot $DestinationRoot -SignatureNaming $SignatureNaming -SignerLabel $SignerLabel -AllFiles -Recurse:([bool]$Recurse) @scope
        }
    }

    if ($null -eq $FilePickerProvider) {
        $FilePickerProvider = {
            param($Owner, $InitialDirectory)
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            try {
                $dialog.Title = 'Выберите файлы для подписи'
                $dialog.Filter = 'Все файлы (*.*)|*.*'
                $dialog.Multiselect = $true
                $dialog.CheckFileExists = $true
                $dialog.RestoreDirectory = $true
                if ([IO.Directory]::Exists($InitialDirectory)) { $dialog.InitialDirectory = $InitialDirectory }
                if ($dialog.ShowDialog($Owner) -eq [System.Windows.Forms.DialogResult]::OK) { return @($dialog.FileNames) }
                return @()
            }
            finally { $dialog.Dispose() }
        }
    }

    if($null -eq $FolderPickerProvider){
        $FolderPickerProvider={
            param($Owner,$InitialDirectory,[bool]$ForOutput,$DocumentsRoot)
            $dialog=New-Object System.Windows.Forms.FolderBrowserDialog
            try{
                $dialog.ShowNewFolderButton=$false
                $dialog.RootFolder=[Environment+SpecialFolder]::Desktop
                $dialog.Description=if($ForOutput){'Выберите папку результата. Имя новой папки можно дописать в поле пути.'}else{'Выберите папку с файлами. Будут просмотрены и её подпапки.'}
                if([IO.Directory]::Exists($InitialDirectory)){$dialog.SelectedPath=$InitialDirectory}
                elseif($ForOutput -and [IO.Directory]::Exists($DocumentsRoot)){$dialog.SelectedPath=$DocumentsRoot}
                if($dialog.ShowDialog($Owner) -eq [Windows.Forms.DialogResult]::OK){return $dialog.SelectedPath}
                return ''
            }finally{$dialog.Dispose()}
        }
    }

    $documentsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
    if ([string]::IsNullOrWhiteSpace($documentsRoot)) {
        $documentsRoot = [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile), 'Documents')
    }
    $defaultOutput = [IO.Path]::Combine($documentsRoot, 'Подписанные_файлы')
    $settings = Get-ActSignerSettings
    $namingModes=@('file_signer','signer','document_signer','legacy')
    $initialNaming='file_signer'
    if($null -ne $settings.PSObject.Properties['SignatureNaming'] -and $settings.SignatureNaming -cin $namingModes) { $initialNaming=$settings.SignatureNaming }
    if (-not [string]::IsNullOrWhiteSpace($settings.SeparateOutputRoot)) {
        $defaultOutput = $settings.SeparateOutputRoot
    }
    $certificateTextBuilder = ${function:Get-ActCertificateDetailsText}
    $newLine = [Environment]::NewLine
    $state = @{
        Plan = $null
        SourceFiles = @()
        Recurse = $true
        Result = $null
        Certificates = @()
        CertificateWarnings = @()
        CertificateReadError = ''
        CertificateDetailsText = 'Список сертификатов будет загружен при открытии окна.'
        Busy = $false
        SuppressChanges = $false
        SuppressGridEvents = $false
        SeparateOutputText = $defaultOutput
        LastSavedSource = $settings.SourceRoot
        LastSavedSeparateOutput = $settings.SeparateOutputRoot
        LastSavedBeside = [bool]$settings.SaveBesideSources
        LastSavedNaming = $initialNaming
        SettingsWarningShown = $false
        Started = $false
    }
    $ui = @{}
    $baseFont = New-Object System.Drawing.Font('Segoe UI', 9)
    $titleFont = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
    $toolTip = New-Object System.Windows.Forms.ToolTip
    $toolTip.AutoPopDelay = 20000
    $toolTip.InitialDelay = 350
    $toolTip.ShowAlways = $true

    $form = New-Object System.Windows.Forms.Form
    $ui.Form = $form
    $form.SuspendLayout()
    $displayVersion = '1.5.0'
    try {
        $versionPath = Join-Path $PSScriptRoot 'ActSigner.Version.json'
        if ([IO.File]::Exists($versionPath) -and (New-Object IO.FileInfo($versionPath)).Length -le 4096) {
            $versionInfo = ConvertFrom-Json ([IO.File]::ReadAllText($versionPath, [Text.Encoding]::UTF8))
            if ($versionInfo.Version -is [string] -and $versionInfo.Version -cmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { $displayVersion = $versionInfo.Version }
        }
    }
    catch { }
    $form.Text = 'CSPSigner ' + $displayVersion
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.Font = $baseFont
    $form.AutoScaleDimensions = New-Object System.Drawing.SizeF(7, 15)
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $availableWidth = [Math]::Max(200, $workArea.Width - 32)
    $availableHeight = [Math]::Max(200, $workArea.Height - 32)

    # Only the grid scrolls. Setup rows use their preferred height; the files
    # receive the remaining space and the footer stays inside the window.
    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'
    $layout.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 10)
    $layout.ColumnCount = 1
    $layout.RowCount = 4
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$form.Controls.Add($layout)
    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'Подписать файлы своей ЭП'
    $title.Font = $titleFont
    $title.AutoSize = $true
    $title.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
    [void]$layout.Controls.Add($title, 0, 0)

    $makeButton = {
        param([string]$Text, [int]$Width, [int]$Height = 28)
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $Text
        $button.AutoSize = $true
        $button.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $button.MinimumSize = New-Object System.Drawing.Size($Width, $Height)
        $button.Padding = New-Object System.Windows.Forms.Padding(8, 3, 8, 3)
        $button.UseVisualStyleBackColor = $true
        return $button
    }
    $folders = New-Object System.Windows.Forms.TableLayoutPanel
    $folders.Dock = 'Fill'
    $folders.AutoSize = $true
    $folders.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $folders.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 7)
    $folders.ColumnCount = 3
    $folders.RowCount = 5
    $folders.TabIndex = 0
    [void]$folders.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$folders.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$folders.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    for ($i = 0; $i -lt 5; $i++) {
        [void]$folders.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    }
    $sourceLabel = New-Object System.Windows.Forms.Label
    $sourceLabel.Text = 'Папка исходников:'
    $sourceLabel.AutoSize = $true
    $sourceLabel.Anchor = 'Left'
    $sourceLabel.Margin = New-Object System.Windows.Forms.Padding(0, 4, 10, 4)
    $sourceBox = New-Object System.Windows.Forms.TextBox
    $ui.Source = $sourceBox
    $sourceBox.Dock = 'Fill'
    $sourceBox.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 4)
    $sourceBox.Text = $settings.SourceRoot
    $sourceBox.TabIndex = 0
    $sourceBox.AccessibleName = 'Папка с исходными файлами'
    $sourceBrowse = & $makeButton 'Выбрать...' 90
    $ui.SourceBrowse = $sourceBrowse
    $sourceBrowse.Dock = 'Fill'
    $sourceBrowse.Margin = New-Object System.Windows.Forms.Padding(7, 1, 0, 3)
    $sourceBrowse.TabIndex = 1
    [void]$folders.Controls.Add($sourceLabel, 0, 0)
    [void]$folders.Controls.Add($sourceBox, 1, 0)
    [void]$folders.Controls.Add($sourceBrowse, 2, 0)

    $beside = New-Object System.Windows.Forms.CheckBox
    $ui.Beside = $beside
    $beside.Text = 'Сохранять рядом с исходниками'
    $beside.Checked = [bool]$settings.SaveBesideSources
    $beside.AutoSize = $true
    $beside.Anchor = 'Left'
    $beside.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 5)
    $beside.TabIndex = 2
    [void]$folders.Controls.Add($beside, 1, 1)
    $folders.SetColumnSpan($beside, 2)
    $outputLabel = New-Object System.Windows.Forms.Label
    $ui.OutputLabel = $outputLabel
    $outputLabel.Text = 'Папка результата:'
    $outputLabel.AutoSize = $true
    $outputLabel.Anchor = 'Left'
    $outputLabel.Margin = New-Object System.Windows.Forms.Padding(0, 4, 10, 4)
    $outputBox = New-Object System.Windows.Forms.TextBox
    $ui.Output = $outputBox
    $outputBox.Dock = 'Fill'
    $outputBox.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 4)
    $outputBox.Text = $defaultOutput
    $outputBox.TabIndex = 3
    $outputBox.AccessibleName = 'Папка для файлов и подписей'
    $outputBrowse = & $makeButton 'Выбрать...' 90
    $ui.OutputBrowse = $outputBrowse
    $outputBrowse.Dock = 'Fill'
    $outputBrowse.Margin = New-Object System.Windows.Forms.Padding(7, 1, 0, 3)
    $outputBrowse.TabIndex = 4
    [void]$folders.Controls.Add($outputLabel, 0, 2)
    [void]$folders.Controls.Add($outputBox, 1, 2)
    [void]$folders.Controls.Add($outputBrowse, 2, 2)

    $certificateLabel = New-Object System.Windows.Forms.Label
    $certificateLabel.Text = 'Сертификат:'
    $certificateLabel.AutoSize = $true
    $certificateLabel.Anchor = 'Left'
    $certificateLabel.Margin = New-Object System.Windows.Forms.Padding(0, 4, 10, 4)
    [void]$folders.Controls.Add($certificateLabel, 0, 3)
    $certificateLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $certificateLayout.Dock = 'Fill'
    $certificateLayout.AutoSize = $true
    $certificateLayout.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $certificateLayout.Margin = New-Object System.Windows.Forms.Padding(0)
    $certificateLayout.ColumnCount = 3
    $certificateLayout.RowCount = 1
    $certificateLayout.TabIndex = 5
    [void]$certificateLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$certificateLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$certificateLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$certificateLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $certificateBox = New-Object System.Windows.Forms.ComboBox
    $ui.Certificate = $certificateBox
    $certificateBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $certificateBox.Dock = 'Fill'
    $certificateBox.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 4)
    $certificateBox.IntegralHeight = $false
    $certificateBox.MaxDropDownItems = 10
    $certificateBox.DropDownHeight = 230
    $certificateBox.DropDownWidth = [Math]::Min(900, $availableWidth)
    $certificateBox.AccessibleName = 'Сертификат для подписания'
    $certificateBox.TabIndex = 0
    $refresh = & $makeButton 'Обновить' 86
    $ui.Refresh = $refresh
    $refresh.Dock = 'Fill'
    $refresh.Margin = New-Object System.Windows.Forms.Padding(7, 1, 0, 3)
    $refresh.TabIndex = 1
    $details = & $makeButton 'Подробнее' 94
    $ui.Details = $details
    $details.Dock = 'Fill'
    $details.Margin = New-Object System.Windows.Forms.Padding(7, 1, 0, 3)
    $details.AccessibleName = 'Данные сертификата и диагностика: открыть'
    $details.TabIndex = 2
    [void]$certificateLayout.Controls.Add($certificateBox, 0, 0)
    [void]$certificateLayout.Controls.Add($refresh, 1, 0)
    [void]$certificateLayout.Controls.Add($details, 2, 0)
    [void]$folders.Controls.Add($certificateLayout, 1, 3)
    $folders.SetColumnSpan($certificateLayout, 2)
    $certificateStatus = New-Object System.Windows.Forms.Label
    $ui.CertificateStatus = $certificateStatus
    $certificateStatus.Dock = 'Fill'
    $certificateStatus.Height = 20
    $certificateStatus.MinimumSize = New-Object System.Drawing.Size(0, 20)
    $certificateStatus.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 1)
    $certificateStatus.AutoEllipsis = $true
    $certificateStatus.TextAlign = 'MiddleLeft'
    $certificateStatus.AccessibleName = 'Состояние сертификатов'
    [void]$folders.Controls.Add($certificateStatus, 1, 4)
    $folders.SetColumnSpan($certificateStatus, 2)
    [void]$layout.Controls.Add($folders, 0, 1)

    $actLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $actLayout.Dock = 'Fill'
    $actLayout.Margin = New-Object System.Windows.Forms.Padding(0)
    $actLayout.ColumnCount = 1
    $actLayout.RowCount = 2
    $actLayout.TabIndex = 1
    [void]$actLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$actLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$actLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $toolbar = New-Object System.Windows.Forms.FlowLayoutPanel
    $toolbar.Dock = 'Fill'
    $toolbar.AutoSize = $true
    $toolbar.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $toolbar.Margin = New-Object System.Windows.Forms.Padding(0)
    $toolbar.WrapContents = $true
    $toolbar.TabIndex = 0
    $find = & $makeButton 'Обновить список' 145 30
    $ui.Find = $find
    $find.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 6)
    $find.TabIndex = 0
    $selectNew = & $makeButton 'Выбрать все' 105 30
    $ui.SelectNew = $selectNew
    $selectNew.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 6)
    $selectNew.TabIndex = 2
    $clearSelection = & $makeButton 'Снять все' 100 30
    $ui.ClearSelection = $clearSelection
    $clearSelection.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
    $clearSelection.TabIndex = 3
    $pickFiles = & $makeButton 'Выбрать файлы...' 140 30
    $ui.PickFiles = $pickFiles
    $pickFiles.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 6)
    $pickFiles.TabIndex = 1
    [void]$toolbar.Controls.Add($find)
    [void]$toolbar.Controls.Add($pickFiles)
    [void]$toolbar.Controls.Add($selectNew)
    [void]$toolbar.Controls.Add($clearSelection)
    $namingLabel=New-Object System.Windows.Forms.Label
    $namingLabel.Text='Имя подписи:'
    $namingLabel.AutoSize=$true
    $namingLabel.Margin=New-Object System.Windows.Forms.Padding(12,6,4,6)
    $naming=New-Object System.Windows.Forms.ComboBox
    $ui.Naming=$naming
    $naming.DropDownStyle='DropDownList'
    $naming.Width=280
    $naming.AccessibleName='Signature filename format'
    $naming.Margin=New-Object System.Windows.Forms.Padding(0,0,0,6)
    [void]$naming.Items.Add('<файл.расширение>_<фамилия>.sig')
    [void]$naming.Items.Add('signature_<фамилия>.sig')
    [void]$naming.Items.Add('<имя файла>_<фамилия>.sig')
    [void]$naming.Items.Add('<имя файла>.my.sig (прежний)')
    $naming.SelectedIndex=[array]::IndexOf($namingModes,$initialNaming)
    $namingGroup = New-Object System.Windows.Forms.FlowLayoutPanel
    $namingGroup.AutoSize = $true
    $namingGroup.AutoSizeMode = 'GrowAndShrink'
    $namingGroup.WrapContents = $false
    $namingGroup.Margin = New-Object System.Windows.Forms.Padding(0)
    $namingGroup.TabIndex = 4
    [void]$namingGroup.Controls.Add($namingLabel)
    [void]$namingGroup.Controls.Add($naming)
    [void]$toolbar.Controls.Add($namingGroup)
    [void]$actLayout.Controls.Add($toolbar, 0, 0)

    $grid = New-Object System.Windows.Forms.DataGridView
    $ui.Grid = $grid
    $grid.Dock = 'Fill'
    $grid.Margin = New-Object System.Windows.Forms.Padding(0)
    $grid.BackgroundColor = [Drawing.SystemColors]::Window
    $grid.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.AllowUserToOrderColumns = $false
    $grid.RowHeadersVisible = $false
    $grid.AutoGenerateColumns = $false
    $grid.MultiSelect = $true
    $grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $grid.EditMode = [System.Windows.Forms.DataGridViewEditMode]::EditOnEnter
    $grid.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::AllCellsExceptHeaders
    $grid.RowTemplate.MinimumHeight = 28
    $grid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(6, 3, 6, 3)
    $grid.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::False
    $grid.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::AutoSize
    $grid.ColumnHeadersDefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(6, 4, 6, 4)
    $grid.CellBorderStyle = [System.Windows.Forms.DataGridViewCellBorderStyle]::SingleHorizontal
    if (-not [System.Windows.Forms.SystemInformation]::HighContrast) {
        $grid.AlternatingRowsDefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(248, 250, 252)
        $grid.GridColor = [Drawing.Color]::FromArgb(225, 229, 234)
    }
    $grid.AccessibleName = 'Предварительный список файлов'
    $grid.TabIndex = 1
    $checkColumn = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $checkColumn.Name = 'Selected'
    $checkColumn.HeaderText = 'Выбор'
    $checkColumn.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::ColumnHeader
    $checkColumn.MinimumWidth = 58
    $checkColumn.Resizable = [System.Windows.Forms.DataGridViewTriState]::False
    $checkColumn.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
    $pathColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $pathColumn.Name = 'RelativePath'
    $pathColumn.HeaderText = 'Файл и подпапка'
    $pathColumn.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    $pathColumn.MinimumWidth = 220
    $pathColumn.ReadOnly = $true
    $pathColumn.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
    $statusColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $statusColumn.Name = 'Status'
    $statusColumn.HeaderText = 'Статус'
    $statusColumn.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
    $statusColumn.ReadOnly = $true
    $statusColumn.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
    [void]$grid.Columns.Add($checkColumn)
    [void]$grid.Columns.Add($pathColumn)
    [void]$grid.Columns.Add($statusColumn)
    [void]$actLayout.Controls.Add($grid, 0, 1)
    [void]$layout.Controls.Add($actLayout, 0, 2)

    $footer = New-Object System.Windows.Forms.TableLayoutPanel
    $footer.Dock = 'Fill'
    $footer.AutoSize = $true
    $footer.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $footer.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)
    $footer.ColumnCount = 3
    $footer.RowCount = 1
    $footer.TabIndex = 2
    [void]$footer.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$footer.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$footer.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$footer.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $summary = New-Object System.Windows.Forms.Label
    $ui.Summary = $summary
    $summary.Dock = 'Fill'
    $summary.AutoSize = $true
    $summary.Margin = New-Object System.Windows.Forms.Padding(0)
    $summary.AutoEllipsis = $true
    $summary.TextAlign = 'MiddleLeft'
    $summary.Text = 'Выберите папку или отдельные файлы.'
    $summary.AccessibleName = 'Итоги поиска и выбора файлов'
    $sign = & $makeButton 'Проверить и подписать' 210 34
    $ui.Sign = $sign
    $sign.Padding = New-Object System.Windows.Forms.Padding(12, 5, 12, 5)
    $sign.Dock = 'Fill'
    $sign.Margin = New-Object System.Windows.Forms.Padding(8, 0, 8, 0)
    $sign.Enabled = $false
    $sign.TabIndex = 0
    $cancel = & $makeButton 'Отмена' 92 34
    $cancel.Padding = New-Object System.Windows.Forms.Padding(12, 5, 12, 5)
    $cancel.Dock = 'Fill'
    $cancel.Margin = New-Object System.Windows.Forms.Padding(0)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancel.TabIndex = 1
    [void]$footer.Controls.Add($summary, 0, 0)
    [void]$footer.Controls.Add($sign, 1, 0)
    [void]$footer.Controls.Add($cancel, 2, 0)
    [void]$layout.Controls.Add($footer, 0, 3)
    $form.AcceptButton = $sign
    $form.CancelButton = $cancel

    $toolTip.SetToolTip($sourceBox, 'После выбора папки список строится автоматически. Вставленный путь подтвердите Enter. Для отдельных файлов используйте Выбрать файлы.')
    $toolTip.SetToolTip($outputBox, 'Папка будет создана при подписании. При отдельной папке в неё попадут копии файлов и новые подписи.')
    $toolTip.SetToolTip($beside, 'Каждая новая подпись сохраняется в той же подпапке, где найден её исходный файл. Подпапки должны быть доступны для записи.')
    $toolTip.SetToolTip($find, 'Повторить поиск в выбранной папке или обновить явно выбранные файлы. Ваши галочки сохраняются. Архивы при поиске папки изначально не отмечены.')
    $toolTip.SetToolTip($grid, 'Ctrl/Shift - выделить несколько строк. Пробел меняет галочки выделенной группы. Действия группы также доступны по правой кнопке мыши.')
    $toolTip.SetToolTip($pickFiles, 'Выбрать один или несколько файлов любого формата. Будут добавлены только выбранные файлы.')
    $toolTip.SetToolTip($details, 'Полные данные выбранного сертификата и сообщения диагностики.')
    $sign.AccessibleDescription = 'Сначала проверим соседние подписи. Уже подписанные выбранным сертификатом файлы будут пропущены. Для остальных создадим новую подпись. Обработка продолжится в консоли; КриптоПро может запросить PIN носителя.'
    $toolTip.SetToolTip($sign, $sign.AccessibleDescription)

    $formatDate = {
        param($Value, [switch]$WithTime)
        try {
            if ($WithTime) { return ([datetime]$Value).ToString('dd.MM.yyyy HH:mm') }
            return ([datetime]$Value).ToString('dd.MM.yyyy')
        }
        catch { return [string]$Value }
    }
    $showError = {
        param([string]$Message, [string]$Caption = 'Не удалось выполнить действие')
        [void][System.Windows.Forms.MessageBox]::Show(
            $ui.Form, $Message, $Caption,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }.GetNewClosure()

    $savePreferences = {
        if ($state.SuppressChanges) { return }
        $source = $ui.Source.Text.Trim()
        $separateOutput = $state.SeparateOutputText.Trim()
        $saveBeside = [bool]$ui.Beside.Checked
        $signatureNaming=$namingModes[$ui.Naming.SelectedIndex]
        if ([string]::Equals($source, $state.LastSavedSource, [StringComparison]::Ordinal) -and
            [string]::Equals($separateOutput, $state.LastSavedSeparateOutput, [StringComparison]::Ordinal) -and
            $saveBeside -eq $state.LastSavedBeside -and $signatureNaming -ceq $state.LastSavedNaming) { return }
        $saved = $false
        try {
            $saved = Save-ActSignerSettings -SourceRoot $source -SeparateOutputRoot $separateOutput -SaveBesideSources $saveBeside -SignatureNaming $signatureNaming
        }
        catch { }
        if ($saved) {
            $state.LastSavedSource = $source
            $state.LastSavedSeparateOutput = $separateOutput
            $state.LastSavedBeside = $saveBeside
            $state.LastSavedNaming = $signatureNaming
        }
        elseif (-not $state.SettingsWarningShown) {
            $state.SettingsWarningShown = $true
            Write-Warning 'Не удалось запомнить папки. Подписание можно продолжить; при следующем запуске потребуется выбрать папку снова.' -WarningAction Continue
        }
    }.GetNewClosure()

    $syncAction = {
        if ($state.SuppressGridEvents) { return }
        $selectedCount = 0
        $existingCount = 0
        $newCount = 0
        foreach ($row in $ui.Grid.Rows) {
            if ($null -eq $row.Tag) { continue }
            if ([bool]$row.Tag.ExistingSignature) { $existingCount++ }
            else {
                $newCount++
            }
            if ([bool]$row.Cells[0].Value) { $selectedCount++ }
        }
        $certificateIndex = $ui.Certificate.SelectedIndex
        $hasCertificate = $certificateIndex -ge 0 -and $certificateIndex -lt $state.Certificates.Count
        $ui.Sign.Text = 'Проверить и подписать ({0})' -f $selectedCount
        $ui.Sign.Enabled = (-not $state.Busy) -and $null -ne $state.Plan -and $selectedCount -gt 0 -and $hasCertificate
        $ui.Find.Enabled = (-not $state.Busy) -and
            (-not [string]::IsNullOrWhiteSpace($ui.Source.Text)) -and
            (-not [string]::IsNullOrWhiteSpace($ui.Output.Text))
        $ui.PickFiles.Enabled = -not $state.Busy
        $ui.SelectNew.Enabled = (-not $state.Busy) -and ($newCount + $existingCount) -gt 0
        $ui.ClearSelection.Enabled = (-not $state.Busy) -and $selectedCount -gt 0
        $ui.Refresh.Enabled = -not $state.Busy
        $ui.Details.Enabled = -not $state.Busy
        $ui.Certificate.Enabled = (-not $state.Busy) -and $state.Certificates.Count -gt 0
        $ui.Source.Enabled = -not $state.Busy
        $ui.SourceBrowse.Enabled = -not $state.Busy
        $ui.Beside.Enabled = -not $state.Busy
        $ui.Output.Enabled = (-not $state.Busy) -and (-not $ui.Beside.Checked)
        $ui.OutputBrowse.Enabled = $ui.Output.Enabled
        $ui.Grid.Enabled = -not $state.Busy
        $ui.Naming.Enabled = -not $state.Busy
        if ($null -ne $state.Plan) {
            $text = 'Найдено: {0}   |   Выбрано: {1}   |   Есть целевая подпись: {2}' -f $ui.Grid.Rows.Count, $selectedCount, $existingCount
            $skippedCount = @($state.Plan.SkippedReparsePoints).Count
            if ($skippedCount -gt 0) { $text += '   |   Пропущено ссылок: ' + $skippedCount }
            if ($ui.Grid.Rows.Count -eq 0) { $text = 'Подходящие файлы в этой папке и её подпапках не найдены.' }
            $ui.Summary.Text = $text
            $toolTip.SetToolTip($ui.Summary, $text)
        }
    }.GetNewClosure()

    $invalidatePlan = {
        if ($state.SuppressChanges) { return }
        $state.Plan = $null
        $state.SuppressGridEvents = $true
        try { $ui.Grid.Rows.Clear() }
        finally { $state.SuppressGridEvents = $false }
        $ui.Summary.Text = 'Параметры изменены. Обновите список или выберите файлы.'
        $toolTip.SetToolTip($ui.Summary, $ui.Summary.Text)
        & $syncAction
    }.GetNewClosure()

    $syncOutputToSource = {
        $wasSuppressed = $state.SuppressChanges
        $state.SuppressChanges = $true
        $folders.SuspendLayout()
        try {
            if ($ui.Beside.Checked) { $ui.Output.Text = $ui.Source.Text }
            else { $ui.Output.Text = $state.SeparateOutputText }
            $showSeparateOutput = -not $ui.Beside.Checked
            $ui.OutputLabel.Visible = $showSeparateOutput
            $ui.Output.Visible = $showSeparateOutput
            $ui.OutputBrowse.Visible = $showSeparateOutput
        }
        finally {
            $state.SuppressChanges = $wasSuppressed
            $folders.ResumeLayout($true)
        }
    }.GetNewClosure()

    $showCertificate = {
        $index = $ui.Certificate.SelectedIndex
        $cert = $null
        if ($index -ge 0 -and $index -lt $state.Certificates.Count) { $cert = $state.Certificates[$index] }
        $state.CertificateDetailsText = & $certificateTextBuilder -CertificateInfo $cert -CertificateCount $state.Certificates.Count `
            -Warnings $state.CertificateWarnings -ReadError $state.CertificateReadError
        $toolTip.SetToolTip($ui.Certificate, $ui.Certificate.Text)
        & $syncAction
    }.GetNewClosure()

    $openCertificateDetails = {
        if ($state.Busy) { return }
        $dialog = New-Object System.Windows.Forms.Form
        try {
            $dialog.SuspendLayout()
            $dialog.Text = 'Сертификат и диагностика'
            $dialog.Font = $ui.Form.Font
            $dialog.AutoScaleDimensions = New-Object System.Drawing.SizeF(7, 15)
            $dialog.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
            $dialog.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
            $dialog.ShowInTaskbar = $false
            $dialog.MinimizeBox = $false
            $area = [System.Windows.Forms.Screen]::FromControl($ui.Form).WorkingArea
            $width = [Math]::Max(200, $area.Width - 32)
            $height = [Math]::Max(200, $area.Height - 32)
            $detailsLayout = New-Object System.Windows.Forms.TableLayoutPanel
            $detailsLayout.Dock = 'Fill'
            $detailsLayout.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 10)
            $detailsLayout.ColumnCount = 1
            $detailsLayout.RowCount = 2
            [void]$detailsLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
            [void]$detailsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
            [void]$detailsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
            $textBox = New-Object System.Windows.Forms.TextBox
            $textBox.Multiline = $true
            $textBox.ReadOnly = $true
            $textBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
            $textBox.Dock = 'Fill'
            $textBox.Margin = New-Object System.Windows.Forms.Padding(0)
            $textBox.BackColor = [Drawing.SystemColors]::Window
            $textBox.Text = $state.CertificateDetailsText
            $textBox.SelectionStart = 0
            $textBox.SelectionLength = 0
            $textBox.AccessibleName = 'Данные сертификата и диагностика'
            $close = New-Object System.Windows.Forms.Button
            $close.Text = 'Закрыть'
            $close.AutoSize = $true
            $close.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $close.MinimumSize = New-Object System.Drawing.Size(92, 32)
            $close.Padding = New-Object System.Windows.Forms.Padding(12, 4, 12, 4)
            $close.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)
            $close.Anchor = 'Right'
            $close.UseVisualStyleBackColor = $true
            $close.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            [void]$detailsLayout.Controls.Add($textBox, 0, 0)
            [void]$detailsLayout.Controls.Add($close, 0, 1)
            [void]$dialog.Controls.Add($detailsLayout)
            $dialog.AcceptButton = $close
            $dialog.CancelButton = $close
            $dialog.ResumeLayout($true)
            $dialog.PerformAutoScale()
            $dialog.MinimumSize = New-Object System.Drawing.Size([Math]::Min(480, $width), [Math]::Min(300, $height))
            $dialog.Size = New-Object System.Drawing.Size([Math]::Min(820, $width), [Math]::Min(520, $height))
            [void]$dialog.ShowDialog($ui.Form)
        }
        finally { $dialog.Dispose() }
    }.GetNewClosure()

    $refreshCertificates = {
        if ($state.Busy) { return }
        $previous = $null
        if ($ui.Certificate.SelectedIndex -ge 0 -and $ui.Certificate.SelectedIndex -lt $state.Certificates.Count) {
            $previous = $state.Certificates[$ui.Certificate.SelectedIndex]
        }
        $state.Busy = $true
        $state.Certificates = @()
        $state.CertificateWarnings = @()
        $state.CertificateReadError = ''
        $ui.Certificate.Items.Clear()
        $ui.Certificate.SelectedIndex = -1
        $state.CertificateDetailsText = 'Читаем сертификаты из доступных хранилищ...'
        $ui.CertificateStatus.Text = ''
        $ui.Refresh.Text = 'Чтение...'
        $ui.Form.UseWaitCursor = $true
        & $syncAction
        $ui.Form.Refresh()
        try {
            $discovery = & $CertificateProvider
            if ($null -eq $discovery) { throw 'Список сертификатов не получен.' }
            $state.Certificates = @($discovery.Certificates | Where-Object { $null -ne $_ })
            $state.CertificateWarnings = @($discovery.Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            $ui.Certificate.BeginUpdate()
            try {
                foreach ($cert in $state.Certificates) {
                    $name = [string]$cert.DisplayName
                    if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$cert.Subject }
                    $label = '{0} | до {1} | {2}' -f $name, (& $formatDate $cert.NotAfter), [string]$cert.Source
                    [void]$ui.Certificate.Items.Add($label)
                }
            }
            finally { $ui.Certificate.EndUpdate() }

            $restoreIndex = -1
            if ($state.Certificates.Count -eq 1) { $restoreIndex = 0 }
            elseif ($null -ne $previous) {
                $matches = @()
                for ($i = 0; $i -lt $state.Certificates.Count; $i++) {
                    $candidate = $state.Certificates[$i]
                    if ([string]$candidate.Thumbprint -eq [string]$previous.Thumbprint -and
                        [string]$candidate.StoreKind -eq [string]$previous.StoreKind -and
                        [string]$candidate.Source -eq [string]$previous.Source) {
                        $matches += $i
                    }
                }
                if ($matches.Count -eq 1) { $restoreIndex = $matches[0] }
            }
            $ui.Certificate.SelectedIndex = $restoreIndex
            $warnings = $state.CertificateWarnings
            if ($state.Certificates.Count -eq 0) {
                $statusText = 'Сертификаты не найдены. Откройте Подробнее.'
                $ui.CertificateStatus.ForeColor = [Drawing.Color]::Firebrick
            }
            elseif ($warnings.Count -gt 0) {
                $statusText = 'Найдено сертификатов: {0}. Диагностика: Подробнее.' -f $state.Certificates.Count
                $ui.CertificateStatus.ForeColor = [Drawing.Color]::DarkGoldenrod
            }
            else {
                $statusText = 'Доступно сертификатов: ' + $state.Certificates.Count
                if ($state.Certificates.Count -gt 1 -and $restoreIndex -lt 0) { $statusText += '. Выберите подписанта.' }
                $ui.CertificateStatus.ForeColor = [Drawing.SystemColors]::ControlText
            }
            $ui.CertificateStatus.Text = $statusText
            $fullStatus = $statusText
            if ($warnings.Count -gt 0) {
                $fullStatus += $newLine + ($warnings -join $newLine)
            }
            $toolTip.SetToolTip($ui.CertificateStatus, $fullStatus)
            & $showCertificate
        }
        catch {
            $state.Certificates = @()
            $state.CertificateReadError = $_.Exception.Message
            $ui.Certificate.Items.Clear()
            & $showCertificate
            $ui.CertificateStatus.Text = 'Сертификаты не загружены. Причина: Подробнее.'
            $ui.CertificateStatus.ForeColor = [Drawing.Color]::Firebrick
            $toolTip.SetToolTip($ui.CertificateStatus, $_.Exception.Message)
        }
        finally {
            $state.Busy = $false
            $ui.Refresh.Text = 'Обновить'
            $ui.Form.UseWaitCursor = $false
            & $syncAction
        }
    }.GetNewClosure()

    $browseFolder = {
        param([bool]$ForOutput)
        try{
            $candidate=if($ForOutput){$ui.Output.Text.Trim()}else{$ui.Source.Text.Trim()}
            $chosen=[string](& $FolderPickerProvider $ui.Form $candidate $ForOutput $documentsRoot)
            if([string]::IsNullOrWhiteSpace($chosen)){return $false}
            if($ForOutput){$ui.Output.Text=$chosen}else{$ui.Source.Text=$chosen}
            & $savePreferences
            return $true
        }catch{& $showError $_.Exception.Message 'Не удалось выбрать папку';return $false}
    }.GetNewClosure()

    $findActs = {
        param([bool]$ScanFolder = $true,[bool]$PreserveSelection = $false)
        if ($state.Busy) { return }
        $previousChecks=@{}
        if($PreserveSelection){
            [void]$ui.Grid.EndEdit()
            foreach($row in $ui.Grid.Rows){if($null -ne $row.Tag){$previousChecks[[string]$row.Tag.SourcePath]=[bool]$row.Cells[0].Value}}
        }
        if ($ScanFolder) { $state.SourceFiles = @(); $state.Recurse = $true }
        $sourceRoot = $ui.Source.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($sourceRoot)) {
            & $showError 'Выберите папку с файлами.'
            [void]$ui.Source.Focus()
            return
        }
        # Use the mode directly. With the same root, Core keeps each signature
        # next to its own source file, including files in different subfolders.
        $destinationRoot = if ($ui.Beside.Checked) { $sourceRoot } else { $ui.Output.Text.Trim() }
        if ([string]::IsNullOrWhiteSpace($destinationRoot)) {
            & $showError 'Укажите папку результата.'
            [void]$ui.Output.Focus()
            return
        }
        & $savePreferences
        & $invalidatePlan
        $state.Busy = $true
        $ui.Form.UseWaitCursor = $true
        $ui.Find.Text = 'Поиск...'
        $ui.Summary.Text = 'Строим список исходных файлов...'
        & $syncAction
        $ui.Form.Refresh()
        try {
            $signatureNaming=$namingModes[$ui.Naming.SelectedIndex]
            $signerLabel=''
            if($signatureNaming -ne 'legacy') {
                $certificateIndex=$ui.Certificate.SelectedIndex
                if($certificateIndex -lt 0 -or $certificateIndex -ge $state.Certificates.Count) { throw 'Сначала выберите сертификат для имени подписи.' }
                $info=$state.Certificates[$certificateIndex]
                if($null -ne $info.PSObject.Properties['FileLabel']) { $signerLabel=[string]$info.FileLabel }
                else { $signerLabel='cert_'+([string]$info.Thumbprint).Substring(0,12).ToLowerInvariant() }
            }
            $plan = & $PlanProvider $sourceRoot $destinationRoot $signatureNaming $signerLabel $state.SourceFiles $state.Recurse
            if ($null -eq $plan) { throw 'Не удалось построить список файлов.' }
            $state.SuppressGridEvents = $true
            $ui.Grid.SuspendLayout()
            try {
                foreach ($item in @($plan.Items)) {
                    if ($null -eq $item) { continue }
                    $existing = [bool]$item.ExistingSignature
                    $status = 'Подписей рядом нет'
                    $neighborCount = 0
                    if ($null -ne $item.PSObject.Properties['NeighborSignatureCount']) { $neighborCount = [int]$item.NeighborSignatureCount }
                    if ($neighborCount -gt 0) { $status = 'Проверить подписи (' + $neighborCount + ')'  }
                    if ($existing) { $status = 'Проверить подпись' }
                    $archive=[IO.Path]::GetExtension([string]$item.SourcePath).ToLowerInvariant() -in @('.zip','.7z','.rar','.tar','.gz','.bz2','.xz','.tgz','.tbz','.tbz2','.txz','.zst','.cab','.iso')
                    $checked=(-not $ScanFolder) -or ((-not $existing) -and (-not $archive))
                    if($previousChecks.ContainsKey([string]$item.SourcePath)){$checked=[bool]$previousChecks[[string]$item.SourcePath]}
                    $rowIndex = $ui.Grid.Rows.Add([object[]]@($checked, [string]$item.RelativePath, $status))
                    $row = $ui.Grid.Rows[$rowIndex]
                    $row.Tag = $item
                    $row.Cells[0].ReadOnly = $false
                    if($archive -and $ScanFolder){$row.Cells[0].ToolTipText='При поиске папки архивы изначально без галочки. При необходимости отметьте файл вручную или выберите его явно.'}
                    $row.Cells[1].ToolTipText = 'Исходный файл: ' + [string]$item.SourcePath + $newLine + 'Подпись: ' + [string]$item.SignaturePath
                    $row.Cells[2].ToolTipText = [string]$item.SignaturePath
                    if (-not $existing -and $neighborCount -gt 0) {
                        $row.Cells[2].ToolTipText = 'Соседние подписи найдены, но ещё не проверены. Галочка включает файл в проверку. Если математическая проверка подтвердит подпись точных байтов файла выбранным сертификатом, повторной подписи не будет.'
                    }
                    if ($existing) {
                        $row.DefaultCellStyle.ForeColor = [Drawing.SystemColors]::GrayText
                        $row.Cells[0].ToolTipText = 'Можно отметить для проверки существующей подписи. Подтверждённая подпись выбранного сертификата пропускается без ключа; неопределённая блокирует этот файл. Файл подписи не перезаписывается.'
                    }
                }
            }
            finally {
                $ui.Grid.ResumeLayout()
                $state.SuppressGridEvents = $false
            }
            $state.Plan = $plan
            $ui.Grid.ClearSelection()
        }
        catch {
            $state.Plan = $null
            $state.SuppressGridEvents = $true
            try { $ui.Grid.Rows.Clear() }
            finally { $state.SuppressGridEvents = $false }
            $ui.Summary.Text = 'Поиск не завершён. Проверьте пути и доступ к исходной папке.'
            & $showError $_.Exception.Message 'Не удалось найти файлы'
        }
        finally {
            $state.Busy = $false
            $ui.Form.UseWaitCursor = $false
            $ui.Find.Text = 'Обновить список'
            & $syncAction
        }
    }.GetNewClosure()

    $sourceBox.Add_TextChanged({
        if ($state.SuppressChanges) { return }
        $state.SourceFiles = @(); $state.Recurse = $true
        & $syncOutputToSource
        & $invalidatePlan
    }.GetNewClosure())
    $outputBox.Add_TextChanged({
        if ($state.SuppressChanges) { return }
        if (-not $ui.Beside.Checked) { $state.SeparateOutputText = $ui.Output.Text }
        & $invalidatePlan
    }.GetNewClosure())
    $beside.Add_CheckedChanged({
        if ($state.SuppressChanges) { return }
        if ($ui.Beside.Checked) { $state.SeparateOutputText = $ui.Output.Text }
        & $syncOutputToSource
        & $invalidatePlan
        & $savePreferences
    }.GetNewClosure())
    $naming.Add_SelectedIndexChanged({ & $invalidatePlan; & $savePreferences }.GetNewClosure())
    $sourceBox.Add_Leave({ & $savePreferences }.GetNewClosure())
    $outputBox.Add_Leave({ & $savePreferences }.GetNewClosure())
    $sourceBrowse.Add_Click({if(& $browseFolder $false){& $findActs $true}}.GetNewClosure())
    $sourceBox.Add_KeyDown({
        param($sender,$eventArgs)
        if($eventArgs.KeyCode -eq [Windows.Forms.Keys]::Enter){$eventArgs.Handled=$true;$eventArgs.SuppressKeyPress=$true;& $findActs $true}
    }.GetNewClosure())
    $outputBrowse.Add_Click({ [void](& $browseFolder $true) }.GetNewClosure())
    $refresh.Add_Click({ & $refreshCertificates }.GetNewClosure())
    $details.Add_Click({ & $openCertificateDetails }.GetNewClosure())
    $certificateBox.Add_SelectedIndexChanged({ & $invalidatePlan; & $showCertificate }.GetNewClosure())
    $find.Add_Click({ & $findActs (@($state.SourceFiles).Count -eq 0) $true }.GetNewClosure())
    $pickFiles.Add_Click({
        if ($state.Busy) { return }
        try {
            $chosen = @(& $FilePickerProvider $ui.Form $ui.Source.Text.Trim() | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            if ($chosen.Count -eq 0) { return }
            $sourceRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath([string]$chosen[0]))
            $state.SuppressChanges = $true
            try { $ui.Source.Text = $sourceRoot }
            finally { $state.SuppressChanges = $false }
            $state.SourceFiles = [string[]]$chosen
            $state.Recurse = $false
            & $syncOutputToSource
            & $findActs $false
        }
        catch { & $showError $_.Exception.Message 'Не удалось выбрать файлы' }
    }.GetNewClosure())
    $grid.Add_CurrentCellDirtyStateChanged({
        if ($ui.Grid.IsCurrentCellDirty) {
            [void]$ui.Grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
        }
    }.GetNewClosure())
    $grid.Add_CellValueChanged({
        param($sender, $eventArgs)
        if ($eventArgs.RowIndex -ge 0 -and $eventArgs.ColumnIndex -eq 0) { & $syncAction }
    }.GetNewClosure())
    $setRowChecks={
        param([bool]$Check,[bool]$SelectedOnly=$false)
        if($state.Busy -or $null -eq $state.Plan){return}
        $state.SuppressGridEvents=$true
        try{
            if($ui.Grid.IsCurrentCellDirty){[void]$ui.Grid.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit)}
            [void]$ui.Grid.EndEdit()
            $rows=if($SelectedOnly){@($ui.Grid.SelectedRows)}else{@($ui.Grid.Rows)}
            foreach($row in $rows){if($null -ne $row.Tag){$row.Cells[0].Value=$Check}}
        }finally{$state.SuppressGridEvents=$false}
        & $syncAction
    }.GetNewClosure()
    $selectNew.Add_Click({& $setRowChecks $true}.GetNewClosure())
    $clearSelection.Add_Click({& $setRowChecks $false}.GetNewClosure())
    $grid.Add_KeyDown({
        param($sender,$eventArgs)
        if($eventArgs.KeyCode -eq [Windows.Forms.Keys]::Space -and $eventArgs.Modifiers -eq [Windows.Forms.Keys]::None -and $ui.Grid.SelectedRows.Count -gt 0){
            $eventArgs.Handled=$true;$eventArgs.SuppressKeyPress=$true
            $check=@($ui.Grid.SelectedRows | Where-Object {-not [bool]$_.Cells[0].Value}).Count -gt 0
            & $setRowChecks $check $true
        }
    }.GetNewClosure())
    $groupMenu=New-Object Windows.Forms.ContextMenuStrip
    $groupMenu.AccessibleName='Галочки выделенных файлов'
    $markGroup=New-Object Windows.Forms.ToolStripMenuItem('Отметить выделенные')
    $unmarkGroup=New-Object Windows.Forms.ToolStripMenuItem('Снять галочки с выделенных')
    [void]$groupMenu.Items.Add($markGroup);[void]$groupMenu.Items.Add($unmarkGroup)
    $markGroup.Add_Click({& $setRowChecks $true $true}.GetNewClosure())
    $unmarkGroup.Add_Click({& $setRowChecks $false $true}.GetNewClosure())
    $groupMenu.Add_Opening({
        param($sender,$eventArgs)
        $enabled=(-not $state.Busy) -and $null -ne $state.Plan -and $ui.Grid.SelectedRows.Count -gt 0
        $markGroup.Enabled=$enabled;$unmarkGroup.Enabled=$enabled;$eventArgs.Cancel=(-not $enabled)
    }.GetNewClosure())
    $grid.ContextMenuStrip=$groupMenu
    $grid.Add_CellMouseDown({
        param($sender,$eventArgs)
        if($eventArgs.Button -eq [Windows.Forms.MouseButtons]::Right -and $eventArgs.RowIndex -ge 0 -and -not $ui.Grid.Rows[$eventArgs.RowIndex].Selected){
            $ui.Grid.ClearSelection();$ui.Grid.CurrentCell=$ui.Grid.Rows[$eventArgs.RowIndex].Cells[1]
            $ui.Grid.Rows[$eventArgs.RowIndex].Selected=$true
        }
    }.GetNewClosure())
    $sign.Add_Click({
        try {
            if ($state.Busy -or $null -eq $state.Plan) { return }
            if ($ui.Grid.IsCurrentCellDirty) {
                [void]$ui.Grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
            }
            [void]$ui.Grid.EndEdit()
            $certificateIndex = $ui.Certificate.SelectedIndex
            if ($certificateIndex -lt 0 -or $certificateIndex -ge $state.Certificates.Count) {
                throw 'Выберите сертификат для подписи.'
            }
            $selectedItems = New-Object 'System.Collections.Generic.List[object]'
            foreach ($row in $ui.Grid.Rows) {
                if ($null -ne $row.Tag -and [bool]$row.Cells[0].Value) {
                    $selectedItems.Add($row.Tag)
                }
            }
            if ($selectedItems.Count -eq 0) { throw 'Отметьте хотя бы один файл для проверки или подписания.' }
            $selectedPlan = [pscustomobject]@{
                AllFiles = $(if ($null -ne $state.Plan.PSObject.Properties['AllFiles']) { [bool]$state.Plan.AllFiles } else { $true })
                Recurse = $(if ($null -ne $state.Plan.PSObject.Properties['Recurse']) { [bool]$state.Plan.Recurse } else { [bool]$state.Recurse })
                SourceFiles = @(if ($null -ne $state.Plan.PSObject.Properties['SourceFiles']) { $state.Plan.SourceFiles } else { $state.SourceFiles })
                Root = $state.Plan.Root
                OutputRoot = $state.Plan.OutputRoot
                SeparateOutput = [bool]$state.Plan.SeparateOutput
                Items = @($selectedItems.ToArray())
                SkippedReparsePoints = @($state.Plan.SkippedReparsePoints)
            }
            $state.Result = [pscustomobject]@{
                Plan = $selectedPlan
                CertificateInfo = $state.Certificates[$certificateIndex]
                CopyOriginals = [bool]$state.Plan.SeparateOutput
            }
            $ui.Form.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $ui.Form.Close()
        }
        catch { & $showError $_.Exception.Message 'Не удалось начать подписание' }
    }.GetNewClosure())
    $form.Add_Shown({
        if (-not $state.Started) {
            $state.Started = $true
            & $refreshCertificates
            [void]$ui.Source.Focus()
        }
    }.GetNewClosure())
    $form.Add_FormClosing({ & $savePreferences }.GetNewClosure())

    & $syncOutputToSource
    & $syncAction
    $form.ResumeLayout($true)
    $form.PerformAutoScale()
    # Apply screen-relative window bounds after the initial font scaling.
    $form.MinimumSize = New-Object System.Drawing.Size([Math]::Min(640, $availableWidth), [Math]::Min(480, $availableHeight))
    $form.Size = New-Object System.Drawing.Size([Math]::Min(1180, $availableWidth), [Math]::Min(800, $availableHeight))
    try {
        [void]$form.ShowDialog()
        return $state.Result
    }
    finally {
        $form.Dispose()
        $groupMenu.Dispose()
        $toolTip.Dispose()
        $titleFont.Dispose()
        $baseFont.Dispose()
    }
}

Export-ModuleMember -Function Show-ActSignerWindow
