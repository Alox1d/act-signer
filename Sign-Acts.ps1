#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$signingState = @{ Session = $null }
$consoleState = $null
$exitCode = 0
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Эта программа предназначена для Windows с установленным КриптоПро CSP.'
    }
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'Запустите Start.cmd: нужен встроенный Windows PowerShell 5.1.'
    }
    if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        throw 'Запустите Start.cmd: для окна выбора нужен режим STA.'
    }
    Import-Module (Join-Path $PSScriptRoot 'ActSigner.Console.psm1') -Force -DisableNameChecking
    $consoleState = Disable-ActConsoleQuickEdit
    try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
    $displayVersion = '1.5.0'
    try {
        $versionPath = Join-Path $PSScriptRoot 'ActSigner.Version.json'
        if ([IO.File]::Exists($versionPath) -and (New-Object IO.FileInfo($versionPath)).Length -le 4096) {
            $versionInfo = ConvertFrom-Json ([IO.File]::ReadAllText($versionPath, [Text.Encoding]::UTF8))
            if ($versionInfo.Version -is [string] -and $versionInfo.Version -cmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { $displayVersion = $versionInfo.Version }
        }
    }
    catch { }
    try { $Host.UI.RawUI.WindowTitle = 'CSPSigner - подпись файлов через КриптоПро ' + $displayVersion } catch { }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    foreach ($module in @('ActSigner.Core.psm1', 'ActSigner.CryptoPro.psm1', 'ActSigner.Settings.psm1', 'ActSigner.UI.psm1')) {
        Import-Module (Join-Path $PSScriptRoot $module) -Force -Global -DisableNameChecking
    }
    $cryptoStatus = Test-ActCryptoPro
    if (-not $cryptoStatus.Available) {
        [void][System.Windows.Forms.MessageBox]::Show($cryptoStatus.Message, 'Не найден компонент КриптоПро',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        throw $cryptoStatus.Message
    }

    Write-Host 'Убедитесь, что носитель ключа доступен в этой Windows.'
    Write-Host 'В окне выберите файлы или папку, затем сертификат для подписи.'
    $selection = Show-ActSignerWindow -CertificateProvider { Get-ActCertificates } -PlanProvider {
        param($Root, $OutputRoot, $SignatureNaming, $SignerLabel, $SourceFiles, $Recurse)
        $scope = @{}
        if (@($SourceFiles).Count -gt 0) { $scope.SourceFiles = [string[]]$SourceFiles }
        Get-ActPlan -Root $Root -OutputRoot $OutputRoot -SignatureNaming $SignatureNaming -SignerLabel $SignerLabel -AllFiles -Recurse:([bool]$Recurse) @scope
    }
    if ($null -eq $selection) {
        Write-Host 'Запуск отменён. Подписание не начиналось.'
    }
    else {
        $certificate = $selection.CertificateInfo
        Write-Host ''
        Write-Host ('Сертификат: {0}' -f $certificate.DisplayName)
        Write-Host ('Действует до: {0:dd.MM.yyyy HH:mm}' -f $certificate.NotAfter)
        Write-Host ('Отпечаток: {0}' -f $certificate.Thumbprint)
        Write-Host ('Выбрано файлов: {0}' -f @($selection.Plan.Items).Count)
        Write-Host ('Результат: {0}' -f $selection.Plan.OutputRoot)
        Write-Host 'PIN вводите только в штатном окне КриптоПро или токена.'
        Write-Host 'Отмена запроса PIN остановит пакет. Уже готовые подписи сохранятся.'
        Write-Host 'Сначала проверяем подписи рядом с файлом. Повторную подпись тем же сертификатом пропускаем.'
        Write-Host ''

        $signBlock = {
            param([byte[]]$PdfBytes)
            if ($null -eq $signingState.Session) {
                $signingState.Session = New-ActCryptoSession -CertificateInfo $certificate
            }
            Invoke-ActCryptoSign -Session $signingState.Session -PdfBytes $PdfBytes
        }.GetNewClosure()
        $existingSignatureInspector = {
            param([byte[]]$PdfBytes, [byte[]]$SignatureBytes)
            Get-ActExistingSignatureInfo -PdfBytes $PdfBytes -SignatureBytes $SignatureBytes
        }
        $verifyBlock = {
            param([byte[]]$PdfBytes, [byte[]]$SignatureBytes, [string]$Thumbprint)
            Test-ActCryptoSignature -PdfBytes $PdfBytes -SignatureBytes $SignatureBytes -Thumbprint $Thumbprint
        }
        $progressBlock = {
            param($Event)
            if ($Event.Status -eq 'checking_existing') {
                Write-Host ('[{0}/{1}] {2}' -f $Event.Index, $Event.Total, $Event.Item.RelativePath)
                Write-Host ('  ' + $Event.Message)
            }
            elseif ($Event.Status -in @('foreign_signature','cancelled')) { Write-Host ('  ' + $Event.Message) -ForegroundColor Yellow }
            elseif ($Event.Status -eq 'signing') {
                Write-Host ('[{0}/{1}] {2}' -f $Event.Index, $Event.Total, $Event.Item.RelativePath)
            }
            elseif ($Event.Status -eq 'signed_verified') {
                Write-Host '  Создана и проверена.' -ForegroundColor Green
            }
            elseif ($Event.Status -eq 'error') {
                Write-Host ('  Ошибка: {0}' -f $Event.Message) -ForegroundColor Red
            }
            elseif ($Event.Status -eq 'already_signed') {
                Write-Host ('  Пропущен: ' + $Event.Message) -ForegroundColor Cyan
            }
            elseif ($Event.Status -eq 'exists_unverified') {
                Write-Host ('  Пропущен готовый файл: {0}' -f $Event.Item.RelativePath)
            }
        }
        $logRoot = Join-Path $selection.Plan.OutputRoot '_CSPSigner_logs'
        $result = Invoke-ActBatch -Plan $selection.Plan -Thumbprint $certificate.Thumbprint `
            -SignBlock $signBlock -VerifyBlock $verifyBlock -ExistingSignatureInspector $existingSignatureInspector -LogRoot $logRoot `
            -CopyOriginals:([bool]$selection.CopyOriginals) -OnProgress $progressBlock
        Write-Host ''
        Write-Host ('Создано и проверено: {0}' -f $result.CompletedCount)
        Write-Host ('Пропущено всего: {0}' -f $result.SkippedCount)
        Write-Host ('Уже подписано выбранным сертификатом: {0}' -f $result.AlreadySignedCount)
        Write-Host ('Отменено: {0}' -f $result.CancelledCount)
        Write-Host ('Ошибок: {0}; не обработано: {1}' -f $result.ErrorCount, $result.NotProcessedCount)
        Write-Host ('Журнал: {0}' -f $result.LogPath)
        if ($result.ErrorCount -gt 0 -or $result.CancelledCount -gt 0) { $exitCode = 1 }
        if ($result.Stopped) {
            $exitCode = 1
            Write-Host 'Пакет остановлен. Причина указана выше и в журнале.' -ForegroundColor Yellow
            Write-Host 'После устранения причины запустите программу снова: готовые подписи не перезаписываются.'
        }
        else {
            if ($result.ErrorCount -gt 0) { Write-Host 'Обработка завершена с ошибками отдельных файлов. Причины указаны в журнале.' -ForegroundColor Yellow }
            Write-Host ('Обработка завершена. Новых подписей: {0}; пропущено: {1}.' -f $result.CompletedCount, $result.SkippedCount) -ForegroundColor Green
            if ($result.CompletedCount -gt 0) { Write-Host ('Новые файлы: {0}' -f $selection.Plan.OutputRoot) }
        }
    }
}
catch {
    $exitCode = 1
    Write-Host ''
    Write-Host ('Ошибка: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host 'Скопируйте текст ошибки, если нужна помощь. PIN и закрытый ключ сообщать не нужно.'
}
finally {
    try {
        if ($null -ne $signingState.Session) { Close-ActCryptoSession -Session $signingState.Session }
    }
    finally {
        if ($null -ne $consoleState) { Restore-ActConsoleQuickEdit -State $consoleState }
    }
}
exit $exitCode
