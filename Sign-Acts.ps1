#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$session = $null
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
    try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
    try { $Host.UI.RawUI.WindowTitle = 'Подпись актов через КриптоПро 1.2' } catch { }
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

    Write-Host 'Подключите флешку или токен к Windows внутри VM.'
    Write-Host 'В окне выберите папки, сертификат и акты для подписи.'
    $selection = Show-ActSignerWindow -CertificateProvider { Get-ActCertificates } -PlanProvider {
        param($Root, $OutputRoot)
        Get-ActPlan -Root $Root -OutputRoot $OutputRoot
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
        Write-Host ('Выбрано актов: {0}' -f @($selection.Plan.Items).Count)
        Write-Host ('Результат: {0}' -f $selection.Plan.OutputRoot)
        Write-Host 'PIN вводите только в штатном окне КриптоПро или токена.'
        Write-Host 'Отмена запроса PIN остановит пакет. Уже готовые подписи сохранятся.'
        Write-Host ''

        $session = New-ActCryptoSession -CertificateInfo $certificate
        $signBlock = {
            param([byte[]]$PdfBytes)
            Invoke-ActCryptoSign -Session $session -PdfBytes $PdfBytes
        }.GetNewClosure()
        $verifyBlock = {
            param([byte[]]$PdfBytes, [byte[]]$SignatureBytes, [string]$Thumbprint)
            Test-ActCryptoSignature -PdfBytes $PdfBytes -SignatureBytes $SignatureBytes -Thumbprint $Thumbprint
        }
        $progressBlock = {
            param($Event)
            if ($Event.Status -eq 'signing') {
                Write-Host ('[{0}/{1}] {2}' -f $Event.Index, $Event.Total, $Event.Item.RelativePath)
            }
            elseif ($Event.Status -eq 'signed_verified') {
                Write-Host '  Создана и проверена.' -ForegroundColor Green
            }
            elseif ($Event.Status -eq 'error') {
                Write-Host ('  Ошибка: {0}' -f $Event.Message) -ForegroundColor Red
            }
            elseif ($Event.Status -eq 'exists_unverified') {
                Write-Host ('  Пропущен готовый файл: {0}' -f $Event.Item.RelativePath)
            }
        }
        $logRoot = Join-Path $selection.Plan.OutputRoot '_ActSigner_logs'
        $result = Invoke-ActBatch -Plan $selection.Plan -Thumbprint $certificate.Thumbprint `
            -SignBlock $signBlock -VerifyBlock $verifyBlock -LogRoot $logRoot `
            -CopyOriginals:([bool]$selection.CopyOriginals) -OnProgress $progressBlock
        Write-Host ''
        Write-Host ('Создано и проверено: {0}' -f $result.CompletedCount)
        Write-Host ('Пропущено существующих: {0}' -f $result.SkippedCount)
        Write-Host ('Ошибок: {0}; не обработано: {1}' -f $result.ErrorCount, $result.NotProcessedCount)
        Write-Host ('Журнал: {0}' -f $result.LogPath)
        if ($result.Stopped) {
            $exitCode = 1
            Write-Host 'Пакет остановлен. Причина указана выше и в журнале.' -ForegroundColor Yellow
            Write-Host 'После устранения причины запустите программу снова: готовые подписи не перезаписываются.'
        }
        else {
            Write-Host ('Готово. Файлы находятся в: {0}' -f $selection.Plan.OutputRoot) -ForegroundColor Green
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
    if ($null -ne $session) { Close-ActCryptoSession -Session $session }
}
exit $exitCode
