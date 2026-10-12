#requires -Version 5.1
Set-StrictMode -Version 2.0

function New-ActComObject {
    param([Parameter(Mandatory = $true)][string]$ProgId)
    $type = [Type]::GetTypeFromProgID($ProgId, $true)
    $value = [Activator]::CreateInstance($type)
    if ($null -eq $value) { throw ('Не удалось создать ' + $ProgId) }
    return ,$value
}

# Use IDispatch through .NET reflection, without PowerShell's COM member adapter.
# Unary comma preserves empty/single-item/iterable COM collections as one object.
function Get-ActComProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Target,
        [Parameter(Mandatory = $true)][string]$Name,
        [object[]]$Arguments = @()
    )
    $flags = [Reflection.BindingFlags]::GetProperty -bor [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Instance
    $value = $Target.GetType().InvokeMember($Name, $flags, $null, $Target, [object[]]$Arguments)
    return ,$value
}

function Invoke-ActComMethod {
    param(
        [Parameter(Mandatory = $true)][object]$Target,
        [Parameter(Mandatory = $true)][string]$Name,
        [object[]]$Arguments = @()
    )
    $flags = [Reflection.BindingFlags]::InvokeMethod -bor [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Instance
    $value = $Target.GetType().InvokeMember($Name, $flags, $null, $Target, [object[]]$Arguments)
    return ,$value
}

function Set-ActComProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Target,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowNull()][object]$Value
    )
    $flags = [Reflection.BindingFlags]::SetProperty -bor [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Instance
    # SetProperty supports both PROPPUT and PROPPUTREF for COM object properties.
    [void]$Target.GetType().InvokeMember($Name, $flags, $null, $Target, [object[]]@(,$Value))
}

function Close-ActComObject {
    param([object]$Value)
    if ($null -ne $Value -and [Runtime.InteropServices.Marshal]::IsComObject($Value)) {
        # Release this reference once; never force all other RCW references closed.
        try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($Value) } catch { }
    }
}

function Get-ActNativeError {
    param([System.Exception]$Exception)
    $detail = $Exception
    while ($null -ne $detail.InnerException) { $detail = $detail.InnerException }
    return ('{0} (0x{1}; {2})' -f $detail.Message, $detail.HResult.ToString('X8'), $detail.GetType().Name)
}

function Get-ActStageError {
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $line = $ErrorRecord.InvocationInfo.ScriptLineNumber
    return ('Этап {0}: {1}. Строка {2}.' -f $Stage, (Get-ActNativeError $ErrorRecord.Exception), $line)
}

function Get-ActNormalizedThumbprint {
    param([string]$Thumbprint)
    $value = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($value -notmatch '^[0-9A-F]{40}$') { throw 'Некорректный отпечаток сертификата.' }
    return $value
}

function Test-ActCryptoPro {
    # The lookup does not instantiate and prematurely release the Store before discovery.
    try {
        foreach ($progId in @('CAdESCOM.Store', 'CAdESCOM.CadesSignedData', 'CAdESCOM.CPSigner')) {
            if ($null -eq [Type]::GetTypeFromProgID($progId, $false)) {
                throw ('Компонент не зарегистрирован: ' + $progId)
            }
        }
        return [pscustomobject]@{ Available = $true; Message = '' }
    }
    catch {
        return [pscustomobject]@{
            Available = $false
            Message = ('Не найден компонент КриптоПро ЭЦП (CAdESCOM). ' +
                'Установите КриптоПро ЭЦП Browser plug-in в Windows внутри VM, затем запустите программу снова.' +
                [Environment]::NewLine + 'Официальная страница: https://cryptopro.ru/products/cades/plugin' +
                [Environment]::NewLine + (Get-ActNativeError $_.Exception))
        }
    }
}

function Get-ActCertificates {
    # 100 reads certificates directly from containers; 2 is CurrentUser\My.
    # Every refresh opens fresh stores. No key import/export and no signing here.
    $byThumbprint = @{}
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    $storeCounts = New-Object 'System.Collections.Generic.List[string]'
    $expiredCount = 0
    $missingKeyCount = 0
    $unsupportedCount = 0
    $unreadableCount = 0
    $now = [DateTime]::Now
    foreach ($kind in @(100, 2)) {
        $store = $null
        $certificates = $null
        $opened = $false
        $source = if ($kind -eq 100) { 'Контейнер КриптоПро' } else { 'Личное хранилище Windows' }
        $stage = 'создание CAdESCOM.Store'
        try {
            $store = New-ActComObject 'CAdESCOM.Store'
            $stage = 'Store.Open'
            [void](Invoke-ActComMethod $store 'Open' @([int]$kind, 'My', [int]0))
            $opened = $true
            $stage = 'Store.Certificates'
            $certificates = Get-ActComProperty $store 'Certificates'
            if ($null -eq $certificates) { throw 'КриптоПро вернул пустой объект коллекции сертификатов.' }
            $stage = 'Certificates.Count'
            $count = [int](Get-ActComProperty $certificates 'Count')
            $storeCounts.Add(('{0}: сертификатов прочитано {1}.' -f $source, $count))
            for ($i = 1; $i -le $count; $i++) {
                $certificate = $null
                $metadata = $null
                $certificateStage = 'Certificates.Item'
                try {
                    # Item is an indexed property, not a method.
                    $certificate = Get-ActComProperty $certificates 'Item' @([int]$i)
                    if ($null -eq $certificate) { throw 'КриптоПро вернул пустой объект сертификата.' }
                    $certificateStage = 'Certificate.HasPrivateKey'
                    if (-not [bool](Invoke-ActComMethod $certificate 'HasPrivateKey')) {
                        $missingKeyCount++
                        continue
                    }
                    $certificateStage = 'Certificate.Export'
                    $publicCertificate = [string](Invoke-ActComMethod $certificate 'Export' @([int]0))
                    $raw = [Convert]::FromBase64String($publicCertificate)
                    $certificateStage = 'разбор открытого сертификата X509'
                    $metadata = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
                    if ($metadata.GetKeyAlgorithm() -notin @('1.2.643.7.1.1.1.1', '1.2.643.7.1.1.1.2')) {
                        $unsupportedCount++
                        continue
                    }
                    if ($metadata.NotBefore -gt $now -or $metadata.NotAfter -le $now) {
                        $expiredCount++
                        continue
                    }
                    $thumbprint = Get-ActNormalizedThumbprint $metadata.Thumbprint
                    if ($byThumbprint.ContainsKey($thumbprint)) { continue }
                    $displayName = $metadata.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $metadata.Subject }
                    $byThumbprint[$thumbprint] = [pscustomobject]@{
                        Thumbprint = $thumbprint
                        DisplayName = $displayName
                        Subject = $metadata.Subject
                        Issuer = $metadata.Issuer
                        NotBefore = $metadata.NotBefore
                        NotAfter = $metadata.NotAfter
                        Source = $source
                        StoreKind = $kind
                    }
                }
                catch {
                    $unreadableCount++
                    if ($unreadableCount -le 5) {
                        $warnings.Add(('{0}, сертификат {1}. {2}' -f $source, $i, (Get-ActStageError $certificateStage $_)))
                    }
                }
                finally {
                    if ($null -ne $metadata) { $metadata.Dispose() }
                    Close-ActComObject $certificate
                }
            }
        }
        catch {
            $warnings.Add(('{0}. {1}' -f $source, (Get-ActStageError $stage $_)))
        }
        finally {
            Close-ActComObject $certificates
            if ($opened) { try { [void](Invoke-ActComMethod $store 'Close') } catch { } }
            Close-ActComObject $store
        }
    }
    if ($expiredCount -gt 0) {
        $warnings.Add(('Вне срока действия: {0}. Проверьте срок сертификатов и дату в Windows VM.' -f $expiredCount))
    }
    if ($missingKeyCount -gt 0) {
        $warnings.Add(('Без связи с закрытым ключом: {0}. При необходимости установите личный сертификат с привязкой к контейнеру через КриптоПро.' -f $missingKeyCount))
    }
    if ($unsupportedCount -gt 0) {
        $warnings.Add(('С другим алгоритмом: {0}. Для подписи нужен сертификат ГОСТ Р 34.10-2012.' -f $unsupportedCount))
    }
    if ($unreadableCount -gt 5) {
        $warnings.Add(('Всего ошибок чтения сертификатов: {0}; выше показаны первые пять.' -f $unreadableCount))
    }
    if ($byThumbprint.Count -eq 0) {
        foreach ($message in $storeCounts) { $warnings.Add($message) }
    }
    return [pscustomobject]@{
        Certificates = @($byThumbprint.Values | Sort-Object DisplayName, NotAfter, Thumbprint)
        Warnings = @($warnings.ToArray())
    }
}

function New-ActCryptoSession {
    param([Parameter(Mandatory = $true)][object]$CertificateInfo)
    $thumbprint = Get-ActNormalizedThumbprint $CertificateInfo.Thumbprint
    $kind = [int]$CertificateInfo.StoreKind
    if ($kind -notin @(2, 100)) { throw 'Неизвестное хранилище сертификата.' }
    $store = $null
    $certificates = $null
    $matches = $null
    $selected = $null
    $opened = $false
    $transferred = $false
    $stage = 'создание CAdESCOM.Store'
    try {
        $store = New-ActComObject 'CAdESCOM.Store'
        $stage = 'Store.Open'
        [void](Invoke-ActComMethod $store 'Open' @([int]$kind, 'My', [int]0))
        $opened = $true
        $stage = 'Store.Certificates'
        $certificates = Get-ActComProperty $store 'Certificates'
        $stage = 'Certificates.Find'
        $matches = Invoke-ActComMethod $certificates 'Find' @([int]0, $thumbprint, $false)
        $stage = 'Certificates.Count'
        $count = [int](Get-ActComProperty $matches 'Count')
        for ($i = 1; $i -le $count; $i++) {
            $candidate = $null
            try {
                $stage = 'Certificates.Item'
                $candidate = Get-ActComProperty $matches 'Item' @([int]$i)
                $stage = 'Certificate.HasPrivateKey'
                if ([bool](Invoke-ActComMethod $candidate 'HasPrivateKey')) {
                    $selected = $candidate
                    $candidate = $null
                    break
                }
            }
            finally { Close-ActComObject $candidate }
        }
        if ($null -eq $selected) {
            throw 'Выбранный сертификат или его закрытый ключ больше не доступен. Подключите носитель и обновите список.'
        }
        $stage = 'проверка выбранного сертификата'
        $foundThumbprint = [string](Get-ActComProperty $selected 'Thumbprint')
        if ((Get-ActNormalizedThumbprint $foundThumbprint) -ne $thumbprint) {
            throw 'Отпечаток найденного сертификата не совпадает с выбранным.'
        }
        $now = [DateTime]::Now
        $notBefore = [DateTime](Get-ActComProperty $selected 'ValidFromDate')
        $notAfter = [DateTime](Get-ActComProperty $selected 'ValidToDate')
        if ($notBefore -gt $now -or $notAfter -le $now) {
            throw 'Срок действия выбранного сертификата ещё не начался или уже закончился.'
        }
        $session = [pscustomobject]@{
            Store = $store
            Certificate = $selected
            Thumbprint = $thumbprint
            Closed = $false
        }
        $transferred = $true
        return $session
    }
    catch { throw ('Не удалось открыть ключ выбранного сертификата. ' + (Get-ActStageError $stage $_)) }
    finally {
        Close-ActComObject $matches
        Close-ActComObject $certificates
        if (-not $transferred) {
            Close-ActComObject $selected
            if ($opened) { try { [void](Invoke-ActComMethod $store 'Close') } catch { } }
            Close-ActComObject $store
        }
    }
}

function Invoke-ActCryptoSign {
    param(
        [Parameter(Mandatory = $true)][object]$Session,
        [Parameter(Mandatory = $true)][byte[]]$PdfBytes
    )
    if ($Session.Closed) { throw 'Сеанс подписи уже закрыт.' }
    $signer = $null
    $attribute = $null
    $attributes = $null
    $data = $null
    $stage = 'создание CAdESCOM.CPSigner'
    try {
        $signer = New-ActComObject 'CAdESCOM.CPSigner'
        $stage = 'настройка CPSigner'
        Set-ActComProperty $signer 'Certificate' $Session.Certificate
        Set-ActComProperty $signer 'CheckCertificate' $true
        Set-ActComProperty $signer 'Options' ([int]2)
        $stage = 'атрибут времени подписи'
        $attribute = New-ActComObject 'CAdESCOM.CPAttribute'
        Set-ActComProperty $attribute 'Name' ([int]0)
        Set-ActComProperty $attribute 'Value' ([DateTime]::Now)
        $attributes = Get-ActComProperty $signer 'AuthenticatedAttributes2'
        [void](Invoke-ActComMethod $attributes 'Add' @(,$attribute))
        $stage = 'создание CAdESCOM.CadesSignedData'
        $data = New-ActComObject 'CAdESCOM.CadesSignedData'
        Set-ActComProperty $data 'ContentEncoding' ([int]1)
        Set-ActComProperty $data 'Content' ([Convert]::ToBase64String($PdfBytes))
        $stage = 'CadesSignedData.SignCades'
        $base64 = [string](Invoke-ActComMethod $data 'SignCades' @($signer, [int]1, $true, [int]0))
        [byte[]]$bytes = [Convert]::FromBase64String($base64)
        if ($bytes.Length -eq 0) { throw 'КриптоПро вернул пустую подпись.' }
        return ,$bytes
    }
    catch { throw ('КриптоПро не создал подпись. ' + (Get-ActStageError $stage $_)) }
    finally {
        Close-ActComObject $data
        Close-ActComObject $attributes
        Close-ActComObject $attribute
        Close-ActComObject $signer
    }
}

function Test-ActCryptoSignature {
    param(
        [Parameter(Mandatory = $true)][byte[]]$PdfBytes,
        [Parameter(Mandatory = $true)][byte[]]$SignatureBytes,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )
    $expected = Get-ActNormalizedThumbprint $Thumbprint
    $data = $null
    $signers = $null
    $signer = $null
    $certificate = $null
    $stage = 'создание CAdESCOM.CadesSignedData'
    try {
        $data = New-ActComObject 'CAdESCOM.CadesSignedData'
        Set-ActComProperty $data 'ContentEncoding' ([int]1)
        Set-ActComProperty $data 'Content' ([Convert]::ToBase64String($PdfBytes))
        $stage = 'CadesSignedData.VerifyCades'
        [void](Invoke-ActComMethod $data 'VerifyCades' @([Convert]::ToBase64String($SignatureBytes), [int]1, $true))
        $stage = 'проверка подписанта'
        $signers = Get-ActComProperty $data 'Signers'
        if ([int](Get-ActComProperty $signers 'Count') -ne 1) {
            throw 'В новой подписи неожиданное число подписантов.'
        }
        $signer = Get-ActComProperty $signers 'Item' @([int]1)
        $certificate = Get-ActComProperty $signer 'Certificate'
        $actual = [string](Get-ActComProperty $certificate 'Thumbprint')
        if ((Get-ActNormalizedThumbprint $actual) -ne $expected) {
            throw 'Новая подпись создана другим сертификатом.'
        }
    }
    catch { throw ('Проверка новой подписи не прошла. ' + (Get-ActStageError $stage $_)) }
    finally {
        Close-ActComObject $certificate
        Close-ActComObject $signer
        Close-ActComObject $signers
        Close-ActComObject $data
    }
}

function Close-ActCryptoSession {
    param([object]$Session)
    if ($null -eq $Session -or $Session.Closed) { return }
    $Session.Closed = $true
    Close-ActComObject $Session.Certificate
    try { [void](Invoke-ActComMethod $Session.Store 'Close') } catch { }
    Close-ActComObject $Session.Store
    $Session.Certificate = $null
    $Session.Store = $null
}

Export-ModuleMember -Function Test-ActCryptoPro, Get-ActCertificates, New-ActCryptoSession, Invoke-ActCryptoSign, Test-ActCryptoSignature, Close-ActCryptoSession
