# File operations for Windows PowerShell 5.1. No UI, private-key or COM access.
Set-StrictMode -Version 2.0

$script:ActMaxBytes = 64MB
$script:ActNamePattern = '^Акт[_ ](?:оказанных[_ ]услуг|выполненных[_ ]работ)(?:\s*\(\d+\))?\.pdf$'
$script:ActPathComparison = [System.StringComparison]::OrdinalIgnoreCase
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    $script:ActPathComparison = [System.StringComparison]::Ordinal
}

function Get-ActFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Путь не указан.' }
    $full = [System.IO.Path]::GetFullPath($Path)
    $volume = [System.IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $volume.Length) {
        $full = $full.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    }
    return $full
}

function Test-ActSamePath {
    param([string]$First, [string]$Second)
    return [string]::Equals($First, $Second, $script:ActPathComparison)
}

function Test-ActPathWithin {
    param([string]$Path, [string]$BasePath)
    if (Test-ActSamePath $Path $BasePath) { return $true }
    $prefix = $BasePath
    if (-not $prefix.EndsWith([string][System.IO.Path]::DirectorySeparatorChar)) {
        $prefix += [System.IO.Path]::DirectorySeparatorChar
    }
    return $Path.StartsWith($prefix, $script:ActPathComparison)
}

function Assert-ActNotReparse {
    param([string]$Path)
    $attributes = [System.IO.File]::GetAttributes($Path)
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw ('Ссылки и точки повторной обработки не поддерживаются: ' + $Path)
    }
}

function Assert-ActSafeExistingAncestors {
    param([string]$Path)
    $current = Get-ActFullPath $Path
    while (-not [string]::IsNullOrEmpty($current)) {
        if ([System.IO.File]::Exists($current) -or [System.IO.Directory]::Exists($current)) {
            Assert-ActNotReparse $current
        }
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or (Test-ActSamePath $parent $current)) { break }
        $current = $parent
    }
}

function New-ActSafeDirectory {
    param([string]$Path)
    Assert-ActSafeExistingAncestors $Path
    if ([System.IO.File]::Exists($Path)) { throw ('Вместо папки найден файл: ' + $Path) }
    [void][System.IO.Directory]::CreateDirectory($Path)
    Assert-ActSafeExistingAncestors $Path
}

function Test-ActWritableDirectory {
    param([string]$Path)
    New-ActSafeDirectory $Path
    $probe = [System.IO.Path]::Combine($Path, '.actsign-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($probe, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $stream.Flush($true)
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([System.IO.File]::Exists($probe)) { [System.IO.File]::Delete($probe) }
    }
}

function Test-ActSignatureExtension {
    param([string]$Path)
    return [IO.Path]::GetExtension($Path) -imatch '^\.(sig|p7s|p7m|sgn)$'
}

function Get-ActNeighborSignaturePaths {
    param($Item)
    $directories = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in @($Item.SourcePath, $Item.DocumentOutputPath)) {
        $directory = [IO.Path]::GetDirectoryName((Get-ActFullPath $path))
        if (@($directories | Where-Object { Test-ActSamePath $_ $directory }).Count -eq 0) { $directories.Add($directory) }
    }
    foreach ($directory in $directories) {
        Assert-ActSafeExistingAncestors $directory
        if (-not [IO.Directory]::Exists($directory)) { continue }
        $info = New-Object IO.DirectoryInfo($directory)
        # Include reparse candidates as unresolved; safe reads reject them without
        # following their targets. No child directory is searched here.
        foreach ($file in @($info.GetFiles() | Sort-Object -Property Name)) {
            if ((Test-ActSamePath $file.FullName $Item.SourcePath) -or (Test-ActSamePath $file.FullName $Item.DocumentOutputPath)) { continue }
            if (Test-ActSignatureExtension $file.Name) { $file.FullName }
        }
    }
}

function Invoke-ActCachedInspection {
    param($SourceState, $SignatureState, [scriptblock]$Inspector, [hashtable]$Context)
    $key = $SignatureState.Hash + ':' + $SourceState.Hash
    if ($Context.Cache.ContainsKey($key)) { return $Context.Cache[$key] }
    # Untrusted sibling association has a separate batch-wide work bound. A hit
    # is reused only for identical signature and source snapshots, never names.
    $work = [long]$SourceState.Bytes.Length + [long]$SignatureState.Bytes.Length + 1
    if ($Context.Calls -ge 4096 -or $Context.WorkBytes + $work -gt 512MB) {
        $Context.Exhausted = $true
        throw 'Превышен предел проверки связей соседних файлов. Разделите пакет на меньшие папки.'
    }
    $Context.Calls++
    $Context.WorkBytes += $work
    $answers = @(& $Inspector ([byte[]]$SourceState.Bytes) ([byte[]]$SignatureState.Bytes))
    if ($answers.Count -ne 1 -or $null -eq $answers[0] -or $null -eq $answers[0].PSObject.Properties['Status']) { throw 'Средство проверки вернуло некорректный результат.' }
    $Context.Cache[$key] = $answers[0]
    return $answers[0]
}

function Test-ActCompleteMathematicalResult {
    param($Answer)
    if ($Answer.Status -ceq 'identified') {
        if ($null -eq $Answer.PSObject.Properties['Signers'] -or @($Answer.Signers).Count -lt 1 -or @($Answer.Signers).Count -gt 4096) { return $false }
        foreach ($signer in @($Answer.Signers)) {
            if ($null -eq $signer -or $null -eq $signer.PSObject.Properties['Thumbprint'] -or $null -eq $signer.PSObject.Properties['SignatureStatus']) { return $false }
            $thumb = [regex]::Replace([string]$signer.Thumbprint, '\s', '').ToUpperInvariant()
            if ($signer.SignatureStatus -cne 'valid' -or $thumb -cnotmatch '^[0-9A-F]{40}$') { return $false }
        }
        return $true
    }
    if ($Answer.Status -ceq 'valid') {
        if ($null -eq $Answer.PSObject.Properties['Thumbprints'] -or @($Answer.Thumbprints).Count -lt 1) { return $false }
        foreach ($thumb in @($Answer.Thumbprints)) { if ([regex]::Replace([string]$thumb, '\s', '').ToUpperInvariant() -cnotmatch '^[0-9A-F]{40}$') { return $false } }
        return $true
    }
    return $false
}

function Find-ActSiblingSignatureBinding {
    param($Item, $SignatureState, [scriptblock]$Inspector, [hashtable]$Context)
    $directoryPath = [IO.Path]::GetDirectoryName($Item.SourcePath)
    if (-not $Context.Directories.ContainsKey($directoryPath)) {
        Assert-ActSafeExistingAncestors $directoryPath
        $directory = New-Object IO.DirectoryInfo($directoryPath)
        $paths = New-Object 'System.Collections.Generic.List[object]'
        foreach ($file in $directory.GetFiles()) {
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $explicitSource = @($Context.SourceFiles | Where-Object { Test-ActSamePath $_ $file.FullName }).Count -gt 0
            if ((Test-ActGenericSourceFile $file.Name) -or $explicitSource) { $paths.Add($file) }
        }
        $Context.Directories[$directoryPath] = @($paths.ToArray())
    }
    $signatureName = [IO.Path]::GetFileName($SignatureState.Path)
    # Filename hints affect ordering only. A candidate is unrelated solely after
    # every signer is mathematically verified against another exact source.
    $candidates = @($Context.Directories[$directoryPath] | Sort-Object -Property @{Expression={ if ($signatureName.StartsWith($_.Name, [StringComparison]::OrdinalIgnoreCase)) { 0 } else { 1 } }}, FullName)
    foreach ($file in $candidates) {
        if (Test-ActSamePath $file.FullName $Item.SourcePath) { continue }
        $state = $null
        try {
            $state = Open-ActReadState -Path $file.FullName
            $answer = Invoke-ActCachedInspection $state $SignatureState $Inspector $Context
            if (Test-ActCompleteMathematicalResult $answer) { return [pscustomobject]@{ Path = $state.Path; Hash = $state.Hash } }
        }
        catch {
            # Unreadable siblings are not evidence of an unrelated signature.
            # Preserve a finite work limit rather than retrying after exhaustion.
            $failure = $_.Exception
            while ($null -ne $failure) {
                if ($failure.Data['ActSignerFailure'] -in @('session','cancelled') -or $failure -is [OperationCanceledException]) { throw }
                $failure = $failure.InnerException
            }
            if (($Context.ContainsKey('Exhausted') -and $Context.Exhausted) -or $Context.Calls -ge 4096 -or $Context.WorkBytes -ge 512MB) { throw }
        }
        finally { if ($null -ne $state -and $null -ne $state.Stream) { $state.Stream.Dispose() } }
    }
    return $null
}

function Get-ActDeclaredDocumentProof {
    param($SignatureState, [hashtable]$Context)
    if ($null -eq $Context -or -not $Context.ContainsKey('SourceDocuments') -or -not $Context.SourceDocuments.ContainsKey($SignatureState.Path)) { return $null }
    $sourcePath = [string]$Context.SourceDocuments[$SignatureState.Path]
    if (Test-ActSamePath $sourcePath $SignatureState.Path) { return [pscustomobject]@{ Path = $sourcePath; Hash = $SignatureState.Hash } }
    # An output name alone is not a declared document. Require a byte-identical
    # copy of the explicit input, and recheck both snapshots before publication.
    $state = Open-ActReadState -Path $sourcePath
    try {
        if ($state.Hash -ceq $SignatureState.Hash) { return [pscustomobject]@{ Path = $sourcePath; Hash = $state.Hash } }
        return $null
    }
    finally { $state.Stream.Dispose() }
}

function Get-ActNeighborSignatureCheck {
    param($Item, $SourceState, [string]$Thumbprint, [scriptblock]$Inspector, [scriptblock]$OnProgress, [int]$Index, [int]$Total, [hashtable]$BindingContext)
    $paths = @(Get-ActNeighborSignaturePaths $Item)
    $records = New-Object 'System.Collections.Generic.List[object]'
    $issues = New-Object 'System.Collections.Generic.List[string]'
    $bindings = New-Object 'System.Collections.Generic.List[object]'
    $matchingPaths = New-Object 'System.Collections.Generic.List[string]'
    $duplicatePath = ''
    $foreignCount = 0
    $candidateIndex = 0
    foreach ($path in $paths) {
        $candidateIndex++
        Send-ActProgress $OnProgress $Index $Total $Item 'checking_existing' ('Проверяем соседнюю подпись {0}/{1}: {2}' -f $candidateIndex, $paths.Count, [IO.Path]::GetFileName($path))
        $signatureState = $null
        $declaredDocument = $null
        $hasConfirmedSigner = $false
        try {
            if ($null -eq $Inspector) { throw 'Не задано средство проверки существующих подписей. Новая подпись не создаётся.' }
            $signatureState = Open-ActReadState -Path $path
            $records.Add([pscustomobject]@{ Path = $path; Hash = $signatureState.Hash })
            if ($signatureState.Bytes.Length -eq 0) {
                $declaredDocument = Get-ActDeclaredDocumentProof $signatureState $BindingContext
                if ($null -ne $declaredDocument) { $bindings.Add($declaredDocument); continue }
                throw 'Файл подписи пуст.'
            }
            # The exact snapshot is inspected. Close its stream before invoking
            # external code, then recheck its digest before private-key use.
            $signatureState.Stream.Dispose()
            $signatureState.Stream = $null
            if ($null -ne $BindingContext) { $answers = @(Invoke-ActCachedInspection $SourceState $signatureState $Inspector $BindingContext) }
            else { $answers = @(& $Inspector ([byte[]]$SourceState.Bytes) ([byte[]]$signatureState.Bytes)) }
            if ($answers.Count -ne 1 -or $null -eq $answers[0] -or $null -eq $answers[0].PSObject.Properties['Status']) { throw 'Средство проверки вернуло некорректный результат.' }
            $answer = $answers[0]
            if ([string]$answer.Status -cnotin @('identified', 'valid', 'different_content', 'unverifiable')) { throw 'Средство проверки вернуло неизвестный статус.' }
            $confirmedSelected = $false
            if ($answer.Status -ceq 'identified') {
                if ($null -eq $answer.PSObject.Properties['Signers'] -or @($answer.Signers).Count -lt 1 -or @($answer.Signers).Count -gt 4096) { throw 'Не установлен полный состав подписантов CMS.' }
                foreach ($signer in @($answer.Signers)) {
                    if ($null -eq $signer -or $null -eq $signer.PSObject.Properties['Thumbprint'] -or $null -eq $signer.PSObject.Properties['SignatureStatus']) { throw 'Неполные сведения о подписанте CMS.' }
                    $actualThumb = [regex]::Replace([string]$signer.Thumbprint, '\s', '').ToUpperInvariant()
                    if ($actualThumb -cnotmatch '^[0-9A-F]{40}$' -or [string]$signer.SignatureStatus -cnotin @('valid','unverifiable')) { throw 'Некорректные сведения о подписанте CMS.' }
                    if ($signer.SignatureStatus -ceq 'valid') {
                        $hasConfirmedSigner = $true
                        if ($actualThumb -ceq $Thumbprint) { $confirmedSelected = $true }
                    }
                }
            }
            if ($answer.Status -ceq 'valid') {
                if ($null -eq $answer.PSObject.Properties['Thumbprints'] -or @($answer.Thumbprints).Count -eq 0) { throw 'Проверенная подпись не содержит данных подписантов.' }
                foreach ($signerThumb in @($answer.Thumbprints)) {
                    if ([regex]::Replace([string]$signerThumb, '\s', '').ToUpperInvariant() -cnotmatch '^[0-9A-F]{40}$') { throw 'Средство проверки вернуло некорректный отпечаток подписанта.' }
                }
            }
            $completeMatch = Test-ActCompleteMathematicalResult $answer
            if (-not $completeMatch -and -not $hasConfirmedSigner) { $declaredDocument = Get-ActDeclaredDocumentProof $signatureState $BindingContext }
            if ($null -ne $declaredDocument -and -not $completeMatch -and -not $hasConfirmedSigner) {
                # The user explicitly classified these exact bytes as input.
                # Mathematical evidence takes priority; only inconclusive data
                # is treated as an opaque document rather than a corrupt sidecar.
                $bindings.Add($declaredDocument)
                continue
            }
            if ($null -ne $BindingContext -and -not $completeMatch -and -not $confirmedSelected) {
                $binding = Find-ActSiblingSignatureBinding $Item $signatureState $Inspector $BindingContext
                if ($null -ne $binding) { $bindings.Add($binding); continue }
                if ($answer.Status -ceq 'different_content') { throw 'Подпись не подтверждена для этого файла и не связана с другим исходником.' }
            }
            if ($completeMatch) { $matchingPaths.Add($path) }
            if ($answer.Status -ceq 'identified') {
                if ($null -eq $answer.PSObject.Properties['Signers'] -or @($answer.Signers).Count -lt 1 -or @($answer.Signers).Count -gt 4096) { throw 'Не установлен полный состав подписантов CMS.' }
                $confirmedOwn = $false
                $unresolved = $false
                $details = New-Object 'System.Collections.Generic.List[string]'
                foreach ($signer in @($answer.Signers)) {
                    if ($null -eq $signer -or $null -eq $signer.PSObject.Properties['Thumbprint'] -or $null -eq $signer.PSObject.Properties['SignatureStatus']) { throw 'Неполные сведения о подписанте CMS.' }
                    $actual = [regex]::Replace([string]$signer.Thumbprint, '\s', '').ToUpperInvariant()
                    if ($actual -cnotmatch '^[0-9A-F]{40}$' -or [string]$signer.SignatureStatus -cnotin @('valid', 'unverifiable')) { throw 'Некорректные сведения о подписанте CMS.' }
                    if ($signer.SignatureStatus -ceq 'valid' -and $actual -ceq $Thumbprint) { $confirmedOwn = $true }
                    if ($signer.SignatureStatus -cne 'valid') {
                        $unresolved = $true
                        $hr = ''
                        if ($null -ne $signer.PSObject.Properties['HResult'] -and [string]$signer.HResult -cmatch '^0x[0-9A-F]{8}$') { $hr = ' HRESULT ' + $signer.HResult + '.' }
                        $details.Add(('Подписант {0}: математическая проверка над точными байтами файла не подтверждена.{1}' -f $actual, $hr))
                    }
                }
                if ($confirmedOwn) { $duplicatePath = $path; break }
                if ($unresolved) { throw ($details.ToArray() -join ' ') }
                $foreignCount++
                Send-ActProgress $OnProgress $Index $Total $Item 'foreign_signature' ('Чужая подпись: {0}. Математическая проверка успешна; доверие, сроки цепочки и отзыв не проверялись.' -f [IO.Path]::GetFileName($path))
            }
            if ($answer.Status -ceq 'unverifiable') {
                $message = 'Не удалось достоверно проверить подпись.'
                if ($null -ne $answer.PSObject.Properties['Message'] -and -not [string]::IsNullOrWhiteSpace([string]$answer.Message)) { $message = [string]$answer.Message }
                throw $message
            }
            if ($answer.Status -ceq 'valid') {
                if ($null -eq $answer.PSObject.Properties['Thumbprints'] -or @($answer.Thumbprints).Count -eq 0) { throw 'Проверенная подпись не содержит данных подписантов.' }
                $matchesSelected = $false
                foreach ($signerThumb in @($answer.Thumbprints)) {
                    $normalized = [regex]::Replace([string]$signerThumb, '\s', '').ToUpperInvariant()
                    if ($normalized -cnotmatch '^[0-9A-F]{40}$') { throw 'Средство проверки вернуло некорректный отпечаток подписанта.' }
                    if ($normalized -ceq $Thumbprint) { $matchesSelected = $true }
                }
                if ($matchesSelected) { $duplicatePath = $path; break }
                $foreignCount++
            }
        }
        catch {
            $failure = $_.Exception
            while ($null -ne $failure) {
                if ($failure.Data['ActSignerFailure'] -in @('session', 'cancelled') -or $failure -is [OperationCanceledException]) { throw }
                $failure = $failure.InnerException
            }
            $issues.Add(([IO.Path]::GetFileName($path) + ': ' + $_.Exception.Message))
        }
        finally { if ($null -ne $signatureState -and $null -ne $signatureState.Stream) { $signatureState.Stream.Dispose() } }
    }
    # A confirmed selected-certificate duplicate ends further inspections, even
    # after an unsupported candidate. Otherwise uncertainty must not become absence.
    if ([string]::IsNullOrEmpty($duplicatePath) -and $issues.Count -gt 0) {
        throw ('Нельзя безопасно создать новую подпись: ' + ($issues.ToArray() -join ' | '))
    }
    return [pscustomobject]@{ Paths = $paths; Records = $records; DuplicatePath = $duplicatePath; ForeignCount = $foreignCount; Bindings = @($bindings.ToArray()); MatchingPaths = @($matchingPaths.ToArray()) }
}

function Assert-ActNeighborSignaturesUnchanged {
    param($Item, $Check, [switch]$DuplicateOnly)
    if (-not $DuplicateOnly) {
        foreach ($binding in @($Check.Bindings)) {
            $state = Open-ActReadState -Path $binding.Path
            try { if ($state.Hash -cne $binding.Hash) { throw ('Исходник, подтвердивший связь соседней подписи, изменился: ' + $binding.Path) } }
            finally { $state.Stream.Dispose() }
        }
        $currentPaths = @(Get-ActNeighborSignaturePaths $Item)
        if ($currentPaths.Count -ne $Check.Paths.Count) { throw 'Набор соседних подписей изменился во время проверки. Повторите поиск и подписание.' }
        foreach ($path in $currentPaths) {
            if (@($Check.Paths | Where-Object { Test-ActSamePath $_ $path }).Count -ne 1) { throw 'Набор соседних подписей изменился во время проверки. Повторите поиск и подписание.' }
        }
    }
    foreach ($record in $Check.Records) {
        if ($DuplicateOnly -and -not (Test-ActSamePath $record.Path $Check.DuplicatePath)) { continue }
        $snapshot = Open-ActReadState -Path $record.Path
        try {
            if ($snapshot.Hash -cne $record.Hash) { throw ('Соседняя подпись изменилась во время проверки: ' + [IO.Path]::GetFileName($record.Path)) }
        }
        finally { $snapshot.Stream.Dispose() }
    }
}

function Get-ActPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [ValidateSet('legacy','signer','document_signer','file_signer')][string]$SignatureNaming = 'legacy',
        [string]$SignerLabel = '',
        [switch]$AllFiles,
        [AllowEmptyCollection()][string[]]$SourceFiles,
        [bool]$Recurse = $true
    )
    if($SignatureNaming -ne 'legacy' -and $SignerLabel -cnotmatch '^[a-z0-9][a-z0-9_-]{0,79}$') { throw 'Не удалось получить безопасное имя подписанта из сертификата. Выберите прежний формат .my.sig.' }
    $sourceRoot = Get-ActFullPath $Root
    $destinationRoot = Get-ActFullPath $OutputRoot
    if (-not [System.IO.Directory]::Exists($sourceRoot)) { throw ('Исходная папка не найдена: ' + $sourceRoot) }
    Assert-ActSafeExistingAncestors $sourceRoot
    Assert-ActSafeExistingAncestors $destinationRoot
    $separate = -not (Test-ActSamePath $sourceRoot $destinationRoot)
    $excludeOutput = $separate -and (Test-ActPathWithin $destinationRoot $sourceRoot)
    $generic = [bool]$AllFiles -or $PSBoundParameters.ContainsKey('SourceFiles')
    $explicit = $PSBoundParameters.ContainsKey('SourceFiles')
    $items = New-Object 'System.Collections.Generic.List[object]'
    $sourceEntries = New-Object 'System.Collections.Generic.List[object]'
    $selectedPaths = New-Object 'System.Collections.Generic.List[string]'
    $reparse = New-Object 'System.Collections.Generic.List[string]'
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    if ($explicit) {
        foreach ($path in @($SourceFiles)) {
            $full = Get-ActFullPath $path
            if (-not (Test-ActPathWithin $full $sourceRoot) -or (Test-ActSamePath $full $sourceRoot)) { throw ('Выбранный файл находится вне исходной папки: ' + $full) }
            if ($excludeOutput -and (Test-ActPathWithin $full $destinationRoot)) { throw ('Нельзя выбрать файл из папки результата: ' + $full) }
            if (-not [IO.File]::Exists($full)) { throw ('Выбранный файл не найден: ' + $full) }
            Assert-ActSafeExistingAncestors $full
            if (@($selectedPaths | Where-Object { Test-ActSamePath $_ $full }).Count -eq 0) {
                $selectedPaths.Add($full)
                $sourceEntries.Add((New-Object IO.FileInfo($full)))
            }
        }
    }
    else { $pending.Push($sourceRoot) }
    $sourcePrefix = $sourceRoot
    if (-not $sourcePrefix.EndsWith([string][System.IO.Path]::DirectorySeparatorChar)) { $sourcePrefix += [System.IO.Path]::DirectorySeparatorChar }
    while ($pending.Count -gt 0) {
        $directoryPath = $pending.Pop()
        Assert-ActNotReparse $directoryPath
        $directory = New-Object System.IO.DirectoryInfo($directoryPath)
        $entries = @($directory.GetFileSystemInfos() | Sort-Object -Property Name)
        foreach ($entry in $entries) {
            if ($excludeOutput -and (Test-ActPathWithin $entry.FullName $destinationRoot)) { continue }
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $reparse.Add($entry.FullName)
                continue
            }
            if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                if ($generic -and $entry.Name -in @('_ActSigner_logs','_CSPSigner_logs')) { continue }
                if ($Recurse) { $pending.Push($entry.FullName) }
                continue
            }
            if ($generic) {
                if (-not (Test-ActGenericSourceFile $entry.Name)) { continue }
            }
            elseif (-not [regex]::IsMatch($entry.Name, $script:ActNamePattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) { continue }
            $sourceEntries.Add($entry)
        }
    }
    foreach ($entry in @($sourceEntries.ToArray() | Sort-Object -Property FullName)) {
        $relative = $entry.FullName.Substring($sourcePrefix.Length)
        $documentOutput = [System.IO.Path]::Combine($destinationRoot, $relative)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($entry.Name)
        $signatureName = switch($SignatureNaming) {
            'signer' { 'signature_' + $SignerLabel + '.sig' }
            'document_signer' { $baseName + '_' + $SignerLabel + '.sig' }
            'file_signer' { $entry.Name + '_' + $SignerLabel + '.sig' }
            default { $baseName + '.my.sig' }
        }
        $signaturePath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($documentOutput), $signatureName)
        $items.Add([pscustomobject]@{
            SourcePath = $entry.FullName
            RelativePath = $relative
            SourceDirectory = $entry.DirectoryName
            SignaturePath = $signaturePath
            DocumentOutputPath = $documentOutput
            ExistingSignature = [System.IO.File]::Exists($signaturePath)
            NeighborSignatureCount = @(Get-ActNeighborSignaturePaths ([pscustomobject]@{ SourcePath = $entry.FullName; DocumentOutputPath = $documentOutput })).Count
        })
    }
    return [pscustomobject]@{
        Root = $sourceRoot
        OutputRoot = $destinationRoot
        SeparateOutput = $separate
        AllFiles = $generic
        Recurse = $Recurse
        SourceFiles = @($selectedPaths.ToArray())
        Items = @($items.ToArray() | Sort-Object -Property RelativePath)
        SkippedReparsePoints = @($reparse.ToArray())
    }
}

function Test-ActGenericSourceFile {
    param([string]$Name)
    return -not ((Test-ActSignatureExtension $Name) -or [IO.Path]::GetExtension($Name) -ieq '.tmp')
}

function Get-ActSha256 {
    [CmdletBinding(DefaultParameterSetName = 'Bytes')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Bytes')][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')][string]$Path
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            Assert-ActNotReparse $Path
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            $hash = $sha.ComputeHash($stream)
        }
        else { $hash = $sha.ComputeHash($Bytes) }
        return [System.BitConverter]::ToString($hash).Replace('-', '')
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $sha.Dispose()
    }
}

function Open-ActReadState {
    param([string]$Path, [switch]$RequirePdf, [long]$MaxBytes = $script:ActMaxBytes)
    Assert-ActSafeExistingAncestors $Path
    Assert-ActNotReparse $Path
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $length = $stream.Length
        if ($length -gt $MaxBytes) { throw ('Файл больше установленного лимита 64 МиБ: ' + $Path) }
        if ($length -lt 0 -or $length -gt [int]::MaxValue) { throw ('Недопустимый размер файла: ' + $Path) }
        $bytes = New-Object byte[] ([int]$length)
        $read = 0
        while ($read -lt $bytes.Length) {
            $count = $stream.Read($bytes, $read, $bytes.Length - $read)
            if ($count -eq 0) { throw ('Файл изменился во время чтения: ' + $Path) }
            $read += $count
        }
        if ($RequirePdf -and ($bytes.Length -lt 5 -or [System.Text.Encoding]::ASCII.GetString($bytes, 0, 5) -ne '%PDF-')) {
            throw ('У файла нет заголовка PDF %PDF-: ' + $Path)
        }
        return [pscustomobject]@{ Path = $Path; Stream = $stream; Bytes = $bytes; Hash = (Get-ActSha256 -Bytes $bytes) }
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Read-ActPdfBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $state = Open-ActReadState -Path $Path -RequirePdf
    try { return ,([byte[]]$state.Bytes) }
    finally { $state.Stream.Dispose() }
}

function Assert-ActCopyDestination {
    param([string]$Path, [string]$ExpectedHash)
    Assert-ActSafeExistingAncestors $Path
    if ([System.IO.Directory]::Exists($Path)) { throw ('На месте файла результата находится папка: ' + $Path) }
    if ([System.IO.File]::Exists($Path)) {
        if ((Get-ActSha256 -Path $Path) -ne $ExpectedHash) {
            throw ('Существующая копия отличается от исходника. Перезапись запрещена: ' + $Path)
        }
        return $true
    }
    return $false
}

function Write-NewActFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes
    )
    $full = Get-ActFullPath $Path
    $parent = [System.IO.Path]::GetDirectoryName($full)
    New-ActSafeDirectory $parent
    if ([System.IO.File]::Exists($full) -or [System.IO.Directory]::Exists($full)) { throw ('Файл результата уже существует. Перезапись запрещена: ' + $full) }
    $temporary = [System.IO.Path]::Combine($parent, '.actsign-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($temporary, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        Assert-ActSafeExistingAncestors $full
        [System.IO.File]::Move($temporary, $full)
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([System.IO.File]::Exists($temporary)) { [System.IO.File]::Delete($temporary) }
    }
}

function Copy-ActStateNoOverwrite {
    param($State, [string]$DestinationPath)
    if (Assert-ActCopyDestination -Path $DestinationPath -ExpectedHash $State.Hash) { return 'identical' }
    Write-NewActFile -Path $DestinationPath -Bytes $State.Bytes
    if ((Get-ActSha256 -Path $DestinationPath) -ne $State.Hash) { throw ('Не совпадает хеш созданной копии: ' + $DestinationPath) }
    return 'copied'
}

function Copy-ActFileNoOverwrite {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SourcePath, [Parameter(Mandatory = $true)][string]$DestinationPath)
    $state = Open-ActReadState -Path $SourcePath
    try { return (Copy-ActStateNoOverwrite -State $state -DestinationPath $DestinationPath) }
    finally { $state.Stream.Dispose() }
}

function Get-ActCompanions {
    param($Item)
    $sourceName = [System.IO.Path]::GetFileName($Item.SourcePath)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Item.SourcePath)
    $directory = New-Object System.IO.DirectoryInfo([System.IO.Path]::GetDirectoryName($Item.SourcePath))
    foreach ($file in @($directory.GetFiles() | Sort-Object -Property Name)) {
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        if ($file.Name -match '(?i)\.my\.sig$') { continue }
        if ($file.Name -match '(?i)^signature.*\.sig$' -or $file.Name -ieq ($sourceName + '.sig') -or $file.Name -ieq ($baseName + '.sig') -or $file.Name -match '(?i)^Печатная_форма.*\.pdf$') {
            $file.FullName
        }
    }
}

function ConvertTo-ActCsvCell {
    param($Value)
    $text = [string]$Value
    $formula = $text -match '^\s*[=+@-]' -or $text -match '^[\t\r\n]'
    $text = [regex]::Replace($text, '[\x00-\x1F\x7F]', ' ')
    if ($formula) { $text = "'" + $text }
    return '"' + $text.Replace('"', '""') + '"'
}

function Write-ActCsvRow {
    param($Writer, $Row)
    $values = @($Row.Source, $Row.Destination, $Row.Hash, $Row.Thumb, $Row.Status, $Row.Message, $Row.Time)
    $cells = @($values | ForEach-Object { ConvertTo-ActCsvCell $_ })
    $Writer.WriteLine([string]::Join(',', [string[]]$cells))
    $Writer.Flush()
}

function Send-ActProgress {
    param([scriptblock]$OnProgress, [int]$Index, [int]$Total, $Item, [string]$Status, [string]$Message)
    if ($null -eq $OnProgress) { return }
    try { & $OnProgress ([pscustomobject]@{ Index = $Index; Total = $Total; Item = $Item; Status = $Status; Message = $Message }) | Out-Null }
    catch { Write-Verbose ('Не удалось обновить индикатор: ' + $_.Exception.Message) }
}

function New-ActResultRow {
    param($Item, [string]$Hash, [string]$Thumbprint, [string]$Status, [string]$Message)
    return [pscustomobject]@{
        Source = $Item.SourcePath
        Destination = $Item.SignaturePath
        Hash = $Hash
        Thumb = $Thumbprint
        Status = $Status
        Message = $Message
        Time = [System.DateTimeOffset]::Now.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    }
}

function Invoke-ActBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Thumbprint,
        [Parameter(Mandatory = $true)][scriptblock]$SignBlock,
        [Parameter(Mandatory = $true)][scriptblock]$VerifyBlock,
        [Parameter(Mandatory = $true)][string]$LogRoot,
        [scriptblock]$OnProgress,
        [scriptblock]$ExistingSignatureInspector,
        [switch]$CopyOriginals
    )
    $ErrorActionPreference = 'Stop'
    $items = @($Plan.Items)
    $generic = $null -ne $Plan.PSObject.Properties['AllFiles'] -and [bool]$Plan.AllFiles
    $bindingContext = $null
    if ($generic) {
        $explicitSources = @()
        if ($null -ne $Plan.PSObject.Properties['SourceFiles']) { $explicitSources = @($Plan.SourceFiles) }
        $sourceDocuments = @{}
        $sourcePrefix = (Get-ActFullPath $Plan.Root).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        foreach ($sourcePath in $explicitSources) {
            $fullSource = Get-ActFullPath $sourcePath
            if (-not $fullSource.StartsWith($sourcePrefix, $script:ActPathComparison)) { throw 'Выбранный исходник находится вне корня пакета.' }
            $relative = $fullSource.Substring($sourcePrefix.Length)
            $sourceDocuments[[IO.Path]::Combine($Plan.OutputRoot, $relative)] = $fullSource
        }
        # Explicit inputs win when an ancestor output root makes an inferred
        # nested copy path coincide with another actual selected input path.
        foreach ($sourcePath in $explicitSources) {
            $fullSource = Get-ActFullPath $sourcePath
            $sourceDocuments[$fullSource] = $fullSource
        }
        $bindingContext = @{ Cache = @{}; Directories = @{}; Calls = 0; WorkBytes = [long]0; SourceFiles = $explicitSources; SourceDocuments = $sourceDocuments }
    }
    $conflictingTargets=@{}
    foreach($group in @($items | Group-Object -Property SignaturePath | Where-Object {$_.Count -gt 1})) { $conflictingTargets[[string]$group.Name]=$true }
    $copy = [bool]$Plan.SeparateOutput
    if ($PSBoundParameters.ContainsKey('CopyOriginals')) { $copy = [bool]$CopyOriginals }
    $thumb = [regex]::Replace($Thumbprint, '\s', '').ToUpperInvariant()
    if ($thumb -cnotmatch '^[0-9A-F]{40}$') { throw 'Некорректный отпечаток выбранного сертификата.' }
    $logDirectory = Get-ActFullPath $LogRoot
    New-ActSafeDirectory $logDirectory
    $logPath = [System.IO.Path]::Combine($logDirectory, 'act-sign-' + [datetime]::Now.ToString('yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.csv')
    $logStream = $null
    $writer = $null
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $stopped = $false
    $stopReason = ''
    try {
        $logStream = [System.IO.File]::Open($logPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $writer = New-Object System.IO.StreamWriter($logStream, (New-Object System.Text.UTF8Encoding($true)))
        $writer.NewLine = "`r`n"
        $writer.WriteLine('"Source","Destination","Hash","Thumb","Status","Message","Time"')
        $writer.Flush()
        for ($index = 0; $index -lt $items.Count; $index++) {
            $item = $items[$index]
            if ($stopped) {
                $reason = if ($stopReason -eq 'cancelled') { 'пользователь отменил криптографическую операцию' } else { 'криптографический сеанс остановлен после ошибки' }
                $row = New-ActResultRow $item '' $thumb 'not_processed' ('Не обработан: ' + $reason + '.')
                $rows.Add($row)
                Write-ActCsvRow $writer $row
                Send-ActProgress $OnProgress ($index + 1) $items.Count $item $row.Status $row.Message
                continue
            }
            if ([System.IO.File]::Exists($item.SignaturePath) -and $null -eq $ExistingSignatureInspector) {
                $row = New-ActResultRow $item '' $thumb 'exists_unverified' 'Подпись с таким именем уже существует. Пропущена без проверки.'
                $rows.Add($row)
                Write-ActCsvRow $writer $row
                Send-ActProgress $OnProgress ($index + 1) $items.Count $item $row.Status $row.Message
                continue
            }
            $states = New-Object 'System.Collections.Generic.List[object]'
            $copies = New-Object 'System.Collections.Generic.List[object]'
            $sourceState = $null
            $hash = ''
            $stage = 'Подготовка'
            try {
                if($conflictingTargets.ContainsKey([string]$item.SignaturePath)) { throw 'Несколько выбранных файлов имеют одинаковое имя подписи. Выберите формат с полным именем файла или разные папки.' }
                $sourceState = Open-ActReadState -Path $item.SourcePath -RequirePdf:(-not $generic)
                $states.Add($sourceState)
                $hash = $sourceState.Hash
                $stage = 'Проверка соседних подписей'
                Send-ActProgress $OnProgress ($index + 1) $items.Count $item 'checking_existing' 'Проверяем существующие подписи рядом с файлом.'
                $neighborCheck = Get-ActNeighborSignatureCheck $item $sourceState $thumb $ExistingSignatureInspector $OnProgress ($index + 1) $items.Count $bindingContext
                if (-not [string]::IsNullOrEmpty($neighborCheck.DuplicatePath)) {
                    Assert-ActNeighborSignaturesUnchanged $item $neighborCheck -DuplicateOnly
                    if ((Get-ActSha256 -Path $item.SourcePath) -ne $hash) { throw 'Исходный файл изменился во время проверки существующих подписей.' }
                    $row = New-ActResultRow $item $hash $thumb 'already_signed' ('Файл уже подписан выбранным сертификатом. Проверенная соседняя подпись: ' + $neighborCheck.DuplicatePath + '. Новая подпись и копии не создавались.')
                }
                elseif ([System.IO.File]::Exists($item.SignaturePath)) {
                    $row = New-ActResultRow $item $hash $thumb 'exists_unverified' 'Имя выходной подписи занято. Подпись выбранным сертификатом над этим файлом не подтверждена. Файл сохранён без перезаписи.'
                }
                else {
                    $stage = 'Подготовка'
                    $signatureDirectory = [System.IO.Path]::GetDirectoryName($item.SignaturePath)
                    Test-ActWritableDirectory $signatureDirectory
                    Assert-ActSafeExistingAncestors $item.SignaturePath
                    if ([System.IO.File]::Exists($item.SignaturePath) -or [System.IO.Directory]::Exists($item.SignaturePath)) { throw ('Путь подписи уже занят: ' + $item.SignaturePath) }
                    if ($copy) {
                        [void](Assert-ActCopyDestination -Path $item.DocumentOutputPath -ExpectedHash $sourceState.Hash)
                        $copies.Add([pscustomobject]@{ State = $sourceState; DestinationPath = $item.DocumentOutputPath })
                        $companions = @()
                        if ($generic) { $companions = @($neighborCheck.MatchingPaths) }
                        else { $companions = @(Get-ActCompanions $item) }
                        foreach ($companion in $companions) {
                            $state = Open-ActReadState -Path $companion
                            $states.Add($state)
                            $destination = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($item.DocumentOutputPath), [System.IO.Path]::GetFileName($companion))
                            [void](Assert-ActCopyDestination -Path $destination -ExpectedHash $state.Hash)
                            $copies.Add([pscustomobject]@{ State = $state; DestinationPath = $destination })
                        }
                    }
                    Send-ActProgress $OnProgress ($index + 1) $items.Count $item 'signing' 'Подписание исходного файла.'
                    # Console progress is synchronous and can pause. Recheck after
                    # it returns, immediately before any private-key operation.
                    $stage = 'Проверка соседних подписей'
                    Assert-ActNeighborSignaturesUnchanged $item $neighborCheck
                    if ((Get-ActSha256 -Path $item.SourcePath) -ne $hash) { throw 'Исходный файл изменился до начала подписания.' }
                    $stage = 'Подписание'
                    [byte[]]$signatureBytes = & $SignBlock ([byte[]]$sourceState.Bytes)
                    if ($null -eq $signatureBytes -or $signatureBytes.Length -eq 0) { throw 'Средство подписи вернуло пустой результат.' }
                    if ($signatureBytes.Length -gt $script:ActMaxBytes) { throw 'Размер подписи превышает 64 МиБ.' }
                    $stage = 'Проверка подписи'
                    & $VerifyBlock ([byte[]]$sourceState.Bytes) $signatureBytes $thumb | Out-Null
                    $stage = 'Повторная проверка исходника'
                    if ((Get-ActSha256 -Path $item.SourcePath) -ne $hash) { throw 'Исходный файл изменился во время подписания. Подпись не сохранена.' }
                    $stage = 'Проверка соседних подписей'
                    Assert-ActNeighborSignaturesUnchanged $item $neighborCheck
                    $stage = 'Сохранение комплекта'
                    foreach ($copyItem in $copies) { [void](Copy-ActStateNoOverwrite -State $copyItem.State -DestinationPath $copyItem.DestinationPath) }
                    if ((Get-ActSha256 -Path $item.SourcePath) -ne $hash) { throw 'Исходный файл изменился во время копирования. Подпись не сохранена.' }
                    # Companion signatures copied by this batch are expected additions;
                    # every other late addition/change still blocks publication.
                    foreach ($copyItem in $copies) {
                        if ((Test-ActSignatureExtension $copyItem.DestinationPath) -and -not (Test-ActSamePath $copyItem.DestinationPath $item.DocumentOutputPath) -and @($neighborCheck.Paths | Where-Object { Test-ActSamePath $_ $copyItem.DestinationPath }).Count -eq 0) {
                            $neighborCheck.Paths = @($neighborCheck.Paths) + @($copyItem.DestinationPath)
                            $neighborCheck.Records.Add([pscustomobject]@{ Path = $copyItem.DestinationPath; Hash = $copyItem.State.Hash })
                        }
                    }
                    $stage = 'Проверка соседних подписей'
                    Assert-ActNeighborSignaturesUnchanged $item $neighborCheck
                    $stage = 'Сохранение подписи'
                    Write-NewActFile -Path $item.SignaturePath -Bytes $signatureBytes
                    $message = 'Новая подпись создана и проверена; исходный файл не изменён.'
                    if ($neighborCheck.ForeignCount -gt 0) { $message += (' Соседние подписи других сертификатов: {0}. Их математическая проверка успешна; доверие, сроки цепочки и отзыв не проверялись.' -f $neighborCheck.ForeignCount) }
                    $row = New-ActResultRow $item $hash $thumb 'signed_verified' $message
                }
            }
            catch {
                $kind = ''
                $failure = $_.Exception
                while ($null -ne $failure) {
                    if ($failure.Data['ActSignerFailure'] -in @('session', 'cancelled')) { $kind = [string]$failure.Data['ActSignerFailure']; break }
                    if ($failure -is [OperationCanceledException]) { $kind = 'cancelled'; break }
                    $failure = $failure.InnerException
                }
                if ($kind -eq '' -and $stage -in @('Подписание', 'Проверка подписи')) { $kind = 'session' }
                $stopped = $kind -in @('session', 'cancelled')
                if ($stopped) { $stopReason = $kind }
                $status = if ($kind -eq 'cancelled') { 'cancelled' } else { 'error' }
                $row = New-ActResultRow $item $hash $thumb $status ($stage + ': ' + $_.Exception.Message)
            }
            finally {
                foreach ($state in $states) { if ($null -ne $state.Stream) { $state.Stream.Dispose() } }
            }
            $rows.Add($row)
            Write-ActCsvRow $writer $row
            Send-ActProgress $OnProgress ($index + 1) $items.Count $item $row.Status $row.Message
        }
    }
    finally {
        if ($null -ne $writer) { $writer.Dispose() }
        elseif ($null -ne $logStream) { $logStream.Dispose() }
    }
    $allRows = @($rows.ToArray())
    return [pscustomobject]@{
        Rows = $allRows
        LogPath = $logPath
        Stopped = $stopped
        StopReason = $stopReason
        CancelledCount = @($allRows | Where-Object { $_.Status -eq 'cancelled' }).Count
        CompletedCount = @($allRows | Where-Object { $_.Status -eq 'signed_verified' }).Count
        SkippedCount = @($allRows | Where-Object { $_.Status -in @('exists_unverified', 'already_signed') }).Count
        AlreadySignedCount = @($allRows | Where-Object { $_.Status -eq 'already_signed' }).Count
        ErrorCount = @($allRows | Where-Object { $_.Status -eq 'error' }).Count
        NotProcessedCount = @($allRows | Where-Object { $_.Status -eq 'not_processed' }).Count
    }
}

Export-ModuleMember -Function Get-ActPlan, Get-ActSha256, Read-ActPdfBytes, Write-NewActFile, Copy-ActFileNoOverwrite, Invoke-ActBatch
