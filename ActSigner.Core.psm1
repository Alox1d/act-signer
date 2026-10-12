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

function Get-ActPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$OutputRoot
    )
    $sourceRoot = Get-ActFullPath $Root
    $destinationRoot = Get-ActFullPath $OutputRoot
    if (-not [System.IO.Directory]::Exists($sourceRoot)) { throw ('Исходная папка не найдена: ' + $sourceRoot) }
    Assert-ActSafeExistingAncestors $sourceRoot
    Assert-ActSafeExistingAncestors $destinationRoot
    $separate = -not (Test-ActSamePath $sourceRoot $destinationRoot)
    $excludeOutput = $separate -and (Test-ActPathWithin $destinationRoot $sourceRoot)
    $items = New-Object 'System.Collections.Generic.List[object]'
    $reparse = New-Object 'System.Collections.Generic.List[string]'
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($sourceRoot)
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
                $pending.Push($entry.FullName)
                continue
            }
            if (-not [regex]::IsMatch($entry.Name, $script:ActNamePattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) { continue }
            $relative = $entry.FullName.Substring($sourcePrefix.Length)
            $documentOutput = [System.IO.Path]::Combine($destinationRoot, $relative)
            $signatureName = [System.IO.Path]::GetFileNameWithoutExtension($entry.Name) + '.my.sig'
            $signaturePath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($documentOutput), $signatureName)
            $items.Add([pscustomobject]@{
                SourcePath = $entry.FullName
                RelativePath = $relative
                SourceDirectory = $entry.DirectoryName
                SignaturePath = $signaturePath
                DocumentOutputPath = $documentOutput
                ExistingSignature = [System.IO.File]::Exists($signaturePath)
            })
        }
    }
    return [pscustomobject]@{
        Root = $sourceRoot
        OutputRoot = $destinationRoot
        SeparateOutput = $separate
        Items = @($items.ToArray() | Sort-Object -Property RelativePath)
        SkippedReparsePoints = @($reparse.ToArray())
    }
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
        [switch]$CopyOriginals
    )
    $ErrorActionPreference = 'Stop'
    $items = @($Plan.Items)
    $copy = [bool]$Plan.SeparateOutput
    if ($PSBoundParameters.ContainsKey('CopyOriginals')) { $copy = [bool]$CopyOriginals }
    $thumb = [regex]::Replace($Thumbprint, '\s', '').ToUpperInvariant()
    $logDirectory = Get-ActFullPath $LogRoot
    New-ActSafeDirectory $logDirectory
    $logPath = [System.IO.Path]::Combine($logDirectory, 'act-sign-' + [datetime]::Now.ToString('yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.csv')
    $logStream = $null
    $writer = $null
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $stopped = $false
    try {
        $logStream = [System.IO.File]::Open($logPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $writer = New-Object System.IO.StreamWriter($logStream, (New-Object System.Text.UTF8Encoding($true)))
        $writer.NewLine = "`r`n"
        $writer.WriteLine('"Source","Destination","Hash","Thumb","Status","Message","Time"')
        $writer.Flush()
        for ($index = 0; $index -lt $items.Count; $index++) {
            $item = $items[$index]
            if ($stopped) {
                $row = New-ActResultRow $item '' $thumb 'not_processed' 'Не обработан: выполнение остановлено после предыдущей ошибки.'
                $rows.Add($row)
                Write-ActCsvRow $writer $row
                Send-ActProgress $OnProgress ($index + 1) $items.Count $item $row.Status $row.Message
                continue
            }
            if ([System.IO.File]::Exists($item.SignaturePath)) {
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
                $sourceState = Open-ActReadState -Path $item.SourcePath -RequirePdf
                $states.Add($sourceState)
                $hash = $sourceState.Hash
                $signatureDirectory = [System.IO.Path]::GetDirectoryName($item.SignaturePath)
                Test-ActWritableDirectory $signatureDirectory
                Assert-ActSafeExistingAncestors $item.SignaturePath
                if ([System.IO.File]::Exists($item.SignaturePath) -or [System.IO.Directory]::Exists($item.SignaturePath)) { throw ('Путь подписи уже занят: ' + $item.SignaturePath) }
                if ($copy) {
                    [void](Assert-ActCopyDestination -Path $item.DocumentOutputPath -ExpectedHash $sourceState.Hash)
                    $copies.Add([pscustomobject]@{ State = $sourceState; DestinationPath = $item.DocumentOutputPath })
                    foreach ($companion in @(Get-ActCompanions $item)) {
                        $state = Open-ActReadState -Path $companion
                        $states.Add($state)
                        $destination = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($item.DocumentOutputPath), [System.IO.Path]::GetFileName($companion))
                        [void](Assert-ActCopyDestination -Path $destination -ExpectedHash $state.Hash)
                        $copies.Add([pscustomobject]@{ State = $state; DestinationPath = $destination })
                    }
                }
                $stage = 'Подписание'
                Send-ActProgress $OnProgress ($index + 1) $items.Count $item 'signing' 'Подписание исходного акта.'
                [byte[]]$signatureBytes = & $SignBlock ([byte[]]$sourceState.Bytes)
                if ($null -eq $signatureBytes -or $signatureBytes.Length -eq 0) { throw 'Средство подписи вернуло пустой результат.' }
                if ($signatureBytes.Length -gt $script:ActMaxBytes) { throw 'Размер подписи превышает 64 МиБ.' }
                $stage = 'Проверка подписи'
                & $VerifyBlock ([byte[]]$sourceState.Bytes) $signatureBytes $thumb | Out-Null
                $stage = 'Повторная проверка исходника'
                if ((Get-ActSha256 -Path $item.SourcePath) -ne $hash) { throw 'Исходный файл изменился во время подписания. Подпись не сохранена.' }
                $stage = 'Сохранение комплекта'
                foreach ($copyItem in $copies) { [void](Copy-ActStateNoOverwrite -State $copyItem.State -DestinationPath $copyItem.DestinationPath) }
                if ((Get-ActSha256 -Path $item.SourcePath) -ne $hash) { throw 'Исходный файл изменился во время копирования. Подпись не сохранена.' }
                $stage = 'Сохранение подписи'
                Write-NewActFile -Path $item.SignaturePath -Bytes $signatureBytes
                $row = New-ActResultRow $item $hash $thumb 'signed_verified' 'Новая подпись создана и проверена; исходный акт не изменён.'
            }
            catch {
                $stopped = $true
                $row = New-ActResultRow $item $hash $thumb 'error' ($stage + ': ' + $_.Exception.Message)
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
        CompletedCount = @($allRows | Where-Object { $_.Status -eq 'signed_verified' }).Count
        SkippedCount = @($allRows | Where-Object { $_.Status -eq 'exists_unverified' }).Count
        ErrorCount = @($allRows | Where-Object { $_.Status -eq 'error' }).Count
        NotProcessedCount = @($allRows | Where-Object { $_.Status -eq 'not_processed' }).Count
    }
}

Export-ModuleMember -Function Get-ActPlan, Get-ActSha256, Read-ActPdfBytes, Write-NewActFile, Copy-ActFileNoOverwrite, Invoke-ActBatch
