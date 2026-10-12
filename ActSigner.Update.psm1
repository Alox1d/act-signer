#requires -Version 5.1
# The launcher imports its bundled copy before trusting downloaded application code.
Set-StrictMode -Version 2.0
$script:ActUpdateRepository = 'Alox1d/act-signer'
$script:ActManifestLimit = 262144
$script:ActArchiveLimit = 8388608
$script:ActFileLimit = 2097152
$script:ActPayloadLimit = 16777216
$script:ActRequiredFiles = @('Sign-Acts.ps1', 'ActSigner.Core.psm1', 'ActSigner.CryptoPro.psm1',
    'ActSigner.Settings.psm1', 'ActSigner.UI.psm1', 'ActSigner.Console.psm1',
    'ActSigner.Update.psm1', 'ActSigner.CryptoPro.js', 'Start-ActSigner.ps1',
    'Update-ActSigner.ps1', 'ActSigner.Version.json')

function Get-ActUpdateStateRoot {
    $localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($localData)) { throw 'Cannot determine the current user update directory.' }
    return [IO.Path]::Combine($localData, 'ActSigner', 'updates')
}

function Get-ActUpdateProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object -or $Object -is [array] -or $Object -is [string]) { throw ('Invalid object for ' + $Name) }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { throw ('Missing field: ' + $Name) }
    return $property.Value
}

function ConvertTo-ActUpdateVersion {
    param($Value)
    if ($Value -isnot [string] -or $Value -cnotmatch '^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})$') { throw 'Invalid stable version.' }
    foreach ($part in $Value.Split('.')) {
        $number = 0
        if (-not [int]::TryParse($part, [ref]$number)) { throw 'Version component exceeds Int32.' }
    }
    return [version]$Value
}

function Assert-ActUpdateInteger {
    param($Value, [long]$Maximum, [long]$Minimum = 0)
    if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt $Minimum -or $Value -gt $Maximum) { throw 'Invalid bounded integer.' }
}

function Assert-ActUpdateAncestors {
    param([string]$Path)
    $current = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $attributes = $null
        try { $attributes = [IO.File]::GetAttributes($current) }
        catch [IO.FileNotFoundException] { }
        catch [IO.DirectoryNotFoundException] { }
        if ($null -ne $attributes -and ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Update paths must not contain links or reparse points.' }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function New-ActUpdateDirectory {
    param([string]$Path)
    Assert-ActUpdateAncestors $Path
    [void][IO.Directory]::CreateDirectory($Path)
    Assert-ActUpdateAncestors $Path
}

function Get-ActUpdateHash {
    param([string]$Path)
    Assert-ActUpdateAncestors $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Read-ActUpdateJson {
    param([string]$Path, [long]$MaxBytes)
    Assert-ActUpdateAncestors $Path
    $info = New-Object IO.FileInfo($Path)
    if (-not $info.Exists -or $info.Length -gt $MaxBytes -or $info.Length -le 0) { throw 'Missing or oversized update metadata.' }
    $json = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    if (-not $json.TrimStart().StartsWith('{')) { throw 'Update metadata must be a JSON object.' }
    $object = ConvertFrom-Json -InputObject $json -ErrorAction Stop
    if ($null -eq $object -or $object -is [array]) { throw 'Update metadata must be a JSON object.' }
    return $object
}

function Get-ActApplicationVersion {
    param([string]$ApplicationRoot)
    $info = Read-ActUpdateJson (Join-Path $ApplicationRoot 'ActSigner.Version.json') 4096
    $schema = Get-ActUpdateProperty $info 'SchemaVersion'
    $protocol = Get-ActUpdateProperty $info 'LauncherProtocol'
    Assert-ActUpdateInteger $schema 2147483647
    Assert-ActUpdateInteger $protocol 2147483647
    if ($schema -ne 1 -or $protocol -ne 1) { throw 'UNSUPPORTED: application protocol or version schema.' }
    $text = Get-ActUpdateProperty $info 'Version'
    $number = ConvertTo-ActUpdateVersion $text
    return [pscustomobject]@{ Text = $text; Number = $number }
}

function Assert-ActUpdateRelativePath {
    param($Path)
    if ($Path -isnot [string] -or $Path.Length -gt 200 -or $Path -cnotmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$') { throw 'Invalid update payload path.' }
    foreach ($segment in $Path.Split('/')) {
        if ($segment -eq '.' -or $segment -eq '..' -or $segment.EndsWith('.') -or $segment -imatch '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])($|\.)') { throw 'Unsafe Windows payload path.' }
    }
    if ($Path -ieq 'payload-manifest.json') { throw 'The payload cannot overwrite its verification manifest.' }
}

function Assert-ActUpdateManifest {
    param($Manifest)
    $schema = Get-ActUpdateProperty $Manifest 'SchemaVersion'
    $protocol = Get-ActUpdateProperty $Manifest 'LauncherProtocol'
    Assert-ActUpdateInteger $schema 2147483647
    Assert-ActUpdateInteger $protocol 2147483647
    if ($schema -ne 1 -or $protocol -ne 1) { throw 'UNSUPPORTED: update protocol or manifest schema.' }
    $text = Get-ActUpdateProperty $Manifest 'Version'
    $number = ConvertTo-ActUpdateVersion $text
    if ((Get-ActUpdateProperty $Manifest 'Repository') -cne $script:ActUpdateRepository) { throw 'Wrong update repository.' }
    $commit = Get-ActUpdateProperty $Manifest 'SourceCommit'
    if ($commit -isnot [string] -or $commit -cnotmatch '^[0-9a-fA-F]{40}$') { throw 'Invalid update source commit.' }
    if ((Get-ActUpdateProperty $Manifest 'AssetName') -cne ('ActSigner-' + $text + '.zip')) { throw 'Update archive name does not match version.' }
    Assert-ActUpdateInteger (Get-ActUpdateProperty $Manifest 'Size') $script:ActArchiveLimit 1
    $digest = Get-ActUpdateProperty $Manifest 'Sha256'
    if ($digest -isnot [string] -or $digest -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid archive digest.' }
    $files = @(Get-ActUpdateProperty $Manifest 'Files')
    if ($files.Count -lt $script:ActRequiredFiles.Count -or $files.Count -gt 100) { throw 'Invalid payload file count.' }
    $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $total = [long]0
    foreach ($file in $files) {
        $path = Get-ActUpdateProperty $file 'Path'
        Assert-ActUpdateRelativePath $path
        if (-not $seen.Add($path)) { throw 'Duplicate update manifest path.' }
        $size = Get-ActUpdateProperty $file 'Size'
        Assert-ActUpdateInteger $size $script:ActFileLimit
        $total += $size
        if ($total -gt $script:ActPayloadLimit) { throw 'Payload is too large.' }
        $hash = Get-ActUpdateProperty $file 'Sha256'
        if ($hash -isnot [string] -or $hash -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid payload file digest.' }
    }
    foreach ($required in $script:ActRequiredFiles) {
        if (-not $seen.Contains($required) -or @($files | Where-Object { $_.Path -ceq $required }).Count -ne 1) { throw ('Missing runtime file: ' + $required) }
    }
    return [pscustomobject]@{ Text=$text; Number=$number; Files=$files; Directory=('v' + $text + '-' + $digest.Substring(0, 16)) }
}

function Assert-ActUpdatePayload {
    param([string]$Root, $Manifest)
    $validated = Assert-ActUpdateManifest $Manifest
    Assert-ActUpdateAncestors $Root
    $expected = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $validated.Files) {
        [void]$expected.Add($file.Path)
        $path = [IO.Path]::Combine($Root, $file.Path.Replace('/', [IO.Path]::DirectorySeparatorChar))
        Assert-ActUpdateAncestors $path
        $info = New-Object IO.FileInfo($path)
        if (-not $info.Exists -or $info.Length -ne $file.Size -or (Get-ActUpdateHash $path) -cne $file.Sha256) { throw ('Payload integrity check failed: ' + $file.Path) }
        if ($file.Path -imatch '\.(ps1|psm1)$') {
            $tokens = $null; $parseErrors = $null
            $null = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
            if (@($parseErrors).Count -ne 0) { throw ('Payload PowerShell parse failed: ' + $file.Path) }
        }
    }
    # Walk one directory at a time so links are inspected before recursion.
    $pending = New-Object 'Collections.Generic.Stack[string]'
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked payload item.' }
            if ($item.PSIsContainer) { $pending.Push($item.FullName); continue }
            $relative = $item.FullName.Substring($Root.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace([IO.Path]::DirectorySeparatorChar, '/')
            if ($relative -cne 'payload-manifest.json' -and -not $expected.Contains($relative)) { throw 'Unexpected cached payload file.' }
        }
    }
    $app = Get-ActApplicationVersion $Root
    if ($app.Text -cne $validated.Text) { throw 'Payload version JSON does not match manifest.' }
    return $validated
}

function Read-ActUpdateState {
    param([string]$StateRoot)
    $state = Read-ActUpdateJson (Join-Path $StateRoot 'active.json') 65536
    $schema = Get-ActUpdateProperty $state 'SchemaVersion'
    Assert-ActUpdateInteger $schema 2147483647
    if ($schema -ne 1) { throw 'UNSUPPORTED: active state schema.' }
    $null = Get-ActUpdateProperty $state 'Active'
    $null = Get-ActUpdateProperty $state 'Previous'
    return $state
}

function Get-ActVerifiedCache {
    param([string]$StateRoot, $Pointer)
    if ($null -eq $Pointer) { return $null }
    $version = Get-ActUpdateProperty $Pointer 'Version'
    $null = ConvertTo-ActUpdateVersion $version
    $directory = Get-ActUpdateProperty $Pointer 'Directory'
    $manifestHash = Get-ActUpdateProperty $Pointer 'ManifestSha256'
    if ($directory -isnot [string] -or $directory -cnotmatch ('^v' + [regex]::Escape($version) + '-[0-9a-f]{16}$')) { throw 'Invalid cached version directory.' }
    if ($manifestHash -isnot [string] -or $manifestHash -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid cached manifest digest.' }
    $root = [IO.Path]::Combine($StateRoot, 'versions', $directory)
    $path = Join-Path $root 'payload-manifest.json'
    $manifest = Read-ActUpdateJson $path $script:ActManifestLimit
    if ((Get-ActUpdateHash $path) -cne $manifestHash) { throw 'Cached manifest was modified.' }
    $validated = Assert-ActUpdatePayload $root $manifest
    if ($validated.Text -cne $version -or $validated.Directory -cne $directory) { throw 'Cached pointer does not match payload.' }
    return [pscustomobject]@{ ApplicationRoot=$root; Version=$version; Number=$validated.Number; Pointer=$Pointer }
}

function Get-ActLaunchSelection {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BundledRoot, [string]$StateRoot, [switch]$Previous)
    $BundledRoot = [IO.Path]::GetFullPath($BundledRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $version = 'unknown'; $bundledNumber = $null
    try { $app = Get-ActApplicationVersion $BundledRoot; $version=$app.Text; $bundledNumber=$app.Number } catch { }
    $notice = ''; $selected = $null
    try {
        if ([string]::IsNullOrWhiteSpace($StateRoot)) { $StateRoot = Get-ActUpdateStateRoot }
        $StateRoot = [IO.Path]::GetFullPath($StateRoot)
        $state = Read-ActUpdateState $StateRoot
        if ($Previous) {
            try { $selected=Get-ActVerifiedCache $StateRoot $state.Previous } catch { $notice='Предыдущая версия недоступна. Запускаем программу из исходного комплекта.' }
        }
        else {
            try { $selected=Get-ActVerifiedCache $StateRoot $state.Active } catch { $notice='Обновление не прошло проверку.' }
            if ($null -eq $selected) {
                try { $selected=Get-ActVerifiedCache $StateRoot $state.Previous } catch { }
                if ($null -ne $selected) { $notice='Обновление не прошло проверку. Запускаем предыдущую проверенную версию.' }
            }
            if ($null -ne $selected -and $null -ne $bundledNumber -and $selected.Number -lt $bundledNumber) { $selected=$null; $notice='Запускаем более новую программу из исходного комплекта.' }
        }
    }
    catch { if ([IO.File]::Exists((Join-Path ([string]$StateRoot) 'active.json'))) { $notice='Состояние обновлений недоступно. Запускаем программу из исходного комплекта.' } }
    if ($null -ne $selected) { return [pscustomobject]@{ApplicationRoot=$selected.ApplicationRoot;Version=$selected.Version;UsingCached=$true;Rollback=[bool]$Previous;Notice=$notice} }
    return [pscustomobject]@{ApplicationRoot=$BundledRoot;Version=$version;UsingCached=$false;Rollback=[bool]$Previous;Notice=$notice}
}

function Assert-ActUpdateHttpUri {
    param([string]$Url, [switch]$Redirect)
    $uri = $null
    if (-not [uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -cne 'https' -or -not $uri.IsDefaultPort -or $uri.UserInfo.Length -ne 0 -or $uri.Fragment.Length -ne 0) { throw 'Invalid HTTPS update endpoint.' }
    if ($Redirect) {
        if ($uri.DnsSafeHost -notin @('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com','github-releases.githubusercontent.com')) { throw 'Untrusted update redirect host.' }
    }
    elseif ($Url -cne 'https://api.github.com/repos/Alox1d/act-signer/releases/latest' -and $Url -cnotmatch '^https://github\.com/Alox1d/act-signer/releases/download/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)/(ActSigner-update\.json|ActSigner-[0-9]+\.[0-9]+\.[0-9]+\.zip)$') { throw 'Unexpected update endpoint.' }
    return $uri
}

function Wait-ActUpdateHttpTask {
    param([Threading.Tasks.Task]$Task, [Diagnostics.Stopwatch]$Clock, [int]$TimeoutMilliseconds = 60000)
    # Some .NET Framework streams do not promptly honor a cancelled token.
    # Bound the wait itself; the caller then cancels and disposes its connection.
    $remaining = [long]$TimeoutMilliseconds - $Clock.ElapsedMilliseconds
    if ($remaining -le 0) { throw (New-Object TimeoutException('Update HTTP deadline exceeded.')) }
    try {
        if (-not $Task.Wait([int]$remaining)) { throw (New-Object TimeoutException('Update HTTP deadline exceeded.')) }
    }
    catch [AggregateException] {
        # GetAwaiter exposes the original HTTP/cancellation exception.
        return $Task.GetAwaiter().GetResult()
    }
    return $Task.GetAwaiter().GetResult()
}

function Receive-ActUpdateHttpFile {
    param([string]$Url, [string]$Destination, [long]$MaxBytes)
    $uri = Assert-ActUpdateHttpUri $Url
    Assert-ActUpdateAncestors $Destination
    Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
    # TLS selection is isolated to the background worker process on Windows PowerShell.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $handler.UseDefaultCredentials = $false
    $handler.Credentials = $null
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $null = $client.DefaultRequestHeaders.TryAddWithoutValidation('User-Agent', 'ActSigner-Updater/1')
    $null = $client.DefaultRequestHeaders.TryAddWithoutValidation('Accept', 'application/vnd.github+json')
    $cancellation = New-Object Threading.CancellationTokenSource
    $cancellation.CancelAfter(60000)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $response = $null; $input = $null; $output = $null
    try {
        for ($redirects=0; $redirects -le 4; $redirects++) {
            $task = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancellation.Token)
            $response = Wait-ActUpdateHttpTask $task $clock
            if ([int]$response.StatusCode -in @(301,302,303,307,308)) {
                if ($redirects -eq 4 -or $null -eq $response.Headers.Location) { throw 'Too many update redirects.' }
                $next = New-Object uri($uri, $response.Headers.Location)
                $uri = Assert-ActUpdateHttpUri $next.AbsoluteUri -Redirect
                $response.Dispose(); $response=$null
                continue
            }
            $null = $response.EnsureSuccessStatusCode()
            $length = $response.Content.Headers.ContentLength
            if ($null -ne $length -and $length -gt $MaxBytes) { throw 'Update HTTP payload exceeds its limit.' }
            $task = $response.Content.ReadAsStreamAsync()
            $input = Wait-ActUpdateHttpTask $task $clock
            $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $buffer = New-Object byte[] 65536
            $total = [long]0
            while ($true) {
                $task = $input.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token)
                $read = Wait-ActUpdateHttpTask $task $clock
                if ($read -eq 0) { break }
                $total += $read
                if ($total -gt $MaxBytes) { throw 'Update HTTP payload exceeds its limit.' }
                $output.Write($buffer, 0, $read)
            }
            $output.Flush($true)
            return
        }
    }
    finally {
        $cancellation.Cancel()
        $client.CancelPendingRequests()
        $client.Dispose()
        if ($null -ne $output) { $output.Dispose() }
        if ($null -ne $input) { $input.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $cancellation.Dispose(); $handler.Dispose()
    }
}

function Get-ActUpdateRelease {
    param([string]$TemporaryPath)
    Receive-ActUpdateHttpFile 'https://api.github.com/repos/Alox1d/act-signer/releases/latest' $TemporaryPath $script:ActManifestLimit
    return Read-ActUpdateJson $TemporaryPath $script:ActManifestLimit
}

function Expand-ActUpdateArchive {
    param([string]$ArchivePath, [string]$PayloadRoot, $Manifest)
    $validated = Assert-ActUpdateManifest $Manifest
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $stream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $archive = $null
    try {
        $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        if ($archive.Entries.Count -ne $validated.Files.Count -or $archive.Entries.Count -gt 100) { throw 'ZIP entries do not match the exact manifest.' }
        $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $mapping = @{}
        foreach ($file in $validated.Files) { $mapping[$file.Path]=$file }
        # Preflight EVERY entry before creating any extracted file.
        foreach ($entry in $archive.Entries) {
            Assert-ActUpdateRelativePath $entry.FullName
            if (-not $seen.Add($entry.FullName) -or -not $mapping.ContainsKey($entry.FullName)) { throw 'Unexpected or duplicate ZIP entry.' }
            $file = $mapping[$entry.FullName]
            if ($file.Path -cne $entry.FullName -or $entry.Length -ne $file.Size) { throw 'ZIP entry metadata does not match manifest.' }
            $unixKind = ($entry.ExternalAttributes -shr 16) -band 61440
            if ($unixKind -ne 0 -and $unixKind -ne 32768) { throw 'ZIP entry is not a regular file.' }
            if (($entry.ExternalAttributes -band 1040) -ne 0) { throw 'ZIP entry has directory or reparse attributes.' }
        }
        New-ActUpdateDirectory $PayloadRoot
        foreach ($entry in $archive.Entries) {
            $file = $mapping[$entry.FullName]
            $path = [IO.Path]::Combine($PayloadRoot, $entry.FullName.Replace('/', [IO.Path]::DirectorySeparatorChar))
            New-ActUpdateDirectory ([IO.Path]::GetDirectoryName($path))
            Assert-ActUpdateAncestors $path
            $input = $entry.Open(); $output=$null
            try {
                $output = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $buffer = New-Object byte[] 65536; $total=[long]0
                while (($read=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
                    $total += $read
                    if ($total -gt $file.Size -or $total -gt $script:ActFileLimit) { throw 'Decompressed ZIP entry exceeds its declared limit.' }
                    $output.Write($buffer,0,$read)
                }
                if ($total -ne $file.Size) { throw 'Decompressed ZIP entry is truncated.' }
                $output.Flush($true)
            }
            finally { if ($null -ne $output) { $output.Dispose() }; $input.Dispose() }
        }
    }
    finally { if ($null -ne $archive) { $archive.Dispose() }; $stream.Dispose() }
}

function Write-ActUpdateState {
    param([string]$StateRoot, $State)
    $temporary = [IO.Path]::Combine($StateRoot, '.active-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $destination = Join-Path $StateRoot 'active.json'
    Assert-ActUpdateAncestors $destination
    $stream=$null; $writer=$null
    try {
        $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $writer=New-Object IO.StreamWriter($stream,(New-Object Text.UTF8Encoding($true)))
        $writer.Write((ConvertTo-Json -InputObject $State -Depth 5))
        $writer.Flush(); $stream.Flush($true); $writer.Dispose(); $writer=$null; $stream=$null
        if ([IO.File]::Exists($destination)) { [IO.File]::Replace($temporary,$destination,[NullString]::Value) }
        else { [IO.File]::Move($temporary,$destination) }
        $temporary=$null
    }
    finally {
        if ($null -ne $writer) { $writer.Dispose() } elseif ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $temporary -and [IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Invoke-ActUpdateCheck {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ApplicationRoot, [string]$StateRoot, [scriptblock]$ReleaseProvider, [scriptblock]$Downloader)
    $lock=$null; $staging=$null; $currentText='unknown'
    try {
        $application = Get-ActApplicationVersion $ApplicationRoot
        $currentText=$application.Text; $currentNumber=$application.Number
        if ([string]::IsNullOrWhiteSpace($StateRoot)) { $StateRoot=Get-ActUpdateStateRoot }
        $StateRoot=[IO.Path]::GetFullPath($StateRoot)
        New-ActUpdateDirectory $StateRoot
        $lockPath=Join-Path $StateRoot 'update.lock'
        Assert-ActUpdateAncestors $lockPath
        try { $lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
        catch [IO.IOException] { return [pscustomobject]@{Status='busy';Version=$currentText;Message='Another updater owns the transaction lock.'} }
        $previous=$null
        try {
            $state=Read-ActUpdateState $StateRoot
            foreach ($pointer in @($state.Active,$state.Previous)) {
                try {
                    $cache=Get-ActVerifiedCache $StateRoot $pointer
                    if ($null -ne $cache -and $cache.Number -ge $currentNumber) {
                        $currentNumber=$cache.Number; $currentText=$cache.Version; $previous=$cache.Pointer
                        break
                    }
                }
                catch { }
            }
        }
        catch { }
        $staging=Join-Path $StateRoot ('.staging-' + [guid]::NewGuid().ToString('N'))
        New-ActUpdateDirectory $staging
        if ($null -ne $ReleaseProvider) { $release=& $ReleaseProvider }
        else { $release=Get-ActUpdateRelease (Join-Path $staging 'release.json') }
        $draft=Get-ActUpdateProperty $release 'draft'; $prerelease=Get-ActUpdateProperty $release 'prerelease'
        if ($draft -isnot [bool] -or $prerelease -isnot [bool] -or $draft -or $prerelease) { throw 'Only published stable releases are accepted.' }
        $tag=Get-ActUpdateProperty $release 'tag_name'
        if ($tag -isnot [string] -or -not $tag.StartsWith('v')) { throw 'Invalid release tag.' }
        $candidateText=$tag.Substring(1); $candidate=ConvertTo-ActUpdateVersion $candidateText
        if ($candidate -le $currentNumber) { return [pscustomobject]@{Status='current';Version=$currentText;Message='No newer stable release.'} }
        $assetName='ActSigner-' + $candidateText + '.zip'
        $assets=@(Get-ActUpdateProperty $release 'assets')
        if ($assets.Count -gt 100) { throw 'Too many release assets.' }
        $manifestAssets=@($assets | Where-Object {(Get-ActUpdateProperty $_ 'name') -ceq 'ActSigner-update.json'})
        $zipAssets=@($assets | Where-Object {(Get-ActUpdateProperty $_ 'name') -ceq $assetName})
        if ($manifestAssets.Count -ne 1 -or $zipAssets.Count -ne 1) { throw 'Release requires one matching archive and manifest.' }
        $base='https://github.com/Alox1d/act-signer/releases/download/' + $tag + '/'
        foreach ($pair in @(@($manifestAssets[0],'ActSigner-update.json',$script:ActManifestLimit),@($zipAssets[0],$assetName,$script:ActArchiveLimit))) {
            Assert-ActUpdateInteger (Get-ActUpdateProperty $pair[0] 'size') $pair[2] 1
            if ((Get-ActUpdateProperty $pair[0] 'browser_download_url') -cne ($base+$pair[1])) { throw 'Release asset has an unexpected repository URL.' }
        }
        if ($null -eq $Downloader) { $Downloader={param($Url,$Destination,$MaxBytes) Receive-ActUpdateHttpFile $Url $Destination $MaxBytes} }
        $manifestPath=Join-Path $staging 'ActSigner-update.json'
        $null=& $Downloader ($base+'ActSigner-update.json') $manifestPath $script:ActManifestLimit
        $manifest=Read-ActUpdateJson $manifestPath $script:ActManifestLimit
        $validated=Assert-ActUpdateManifest $manifest
        if ($validated.Text -cne $candidateText -or ([IO.FileInfo]$manifestPath).Length -ne $manifestAssets[0].size -or $manifest.Size -ne $zipAssets[0].size) { throw 'Release and manifest metadata disagree.' }
        $zipPath=Join-Path $staging $assetName
        $null=& $Downloader ($base+$assetName) $zipPath $script:ActArchiveLimit
        Assert-ActUpdateAncestors $zipPath
        if (([IO.FileInfo]$zipPath).Length -ne $manifest.Size -or (Get-ActUpdateHash $zipPath) -cne $manifest.Sha256) { throw 'Archive size or checksum verification failed.' }
        $payload=Join-Path $staging 'payload'
        Expand-ActUpdateArchive $zipPath $payload $manifest
        $null=Assert-ActUpdatePayload $payload $manifest
        [IO.File]::Copy($manifestPath,(Join-Path $payload 'payload-manifest.json'),$false)
        $manifestHash=Get-ActUpdateHash (Join-Path $payload 'payload-manifest.json')
        $versions=Join-Path $StateRoot 'versions'
        New-ActUpdateDirectory $versions
        $destination=Join-Path $versions $validated.Directory
        Assert-ActUpdateAncestors $destination
        $newPointer=[pscustomobject]@{Directory=$validated.Directory;Version=$candidateText;ManifestSha256=$manifestHash}
        if ([IO.Directory]::Exists($destination) -or [IO.File]::Exists($destination)) {
            # An interrupted transaction may have published this immutable payload already.
            $null=Get-ActVerifiedCache $StateRoot $newPointer
        }
        else { [IO.Directory]::Move($payload,$destination) }
        $newState=[pscustomobject]@{SchemaVersion=1;Active=$newPointer;Previous=$previous}
        Write-ActUpdateState $StateRoot $newState
        return [pscustomobject]@{Status='updated';Version=$candidateText;Message='Verified update prepared for the next launch.'}
    }
    catch {
        $status='unavailable'
        if ($_.Exception.Message.StartsWith('UNSUPPORTED:')) { $status='unsupported' }
        # Keep status free of paths, server text, credentials and user document information.
        return [pscustomobject]@{Status=$status;Version=$currentText;Message='Update unavailable; the installed application remains usable.'}
    }
    finally {
        if ($null -ne $staging -and [IO.Directory]::Exists($staging)) {
            try { Assert-ActUpdateAncestors $staging; Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop } catch { }
        }
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

Export-ModuleMember -Function Get-ActUpdateStateRoot, Get-ActLaunchSelection, Invoke-ActUpdateCheck
