#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
# Intentional literal allowlist: do not replace with a directory or glob scan.
$payload = @(
    'ActSigner.Console.psm1', 'ActSigner.Core.psm1', 'ActSigner.CryptoPro.js',
    'ActSigner.CryptoPro.psm1', 'ActSigner.Settings.psm1', 'ActSigner.UI.psm1',
    'ActSigner.Update.psm1', 'ActSigner.Version.json', 'README.md', 'README.txt',
    'Sign-Acts.ps1', 'Start-ActSigner.ps1', 'Start.cmd', 'Update-ActSigner.ps1',
    'diagnostics/Check-CryptoPro.cmd', 'diagnostics/Check-CryptoPro.js',
    'diagnostics/Check-CryptoPro.ps1', 'diagnostics/README.txt'
)
function Get-ReleaseHash {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-OrdinaryReleasePath {
    param([string]$Path)
    $current = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($current)) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Release paths must not traverse links or reparse points.' }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }; $current = $parent
    }
}
if ($SourceCommit -cnotmatch '^[0-9a-fA-F]{40}$') { throw 'SourceCommit must be a full 40-character Git commit.' }
$SourceRoot = [IO.Path]::GetFullPath($SourceRoot)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
Assert-OrdinaryReleasePath $SourceRoot
Assert-OrdinaryReleasePath $OutputDirectory
$versionPath = Join-Path $SourceRoot 'ActSigner.Version.json'
Assert-OrdinaryReleasePath $versionPath
$version = [IO.File]::ReadAllText($versionPath) | ConvertFrom-Json
if (($version.SchemaVersion -isnot [int] -and $version.SchemaVersion -isnot [long]) -or $version.SchemaVersion -ne 1 -or ($version.LauncherProtocol -isnot [int] -and $version.LauncherProtocol -isnot [long]) -or $version.LauncherProtocol -ne 1) { throw 'Unsupported version schema or launcher protocol.' }
if ($version.Version -isnot [string] -or $version.Version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'Version must be canonical MAJOR.MINOR.PATCH.' }
foreach ($component in $version.Version.Split('.')) { $number = 0; if (-not [int]::TryParse($component, [ref]$number)) { throw 'Version components must fit Int32.' } }
$assetName = 'ActSigner-' + $version.Version + '.zip'
$zipPath = Join-Path $OutputDirectory $assetName
$manifestPath = Join-Path $OutputDirectory 'ActSigner-update.json'
if (Test-Path -LiteralPath $zipPath) { throw 'ZIP already exists; release assets are immutable.' }
if (Test-Path -LiteralPath $manifestPath) { throw 'Manifest already exists; release assets are immutable.' }
$files = New-Object 'System.Collections.Generic.List[object]'
$total = [long]0
foreach ($relative in $payload) {
    $path = Join-Path $SourceRoot $relative
    Assert-OrdinaryReleasePath $path
    if (-not [IO.File]::Exists($path)) { throw ('Missing required release file: ' + $relative) }
    $size = (Get-Item -LiteralPath $path).Length
    if ($size -gt 2MB) { throw 'A release file exceeds the updater 2 MiB limit.' }
    $total += $size
    $files.Add([pscustomobject][ordered]@{ Path = $relative; Size = $size; Sha256 = (Get-ReleaseHash $path) })
}
if ($total -gt 16MB -or $files.Count -gt 100) { throw 'Payload exceeds updater bounds.' }
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$staging = Join-Path $OutputDirectory ('.build-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($staging)
$zipTemporary = Join-Path $staging $assetName
$manifestTemporary = Join-Path $staging 'ActSigner-update.json'
$zipCommitted = $false
try {
    $archive = [IO.Compression.ZipFile]::Open($zipTemporary, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in $files) {
            $path = Join-Path $SourceRoot $file.Path
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $path, $file.Path, [IO.Compression.CompressionLevel]::Optimal)
        }
    } finally { $archive.Dispose() }
    # Detect changed source bytes between metadata collection and archive construction.
    $archive = [IO.Compression.ZipFile]::OpenRead($zipTemporary)
    try {
        for ($i = 0; $i -lt $files.Count; $i++) {
            $entry = $archive.Entries[$i]; $metadata = $files[$i]
            $stream = $entry.Open(); $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose(); $stream.Dispose() }
            if ($entry.FullName -cne $metadata.Path -or $entry.Length -ne $metadata.Size -or $hash -cne $metadata.Sha256) { throw 'Source changed during build; no release assets committed.' }
        }
    } finally { $archive.Dispose() }
    $zipSize = (Get-Item -LiteralPath $zipTemporary).Length
    if ($zipSize -gt 8MB) { throw 'ZIP exceeds the updater 8 MiB limit.' }
    $manifest = [ordered]@{
        SchemaVersion = 1; Version = $version.Version; LauncherProtocol = 1
        Repository = 'Alox1d/act-signer'; SourceCommit = $SourceCommit.ToLowerInvariant()
        AssetName = $assetName; Size = $zipSize; Sha256 = (Get-ReleaseHash $zipTemporary); Files = @($files.ToArray())
    }
    [IO.File]::WriteAllText($manifestTemporary, (($manifest | ConvertTo-Json -Depth 6) + "`n"), (New-Object Text.UTF8Encoding($false)))
    if ((Get-Item -LiteralPath $manifestTemporary).Length -gt 256KB) { throw 'Manifest exceeds the updater 256 KiB limit.' }
    [IO.File]::Move($zipTemporary, $zipPath); $zipCommitted = $true
    [IO.File]::Move($manifestTemporary, $manifestPath)
    [pscustomobject]@{ Version = $version.Version; ZipPath = $zipPath; ManifestPath = $manifestPath; Sha256 = $manifest.Sha256 }
} catch {
    if ($zipCommitted -and [IO.File]::Exists($zipPath)) { [IO.File]::Delete($zipPath) }
    throw
} finally { if ([IO.Directory]::Exists($staging)) { Remove-Item -LiteralPath $staging -Recurse -Force } }
