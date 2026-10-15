#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AssetDirectory,
    [Parameter(Mandatory = $true)][string]$SourceCommit,
    [scriptblock]$GhCommand
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repository = 'Alox1d/act-signer'
# Only the main push job receives GH_TOKEN = github.token and contents:write.
# No stored GH login, personal token, Git credential or updater token is used.
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_EVENT_NAME -cne 'push' -or $env:GITHUB_REF -cne 'refs/heads/main' -or $env:GITHUB_REPOSITORY -cne $repository) { throw 'Publication is permitted only in the repository main push workflow.' }
if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN)) { throw 'The workflow GitHub token is required.' }
if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$' -or $env:GITHUB_SHA -cne $SourceCommit) { throw 'Publication source must match the exact tested workflow SHA.' }
if ($null -eq $GhCommand) {
    $GhCommand = {
        param([string[]]$Arguments)
        $savedPreference = $ErrorActionPreference
        try {
            # A 404 is expected for a new release/tag. Capture it without printing token-bearing diagnostics.
            $ErrorActionPreference = 'Continue'
            $output = @(& gh @Arguments 2>&1)
            $code = $LASTEXITCODE
            [pscustomobject]@{ ExitCode = $code; Output = ($output -join "`n") }
        } finally { $ErrorActionPreference = $savedPreference }
    }
}
function Invoke-ReleaseGh {
    param([string[]]$Arguments, [switch]$AllowNotFound)
    $result = & $GhCommand -Arguments $Arguments
    if ($result.ExitCode -ne 0) {
        if ($AllowNotFound -and $result.Output -match '\(HTTP 404\)') { return $null }
        throw ('GitHub CLI operation failed: ' + $Arguments[0] + '/' + $Arguments[1] + '. Draft publication has not been requested.')
    }
    return [string]$result.Output
}
function Get-ReleaseObject {
    # Authenticated listing includes drafts; the by-tag REST endpoint is documented for published releases.
    # Slurp pages as JSON and filter in PowerShell, avoiding native Windows jq quote escaping.
    $json = Invoke-ReleaseGh -Arguments @('api', ('repos/' + $repository + '/releases?per_page=100'), '--paginate', '--slurp')
    $pages = ConvertFrom-Json -InputObject $json
    $releaseMatches = @(foreach ($page in $pages) { foreach ($item in $page) { if ($item.tag_name -ceq $tag) { $item } } })
    if ($releaseMatches.Count -eq 0) { return $null }
    if ($releaseMatches.Count -ne 1) { throw 'Multiple releases share the version tag; refusing ambiguous publication.' }
    return $releaseMatches[0]
}
function Assert-MatchingDraft {
    param($Release)
    if ($null -eq $Release -or $Release.draft -ne $true -or $Release.prerelease -ne $false -or $Release.tag_name -cne $tag -or $Release.target_commitish -cne $SourceCommit) { throw 'Refusing a published release, prerelease or draft for another source commit. Bump the version for new source.' }
    foreach ($asset in @($Release.assets)) {
        if ($asset.name -cne $manifest.AssetName -and $asset.name -cne $publicAssetName -and $asset.name -cne 'ActSigner-update.json') { throw 'Existing draft contains an unexpected asset; refusing to modify it.' }
    }
}
function Get-VerifiedPublishedRelease {
    param($Release, [string]$TagCommit)
    if ($Release.draft -isnot [bool] -or $Release.draft -or $Release.prerelease -isnot [bool] -or $Release.prerelease -or $Release.tag_name -cne $tag) { throw 'Only the matching published stable release can be reused.' }
    if ($Release.target_commitish -cnotmatch '^[0-9a-f]{40}$' -or $TagCommit -cne $Release.target_commitish) { throw 'Published version tag does not match its declared source commit.' }
    $assets = @($Release.assets)
    if ($assets.Count -ne 3) { throw 'Published release must contain exactly the three required assets.' }
    foreach ($name in @($manifest.AssetName, $publicAssetName, 'ActSigner-update.json')) {
        $matches = @($assets | Where-Object { $_.name -ceq $name })
        $limit = if ($name -ceq 'ActSigner-update.json') { 256KB } else { 8MB }
        if ($matches.Count -ne 1) { throw 'Published release has missing, duplicate or unexpected assets.' }
        $asset = $matches[0]
        if ($asset.state -cne 'uploaded' -or ($asset.size -isnot [int] -and $asset.size -isnot [long]) -or $asset.size -le 0 -or $asset.size -gt $limit) { throw 'Published release asset is incomplete or outside its bounds.' }
    }
    $readback = Join-Path ([IO.Path]::GetTempPath()) ('CSPSigner-published-readback-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($readback)
    try {
        Invoke-ReleaseGh -Arguments @('release', 'download', $tag, '--repo', $repository, '--pattern', $manifest.AssetName, '--pattern', 'ActSigner-update.json', '--pattern', $publicAssetName, '--dir', $readback) | Out-Null
        foreach ($asset in $assets) {
            if ((Get-Item -LiteralPath (Join-Path $readback $asset.name)).Length -ne $asset.size) { throw 'Published asset readback size differs from release metadata.' }
        }
        # Use the local trusted updater's bounded manifest, archive and payload checks.
        # Downloaded scripts are parsed and hashed; they are never imported or executed.
        $updater = Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ActSigner.Update.psm1') -Force -PassThru -DisableNameChecking
        $published = & $updater {
            param($Directory, $Expected, [string]$PublicAssetName)
            $candidate = Read-ActUpdateJson (Join-Path $Directory 'ActSigner-update.json') 256KB
            $actual = Assert-ActUpdateManifest $candidate
            $wanted = Assert-ActUpdateManifest $Expected
            if ($candidate.Version -cne $Expected.Version -or $candidate.SourceCommit -cnotmatch '^[0-9a-f]{40}$' -or $actual.Files.Count -ne $wanted.Files.Count) { throw 'Published release identity or payload differs; bump the version for new source.' }
            $byPath = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
            foreach ($file in $wanted.Files) { $byPath.Add($file.Path, $file) }
            foreach ($file in $actual.Files) {
                if (-not $byPath.ContainsKey($file.Path) -or $file.Size -ne $byPath[$file.Path].Size -or $file.Sha256 -cne $byPath[$file.Path].Sha256) { throw 'Published payload differs from tested source; bump the release version.' }
            }
            foreach ($name in @($candidate.AssetName, $PublicAssetName)) {
                $path = Join-Path $Directory $name
                if ((Get-Item -LiteralPath $path).Length -ne $candidate.Size -or (Get-ActUpdateHash $path) -cne $candidate.Sha256) { throw 'Published ZIP readback does not match its manifest.' }
            }
            $payload = Join-Path $Directory 'payload'
            Expand-ActUpdateArchive (Join-Path $Directory $candidate.AssetName) $payload $candidate
            $null = Assert-ActUpdatePayload $payload $candidate
            return $candidate
        } $readback $manifest $publicAssetName
        [pscustomobject]@{ Status = 'already-published'; Version = $published.Version; Tag = $tag; SourceCommit = $published.SourceCommit; ManifestSha256 = (Get-FileHash -LiteralPath (Join-Path $readback 'ActSigner-update.json') -Algorithm SHA256).Hash.ToLowerInvariant() }
    } finally { if ([IO.Directory]::Exists($readback)) { Remove-Item -LiteralPath $readback -Recurse -Force } }
}
$AssetDirectory = [IO.Path]::GetFullPath($AssetDirectory)
$manifestPath = Join-Path $AssetDirectory 'ActSigner-update.json'
$manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
if ($manifest.SchemaVersion -ne 1 -or $manifest.LauncherProtocol -ne 1 -or $manifest.Repository -cne $repository -or $manifest.SourceCommit -cne $SourceCommit -or $manifest.Version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'Invalid publication manifest.' }
foreach ($part in $manifest.Version.Split('.')) { $number = 0; if (-not [int]::TryParse($part, [ref]$number)) { throw 'Version is outside Int32 bounds.' } }
$tag = 'v' + $manifest.Version
if ($manifest.AssetName -cne ('ActSigner-' + $manifest.Version + '.zip')) { throw 'ZIP asset name does not match release version.' }
$zipPath = Join-Path $AssetDirectory $manifest.AssetName
$publicAssetName = 'CSPSigner-' + $manifest.Version + '.zip'
$publicZipPath = Join-Path $AssetDirectory $publicAssetName
if ($manifest.Size -ne (Get-Item -LiteralPath $zipPath).Length -or $manifest.Sha256 -cne (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Publication ZIP does not match its manifest.' }
if ($manifest.Size -ne (Get-Item -LiteralPath $publicZipPath).Length -or $manifest.Sha256 -cne (Get-FileHash -LiteralPath $publicZipPath -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Public CSPSigner ZIP does not match the verified update ZIP.' }
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$release = Get-ReleaseObject
# --target does not move an already existing tag; explicitly verify it first.
$tagCommit = $null
$tagJson = Invoke-ReleaseGh -Arguments @('api', ('repos/' + $repository + '/git/ref/tags/' + $tag)) -AllowNotFound
if ($null -ne $tagJson) {
    $object = ($tagJson | ConvertFrom-Json).object
    $depth = 0
    while ($object.type -ceq 'tag' -and $depth -lt 4) {
        $annotation = Invoke-ReleaseGh -Arguments @('api', ('repos/' + $repository + '/git/tags/' + $object.sha))
        $object = ($annotation | ConvertFrom-Json).object; $depth++
    }
    if ($object.type -cne 'commit') { throw 'Existing version tag does not resolve to a commit.' }
    $tagCommit = $object.sha
}
if ($null -ne $release -and $release.draft -eq $false) {
    Get-VerifiedPublishedRelease $release $tagCommit
    return
}
if ($null -ne $release) { Assert-MatchingDraft $release }
if ($null -ne $tagCommit -and $tagCommit -cne $SourceCommit) { throw 'Existing version tag points to another commit; bump the release version.' }
if ($null -eq $release) {
    Invoke-ReleaseGh -Arguments @('release', 'create', $tag, '--repo', $repository, '--target', $SourceCommit, '--title', ('CSPSigner ' + $manifest.Version), '--notes', ('CSPSigner ' + $manifest.Version + '. File signing through CryptoPro CSP. Verified native Windows PowerShell 5.1 package.'), '--draft') | Out-Null
    $release = Get-ReleaseObject
    Assert-MatchingDraft $release
}
# Recovery is limited to an unpublished same-commit draft and these three asset names.
# A failure at any point before edit leaves the release unpublished for a safe retry.
Invoke-ReleaseGh -Arguments @('release', 'upload', $tag, $zipPath, $manifestPath, $publicZipPath, '--repo', $repository, '--clobber') | Out-Null
$release = Get-ReleaseObject
Assert-MatchingDraft $release
$assets = @($release.assets)
if ($assets.Count -ne 3) { throw 'Draft does not contain exactly the three required assets.' }
foreach ($asset in $assets) {
    $expectedSize = if ($asset.name -ceq $manifest.AssetName -or $asset.name -ceq $publicAssetName) { $manifest.Size } else { (Get-Item -LiteralPath $manifestPath).Length }
    if ($asset.state -cne 'uploaded' -or $asset.size -ne $expectedSize) { throw 'Draft asset upload is incomplete or has incorrect size.' }
}
$readback = Join-Path ([IO.Path]::GetTempPath()) ('CSPSigner-release-readback-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($readback)
try {
    Invoke-ReleaseGh -Arguments @('release', 'download', $tag, '--repo', $repository, '--pattern', $manifest.AssetName, '--pattern', 'ActSigner-update.json', '--pattern', $publicAssetName, '--dir', $readback) | Out-Null
    if ((Get-FileHash -LiteralPath (Join-Path $readback $publicAssetName) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.Sha256 -or (Get-FileHash -LiteralPath (Join-Path $readback $manifest.AssetName) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.Sha256 -or (Get-FileHash -LiteralPath (Join-Path $readback 'ActSigner-update.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifestHash) { throw 'Uploaded draft asset readback does not match local verified assets.' }
    $release = Get-ReleaseObject
    Assert-MatchingDraft $release
    Invoke-ReleaseGh -Arguments @('release', 'edit', $tag, '--repo', $repository, '--draft=false', '--prerelease=false', '--latest') | Out-Null
    $release = Get-ReleaseObject
    if ($release.draft -ne $false -or $release.prerelease -ne $false) { throw 'GitHub did not confirm stable release publication.' }
    [pscustomobject]@{ Status = 'published'; Version = $manifest.Version; Tag = $tag; SourceCommit = $SourceCommit; ManifestSha256 = $manifestHash }
} finally { if ([IO.Directory]::Exists($readback)) { Remove-Item -LiteralPath $readback -Recurse -Force } }
