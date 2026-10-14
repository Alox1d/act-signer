#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$builder = Join-Path $PSScriptRoot 'Build-Release.ps1'
$publisher = Join-Path $PSScriptRoot 'Publish-Release.ps1'
function Assert-Package { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw ('ASSERT: ' + $Message) } }
Assert-Package ([IO.File]::Exists($builder)) 'Release builder must exist before allowlist packaging can pass.'
$expected = @('ActSigner.Console.psm1','ActSigner.Core.psm1','ActSigner.CryptoPro.js','ActSigner.CryptoPro.psm1','ActSigner.Settings.psm1','ActSigner.UI.psm1','ActSigner.Update.psm1','ActSigner.Version.json','README.md','README.txt','README.en.md','REFERENCE.md','Sign-Acts.ps1','Start-ActSigner.ps1','Start.cmd','Update-ActSigner.ps1','diagnostics/Check-CryptoPro.cmd','diagnostics/Check-CryptoPro.js','diagnostics/Check-CryptoPro.ps1','diagnostics/README.txt')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ActSigner-package-' + [guid]::NewGuid().ToString('N'))
$source = Join-Path $testRoot 'source'
$commit = '0123456789abcdef0123456789abcdef01234567'
[void][IO.Directory]::CreateDirectory($source)
try {
    foreach ($path in $expected) {
        $file = Join-Path $source $path
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($file))
        [IO.File]::WriteAllText($file, ('SYNTHETIC PAYLOAD ' + $path), (New-Object Text.UTF8Encoding($false)))
    }
    [IO.File]::WriteAllText((Join-Path $source 'ActSigner.Version.json'), '{"SchemaVersion":1,"Version":"1.5.0","LauncherProtocol":1}')
    $private = @('settings.json','documents/SYNTHETIC-PRIVATE.pdf','documents/SYNTHETIC-PRIVATE.pdf.sig','keys/SYNTHETIC-PRIVATE.key','diagnostics/results.json','ActSigner.Update.Tests.ps1','tools/private.ps1','.github/workflows/private.yml','docs/private.md','ActSigner.Secret.psm1')
    foreach ($path in $private) {
        $file = Join-Path $source $path
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($file))
        [IO.File]::WriteAllText($file, 'SYNTHETIC PRIVATE SENTINEL')
    }
    # Exercise the actual -File interface, with no SourceRoot and an unrelated CWD.
    # Windows explicitly selects Windows PowerShell 5.1, never a pwsh substitute.
    $fixtureTools = Join-Path $source 'tools'
    [void][IO.Directory]::CreateDirectory($fixtureTools)
    $fixtureBuilder = Join-Path $fixtureTools 'Build-Release.ps1'
    [IO.File]::Copy($builder, $fixtureBuilder)
    $defaultOutput = Join-Path $testRoot 'default-source-release'
    $nativeHost = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    } else { Join-Path $PSHOME 'pwsh' }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $nativeHost
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $fixtureBuilder + '" -OutputDirectory "' + $defaultOutput + '" -SourceCommit ' + $commit
    $start.WorkingDirectory = $testRoot
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Default-SourceRoot native package process exceeded 30 seconds.' }
        $nativeOutput = $process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd()
        Assert-Package ($process.ExitCode -eq 0) ('Default-SourceRoot -File build must succeed from an unrelated working directory. Synthetic child output: ' + $nativeOutput)
    } finally { $process.Dispose() }
    $defaultManifest = [IO.File]::ReadAllText((Join-Path $defaultOutput 'ActSigner-update.json')) | ConvertFrom-Json
    Assert-Package ($defaultManifest.Version -ceq '1.5.0' -and $defaultManifest.SourceCommit -ceq $commit) 'Default source must resolve to the copied builder parent application, not CWD.'
    Assert-Package ((@($defaultManifest.Files.Path | Sort-Object) -join ',') -ceq (@($expected | Sort-Object) -join ',')) 'Default-SourceRoot subprocess must package exactly the runtime allowlist.'
    Assert-Package ($defaultManifest.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $defaultOutput 'ActSigner-1.5.0.zip') -Algorithm SHA256).Hash.ToLowerInvariant()) 'Default-SourceRoot subprocess archive must match its manifest.'
    Assert-Package ([IO.File]::Exists((Join-Path $defaultOutput 'CSPSigner-1.5.0.zip'))) 'Native -File build must include the CSPSigner download archive.'
    $output = Join-Path $testRoot 'release'
    $result = & $builder -SourceRoot $source -OutputDirectory $output -SourceCommit $commit
    Assert-Package ($result.Version -ceq '1.5.0') 'Builder must report the validated version.'
    $zipPath = Join-Path $output 'ActSigner-1.5.0.zip'
    $manifestPath = Join-Path $output 'ActSigner-update.json'
    Assert-Package ([IO.File]::Exists($zipPath) -and [IO.File]::Exists($manifestPath)) 'Both update assets must exist.'
    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    $publicZipPath = Join-Path $output 'CSPSigner-1.5.0.zip'
    Assert-Package ([IO.File]::Exists($publicZipPath)) 'CSPSigner download archive must exist alongside the legacy update archive.'
    Assert-Package ((Get-FileHash -LiteralPath $publicZipPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $manifest.Sha256) 'Branded and legacy archives must contain identical verified bytes.'
    Assert-Package ((@($manifest.PSObject.Properties.Name | Sort-Object) -join ',') -ceq 'AssetName,Files,LauncherProtocol,Repository,SchemaVersion,Sha256,Size,SourceCommit,Version') 'Manifest field names must match protocol 1 exactly.'
    Assert-Package ($manifest.SchemaVersion -eq 1 -and $manifest.LauncherProtocol -eq 1 -and $manifest.Version -ceq '1.5.0') 'Manifest and version protocols must agree.'
    Assert-Package ($manifest.Repository -ceq 'Alox1d/act-signer' -and $manifest.SourceCommit -ceq $commit -and $manifest.AssetName -ceq 'ActSigner-1.5.0.zip') 'Release identity must be exact.'
    Assert-Package ($manifest.Size -eq (Get-Item -LiteralPath $zipPath).Length -and $manifest.Sha256 -ceq (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()) 'ZIP digest and size must match real archive bytes.'
    Assert-Package ((@($manifest.Files.Path | Sort-Object) -join ',') -ceq (@($expected | Sort-Object) -join ',')) 'Manifest must list only explicit runtime payload.'
    $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        Assert-Package ((@($zip.Entries.FullName | Sort-Object) -join ',') -ceq (@($expected | Sort-Object) -join ',')) 'ZIP must exactly match the allowlist without wrapper or manifest.'
        foreach ($entry in $zip.Entries) {
            $item = @($manifest.Files | Where-Object { $_.Path -ceq $entry.FullName })[0]
            Assert-Package ((@($item.PSObject.Properties.Name | Sort-Object) -join ',') -ceq 'Path,Sha256,Size') 'File metadata shape must match protocol.'
            $stream = $entry.Open(); $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose(); $stream.Dispose() }
            Assert-Package ($entry.Length -eq $item.Size -and $hash -ceq $item.Sha256) ('Archive bytes must match file metadata: ' + $entry.FullName)
            Assert-Package ($item.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $source $entry.FullName) -Algorithm SHA256).Hash.ToLowerInvariant()) 'Packaged bytes must preserve source bytes.'
        }
    } finally { $zip.Dispose() }
    foreach ($path in $private) { Assert-Package ([IO.File]::ReadAllText((Join-Path $source $path)) -ceq 'SYNTHETIC PRIVATE SENTINEL') 'Packaging must leave private files untouched.' }
    $rejected = $false
    try { & $builder -SourceRoot $source -OutputDirectory $output -SourceCommit $commit | Out-Null } catch { $rejected = $true }
    Assert-Package $rejected 'Existing release assets must never be overwritten by a build.'
    # The production publication boundary is GH CLI; this seam never contacts GitHub.
    Assert-Package ([IO.File]::Exists($publisher)) 'Release publisher must exist before draft/publication safety can pass.'
    $savedEnvironment = @{}
    foreach ($name in @('GITHUB_ACTIONS','GITHUB_EVENT_NAME','GITHUB_REF','GITHUB_REPOSITORY','GITHUB_SHA','GH_TOKEN')) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    try {
        $env:GITHUB_ACTIONS = 'true'; $env:GITHUB_EVENT_NAME = 'push'; $env:GITHUB_REF = 'refs/heads/main'
        $env:GITHUB_REPOSITORY = 'Alox1d/act-signer'; $env:GITHUB_SHA = $commit; $env:GH_TOKEN = 'SYNTHETIC-NON-CREDENTIAL'
        $state = @{ Release = $null; Calls = (New-Object 'System.Collections.Generic.List[string]'); RejectUpload = $false; FailDownload = $false; WrongTag = $false }
        $fakeGh = {
            param([string[]]$Arguments)
            $line = $Arguments -join ' '; $state.Calls.Add($line)
            if ($Arguments[0] -ceq 'api') {
                if ($Arguments[1] -like '*/git/ref/tags/*') {
                    if ($state.WrongTag) { return [pscustomobject]@{ ExitCode = 0; Output = '{"object":{"type":"commit","sha":"ffffffffffffffffffffffffffffffffffffffff"}}' } }
                    return [pscustomobject]@{ ExitCode = 1; Output = 'gh: Not Found (HTTP 404)' }
                }
                if ($null -eq $state.Release) { return [pscustomobject]@{ ExitCode = 0; Output = '[[]]' } }
                return [pscustomobject]@{ ExitCode = 0; Output = ('[[' + ($state.Release | ConvertTo-Json -Depth 6 -Compress) + ']]') }
            }
            if ($Arguments[1] -ceq 'create') {
                $state.Release = [ordered]@{ draft = $true; prerelease = $false; tag_name = 'v1.5.0'; target_commitish = $commit; assets = @() }
            } elseif ($Arguments[1] -ceq 'upload') {
                if ($state.RejectUpload) { return [pscustomobject]@{ ExitCode = 1; Output = 'SYNTHETIC interrupted upload' } }
                $state.Release.assets = @([ordered]@{ name = 'ActSigner-1.5.0.zip'; size = (Get-Item -LiteralPath $zipPath).Length; state = 'uploaded' }, [ordered]@{ name = 'ActSigner-update.json'; size = (Get-Item -LiteralPath $manifestPath).Length; state = 'uploaded' }, [ordered]@{ name = 'CSPSigner-1.5.0.zip'; size = (Get-Item -LiteralPath $publicZipPath).Length; state = 'uploaded' })
            } elseif ($Arguments[1] -ceq 'download') {
                if ($state.FailDownload) { return [pscustomobject]@{ ExitCode = 1; Output = 'SYNTHETIC readback failed' } }
                $destination = $Arguments[[Array]::IndexOf($Arguments, '--dir') + 1]
                [IO.File]::Copy($zipPath, (Join-Path $destination 'ActSigner-1.5.0.zip'))
                [IO.File]::Copy($manifestPath, (Join-Path $destination 'ActSigner-update.json'))
                [IO.File]::Copy($publicZipPath, (Join-Path $destination 'CSPSigner-1.5.0.zip'))
            } elseif ($Arguments[1] -ceq 'edit') { $state.Release.draft = $false }
            return [pscustomobject]@{ ExitCode = 0; Output = '' }
        }.GetNewClosure()
        $published = & $publisher -AssetDirectory $output -SourceCommit $commit -GhCommand $fakeGh
        Assert-Package ($published.Status -ceq 'published' -and -not $state.Release.draft) 'A complete uploaded and readback-verified pair must publish.'
        $calls = @($state.Calls.ToArray())
        Assert-Package (@($calls | Where-Object { $_ -like 'api */releases?per_page=100 --paginate --slurp' }).Count -gt 0) 'Publication lookup must use authenticated release listing because by-tag REST lookup is documented for published releases.'
        Assert-Package ((@($calls | Where-Object { $_ -like 'release create *--draft*' })).Count -eq 1) 'New release must begin as a draft.'
        Assert-Package ((@($calls | Where-Object { $_ -like 'release edit *--draft=false*--latest*' })).Count -eq 1) 'Publication must explicitly become stable latest after upload.'
        Assert-Package (@($calls | Where-Object { $_ -like ('release upload *' + $publicZipPath + '*') }).Count -eq 1) 'Publication must actually upload the branded download, not only invent it in a mock response.'
        Assert-Package (@($calls | Where-Object { $_ -like 'release download *--pattern CSPSigner-1.5.0.zip*' }).Count -eq 1) 'Publication must request readback of the branded archive.'
        Assert-Package (@($calls | Where-Object { $_ -like 'release create *--title CSPSigner 1.5.0*' }).Count -eq 1) 'Release API must use the selected public product name.'
        $state.Calls.Clear(); $rejected = $false
        try { & $publisher -AssetDirectory $output -SourceCommit $commit -GhCommand $fakeGh | Out-Null } catch { $rejected = $true }
        Assert-Package ($rejected -and @($state.Calls | Where-Object { $_ -like 'release *' }).Count -eq 0) 'Published versions must be refused before any mutation.'
        $state.Release.draft = $true; $state.Release.assets = @(); $state.Calls.Clear()
        & $publisher -AssetDirectory $output -SourceCommit $commit -GhCommand $fakeGh | Out-Null
        Assert-Package (@($state.Calls | Where-Object { $_ -like 'release create *' }).Count -eq 0 -and @($state.Calls | Where-Object { $_ -like 'release upload *--clobber*' }).Count -eq 1) 'Same-commit incomplete draft must resume without another release.'
        $state.Release.draft = $true; $state.Release.target_commitish = 'ffffffffffffffffffffffffffffffffffffffff'; $state.Calls.Clear(); $rejected = $false
        try { & $publisher -AssetDirectory $output -SourceCommit $commit -GhCommand $fakeGh | Out-Null } catch { $rejected = $true }
        Assert-Package ($rejected -and @($state.Calls | Where-Object { $_ -like 'release *' }).Count -eq 0) 'A draft for a different commit must never be resumed.'
        $state.Release = $null; $state.RejectUpload = $true; $state.Calls.Clear(); $rejected = $false
        try { & $publisher -AssetDirectory $output -SourceCommit $commit -GhCommand $fakeGh | Out-Null } catch { $rejected = $true }
        Assert-Package ($rejected -and $state.Release.draft -and @($state.Calls | Where-Object { $_ -like 'release edit *' }).Count -eq 0) 'Interrupted asset upload must leave an unpublished draft.'
        $state.RejectUpload = $false; $state.FailDownload = $true; $state.Calls.Clear(); $rejected = $false
        try { & $publisher -AssetDirectory $output -SourceCommit $commit -GhCommand $fakeGh | Out-Null } catch { $rejected = $true }
        Assert-Package ($rejected -and $state.Release.draft -and @($state.Calls | Where-Object { $_ -like 'release edit *' }).Count -eq 0) 'Failed asset readback must leave an unpublished draft.'
        $state.Release = $null; $state.FailDownload = $false; $state.WrongTag = $true; $state.Calls.Clear(); $rejected = $false
        try { & $publisher -AssetDirectory $output -SourceCommit $commit -GhCommand $fakeGh | Out-Null } catch { $rejected = $true }
        Assert-Package ($rejected -and @($state.Calls | Where-Object { $_ -like 'release *' }).Count -eq 0) 'An existing tag targeting another commit must be refused.'
        $state.Release = $null; $state.Calls.Clear(); $rejected = $false
        [IO.File]::WriteAllText($publicZipPath, 'SYNTHETIC TAMPERED PUBLIC ARCHIVE')
        try { & $publisher -AssetDirectory $output -SourceCommit $commit -GhCommand $fakeGh | Out-Null } catch { $rejected = $true }
        Assert-Package ($rejected -and $state.Calls.Count -eq 0) 'Tampered CSPSigner archive must be rejected before contacting GitHub.'
        [IO.File]::Copy($zipPath, $publicZipPath, $true)
        $env:GITHUB_REF = 'refs/heads/ui-layout-check'; $state.Calls.Clear(); $rejected = $false
        try { & $publisher -AssetDirectory $output -SourceCommit $commit -GhCommand $fakeGh | Out-Null } catch { $rejected = $true }
        Assert-Package ($rejected -and $state.Calls.Count -eq 0) 'Publication must refuse a non-main event without contacting GitHub.'
    } finally { foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name]) } }
    foreach ($badVersion in @('01.5.0','1.5','1.5.0-beta','2147483648.5.0')) {
        [IO.File]::WriteAllText((Join-Path $source 'ActSigner.Version.json'), ('{"SchemaVersion":1,"Version":"' + $badVersion + '","LauncherProtocol":1}'))
        $rejected = $false
        try { & $builder -SourceRoot $source -OutputDirectory (Join-Path $testRoot ([guid]::NewGuid().ToString('N'))) -SourceCommit $commit | Out-Null } catch { $rejected = $true }
        Assert-Package $rejected ('Invalid release version must be rejected: ' + $badVersion)
    }
    [IO.File]::WriteAllText((Join-Path $source 'ActSigner.Version.json'), '{"SchemaVersion":1,"Version":"1.5.0","LauncherProtocol":1}')
    Remove-Item -LiteralPath (Join-Path $source 'ActSigner.Update.psm1')
    $rejected = $false
    try { & $builder -SourceRoot $source -OutputDirectory (Join-Path $testRoot 'missing') -SourceCommit $commit | Out-Null } catch { $rejected = $true }
    Assert-Package $rejected 'Incomplete runtime payload must be rejected.'
    Write-Host 'Build-Release tests passed: default-SourceRoot subprocess from unrelated CWD, real allowlist ZIP, manifest/file hashes, private-file exclusion, immutable assets and version/missing-file rejection.'
    Write-Host 'Publish-Release tests passed: draft/full-pair/readback/stable publication, published-version refusal, same-commit recovery, mismatched commit/tag refusal, interrupted upload/readback and main-only gating.'
} finally { if ([IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force } }
