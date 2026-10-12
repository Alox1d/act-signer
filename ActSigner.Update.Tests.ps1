#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
function Assert-Update { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw ('ASSERT: ' + $Message) } }
$modulePath = Join-Path $PSScriptRoot 'ActSigner.Update.psm1'
Assert-Update ([IO.File]::Exists($modulePath)) 'The updater public interfaces and ZIP installer do not exist yet.'
Import-Module $modulePath -Force
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Get-FixtureHash { param([string]$Path) $sha = [Security.Cryptography.SHA256]::Create(); $stream = [IO.File]::OpenRead($Path); try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() } finally { $stream.Dispose(); $sha.Dispose() } }
function Write-UpdateFixture { param([string]$Path, [string]$Text) [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)); [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($true))) }
$runtimeNames = @('Sign-Acts.ps1','ActSigner.Core.psm1','ActSigner.CryptoPro.psm1','ActSigner.Settings.psm1','ActSigner.UI.psm1','ActSigner.Console.psm1','ActSigner.Update.psm1','ActSigner.CryptoPro.js','Start-ActSigner.ps1','Update-ActSigner.ps1','ActSigner.Version.json')
function New-UpdateFixture {
    param([string]$Root, [string]$Version = '1.6.0', [string]$ExtraEntry = '', [switch]$DuplicateEntry, [switch]$LinkEntry, [switch]$BrokenScript, [switch]$MissingRuntime)
    $payload = Join-Path $Root 'payload'
    foreach ($name in $runtimeNames) {
        if ($MissingRuntime -and $name -eq 'ActSigner.CryptoPro.js') { continue }
        $text = '# synthetic public updater fixture'
        if ($name -eq 'ActSigner.Version.json') { $text = '{"SchemaVersion":1,"Version":"' + $Version + '","LauncherProtocol":1}' }
        if ($BrokenScript -and $name -eq 'Sign-Acts.ps1') { $text = 'function broken {' }
        Write-UpdateFixture (Join-Path $payload $name) $text
    }
    $zip = Join-Path $Root ('ActSigner-' + $Version + '.zip')
    $files = @()
    $zipStream = [IO.File]::Open($zip, [IO.FileMode]::CreateNew)
    $archive = New-Object IO.Compression.ZipArchive($zipStream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $payload -File | Sort-Object Name)) {
            $entry = $archive.CreateEntry($file.Name)
            $out = $entry.Open(); $bytes = [IO.File]::ReadAllBytes($file.FullName); try { $out.Write($bytes, 0, $bytes.Length) } finally { $out.Dispose() }
            $files += [pscustomobject]@{ Path=$file.Name; Size=$bytes.Length; Sha256=(Get-FixtureHash $file.FullName) }
        }
        if ($ExtraEntry) { $entry=$archive.CreateEntry($ExtraEntry); $out=$entry.Open(); try { $out.WriteByte(65) } finally { $out.Dispose() }; $files += [pscustomobject]@{Path=$ExtraEntry;Size=1;Sha256='559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd'} }
        if ($DuplicateEntry) { $entry=$archive.CreateEntry('SIGN-ACTS.PS1'); $out=$entry.Open(); try { $out.WriteByte(65) } finally { $out.Dispose() }; $files += [pscustomobject]@{Path='SIGN-ACTS.PS1';Size=1;Sha256='559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd'} }
        if ($LinkEntry) { $entry=$archive.CreateEntry('link.txt'); $entry.ExternalAttributes = -1610612736; $out=$entry.Open(); try { $out.WriteByte(65) } finally { $out.Dispose() }; $files += [pscustomobject]@{Path='link.txt';Size=1;Sha256='559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd'} }
    }
    finally { $archive.Dispose(); $zipStream.Dispose() }
    $manifest = [pscustomobject]@{SchemaVersion=1;Version=$Version;LauncherProtocol=1;Repository='Alox1d/act-signer';SourceCommit=('a'*40);AssetName=[IO.Path]::GetFileName($zip);Size=([IO.FileInfo]$zip).Length;Sha256=(Get-FixtureHash $zip);Files=$files}
    $manifestPath = Join-Path $Root 'ActSigner-update.json'
    Write-UpdateFixture $manifestPath (ConvertTo-Json -InputObject $manifest -Depth 5)
    $base='https://github.com/Alox1d/act-signer/releases/download/v' + $Version + '/'
    $release=[pscustomobject]@{tag_name=('v'+$Version);draft=$false;prerelease=$false;assets=@([pscustomobject]@{name='ActSigner-update.json';size=([IO.FileInfo]$manifestPath).Length;browser_download_url=($base+'ActSigner-update.json')},[pscustomobject]@{name=$manifest.AssetName;size=$manifest.Size;browser_download_url=($base+$manifest.AssetName)})}
    return [pscustomobject]@{Root=$Root;Manifest=$manifest;ManifestPath=$manifestPath;Zip=$zip;Release=$release}
}
function Invoke-FixtureUpdate { param($Fixture,[string]$ApplicationRoot,[string]$StateRoot)
    $release = $Fixture.Release
    $manifestPath = $Fixture.ManifestPath
    $zipPath = $Fixture.Zip
    $provider = { return $release }.GetNewClosure()
    $downloader = { param($Url,$Destination,$MaxBytes) if ($Url.EndsWith('/ActSigner-update.json')) { [IO.File]::Copy($manifestPath,$Destination) } else { [IO.File]::Copy($zipPath,$Destination) } }.GetNewClosure()
    return Invoke-ActUpdateCheck -ApplicationRoot $ApplicationRoot -StateRoot $StateRoot -ReleaseProvider $provider -Downloader $downloader
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ActSigner Update Кириллица [1] & (2) ' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$external=$null
try {
    $bundled = Join-Path $testRoot 'bundled'
    Write-UpdateFixture (Join-Path $bundled 'ActSigner.Version.json') '{"SchemaVersion":1,"Version":"1.5.0","LauncherProtocol":1}'
    $stateRoot = Join-Path $testRoot 'state'
    $selection=Get-ActLaunchSelection -BundledRoot $bundled -StateRoot $stateRoot
    Assert-Update (-not $selection.UsingCached -and $selection.Version -eq '1.5.0' -and $selection.ApplicationRoot -ceq $bundled) 'First launch must select the bundled application without a network call.'
    $fixture=New-UpdateFixture (Join-Path $testRoot 'release')
    $result=Invoke-FixtureUpdate $fixture $bundled $stateRoot
    Assert-Update ($result.Status -eq 'updated') ('Valid real ZIP was not installed: '+$result.Message)
    Assert-Update ([IO.File]::Exists((Join-Path $stateRoot 'active.json'))) 'Installer did not commit state.'
    Assert-Update ($selection.ApplicationRoot -ceq $bundled) 'Installer changed the application snapshot already selected for this invocation.'
    $next=Get-ActLaunchSelection -BundledRoot $bundled -StateRoot $stateRoot
    Assert-Update ($next.UsingCached -and $next.Version -eq '1.6.0') 'The next launch did not select the validated update.'
    Assert-Update ([IO.File]::Exists((Join-Path $next.ApplicationRoot 'ActSigner.CryptoPro.js'))) 'A required runtime file is absent.'
    $originalState=[IO.File]::ReadAllText((Join-Path $stateRoot 'active.json'))
    $result=Invoke-FixtureUpdate $fixture $bundled $stateRoot
    Assert-Update ($result.Status -eq 'current') 'Same version should not reinstall.'
    Assert-Update ([IO.File]::ReadAllText((Join-Path $stateRoot 'active.json')) -ceq $originalState) 'Same release changed active state.'
    Write-Host 'PASS: real ZIP installation, immutable current invocation, next launch and idempotence'
    $newer=New-UpdateFixture (Join-Path $testRoot 'release-newer') '1.7.0'
    $result=Invoke-FixtureUpdate $newer $next.ApplicationRoot $stateRoot
    Assert-Update ($result.Status -eq 'updated') ('Second release failed: '+$result.Message)
    $rollback=Get-ActLaunchSelection -BundledRoot $bundled -StateRoot $stateRoot -Previous
    Assert-Update ($rollback.UsingCached -and $rollback.Rollback -and $rollback.Version -eq '1.6.0') 'Previous selection did not return the verified old release.'
    $active=Get-ActLaunchSelection -BundledRoot $bundled -StateRoot $stateRoot
    Assert-Update ($active.Version -eq '1.7.0') 'One-launch rollback mutated persistent active selection.'
    [IO.File]::WriteAllText((Join-Path $active.ApplicationRoot 'Sign-Acts.ps1'),'# corrupt')
    $fallback=Get-ActLaunchSelection -BundledRoot $bundled -StateRoot $stateRoot
    Assert-Update ($fallback.Version -eq '1.6.0') 'Corrupt active files did not fall back to the verified previous release.'
    Write-Host 'PASS: atomic previous selection and corrupt active fallback'
    $badRoot=Join-Path $testRoot 'rejection-state'
    $prior=Invoke-FixtureUpdate $fixture $bundled $badRoot
    Assert-Update ($prior.Status -eq 'updated') 'Rejection fixture setup failed.'
    $pointer=Join-Path $badRoot 'active.json'
    $before=[IO.File]::ReadAllText($pointer)
    foreach ($kind in @('zip-hash','file-hash','version','path','duplicate','ads','reserved','link','script','missing','size','protocol','draft','prerelease','redirect','tag')) {
        $args=@{Root=(Join-Path $testRoot ('bad-'+$kind));Version='1.8.0'}
        switch ($kind) {
            'path' {$args.ExtraEntry='../escape.txt'}
            'duplicate' {$args.DuplicateEntry=$true}
            'ads' {$args.ExtraEntry='file.txt:evil'}
            'reserved' {$args.ExtraEntry='CON.txt'}
            'link' {$args.LinkEntry=$true}
            'script' {$args.BrokenScript=$true}
            'missing' {$args.MissingRuntime=$true}
        }
        $bad=New-UpdateFixture @args
        switch ($kind) {
            'zip-hash' {$bad.Manifest.Sha256='0'*64}
            'file-hash' {$bad.Manifest.Files[0].Sha256='0'*64}
            'version' {$bad.Manifest.Version='1.9.0'}
            'size' {$bad.Manifest.Files[0].Size=2097153}
            'protocol' {$bad.Manifest.LauncherProtocol=2}
            'draft' {$bad.Release.draft=$true}
            'prerelease' {$bad.Release.prerelease=$true}
            'redirect' {$bad.Release.assets[0].browser_download_url='https://evil.invalid/ActSigner-update.json'}
            'tag' {$bad.Release.tag_name='v01.8.0'}
        }
        Write-UpdateFixture $bad.ManifestPath (ConvertTo-Json $bad.Manifest -Depth 5)
        $bad.Release.assets[0].size=([IO.FileInfo]$bad.ManifestPath).Length
        $result=Invoke-FixtureUpdate $bad $bundled $badRoot
        Assert-Update ($result.Status -in @('unavailable','unsupported')) ('Malformed '+$kind+' package was accepted: '+$result.Status)
        Assert-Update ([IO.File]::ReadAllText($pointer) -ceq $before) ('Rejected '+$kind+' modified active state.')
        Assert-Update (-not [IO.File]::Exists((Join-Path $badRoot 'escape.txt'))) 'ZIP traversal escaped staging.'
    }
    Write-Host 'PASS: hash, version, path, duplicate, ADS, reserved names, links, parser, runtime, size, protocol and release rejection'
    $lockPath=Join-Path $badRoot 'update.lock'
    $lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { $busy=Invoke-FixtureUpdate $newer $bundled $badRoot; Assert-Update ($busy.Status -eq 'busy') 'Concurrent worker did not respect held exclusive lock.' } finally { $lock.Dispose() }
    $afterLock=Invoke-FixtureUpdate $newer $bundled $badRoot
    Assert-Update ($afterLock.Status -eq 'updated') 'Persistent lock-file existence prevented recovery after handle close.'
    $off=Invoke-ActUpdateCheck -ApplicationRoot $bundled -StateRoot $badRoot -ReleaseProvider {throw 'synthetic offline'} -Downloader {throw 'must not download'}
    Assert-Update ($off.Status -eq 'unavailable') 'Offline check did not fail quietly.'
    Write-Host 'PASS: exclusive lock, released-lock recovery and offline behavior'
    $blockedRoot=Join-Path $testRoot 'pointer-blocked'
    [void][IO.Directory]::CreateDirectory((Join-Path $blockedRoot 'active.json'))
    Write-UpdateFixture (Join-Path $blockedRoot 'active.json/keep.txt') 'unchanged'
    $failed=Invoke-FixtureUpdate $fixture $bundled $blockedRoot
    Assert-Update ($failed.Status -eq 'unavailable') 'Occupied active pointer should prevent activation.'
    Assert-Update ([IO.File]::ReadAllText((Join-Path $blockedRoot 'active.json/keep.txt')) -ceq 'unchanged') 'Failed state publication changed occupied destination.'
    $bundledFallback=Get-ActLaunchSelection -BundledRoot $bundled -StateRoot $blockedRoot
    Assert-Update (-not $bundledFallback.UsingCached) 'Failed publication selected an uncommitted cache.'
    [IO.File]::WriteAllText((Join-Path $badRoot 'active.json'),'{broken')
    $corrupt=Get-ActLaunchSelection -BundledRoot $bundled -StateRoot $badRoot
    Assert-Update (-not $corrupt.UsingCached) 'Malformed active JSON did not select bundled fallback.'
    $newBundle=Join-Path $testRoot 'new-bundle'
    Write-UpdateFixture (Join-Path $newBundle 'ActSigner.Version.json') '{"SchemaVersion":1,"Version":"2.0.0","LauncherProtocol":1}'
    $noDowngrade=Get-ActLaunchSelection -BundledRoot $newBundle -StateRoot $stateRoot
    Assert-Update (-not $noDowngrade.UsingCached -and $noDowngrade.Version -eq '2.0.0') 'Old cache downgraded a newer bundled app.'
    Write-Host 'PASS: failed pointer publication, corrupt state and bundled downgrade prevention'
    # Interrupted download and existing immutable cache must not modify pointer or user files.
    $stableRoot=Join-Path $testRoot 'stable-state'
    $installed=Invoke-FixtureUpdate $fixture $bundled $stableRoot
    Assert-Update ($installed.Status -eq 'updated') 'Immutable fixture setup failed.'
    $stablePointer=Join-Path $stableRoot 'active.json'
    $stableText=[IO.File]::ReadAllText($stablePointer)
    $settings=Join-Path $testRoot 'ActSigner/settings.json'
    $document=Join-Path $testRoot 'synthetic-documents/act.pdf'
    $signature=Join-Path $testRoot 'synthetic-documents/act.pdf.sig'
    Write-UpdateFixture $settings '{"SourceRoot":"synthetic only"}'
    Write-UpdateFixture $document '%PDF synthetic updater preservation test'
    Write-UpdateFixture $signature 'synthetic signature bytes; no private data'
    $protected=@{}
    foreach ($path in @($settings,$document,$signature)) {$protected[$path]=Get-FixtureHash $path}
    $brokenDownload=Invoke-ActUpdateCheck -ApplicationRoot $bundled -StateRoot $stableRoot -ReleaseProvider {$newer.Release}.GetNewClosure() -Downloader {param($Url,$Destination,$MaxBytes) [IO.File]::WriteAllText($Destination,'partial');throw 'synthetic interruption'}
    Assert-Update ($brokenDownload.Status -eq 'unavailable') 'Interrupted download activated.'
    Assert-Update ([IO.File]::ReadAllText($stablePointer) -ceq $stableText) 'Interrupted download changed pointer.'
    Assert-Update (@(Get-ChildItem -LiteralPath $stableRoot -Directory -Force | Where-Object {$_.Name -like '.staging-*'}).Count -eq 0) 'Failed transaction left staging directories.'
    foreach ($path in @($settings,$document,$signature)) {Assert-Update ((Get-FixtureHash $path) -ceq $protected[$path]) 'Updater changed user data outside its state root.'}
    # Put the exact future version directory in place, but damage it: installer must not overwrite it.
    $futureDirectory=Join-Path $stableRoot ('versions/v1.7.0-'+$newer.Manifest.Sha256.Substring(0,16))
    [void][IO.Directory]::CreateDirectory($futureDirectory)
    $immutable=Join-Path $futureDirectory 'keep.txt'
    Write-UpdateFixture $immutable 'must not overwrite existing cache'
    $occupied=Invoke-FixtureUpdate $newer $bundled $stableRoot
    Assert-Update ($occupied.Status -eq 'unavailable') 'Installer overwrote an invalid existing version directory.'
    Assert-Update ([IO.File]::ReadAllText($immutable) -ceq 'must not overwrite existing cache') 'Existing version directory was modified.'
    Assert-Update ([IO.File]::ReadAllText($stablePointer) -ceq $stableText) 'Existing-directory failure modified active pointer.'
    Write-Host 'PASS: interrupted download, staging cleanup, immutable occupied version and user data preservation'
    # The successful directory left by failed pointer publication can be reused without overwriting.
    Remove-Item -LiteralPath (Join-Path $blockedRoot 'active.json') -Recurse -Force
    $orphanDirectory=@(Get-ChildItem -LiteralPath (Join-Path $blockedRoot 'versions') -Directory)[0].FullName
    $orphanHash=Get-FixtureHash (Join-Path $orphanDirectory 'Sign-Acts.ps1')
    $recovered=Invoke-FixtureUpdate $fixture $bundled $blockedRoot
    Assert-Update ($recovered.Status -eq 'updated') 'Interrupted pointer publication could not recover its complete immutable directory.'
    Assert-Update ((Get-FixtureHash (Join-Path $orphanDirectory 'Sign-Acts.ps1')) -ceq $orphanHash) 'Recovery rewrote existing runtime bytes.'
    # State must not authorize a manifest that has changed, nor point outside versions.
    $savedPointer=ConvertFrom-Json ([IO.File]::ReadAllText($stablePointer))
    $cacheRoot=Join-Path $stableRoot ('versions/'+$savedPointer.Active.Directory)
    [IO.File]::AppendAllText((Join-Path $cacheRoot 'payload-manifest.json'),' ')
    $changedManifest=Get-ActLaunchSelection -BundledRoot $bundled -StateRoot $stableRoot
    Assert-Update (-not $changedManifest.UsingCached) 'Modified cached manifest was trusted.'
    $savedPointer.Active.Directory='../outside'
    Write-UpdateFixture $stablePointer (ConvertTo-Json $savedPointer -Depth 5)
    $escapedPointer=Get-ActLaunchSelection -BundledRoot $bundled -StateRoot $stableRoot
    Assert-Update (-not $escapedPointer.UsingCached) 'Escaping cached pointer was accepted.'
    Write-Host 'PASS: orphaned complete-version recovery and cached manifest/pointer tamper fallback'
    # A redirected state root must be rejected before creating any external updater files.
    # Windows PowerShell 5.1 treats brackets in New-Item -Target as wildcards.
    # Keep the linked state path under the special-character root, but give its
    # independently owned target a plain unique name outside that root.
    $external=Join-Path ([IO.Path]::GetTempPath()) ('ActSigner-update-external-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($external)
    Write-UpdateFixture (Join-Path $external 'keep.txt') 'external bytes'
    $linkedState=Join-Path $testRoot 'linked-state'
    $createdLink=$false
    try {
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { $null=New-Item -ItemType Junction -Path $linkedState -Target $external -ErrorAction Stop }
        else { $null=New-Item -ItemType SymbolicLink -Path $linkedState -Target $external -ErrorAction Stop }
        $createdLink=$true
    }
    catch {
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { throw }
        Write-Host ('SKIP state reparse fixture: '+$_.Exception.Message)
    }
    if ($createdLink) {
        try {
            $redirected=Invoke-FixtureUpdate $fixture $bundled $linkedState
            Assert-Update ($redirected.Status -eq 'unavailable') 'Linked state directory was followed.'
            Assert-Update (@(Get-ChildItem -LiteralPath $external -Force).Count -eq 1) 'Linked state directory caused external writes.'
        }
        finally { [IO.Directory]::Delete($linkedState) }
        Write-Host 'PASS: state ancestor reparse rejection'
    }
    # A task that ignores cancellation must still stop at the wall-clock deadline.
    $transportBudget=& (Get-Module ActSigner.Update) {
        $never=New-Object 'Threading.Tasks.TaskCompletionSource[string]'
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $completed=New-Object 'Threading.Tasks.TaskCompletionSource[string]'
        $completed.SetResult('actual task result')
        $value=Wait-ActUpdateHttpTask -Task $completed.Task -Clock $clock -TimeoutMilliseconds 2000
        if ($value -cne 'actual task result') {throw 'HTTP wait lost the completed task result.'}
        $timedOut=$false
        try {$null=Wait-ActUpdateHttpTask -Task $never.Task -Clock $clock -TimeoutMilliseconds 80}
        catch [TimeoutException] {$timedOut=$true}
        return [pscustomobject]@{TimedOut=$timedOut;Elapsed=$clock.ElapsedMilliseconds}
    }
    Assert-Update ($transportBudget.TimedOut -and $transportBudget.Elapsed -lt 2000) 'HTTP wait ignored the hard deadline for a non-cancelling task.'
    Write-Host 'PASS: hard HTTP task deadline independent of cooperative cancellation'
    # An updater process that is killed releases its OS lock even though its lock file remains.
    $childRoot=Join-Path $testRoot 'child-lock-state'
    [void][IO.Directory]::CreateDirectory($childRoot)
    $childLock=Join-Path $childRoot 'update.lock'
    $ready=Join-Path $testRoot 'child-lock-ready.txt'
    $lockLiteral=$childLock.Replace("'","''")
    $readyLiteral=$ready.Replace("'","''")
    $childCode='$ErrorActionPreference=''Stop''; $lock=[IO.File]::Open('''+$lockLiteral+''',[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None); [IO.File]::WriteAllText('''+$readyLiteral+''',''ready''); [Threading.Thread]::Sleep(30000); $lock.Dispose()'
    $process=New-Object Diagnostics.Process
    $process.StartInfo.FileName=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $process.StartInfo.UseShellExecute=$false
    $process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCode))
    try {
        Assert-Update ($process.Start()) 'Lock owner subprocess did not start.'
        $startup=[Diagnostics.Stopwatch]::StartNew()
        while (-not [IO.File]::Exists($ready) -and $startup.ElapsedMilliseconds -lt 10000 -and -not $process.HasExited) {[Threading.Thread]::Sleep(50)}
        Assert-Update ([IO.File]::Exists($ready)) 'Lock owner subprocess did not acquire its lock.'
        $other=Invoke-FixtureUpdate $fixture $bundled $childRoot
        Assert-Update ($other.Status -eq 'busy') 'Updater did not observe an exclusive lock owned by another process.'
        $process.Kill()
        Assert-Update ($process.WaitForExit(5000)) 'Terminated lock owner did not exit.'
        Assert-Update ([IO.File]::Exists($childLock)) 'Crash fixture unexpectedly removed lock file.'
        $afterCrash=Invoke-FixtureUpdate $fixture $bundled $childRoot
        Assert-Update ($afterCrash.Status -eq 'updated') 'Updater could not recover the stale lock file after owner process termination.'
    }
    finally {if (-not $process.HasExited) {$process.Kill();$null=$process.WaitForExit(5000)};$process.Dispose()}
    Write-Host 'PASS: native subprocess exclusive lock and killed-worker recovery'
    Write-Host 'ActSigner.Update tests passed.'
 

}
finally {
    try { if ([IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force } }
    finally { if ($null -ne $external -and [IO.Directory]::Exists($external)) { Remove-Item -LiteralPath $external -Recurse -Force } }
}
