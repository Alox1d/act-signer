#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Assert-LaunchTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('ASSERT: ' + $Message) }
}
Assert-LaunchTest (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Start-ActSigner.ps1')) 'Startup must include the version-selecting launcher.'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Output 'SKIP: actual launcher subprocess tests require Windows PowerShell 5.1.'
    exit 0
}
Assert-LaunchTest ($PSVersionTable.PSEdition -eq 'Desktop') 'Run native launcher tests with Windows PowerShell 5.1.'

function Quote-LaunchTestArgument {
    param([string]$Value)
    # Windows paths cannot contain double quotes; retain terminal backslashes.
    if ($Value.Contains('"')) { throw 'Unexpected quote in native test path.' }
    return '"' + [regex]::Replace($Value, '(\\+)$', '$1$1') + '"'
}
function Write-LaunchTestText {
    param([string]$Path, [string]$Text)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($true)))
}
function Wait-LaunchTestFile {
    param([string]$Path, [int]$Seconds = 15)
    $deadline = [datetime]::UtcNow.AddSeconds($Seconds)
    while (-not [IO.File]::Exists($Path) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 40 }
    Assert-LaunchTest ([IO.File]::Exists($Path)) ('Timed out waiting for synthetic event: ' + [IO.Path]::GetFileName($Path))
}

$appScript = @'
param()
$ErrorActionPreference = 'Stop'
$stateRoot = $env:ACTSIGNER_LAUNCH_TEST_STATE
$report = [ordered]@{
    Root = $PSScriptRoot
    ProcessId = $PID
    Edition = $PSVersionTable.PSEdition
    Apartment = [string][Threading.Thread]::CurrentThread.ApartmentState
    VersionMajor = $PSVersionTable.PSVersion.Major
}
[IO.File]::WriteAllText((Join-Path $stateRoot 'app.json'), (ConvertTo-Json $report))
$limit = [datetime]::UtcNow.AddSeconds(20)
while (-not [IO.File]::Exists((Join-Path $stateRoot 'finish-app')) -and [datetime]::UtcNow -lt $limit) { Start-Sleep -Milliseconds 40 }
exit 7
'@
$updateStub = @'
Set-StrictMode -Version 2.0
function Get-ActUpdateStateRoot { return $env:ACTSIGNER_LAUNCH_TEST_STATE }
function Get-ActLaunchSelection {
    param([string]$BundledRoot, [string]$StateRoot, [switch]$Previous)
    if ([IO.File]::Exists((Join-Path $StateRoot 'selection-fails'))) { throw 'Synthetic unreadable cache.' }
    $selection = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $StateRoot 'selection.json')))
    [IO.File]::AppendAllText((Join-Path $StateRoot 'selection-calls.txt'), ([string][bool]$Previous + [Environment]::NewLine))
    return [pscustomobject]@{ ApplicationRoot = [string]$selection.Root; Version = '1.5.0'; UsingCached = $true; Rollback = [bool]$Previous; Notice = '' }
}
function Invoke-ActUpdateCheck {
    param([string]$ApplicationRoot, [string]$StateRoot)
    [IO.File]::WriteAllText((Join-Path $StateRoot 'worker.json'), (ConvertTo-Json ([ordered]@{ Root=$ApplicationRoot; ModuleRoot=$PSScriptRoot; ProcessId=$PID })))
    # Model a network operation that has not completed while the app opens.
    $limit = [datetime]::UtcNow.AddSeconds(20)
    while (-not [IO.File]::Exists((Join-Path $StateRoot 'finish-worker')) -and [datetime]::UtcNow -lt $limit) { Start-Sleep -Milliseconds 40 }
    return [pscustomobject]@{ Status='current'; Version='1.5.0'; Message='' }
}
Export-ModuleMember -Function Get-ActUpdateStateRoot, Get-ActLaunchSelection, Invoke-ActUpdateCheck
'@
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ActSigner launch Кириллица & (test) 100% ' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$reports = New-Object 'System.Collections.Generic.List[object]'
$children = New-Object 'System.Collections.Generic.List[object]'
$stateDirectories = New-Object 'System.Collections.Generic.List[string]'
try {
    $cases = @(
        [pscustomobject]@{ Name='background'; Switch=''; Cache=$true; Worker=$true; Cmd=$false },
        [pscustomobject]@{ Name='no-update'; Switch='-NoUpdate'; Cache=$true; Worker=$false; Cmd=$false },
        [pscustomobject]@{ Name='previous'; Switch='-Previous'; Cache=$true; Worker=$false; Cmd=$false },
        [pscustomobject]@{ Name='cache-fallback'; Switch='-NoUpdate'; Cache=$false; Worker=$false; Cmd=$false },
        [pscustomobject]@{ Name='cmd-chain'; Switch=''; Cache=$true; Worker=$true; Cmd=$true }
    )
    foreach ($case in $cases) {
        $caseRoot = Join-Path $testRoot $case.Name
        $bundle = Join-Path $caseRoot "bundle O'Brien"
        $cached = Join-Path $caseRoot 'cached version'
        $stateRoot = Join-Path $caseRoot 'state'
        $stateDirectories.Add($stateRoot)
        foreach ($directory in @($bundle, $cached, $stateRoot)) { [void][IO.Directory]::CreateDirectory($directory) }
        foreach ($directory in @($bundle, $cached)) {
            foreach ($name in @('Start-ActSigner.ps1', 'Update-ActSigner.ps1', 'ActSigner.Console.psm1', 'Start.cmd')) {
                Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $directory $name)
            }
            Write-LaunchTestText (Join-Path $directory 'ActSigner.Update.psm1') $updateStub
            Write-LaunchTestText (Join-Path $directory 'Sign-Acts.ps1') $appScript
            Write-LaunchTestText (Join-Path $directory 'ActSigner.Version.json') '{"SchemaVersion":1,"Version":"1.5.0","LauncherProtocol":1}'
        }
        Write-LaunchTestText (Join-Path $stateRoot 'selection.json') (ConvertTo-Json @{Root=$cached})
        Write-LaunchTestText (Join-Path $stateRoot 'settings.json') '{"SourceRoot":"SYNTHETIC_SOURCE","SaveBesideSources":true}'
        Write-LaunchTestText (Join-Path $stateRoot 'document.pdf') '%PDF-1.4 SYNTHETIC TEST'
        Write-LaunchTestText (Join-Path $stateRoot 'document.sig') 'SYNTHETIC SIGNATURE SENTINEL'
        $originals = @{}
        foreach ($name in @('settings.json','document.pdf','document.sig')) { $originals[$name] = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $stateRoot $name))) }
        if (-not $case.Cache) { Write-LaunchTestText (Join-Path $stateRoot 'selection-fails') 'synthetic' }
        $start = New-Object Diagnostics.ProcessStartInfo
        if ($case.Cmd) {
            $start.FileName = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'cmd.exe'
            $start.Arguments = '/d /s /c "' + (Quote-LaunchTestArgument (Join-Path $bundle 'Start.cmd')) + '"'
        }
        else {
            $start.FileName = Join-Path $PSHOME 'powershell.exe'
            $start.Arguments = '-NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File ' + (Quote-LaunchTestArgument (Join-Path $bundle 'Start-ActSigner.ps1')) + ' -StateRoot ' + (Quote-LaunchTestArgument $stateRoot) + ' ' + $case.Switch
        }
        $start.EnvironmentVariables['ACTSIGNER_LAUNCH_TEST_STATE'] = $stateRoot
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.RedirectStandardInput = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $start
        [void]$process.Start()
        $children.Add($process)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine('')
        $process.StandardInput.Close()
        Wait-LaunchTestFile (Join-Path $stateRoot 'app.json')
        $app = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $stateRoot 'app.json')))
        $expectedRoot = if ($case.Cache) { $cached } else { $bundle }
        Assert-LaunchTest ($app.Root -ceq $expectedRoot) ($case.Name + ': application must use selected snapshot.')
        Assert-LaunchTest ($app.Edition -eq 'Desktop' -and $app.Apartment -eq 'STA' -and $app.VersionMajor -eq 5) ($case.Name + ': native Windows PowerShell 5.1 and STA must be preserved.')
        if ($case.Worker) {
            Wait-LaunchTestFile (Join-Path $stateRoot 'worker.json')
            $worker = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $stateRoot 'worker.json')))
            Assert-LaunchTest ($worker.Root -ceq $cached -and $worker.ModuleRoot -ceq $cached) ($case.Name + ': validated cached worker must load sibling module.')
            Assert-LaunchTest (-not [IO.File]::Exists((Join-Path $stateRoot 'finish-worker'))) ($case.Name + ': app opened before background networking completed.')
            # A change prepared while this invocation runs must not start a second app.
            Write-LaunchTestText (Join-Path $stateRoot 'selection.json') (ConvertTo-Json @{Root=$bundle})
        }
        Write-LaunchTestText (Join-Path $stateRoot 'finish-app') 'done'
        Assert-LaunchTest ($process.WaitForExit(15000)) ($case.Name + ': launcher must exit after app exit.')
        Assert-LaunchTest ($process.ExitCode -eq 7) ($case.Name + ': application exit code must propagate.')
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Assert-LaunchTest ([string]::IsNullOrWhiteSpace($stderr)) ($case.Name + ': unexpected process error: ' + $stderr)
        if (-not $case.Worker) { Assert-LaunchTest (-not [IO.File]::Exists((Join-Path $stateRoot 'worker.json'))) ($case.Name + ': networking must be suppressed.') }
        if ($case.Cache) {
            $calls = @([IO.File]::ReadAllLines((Join-Path $stateRoot 'selection-calls.txt')))
            Assert-LaunchTest ($calls.Count -eq 1) ($case.Name + ': selection must be read exactly once.')
            Assert-LaunchTest ($calls[0] -eq ([string]($case.Name -eq 'previous'))) ($case.Name + ': previous-mode contract.')
        }
        foreach ($name in $originals.Keys) {
            Assert-LaunchTest ($originals[$name] -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $stateRoot $name)))) ($case.Name + ': user data changed.')
        }
        Write-LaunchTestText (Join-Path $stateRoot 'finish-worker') 'done'
        $reports.Add([pscustomobject]@{Case=$case.Name;ExitCode=$process.ExitCode;Apartment=$app.Apartment;Edition=$app.Edition;Cached=[bool]$case.Cache;Background=[bool]$case.Worker;UserDataUnchanged=$true})
        Write-Output ('PASS launcher: ' + $case.Name)
    }
    $artifactRoot = Join-Path $PSScriptRoot 'update-test-artifacts'
    [void][IO.Directory]::CreateDirectory($artifactRoot)
    [IO.File]::WriteAllText((Join-Path $artifactRoot 'launcher-measurements.json'), (ConvertTo-Json ([ordered]@{NativeWindows=$true;PowerShellVersion=[string]$PSVersionTable.PSVersion;Cases=@($reports.ToArray());Failures=@()}) -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
finally {
    foreach ($directory in $stateDirectories) {
        foreach ($name in @('finish-app','finish-worker')) { try { Write-LaunchTestText (Join-Path $directory $name) 'cleanup' } catch { } }
    }
    foreach ($process in $children) {
        try { if (-not $process.HasExited -and -not $process.WaitForExit(3000)) { $process.Kill() } } catch { }
        try { $process.Dispose() } catch { }
    }
    # The bounded worker may still be releasing files for a brief interval.
    $cleanupLimit = [datetime]::UtcNow.AddSeconds(5)
    do {
        try { if ([IO.Directory]::Exists($testRoot)) { [IO.Directory]::Delete($testRoot, $true) } }
        catch { Start-Sleep -Milliseconds 50 }
    } while ([IO.Directory]::Exists($testRoot) -and [datetime]::UtcNow -lt $cleanupLimit)
}
