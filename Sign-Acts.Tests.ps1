# Black-box entry-point integration checks. Synthetic PDF/signature bytes and crypto stubs only.
param(
    [string]$CandidateDirectory = $PSScriptRoot,
    [string]$ArtifactDirectory = (Join-Path $PSScriptRoot 'entry-test-artifacts')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Entry-point integration checks require native Windows PowerShell 5.1.'
}
$CandidateDirectory = [IO.Path]::GetFullPath($CandidateDirectory)
$ArtifactDirectory = [IO.Path]::GetFullPath($ArtifactDirectory)
[void][IO.Directory]::CreateDirectory($ArtifactDirectory)
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('act-entry-synthetic-' + [guid]::NewGuid().ToString('N'))
$thumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
$failures = New-Object 'System.Collections.Generic.List[string]'
$reports = New-Object 'System.Collections.Generic.List[object]'
function Assert-Entry { param([bool]$Condition, [string]$Message) if (-not $Condition) { $failures.Add($Message) } }
function Write-SyntheticText {
    param([string]$Path, [string]$Text)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($true)))
}

$cryptoStub = @'
Set-StrictMode -Version 2.0
$script:configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'case.json') -Raw | ConvertFrom-Json
$script:counterPath = Join-Path $PSScriptRoot 'counter-report.json'
$script:counts = [pscustomobject]@{ NewSession = 0; Sign = 0; VerifyNew = 0; Close = 0; Inspect = 0; Events = @() }
function Write-SyntheticCounters { $script:counts | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:counterPath -Encoding UTF8 }
function Add-SyntheticEvent {
    param([string]$Kind)
    $script:counts.$Kind++
    $script:counts.Events = @($script:counts.Events) + @($Kind)
    Write-SyntheticCounters
}
function Test-ActCryptoPro { [pscustomobject]@{ Available = $true; Message = 'SYNTHETIC PROBE' } }
function Get-ActCertificates {
    $certificate = [pscustomobject]@{
        DisplayName = 'SYNTHETIC ENTRY TEST'; Thumbprint = $script:configuration.Thumbprint
        NotAfter = [datetime]'2030-01-01'; Subject = 'CN=SYNTHETIC ENTRY TEST'; Issuer = 'CN=SYNTHETIC ISSUER'
        Source = 'Synthetic provider'; StoreKind = 1; NotBefore = [datetime]'2026-01-01'
    }
    [pscustomobject]@{ Certificates = @($certificate); Warnings = @() }
}
function Get-ActExistingSignatureInfo {
    param([byte[]]$PdfBytes, [byte[]]$SignatureBytes)
    Add-SyntheticEvent 'Inspect'
    if (-not [Text.Encoding]::UTF8.GetString($PdfBytes).StartsWith('%PDF-1.4 SYNTHETIC')) { throw 'Unexpected synthetic PDF bytes.' }
    $text = [Text.Encoding]::UTF8.GetString($SignatureBytes)
    if ($text -eq 'SYNTHETIC_UNVERIFIABLE') {
        return [pscustomobject]@{ Status = 'unverifiable'; Thumbprints = @(); Message = 'SYNTHETIC PRECHECK ERROR' }
    }
    if ($text -ne 'SYNTHETIC_VALID_DUPLICATE') { throw 'Unexpected synthetic existing signature bytes.' }
    return [pscustomobject]@{ Status = 'valid'; Thumbprints = @($script:configuration.Thumbprint); Message = 'SYNTHETIC VALID SAME SIGNER' }
}
function New-ActCryptoSession {
    param($CertificateInfo)
    Add-SyntheticEvent 'NewSession'
    if ($CertificateInfo.Thumbprint -ne $script:configuration.Thumbprint) { throw 'Wrong synthetic certificate selection.' }
    return [pscustomobject]@{ Id = 'SYNTHETIC_SESSION' }
}
function Invoke-ActCryptoSign {
    param($Session, [byte[]]$PdfBytes)
    Add-SyntheticEvent 'Sign'
    if ($null -eq $Session -or $Session.Id -ne 'SYNTHETIC_SESSION') { throw 'Signing did not receive the lazy synthetic session.' }
    if ($script:configuration.SignError) { throw 'SYNTHETIC SIGNING ERROR' }
    return ,([Text.Encoding]::ASCII.GetBytes('SYNTHETIC-NEW:' + (Get-ActSha256 -Bytes $PdfBytes)))
}
function Test-ActCryptoSignature {
    param([byte[]]$PdfBytes, [byte[]]$SignatureBytes, [string]$Thumbprint)
    Add-SyntheticEvent 'VerifyNew'
    if ($Thumbprint -ne $script:configuration.Thumbprint -or
        [Text.Encoding]::ASCII.GetString($SignatureBytes) -ne ('SYNTHETIC-NEW:' + (Get-ActSha256 -Bytes $PdfBytes))) { throw 'Synthetic new signature verification mismatch.' }
}
function Close-ActCryptoSession {
    param($Session)
    Add-SyntheticEvent 'Close'
    if ($null -eq $Session -or $Session.Id -ne 'SYNTHETIC_SESSION') { throw 'Unexpected synthetic close session.' }
}
Write-SyntheticCounters
Export-ModuleMember -Function Test-ActCryptoPro, Get-ActCertificates, Get-ActExistingSignatureInfo, New-ActCryptoSession, Invoke-ActCryptoSign, Test-ActCryptoSignature, Close-ActCryptoSession
'@
$uiStub = @'
Set-StrictMode -Version 2.0
function Show-ActSignerWindow {
    param([scriptblock]$CertificateProvider, [scriptblock]$PlanProvider)
    $configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'case.json') -Raw | ConvertFrom-Json
    $discovery = & $CertificateProvider
    # Use the real entry point's provider and real Core.Get-ActPlan, not a fabricated plan.
    $plan = & $PlanProvider $configuration.InputRoot $configuration.InputRoot
    return [pscustomobject]@{ Plan = $plan; CertificateInfo = $discovery.Certificates[0]; CopyOriginals = $false }
}
Export-ModuleMember -Function Show-ActSignerWindow
'@
$settingsStub = @'
function Get-ActSignerSettings { [pscustomobject]@{ SourceRoot = ''; SeparateOutputRoot = ''; SaveBesideSources = $false } }
function Save-ActSignerSettings { param($SourceRoot, $SeparateOutputRoot, $SaveBesideSources) return $true }
Export-ModuleMember -Function Get-ActSignerSettings, Save-ActSignerSettings
'@

$cases = @(
    [pscustomobject]@{ Name = 'all-duplicates'; Kinds = @('duplicate', 'duplicate'); Exit = 0; Inspect = 2; NewSession = 0; Sign = 0; VerifyNew = 0; Close = 0; Already = 2; Status = 'already_signed,already_signed'; Events = 'Inspect,Inspect'; SignError = $false },
    [pscustomobject]@{ Name = 'mixed'; Kinds = @('duplicate', 'new', 'new'); Exit = 0; Inspect = 1; NewSession = 1; Sign = 2; VerifyNew = 2; Close = 1; Already = 1; Status = 'already_signed,signed_verified,signed_verified'; Events = 'Inspect,NewSession,Sign,VerifyNew,Sign,VerifyNew,Close'; SignError = $false },
    [pscustomobject]@{ Name = 'precheck-unverifiable'; Kinds = @('unverifiable'); Exit = 1; Inspect = 1; NewSession = 0; Sign = 0; VerifyNew = 0; Close = 0; Already = 0; Status = 'error'; Events = 'Inspect'; SignError = $false },
    [pscustomobject]@{ Name = 'signing-error'; Kinds = @('new'); Exit = 1; Inspect = 0; NewSession = 1; Sign = 1; VerifyNew = 0; Close = 1; Already = 0; Status = 'error'; Events = 'NewSession,Sign,Close'; SignError = $true }
)
try {
    foreach ($case in $cases) {
        $caseRoot = Join-Path $testRoot $case.Name
        $app = Join-Path $caseRoot 'app'
        $inputRoot = Join-Path $caseRoot 'SyntheticActs'
        [void][IO.Directory]::CreateDirectory($app)
        foreach ($name in @('Sign-Acts.ps1', 'ActSigner.Core.psm1', 'ActSigner.Console.psm1')) {
            Copy-Item -LiteralPath (Join-Path $CandidateDirectory $name) -Destination (Join-Path $app $name)
        }
        Write-SyntheticText (Join-Path $app 'ActSigner.CryptoPro.psm1') $cryptoStub
        Write-SyntheticText (Join-Path $app 'ActSigner.UI.psm1') $uiStub
        Write-SyntheticText (Join-Path $app 'ActSigner.Settings.psm1') $settingsStub
        $unchanged = @{}
        for ($i = 0; $i -lt $case.Kinds.Count; $i++) {
            $directory = Join-Path $inputRoot ('{0:D2}-synthetic' -f $i)
            [void][IO.Directory]::CreateDirectory($directory)
            $pdf = Join-Path $directory 'Акт_оказанных_услуг.pdf'
            $pdfBytes = [Text.Encoding]::UTF8.GetBytes(('%PDF-1.4 SYNTHETIC {0} ITEM {1}' -f $case.Name, $i))
            [IO.File]::WriteAllBytes($pdf, $pdfBytes)
            $unchanged[$pdf] = [Convert]::ToBase64String($pdfBytes)
            if ($case.Kinds[$i] -ne 'new') {
                $signature = Join-Path $directory 'signature.sig'
                $signatureText = if ($case.Kinds[$i] -eq 'unverifiable') { 'SYNTHETIC_UNVERIFIABLE' } else { 'SYNTHETIC_VALID_DUPLICATE' }
                $signatureBytes = [Text.Encoding]::UTF8.GetBytes($signatureText)
                [IO.File]::WriteAllBytes($signature, $signatureBytes)
                $unchanged[$signature] = [Convert]::ToBase64String($signatureBytes)
            }
        }
        $configuration = [pscustomobject]@{ InputRoot = $inputRoot; Thumbprint = $thumbprint; SignError = $case.SignError }
        Write-SyntheticText (Join-Path $app 'case.json') ($configuration | ConvertTo-Json)
        $entryPoint = Join-Path $app 'Sign-Acts.ps1'
        if ($entryPoint.Contains('"')) { throw 'Unexpected quote in synthetic test path.' }
        $process = New-Object Diagnostics.Process
        $process.StartInfo.FileName = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
        $process.StartInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -STA -ExecutionPolicy Bypass -File "' + $entryPoint + '"'
        $process.StartInfo.WorkingDirectory = $app
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
        $process.StartInfo.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
        try {
            [void]$process.Start()
            $outputTask = $process.StandardOutput.ReadToEndAsync()
            $errorTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(45000)) {
                $process.Kill()
                $process.WaitForExit()
                throw ('Entry-point child timed out: ' + $case.Name)
            }
            $stdout = $outputTask.GetAwaiter().GetResult()
            $stderr = $errorTask.GetAwaiter().GetResult()
            $exitCode = $process.ExitCode
        }
        finally { $process.Dispose() }
        Write-SyntheticText (Join-Path $ArtifactDirectory ($case.Name + '-stdout.txt')) $stdout.Replace($caseRoot, '<SYNTHETIC_CASE>')
        Write-SyntheticText (Join-Path $ArtifactDirectory ($case.Name + '-stderr.txt')) $stderr.Replace($caseRoot, '<SYNTHETIC_CASE>')
        Assert-Entry ($exitCode -eq $case.Exit) ($case.Name + ': wrong entry-point exit code: ' + $exitCode)
        Assert-Entry ([string]::IsNullOrWhiteSpace($stderr)) ($case.Name + ': unexpected stderr: ' + $stderr)
        $counterFile = Join-Path $app 'counter-report.json'
        if (-not [IO.File]::Exists($counterFile)) {
            $failures.Add($case.Name + ': crypto instrumentation was not loaded; see synthetic stdout/stderr.')
            continue
        }
        $counts = Get-Content -LiteralPath $counterFile -Raw | ConvertFrom-Json
        foreach ($key in @('Inspect', 'NewSession', 'Sign', 'VerifyNew', 'Close')) {
            Assert-Entry ($counts.$key -eq $case.$key) ($case.Name + ': ' + $key + '=' + $counts.$key + '; expected ' + $case.$key)
        }
        $events = [string]::Join(',', [string[]]@($counts.Events))
        Assert-Entry ($events -eq $case.Events) ($case.Name + ': wrong crypto event order: ' + $events)
        $csvFiles = @(Get-ChildItem -LiteralPath (Join-Path $inputRoot '_ActSigner_logs') -Filter '*.csv' -File -ErrorAction SilentlyContinue)
        $statuses = ''
        Assert-Entry ($csvFiles.Count -eq 1) ($case.Name + ': expected one actual Core batch CSV.')
        if ($csvFiles.Count -eq 1) {
            $rows = @(Import-Csv -LiteralPath $csvFiles[0].FullName -Encoding UTF8)
            $statuses = [string]::Join(',', [string[]]@($rows | ForEach-Object { $_.Status }))
            Assert-Entry ($statuses -eq $case.Status) ($case.Name + ': unexpected actual Core CSV statuses: ' + $statuses)
        }
        Assert-Entry ($stdout.Contains(('Уже подписано выбранным сертификатом: {0}' -f $case.Already))) ($case.Name + ': missing AlreadySignedCount summary.')
        if ($case.Name -eq 'all-duplicates') {
            Assert-Entry ($stdout.Contains('Обработка завершена. Новых подписей: 0; пропущено: 2.')) 'All-duplicate summary must report zero new signatures and two skips.'
        }
        foreach ($path in $unchanged.Keys) {
            Assert-Entry ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -eq $unchanged[$path]) ($case.Name + ': original synthetic PDF/neighbor signature changed.')
        }
        $published = @(Get-ChildItem -LiteralPath $inputRoot -Filter '*.my.sig' -Recurse -File)
        Assert-Entry ($published.Count -eq $case.VerifyNew) ($case.Name + ': wrong number of newly published signatures.')
        $reports.Add([pscustomobject]@{ Case = $case.Name; ExitCode = $exitCode; Counts = $counts; CsvStatuses = $statuses; PublishedSignatures = $published.Count })
        Write-Host ('CHECK {0}: exit={1}; sessions={2}; signs={3}; verifies={4}; closes={5}; inspections={6}; events={7}' -f $case.Name, $exitCode, $counts.NewSession, $counts.Sign, $counts.VerifyNew, $counts.Close, $counts.Inspect, $events)
    }
}
catch { $failures.Add($_.Exception.Message) }
finally {
    [pscustomobject]@{ NativeWindows = $true; PowerShellVersion = $PSVersionTable.PSVersion.ToString(); Cases = @($reports.ToArray()); Failures = @($failures.ToArray()) } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ArtifactDirectory 'entry-measurements.json') -Encoding UTF8
    if ([IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
if ($failures.Count -gt 0) { throw ('Entry-point integration checks failed:' + [Environment]::NewLine + ($failures.ToArray() -join [Environment]::NewLine)) }
Write-Host 'PASS: actual entry point skips same-signer duplicates before session creation, lazily reuses one session, and closes it on signing error.'
