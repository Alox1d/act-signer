# Dependency-free tests, using mock bytes rather than real electronic signatures.
param([string]$ModulePath = (Join-Path $PSScriptRoot 'ActSigner.Core.psm1'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module $ModulePath -Force

function Assert-True { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw ('ASSERT: ' + $Message) } }
function Write-Fixture { param([string]$Path, [string]$Text) [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)); [IO.File]::WriteAllBytes($Path, [Text.Encoding]::UTF8.GetBytes($Text)) }
function Get-Status { param($Result) return [string]::Join(',', [string[]]@($Result.Rows | ForEach-Object { $_.Status })) }

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('act-signer-test-' + [guid]::NewGuid().ToString('N'))
$testLink = $null
$thumb = '0123456789ABCDEF0123456789ABCDEF01234567'
try {
    # Test 1: strict file selection, unicode/literal paths, duplicate basenames,
    # output exclusion, and junction/symlink exclusion without following a cycle.
    $root = Join-Path $testRoot 'Тест [папки] (1)'
    $output = Join-Path $root 'Результат'
    $first = Join-Path $root 'Май [1]/Акт_оказанных_услуг.pdf'
    $second = Join-Path $root 'Июнь (2)/Акт выполненных работ (2).pdf'
    Write-Fixture $first '%PDF-1.4 first'
    Write-Fixture $second '%PDF-1.4 second'
    Write-Fixture (Join-Path $root 'Май [1]/Печатная_форма_001.pdf') '%PDF-1.4 print'
    Write-Fixture (Join-Path $root 'Май [1]/signature.sig') 'other-signature'
    Write-Fixture (Join-Path $root 'Май [1]/акт_оказанных_услуг_подписанный.pdf') '%PDF-1.4 excluded'
    Write-Fixture (Join-Path $root 'Другой.pdf') '%PDF-1.4 other'
    Write-Fixture (Join-Path $output 'Архив/Акт_оказанных_услуг.pdf') '%PDF-1.4 output-only'
    $testLink = Join-Path $root 'Не_обходить'
    $linkCreated = $false
    try {
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            [void](New-Item -ItemType Junction -Path $testLink -Target $root -ErrorAction Stop)
        }
        else { [void](New-Item -ItemType SymbolicLink -Path $testLink -Target $root -ErrorAction Stop) }
        $linkCreated = $true
    }
    catch { Write-Host ('SKIP junction fixture: ' + $_.Exception.Message) }
    $plan = Get-ActPlan -Root $root -OutputRoot $output
    Assert-True ($plan.Items.Count -eq 2) 'Only the two original acts should be selected.'
    Assert-True (@($plan.Items | Where-Object { $_.RelativePath -like '*Результат*' }).Count -eq 0) 'Output subtree was included.'
    Assert-True ($plan.Items[0].SignaturePath -ne $plan.Items[1].SignaturePath) 'Nested output paths collided.'
    if ($linkCreated) { Assert-True ($plan.SkippedReparsePoints.Count -eq 1) 'A cycle link was not excluded.' }
    $sourceHash = Get-ActSha256 -Path $first
    Assert-True ((Read-ActPdfBytes -Path $first).Length -eq [IO.File]::ReadAllBytes($first).Length) 'Binary/literal reading failed.'
    Assert-True ((Get-ActSha256 -Path $first) -eq $sourceHash) 'Planning or reading changed the original.'
    Write-Host 'PASS 1: recursive plan, unicode, exact names, output and link exclusion'

    # Test 2: successful verified publication and companion copies, rerun skips,
    # changed source conflict before signing, and signing failure stops the batch.
    $script:mockSignCalls = 0
    $script:mockVerifyCalls = 0
    $sign = {
        param([byte[]]$Pdf)
        $script:mockSignCalls++
        return ,([Text.Encoding]::ASCII.GetBytes('MOCK:' + (Get-ActSha256 -Bytes $Pdf)))
    }
    $verify = {
        param([byte[]]$Pdf, [byte[]]$Signature, [string]$Thumbprint)
        $script:mockVerifyCalls++
        if ([Text.Encoding]::ASCII.GetString($Signature) -ne ('MOCK:' + (Get-ActSha256 -Bytes $Pdf))) { throw 'Mock signature does not match.' }
        if ($Thumbprint -ne '0123456789ABCDEF0123456789ABCDEF01234567') { throw 'Unexpected thumbprint.' }
    }
    $oneRoot = Join-Path $testRoot 'Подписание'
    $oneOutput = Join-Path $testRoot 'Сохранённые копии'
    $oneSource = Join-Path $oneRoot 'Май/Акт_оказанных_услуг.pdf'
    Write-Fixture $oneSource '%PDF-1.4 immutable-original'
    Write-Fixture (Join-Path $oneRoot 'Май/signature.sig') 'WB-signature-bytes'
    Write-Fixture (Join-Path $oneRoot 'Май/signature(1).sig') 'WB-second-signature-bytes'
    Write-Fixture (Join-Path $oneRoot 'Май/Акт_оказанных_услуг.pdf.sig') 'WB-filename-signature'
    Write-Fixture (Join-Path $oneRoot 'Май/Печатная_форма_001.pdf') '%PDF-1.4 print-copy'
    Write-Fixture (Join-Path $oneRoot 'Май/signature-old.my.sig') 'must-not-copy'
    $onePlan = Get-ActPlan -Root $oneRoot -OutputRoot $oneOutput
    $oneItem = $onePlan.Items[0]
    $result = Invoke-ActBatch -Plan $onePlan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -LogRoot (Join-Path $testRoot 'Журналы')
    Assert-True ((Get-Status $result) -eq 'signed_verified') 'First run did not succeed.'
    Assert-True ($script:mockSignCalls -eq 1 -and $script:mockVerifyCalls -eq 1) 'Unexpected callback counts.'
    Assert-True ((Get-ActSha256 -Path $oneSource) -eq (Get-ActSha256 -Path $oneItem.DocumentOutputPath)) 'Copied act differs.'
    Assert-True ([IO.File]::Exists((Join-Path $oneOutput 'Май/signature.sig'))) 'Other party signature not copied.'
    Assert-True ([IO.File]::Exists((Join-Path $oneOutput 'Май/signature(1).sig'))) 'Numbered signature not copied.'
    Assert-True ([IO.File]::Exists((Join-Path $oneOutput 'Май/Акт_оказанных_услуг.pdf.sig'))) 'Filename signature not copied.'
    Assert-True ([IO.File]::Exists((Join-Path $oneOutput 'Май/Печатная_форма_001.pdf'))) 'Printable form not copied.'
    Assert-True (-not [IO.File]::Exists((Join-Path $oneOutput 'Май/signature-old.my.sig'))) 'Own previous signature was copied.'
    $logBytes = [IO.File]::ReadAllBytes($result.LogPath)
    Assert-True ($logBytes[0] -eq 239 -and $logBytes[1] -eq 187 -and $logBytes[2] -eq 191) 'CSV must have UTF-8 BOM.'
    $ownHash = Get-ActSha256 -Path $oneItem.SignaturePath
    $again = Invoke-ActBatch -Plan $onePlan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -LogRoot (Join-Path $testRoot 'Журналы')
    Assert-True ((Get-Status $again) -eq 'exists_unverified') 'Rerun must be an honest unverified skip.'
    Assert-True ($script:mockSignCalls -eq 1 -and $script:mockVerifyCalls -eq 1) 'Rerun called signing or verification.'
    Assert-True ((Get-ActSha256 -Path $oneItem.SignaturePath) -eq $ownHash) 'Rerun changed existing own signature.'
    [IO.File]::Delete($oneItem.SignaturePath)
    $savedHash = Get-ActSha256 -Path $oneItem.DocumentOutputPath
    Write-Fixture $oneSource '%PDF-1.4 changed-original'
    $conflict = Invoke-ActBatch -Plan $onePlan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -LogRoot (Join-Path $testRoot 'Журналы')
    Assert-True ((Get-Status $conflict) -eq 'error') 'A changed original must conflict with its old copy.'
    Assert-True ($script:mockSignCalls -eq 1) 'Conflict must be found before private-key use.'
    Assert-True ((Get-ActSha256 -Path $oneItem.DocumentOutputPath) -eq $savedHash) 'Conflicting existing copy was overwritten.'
    Assert-True (-not [IO.File]::Exists($oneItem.SignaturePath)) 'Conflict left a new own signature.'
    $failureRoot = Join-Path $testRoot 'Ошибка токена'
    $failureOutput = Join-Path $testRoot 'Ошибка результат'
    Write-Fixture (Join-Path $failureRoot '1/Акт_оказанных_услуг.pdf') '%PDF-1.4 one'
    Write-Fixture (Join-Path $failureRoot '2/Акт_оказанных_услуг.pdf') '%PDF-1.4 two'
    $script:failedCalls = 0
    $badSign = { param([byte[]]$Pdf) $script:failedCalls++; throw '=MOCK-PIN-CANCELLED' }
    $failurePlan = Get-ActPlan -Root $failureRoot -OutputRoot $failureOutput
    $failure = Invoke-ActBatch -Plan $failurePlan -Thumbprint $thumb -SignBlock $badSign -VerifyBlock $verify -LogRoot (Join-Path $testRoot 'Журналы')
    Assert-True ((Get-Status $failure) -eq 'error,not_processed') 'Signing failure did not stop the batch.'
    Assert-True ($script:failedCalls -eq 1) 'Batch retried after a PIN/provider failure.'
    Assert-True (@($failurePlan.Items | Where-Object { [IO.File]::Exists($_.SignaturePath) }).Count -eq 0) 'Failed batch published an own signature.'
    Assert-True (@(Get-ChildItem -LiteralPath $failureOutput -Filter '*.tmp' -Recurse -Force).Count -eq 0) 'Temporary file remained after failure.'
    $rejectVerify = { param([byte[]]$Pdf, [byte[]]$Signature, [string]$Thumbprint) throw 'Mock verification rejected the signature.' }
    $verificationFailure = Invoke-ActBatch -Plan $failurePlan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $rejectVerify -LogRoot (Join-Path $testRoot 'Журналы')
    Assert-True ((Get-Status $verificationFailure) -eq 'error,not_processed') 'Verification rejection did not stop the batch.'
    Assert-True (@($failurePlan.Items | Where-Object { [IO.File]::Exists($_.SignaturePath) }).Count -eq 0) 'Unverified signature was published.'
    Assert-True (@(Get-ChildItem -LiteralPath $failureOutput -Filter '*.tmp' -Recurse -Force).Count -eq 0) 'Temporary file remained after verification rejection.'
    $module = Get-Module ActSigner.Core
    $safeCell = & $module { ConvertTo-ActCsvCell '=1+1' }
    Assert-True ($safeCell.StartsWith('"''=')) 'CSV formula-leading content was not escaped.'
    Write-Host 'PASS 2: verified publication, companions, repeat, conflict, stop-on-error, CSV'
}
finally {
    if ($null -ne $testLink -and (Test-Path -LiteralPath $testLink)) {
        [IO.Directory]::Delete($testLink)
    }
    if ([IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
