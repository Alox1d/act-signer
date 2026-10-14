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
    Write-Fixture (Join-Path $oneRoot 'Май/signature.sig') 'other-signature-bytes'
    Write-Fixture (Join-Path $oneRoot 'Май/signature(1).sig') 'second-other-signature-bytes'
    Write-Fixture (Join-Path $oneRoot 'Май/Акт_оказанных_услуг.pdf.sig') 'filename-signature-bytes'
    Write-Fixture (Join-Path $oneRoot 'Май/Печатная_форма_001.pdf') '%PDF-1.4 print-copy'
    Write-Fixture (Join-Path $oneRoot 'Май/signature-old.my.sig') 'must-not-copy'
    $unrelatedInspector = { param([byte[]]$PdfBytes, [byte[]]$SignatureBytes) [pscustomobject]@{ Status = 'different_content'; Thumbprints = @(); Message = 'Synthetic unrelated companion.' } }
    $onePlan = Get-ActPlan -Root $oneRoot -OutputRoot $oneOutput
    $oneItem = $onePlan.Items[0]
    $result = Invoke-ActBatch -Plan $onePlan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $unrelatedInspector -LogRoot (Join-Path $testRoot 'Журналы')
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
    $again = Invoke-ActBatch -Plan $onePlan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $unrelatedInspector -LogRoot (Join-Path $testRoot 'Журналы')
    Assert-True ((Get-Status $again) -eq 'exists_unverified') 'Rerun must be an honest unverified skip.'
    Assert-True ($script:mockSignCalls -eq 1 -and $script:mockVerifyCalls -eq 1) 'Rerun called signing or verification.'
    Assert-True ((Get-ActSha256 -Path $oneItem.SignaturePath) -eq $ownHash) 'Rerun changed existing own signature.'
    [IO.File]::Delete($oneItem.SignaturePath)
    $savedHash = Get-ActSha256 -Path $oneItem.DocumentOutputPath
    Write-Fixture $oneSource '%PDF-1.4 changed-original'
    $conflict = Invoke-ActBatch -Plan $onePlan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $unrelatedInspector -LogRoot (Join-Path $testRoot 'Журналы')
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
    # Test 3: neighbor discovery is advisory and does not inspect crypto at Find.
    $neighborRoot = Join-Path $testRoot 'Neighbor advisory'
    $neighborOutput = Join-Path $testRoot 'Neighbor destination'
    $neighborSource = Join-Path $neighborRoot 'Акт_оказанных_услуг.pdf'
    Write-Fixture $neighborSource '%PDF-1.4 neighbor-content'
    Write-Fixture (Join-Path $neighborRoot 'arbitrary.SIG') 'fixture'
    Write-Fixture (Join-Path $neighborRoot 'second.p7s') 'fixture'
    Write-Fixture (Join-Path $neighborRoot 'third.P7M') 'fixture'
    Write-Fixture (Join-Path $neighborRoot 'fourth.sGn') 'fixture'
    Write-Fixture (Join-Path $neighborRoot 'ignored.sig.bak') 'fixture'
    Write-Fixture (Join-Path $neighborRoot 'child/nested.sig') 'fixture'
    Write-Fixture (Join-Path $neighborOutput 'destination.p7s') 'fixture'
    $neighborPlan = Get-ActPlan -Root $neighborRoot -OutputRoot $neighborOutput
    $hasNeighborCount = $null -ne $neighborPlan.Items[0].PSObject.Properties['NeighborSignatureCount']
    Assert-True $hasNeighborCount 'Plan must expose an advisory neighboring signature count.'
    Assert-True ($neighborPlan.Items[0].NeighborSignatureCount -eq 5) 'Neighbor discovery must include all supported extensions in source+destination without recursion.'
    Write-Host 'PASS 3: advisory signature extensions, destination, no recursion'

    # Crypto is injected because these are synthetic bytes, never real signatures.
    $otherThumb = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    $neighborInspector = {
        param([byte[]]$PdfBytes, [byte[]]$SignatureBytes)
        $text = [Text.Encoding]::ASCII.GetString($SignatureBytes)
        if ($text -eq 'THROW') { throw 'Synthetic inspector unavailable.' }
        if ($text -eq 'UNKNOWN') { return [pscustomobject]@{ Status = 'unverifiable'; Thumbprints = @(); Message = 'Synthetic unsupported signature.' } }
        if ($text -eq 'BADRESULT') { return [pscustomobject]@{ Status = 'valid'; Thumbprints = @('invalid'); Message = 'Malformed.' } }
        $parts = $text.Split('|')
        if ($parts.Count -ne 3 -or $parts[0] -ne 'SYNTHETIC') { return [pscustomobject]@{ Status = 'unverifiable'; Thumbprints = @(); Message = 'Synthetic malformed data.' } }
        if ($parts[1] -ne (Get-ActSha256 -Bytes $PdfBytes)) { return [pscustomobject]@{ Status = 'different_content'; Thumbprints = @(); Message = 'Different synthetic PDF.' } }
        return [pscustomobject]@{ Status = 'valid'; Thumbprints = @($parts[2].Split(',')); Message = 'Synthetic valid signature.' }
    }
    function Write-NeighborFixture {
        param([string]$Path, [string]$PdfPath, [string[]]$Thumbprints)
        Write-Fixture $Path ('SYNTHETIC|' + (Get-ActSha256 -Path $PdfPath) + '|' + ($Thumbprints -join ','))
    }
    function New-NeighborCase {
        param([string]$Name, [switch]$Separate)
        $caseRoot = Join-Path $testRoot ('Neighbor ' + $Name)
        $caseOutput = if ($Separate) { Join-Path $testRoot ('Output ' + $Name) } else { $caseRoot }
        $source = Join-Path $caseRoot 'Акт_оказанных_услуг.pdf'
        Write-Fixture $source ('%PDF-1.4 ' + $Name)
        $plan = Get-ActPlan -Root $caseRoot -OutputRoot $caseOutput
        return [pscustomobject]@{ Root = $caseRoot; Output = $caseOutput; Source = $source; Plan = $plan }
    }
    function Invoke-NeighborCase {
        param($Case, [AllowNull()][scriptblock]$Inspector = $neighborInspector, [scriptblock]$Progress)
        $script:mockSignCalls = 0; $script:mockVerifyCalls = 0
        return (Invoke-ActBatch -Plan $Case.Plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $Inspector -OnProgress $Progress -LogRoot (Join-Path $testRoot 'Neighbor logs'))
    }
    function Assert-NeighborSkip {
        param($Result, $Case, [string]$FileName)
        Assert-True ((Get-Status $Result) -eq 'already_signed') 'Valid same-certificate neighbor must skip new signing.'
        Assert-True ($script:mockSignCalls -eq 0 -and $script:mockVerifyCalls -eq 0) 'Duplicate invoked signing or new-signature verification.'
        Assert-True ($Result.AlreadySignedCount -eq 1 -and $Result.SkippedCount -eq 1 -and $Result.CompletedCount -eq 0) 'Duplicate counts must be honest.'
        Assert-True (-not [IO.File]::Exists($Case.Plan.Items[0].SignaturePath)) 'Duplicate published another own signature.'
        Assert-True ($Result.Rows[0].Message.Contains($FileName)) 'Duplicate message must identify the actual neighbor.'
        Assert-True ($Result.Rows[0].Hash -eq (Get-ActSha256 -Path $Case.Source)) 'Duplicate log must record the checked PDF hash.'
        Assert-True (-not $Result.Stopped) 'Confirmed duplicate must not stop the batch.'
    }
    function Assert-NeighborBlocked {
        param($Result, $Case)
        Assert-True ((Get-Status $Result) -eq 'error') 'Unresolved neighbor must stop with an error.'
        Assert-True ($script:mockSignCalls -eq 0 -and $script:mockVerifyCalls -eq 0) 'Unresolved neighbor invoked private-key or verification callbacks.'
        Assert-True (-not [IO.File]::Exists($Case.Plan.Items[0].SignaturePath)) 'Unresolved neighbor published an own signature.'
        Assert-True (-not $Result.Stopped) 'A document error must not stop independent acts.'
        Assert-True ($Result.Rows[0].Message -like '*Проверка соседних подписей*') 'Error must explain the precheck stage.'
    }
    $case = New-NeighborCase 'arbitrary filename'
    Write-NeighborFixture (Join-Path $case.Root 'unrelated-name.SIG') $case.Source @($thumb.ToLowerInvariant())
    $events = New-Object 'System.Collections.Generic.List[string]'
    $progress = { param($Event) $events.Add([string]$Event.Status) }.GetNewClosure()
    $result = Invoke-NeighborCase $case -Progress $progress
    Assert-NeighborSkip $result $case 'unrelated-name.SIG'
    Assert-True ($events.Contains('checking_existing') -and -not $events.Contains('signing')) 'Existing-signature progress must precede a duplicate skip.'
    Write-Host 'PASS 4: arbitrary filename, normalized certificate, duplicate skip and hash'

    foreach ($mode in @('different PDF', 'other signer')) {
        $case = New-NeighborCase $mode
        if ($mode -eq 'different PDF') {
            $otherPdf = Join-Path $case.Root 'other.pdf'; Write-Fixture $otherPdf '%PDF-1.4 other-content'
            Write-NeighborFixture (Join-Path $case.Root 'other.p7m') $otherPdf @($thumb)
        }
        else { Write-NeighborFixture (Join-Path $case.Root 'other.sgn') $case.Source @($otherThumb) }
        $result = Invoke-NeighborCase $case
        Assert-True ((Get-Status $result) -eq 'signed_verified') 'Known different content or other signer should permit a new signature.'
        Assert-True ($script:mockSignCalls -eq 1 -and $script:mockVerifyCalls -eq 1) 'Permitted signing callback counts changed.'
        Assert-True ($result.AlreadySignedCount -eq 0) 'Unrelated signature counted as a selected-certificate duplicate.'
    }
    $case = New-NeighborCase 'parallel signer list'
    Write-NeighborFixture (Join-Path $case.Root 'parallel.p7s') $case.Source @($otherThumb, $thumb)
    Assert-NeighborSkip (Invoke-NeighborCase $case) $case 'parallel.p7s'
    Write-Host 'PASS 5: different content, other signer, all parallel signer positions'

    foreach ($mode in @('UNKNOWN', 'THROW', 'BADRESULT')) {
        $case = New-NeighborCase $mode
        Write-Fixture (Join-Path $case.Root 'unknown.sig') $mode
        Assert-NeighborBlocked (Invoke-NeighborCase $case) $case
    }
    $case = New-NeighborCase 'no inspector'
    Write-NeighborFixture (Join-Path $case.Root 'existing.sig') $case.Source @($thumb)
    Assert-NeighborBlocked (Invoke-NeighborCase $case -Inspector $null) $case
    $case = New-NeighborCase 'unknown then selected'
    Write-Fixture (Join-Path $case.Root '00-unknown.sig') 'UNKNOWN'
    Write-NeighborFixture (Join-Path $case.Root '99-selected.sig') $case.Source @($thumb)
    Assert-NeighborSkip (Invoke-NeighborCase $case) $case '99-selected.sig'
    Write-Host 'PASS 6: uncertainty blocks, later confirmed duplicate'

    foreach ($mode in @('source', 'destination')) {
        $case = New-NeighborCase ('separate ' + $mode) -Separate
        $directory = if ($mode -eq 'source') { $case.Root } else { $case.Output }
        Write-NeighborFixture (Join-Path $directory 'already.p7s') $case.Source @($thumb)
        Assert-NeighborSkip (Invoke-NeighborCase $case) $case 'already.p7s'
        Assert-True (-not [IO.File]::Exists($case.Plan.Items[0].DocumentOutputPath)) 'Duplicate skip must not claim or create a destination PDF.'
    }
    $case = New-NeighborCase 'late after plan'
    $latePath = Join-Path $case.Root 'late.sig'
    $progress = { param($Event) if ($Event.Status -eq 'checking_existing') { Write-NeighborFixture $latePath $case.Source @($thumb) } }.GetNewClosure()
    Assert-NeighborSkip (Invoke-NeighborCase $case -Progress $progress) $case 'late.sig'
    Write-Host 'PASS 7: source/destination inspection and live discovery after planning'

    $case = New-NeighborCase 'oversize'
    $largePath = Join-Path $case.Root 'oversize.sig'
    $stream = [IO.File]::Open($largePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $stream.SetLength(64MB + 1) } finally { $stream.Dispose() }
    Assert-NeighborBlocked (Invoke-NeighborCase $case) $case
    $case = New-NeighborCase 'zero bytes'
    [IO.File]::WriteAllBytes((Join-Path $case.Root 'empty.sig'), [byte[]]@())
    Assert-NeighborBlocked (Invoke-NeighborCase $case) $case
    $case = New-NeighborCase 'reparse'
    $candidateLink = Join-Path $case.Root 'link.sig'
    $linkTarget = Join-Path $testRoot 'private-outside-fixture.sig'
    Write-NeighborFixture $linkTarget $case.Source @($thumb)
    $fileLinkCreated = $false
    try { [void](New-Item -ItemType SymbolicLink -Path $candidateLink -Target $linkTarget -ErrorAction Stop); $fileLinkCreated = $true } catch { Write-Host 'SKIP signature symlink fixture: OS privileges do not allow creating it.' }
    if ($fileLinkCreated) {
        try { Assert-NeighborBlocked (Invoke-NeighborCase $case) $case }
        finally { [IO.File]::Delete($candidateLink) }
    }
    Write-Host 'PASS 8: size bounds, empty signatures, reparse rejection'

    # A file appearing/being replaced after inspection must stop before private-key use.
    foreach ($mode in @('appeared', 'changed')) {
        $case = New-NeighborCase ('race ' + $mode)
        $existing = Join-Path $case.Root 'existing.sig'
        Write-NeighborFixture $existing $case.Source @($otherThumb)
        $raceInspector = {
            param([byte[]]$PdfBytes, [byte[]]$SignatureBytes)
            if ($mode -eq 'appeared') { Write-Fixture (Join-Path $case.Root 'appeared.sig') 'UNKNOWN' }
            else { Write-Fixture $existing 'UNKNOWN' }
            return [pscustomobject]@{ Status = 'valid'; Thumbprints = @($otherThumb); Message = 'Synthetic other signer.' }
        }.GetNewClosure()
        Assert-NeighborBlocked (Invoke-NeighborCase $case -Inspector $raceInspector) $case
    }
    Write-Host 'PASS 9: neighbor manifest and digest changes stop before signing'

    $case = New-NeighborCase 'locked signature'
    $lockedPath = Join-Path $case.Root 'locked.sig'
    Write-NeighborFixture $lockedPath $case.Source @($thumb)
    $exclusive = [IO.File]::Open($lockedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try { Assert-NeighborBlocked (Invoke-NeighborCase $case) $case }
    finally { $exclusive.Dispose() }
    $case = New-NeighborCase 'precheck stops subsequent acts'
    Write-Fixture (Join-Path $case.Root 'Акт_выполненных_работ.pdf') '%PDF-1.4 next-act'
    Write-Fixture (Join-Path $case.Root 'uncertain.sig') 'UNKNOWN'
    $case.Plan = Get-ActPlan -Root $case.Root -OutputRoot $case.Output
    $result = Invoke-NeighborCase $case
    Assert-True ((Get-Status $result) -eq 'error,error' -and -not $result.Stopped) 'Each act sharing an unresolved neighbor must receive its own error.'
    Assert-True ($script:mockSignCalls -eq 0 -and $script:mockVerifyCalls -eq 0) 'An unresolved batch used signing callbacks.'
    $case = New-NeighborCase 'read error then duplicate'
    Write-Fixture (Join-Path $case.Root '00-unreadable.sig') 'THROW'
    Write-NeighborFixture (Join-Path $case.Root '99-duplicate.sig') $case.Source @($thumb)
    Assert-NeighborSkip (Invoke-NeighborCase $case) $case '99-duplicate.sig'
    Write-Host 'PASS 10: real exclusive read failure, precheck stop, later duplicate after operation error'

    $case = New-NeighborCase 'signature appears during signing'
    $lateSign = {
        param([byte[]]$Pdf)
        Write-Fixture (Join-Path $case.Root 'late-during-sign.sig') 'UNKNOWN'
        $mockBytes = & $sign $Pdf
        return ,([byte[]]$mockBytes)
    }.GetNewClosure()
    $script:mockSignCalls = 0; $script:mockVerifyCalls = 0
    $result = Invoke-ActBatch -Plan $case.Plan -Thumbprint $thumb -SignBlock $lateSign -VerifyBlock $verify -ExistingSignatureInspector $neighborInspector -LogRoot (Join-Path $testRoot 'Neighbor logs')
    Assert-True ((Get-Status $result) -eq 'error' -and -not $result.Stopped) 'Late signing-time neighbor must block publication for that act.'
    Assert-True ($script:mockSignCalls -eq 1 -and $script:mockVerifyCalls -eq 1) 'Signing-time race callback counts changed.'
    Assert-True (-not [IO.File]::Exists($case.Plan.Items[0].SignaturePath)) 'A late neighbor allowed new signature publication.'
    Assert-True ($result.Rows[0].Message -like '*Проверка соседних подписей*') 'Publication race must name the neighboring-signature precheck stage.'
    Write-Host 'PASS 11: late appearance during signing blocks final signature publication'

    $case = New-NeighborCase 'early match short circuit'
    Write-NeighborFixture (Join-Path $case.Root '00-match.sig') $case.Source @($thumb)
    Write-Fixture (Join-Path $case.Root '99-unneeded.sig') 'THROW'
    $inspectionCalls = @{ Count = 0 }
    $shortInspector = {
        param([byte[]]$PdfBytes, [byte[]]$SignatureBytes)
        $inspectionCalls.Count++
        if ([Text.Encoding]::ASCII.GetString($SignatureBytes) -eq 'THROW') { throw 'Do not inspect an irrelevant later candidate.' }
        return (& $neighborInspector $PdfBytes $SignatureBytes)
    }.GetNewClosure()
    Assert-NeighborSkip (Invoke-NeighborCase $case -Inspector $shortInspector) $case '00-match.sig'
    Assert-True ($inspectionCalls.Count -eq 1) 'A confirmed selected-certificate duplicate must stop unnecessary later inspections.'
    Write-Host 'PASS 12: confirmed duplicate stops unnecessary later inspections'

    $case = New-NeighborCase 'signature appears during progress'
    $progress = {
        param($Event)
        if ($Event.Status -eq 'signing') { Write-Fixture (Join-Path $case.Root 'late-during-progress.sig') 'UNKNOWN' }
    }.GetNewClosure()
    Assert-NeighborBlocked (Invoke-NeighborCase $case -Progress $progress) $case
    Write-Host 'PASS 13: pre-sign progress cannot bypass the final neighboring-signature check'

    $case = New-NeighborCase 'foreign expired chain'
    Write-Fixture (Join-Path $case.Root 'signature.sig') 'synthetic-native-cms'
    $foreign = { param($p,$s) [pscustomobject]@{Status='identified'; Signers=@([pscustomobject]@{Thumbprint=$otherThumb;SignatureStatus='valid';HResult='0x00000000'});TrustStatus='not_checked';Message='Trust unchecked'} }.GetNewClosure()
    $result = Invoke-NeighborCase $case -Inspector $foreign
    Assert-True ((Get-Status $result) -eq 'signed_verified') 'Foreign mathematical signature must permit a separate own signature without chain trust.'
    Assert-True ($result.Rows[0].Message -match 'других сертификатов') 'Foreign signature and unchecked trust must remain visible in the journal.'

    foreach($selectedStatus in @('valid','unverifiable')) {
        $case = New-NeighborCase ('native parallel '+$selectedStatus)
        Write-Fixture (Join-Path $case.Root 'parallel.sig') 'synthetic-native-cms'
        $inspector = { param($p,$s) [pscustomobject]@{Status='identified';Signers=@([pscustomobject]@{Thumbprint=$otherThumb;SignatureStatus='unverifiable';HResult='0x80090006'},[pscustomobject]@{Thumbprint=$thumb;SignatureStatus=$selectedStatus;HResult='0x80090006'});TrustStatus='not_checked';Message='Synthetic per-signer results'} }.GetNewClosure()
        $result=Invoke-NeighborCase $case -Inspector $inspector
        if($selectedStatus -eq 'valid'){Assert-NeighborSkip $result $case 'parallel.sig'}
        else {Assert-True ((Get-Status $result) -eq 'error' -and -not $result.Stopped -and $script:mockSignCalls -eq 0) 'An unresolved possible own signature must block only that act without key access.'}
    }
    $case=New-NeighborCase 'independent after unknown'
    $second=Join-Path $case.Root 'next/Акт_оказанных_услуг.pdf';Write-Fixture $second '%PDF-1.4 independent next'
    Write-Fixture (Join-Path $case.Root 'unknown.sig') 'UNKNOWN'
    $case.Plan=Get-ActPlan -Root $case.Root -OutputRoot $case.Output
    $case.Plan.Items=@($case.Plan.Items | Where-Object { $_.SourcePath -eq $case.Source }) + @($case.Plan.Items | Where-Object { $_.SourcePath -eq $second })
    $result=Invoke-NeighborCase $case
    Assert-True ((Get-Status $result) -eq 'error,signed_verified' -and -not $result.Stopped) 'A document precheck error must leave the independent next document processable.'
    Assert-True ($script:mockSignCalls -eq 1 -and $result.ErrorCount -eq 1 -and $result.CompletedCount -eq 1) 'Independent document counts/key calls are incorrect.'
    $cancel = { param($p) $e=[OperationCanceledException]::new('Synthetic token cancellation');$e.Data['ActSignerFailure']='cancelled';throw $e }
    $cancelPlan=Get-ActPlan -Root $failureRoot -OutputRoot $failureOutput
    $result=Invoke-ActBatch -Plan $cancelPlan -Thumbprint $thumb -SignBlock $cancel -VerifyBlock $verify -LogRoot (Join-Path $testRoot 'Cancelled logs')
    Assert-True ($result.Stopped -and $result.StopReason -eq 'cancelled' -and (Get-Status $result) -eq 'cancelled,not_processed') 'User cancellation must stop separately from document errors.'
    $case=New-NeighborCase 'signer filenames'
    foreach($mode in @('signer','document_signer','legacy')) {
        $named=Get-ActPlan -Root $case.Root -OutputRoot $case.Root -SignatureNaming $mode -SignerLabel 'ivanov'
        $expected=if($mode -eq 'signer'){'signature_ivanov.sig'}elseif($mode -eq 'document_signer'){'Акт_оказанных_услуг_ivanov.sig'}else{'Акт_оказанных_услуг.my.sig'}
        Assert-True ([IO.Path]::GetFileName($named.Items[0].SignaturePath) -ceq $expected) 'Naming mode must select the intended no-overwrite target.'
    }
    $unsafeRejected=$false
    try { Get-ActPlan -Root $case.Root -OutputRoot $case.Root -SignatureNaming signer -SignerLabel '../escape' | Out-Null } catch {$unsafeRejected=$true}
    Assert-True $unsafeRejected 'Untrusted signer labels must not escape the act folder.'
    Write-Fixture (Join-Path $case.Root 'Акт_выполненных_работ.pdf') '%PDF-1.4 second act sharing a folder'
    $case.Plan=Get-ActPlan -Root $case.Root -OutputRoot $case.Root -SignatureNaming signer -SignerLabel ivanov
    $result=Invoke-NeighborCase $case
    Assert-True ((Get-Status $result) -ceq 'error,error' -and $script:mockSignCalls -eq 0 -and -not $result.Stopped) 'Two acts sharing a signer target must fail before any private-key call; no overwrite or automatic rename.'
    Write-Host 'PASS 14: native signer policy, foreign trust messages, independent documents and cancellation.'



}
finally {
    if ($null -ne $testLink -and (Test-Path -LiteralPath $testLink)) {
        [IO.Directory]::Delete($testLink)
    }
    if ([IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
