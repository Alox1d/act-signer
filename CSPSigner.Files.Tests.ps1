# Generic file behavior. Only temporary synthetic bytes and injected crypto providers.
# Breaks caught: act-only discovery, extension-stripping collisions, output recursion,
# and explicit-file selection escaping the chosen relative-output root.
param([ValidateSet('discovery','batch','all')][string]$CaseSet = 'all')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'ActSigner.Core.psm1') -Force
function Assert-FileCase { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw ('ASSERT: ' + $Message) } }
function Write-FileCase { param([string]$Path,[byte[]]$Bytes) [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)); [IO.File]::WriteAllBytes($Path,$Bytes) }
function Text-FileCase { param([string]$Path,[string]$Text) Write-FileCase $Path ([Text.Encoding]::UTF8.GetBytes($Text)) }
function Status-FileCase { param($Result) return [string]::Join(',', [string[]]@($Result.Rows | ForEach-Object { $_.Status })) }
$taskRoot = Join-Path ([IO.Path]::GetTempPath()) ('CSPSigner-files-' + [guid]::NewGuid().ToString('N'))
$thumb = '1111111111111111111111111111111111111111'
try {
    if ($CaseSet -in @('discovery','all')) {
        $root = Join-Path $taskRoot 'discovery'
        $output = Join-Path $root 'output'
        Write-FileCase (Join-Path $root 'report.pdf') ([byte[]]@(0,255,128,1))
        Text-FileCase (Join-Path $root 'report.docx') 'synthetic document'
        Text-FileCase (Join-Path $root 'README') 'extensionless'
        Write-FileCase (Join-Path $root 'empty') ([byte[]]@())
        Text-FileCase (Join-Path $root 'nested/data.xml') '<synthetic/>'
        foreach ($excluded in @('old.sig','old.p7s','old.p7m','old.sgn','draft.tmp','_ActSigner_logs/old.csv','_CSPSigner_logs/new.csv','output/generated.txt')) { Text-FileCase (Join-Path $root $excluded) 'excluded' }
        $plan = Get-ActPlan -Root $root -OutputRoot $output -AllFiles -SignatureNaming file_signer -SignerLabel ivanov
        Assert-FileCase ($plan.AllFiles -and $plan.Items.Count -eq 5) 'Generic discovery must include binary, text, extensionless and empty files while excluding outputs, sidecars and logs.'
        $names = @($plan.Items | ForEach-Object { [IO.Path]::GetFileName($_.SignaturePath) })
        Assert-FileCase ($names -contains 'report.pdf_ivanov.sig' -and $names -contains 'report.docx_ivanov.sig') 'Full source extension must disambiguate same-stem targets.'
        $flat = Get-ActPlan -Root $root -OutputRoot $output -AllFiles -Recurse $false -SignatureNaming file_signer -SignerLabel ivanov
        Assert-FileCase ($flat.Items.Count -eq 4) 'Nonrecursive discovery must omit nested sources.'
        $explicit = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @((Join-Path $root 'nested/data.xml'),(Join-Path $root 'nested/data.xml'),(Join-Path $root 'old.sig')) -SignatureNaming file_signer -SignerLabel ivanov
        Assert-FileCase ($explicit.AllFiles -and $explicit.Items.Count -eq 2 -and @($explicit.Items | Where-Object { $_.RelativePath -eq 'nested\data.xml' }).Count -eq 1) 'Explicit selection must preserve relative subfolders, normalize duplicates and allow a signature file as source.'
        $outside = Join-Path $taskRoot 'outside.txt'; Text-FileCase $outside 'outside'
        $rejected = $false
        try { Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($outside) | Out-Null } catch { $rejected = $true }
        Assert-FileCase $rejected 'Explicit sources must not escape the chosen output-relative root.'
        Write-Host 'PASS: generic discovery, distinct filenames and explicit selection.'
    }
    if ($CaseSet -in @('batch','all')) {
        # Only these synthetic RSA keys are used; the user's certificate stores,
        # CryptoPro COM providers and PIN dialogs are never opened.
        Import-Module (Join-Path $PSScriptRoot 'ActSigner.CryptoPro.psm1') -Force
        Add-Type -AssemblyName System.Security
        Add-Type -ReferencedAssemblies System.Security -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
namespace CSPSignerTests {
 public sealed class FileSigner : IDisposable {
  RSACryptoServiceProvider key;
  X509Certificate2 certificate;
  public string Thumbprint { get { return certificate.Thumbprint; } }
  public FileSigner() {
   key = new RSACryptoServiceProvider(2048); key.PersistKeyInCsp = false;
   var request = new CertificateRequest("CN=CSPSigner synthetic file tests",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-2),DateTimeOffset.Now.AddDays(2));
  }
  public byte[] Sign(byte[] content) {
   if (content.Length == 0) {
    // .NET SignedCms refuses empty signing. Construct ordinary detached CMS
    // around a real signature by this same ephemeral RSA test key.
    byte[] serial = certificate.GetSerialNumber(); Array.Reverse(serial);
    if ((serial[0] & 128) != 0) { byte[] positive = new byte[serial.Length + 1]; Array.Copy(serial,0,positive,1,serial.Length); serial = positive; }
    byte[] sha256 = Der(0x30,Der(0x06,new byte[]{0x60,0x86,0x48,1,0x65,3,4,2,1}),Der(0x05));
    byte[] rsa = Der(0x30,Der(0x06,new byte[]{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1}),Der(0x05));
    byte[] signerRecord = Der(0x30,Der(0x02,new byte[]{1}),Der(0x30,certificate.IssuerName.RawData,Der(0x02,serial)),sha256,rsa,Der(0x04,key.SignData(content,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1)));
    byte[] signed = Der(0x30,Der(0x02,new byte[]{1}),Der(0x31,sha256),Der(0x30,Der(0x06,new byte[]{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1})),Der(0xa0,certificate.RawData),Der(0x31,signerRecord));
    return Der(0x30,Der(0x06,new byte[]{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,2}),Der(0xa0,signed));
   }
   var cms = new SignedCms(new ContentInfo(content),true);
   var signer = new CmsSigner(certificate); signer.IncludeOption = X509IncludeOption.EndCertOnly;
   cms.ComputeSignature(signer,true); return cms.Encode();
  }
  static byte[] Der(byte tag, params byte[][] values) {
   var content = new List<byte>(); foreach(var value in values) content.AddRange(value);
   var encoded = new List<byte>(); encoded.Add(tag);
   if(content.Count < 128) encoded.Add((byte)content.Count);
   else { var size = new List<byte>(); int length = content.Count; while(length > 0) { size.Insert(0,(byte)(length & 255)); length >>= 8; } encoded.Add((byte)(128 + size.Count)); encoded.AddRange(size); }
   encoded.AddRange(content); return encoded.ToArray();
  }
  public void Dispose() { certificate.Dispose(); key.Dispose(); }
 }
}
'@
        $own = New-Object CSPSignerTests.FileSigner
        $foreign = New-Object CSPSignerTests.FileSigner
        try {
            $thumb = $own.Thumbprint
            $statistics = @{ Signs = 0 }
            $sign = { param([AllowEmptyCollection()][byte[]]$Bytes) $statistics.Signs++; return ,($own.Sign($Bytes)) }.GetNewClosure()
            $inspect = { param([AllowEmptyCollection()][byte[]]$Bytes,[byte[]]$Signature) Get-ActExistingSignatureInfo -PdfBytes $Bytes -SignatureBytes $Signature }
            $verify = {
                param([AllowEmptyCollection()][byte[]]$Bytes,[byte[]]$Signature,[string]$ExpectedThumb)
                $answer = Get-ActExistingSignatureInfo -PdfBytes $Bytes -SignatureBytes $Signature
                if ($answer.Status -cne 'identified' -or @($answer.Signers | Where-Object { $_.Thumbprint -ceq $ExpectedThumb -and $_.SignatureStatus -ceq 'valid' }).Count -ne 1) { throw 'Synthetic new signature was not verified.' }
            }
            $root = Join-Path $taskRoot 'batch'
            $output = Join-Path $taskRoot 'batch-output'
            $paths = @('report.pdf','report.docx','README','empty') | ForEach-Object { Join-Path $root $_ }
            $snapshots = @([byte[]]@(0,255,128,1),[Text.Encoding]::UTF8.GetBytes('Synthetic text'),[Text.Encoding]::UTF8.GetBytes('No extension'),[byte[]]@())
            for ($i=0;$i -lt $paths.Count;$i++) { Write-FileCase $paths[$i] $snapshots[$i] }
            Text-FileCase (Join-Path $root 'Printable_form.pdf') '%PDF-1.4 unrelated printable document'
            $plan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles $paths -SignatureNaming file_signer -SignerLabel ivanov
            $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
            Assert-FileCase ((Status-FileCase $run) -ceq 'signed_verified,signed_verified,signed_verified,signed_verified') ('Binary/text/extensionless/empty batch must succeed: ' + ($run.Rows.Message -join ' | '))
            Assert-FileCase ($statistics.Signs -eq 4) 'Each fresh source must reach signing exactly once.'
            for ($i=0;$i -lt $paths.Count;$i++) {
                $copy = Join-Path $output ([IO.Path]::GetFileName($paths[$i]))
                Assert-FileCase ([Convert]::ToBase64String([IO.File]::ReadAllBytes($copy)) -ceq [Convert]::ToBase64String($snapshots[$i])) 'Published source copy must retain exact binary bytes.'
                Assert-FileCase ([Convert]::ToBase64String([IO.File]::ReadAllBytes($paths[$i])) -ceq [Convert]::ToBase64String($snapshots[$i])) 'Original source bytes must not change.'
            }
            Assert-FileCase (-not [IO.File]::Exists((Join-Path $output 'Printable_form.pdf'))) 'Generic output must not copy unrelated printable forms.'
            $again = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
            Assert-FileCase ((Status-FileCase $again) -ceq 'already_signed,already_signed,already_signed,already_signed' -and $statistics.Signs -eq 4) 'Rerun must verify each exact source and skip it without using the signing provider.'
            Write-Host 'PASS: arbitrary bytes, multiple documents per directory, exact copies and duplicate rerun.'

            # A valid signature of an unselected sibling is provably unrelated.
            # A corrupted signature or a signature of a changed source is not.
            $root = Join-Path $taskRoot 'sibling'
            $output = Join-Path $taskRoot 'sibling-output'
            $sibling = Join-Path $root 'unselected.bin'; Write-FileCase $sibling ([byte[]]@(10,11,12))
            $selected = Join-Path $root 'selected.xml'; Text-FileCase $selected '<selected/>'
            $siblingSig = Join-Path $root 'arbitrary-name.sig'; Write-FileCase $siblingSig ($foreign.Sign([IO.File]::ReadAllBytes($sibling)))
            $matchedSig = Join-Path $root 'matching.p7s'; Write-FileCase $matchedSig ($foreign.Sign([IO.File]::ReadAllBytes($selected)))
            $plan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($selected) -SignatureNaming file_signer -SignerLabel ivanov
            $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
            Assert-FileCase ((Status-FileCase $run) -ceq 'signed_verified') ('Verified signature of an unselected sibling must not block this source: ' + ($run.Rows.Message -join ' | '))
            Assert-FileCase ([IO.File]::Exists((Join-Path $output 'matching.p7s')) -and -not [IO.File]::Exists((Join-Path $output 'arbitrary-name.sig')) -and -not [IO.File]::Exists((Join-Path $output 'unselected.bin'))) 'Only mathematically matching sidecars and selected sources belong in generic output.'
            Write-Host 'PASS: verified sibling binding and matching sidecar copying.'

            foreach ($broken in @('corrupt','changed')) {
                $root = Join-Path $taskRoot $broken
                $source = Join-Path $root 'source.txt'; Text-FileCase $source 'original source'
                $sig = Join-Path $root 'foreign.sig'
                if ($broken -eq 'corrupt') { Text-FileCase $sig 'not a signature' }
                else { Write-FileCase $sig ($foreign.Sign([IO.File]::ReadAllBytes($source))); Text-FileCase $source 'changed source' }
                $plan = Get-ActPlan -Root $root -OutputRoot $root -AllFiles -SignatureNaming file_signer -SignerLabel ivanov
                $before = $statistics.Signs
                $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
                Assert-FileCase ((Status-FileCase $run) -ceq 'error' -and $statistics.Signs -eq $before -and -not [IO.File]::Exists($plan.Items[0].SignaturePath)) 'Unresolved or changed-content signatures must block private-key use and publication.'
            }
            Write-Host 'PASS: damaged and changed-content signatures remain conservative.'

            $root = Join-Path $taskRoot 'binding-race'
            $sibling = Join-Path $root 'unselected.txt'; Text-FileCase $sibling 'before race'
            $selected = Join-Path $root 'selected.bin'; Write-FileCase $selected ([byte[]]@(31,32,33))
            Write-FileCase (Join-Path $root 'sibling.sig') ($foreign.Sign([IO.File]::ReadAllBytes($sibling)))
            $plan = Get-ActPlan -Root $root -OutputRoot $root -SourceFiles @($selected) -SignatureNaming file_signer -SignerLabel ivanov
            $changeBinding = { param($Event) if ($Event.Status -ceq 'signing') { Text-FileCase $sibling 'changed after binding' } }.GetNewClosure()
            $before = $statistics.Signs
            $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -OnProgress $changeBinding -LogRoot (Join-Path $taskRoot 'logs')
            Assert-FileCase ((Status-FileCase $run) -ceq 'error' -and $statistics.Signs -eq $before -and -not [IO.File]::Exists($plan.Items[0].SignaturePath)) 'A sibling source changed after binding must be caught before signing.'
            Write-Host 'PASS: sibling binding race rechecked before private-key use.'

            # The real synthetic CMS fixture and native inspector also cover an
            # empty source on its own, with no PDF header or format conversion.
            $root = Join-Path $taskRoot 'empty-content'; $source = Join-Path $root 'empty'; Write-FileCase $source ([byte[]]@())
            $plan = Get-ActPlan -Root $root -OutputRoot $root -AllFiles -SignatureNaming file_signer -SignerLabel ivanov
            $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
            Assert-FileCase ((Status-FileCase $run) -ceq 'signed_verified' -and (New-Object IO.FileInfo($source)).Length -eq 0 -and [IO.File]::Exists($plan.Items[0].SignaturePath)) 'Core must pass an empty file through signing and verification without changing the source.'
            Write-Host 'PASS: empty source byte contract without PDF validation.'

            $root = Join-Path $taskRoot 'binding-cancel'
            $sibling = Join-Path $root 'unselected.txt'; Text-FileCase $sibling 'cancel sibling'
            $selected = Join-Path $root 'selected.bin'; Write-FileCase $selected ([byte[]]@(41,42,43))
            $next = Join-Path $root 'next/next.bin'; Write-FileCase $next ([byte[]]@(51,52,53))
            Write-FileCase (Join-Path $root 'sibling.sig') ($foreign.Sign([IO.File]::ReadAllBytes($sibling)))
            $plan = Get-ActPlan -Root $root -OutputRoot $root -SourceFiles @($selected,$next) -SignatureNaming file_signer -SignerLabel ivanov
            # Relative ordering places next/ first; keep the canceled source first
            # to assert that the following independent source is not processed.
            $plan.Items = @($plan.Items | Sort-Object -Property @{Expression={if($_.SourcePath -eq $selected){0}else{1}}})
            foreach ($tagCancellation in @($true,$false)) {
                $cancelInspector = {
                    param([AllowEmptyCollection()][byte[]]$Bytes,[byte[]]$Signature)
                    if ([Text.Encoding]::UTF8.GetString($Bytes) -ceq 'cancel sibling') {
                        $error = New-Object OperationCanceledException('Synthetic read cancellation')
                        if ($tagCancellation) { $error.Data['ActSignerFailure']='cancelled' }
                        throw $error
                    }
                    Get-ActExistingSignatureInfo -PdfBytes $Bytes -SignatureBytes $Signature
                }.GetNewClosure()
                $before = $statistics.Signs
                $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $cancelInspector -LogRoot (Join-Path $taskRoot 'logs')
                Assert-FileCase ($run.Stopped -and $run.StopReason -ceq 'cancelled' -and (Status-FileCase $run) -ceq 'cancelled,not_processed' -and $statistics.Signs -eq $before) ('Cancellation during sibling association must stop the batch, not become an unresolved per-file error. Tagged=' + $tagCancellation)
            }
            Write-Host 'PASS: sibling inspection cancellation keeps batch stop semantics.'

            # Break caught: an exhausted byte budget swallowed as an unreadable
            # sibling would keep scanning files and fail to report finite work.
            $root = Join-Path $taskRoot 'binding-work-limit'
            Write-FileCase (Join-Path $root 'selected') ([byte[]]@(0))
            Write-FileCase (Join-Path $root 'a') ([byte[]]@(1))
            Write-FileCase (Join-Path $root 'b') ([byte[]]@(2))
            $limited = & (Get-Module ActSigner.Core) {
                param($Directory)
                $context = @{ Cache=@{}; Directories=@{}; Calls=0; WorkBytes=([long]512MB - 4); SourceFiles=@() }
                $item = [pscustomobject]@{ SourcePath=(Join-Path $Directory 'selected') }
                $signature = [pscustomobject]@{ Path=(Join-Path $Directory 'unknown.sig'); Bytes=[byte[]]@(1); Hash='synthetic-signature-hash' }
                $unresolved = { param($Bytes,$Signature) [pscustomobject]@{ Status='unverifiable'; Signers=@(); Thumbprints=@(); TrustStatus='not_checked'; Message='Synthetic unresolved signature' } }
                $blocked = $false
                try { Find-ActSiblingSignatureBinding $item $signature $unresolved $context | Out-Null } catch { $blocked=$true }
                [pscustomobject]@{ Blocked=$blocked; Calls=$context.Calls }
            } $root
            Assert-FileCase ($limited.Blocked -and $limited.Calls -eq 1) 'Sibling association must stop and report the exhausted work bound before another inspection.'
            Write-Host 'PASS: sibling association stops at its finite byte-work bound.'

            foreach ($extension in @('sig','p7m')) {
                $root = Join-Path $taskRoot ('source-extension-' + $extension)
                $output = Join-Path $taskRoot ('source-extension-output-' + $extension)
                $source = Join-Path $root ('opaque.' + $extension); Text-FileCase $source 'Opaque source bytes with signature-like extension'
                $firstPlan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($source) -SignatureNaming file_signer -SignerLabel one
                $before = $statistics.Signs
                $first = Invoke-ActBatch -Plan $firstPlan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
                $secondPlan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($source) -SignatureNaming file_signer -SignerLabel two
                $secondSign = { param([AllowEmptyCollection()][byte[]]$Bytes) $statistics.Signs++; return ,($foreign.Sign($Bytes)) }.GetNewClosure()
                $second = Invoke-ActBatch -Plan $secondPlan -Thumbprint $foreign.Thumbprint -SignBlock $secondSign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
                Assert-FileCase ((Status-FileCase $first) -ceq 'signed_verified' -and (Status-FileCase $second) -ceq 'signed_verified' -and $statistics.Signs -eq ($before + 2)) ('Explicit signature-extension source and its exact copy must not be mistaken for neighboring CMS: ' + ($second.Rows.Message -join ' | '))
                Assert-FileCase ([IO.File]::Exists($firstPlan.Items[0].SignaturePath) -and [IO.File]::Exists($secondPlan.Items[0].SignaturePath) -and [IO.File]::ReadAllText($secondPlan.Items[0].DocumentOutputPath) -ceq 'Opaque source bytes with signature-like extension') 'Both certificates must sign the exact unchanged opaque source without overwriting the first signature.'
            }
            Write-Host 'PASS: explicit signature-extension sources and their output copies remain documents.'

            foreach ($extension in @('sig','p7m')) {
                foreach ($separate in @($false,$true)) {
                    $root = Join-Path $taskRoot ('mixed-source-' + $extension + '-' + $separate)
                    $output = if ($separate) { Join-Path $taskRoot ('mixed-output-' + $extension) } else { $root }
                    $opaqueText = if ($extension -eq 'p7m' -and -not $separate) { '' } else { 'Explicit opaque source document' }
                    $opaque = Join-Path $root ('a-opaque.' + $extension); Text-FileCase $opaque $opaqueText
                    $document = Join-Path $root 'b-document.docx'; Text-FileCase $document 'Ordinary selected document'
                    $plan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($opaque,$document) -SignatureNaming file_signer -SignerLabel one
                    $before = $statistics.Signs
                    $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
                    Assert-FileCase ((Status-FileCase $run) -ceq 'signed_verified,signed_verified' -and $statistics.Signs -eq ($before + 2)) ('Explicit opaque sources must remain documents across selected items: ' + $extension + ', separate=' + $separate + ', ' + ($run.Rows.Message -join ' | '))
                    Assert-FileCase ([IO.File]::ReadAllText((Join-Path $output ([IO.Path]::GetFileName($opaque)))) -ceq $opaqueText -and [IO.File]::ReadAllText((Join-Path $output 'b-document.docx')) -ceq 'Ordinary selected document') 'Mixed input documents must remain unchanged in the chosen output.'
                    Text-FileCase (Join-Path $root 'unselected-corrupt.sig') 'Unselected malformed neighboring signature'
                    $blockedPlan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($opaque,$document) -SignatureNaming file_signer -SignerLabel two
                    $before = $statistics.Signs
                    $blocked = Invoke-ActBatch -Plan $blockedPlan -Thumbprint $foreign.Thumbprint -SignBlock $secondSign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
                    Assert-FileCase ((Status-FileCase $blocked) -ceq 'error,error' -and $statistics.Signs -eq $before) 'A non-source corrupt sidecar must still block a new certificate for every affected source.'
                }
            }
            Write-Host 'PASS: mixed explicit signature-extension documents do not block other files; unselected corrupt sidecars still do.'

            foreach ($separate in @($false,$true)) {
                $root = Join-Path $taskRoot ('selected-real-cms-' + $separate)
                $output = if ($separate) { Join-Path $taskRoot 'selected-real-cms-output' } else { $root }
                $document = Join-Path $root 'a-document.txt'; Text-FileCase $document 'Source already signed by own certificate'
                $cmsSource = Join-Path $root 'b-real-source.sig'; Write-FileCase $cmsSource ($own.Sign([IO.File]::ReadAllBytes($document)))
                $plan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($document,$cmsSource) -SignatureNaming file_signer -SignerLabel one
                $before = $statistics.Signs
                $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
                Assert-FileCase ((Status-FileCase $run) -ceq 'already_signed,signed_verified' -and $statistics.Signs -eq ($before + 1)) 'Explicitly selected real CMS must still suppress duplicate signing of the source it actually authenticates.'
                Assert-FileCase (-not [IO.File]::Exists($plan.Items[0].SignaturePath) -and [IO.File]::Exists($plan.Items[1].SignaturePath)) 'A valid selected CMS document must remain usable evidence while being separately signed as input bytes.'
            }
            Write-Host 'PASS: selected real own CMS retains duplicate suppression.'

            $root = Join-Path $taskRoot 'declared-foreign-cms'
            $output = Join-Path $taskRoot 'declared-foreign-cms-output'
            $document = Join-Path $root 'a-document.txt'; Text-FileCase $document 'Source with a declared foreign CMS input'
            $cmsSource = Join-Path $root 'b-real-source.sig'; Write-FileCase $cmsSource ($foreign.Sign([IO.File]::ReadAllBytes($document)))
            $plan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($document,$cmsSource) -SignatureNaming file_signer -SignerLabel one
            $plan.Items = @($plan.Items | Where-Object { $_.SourcePath -eq $document })
            $before = $statistics.Signs
            $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
            Assert-FileCase ((Status-FileCase $run) -ceq 'signed_verified' -and $statistics.Signs -eq ($before + 1) -and [IO.File]::Exists((Join-Path $output 'b-real-source.sig'))) 'A declared foreign CMS remains verified matching evidence and is copied even when not independently selected for signing.'
            Write-Host 'PASS: declared foreign CMS retains matching-sidecar behavior.'

            $root = Join-Path $taskRoot 'stale-declared-copy'
            $output = Join-Path $taskRoot 'stale-declared-copy-output'
            $opaque = Join-Path $root 'a-opaque.p7m'; Text-FileCase $opaque 'Actual declared document'
            $document = Join-Path $root 'b-document.txt'; Text-FileCase $document 'Another selected document'
            Text-FileCase (Join-Path $output 'a-opaque.p7m') 'Different malformed sidecar occupying the expected copy path'
            $plan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($opaque,$document) -SignatureNaming file_signer -SignerLabel one
            $plan.Items = @($plan.Items | Where-Object { $_.SourcePath -eq $document })
            $before = $statistics.Signs
            $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
            Assert-FileCase ((Status-FileCase $run) -ceq 'error' -and $statistics.Signs -eq $before -and -not [IO.File]::Exists($plan.Items[0].SignaturePath)) 'An output filename is not a declared-source copy unless its bytes match the actual explicit source.'
            Write-Host 'PASS: stale output documents do not gain an inferred source-copy exemption.'

            $root = Join-Path $taskRoot 'declared-inspection-failures'
            $document = Join-Path $root 'a-document.txt'; Text-FileCase $document 'Actual own signed input'
            $cmsSource = Join-Path $root 'b-selected.sig'; Write-FileCase $cmsSource ($own.Sign([IO.File]::ReadAllBytes($document)))
            foreach ($failureMode in @('budget','protocol','identified-empty','identified-missing','identified-bad-thumb','identified-bad-status','valid-empty','valid-missing','valid-bad-thumb')) {
                $guard = & (Get-Module ActSigner.Core) {
                    param($Directory,$SelectedThumb,$Mode,$NativeInspector)
                    $source = Join-Path $Directory 'a-document.txt'
                    $selectedCms = Join-Path $Directory 'b-selected.sig'
                    $documents = @{}; $documents[$source]=$source; $documents[$selectedCms]=$selectedCms
                    $calls = if($Mode -eq 'budget'){4096}else{0}
                    $context = @{Cache=@{};Directories=@{};Calls=$calls;WorkBytes=[long]0;SourceFiles=@($source,$selectedCms);SourceDocuments=$documents}
                    $state = Open-ActReadState $source
                    $item = [pscustomobject]@{SourcePath=$source;DocumentOutputPath=$source;RelativePath='a-document.txt'}
                    $reader = $NativeInspector
                    if($Mode -ne 'budget') {
                        $reader = {
                            param($Bytes,$Signature)
                            switch ($Mode) {
                                'protocol' { [pscustomobject]@{Status='invalid_provider_status'} }
                                'identified-empty' { [pscustomobject]@{Status='identified';Signers=@();Thumbprints=@()} }
                                'identified-missing' { [pscustomobject]@{Status='identified'} }
                                'identified-bad-thumb' { [pscustomobject]@{Status='identified';Signers=@([pscustomobject]@{Thumbprint='invalid';SignatureStatus='unverifiable'})} }
                                'identified-bad-status' { [pscustomobject]@{Status='identified';Signers=@([pscustomobject]@{Thumbprint=('1'*40);SignatureStatus='invalid'})} }
                                'valid-empty' { [pscustomobject]@{Status='valid';Thumbprints=@()} }
                                'valid-missing' { [pscustomobject]@{Status='valid'} }
                                'valid-bad-thumb' { [pscustomobject]@{Status='valid';Thumbprints=@('invalid')} }
                            }
                        }.GetNewClosure()
                    }
                    $allowed = $false
                    try { Get-ActNeighborSignatureCheck $item $state $SelectedThumb $reader $null 1 1 $context | Out-Null; $allowed=$true }
                    catch { }
                    finally { $state.Stream.Dispose() }
                    [pscustomobject]@{Allowed=$allowed;Calls=$context.Calls}
                } $root $thumb $failureMode $inspect
                Assert-FileCase (-not $guard.Allowed) ('An explicitly chosen actual own CMS cannot bypass a failed inspection: ' + $failureMode)
            }
            Write-Host 'PASS: declared input roles do not bypass inspection budgets or malformed provider answers.'

            $root = Join-Path $taskRoot 'overlap-root'
            $outer = Join-Path $root 'a-source.sig'; Text-FileCase $outer 'Explicit outer input document'
            $inner = Join-Path $root 'overlap-root/a-source.sig'; Text-FileCase $inner 'Different nested input document'
            $document = Join-Path $root 'b-document.txt'; Text-FileCase $document 'Independent input near the outer opaque source'
            # With output as an ancestor, the inferred copy of inner equals the
            # actual outer input path. Actual explicit roles take precedence.
            $plan = Get-ActPlan -Root $root -OutputRoot $taskRoot -SourceFiles @($outer,$inner,$document) -SignatureNaming file_signer -SignerLabel one
            $plan.Items = @($plan.Items | Where-Object { $_.SourcePath -eq $document })
            $before = $statistics.Signs
            $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
            Assert-FileCase ((Status-FileCase $run) -ceq 'signed_verified' -and $statistics.Signs -eq ($before + 1) -and [IO.File]::ReadAllText($outer) -ceq 'Explicit outer input document') 'An inferred output-copy role must not overwrite another explicitly declared source role.'
            Write-Host 'PASS: explicit source roles take priority over overlapping inferred output-copy roles.'

            foreach ($signerRole in @('own','foreign')) {
                $root = Join-Path $taskRoot ('math-before-role-' + $signerRole)
                $output = Join-Path $taskRoot ('math-before-role-output-' + $signerRole)
                $document = Join-Path $root 'a-document.txt'; Text-FileCase $document 'Document authenticated by the surviving output CMS'
                $cmsSource = Join-Path $root 'b-selected.sig'
                $cmsBytes = if ($signerRole -eq 'own') { $own.Sign([IO.File]::ReadAllBytes($document)) } else { $foreign.Sign([IO.File]::ReadAllBytes($document)) }
                Write-FileCase $cmsSource $cmsBytes
                Write-FileCase (Join-Path $output 'b-selected.sig') $cmsBytes
                $plan = Get-ActPlan -Root $root -OutputRoot $output -SourceFiles @($document,$cmsSource) -SignatureNaming file_signer -SignerLabel one
                $plan.Items = @($plan.Items | Where-Object { $_.SourcePath -eq $document })
                [IO.File]::Delete($cmsSource)
                $before = $statistics.Signs
                $run = Invoke-ActBatch -Plan $plan -Thumbprint $thumb -SignBlock $sign -VerifyBlock $verify -ExistingSignatureInspector $inspect -LogRoot (Join-Path $taskRoot 'logs')
                $expectedStatus = if ($signerRole -eq 'own') { 'already_signed' } else { 'signed_verified' }
                $expectedCalls = if ($signerRole -eq 'own') { $before } else { $before + 1 }
                Assert-FileCase ((Status-FileCase $run) -ceq $expectedStatus -and $statistics.Signs -eq $expectedCalls) ('Independent mathematical evidence must precede an unavailable unchecked source-role proof: ' + $signerRole + ', ' + ($run.Rows.Message -join ' | '))
            }
            Write-Host 'PASS: surviving own/foreign CMS evidence precedes unavailable document-role originals.'
        }
        finally { $own.Dispose(); $foreign.Dispose() }
    }
}
finally {
    if ([IO.Directory]::Exists($taskRoot)) { Remove-Item -LiteralPath $taskRoot -Recurse -Force }
}
