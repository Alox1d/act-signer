#requires -Version 5.1
# Read-only preview association tests with synthetic, expired RSA certificates.
param([switch]$FixtureOnly)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'ActSigner.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'ActSigner.CryptoPro.psm1') -Force -DisableNameChecking
Add-Type -AssemblyName System.Security
Add-Type -ReferencedAssemblies System.Security -TypeDefinition @'
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
public static class PreviewCmsFixture {
 public static byte[] Sign(byte[] bytes, bool detached, bool includeCertificate) {
  using(var key=new RSACryptoServiceProvider(2048)) {
   key.PersistKeyInCsp=false;
   var request=new CertificateRequest("CN=Synthetic preview signer",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   using(var certificate=request.CreateSelfSigned(DateTimeOffset.Now.AddYears(-3),DateTimeOffset.Now.AddYears(-2))) {
    var cms=new SignedCms(new ContentInfo(bytes),detached);
    var signer=new CmsSigner(certificate);
    signer.IncludeOption=includeCertificate?X509IncludeOption.EndCertOnly:X509IncludeOption.None;
    cms.ComputeSignature(signer);
    return cms.Encode();
   }
  }
 }
}
'@
if($FixtureOnly){return}
function Assert-Preview([bool]$Condition,[string]$Message){if(-not $Condition){throw ('ASSERT: '+$Message)}}
$root=Join-Path ([IO.Path]::GetTempPath()) ('cspsigner-preview-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try {
 $document=Join-Path $root 'document.pdf';$print=Join-Path $root 'print.pdf';$signature=Join-Path $root 'arbitrary-sidecar.sig'
 [byte[]]$bytes=[Text.Encoding]::UTF8.GetBytes('%PDF-1.4 synthetic document')
 [IO.File]::WriteAllBytes($document,$bytes)
 [IO.File]::WriteAllText($print,'%PDF-1.4 a different printed representation')
 [byte[]]$cms=[PreviewCmsFixture]::Sign($bytes,$true,$true)
 [IO.File]::WriteAllBytes($signature,$cms)
 $beforeDocument=Get-ActSha256 -Path $document;$beforeSignature=Get-ActSha256 -Path $signature
 $plan=Get-ActPlan -Root $root -OutputRoot $root -AllFiles -SignatureNaming signer -SignerLabel synthetic
 $inspector={param([byte[]]$SourceBytes,[byte[]]$SignatureBytes) Get-ActExistingSignatureInfo -PdfBytes $SourceBytes -SignatureBytes $SignatureBytes}
 $presence=@(Get-ActSignaturePresence -Items $plan.Items -Inspector $inspector)
 $matched=@($presence | Where-Object {$_.SourcePath -eq $document})[0]
 $unmatched=@($presence | Where-Object {$_.SourcePath -eq $print})[0]
 Assert-Preview ($matched.Status -ceq 'matched' -and $matched.MatchingSignatureCount -eq 1) 'An expired foreign signature must confirm the exact source bytes without trust validation.'
 Assert-Preview ($unmatched.Status -ceq 'unconfirmed' -and $unmatched.MatchingSignatureCount -eq 0 -and $unmatched.CandidateCount -eq 1) 'A neighboring signature must not select a different printed file.'
 Assert-Preview ((Get-ActSha256 -Path $document) -ceq $beforeDocument -and (Get-ActSha256 -Path $signature) -ceq $beforeSignature) 'Preview must leave source and signature bytes unchanged.'
 [IO.File]::WriteAllText($document,'changed bytes')
 $changed=@(Get-ActSignaturePresence -Items @($plan.Items | Where-Object {$_.SourcePath -eq $document}) -Inspector $inspector)
 Assert-Preview ($changed[0].Status -ceq 'unconfirmed' -and $changed[0].MatchingSignatureCount -eq 0) 'A previous match must not survive changed source bytes.'
 [IO.File]::WriteAllBytes($document,$bytes)
 foreach($bad in @([byte[]]@(1,2,3),[PreviewCmsFixture]::Sign($bytes,$false,$true),[PreviewCmsFixture]::Sign($bytes,$true,$false))){
  [IO.File]::WriteAllBytes($signature,$bad)
  $answer=@(Get-ActSignaturePresence -Items @($plan.Items | Where-Object {$_.SourcePath -eq $document}) -Inspector $inspector)
  Assert-Preview ($answer[0].Status -ceq 'unconfirmed') 'Corrupt, attached and missing-certificate candidates must remain unconfirmed.'
 }
 [IO.File]::WriteAllBytes($signature,$cms)
 $unsupported={param($SourceBytes,$SignatureBytes) [pscustomobject]@{Status='identified';Signers=@([pscustomobject]@{Thumbprint=('A'*40);SignatureStatus='unverifiable';HResult='0x80090008'});Message='Synthetic unsupported algorithm'}}
 $answer=@(Get-ActSignaturePresence -Items $plan.Items -Inspector $unsupported)
 Assert-Preview (@($answer | Where-Object {$_.Status -ceq 'unconfirmed'}).Count -eq 2) 'Unsupported verification must not be called unsigned or matched.'
 Assert-Preview ($answer[0].Message -like '*0x80090008*' -and $answer[0].Message -like '*Synthetic unsupported algorithm*') 'Preview must retain verification diagnostics for an unconfirmed source.'
 $empty=Join-Path $root 'unsigned';[void][IO.Directory]::CreateDirectory($empty)
 [IO.File]::WriteAllText((Join-Path $empty 'new.txt'),'unsigned')
 $unsigned=Get-ActPlan -Root $empty -OutputRoot $empty -AllFiles -SignatureNaming file_signer -SignerLabel synthetic
 $answer=@(Get-ActSignaturePresence -Items $unsigned.Items -Inspector $inspector)
 Assert-Preview ($answer[0].Status -ceq 'none' -and $answer[0].CandidateCount -eq 0) 'No candidates must remain distinct from failed verification.'
 [IO.File]::WriteAllBytes($print,$bytes)
 $answer=@(Get-ActSignaturePresence -Items $plan.Items -Inspector $inspector)
 Assert-Preview (@($answer | Where-Object {$_.Status -ceq 'matched'}).Count -eq 2) 'Byte-identical sources both match; paths and filenames are not cryptographic identity.'
 Write-Host 'PASS: exact-byte preview binding, expired foreign signer, changed sources, corrupt/attached/missing-certificate/unsupported CMS and read-only snapshots.'
}finally{
 $full=[IO.Path]::GetFullPath($root)
 if(-not $full.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup target'}
 Remove-Item -LiteralPath $full -Recurse -Force
}
