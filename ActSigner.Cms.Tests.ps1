#requires -Version 5.1
# Native Windows CryptoAPI tests. All documents, keys and certificates are synthetic.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'ActSigner.CryptoPro.psm1') -Force
Add-Type -AssemblyName System.Security
Add-Type -ReferencedAssemblies System.Security -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
namespace ActSignerTests {
 public sealed class CmsFixture {
  public byte[] Pdf, Signature;
  public string[] Thumbprints;
  public static byte[] Certificate(string subject) {
   using(var key=new RSACryptoServiceProvider(2048)) {
    key.PersistKeyInCsp=false;
    var request=new CertificateRequest(subject,key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
    using(var cert=request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1),DateTimeOffset.Now.AddDays(1))) return cert.RawData;
   }
  }
  public static CmsFixture Make(int count, bool expired, bool missing, bool extra, bool ambiguous, bool attached) {
   return Make(count,expired,missing,extra,ambiguous,attached,false);
  }
  public static CmsFixture Make(int count, bool expired, bool missing, bool extra, bool ambiguous, bool attached, bool ski) {
   var keys = new List<RSACryptoServiceProvider>(); var certs = new List<X509Certificate2>();
   try {
    byte[] pdf = System.Text.Encoding.ASCII.GetBytes("%PDF-1.4 synthetic ActSigner native CMS test");
    var cms = new SignedCms(new ContentInfo(pdf), !attached);var thumbs = new List<string>();
    for(int i=0;i<count;i++) {
     var rsa = new RSACryptoServiceProvider(2048);rsa.PersistKeyInCsp=false;keys.Add(rsa);
     var request = new CertificateRequest("CN=ActSigner synthetic " + i, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
     request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey,false));
     var certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddYears(-3), expired ? DateTimeOffset.Now.AddYears(-2) : DateTimeOffset.Now.AddDays(2));
     certs.Add(certificate);thumbs.Add(certificate.Thumbprint);
     var signer = new CmsSigner(ski ? SubjectIdentifierType.SubjectKeyIdentifier : SubjectIdentifierType.IssuerAndSerialNumber, certificate);signer.IncludeOption=missing?X509IncludeOption.None:X509IncludeOption.EndCertOnly;
     if(extra || ambiguous) {
      var otherKey=new RSACryptoServiceProvider(2048);otherKey.PersistKeyInCsp=false;keys.Add(otherKey);
      var otherRequest=new CertificateRequest("CN=ActSigner nonsigner",otherKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
      X509Certificate2 other;
      if(ambiguous) {
       byte[] serial=certificate.GetSerialNumber();Array.Reverse(serial);
       other=otherRequest.Create(certificate.IssuerName,X509SignatureGenerator.CreateForRSA(otherKey,RSASignaturePadding.Pkcs1),DateTimeOffset.Now.AddDays(-2),DateTimeOffset.Now.AddDays(2),serial);
      } else other=otherRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-2),DateTimeOffset.Now.AddDays(2));
      certs.Add(other);signer.Certificates.Add(other);
     }
     cms.ComputeSignature(signer,true);
    }
    return new CmsFixture {Pdf=pdf,Signature=cms.Encode(),Thumbprints=thumbs.ToArray()};
   } finally {foreach(var c in certs)c.Dispose();foreach(var k in keys)k.Dispose();}
  }
 }
}
'@
function Assert-Cms { param([bool]$Condition,[string]$Message) if(-not $Condition){throw ('ASSERT: '+$Message)} }

# Removing the native path or restoring full certificate-chain validation must fail here.
foreach($expired in @($false,$true)) {
    $fixture=[ActSignerTests.CmsFixture]::Make(1,$expired,$false,$false,$false,$false)
    $info=Get-ActExistingSignatureInfo $fixture.Pdf $fixture.Signature
    Assert-Cms ($info.Status -ceq 'identified') 'An untrusted or expired signer must retain separately verified identity.'
    Assert-Cms ($info.Signers.Count -eq 1 -and $info.Signers[0].Thumbprint -ceq $fixture.Thumbprints[0]) 'Real signer certificate was not resolved.'
    Assert-Cms ($info.Signers[0].SignatureStatus -ceq 'valid') 'Exact bytes must be mathematically verified despite certificate trust/expiry.'
    Assert-Cms ($info.TrustStatus -ceq 'not_checked') 'Mathematical success must not imply certificate trust or revocation validation.'
    $changed=[byte[]]$fixture.Pdf.Clone();$changed[10]=$changed[10] -bxor 1
    $bad=Get-ActExistingSignatureInfo $changed $fixture.Signature
    Assert-Cms ($bad.Status -ceq 'identified' -and $bad.Signers[0].SignatureStatus -ceq 'unverifiable') 'Changed PDF must not count as a confirmed signature or proven unrelated content.'
}
Write-Host 'PASS: native exact-byte verification independent of expired/untrusted certificate chains; changed PDF rejected.'

$fixture=[ActSignerTests.CmsFixture]::Make(2,$true,$false,$true,$false,$false)
$info=Get-ActExistingSignatureInfo $fixture.Pdf $fixture.Signature
Assert-Cms ($info.Status -ceq 'identified' -and $info.Signers.Count -eq 2) 'All parallel SignerInfo entries must be inspected, excluding extra bag certificates.'
foreach($thumb in $fixture.Thumbprints){Assert-Cms (@($info.Signers | Where-Object {$_.Thumbprint -ceq $thumb -and $_.SignatureStatus -ceq 'valid'}).Count -eq 1) 'Every signer index must verify with its exact certificate.'}
Write-Host 'PASS: multiple signers and nonsigner certificates.'

foreach($kind in @('missing','ambiguous','attached')) {
    $fixture=[ActSignerTests.CmsFixture]::Make(1,$false,($kind -eq 'missing'),$false,($kind -eq 'ambiguous'),($kind -eq 'attached'))
    $info=Get-ActExistingSignatureInfo $fixture.Pdf $fixture.Signature
    Assert-Cms ($info.Status -ceq 'unverifiable' -and $info.Signers.Count -eq 0) ('Unsafe CMS must not expose a complete signer list: '+$kind)
}
$fixture=[ActSignerTests.CmsFixture]::Make(1,$false,$false,$false,$false,$false)
$damaged=[byte[]]$fixture.Signature.Clone();$damaged[$damaged.Length-1]=$damaged[$damaged.Length-1] -bxor 1
$info=Get-ActExistingSignatureInfo $fixture.Pdf $damaged
Assert-Cms ($info.Status -ceq 'identified' -and $info.Signers[0].SignatureStatus -ceq 'unverifiable') 'Damaged signature value must never authenticate a signer.'
$truncated=[byte[]]$fixture.Signature[0..20]
$info=Get-ActExistingSignatureInfo $fixture.Pdf $truncated
Assert-Cms ($info.Status -ceq 'unverifiable' -and $info.Signers.Count -eq 0) 'Truncated CMS must remain unidentified.'
Write-Host 'PASS: missing/ambiguous certificates, attached content, damaged signature and truncated CMS rejected.'

$trailing=[byte[]]($fixture.Signature+[byte[]]@(0,0,0))
$info=Get-ActExistingSignatureInfo $fixture.Pdf $trailing
Assert-Cms ($info.Status -ceq 'unverifiable' -and $info.Signers.Count -eq 0) 'Trailing bytes must not hide an additional or damaged CMS container.'
Write-Host 'PASS: complete CMS envelope required.'

$fixture=[ActSignerTests.CmsFixture]::Make(1,$true,$false,$true,$false,$false,$true)
$info=Get-ActExistingSignatureInfo $fixture.Pdf $fixture.Signature
Assert-Cms ($info.Status -ceq 'identified' -and $info.Signers.Count -eq 1 -and $info.Signers[0].Thumbprint -ceq $fixture.Thumbprints[0] -and $info.Signers[0].SignatureStatus -ceq 'valid') 'SubjectKeyIdentifier SignerInfo must resolve the actual certificate, excluding unrelated certificates.'
Write-Host 'PASS: subject key identifier signer association.'
$fixture=[ActSignerTests.CmsFixture]::Make(9,$false,$false,$false,$false,$false)
$info=Get-ActExistingSignatureInfo (New-Object byte[] (64MB)) $fixture.Signature
Assert-Cms ($info.Status -ceq 'unverifiable' -and $info.Signers.Count -eq 0) 'Excessive multi-signer hash work must be rejected before verification.'
Write-Host 'PASS: bounded multi-signer hash work.'

$raw=[ActSignerTests.CmsFixture]::Certificate('CN=Synthetic different name, SN=Иванов')
Assert-Cms ([ActSigner.NativeCmsInspector]::FileLabel($raw) -ceq 'ivanov') 'Filename surname must come from the surname attribute, with safe transliteration.'
$raw=[ActSignerTests.CmsFixture]::Certificate('CN=Synthetic company only')
$cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
try { Assert-Cms ([ActSigner.NativeCmsInspector]::FileLabel($raw) -ceq ('cert_'+$cert.Thumbprint.Substring(0,12).ToLowerInvariant())) 'Missing surname must use a certificate identifier, not guess an organization name.' } finally {$cert.Dispose()}
Write-Host 'PASS: certificate surname filenames and explicit missing-surname fallback.'
