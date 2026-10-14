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
  private static byte[] Der(byte tag, params byte[][] values) {
   var content=new List<byte>();foreach(var value in values)content.AddRange(value);
   var encoded=new List<byte>();encoded.Add(tag);
   if(content.Count<128)encoded.Add((byte)content.Count);
   else { var size=new List<byte>();int length=content.Count;while(length>0){size.Insert(0,(byte)(length&255));length>>=8;}encoded.Add((byte)(128+size.Count));encoded.AddRange(size); }
   encoded.AddRange(content);return encoded.ToArray();
  }
  public static CmsFixture MakeEmpty(bool expired) {
   return MakeEmpty(expired,false,false);
  }
  private static byte[] Ber(byte tag, params byte[][] values) {
   var encoded=new List<byte>();encoded.Add(tag);encoded.Add(0x80);
   foreach(var value in values)encoded.AddRange(value);
   encoded.Add(0);encoded.Add(0);return encoded.ToArray();
  }
  public static CmsFixture MakeEmpty(bool expired, bool attached, bool ber) {
   // .NET SignedCms refuses to create empty-content signatures. Build a
   // detached CMS envelope around a real synthetic RSA signature instead.
   using(var key=new RSACryptoServiceProvider(2048)) {
    key.PersistKeyInCsp=false;
    var request=new CertificateRequest("CN=Synthetic empty file signer",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
    using(var cert=request.CreateSelfSigned(DateTimeOffset.Now.AddYears(-3),expired?DateTimeOffset.Now.AddYears(-2):DateTimeOffset.Now.AddDays(1))) {
     byte[] serial=cert.GetSerialNumber();Array.Reverse(serial);
     if((serial[0]&128)!=0)serial=DerSerial(serial);
     byte[] sha256=Der(0x30,Der(0x06,new byte[]{0x60,0x86,0x48,1,0x65,3,4,2,1}),Der(0x05));
     byte[] rsa=Der(0x30,Der(0x06,new byte[]{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1}),Der(0x05));
     byte[] signer=Der(0x30,Der(0x02,new byte[]{1}),Der(0x30,cert.IssuerName.RawData,Der(0x02,serial)),sha256,rsa,Der(0x04,key.SignData(new byte[0],HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1)));
     byte[] contentOid=Der(0x06,new byte[]{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1});
     byte[] content=attached?(ber?Ber(0x30,contentOid,Ber(0xa0,Der(0x04))):Der(0x30,contentOid,Der(0xa0,Der(0x04)))):(ber?Ber(0x30,contentOid):Der(0x30,contentOid));
     byte[][] fields={Der(0x02,new byte[]{1}),Der(0x31,sha256),content,Der(0xa0,cert.RawData),Der(0x31,signer)};
     byte[] signed=ber?Ber(0x30,fields):Der(0x30,fields);
     byte[] signedOid=Der(0x06,new byte[]{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,2});
     byte[] signature=ber?Ber(0x30,signedOid,Ber(0xa0,signed)):Der(0x30,signedOid,Der(0xa0,signed));
     return new CmsFixture{Pdf=new byte[0],Signature=signature,Thumbprints=new[]{cert.Thumbprint}};
    }
   }
  }
  private static byte[] DerSerial(byte[] serial) {var positive=new byte[serial.Length+1];Array.Copy(serial,0,positive,1,serial.Length);return positive;}
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

# Reinstating a nonempty-content guard must reject these real empty-file signatures.
foreach($expired in @($false,$true)) {
    $fixture=[ActSignerTests.CmsFixture]::MakeEmpty($expired)
    $native=[ActSigner.NativeCmsInspector]::Inspect($fixture.Pdf,$fixture.Signature)
    Assert-Cms ($native.Count -eq 1 -and $native[0].SignatureStatus -ceq 'valid' -and $native[0].Thumbprint -ceq $fixture.Thumbprints[0]) 'Native verification must authenticate the exact zero-byte source.'
    $oid=$native[0].PSObject.Properties['PublicKeyOid']
    Assert-Cms ($null -ne $oid -and $oid.Value -ceq '1.2.840.113549.1.1.1') 'Verified signer metadata must expose its public-key algorithm, not the certificate issuer-signature algorithm.'
    $invalidNative=[ActSigner.NativeCmsInspector]::Inspect([byte[]]@(0),$fixture.Signature)
    Assert-Cms ([string]::IsNullOrEmpty($invalidNative[0].PublicKeyOid)) 'An unverified signer must not supply the hash-algorithm choice for full verification.'
    $info=Get-ActExistingSignatureInfo $fixture.Pdf $fixture.Signature
    Assert-Cms ($info.Status -ceq 'identified' -and $info.Signers.Count -eq 1 -and $info.Signers[0].SignatureStatus -ceq 'valid' -and $info.TrustStatus -ceq 'not_checked') 'An empty source must retain separate signature mathematics and certificate trust.'
    $changed=Get-ActExistingSignatureInfo ([byte[]]@(0)) $fixture.Signature
    Assert-Cms ($changed.Status -ceq 'identified' -and $changed.Signers[0].SignatureStatus -ceq 'unverifiable') 'Adding one byte to an empty source must invalidate its signature.'
    $missing=Get-ActExistingSignatureInfo $fixture.Pdf ([byte[]]@())
    Assert-Cms ($missing.Status -ceq 'unverifiable' -and $missing.Signers.Count -eq 0) 'An empty signature must remain unverifiable for an empty source.'
}
Write-Host 'PASS: empty-file detached CMS signatures, exact content binding and unchanged trust separation.'

# A mathematically valid RSA fixture is deliberately unsupported by the GOST-only
# full empty-file verifier. It must fail before starting any CAdES worker.
$fixture=[ActSignerTests.CmsFixture]::MakeEmpty($false)
$module=Get-Module ActSigner.CryptoPro
& $module {
    param($fixture)
    $saved=(Get-Item Function:Invoke-ActBridgeOnce).ScriptBlock
    $script:EmptyUnsupportedWorkerCalls=0
    try {
        Set-Item Function:script:Invoke-ActBridgeOnce -Value {
            param($Command,$Kind,$Thumbprint)
            $script:EmptyUnsupportedWorkerCalls++
            return ,([string[]]@('1',$Thumbprint))
        }
        $failed=$false
        try { Test-ActCryptoSignature $fixture.Pdf $fixture.Signature $fixture.Thumbprints[0] } catch { $failed=$true }
        if(-not $failed -or $script:EmptyUnsupportedWorkerCalls -ne 0) { throw 'ASSERT: Unsupported embedded public-key algorithms must fail before a full-verification worker.' }
    } finally {
        Set-Item Function:script:Invoke-ActBridgeOnce -Value $saved
        Remove-Variable EmptyUnsupportedWorkerCalls -Scope Script
    }
} $fixture
Write-Host 'PASS: unsupported empty-file embedded public-key algorithm rejected before the worker.'

# Explicit empty eContent is attached CMS even though decoded content length is
# zero. Restoring a length-only detached check must fail for both BER and DER.
foreach($ber in @($false,$true)) {
    $detached=[ActSignerTests.CmsFixture]::MakeEmpty($false,$false,$ber)
    $detachedInfo=Get-ActExistingSignatureInfo $detached.Pdf $detached.Signature
    Assert-Cms ($detachedInfo.Status -ceq 'identified' -and $detachedInfo.Signers.Count -eq 1 -and $detachedInfo.Signers[0].SignatureStatus -ceq 'valid') 'Detached empty CMS must remain valid with DER or BER indefinite containers.'
    $attached=[ActSignerTests.CmsFixture]::MakeEmpty($false,$true,$ber)
    $info=Get-ActExistingSignatureInfo $attached.Pdf $attached.Signature
    Assert-Cms ($info.Status -ceq 'unverifiable' -and $info.Signers.Count -eq 0) 'Explicit empty eContent must remain attached, exposing no signer or public-key metadata.'
    & $module {
        param($fixture)
        $savedWorker=(Get-Item Function:Invoke-ActBridgeOnce).ScriptBlock
        $savedAlgorithm=(Get-Item Function:Get-ActEmptySignatureHashAlgorithm).ScriptBlock
        $script:AttachedWorkerCalls=0;$script:AttachedAlgorithmCalls=0
        try {
            # The synthetic RSA algorithm is not the reason this test passes:
            # the format gate must reject before even asking for an algorithm.
            Set-Item Function:script:Get-ActEmptySignatureHashAlgorithm -Value { $script:AttachedAlgorithmCalls++; return 101 }
            Set-Item Function:script:Invoke-ActBridgeOnce -Value {
                param($Command,$Kind,$Thumbprint)
                $script:AttachedWorkerCalls++;return ,([string[]]@('1',$Thumbprint))
            }
            $failed=$false
            try { Test-ActCryptoSignature $fixture.Pdf $fixture.Signature $fixture.Thumbprints[0] } catch { $failed=$true }
            if(-not $failed -or $script:AttachedWorkerCalls -ne 0 -or $script:AttachedAlgorithmCalls -ne 0) { throw 'ASSERT: Attached empty CMS must fail before algorithm selection or a full-verification worker.' }
        } finally {
            Set-Item Function:script:Invoke-ActBridgeOnce -Value $savedWorker
            Set-Item Function:script:Get-ActEmptySignatureHashAlgorithm -Value $savedAlgorithm
            Remove-Variable AttachedWorkerCalls,AttachedAlgorithmCalls -Scope Script
        }
    } $attached
}
Write-Host 'PASS: attached empty eContent rejected before identity, hash selection or full verification; detached BER retained.'

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
