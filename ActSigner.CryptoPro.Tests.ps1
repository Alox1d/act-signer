#requires -Version 5.1
# Protocol and managed/JavaScript mocks. These tests do not use real CryptoPro,
# Windows COM, a token, a user certificate or a PIN, and do not prove native signing.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'ActSigner.CryptoPro.psm1') -Force
$module = Get-Module ActSigner.CryptoPro

function Assert-BridgeTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('ASSERT: ' + $Message) }
}

& $module {
    Initialize-ActBridgeTransport
    function Assert-Case {
        param([bool]$Condition, [string]$Message)
        if (-not $Condition) { throw ('ASSERT: ' + $Message) }
    }
    function Must-Fail {
        param([scriptblock]$Action, [string]$Message)
        $failed = $false
        try { & $Action | Out-Null } catch { $failed = $true }
        Assert-Case $failed $Message
    }
    function Make-Frame {
        param([string]$Command, [string[]]$Payload)
        return ,([string[]](@('ACTSIGNER/1', ('0' * 32), 'OK', $Command) + $Payload + @('END')))
    }

    if (-not ('ActSignerTests.BridgeFake' -as [type])) {
        Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.IO;
namespace ActSignerTests {
    public sealed class BridgeFake : IDisposable {
        public string[] Reply;
        public bool IsClosed;
        public bool Finished;
        public bool ThrowOnExchange;
        public bool ThrowOnFinish;
        public int Calls;
        public int Timeout;
        public int Maximum;
        public string Command;
        public int Kind;
        public string Thumb;
        public byte[] Pdf;
        public byte[] Signature;
        public string[] Exchange(string command, int kind, string thumb, byte[] pdf, byte[] signature, int timeout, int maximum) {
            Calls++; Command = command; Kind = kind; Thumb = thumb; Pdf = pdf; Signature = signature; Timeout = timeout; Maximum = maximum;
            if (ThrowOnExchange) throw new IOException("UNSAFE_PROVIDER_DETAIL");
            return Reply;
        }
        public void Finish(int timeout) {
            Finished = true;
            if (ThrowOnFinish) throw new IOException("UNSAFE_PROVIDER_DETAIL");
        }
        public void Dispose() { IsClosed = true; }
    }
}
'@
    }

    $separator = [IO.Path]::DirectorySeparatorChar
    Assert-Case ((Get-ActCScriptPath 'WindowsRoot' $true $false).EndsWith(('Sysnative' + $separator + 'cscript.exe'))) '32-on-64 must use Sysnative.'
    Assert-Case ((Get-ActCScriptPath 'WindowsRoot' $true $true).EndsWith(('System32' + $separator + 'cscript.exe'))) 'Native 64-bit must use System32.'
    Assert-Case ((Get-ActCScriptPath 'WindowsRoot' $false $false).EndsWith(('System32' + $separator + 'cscript.exe'))) '32-bit Windows must use System32.'
    Assert-Case ([ActSigner.CScriptTransport]::QuoteArgument('') -ceq '""') 'Empty argument quoting.'
    Assert-Case ([ActSigner.CScriptTransport]::QuoteArgument('a"b\') -ceq '"a\"b\\"') 'Quote and trailing backslash escaping.'
    Assert-Case ([ActSigner.CScriptTransport]::QuoteArgument('Каталог & [1]') -ceq '"Каталог & [1]"') 'Unicode and shell characters must stay one literal argument.'

    # Exercise the real pipe writer against a script-host double without CAdESCOM.
    # A zero-byte source is a length line only; signatures must stay nonempty.
    # Trace only this synthetic double. The production transport deliberately
    # discards provider stderr and must not acquire a diagnostic logging path.
    $wireWorker = Join-Path ([IO.Path]::GetTempPath()) ('cspsigner-empty-wire-' + [Guid]::NewGuid().ToString('N') + '.js')
    $wireProgram = @'
var tracePath = String(WScript.Arguments.Item(0));
var files = new ActiveXObject("Scripting.FileSystemObject"), reads = 0, writes = 0;
function trace(value) { var file = files.OpenTextFile(tracePath, 8, true, 0); file.WriteLine(value); file.Close(); }
function line(value) { trace("WRITE." + (++writes) + ".WAIT"); WScript.StdOut.WriteLine(value); trace("WRITE." + writes + ".DONE"); }
function value() {
    trace("READ." + (++reads) + ".WAIT");
    var result = WScript.StdIn.ReadLine(), codes = [];
    for (var i = 0; i < Math.min(8, result.length); i++) codes.push(result.charCodeAt(i));
    trace("READ." + reads + ".DONE.LEN=" + result.length + ".CODES=" + codes.join(","));
    return result;
}
function read(expected) { if (value() !== expected) { trace("MISMATCH"); WScript.Quit(1); } }
trace("START");
while (true) {
    read("ACTSIGNER/1");
    var id = value(), command = value();
    if (command === "SIGN") { read("100"); read("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); }
    if (command === "VERIFY" || command === "VERIFYEMPTY") read("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    if (command === "VERIFYEMPTY") read("102");
    if (command === "SIGN" || command === "VERIFY" || command === "VERIFYEMPTY" || command === "INSPECT") read("0");
    if (command === "VERIFY" || command === "VERIFYEMPTY" || command === "INSPECT") { read("3"); read("YWJj"); }
    read("END");
    line("ACTSIGNER/1"); line(id); line("OK"); line(command);
    if (command === "SIGN") { line("3"); line("YWJj"); }
    if (command === "VERIFY" || command === "VERIFYEMPTY") { line("1"); line("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); }
    if (command === "INSPECT") { line("valid"); line("1"); line("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); }
    line("END");
    if (command === "CLOSE") { trace("QUIT.0"); WScript.Quit(0); }
}
'@
    function Read-SyntheticWireTrace {
        param([string]$Path)
        if (-not [IO.File]::Exists($Path)) { return 'NO_TRACE' }
        $text=[IO.File]::ReadAllText($Path)
        if($text.Length -gt 4096){$text=$text.Substring($text.Length-4096)}
        return ($text -replace '\r?\n','|')
    }
    function Get-SyntheticWireProbe {
        param([string]$Worker,[string]$Command,[int]$Kind,[string]$TracePath)
        # An independent bounded probe feeds the same synthetic request plus
        # CLOSE before awaiting output, exposing host stderr/exit and buffering.
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=Get-ActCScriptPath
        $workerArguments=@('//NoLogo','//U','//E:JScript',$Worker,$TracePath)
        $info.Arguments=(@($workerArguments | ForEach-Object {[ActSigner.CScriptTransport]::QuoteArgument($_)}) -join ' ')
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true
        $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $encoding=[Text.UnicodeEncoding]::new($false,$false,$true)
        $info.StandardOutputEncoding=$encoding;$info.StandardErrorEncoding=$encoding
        $process=New-Object Diagnostics.Process;$process.StartInfo=$info
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $output=$null;$errorOutput=$null
        $result=[ordered]@{Command=$Command;Started=$false;TimedOut=$false;ExitCode=$null;ElapsedMs=0;StdoutChars=0;ExpectedMagic=$false;Stderr='';Trace='';FailureType=''}
        try {
            $result.Started=$process.Start()
            $output=$process.StandardOutput.ReadToEndAsync();$errorOutput=$process.StandardError.ReadToEndAsync()
            $probeWriter=[IO.StreamWriter]::new($process.StandardInput.BaseStream,$encoding,1024)
            $probeWriter.NewLine="`r`n"
            $lines=@('ACTSIGNER/1',('0'*32),$Command)
            if($Command -ceq 'SIGN'){$lines+=@('100',('A'*40))}
            if($Command -in @('VERIFY','VERIFYEMPTY')){$lines+=('A'*40)}
            if($Command -ceq 'VERIFYEMPTY'){$lines+=([string]$Kind)}
            $lines+='0'
            if($Command -in @('VERIFY','VERIFYEMPTY','INSPECT')){$lines+=@('3','YWJj')}
            $lines+=@('END','ACTSIGNER/1',('1'*32),'CLOSE','END')
            foreach($item in $lines){$probeWriter.WriteLine($item)}
            $probeWriter.Flush();$probeWriter.Dispose()
            if(-not $process.WaitForExit(5000)){$result.TimedOut=$true;$process.Kill();[void]$process.WaitForExit(2000)}
            if($process.HasExited){$result.ExitCode=$process.ExitCode}
        } catch {$result.FailureType=$_.Exception.GetType().FullName}
        finally {
            try{if(-not $process.HasExited){$process.Kill();[void]$process.WaitForExit(2000)}}catch{}
            try {
                if($null -ne $output -and $output.Wait(1000)){$result.StdoutChars=$output.Result.Length;$result.ExpectedMagic=$output.Result.StartsWith('ACTSIGNER/1')}
                if($null -ne $errorOutput -and $errorOutput.Wait(1000)){
                    $stderr=$errorOutput.Result.Replace($Worker,'<SYNTHETIC_WORKER>').Replace([IO.Path]::GetDirectoryName($Worker),'<SYNTHETIC_TEMP>')
                    if($stderr.Length -gt 1024){$stderr=$stderr.Substring(0,1024)}
                    $result.Stderr=$stderr
                }
            } catch {}
            $clock.Stop();$result.ElapsedMs=$clock.ElapsedMilliseconds
            $result.Trace=Read-SyntheticWireTrace $TracePath
            $process.Dispose()
        }
        return [pscustomobject]$result
    }
    try {
        [IO.File]::WriteAllText($wireWorker, ($wireProgram -replace '\r?\n', "`r`n"), [Text.Encoding]::ASCII)
        foreach ($command in @('SIGN', 'VERIFY', 'VERIFYEMPTY', 'INSPECT')) {
            $tracePath=$wireWorker+'.'+$command+'.trace'
            $probeTracePath=$tracePath+'.probe'
            $wire=$null
            $clock=[Diagnostics.Stopwatch]::StartNew()
            $kind=if($command -ceq 'VERIFYEMPTY'){102}else{100}
            try {
                $wire = [ActSigner.CScriptTransport]::new((Get-ActCScriptPath), [string[]]@('//NoLogo','//U','//E:JScript',$wireWorker,$tracePath))
                $reply = $wire.Exchange($command, $kind, ('A' * 40), [byte[]]@(), [byte[]]@(97,98,99), 3000, 4096)
                Assert-Case ($reply[2] -ceq 'OK' -and $reply[3] -ceq $command) 'Pipe framing must preserve a zero-byte source without an extra Base64 line.'
                $wire.Finish(3000)
                Write-Host ('PASS: synthetic CScript pipe {0}; elapsed={1} ms.' -f $command,$clock.ElapsedMilliseconds)
            } catch {
                $clock.Stop()
                Write-Host ('DIAGNOSTIC: synthetic CScript {0}; elapsed={1} ms; trace={2}' -f $command,$clock.ElapsedMilliseconds,(Read-SyntheticWireTrace $tracePath))
                $probe=Get-SyntheticWireProbe $wireWorker $command $kind $probeTracePath
                Write-Host ('DIAGNOSTIC: synthetic CScript independent probe '+($probe | ConvertTo-Json -Compress))
                throw
            } finally {
                if($null -ne $wire){$wire.Dispose()}
                foreach($path in @($tracePath,$probeTracePath)){if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}}
            }
        }
    } finally { Remove-Item -LiteralPath $wireWorker -Force }

    $index = 0
    $bytes = Read-ActBridgeBlob @('3', 'YWJj') ([ref]$index)
    Assert-Case ($bytes -is [byte[]] -and [Text.Encoding]::ASCII.GetString($bytes) -ceq 'abc' -and $index -eq 2) 'Exact byte[] protocol decoding.'
    $large = New-Object byte[] 73731
    for ($i = 0; $i -lt $large.Length; $i++) { $large[$i] = [byte]($i % 251) }
    $base64 = [Convert]::ToBase64String($large)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    $parts.Add([string]$large.Length)
    for ($i = 0; $i -lt $base64.Length; $i += 49152) { $parts.Add($base64.Substring($i, [Math]::Min(49152, $base64.Length - $i))) }
    $index = 0
    $decoded = Read-ActBridgeBlob $parts.ToArray() ([ref]$index)
    Assert-Case ([Convert]::ToBase64String($decoded) -ceq $base64) 'Chunk boundaries changed snapshot bytes.'
    Must-Fail { $index = 0; Read-ActBridgeBlob @('0') ([ref]$index) } 'Empty binary must fail.'
    Must-Fail { $index = 0; Read-ActBridgeBlob @('67108865') ([ref]$index) } 'Oversized advertised binary must fail before allocation.'
    Must-Fail { $index = 0; Read-ActBridgeBlob @('1', 'Zh==') ([ref]$index) } 'Noncanonical padding bits must fail.'
    Must-Fail { $index = 0; Read-ActBridgeBlob @('2', 'YWJj') ([ref]$index) } 'Declared byte length mismatch must fail.'
    Must-Fail { $index = 0; Read-ActBridgeBlob @('3', 'YW J') ([ref]$index) } 'Whitespace in payload must fail.'
    Must-Fail { Assert-ActBridgeEnd @('extra') 0 } 'Trailing fields must fail.'
    Must-Fail { ConvertFrom-ActBridgeCertificate 2 ('A' * 40) ([byte[]]@(1, 2, 3)) } 'Non-certificate data must not enter X509 metadata.'
    Must-Fail { Get-ActNormalizedThumbprint 'not-a-thumbprint' } 'Invalid thumbprint must fail.'

    $thumb = 'A' * 40
    [byte[]]$snapshot = @(0, 255, 1, 128, 10)
    $fake = New-Object ActSignerTests.BridgeFake
    $fake.Reply = Make-Frame 'SIGN' @('3', 'YWJj')
    $session = [pscustomobject]@{ Transport = $fake; Store = $null; Certificate = $null; Thumbprint = $thumb; StoreKind = 100; Closed = $false }
    $signature = Invoke-ActCryptoSign $session $snapshot
    Assert-Case ($signature -is [byte[]] -and [Text.Encoding]::ASCII.GetString($signature) -ceq 'abc') 'Sign API must return one byte[] value.'
    Assert-Case ([Object]::ReferenceEquals($fake.Pdf, $snapshot)) 'Sign must submit the supplied snapshot, not reread a path.'
    Assert-Case ($fake.Kind -eq 100 -and $fake.Thumb -ceq $thumb -and $fake.Command -ceq 'SIGN') 'Selected source and thumbprint were not submitted.'

    # Rejecting an empty source must not prevent signing a valid zero-byte file.
    [byte[]]$emptySnapshot = @()
    $emptyFake = New-Object ActSignerTests.BridgeFake
    $emptyFake.Reply = Make-Frame 'SIGN' @('3', 'YWJj')
    $emptySession = [pscustomobject]@{ Transport = $emptyFake; Thumbprint = $thumb; StoreKind = 100; Closed = $false }
    $emptySignature = Invoke-ActCryptoSign $emptySession $emptySnapshot
    Assert-Case ([Text.Encoding]::ASCII.GetString($emptySignature) -ceq 'abc' -and $emptyFake.Pdf.Length -eq 0) 'An empty source must produce a nonempty signature over the original zero bytes.'
    $emptyFake.Reply = Make-Frame 'SIGN' @('0')
    Must-Fail { Invoke-ActCryptoSign $emptySession $emptySnapshot } 'An empty signature response must fail even when the source is empty.'
    Assert-Case ($emptySession.Closed -and $emptyFake.IsClosed) 'An invalid signature on empty content must close the signing session.'

    $fake.Reply = Make-Frame 'SIGN' @('3', 'YWJj', 'EXTRA')
    Must-Fail { Invoke-ActCryptoSign $session $snapshot } 'Malformed signature response must fail.'
    Assert-Case ($session.Closed -and $fake.IsClosed) 'A malformed sign response must close the session.'
    $calls = $fake.Calls
    Must-Fail { Invoke-ActCryptoSign $session $snapshot } 'Closed sessions must not retry signing.'
    Assert-Case ($fake.Calls -eq $calls) 'Closed session sent an extra signing command.'

    foreach($hr in @('0x80090036','0x8010006E','0x800704C7','0x80004005')) {
      foreach($command in @('SIGN','VERIFYEMPTY')) {
        $fake=New-Object ActSignerTests.BridgeFake
        $fake.Reply=@('ACTSIGNER/1',('0'*32),'ERROR',$command,'SignedData.VerifyHash','NATIVE',$hr,'END')
        $failure=$null
        try { Invoke-ActBridgeExchange $fake $command | Out-Null } catch { $failure=$_.Exception }
        Assert-Case ($null -ne $failure) 'Native signing error must fail.'
        $expected=if($hr -eq '0x80004005'){'session'}else{'cancelled'}
        Assert-Case ($failure.Data['ActSignerFailure'] -ceq $expected) 'Cancellation/session reason must survive the bridge as a typed error.'
      }
    }
    $savedFactory = (Get-Item Function:New-ActBridgeTransport).ScriptBlock
    try {
        Set-Item Function:script:New-ActBridgeTransport -Value { return $script:ActTestTransport }
        $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
        $script:ActTestTransport.Reply = Make-Frame 'VERIFY' @('1', $thumb)
        Test-ActCryptoSignature $snapshot ([byte[]]@(1, 2, 3)) $thumb
        Assert-Case ($script:ActTestTransport.Command -ceq 'VERIFY' -and $script:ActTestTransport.Finished -and $script:ActTestTransport.IsClosed) 'Verify must use and cleanly finish its separate worker.'

        foreach($algorithm in @(@('1.2.643.7.1.1.1.1',101),@('1.2.643.7.1.1.1.2',102))) {
            $signer=[pscustomobject]@{Thumbprint=$thumb;SignatureStatus='valid';PublicKeyOid=$algorithm[0]}
            $hashAlgorithm=Get-ActEmptySignatureHashAlgorithm @($signer) $thumb
            Assert-Case ($hashAlgorithm -eq $algorithm[1]) 'The verified signer public-key OID must choose the matching GOST hash.'
            $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
            $script:ActTestTransport.Reply = Make-Frame 'VERIFYEMPTY' @('1', $thumb)
            $payload=Invoke-ActBridgeOnce 'VERIFYEMPTY' $hashAlgorithm $thumb $emptySnapshot ([byte[]]@(1,2,3)) 600000
            Assert-Case ($payload[0] -ceq '1' -and $script:ActTestTransport.Kind -eq $algorithm[1] -and $script:ActTestTransport.Command -ceq 'VERIFYEMPTY' -and $script:ActTestTransport.Pdf.Length -eq 0 -and $script:ActTestTransport.Maximum -eq 4096 -and $script:ActTestTransport.Finished -and $script:ActTestTransport.IsClosed) 'Empty full verification must use a bounded separate worker with the verified algorithm.'
        }
        foreach($signers in @(@(),@($signer,$signer),@([pscustomobject]@{Thumbprint=$thumb;SignatureStatus='unverifiable';PublicKeyOid='1.2.643.7.1.1.1.1'}),@([pscustomobject]@{Thumbprint=('B'*40);SignatureStatus='valid';PublicKeyOid='1.2.643.7.1.1.1.1'}),@([pscustomobject]@{Thumbprint=$thumb;SignatureStatus='valid';PublicKeyOid='1.2.643.7.1.1.3.2'}))) {
            Must-Fail { Get-ActEmptySignatureHashAlgorithm $signers $thumb } 'Unverified, ambiguous, unexpected or unsupported signer metadata must not choose an empty-file hash algorithm.'
        }
        $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
        $script:ActTestTransport.Reply = Make-Frame 'VERIFYEMPTY' @('1',$thumb)
        Must-Fail { Test-ActCryptoSignature $emptySnapshot ([byte[]]@(1,2,3)) $thumb } 'Malformed empty-file CMS must fail its native gate.'
        Assert-Case ($script:ActTestTransport.Calls -eq 0) 'A native failure must prevent empty-file full-verification worker requests.'
        Must-Fail { Test-ActCryptoSignature $emptySnapshot ([byte[]]@()) $thumb } 'An empty detached signature must never pass verification.'

        foreach ($bad in @(@('2', $thumb), @('1', ('B' * 40)), @('1', $thumb, 'EXTRA'))) {
            $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
            $script:ActTestTransport.Reply = Make-Frame 'VERIFY' $bad
            Must-Fail { Test-ActCryptoSignature $snapshot ([byte[]]@(1, 2, 3)) $thumb } 'Unexpected signer or extra verification data was accepted.'
        }
        $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
        $script:ActTestTransport.Reply = Make-Frame 'VERIFY' @('1', $thumb)
        $script:ActTestTransport.ThrowOnFinish = $true
        Must-Fail { Test-ActCryptoSignature $snapshot ([byte[]]@(1, 2, 3)) $thumb } 'A failed worker exit must not count as verification.'

        # Normalization has no worker or key access. CMS identity/math is tested natively.
        [byte[]]$der = @(0x30,3,2,1,0)
        $derBase64 = [Convert]::ToBase64String($der)
        foreach($encoded in @($der,[Text.Encoding]::ASCII.GetBytes($derBase64),[Text.Encoding]::ASCII.GetBytes(("-----BEGIN CMS-----`r`n{0}`r`n-----END CMS-----" -f $derBase64)))) {
            Assert-Case ([Convert]::ToBase64String((ConvertTo-ActExistingSignatureDer $encoded)) -ceq $derBase64) 'DER/Base64/PEM normalization changed bytes.'
        }
        foreach($encoded in @([byte[]]@(),[byte[]]@(0,255,0),[Text.Encoding]::ASCII.GetBytes('MAMEAQA= trailing'),[Text.Encoding]::ASCII.GetBytes('-----BEGIN CMS-----MAMCAQA=-----END PKCS7-----'))) {
            Must-Fail { ConvertTo-ActExistingSignatureDer $encoded } 'Malformed encoding must be rejected.'
        }

        $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
        $script:ActTestTransport.Reply = Make-Frame 'DISCOVER' @('0', '0', 'EXTRA')
        $found = Get-ActCertificates
        Assert-Case ($found.Certificates.Count -eq 0 -and $found.Warnings.Count -gt 0) 'Malformed discovery must show an error and no partial list.'

        $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
        $script:ActTestTransport.ThrowOnExchange = $true
        $status = Test-ActCryptoPro
        Assert-Case (-not $status.Available -and $status.Message.Contains('CScript') -and -not $status.Message.Contains('UNSAFE_PROVIDER_DETAIL')) 'Host denial/error must be understandable without raw provider text.'
    } finally {
        Set-Item Function:script:New-ActBridgeTransport -Value $savedFactory
        Remove-Variable ActTestTransport -Scope Script -ErrorAction SilentlyContinue
    }
    Write-Host 'PASS: PowerShell protocol, exact snapshots, encoding guards, signer matching, host errors and closed-session checks.'
}

$node = Get-Command node -ErrorAction SilentlyContinue
if ($null -eq $node) {
    Write-Host 'SKIP: native JScript source mock tests need Node.js; PowerShell checks above completed. No real COM was tested.'
    return
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ActSigner-bridge-tests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$testScript = Join-Path $testRoot 'worker-mocks.js'
$nodeProgram = @'
"use strict";
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");
const source = fs.readFileSync(process.argv[2], "utf8");
const A = "A".repeat(40), B = "B".repeat(40);
let passed = 0;
function blob(bytes) {
    const text = Buffer.from(bytes).toString("base64");
    return [String(bytes.length)].concat(text.match(/.{1,49152}/g) || []);
}
function request(command, index, fields) {
    return ["ACTSIGNER/1", index.toString(16).padStart(32, "0"), command].concat(fields || [], ["END"]);
}
function cert(thumb, options, stats) {
    return {
        Thumbprint: thumb,
        HasPrivateKey: function () { stats.eligibility++; return options.key !== false; },
        PublicKey: function () { return { Algorithm: { Value: options.oid || "1.2.643.7.1.1.1.1" } }; },
        ValidFromDate: new Date(Date.now() - 86400000),
        ValidToDate: new Date(Date.now() + (options.expired ? -1000 : 86400000)),
        Export: function (mode) { assert.strictEqual(mode, 0); return Buffer.from("SYNTHETIC-PUBLIC-CERTIFICATE").toString("base64"); }
    };
}
function run(lines, options) {
    options = options || {};
    const input = lines.slice(), output = [];
    const stats = { opens: [], sign: 0, verify: 0, hashVerify: 0, hashes: [], eligibility: 0, creates: 0, attributes: 0, classes: [] };
    const quit = {};
    let exit = null;
    const certificates = [cert(A, options, stats), cert(B, {}, stats)];
    function collection(list) {
        return {
            Count: options.nullCount ? null : list.length,
            Item: function (i) { assert(i >= 1 && i <= list.length); return list[i - 1]; },
            Find: function (mode, thumb, valid) {
                assert.strictEqual(mode, 0);
                assert.strictEqual(valid, false);
                return collection(options.wrongFind ? [cert(B, {}, stats)] : list.filter(function (c) { return c.Thumbprint === thumb; }));
            }
        };
    }
    const context = {
        WScript: {
            Arguments: { length: 0 },
            StdIn: { ReadLine: function () { if (input.length === 0) throw new Error("EOF"); return input.shift(); } },
            StdOut: { WriteLine: function (value) { output.push(String(value)); } },
            Quit: function (code) { exit = code; throw quit; }
        },
        ActiveXObject: function (name) {
            stats.creates++; stats.classes.push(name);
            if (name === "CAdESCOM.Store") {
                let kind = null;
                return {
                    Open: function (location, store, mode) {
                        assert.strictEqual(store, "My"); assert.strictEqual(mode, 0);
                        assert([0, 2, 100].includes(location));
                        kind = location; stats.opens.push(location);
                        if (options.expireBeforeSign && stats.opens.length >= 2) certificates[0].ValidToDate = new Date(0);
                    },
                    get Certificates() { return collection(kind === 0 ? [] : certificates); },
                    Close: function () {}
                };
            }
            if (name === "CAdESCOM.CPSigner") {
                return { AuthenticatedAttributes2: { Add: function (attribute) {
                    assert.strictEqual(attribute.Name, 0);
                    assert.strictEqual(typeof attribute.Value, "number");
                    stats.attributes++;
                } } };
            }
            if (name === "CAdESCOM.CPAttribute") return {};
            if (name === "CAdESCOM.HashedData") {
                let algorithm = null, encoding = null, hashed = false;
                return {
                    set Algorithm(value) { assert([101, 102].includes(value)); algorithm = value; },
                    get Algorithm() { return algorithm; },
                    set DataEncoding(value) { assert.strictEqual(value, 0); encoding = value; },
                    Hash: function (value) {
                        assert.strictEqual(encoding, 0); assert.strictEqual(value, "");
                        assert([101, 102].includes(algorithm)); hashed = true; stats.hashes.push(algorithm);
                    },
                    get Value() { assert(hashed); return "0".repeat(algorithm === 101 ? 64 : 128); }
                };
            }
            if (name === "CAdESCOM.CadesSignedData") {
                let content = null, encoding = null;
                const data = {
                    set ContentEncoding(value) { assert([0, 1].includes(value)); encoding = value; },
                    set Content(value) { assert([0, 1].includes(encoding)); content = value; },
                    get Content() { return options.returnedContent === undefined ? content : options.returnedContent; },
                    SignCades: function (signer, type, detached, outputEncoding) {
                        stats.sign++;
                        assert.strictEqual(signer.Certificate.Thumbprint, A);
                        assert.strictEqual(signer.CheckCertificate, true);
                        assert.strictEqual(signer.Options, 2);
                        assert.strictEqual(type, 1); assert.strictEqual(detached, true); assert.strictEqual(outputEncoding, 0);
                        assert.strictEqual(content, options.pdf.toString("base64"));
                        assert.strictEqual(encoding, options.pdf.length === 0 ? 0 : 1);
                        assert(stats.eligibility >= 2, "eligibility must be repeated before signing");
                        if (options.emptySignature) return "";
                        if (options.nullSignature) return null;
                        return Buffer.from("MOCK-SIGNATURE").toString("base64");
                    },
                    VerifyCades: function (signature, type, detached) {
                        stats.verify++;
                        assert.strictEqual(type, options.inspect ? 65535 : 1); assert.strictEqual(detached, true);
                        assert.strictEqual(content, options.pdf.toString("base64"));
                        assert.strictEqual(signature, Buffer.from("MOCK-SIGNATURE").toString("base64"));
                        if (options.verifyFails) {
                            const error = new Error("UNSAFE_PROVIDER_DETAIL");
                            error.number = options.verifyErrorNumber === undefined ? -2146885628 : options.verifyErrorNumber;
                            throw error;
                        }
                    },
                    VerifyHash: function (hash, signature, type) {
                        stats.hashVerify++;
                        assert.strictEqual(content, null); assert.strictEqual(encoding, null);
                        assert.strictEqual(type, 1);
                        assert.strictEqual(hash.Algorithm, options.hashAlgorithm);
                        assert.strictEqual(hash.Value.length, options.hashAlgorithm === 101 ? 64 : 128);
                        assert.strictEqual(signature, Buffer.from("MOCK-SIGNATURE").toString("base64"));
                        if (options.verifyFails) {
                            const error = new Error("UNSAFE_PROVIDER_DETAIL"); error.number = -2146762487; throw error;
                        }
                    },
                    Signers: {
                        Count: options.signerCount === undefined ? (options.inspectionThumbs || [A]).length : options.signerCount,
                        Item: function (i) {
                            if (options.inspectionThumbs) { assert(i >= 1 && i <= options.inspectionThumbs.length); return { Certificate: { Thumbprint: options.inspectionThumbs[i - 1] } }; }
                            assert.strictEqual(i, 1); return { Certificate: { Thumbprint: options.otherSigner ? B : A } };
                        }
                    }
                };
                return data;
            }
            throw new Error("Unexpected COM class: " + name);
        }
    };
    vm.createContext(context);
    vm.runInContext("Date.prototype.getVarDate = function () { return this.getTime(); };", context);
    try { vm.runInContext(source, context, { timeout: 5000 }); } catch (error) { if (error !== quit) throw error; }
    const frames = [];
    let frame = [];
    output.forEach(function (line) {
        frame.push(line);
        if (line === "END") { frames.push(frame); frame = []; }
    });
    assert.strictEqual(frame.length, 0, "incomplete output frame");
    frames.forEach(function (f) {
        assert.strictEqual(f[0], "ACTSIGNER/1");
        assert(/^[a-f0-9]{32}$/.test(f[1]));
        assert(["OK", "ERROR"].includes(f[2]));
    });
    return { exit: exit, frames: frames, output: output, stats: stats, remaining: input.length };
}
function test(name, fn) { fn(); passed++; }
const pdf = Buffer.alloc(73731);
for (let i = 0; i < pdf.length; i++) pdf[i] = i % 251;
const select = request("SELECT", 1, ["100", A]);
const sign = request("SIGN", 2, ["100", A].concat(blob(pdf)));
const close = request("CLOSE", 9);
test("zero-byte source is signed without an extra Base64 line", function () {
    const empty = Buffer.alloc(0);
    const result = run(select.concat(request("SIGN", 2, ["100", A].concat(blob(empty))), close), { pdf: empty });
    assert.strictEqual(result.exit, 0);
    assert.deepStrictEqual(result.frames[1].slice(4, -1), ["14", "TU9DSy1TSUdOQVRVUkU="]);
    assert.strictEqual(result.remaining, 0);
});
for (const algorithm of [101, 102]) {
    test("empty source full verification uses the selected GOST hash without stores or keys", function () {
        const fields = [A, String(algorithm)].concat(blob(Buffer.alloc(0)), blob(Buffer.from("MOCK-SIGNATURE")));
        const result = run(request("VERIFYEMPTY", 1, fields).concat(close), { hashAlgorithm: algorithm });
        assert.strictEqual(result.exit, 0);
        assert.deepStrictEqual(result.frames[0].slice(4, -1), ["1", A]);
        assert.deepStrictEqual(result.stats.hashes, [algorithm]);
        assert.strictEqual(result.stats.hashVerify, 1); assert.strictEqual(result.stats.verify, 0);
        assert.deepStrictEqual(result.stats.classes, ["CAdESCOM.HashedData", "CAdESCOM.CadesSignedData"]);
        assert.strictEqual(result.stats.eligibility, 0); assert.strictEqual(result.stats.opens.length, 0);
        assert.strictEqual(result.stats.sign, 0); assert.strictEqual(result.remaining, 0);
        for (const options of [{ otherSigner: true }, { signerCount: 0 }, { signerCount: 2 }, { signerCount: true }, { verifyFails: true }]) {
            const failed = run(request("VERIFYEMPTY", 1, fields), Object.assign({ hashAlgorithm: algorithm }, options));
            assert.strictEqual(failed.exit, 1); assert.strictEqual(failed.frames[0][2], "ERROR");
            assert(!failed.output.join("").includes("UNSAFE_PROVIDER_DETAIL"));
        }
        const repeated = run(request("VERIFYEMPTY", 1, fields).concat(request("VERIFYEMPTY", 2, fields)), { hashAlgorithm: algorithm });
        assert.strictEqual(repeated.exit, 1); assert.strictEqual(repeated.frames[1][5], "SESSION");
        assert.strictEqual(repeated.stats.hashVerify, 1);
    });
}
for (const fields of [
    [A, "100", "0", "14", "TU9DSy1TSUdOQVRVUkU="],
    [A, "0101", "0", "14", "TU9DSy1TSUdOQVRVUkU="],
    [A, "101", "1", "YQ==", "14", "TU9DSy1TSUdOQVRVUkU="],
    [A, "101", "0", "0"],
    [A, "102", "0", "67108865"]
]) {
    test("invalid empty-hash verification rejected before COM", function () {
        const result = run(request("VERIFYEMPTY", 1, fields));
        assert.strictEqual(result.exit, 2); assert.strictEqual(result.stats.creates, 0);
    });
}
test("inspection verifies empty content and rejects a nonempty readback", function () {
    const empty = Buffer.alloc(0);
    const fields = blob(empty).concat(blob(Buffer.from("MOCK-SIGNATURE")));
    const result = run(request("INSPECT", 1, fields).concat(close), { pdf: empty, inspect: true });
    assert.strictEqual(result.exit, 0);
    assert.deepStrictEqual(result.frames[0].slice(4, -1), ["valid", "1", A]);
    for (const returnedContent of [null, "YQ=="]) {
        const failed = run(request("INSPECT", 1, fields).concat(close), { pdf: empty, inspect: true, returnedContent: returnedContent });
        assert.strictEqual(failed.exit, 0);
        assert.deepStrictEqual(failed.frames[0].slice(4, 6), ["unverifiable", "0"]);
    }
});
for (const command of ["VERIFY", "INSPECT"]) {
    test("empty signature rejected before COM even for empty content", function () {
        const fields = (command === "VERIFY" ? [A] : []).concat(blob(Buffer.alloc(0)), ["0"]);
        const result = run(request(command, 1, fields));
        assert.strictEqual(result.exit, 2);
        assert.strictEqual(result.stats.creates, 0);
    });
}
test("persistent source selection and repeated signing", function () {
    const result = run(select.concat(sign, request("SIGN", 3, ["100", A].concat(blob(pdf))), close), { pdf: pdf });
    assert.strictEqual(result.exit, 0);
    assert.strictEqual(result.frames.length, 4);
    assert(result.frames.every(function (f) { return f[2] === "OK"; }));
    assert.deepStrictEqual(result.stats.opens, [100, 100, 100]);
    assert.strictEqual(result.stats.sign, 2);
    assert.strictEqual(result.stats.attributes, 2);
    assert.strictEqual(result.remaining, 0);
});
test("source mismatch never signs", function () {
    const result = run(select.concat(request("SIGN", 2, ["2", A].concat(blob(pdf)))), { pdf: pdf });
    assert.strictEqual(result.exit, 1);
    assert.strictEqual(result.frames[1][5], "SESSION");
    assert.strictEqual(result.stats.sign, 0);
});
test("expiration after selection is rechecked", function () {
    const result = run(select.concat(sign), { pdf: pdf, expireBeforeSign: true });
    assert.strictEqual(result.exit, 1);
    assert.strictEqual(result.frames[1][5], "VALIDITY");
    assert.strictEqual(result.stats.sign, 0);
});
for (const item of [
    ["missing key", { key: false }, "NO_KEY"],
    ["wrong algorithm", { oid: "1.2.840.113549.1.1.1" }, "ALGORITHM"],
    ["expired certificate", { expired: true }, "VALIDITY"],
    ["wrong Find result", { wrongFind: true }, "THUMBPRINT"]
]) {
    test(item[0], function () {
        const result = run(select, item[1]);
        assert.strictEqual(result.exit, 1);
        assert.strictEqual(result.frames[0][5], item[2]);
        assert.strictEqual(result.stats.sign, 0);
    });
}
test("discovery prefers container, deduplicates and returns open certificates", function () {
    const result = run(request("DISCOVER", 1).concat(close));
    assert.strictEqual(result.exit, 0);
    assert.strictEqual(result.frames[0][4], "2");
    assert.strictEqual(result.frames[0][5], "100");
    assert.strictEqual(result.frames[0][6], A);
    assert.deepStrictEqual(result.stats.opens, [100, 2]);
    assert.strictEqual(result.stats.sign, 0);
});
test("null Count is an error, never a successful zero count", function () {
    const result = run(request("DISCOVER", 1).concat(close), { nullCount: true });
    assert.strictEqual(result.exit, 0);
    assert(result.frames[0].includes("PROTOCOL"));
    assert(!result.frames[0].includes("COUNT"));
});
const verify = request("VERIFY", 1, [A].concat(blob(pdf), blob(Buffer.from("MOCK-SIGNATURE"))));
test("detached verification with one exact signer", function () {
    const result = run(verify.concat(close), { pdf: pdf });
    assert.strictEqual(result.exit, 0);
    assert.deepStrictEqual(result.frames[0].slice(4, -1), ["1", A]);
    assert.strictEqual(result.stats.verify, 1);
    assert.strictEqual(result.stats.sign, 0);
    assert.strictEqual(result.stats.opens.length, 0);
});
for (const options of [{ signerCount: 2 }, { signerCount: true }, { otherSigner: true }, { verifyFails: true }]) {
    test("bad verification never succeeds", function () {
        const result = run(verify, Object.assign({ pdf: pdf }, options));
        assert.strictEqual(result.exit, 1);
        assert.strictEqual(result.frames[0][2], "ERROR");
        assert(!result.output.join("").includes("UNSAFE_PROVIDER_DETAIL"));
    });
}
const inspect = request("INSPECT", 1, blob(pdf).concat(blob(Buffer.from("MOCK-SIGNATURE"))));
test("existing PKCS7 inspection returns every verified signer without keys", function () {
    const result = run(inspect.concat(close), { pdf: pdf, inspect: true, inspectionThumbs: [B, " a ".repeat(40)] });
    assert.strictEqual(result.exit, 0);
    assert.deepStrictEqual(result.frames[0].slice(4, -1), ["valid", "2", B, A]);
    assert.strictEqual(result.stats.verify, 1);
    assert.deepStrictEqual(result.stats.classes, ["CAdESCOM.CadesSignedData"]);
    assert.strictEqual(result.stats.eligibility, 0);
    assert.strictEqual(result.stats.sign, 0);
    assert.strictEqual(result.stats.opens.length, 0);
    assert.strictEqual(result.remaining, 0);
});
test("only the known bad-content hash HRESULT means different content", function () {
    const result = run(inspect.concat(close), { pdf: pdf, inspect: true, verifyFails: true, verifyErrorNumber: -2146889721 });
    assert.strictEqual(result.exit, 0);
    assert.deepStrictEqual(result.frames[0].slice(4, -1), ["different_content", "0", "SignedData.VerifyCades", "NATIVE", "0x80091007"]);
    assert.strictEqual(result.stats.verify, 1);
    assert.strictEqual(result.stats.sign, 0);
});
for (const options of [
    { verifyFails: true },
    { verifyFails: true, verifyErrorNumber: -2146762487 },
    { signerCount: 0 }, { signerCount: null }, { signerCount: true }, { signerCount: 0.5 }, { signerCount: 4097 },
    { inspectionThumbs: [A, "bad-thumb"] },
    { returnedContent: Buffer.from("DIFFERENT-ATTACHED-PDF").toString("base64") },
    { returnedContent: "" }, { returnedContent: null }
]) {
    test("uncertain existing signature never grants a signer identity", function () {
        const result = run(inspect.concat(close), Object.assign({ pdf: pdf, inspect: true }, options));
        assert.strictEqual(result.exit, 0);
        assert.deepStrictEqual(result.frames[0].slice(4, 6), ["unverifiable", "0"]);
        assert(!result.frames[0].includes(A));
        assert(!result.output.join("").includes("UNSAFE_PROVIDER_DETAIL"));
        assert.strictEqual(result.stats.sign, 0);
        assert.strictEqual(result.stats.opens.length, 0);
    });
}
test("inspection accepts canonical equivalent Base64 content readback", function () {
    const base64 = pdf.toString("base64");
    const result = run(inspect.concat(close), { pdf: pdf, inspect: true, returnedContent: "\r\n" + base64.slice(0, 60) + "\r\n" + base64.slice(60) + "\r\n" });
    assert.strictEqual(result.exit, 0);
    assert.deepStrictEqual(result.frames[0].slice(4, -1), ["valid", "1", A]);
});
for (const options of [{ emptySignature: true }, { nullSignature: true }]) {
    test("empty/null signature is rejected", function () {
        const result = run(select.concat(sign), Object.assign({ pdf: pdf }, options));
        assert.strictEqual(result.exit, 1);
        assert.strictEqual(result.frames[1][2], "ERROR");
    });
}
for (const fields of [
    ["100", A, "67108865"],
    ["100", A, "1", "Zh=="],
    ["100", A, "3", "YW J"]
]) {
    test("invalid binary request rejected before COM", function () {
        const result = run(request("SIGN", 1, fields));
        assert.strictEqual(result.exit, 2);
        assert.strictEqual(result.stats.creates, 0);
        assert.strictEqual(result.stats.sign, 0);
    });
}
test("no unframed command or eval path", function () {
    const result = run(["bad", "input"]);
    assert.strictEqual(result.exit, 2);
    assert.strictEqual(result.stats.creates, 0);
});
console.log("PASS: " + passed + " JScript worker mock/protocol cases. No real COM, token or cryptographic signature was used.");
'@
try {
    [IO.File]::WriteAllText($testScript, $nodeProgram, (New-Object Text.UTF8Encoding -ArgumentList $false))
    & $node.Source $testScript (Join-Path $PSScriptRoot 'ActSigner.CryptoPro.js')
    Assert-BridgeTest ($LASTEXITCODE -eq 0) 'JScript source mock tests failed.'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
Write-Host 'ActSigner.CryptoPro protocol/mock tests passed. Native Windows/CryptoPro verification is still required.'
