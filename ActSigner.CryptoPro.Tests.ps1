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
        public string Command;
        public int Kind;
        public string Thumb;
        public byte[] Pdf;
        public byte[] Signature;
        public string[] Exchange(string command, int kind, string thumb, byte[] pdf, byte[] signature, int timeout, int maximum) {
            Calls++; Command = command; Kind = kind; Thumb = thumb; Pdf = pdf; Signature = signature;
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
    $fake.Reply = Make-Frame 'SIGN' @('3', 'YWJj', 'EXTRA')
    Must-Fail { Invoke-ActCryptoSign $session $snapshot } 'Malformed signature response must fail.'
    Assert-Case ($session.Closed -and $fake.IsClosed) 'A malformed sign response must close the session.'
    $calls = $fake.Calls
    Must-Fail { Invoke-ActCryptoSign $session $snapshot } 'Closed sessions must not retry signing.'
    Assert-Case ($fake.Calls -eq $calls) 'Closed session sent an extra signing command.'

    $savedFactory = (Get-Item Function:New-ActBridgeTransport).ScriptBlock
    try {
        Set-Item Function:script:New-ActBridgeTransport -Value { return $script:ActTestTransport }
        $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
        $script:ActTestTransport.Reply = Make-Frame 'VERIFY' @('1', $thumb)
        Test-ActCryptoSignature $snapshot ([byte[]]@(1, 2, 3)) $thumb
        Assert-Case ($script:ActTestTransport.Command -ceq 'VERIFY' -and $script:ActTestTransport.Finished -and $script:ActTestTransport.IsClosed) 'Verify must use and cleanly finish its separate worker.'

        foreach ($bad in @(@('2', $thumb), @('1', ('B' * 40)), @('1', $thumb, 'EXTRA'))) {
            $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
            $script:ActTestTransport.Reply = Make-Frame 'VERIFY' $bad
            Must-Fail { Test-ActCryptoSignature $snapshot ([byte[]]@(1, 2, 3)) $thumb } 'Unexpected signer or extra verification data was accepted.'
        }
        $script:ActTestTransport = New-Object ActSignerTests.BridgeFake
        $script:ActTestTransport.Reply = Make-Frame 'VERIFY' @('1', $thumb)
        $script:ActTestTransport.ThrowOnFinish = $true
        Must-Fail { Test-ActCryptoSignature $snapshot ([byte[]]@(1, 2, 3)) $thumb } 'A failed worker exit must not count as verification.'

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
    Write-Host 'PASS: PowerShell protocol, snapshot API, signer matching, host errors and closed-session checks.'
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
    const stats = { opens: [], sign: 0, verify: 0, eligibility: 0, creates: 0, attributes: 0 };
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
            stats.creates++;
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
            if (name === "CAdESCOM.CadesSignedData") {
                let content = null, encoding = null;
                const data = {
                    set ContentEncoding(value) { assert.strictEqual(value, 1); encoding = value; },
                    set Content(value) { assert.strictEqual(encoding, 1); content = value; },
                    SignCades: function (signer, type, detached, outputEncoding) {
                        stats.sign++;
                        assert.strictEqual(signer.Certificate.Thumbprint, A);
                        assert.strictEqual(signer.CheckCertificate, true);
                        assert.strictEqual(signer.Options, 2);
                        assert.strictEqual(type, 1); assert.strictEqual(detached, true); assert.strictEqual(outputEncoding, 0);
                        assert.strictEqual(content, options.pdf.toString("base64"));
                        assert(stats.eligibility >= 2, "eligibility must be repeated before signing");
                        if (options.emptySignature) return "";
                        if (options.nullSignature) return null;
                        return Buffer.from("MOCK-SIGNATURE").toString("base64");
                    },
                    VerifyCades: function (signature, type, detached) {
                        stats.verify++;
                        assert.strictEqual(type, 1); assert.strictEqual(detached, true);
                        assert.strictEqual(content, options.pdf.toString("base64"));
                        assert.strictEqual(signature, Buffer.from("MOCK-SIGNATURE").toString("base64"));
                        if (options.verifyFails) {
                            const error = new Error("UNSAFE_PROVIDER_DETAIL");
                            error.number = -2146885628;
                            throw error;
                        }
                    },
                    Signers: {
                        Count: options.signerCount === undefined ? 1 : options.signerCount,
                        Item: function (i) { assert.strictEqual(i, 1); return { Certificate: { Thumbprint: options.otherSigner ? B : A } }; }
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
for (const options of [{ emptySignature: true }, { nullSignature: true }]) {
    test("empty/null signature is rejected", function () {
        const result = run(select.concat(sign), Object.assign({ pdf: pdf }, options));
        assert.strictEqual(result.exit, 1);
        assert.strictEqual(result.frames[1][2], "ERROR");
    });
}
for (const fields of [
    ["100", A, "67108865"],
    ["100", A, "0"],
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
