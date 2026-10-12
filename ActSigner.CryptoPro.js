// Native Windows Script Host / JScript 5.x. All CAdESCOM stays in this process.
// Protocol alphabet: ASCII. Redirected stdin/stdout: UTF-16LE via cscript //U.
// No eval, JSON, file-system access, input paths, key export or PIN handling.
(function () {
    var MAGIC = "ACTSIGNER/1";
    var MAX_BYTES = 67108864;
    var CERT_BYTES = 1048576;
    var CHUNK_CHARS = 49152;
    var MAX_RECORDS = 4096;
    var MAX_DISCOVERY_CHARS = 16777216;
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var stage = "Protocol";
    var selectedKind = 0;
    var selectedThumb = "";
    var hasWork = false;

    function failure(code) {
        var error = new Error(code);
        error.bridgeCode = code;
        error.number = 0;
        return error;
    }

    function check(condition, code) {
        if (!condition) throw failure(code);
    }

    function hex(number) {
        var value = (number >>> 0).toString(16).toUpperCase();
        while (value.length < 8) value = "0" + value;
        return "0x" + value;
    }

    function safeError(error) {
        var code = error && error.bridgeCode ? String(error.bridgeCode) : "NATIVE";
        if (!/^[A-Z_]{1,32}$/.test(code)) code = "NATIVE";
        var number = error && typeof error.number === "number" ? error.number : 0;
        return { stage: stage, code: code, hr: hex(number) };
    }

    function readLine(maximum) {
        var value = String(WScript.StdIn.ReadLine());
        check(value.length <= maximum && /^[\x20-\x7E]*$/.test(value), "PROTOCOL");
        return value;
    }

    function numberLine(maximum) {
        var value = readLine(9);
        check(/^(0|[1-9][0-9]{0,8})$/.test(value), "PROTOCOL");
        var number = Number(value);
        check(number <= maximum, "BINARY_LIMIT");
        return number;
    }

    function normalizedThumbprint(value) {
        var result = String(value).replace(/\s/g, "").toUpperCase();
        check(/^[0-9A-F]{40}$/.test(result), "THUMBPRINT");
        return result;
    }

    function inputThumbprint() {
        var value = readLine(40);
        check(/^[0-9A-F]{40}$/.test(value), "PROTOCOL");
        return value;
    }

    function inputKind() {
        var value = numberLine(100);
        check(value === 2 || value === 100, "PROTOCOL");
        return value;
    }

    function canonicalBase64(value, bytes) {
        var length = 4 * Math.ceil(bytes / 3);
        check(bytes > 0 && value.length === length, "BINARY_LIMIT");
        check(/^[A-Za-z0-9+/]+={0,2}$/.test(value), "PROTOCOL");
        var padding = (3 - bytes % 3) % 3;
        var actual = value.charAt(value.length - 1) === "=" ? 1 : 0;
        if (value.charAt(value.length - 2) === "=") actual++;
        check(actual === padding, "PROTOCOL");
        if (padding === 1) check((alphabet.indexOf(value.charAt(value.length - 2)) & 3) === 0, "PROTOCOL");
        if (padding === 2) check((alphabet.indexOf(value.charAt(value.length - 3)) & 15) === 0, "PROTOCOL");
    }

    function inputBlob() {
        var bytes = numberLine(MAX_BYTES);
        check(bytes > 0, "BINARY_LIMIT");
        var remaining = 4 * Math.ceil(bytes / 3);
        var chunks = [];
        while (remaining > 0) {
            var expected = Math.min(CHUNK_CHARS, remaining);
            var chunk = readLine(CHUNK_CHARS);
            check(chunk.length === expected, "PROTOCOL");
            if (remaining > CHUNK_CHARS) {
                check(/^[A-Za-z0-9+/]+$/.test(chunk), "PROTOCOL");
            } else {
                canonicalBase64(chunk, bytes - Math.floor(bytes / 36864) * 36864 || 36864);
            }
            chunks.push(chunk);
            remaining -= expected;
        }
        return chunks.join("");
    }

    function exportedBlob(value, maximum) {
        check(typeof value === "string", "PROTOCOL");
        var base64 = String(value).replace(/[ \t\r\n]/g, "");
        check(base64.length > 0 && base64.length <= 4 * Math.ceil(maximum / 3), "BINARY_LIMIT");
        check(base64.length % 4 === 0, "PROTOCOL");
        var padding = base64.charAt(base64.length - 1) === "=" ? 1 : 0;
        if (base64.charAt(base64.length - 2) === "=") padding++;
        var bytes = base64.length / 4 * 3 - padding;
        check(bytes > 0 && bytes <= maximum, "BINARY_LIMIT");
        canonicalBase64(base64, bytes);
        return { bytes: bytes, base64: base64 };
    }

    function line(value) { WScript.StdOut.WriteLine(String(value)); }

    function outputBlob(blob) {
        line(blob.bytes);
        for (var offset = 0; offset < blob.base64.length; offset += CHUNK_CHARS) {
            line(blob.base64.substr(offset, CHUNK_CHARS));
        }
    }

    function beginResponse(request, status) {
        line(MAGIC);
        line(request.id);
        line(status);
        line(request.command);
    }

    function endResponse() { line("END"); }

    function eligibility(certificate) {
        stage = "Certificate.HasPrivateKey";
        if (!certificate.HasPrivateKey()) return "NO_KEY";
        stage = "Certificate.PublicKey";
        var oid = String(certificate.PublicKey().Algorithm.Value);
        if (oid !== "1.2.643.7.1.1.1.1" && oid !== "1.2.643.7.1.1.1.2") return "ALGORITHM";
        stage = "Certificate.Validity";
        var from = new Date(certificate.ValidFromDate).getTime();
        var to = new Date(certificate.ValidToDate).getTime();
        var now = new Date().getTime();
        if (!isFinite(from) || !isFinite(to) || from > now || to <= now) return "VALIDITY";
        return "";
    }

    function certificateRecord(kind, certificate) {
        stage = "Certificate.Thumbprint";
        var thumb = normalizedThumbprint(certificate.Thumbprint);
        stage = "Certificate.Export";
        var blob = exportedBlob(certificate.Export(0), CERT_BYTES);
        return { kind: kind, thumb: thumb, blob: blob };
    }

    function withCertificate(kind, thumb, callback) {
        var store = null;
        var opened = false;
        try {
            stage = "Store.Create";
            store = new ActiveXObject("CAdESCOM.Store");
            stage = "Store.Open";
            store.Open(kind, "My", 0);
            opened = true;
            stage = "Certificates.Find";
            var matches = store.Certificates.Find(0, thumb, false);
            var count = matches.Count;
            check(typeof count === "number" && isFinite(count) && count >= 0 && count === Math.floor(count) && count <= MAX_RECORDS, "PROTOCOL");
            check(count > 0, "CERT_NOT_FOUND");
            var skipped = "";
            for (var i = 1; i <= count; i++) {
                stage = "Certificates.Item";
                var certificate = matches.Item(i);
                stage = "Certificate.Thumbprint";
                check(normalizedThumbprint(certificate.Thumbprint) === thumb, "THUMBPRINT");
                var reason = eligibility(certificate);
                if (reason !== "") { skipped = reason; continue; }
                return callback(certificate);
            }
            throw failure(skipped || "CERT_NOT_FOUND");
        } finally {
            if (opened) {
                // A cleanup failure must not replace the original error stage.
                try { store.Close(); } catch (closeError) { }
            }
            store = null;
        }
    }

    function discover() {
        var records = [];
        var warnings = [];
        var seen = {};
        var totalCharacters = 0;
        var kinds = [100, 2];
        function warning(kind, error, count) {
            if (warnings.length < 62) warnings.push({ kind: kind, stage: error.stage, code: error.code, hr: error.hr, count: count });
        }
        for (var k = 0; k < kinds.length; k++) {
            var kind = kinds[k];
            var store = null;
            var opened = false;
            var counters = { NO_KEY: 0, ALGORITHM: 0, VALIDITY: 0 };
            try {
                stage = "Store.Create";
                store = new ActiveXObject("CAdESCOM.Store");
                stage = "Store.Open";
                store.Open(kind, "My", 0);
                opened = true;
                stage = "Certificates.Count";
                var certificates = store.Certificates;
                var count = certificates.Count;
                check(typeof count === "number" && isFinite(count) && count >= 0 && count === Math.floor(count), "PROTOCOL");
                check(count <= MAX_RECORDS, "DISCOVERY_LIMIT");
                warning(kind, { stage: stage, code: "COUNT", hr: "0x00000000" }, count);
                for (var i = 1; i <= count; i++) {
                    try {
                        stage = "Certificates.Item";
                        var certificate = certificates.Item(i);
                        var reason = eligibility(certificate);
                        if (reason !== "") { counters[reason]++; continue; }
                        var record = certificateRecord(kind, certificate);
                        if (seen[record.thumb] === true) continue;
                        totalCharacters += record.blob.base64.length;
                        check(records.length < MAX_RECORDS && totalCharacters <= MAX_DISCOVERY_CHARS, "DISCOVERY_LIMIT");
                        seen[record.thumb] = true;
                        records.push(record);
                    } catch (certificateError) {
                        if (certificateError.bridgeCode === "DISCOVERY_LIMIT") throw certificateError;
                        warning(kind, safeError(certificateError), 1);
                    }
                }
            } catch (storeError) {
                if (storeError.bridgeCode === "DISCOVERY_LIMIT") throw storeError;
                warning(kind, safeError(storeError), 1);
            } finally {
                if (opened) { try { store.Close(); } catch (closeError) { warning(kind, { stage: "Store.Close", code: "NATIVE", hr: hex(closeError.number) }, 1); } }
                store = null;
            }
            var codes = ["NO_KEY", "ALGORITHM", "VALIDITY"];
            for (var c = 0; c < codes.length; c++) {
                if (counters[codes[c]] > 0) warning(kind, { stage: "Certificate.Filter", code: codes[c], hr: "0x00000000" }, counters[codes[c]]);
            }
        }
        return { records: records, warnings: warnings };
    }

    function sign(request) {
        check(selectedThumb !== "" && request.kind === selectedKind && request.thumb === selectedThumb, "SESSION");
        return withCertificate(selectedKind, selectedThumb, function (certificate) {
            stage = "Signer.Create";
            var signer = new ActiveXObject("CAdESCOM.CPSigner");
            stage = "Signer.Configure";
            signer.Certificate = certificate;
            signer.CheckCertificate = true;
            signer.Options = 2;
            stage = "Signer.SigningTime";
            var attribute = new ActiveXObject("CAdESCOM.CPAttribute");
            attribute.Name = 0;
            attribute.Value = new Date().getVarDate();
            signer.AuthenticatedAttributes2.Add(attribute);
            stage = "SignedData.Create";
            var data = new ActiveXObject("CAdESCOM.CadesSignedData");
            data.ContentEncoding = 1;
            data.Content = request.pdf;
            stage = "SignedData.SignCades";
            return exportedBlob(data.SignCades(signer, 1, true, 0), MAX_BYTES);
        });
    }

    function verify(request) {
        stage = "SignedData.Create";
        var data = new ActiveXObject("CAdESCOM.CadesSignedData");
        data.ContentEncoding = 1;
        data.Content = request.pdf;
        stage = "SignedData.VerifyCades";
        data.VerifyCades(request.signature, 1, true);
        stage = "Signers.Count";
        check(typeof data.Signers.Count === "number" && data.Signers.Count === 1, "SIGNER_COUNT");
        stage = "Signer.Thumbprint";
        var actual = normalizedThumbprint(data.Signers.Item(1).Certificate.Thumbprint);
        check(actual === request.thumb, "SIGNER_MISMATCH");
        return actual;
    }

    function inspect(request) {
        stage = "SignedData.Create";
        var data = new ActiveXObject("CAdESCOM.CadesSignedData");
        data.ContentEncoding = 1;
        data.Content = request.pdf;
        try {
            stage = "SignedData.VerifyCades";
            // Accept existing PKCS7/CMS/CAdES without requiring a newly made BES.
            // All signatures are verified before any identity is returned.
            data.VerifyCades(request.signature, 65535, true);
            stage = "SignedData.Content";
            // Enforce exact external-content binding, including implementations
            // which return embedded content when given an attached CMS.
            var content = exportedBlob(data.Content, MAX_BYTES);
            check(content.base64 === request.pdf, "CONTENT_BINDING");
            stage = "Signers.Count";
            var signers = data.Signers;
            var count = signers.Count;
            check(typeof count === "number" && isFinite(count) && count >= 1 && count === Math.floor(count) && count <= MAX_RECORDS, "SIGNER_COUNT");
            var thumbprints = [];
            for (var i = 1; i <= count; i++) {
                stage = "Signer.Thumbprint";
                thumbprints.push(normalizedThumbprint(signers.Item(i).Certificate.Thumbprint));
            }
            return { status: "valid", thumbprints: thumbprints, detail: null };
        } catch (inspectionError) {
            var detail = safeError(inspectionError);
            // Only the explicit content-hash mismatch is an unrelated document.
            // Malformed, unsupported, trust and all other failures stay unresolved.
            var mismatch = detail.stage === "SignedData.VerifyCades" && detail.code === "NATIVE" && detail.hr === "0x80091007";
            return { status: mismatch ? "different_content" : "unverifiable", thumbprints: [], detail: detail };
        }
    }

    function preflight() {
        stage = "Store.Create";
        var store = new ActiveXObject("CAdESCOM.Store");
        var opened = false;
        try {
            stage = "Store.Open";
            store.Open(0, "My", 0);
            opened = true;
            stage = "Signer.Create";
            var signer = new ActiveXObject("CAdESCOM.CPSigner");
            stage = "SignedData.Create";
            var data = new ActiveXObject("CAdESCOM.CadesSignedData");
            signer = null;
            data = null;
        } finally {
            if (opened) { try { store.Close(); } catch (closeError) { } }
            store = null;
        }
    }

    function readRequest() {
        stage = "Protocol";
        check(readLine(32) === MAGIC, "PROTOCOL");
        var id = readLine(32);
        check(/^[0-9a-f]{32}$/.test(id), "PROTOCOL");
        var command = readLine(16);
        check(/^(CHECK|DISCOVER|SELECT|SIGN|VERIFY|INSPECT|CLOSE)$/.test(command), "PROTOCOL");
        var request = { id: id, command: command };
        if (command === "SELECT" || command === "SIGN") { request.kind = inputKind(); request.thumb = inputThumbprint(); }
        if (command === "VERIFY") request.thumb = inputThumbprint();
        if (command === "SIGN" || command === "VERIFY" || command === "INSPECT") request.pdf = inputBlob();
        if (command === "VERIFY" || command === "INSPECT") request.signature = inputBlob();
        check(readLine(3) === "END", "PROTOCOL");
        return request;
    }

    var exitCode = 0;
    try {
        check(WScript.Arguments.length === 0, "PROTOCOL");
        while (true) {
            var request = readRequest();
            try {
                var command = request.command;
                if (command === "CLOSE") {
                    beginResponse(request, "OK");
                    endResponse();
                    break;
                }
                if (command === "SIGN") {
                    var signature = sign(request);
                    beginResponse(request, "OK");
                    outputBlob(signature);
                } else {
                    check(!hasWork, "SESSION");
                    hasWork = true;
                    if (command === "CHECK") {
                        preflight();
                        beginResponse(request, "OK");
                    } else if (command === "DISCOVER") {
                        var result = discover();
                        beginResponse(request, "OK");
                        line(result.records.length);
                        for (var r = 0; r < result.records.length; r++) {
                            line(result.records[r].kind);
                            line(result.records[r].thumb);
                            outputBlob(result.records[r].blob);
                        }
                        line(result.warnings.length);
                        for (var w = 0; w < result.warnings.length; w++) {
                            line(result.warnings[w].kind);
                            line(result.warnings[w].stage);
                            line(result.warnings[w].code);
                            line(result.warnings[w].hr);
                            line(result.warnings[w].count);
                        }
                    } else if (command === "SELECT") {
                        var selected = withCertificate(request.kind, request.thumb, function (certificate) { return certificateRecord(request.kind, certificate); });
                        selectedKind = request.kind;
                        selectedThumb = request.thumb;
                        beginResponse(request, "OK");
                        line(selected.kind);
                        line(selected.thumb);
                        outputBlob(selected.blob);
                    } else if (command === "VERIFY") {
                        var thumb = verify(request);
                        beginResponse(request, "OK");
                        line(1);
                        line(thumb);
                    } else if (command === "INSPECT") {
                        var inspection = inspect(request);
                        beginResponse(request, "OK");
                        line(inspection.status);
                        line(inspection.thumbprints.length);
                        for (var t = 0; t < inspection.thumbprints.length; t++) line(inspection.thumbprints[t]);
                        if (inspection.detail !== null) {
                            line(inspection.detail.stage);
                            line(inspection.detail.code);
                            line(inspection.detail.hr);
                        }
                    }
                }
                endResponse();
                // Release source snapshots before waiting for the next command.
                request = null;
            } catch (operationError) {
                var detail = safeError(operationError);
                beginResponse(request, "ERROR");
                line(detail.stage);
                line(detail.code);
                line(detail.hr);
                endResponse();
                exitCode = 1;
                break;
            }
        }
    } catch (protocolError) {
        // A damaged request cannot be correlated safely. No raw exception text.
        exitCode = 2;
    }
    WScript.Quit(exitCode);
}());
