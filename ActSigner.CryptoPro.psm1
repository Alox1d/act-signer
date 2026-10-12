#requires -Version 5.1
Set-StrictMode -Version 2.0

$script:ActBridgeMaxBytes = 64MB
$script:ActBridgeScript = Join-Path $PSScriptRoot 'ActSigner.CryptoPro.js'

# Native CScript owns all CAdESCOM objects. PowerShell exchanges only public
# certificate data, PDF snapshots and signatures through inherited local pipes.
function Initialize-ActBridgeTransport {
    if ('ActSigner.CScriptTransport' -as [type]) { return }
    Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace ActSigner {
    public sealed class CScriptTransport : IDisposable {
        private const int ChunkBytes = 36864;
        private const int ChunkChars = 49152;
        private readonly object sync = new object();
        private Process process;
        private StreamWriter input;
        private StreamReader output;
        private Task stderrDrain;
        private bool disposed;
        public bool IsClosed { get { return disposed; } }

        public static string QuoteArgument(string value) {
            if (value == null) value = "";
            StringBuilder result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') {
                    result.Append('\\', slashes * 2 + 1);
                    result.Append('"');
                } else {
                    result.Append('\\', slashes);
                    result.Append(c);
                }
                slashes = 0;
            }
            result.Append('\\', slashes * 2);
            result.Append('"');
            return result.ToString();
        }

        public CScriptTransport(string executable, string[] arguments) {
            ProcessStartInfo info = new ProcessStartInfo();
            info.FileName = executable;
            List<string> quoted = new List<string>();
            foreach (string argument in arguments) quoted.Add(QuoteArgument(argument));
            info.Arguments = String.Join(" ", quoted.ToArray());
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardInput = true;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            Encoding wire = new UnicodeEncoding(false, false, true);
            info.StandardOutputEncoding = wire;
            info.StandardErrorEncoding = wire;
            process = new Process();
            process.StartInfo = info;
            try {
                if (!process.Start()) throw new IOException("The script host did not start.");
                // //U applies to redirected input as well as output. The protocol
                // alphabet is ASCII; its wire encoding is UTF-16LE, without a BOM.
                input = new StreamWriter(process.StandardInput.BaseStream, wire, 8192);
                input.NewLine = "\r\n";
                output = process.StandardOutput;
                stderrDrain = DrainAsync(process.StandardError);
            } catch {
                Dispose();
                throw;
            }
        }

        private static async Task DrainAsync(StreamReader reader) {
            // Drain continuously, retain no host/provider stderr or personal paths.
            try {
                char[] buffer = new char[4096];
                while (await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false) != 0) { }
            } catch { }
        }

        private async Task WriteBlobAsync(byte[] bytes) {
            if (bytes == null || bytes.Length == 0 || bytes.Length > 67108864)
                throw new InvalidDataException("Invalid binary length.");
            await input.WriteLineAsync(bytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)).ConfigureAwait(false);
            for (int offset = 0; offset < bytes.Length; offset += ChunkBytes) {
                int length = Math.Min(ChunkBytes, bytes.Length - offset);
                await input.WriteLineAsync(Convert.ToBase64String(bytes, offset, length)).ConfigureAwait(false);
            }
        }

        private async Task WriteRequestAsync(string id, string command, int kind, string thumbprint, byte[] pdf, byte[] signature) {
            await input.WriteLineAsync("ACTSIGNER/1").ConfigureAwait(false);
            await input.WriteLineAsync(id).ConfigureAwait(false);
            await input.WriteLineAsync(command).ConfigureAwait(false);
            if (command == "SELECT" || command == "SIGN") {
                await input.WriteLineAsync(kind.ToString(System.Globalization.CultureInfo.InvariantCulture)).ConfigureAwait(false);
                await input.WriteLineAsync(thumbprint).ConfigureAwait(false);
            }
            if (command == "VERIFY") await input.WriteLineAsync(thumbprint).ConfigureAwait(false);
            if (command == "SIGN" || command == "VERIFY" || command == "INSPECT") await WriteBlobAsync(pdf).ConfigureAwait(false);
            if (command == "VERIFY" || command == "INSPECT") await WriteBlobAsync(signature).ConfigureAwait(false);
            await input.WriteLineAsync("END").ConfigureAwait(false);
            await input.FlushAsync().ConfigureAwait(false);
        }

        private async Task<string[]> ReadFrameAsync(int maxCharacters) {
            List<string> lines = new List<string>();
            StringBuilder line = new StringBuilder();
            char[] buffer = new char[8192];
            int total = 0;
            bool firstCharacter = true;
            while (true) {
                int read = await output.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                if (read == 0) throw new InvalidDataException("The script host closed an incomplete response.");
                for (int i = 0; i < read; i++) {
                    char c = buffer[i];
                    if (firstCharacter && c == '\uFEFF') { firstCharacter = false; continue; }
                    firstCharacter = false;
                    total++;
                    if (total > maxCharacters) throw new InvalidDataException("The response is too large.");
                    if (c == '\n') {
                        if (line.Length > 0 && line[line.Length - 1] == '\r') line.Length--;
                        string value = line.ToString();
                        line.Length = 0;
                        if (value.IndexOf('\r') >= 0) throw new InvalidDataException("Invalid response line.");
                        lines.Add(value);
                        if (value == "END") {
                            if (i + 1 != read) throw new InvalidDataException("Trailing response data.");
                            return lines.ToArray();
                        }
                    } else {
                        if (c > 127 || (c < 32 && c != '\r'))
                            throw new InvalidDataException("Non-protocol script-host output.");
                        line.Append(c);
                        if (line.Length > ChunkChars + 1) throw new InvalidDataException("The response line is too long.");
                    }
                }
            }
        }

        public string[] Exchange(string command, int kind, string thumbprint, byte[] pdf, byte[] signature, int timeoutMilliseconds, int maxCharacters) {
            lock (sync) {
                if (disposed) throw new ObjectDisposedException("CScriptTransport");
                string id = Guid.NewGuid().ToString("N");
                try {
                    Task<string[]> read = ReadFrameAsync(maxCharacters);
                    Task write = WriteRequestAsync(id, command, kind, thumbprint, pdf, signature);
                    Task all = Task.WhenAll(new Task[] { read, write });
                    if (!all.Wait(timeoutMilliseconds)) throw new TimeoutException("The script-host operation timed out.");
                    string[] lines = read.Result;
                    if (lines.Length < 5 || lines[0] != "ACTSIGNER/1" ||
                        lines[1] != id || lines[3] != command ||
                        (lines[2] != "OK" && lines[2] != "ERROR") ||
                        lines[lines.Length - 1] != "END")
                        throw new InvalidDataException("Unexpected response frame.");
                    if (lines[2] == "ERROR") {
                        Dispose();
                    } else if (command != "CLOSE" && process.HasExited) {
                        throw new InvalidDataException("The script host exited before session close.");
                    }
                    return lines;
                } catch (AggregateException e) {
                    Dispose();
                    throw e.GetBaseException();
                } catch {
                    Dispose();
                    throw;
                }
            }
        }

        public void Finish(int timeoutMilliseconds) {
            lock (sync) {
                if (disposed) throw new ObjectDisposedException("CScriptTransport");
                try {
                    string[] close = Exchange("CLOSE", 0, "", null, null, timeoutMilliseconds, 2048);
                    if (close.Length != 5 || close[2] != "OK")
                        throw new InvalidDataException("Invalid close response.");
                    if (!process.WaitForExit(timeoutMilliseconds)) throw new TimeoutException("The script host did not exit.");
                    if (process.ExitCode != 0) throw new InvalidDataException("The script host failed.");
                    Task<string> remaining = output.ReadToEndAsync();
                    if (!remaining.Wait(timeoutMilliseconds) || remaining.Result.Length != 0)
                        throw new InvalidDataException("Trailing script-host output.");
                } finally { Dispose(); }
            }
        }

        public void Dispose() {
            if (disposed) return;
            disposed = true;
            // Kill before touching the writer: Flush/Dispose on a blocked pipe
            // must never stall shutdown or submit another signing request.
            if (process != null) {
                try { if (!process.HasExited) process.Kill(); } catch { }
                try { process.WaitForExit(2000); } catch { }
                try { if (input != null) input.BaseStream.Close(); } catch { }
                try { if (output != null) output.Close(); } catch { }
                try { process.Dispose(); } catch { }
            }
        }
    }
}
'@
}

function Get-ActNormalizedThumbprint {
    param([string]$Thumbprint)
    $value = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($value -notmatch '^[0-9A-F]{40}$') { throw 'Некорректный отпечаток сертификата.' }
    return $value
}

function Get-ActCScriptPath {
    param(
        [string]$WindowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows),
        [bool]$OS64Bit = [Environment]::Is64BitOperatingSystem,
        [bool]$Process64Bit = [Environment]::Is64BitProcess
    )
    if ([string]::IsNullOrWhiteSpace($WindowsDirectory)) { throw 'Не удалось найти Windows Script Host (CScript).' }
    $directory = 'System32'
    if ($OS64Bit -and -not $Process64Bit) { $directory = 'Sysnative' }
    return [IO.Path]::Combine($WindowsDirectory, $directory, 'cscript.exe')
}

function New-ActBridgeTransport {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Подпись через КриптоПро требует Windows.' }
    $executable = Get-ActCScriptPath
    if (-not [IO.File]::Exists($executable)) { throw 'Windows Script Host (CScript) не найден. Проверьте доступность компонента в Windows.' }
    if (-not [IO.File]::Exists($script:ActBridgeScript)) { throw 'Рядом с программой отсутствует ActSigner.CryptoPro.js. Распакуйте полный комплект файлов.' }
    try {
        Initialize-ActBridgeTransport
        $arguments = [string[]]@('//nologo', '//I', '//U', '//E:JScript', $script:ActBridgeScript)
        return [ActSigner.CScriptTransport]::new($executable, $arguments)
    } catch {
        throw 'Не удалось запустить Windows Script Host (CScript). Компонент может быть недоступен или запрещён политикой Windows.'
    }
}

function Get-ActBridgeErrorText {
    param([string]$Stage, [string]$Code, [string]$HResult)
    $description = switch ($Code) {
        'CERT_NOT_FOUND' { 'Выбранный сертификат больше не найден в выбранном хранилище.' }
        'NO_KEY' { 'Сертификат не связан с доступным закрытым ключом.' }
        'ALGORITHM' { 'Для подписи требуется сертификат ГОСТ Р 34.10-2012.' }
        'VALIDITY' { 'Сертификат находится вне срока действия. Проверьте дату в Windows.' }
        'THUMBPRINT' { 'Отпечаток сертификата не совпал с выбранным.' }
        'SIGNER_COUNT' { 'В новой подписи должен быть ровно один подписант.' }
        'SIGNER_MISMATCH' { 'Новая подпись создана другим сертификатом.' }
        'BINARY_LIMIT' { 'Пустые данные или превышен предел 64 МиБ.' }
        'DISCOVERY_LIMIT' { 'Превышен допустимый объём списка сертификатов.' }
        'SESSION' { 'Сеанс подписи недействителен или уже закрыт.' }
        'PROTOCOL' { 'Получены некорректные данные локального процесса КриптоПро.' }
        default { 'КриптоПро не выполнил операцию. Проверьте носитель и состояние сертификата.' }
    }
    return ('{0} Этап {1}; код {2}; HRESULT {3}.' -f $description, $Stage, $Code, $HResult)
}

function Invoke-ActBridgeExchange {
    param($Transport, [string]$Command, [int]$Kind = 0, [string]$Thumbprint = '', [byte[]]$PdfBytes = $null, [byte[]]$SignatureBytes = $null, [int]$Timeout = 60000)
    $maximum = 24MB
    if ($Command -eq 'SIGN') { $maximum = 90MB }
    if ($Command -in @('CHECK', 'VERIFY')) { $maximum = 4096 }
    if ($Command -eq 'INSPECT') { $maximum = 192KB }
    try {
        $reply = $Transport.Exchange($Command, $Kind, $Thumbprint, $PdfBytes, $SignatureBytes, $Timeout, $maximum)
    } catch {
        $error = $_.Exception
        while ($null -ne $error.InnerException) { $error = $error.InnerException }
        if ($error -is [TimeoutException]) {
            if ($Command -eq 'INSPECT') { throw 'Проверка соседней подписи превысила 60 секунд. Процесс проверки остановлен; документ не считается проверенным.' }
            throw ('Истекло время ожидания КриптоПро ({0} с). Операция остановлена, сеанс закрыт. Начните подписание заново после проверки окна PIN или сертификата.' -f [int]($Timeout / 1000))
        }
        throw 'Windows Script Host (CScript) завершился без корректного ответа. Он может быть недоступен или запрещён политикой Windows; проверьте установленный комплект программы и КриптоПро.'
    }
    if ($reply.Length -lt 5 -or $reply[0] -cne 'ACTSIGNER/1' -or $reply[3] -cne $Command -or $reply[-1] -cne 'END') { throw 'Некорректный ответ локального процесса КриптоПро.' }
    if ($reply[2] -ceq 'ERROR') {
        if ($reply.Length -ne 8 -or $reply[4] -cnotmatch '^[A-Za-z0-9.]{1,64}$' -or $reply[5] -cnotmatch '^[A-Z_]{1,32}$' -or $reply[6] -cnotmatch '^0x[0-9A-F]{8}$') { throw 'Некорректный код ошибки локального процесса КриптоПро.' }
        throw (Get-ActBridgeErrorText $reply[4] $reply[5] $reply[6])
    }
    if ($reply[2] -cne 'OK') { throw 'Локальный процесс КриптоПро не подтвердил операцию.' }
    if ($reply.Length -eq 5) { return ,([string[]]@()) }
    return ,([string[]]$reply[4..($reply.Length - 2)])
}

function Invoke-ActBridgeOnce {
    param([string]$Command, [int]$Kind = 0, [string]$Thumbprint = '', [byte[]]$PdfBytes = $null, [byte[]]$SignatureBytes = $null, [int]$Timeout = 60000)
    $transport = New-ActBridgeTransport
    try {
        $payload = Invoke-ActBridgeExchange $transport $Command $Kind $Thumbprint $PdfBytes $SignatureBytes $Timeout
        try { $transport.Finish(5000) } catch { throw 'Локальный процесс КриптоПро не завершился корректно. Результат не принят.' }
        return ,$payload
    } finally { $transport.Dispose() }
}

function Read-ActBridgeField {
    param([string[]]$Lines, [ref]$Index)
    if ($Index.Value -ge $Lines.Length) { throw 'Неполный ответ локального процесса КриптоПро.' }
    $value = $Lines[$Index.Value]
    $Index.Value++
    return $value
}

function Read-ActBridgeNumber {
    param([string[]]$Lines, [ref]$Index, [int]$Maximum)
    $value = Read-ActBridgeField $Lines $Index
    if ($value -cnotmatch '^(0|[1-9][0-9]{0,8})$') { throw 'Некорректное число в ответе локального процесса КриптоПро.' }
    $number = [long]$value
    if ($number -gt $Maximum) { throw 'Превышен размер ответа локального процесса КриптоПро.' }
    return [int]$number
}

function Read-ActBridgeBlob {
    param([string[]]$Lines, [ref]$Index, [int]$Maximum = 67108864)
    $length = Read-ActBridgeNumber $Lines $Index $Maximum
    if ($length -le 0) { throw 'КриптоПро вернул пустые двоичные данные.' }
    $remaining = [int](4 * [Math]::Ceiling($length / 3.0))
    $chunks = New-Object 'System.Collections.Generic.List[string]'
    while ($remaining -gt 0) {
        $chunk = Read-ActBridgeField $Lines $Index
        $expected = [Math]::Min(49152, $remaining)
        if ($chunk.Length -ne $expected -or $chunk -cnotmatch '^[A-Za-z0-9+/]+={0,2}$') { throw 'Некорректный Base64 в ответе локального процесса КриптоПро.' }
        if ($remaining -gt 49152 -and $chunk.Contains('=')) { throw 'Некорректное завершение Base64.' }
        $chunks.Add($chunk)
        $remaining -= $chunk.Length
    }
    $base64 = [string]::Concat($chunks.ToArray())
    try { [byte[]]$bytes = [Convert]::FromBase64String($base64) } catch { throw 'Не удалось разобрать Base64 локального процесса КриптоПро.' }
    if ($bytes.Length -ne $length -or [Convert]::ToBase64String($bytes) -cne $base64) { throw 'Размер или кодирование данных КриптоПро не совпали с протоколом.' }
    return ,$bytes
}

function Assert-ActBridgeEnd {
    param([string[]]$Lines, [int]$Index)
    if ($Index -ne $Lines.Length) { throw 'Лишние данные в ответе локального процесса КриптоПро.' }
}

function ConvertFrom-ActBridgeCertificate {
    param([int]$Kind, [string]$Thumbprint, [byte[]]$Raw)
    if ($Kind -notin @(2, 100)) { throw 'Неизвестное хранилище сертификата.' }
    $expected = Get-ActNormalizedThumbprint $Thumbprint
    if ([Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Raw) -ne [Security.Cryptography.X509Certificates.X509ContentType]::Cert) {
        throw 'КриптоПро вернул данные, не являющиеся открытым сертификатом X509.'
    }
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($Raw)
    try {
        $actual = Get-ActNormalizedThumbprint $certificate.Thumbprint
        if ($actual -cne $expected) { throw 'Отпечаток открытого сертификата не совпал с ответом КриптоПро.' }
        if ($certificate.GetKeyAlgorithm() -notin @('1.2.643.7.1.1.1.1', '1.2.643.7.1.1.1.2')) { throw 'Требуется сертификат ГОСТ Р 34.10-2012.' }
        $now = [DateTime]::Now
        if ($certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) { throw 'Сертификат находится вне срока действия.' }
        $name = $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $certificate.Subject }
        return [pscustomobject]@{
            Thumbprint = $actual; DisplayName = $name; Subject = $certificate.Subject; Issuer = $certificate.Issuer
            NotBefore = $certificate.NotBefore; NotAfter = $certificate.NotAfter
            Source = $(if ($Kind -eq 100) { 'Контейнер КриптоПро' } else { 'Личное хранилище Windows' })
            StoreKind = $Kind
        }
    } finally { $certificate.Dispose() }
}

function Test-ActCryptoPro {
    try {
        $payload = Invoke-ActBridgeOnce 'CHECK'
        Assert-ActBridgeEnd $payload 0
        return [pscustomobject]@{ Available = $true; Message = '' }
    } catch {
        return [pscustomobject]@{
            Available = $false
            Message = ('Не удалось подготовить КриптоПро через Windows Script Host (CScript). ' + $_.Exception.Message)
        }
    }
}

function Get-ActCertificates {
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    $byThumbprint = @{}
    try {
        $payload = Invoke-ActBridgeOnce 'DISCOVER'
        $index = 0
        $count = Read-ActBridgeNumber $payload ([ref]$index) 4096
        for ($i = 0; $i -lt $count; $i++) {
            $kind = Read-ActBridgeNumber $payload ([ref]$index) 100
            $thumb = Read-ActBridgeField $payload ([ref]$index)
            $raw = Read-ActBridgeBlob $payload ([ref]$index) 1048576
            try {
                $certificate = ConvertFrom-ActBridgeCertificate $kind $thumb $raw
                if (-not $byThumbprint.ContainsKey($certificate.Thumbprint)) { $byThumbprint[$certificate.Thumbprint] = $certificate }
            } catch { $warnings.Add(('Сертификат {0}: {1}' -f ($i + 1), $_.Exception.Message)) }
        }
        $warningCount = Read-ActBridgeNumber $payload ([ref]$index) 64
        for ($i = 0; $i -lt $warningCount; $i++) {
            $kind = Read-ActBridgeNumber $payload ([ref]$index) 100
            if ($kind -notin @(2, 100)) { throw 'Некорректный источник предупреждения КриптоПро.' }
            $stage = Read-ActBridgeField $payload ([ref]$index)
            $code = Read-ActBridgeField $payload ([ref]$index)
            $hr = Read-ActBridgeField $payload ([ref]$index)
            $number = Read-ActBridgeNumber $payload ([ref]$index) 1000000
            if ($stage -cnotmatch '^[A-Za-z0-9.]{1,64}$' -or $code -cnotmatch '^[A-Z_]{1,32}$' -or $hr -cnotmatch '^0x[0-9A-F]{8}$') { throw 'Некорректное предупреждение КриптоПро.' }
            $source = if ($kind -eq 100) { 'Контейнер КриптоПро' } else { 'Личное хранилище Windows' }
            if ($code -eq 'COUNT') {
                if ($byThumbprint.Count -eq 0) { $warnings.Add(('{0}: сертификатов прочитано {1}.' -f $source, $number)) }
            } else {
                $warnings.Add(('{0}: {1} Количество: {2}.' -f $source, (Get-ActBridgeErrorText $stage $code $hr), $number))
            }
        }
        Assert-ActBridgeEnd $payload $index
    } catch {
        # Never expose a partial certificate list from a malformed response.
        $byThumbprint.Clear()
        $warnings.Add($_.Exception.Message)
    }
    return [pscustomobject]@{
        Certificates = @($byThumbprint.Values | Sort-Object DisplayName, NotAfter, Thumbprint)
        Warnings = @($warnings.ToArray())
    }
}

function New-ActCryptoSession {
    param([Parameter(Mandatory = $true)][object]$CertificateInfo)
    $thumbprint = Get-ActNormalizedThumbprint $CertificateInfo.Thumbprint
    $kind = [int]$CertificateInfo.StoreKind
    if ($kind -notin @(2, 100)) { throw 'Неизвестное хранилище сертификата.' }
    $transport = New-ActBridgeTransport
    try {
        $payload = Invoke-ActBridgeExchange $transport 'SELECT' $kind $thumbprint
        $index = 0
        $actualKind = Read-ActBridgeNumber $payload ([ref]$index) 100
        $actualThumb = Read-ActBridgeField $payload ([ref]$index)
        $raw = Read-ActBridgeBlob $payload ([ref]$index) 1048576
        Assert-ActBridgeEnd $payload $index
        if ($actualKind -ne $kind -or $actualThumb -cne $thumbprint) { throw 'КриптоПро выбрал другой сертификат или источник.' }
        $metadata = ConvertFrom-ActBridgeCertificate $kind $thumbprint $raw
        return [pscustomobject]@{
            Transport = $transport; Store = $null; Certificate = $metadata
            Thumbprint = $thumbprint; StoreKind = $kind; Closed = $false
        }
    } catch {
        $transport.Dispose()
        throw
    }
}

function Invoke-ActCryptoSign {
    param([Parameter(Mandatory = $true)][object]$Session, [Parameter(Mandatory = $true)][byte[]]$PdfBytes)
    if ($Session.Closed -or $Session.Transport.IsClosed) { throw 'Сеанс подписи уже закрыт. Начните подписание заново.' }
    if ($PdfBytes.Length -le 0 -or $PdfBytes.Length -gt $script:ActBridgeMaxBytes) { throw 'Размер PDF должен быть от 1 байта до 64 МиБ.' }
    try {
        $thumbprint = Get-ActNormalizedThumbprint $Session.Thumbprint
        $kind = [int]$Session.StoreKind
        if ($kind -notin @(2, 100)) { throw 'Неизвестное хранилище сертификата.' }
        $payload = Invoke-ActBridgeExchange $Session.Transport 'SIGN' $kind $thumbprint $PdfBytes $null 600000
        $index = 0
        [byte[]]$signature = Read-ActBridgeBlob $payload ([ref]$index)
        Assert-ActBridgeEnd $payload $index
        return ,$signature
    } catch {
        $Session.Closed = $true
        $Session.Transport.Dispose()
        throw
    }
}

function Test-ActCryptoSignature {
    param(
        [Parameter(Mandatory = $true)][byte[]]$PdfBytes,
        [Parameter(Mandatory = $true)][byte[]]$SignatureBytes,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )
    if ($PdfBytes.Length -le 0 -or $PdfBytes.Length -gt $script:ActBridgeMaxBytes -or $SignatureBytes.Length -le 0 -or $SignatureBytes.Length -gt $script:ActBridgeMaxBytes) {
        throw 'Некорректный размер PDF или подписи: допустимо от 1 байта до 64 МиБ.'
    }
    $expected = Get-ActNormalizedThumbprint $Thumbprint
    $payload = Invoke-ActBridgeOnce 'VERIFY' 0 $expected $PdfBytes $SignatureBytes 600000
    if ($payload.Length -ne 2 -or $payload[0] -cne '1' -or $payload[1] -cne $expected) { throw 'Проверка подписи не подтвердила единственного выбранного подписанта.' }
}

function ConvertTo-ActExistingSignatureDer {
    param([byte[]]$SignatureBytes)
    # Common detached-signature encodings only. No paths and no content rewriting.
    if ($SignatureBytes.Length -le 0 -or $SignatureBytes.Length -gt $script:ActBridgeMaxBytes) {
        throw [FormatException]::new('Размер соседней подписи должен быть от 1 байта до 64 МиБ.')
    }
    if ($SignatureBytes[0] -eq 0x30) { return ,$SignatureBytes }
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($SignatureBytes) } catch {
        throw [FormatException]::new('Не удалось распознать соседнюю подпись как DER, Base64 или PEM CMS/PKCS7.')
    }
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xfeff) { $text = $text.Substring(1) }
    $text = $text.Trim([char[]]" `t`r`n")
    if ($text.StartsWith('-----BEGIN ')) {
        if ($text -cnotmatch '\A-----BEGIN (PKCS7|CMS)-----[ \t\r\n]*(?<body>[A-Za-z0-9+/= \t\r\n]+)-----END \1-----\z') {
            throw [FormatException]::new('Некорректный PEM: ожидается один полный блок CMS или PKCS7.')
        }
        $text = $Matches['body']
    }
    $base64 = $text -replace '[ \t\r\n]', ''
    if ($base64 -cnotmatch '\A[A-Za-z0-9+/]+={0,2}\z' -or $base64.Length % 4 -ne 0) {
        throw [FormatException]::new('Некорректное кодирование соседней подписи в Base64.')
    }
    try { [byte[]]$raw = [Convert]::FromBase64String($base64) } catch {
        throw [FormatException]::new('Не удалось разобрать соседнюю подпись в Base64.')
    }
    if ($raw.Length -le 0 -or $raw.Length -gt $script:ActBridgeMaxBytes -or $raw[0] -ne 0x30 -or [Convert]::ToBase64String($raw) -cne $base64) {
        throw [FormatException]::new('Соседняя подпись не содержит корректно закодированное сообщение CMS/PKCS7.')
    }
    return ,$raw
}

function Initialize-ActCmsDecoder {
    if ('System.Security.Cryptography.Pkcs.SignedCms' -as [type]) { return }
    try {
        if ($PSVersionTable.PSEdition -eq 'Desktop') { Add-Type -AssemblyName System.Security -ErrorAction Stop }
        else { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    } catch { throw 'Не удалось загрузить системный модуль .NET для чтения CMS/PKCS7. Проверка соседних подписей остановлена.' }
}

function Assert-ActDetachedCmsEnvelope {
    param([byte[]]$SignatureBytes)
    # Decode only. Neither certificate identity nor validity comes from this parser.
    # SignedCms.Detached reflects its constructor, not the decoded envelope.
    Initialize-ActCmsDecoder
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
    try { $cms.Decode($SignatureBytes) } catch {
        throw [FormatException]::new('Соседний файл не удалось разобрать как подписанное сообщение CMS/PKCS7.')
    }
    if ($cms.ContentInfo.ContentType.Value -cne '1.2.840.113549.1.7.1') {
        throw [FormatException]::new('В соседней подписи обнаружен неподдерживаемый тип вложенного содержимого.')
    }
    if ($cms.ContentInfo.Content.Length -ne 0) {
        throw [FormatException]::new('Соседняя подпись содержит вложенный документ. Автоматическая проверка поддерживает отделённые подписи; проверьте этот файл вручную.')
    }
    if ($cms.SignerInfos.Count -lt 1 -or $cms.SignerInfos.Count -gt 4096) {
        throw [FormatException]::new('В соседней подписи отсутствуют подписанты или превышен допустимый предел 4096 подписантов.')
    }
}

function Get-ActExistingSignatureInfo {
    param(
        [Parameter(Mandatory = $true)][byte[]]$PdfBytes,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$SignatureBytes
    )
    if ($PdfBytes.Length -le 0 -or $PdfBytes.Length -gt $script:ActBridgeMaxBytes) { throw 'Размер проверяемого PDF должен быть от 1 байта до 64 МиБ.' }
    try {
        [byte[]]$signature = ConvertTo-ActExistingSignatureDer $SignatureBytes
        Assert-ActDetachedCmsEnvelope $signature
    } catch [FormatException] {
        return [pscustomobject]@{ Status = 'unverifiable'; Thumbprints = [string[]]@(); Message = $_.Exception.Message }
    }
    # A fresh read-only worker; no SELECT/SIGN, certificate store, token or PIN.
    # Transport/timeout/protocol failures deliberately throw, never mean "absent".
    $payload = Invoke-ActBridgeOnce 'INSPECT' 0 '' $PdfBytes $signature 60000
    $index = 0
    $status = Read-ActBridgeField $payload ([ref]$index)
    if ($status -cnotmatch '^(valid|different_content|unverifiable)$') { throw 'Неизвестный результат проверки соседней подписи.' }
    $count = Read-ActBridgeNumber $payload ([ref]$index) 4096
    $thumbprints = New-Object 'System.Collections.Generic.List[string]'
    if ($status -ceq 'valid') {
        if ($count -lt 1) { throw 'КриптоПро не подтвердил ни одного подписанта соседней подписи.' }
        for ($i = 0; $i -lt $count; $i++) {
            $thumbprint = Read-ActBridgeField $payload ([ref]$index)
            if ($thumbprint -cnotmatch '^[0-9A-F]{40}$') { throw 'КриптоПро вернул некорректный отпечаток подписанта соседней подписи.' }
            $thumbprints.Add($thumbprint)
        }
        $message = 'Подпись проверена для этого PDF.'
    } else {
        if ($count -ne 0) { throw 'Неподтверждённая соседняя подпись не должна содержать подтверждённых подписантов.' }
        $stage = Read-ActBridgeField $payload ([ref]$index)
        $code = Read-ActBridgeField $payload ([ref]$index)
        $hresult = Read-ActBridgeField $payload ([ref]$index)
        if ($stage -cnotmatch '^[A-Za-z0-9.]{1,64}$' -or $code -cnotmatch '^[A-Z_]{1,32}$' -or $hresult -cnotmatch '^0x[0-9A-F]{8}$') { throw 'Некорректная диагностика проверки соседней подписи.' }
        if ($status -ceq 'different_content') {
            if ($stage -cne 'SignedData.VerifyCades' -or $code -cne 'NATIVE' -or $hresult -cne '0x80091007') { throw 'КриптоПро не подтвердил несовпадение содержимого соседней подписи.' }
            $message = 'Содержимое соседней подписи не совпало с этим PDF.'
        }
        else { $message = ('Не удалось проверить соседнюю подпись. Этап {0}; код {1}; HRESULT {2}.' -f $stage, $code, $hresult) }
    }
    Assert-ActBridgeEnd $payload $index
    return [pscustomobject]@{ Status = $status; Thumbprints = [string[]]$thumbprints.ToArray(); Message = $message }
}

function Close-ActCryptoSession {
    param([object]$Session)
    if ($null -eq $Session) { return }
    if (-not $Session.Closed) {
        $Session.Closed = $true
        try { if (-not $Session.Transport.IsClosed) { $Session.Transport.Finish(5000) } } catch { }
    }
    if ($null -ne $Session.Transport) { $Session.Transport.Dispose() }
    $Session.Certificate = $null
    $Session.Store = $null
}

Export-ModuleMember -Function Test-ActCryptoPro, Get-ActCertificates, New-ActCryptoSession, Invoke-ActCryptoSign, Test-ActCryptoSignature, Get-ActExistingSignatureInfo, Close-ActCryptoSession
