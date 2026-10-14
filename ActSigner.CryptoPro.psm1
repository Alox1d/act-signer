#requires -Version 5.1
Set-StrictMode -Version 2.0

$script:ActBridgeMaxBytes = 64MB
$script:ActBridgeScript = Join-Path $PSScriptRoot 'ActSigner.CryptoPro.js'

# Native CScript owns all CAdESCOM objects. PowerShell exchanges only public
# certificate data, file snapshots and signatures through inherited local pipes.
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
        private static readonly object inputEncodingSync = new object();
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
                if (!StartWithoutInputPreamble(process)) throw new IOException("The script host did not start.");
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

        private static bool StartWithoutInputPreamble(Process target) {
            // .NET Framework creates an AutoFlush stdin writer during Start.
            // A BOM-bearing Console.InputEncoding writes a preamble before our
            // UTF-16LE writer takes over the pipe. Keep that prefix out of the
            // wire without changing the caller's encoding or buffered reader.
            lock (inputEncodingSync) {
                Encoding originalEncoding = Console.InputEncoding;
                if (originalEncoding.GetPreamble().Length == 0) return target.Start();
                Encoding startupEncoding;
                switch (originalEncoding.CodePage) {
                    case 65001: startupEncoding = new UTF8Encoding(false); break;
                    case 1200: startupEncoding = new UnicodeEncoding(false, false); break;
                    case 1201: startupEncoding = new UnicodeEncoding(true, false); break;
                    case 12000: startupEncoding = new UTF32Encoding(false, false); break;
                    case 12001: startupEncoding = new UTF32Encoding(true, false); break;
                    default: throw new IOException("Unsupported console input preamble.");
                }
                TextReader originalInput = Console.In;
                try {
                    // Keep the code page: UnicodeLE Console.InputEncoding setters
                    // skip SetConsoleCP, so changing to UTF-8 would leak native CP.
                    Console.InputEncoding = startupEncoding;
                    return target.Start();
                } finally {
                    try { Console.InputEncoding = originalEncoding; }
                    finally { Console.SetIn(originalInput); }
                }
            }
        }

        private static async Task DrainAsync(StreamReader reader) {
            // Drain continuously, retain no host/provider stderr or personal paths.
            try {
                char[] buffer = new char[4096];
                while (await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false) != 0) { }
            } catch { }
        }

        private async Task WriteBlobAsync(byte[] bytes, bool allowEmpty) {
            if (bytes == null || (!allowEmpty && bytes.Length == 0) || bytes.Length > 67108864)
                throw new InvalidDataException("Invalid binary length.");
            await input.WriteLineAsync(bytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)).ConfigureAwait(false);
            for (int offset = 0; offset < bytes.Length; offset += ChunkBytes) {
                int length = Math.Min(ChunkBytes, bytes.Length - offset);
                await input.WriteLineAsync(Convert.ToBase64String(bytes, offset, length)).ConfigureAwait(false);
            }
        }

        private async Task WriteRequestAsync(string id, string command, int kind, string thumbprint, byte[] pdf, byte[] signature) {
            if (command == "VERIFYEMPTY" && ((kind != 101 && kind != 102) || pdf == null || pdf.Length != 0))
                throw new InvalidDataException("Invalid empty-file verification request.");
            await input.WriteLineAsync("ACTSIGNER/1").ConfigureAwait(false);
            await input.WriteLineAsync(id).ConfigureAwait(false);
            await input.WriteLineAsync(command).ConfigureAwait(false);
            if (command == "SELECT" || command == "SIGN") {
                await input.WriteLineAsync(kind.ToString(System.Globalization.CultureInfo.InvariantCulture)).ConfigureAwait(false);
                await input.WriteLineAsync(thumbprint).ConfigureAwait(false);
            }
            if (command == "VERIFY" || command == "VERIFYEMPTY") await input.WriteLineAsync(thumbprint).ConfigureAwait(false);
            if (command == "VERIFYEMPTY") await input.WriteLineAsync(kind.ToString(System.Globalization.CultureInfo.InvariantCulture)).ConfigureAwait(false);
            if (command == "SIGN" || command == "VERIFY" || command == "VERIFYEMPTY" || command == "INSPECT") await WriteBlobAsync(pdf, true).ConfigureAwait(false);
            if (command == "VERIFY" || command == "VERIFYEMPTY" || command == "INSPECT") await WriteBlobAsync(signature, false).ConfigureAwait(false);
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
        'BINARY_LIMIT' { 'Некорректный размер данных. Предел для файла и подписи - 64 МиБ.' }
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
    if ($Command -in @('CHECK', 'VERIFY', 'VERIFYEMPTY')) { $maximum = 4096 }
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
        $failure=[InvalidOperationException]::new((Get-ActBridgeErrorText $reply[4] $reply[5] $reply[6]))
        if($Command -in @('SELECT','SIGN','VERIFY','VERIFYEMPTY')) {
            $failure.Data['ActSignerFailure']=if($reply[6] -in @('0x80090036','0x8010006E','0x800704C7')){'cancelled'}else{'session'}
        }
        throw $failure
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
            StoreKind = $Kind; FileLabel = $(Initialize-ActNativeCmsInspector; [ActSigner.NativeCmsInspector]::FileLabel($Raw))
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
    param([Parameter(Mandatory = $true)][object]$Session, [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$PdfBytes)
    if ($Session.Closed -or $Session.Transport.IsClosed) { throw 'Сеанс подписи уже закрыт. Начните подписание заново.' }
    if ($PdfBytes.Length -gt $script:ActBridgeMaxBytes) { throw 'Размер файла не должен превышать 64 МиБ.' }
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

function Get-ActEmptySignatureHashAlgorithm {
    param([AllowEmptyCollection()][object[]]$Signers, [string]$Thumbprint)
    if ($Signers.Count -ne 1 -or $Signers[0].SignatureStatus -cne 'valid' -or $Signers[0].Thumbprint -cne $Thumbprint) {
        throw 'Математическая проверка пустого файла не подтвердила единственного выбранного подписанта.'
    }
    # This OID belongs to the actual mathematically verified embedded signer.
    # The algorithm used by the certificate issuer is unrelated to this choice.
    switch ($Signers[0].PublicKeyOid) {
        '1.2.643.7.1.1.1.1' { return 101 }
        '1.2.643.7.1.1.1.2' { return 102 }
        default { throw 'Для проверки новой подписи пустого файла требуется публичный ключ ГОСТ Р 34.10-2012.' }
    }
}

function Test-ActCryptoSignature {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$PdfBytes,
        [Parameter(Mandatory = $true)][byte[]]$SignatureBytes,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )
    if ($PdfBytes.Length -gt $script:ActBridgeMaxBytes -or $SignatureBytes.Length -le 0 -or $SignatureBytes.Length -gt $script:ActBridgeMaxBytes) {
        throw 'Файл не должен превышать 64 МиБ; размер подписи должен быть от 1 байта до 64 МиБ.'
    }
    $expected = Get-ActNormalizedThumbprint $Thumbprint
    if ($PdfBytes.Length -eq 0) {
        try {
            Initialize-ActNativeCmsInspector
            $native = @([ActSigner.NativeCmsInspector]::Inspect($PdfBytes, $SignatureBytes))
            $algorithm = Get-ActEmptySignatureHashAlgorithm $native $expected
        } catch {
            $failure = [InvalidOperationException]::new('Подпись пустого файла не прошла математическую проверку выбранного подписанта или содержит неподдерживаемый публичный ключ.')
            $failure.Data['ActSignerFailure'] = 'session'
            throw $failure
        }
        # Additive command: legacy VERIFY frames and nonempty-file behavior stay
        # compatible. No installed certificate store is needed for verification.
        $payload = Invoke-ActBridgeOnce 'VERIFYEMPTY' $algorithm $expected $PdfBytes $SignatureBytes 600000
    } else {
        $payload = Invoke-ActBridgeOnce 'VERIFY' 0 $expected $PdfBytes $SignatureBytes 600000
    }
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

function Initialize-ActNativeCmsInspector {
    if ('ActSigner.NativeCmsInspector' -as [type]) { return }
    Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
namespace ActSigner {
    public sealed class NativeCmsSigner {
        public string Thumbprint, SignatureStatus, HResult, PublicKeyOid;
        public DateTime NotBeforeUtc, NotAfterUtc;
    }
    // Read-only CryptoAPI: no user stores, chain validation, private keys or PIN.
    public static class NativeCmsInspector {
        const uint Encoding = 0x10001, SignerIdParam = 38, FindCertId = 0x100000;
        const int MaxCount = 4096, MaxBytes = 67108864;
        [StructLayout(LayoutKind.Sequential)] struct VerifyPara {
            public uint Size, Encoding;
            public IntPtr Provider, Callback, Arg;
        }
        [DllImport("crypt32.dll", SetLastError=true)] static extern IntPtr CryptMsgOpenToDecode(uint encoding, uint flags, uint type, IntPtr provider, IntPtr recipient, IntPtr stream);
        [DllImport("crypt32.dll", SetLastError=true)] static extern bool CryptMsgUpdate(IntPtr message, byte[] bytes, uint length, bool final);
        [DllImport("crypt32.dll", SetLastError=true)] static extern bool CryptMsgGetParam(IntPtr message, uint type, uint index, IntPtr data, ref uint length);
        [DllImport("crypt32.dll")] static extern bool CryptMsgClose(IntPtr message);
        [DllImport("crypt32.dll", SetLastError=true)] static extern IntPtr CertOpenStore(IntPtr provider, uint encoding, IntPtr crypto, uint flags, IntPtr data);
        [DllImport("crypt32.dll", SetLastError=true)] static extern bool CertAddEncodedCertificateToStore(IntPtr store, uint encoding, byte[] bytes, uint length, uint disposition, IntPtr context);
        [DllImport("crypt32.dll", SetLastError=true)] static extern IntPtr CertFindCertificateInStore(IntPtr store, uint encoding, uint flags, uint type, IntPtr criteria, IntPtr previous);
        [DllImport("crypt32.dll")] static extern bool CertFreeCertificateContext(IntPtr context);
        [DllImport("crypt32.dll")] static extern bool CertCloseStore(IntPtr store, uint flags);
        [DllImport("crypt32.dll", SetLastError=true)] static extern bool CryptVerifyDetachedMessageSignature(ref VerifyPara parameters, uint index, byte[] signature, uint signatureLength, uint count, IntPtr[] contents, uint[] lengths, out IntPtr signer);

        [DllImport("crypt32.dll", CharSet=CharSet.Unicode)] static extern uint CertGetNameString(IntPtr certificate, uint type, uint flags, [MarshalAs(UnmanagedType.LPStr)] string attribute, System.Text.StringBuilder text, uint size);
        public static string FileLabel(byte[] raw) {
            using (var certificate = new X509Certificate2(raw)) {
                string fallback = "cert_" + certificate.Thumbprint.Substring(0,12).ToLowerInvariant();
                uint count = CertGetNameString(certificate.Handle, 3, 0, "2.5.4.4", null, 0);
                if (count < 2 || count > 1024) return fallback;
                var text = new System.Text.StringBuilder((int)count);
                if (CertGetNameString(certificate.Handle, 3, 0, "2.5.4.4", text, count) != count) return fallback;
                string alphabet = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя";
                string[] latin = {"a","b","v","g","d","e","e","zh","z","i","y","k","l","m","n","o","p","r","s","t","u","f","kh","ts","ch","sh","shch","","y","","e","yu","ya"};
                var label = new System.Text.StringBuilder();
                foreach (char c in text.ToString().ToLowerInvariant()) {
                    int i = alphabet.IndexOf(c);
                    if (i >= 0) label.Append(latin[i]);
                    else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') label.Append(c);
                    else label.Append('_');
                }
                string value = System.Text.RegularExpressions.Regex.Replace(label.ToString(), "_+", "_").Trim('_','-');
                if (value.Length > 80) value = value.Substring(0,80).TrimEnd('_','-');
                return value.Length == 0 ? fallback : value;
            }
        }
        static void Native(bool success) { if (!success) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        static IntPtr Parameter(IntPtr message, uint type, uint index, out uint length) {
            length = 0; Native(CryptMsgGetParam(message, type, index, IntPtr.Zero, ref length));
            if (length > MaxBytes) throw new FormatException("CMS_PARAMETER_LIMIT");
            IntPtr memory = Marshal.AllocHGlobal((int)Math.Max(1, length));
            try { Native(CryptMsgGetParam(message, type, index, memory, ref length)); return memory; }
            catch { Marshal.FreeHGlobal(memory); throw; }
        }
        static byte[] Bytes(IntPtr message, uint type, uint index) {
            uint length; IntPtr memory = Parameter(message, type, index, out length);
            try { byte[] bytes = new byte[length]; Marshal.Copy(memory, bytes, 0, (int)length); return bytes; }
            finally { Marshal.FreeHGlobal(memory); }
        }
        static uint Number(IntPtr message, uint type) {
            byte[] bytes = Bytes(message, type, 0);
            if (bytes.Length != 4) throw new FormatException("CMS_NUMBER");
            return BitConverter.ToUInt32(bytes, 0);
        }
        // CryptoAPI can accept a valid message prefix. Require exactly one BER envelope,
        // including the indefinite-length form produced by installed CryptoPro.
        static void EnvelopeEnd(byte[] bytes, ref int offset, int depth, ref int nodes) {
            if (depth > 64 || ++nodes > 65536 || offset >= bytes.Length) throw new FormatException("CMS_ENVELOPE_LIMIT");
            int tag = bytes[offset++];
            if (tag == 0) throw new FormatException("CMS_UNEXPECTED_EOC");
            if ((tag & 31) == 31) {
                int size = 0, part;
                do { if (offset >= bytes.Length || ++size > 8) throw new FormatException("CMS_TAG"); part = bytes[offset++]; } while ((part & 128) != 0);
            }
            if (offset >= bytes.Length) throw new FormatException("CMS_LENGTH");
            int first = bytes[offset++];
            if (first == 128) {
                if ((tag & 32) == 0) throw new FormatException("CMS_PRIMITIVE_INDEFINITE");
                while (true) {
                    if (offset + 1 >= bytes.Length) throw new FormatException("CMS_MISSING_EOC");
                    if (bytes[offset] == 0 && bytes[offset + 1] == 0) { offset += 2; return; }
                    EnvelopeEnd(bytes, ref offset, depth + 1, ref nodes);
                }
            }
            long length = first;
            if ((first & 128) != 0) {
                int count = first & 127;
                if (count == 0 || count > 4 || offset + count > bytes.Length) throw new FormatException("CMS_LENGTH");
                length = 0;
                for (int i = 0; i < count; i++) length = (length << 8) | bytes[offset++];
            }
            if (length > bytes.Length - offset) throw new FormatException("CMS_TRUNCATED");
            offset += (int)length;
        }
        // Read only the bounded CMS path needed to distinguish absent eContent
        // from explicit empty eContent. Preserve BER indefinite containers.
        static int ContentElement(byte[] bytes, ref int offset, int limit, int tag, out int contentEnd) {
            int start = offset;
            if (start >= limit || bytes[start] != tag) throw new FormatException("CMS_CONTENT_INFO");
            int end = start, nodes = 0;
            EnvelopeEnd(bytes, ref end, 0, ref nodes);
            if (end > limit) throw new FormatException("CMS_CONTENT_INFO");
            int first = bytes[start + 1], content = start + 2;
            if (first == 128) contentEnd = end - 2;
            else {
                if ((first & 128) != 0) content += first & 127;
                contentEnd = end;
            }
            if (content > contentEnd) throw new FormatException("CMS_CONTENT_INFO");
            offset = end;
            return content;
        }
        static void RequireDetachedContent(byte[] signature) {
            int cursor = 0, outerEnd, ignored;
            int outer = ContentElement(signature, ref cursor, signature.Length, 0x30, out outerEnd);
            cursor = outer;
            ContentElement(signature, ref cursor, outerEnd, 0x06, out ignored);
            int wrapperEnd;
            int wrapper = ContentElement(signature, ref cursor, outerEnd, 0xa0, out wrapperEnd);
            if (cursor != outerEnd) throw new FormatException("CMS_CONTENT_INFO");
            cursor = wrapper;
            int signedEnd;
            int signed = ContentElement(signature, ref cursor, wrapperEnd, 0x30, out signedEnd);
            if (cursor != wrapperEnd) throw new FormatException("CMS_CONTENT_INFO");
            cursor = signed;
            ContentElement(signature, ref cursor, signedEnd, 0x02, out ignored);
            ContentElement(signature, ref cursor, signedEnd, 0x31, out ignored);
            int infoEnd;
            int info = ContentElement(signature, ref cursor, signedEnd, 0x30, out infoEnd);
            cursor = info;
            ContentElement(signature, ref cursor, infoEnd, 0x06, out ignored);
            if (cursor != infoEnd) throw new FormatException("CMS_NOT_DETACHED_DATA");
        }
        public static NativeCmsSigner[] Inspect(byte[] pdf, byte[] signature) {
            if (pdf == null || signature == null || signature.Length < 1 || pdf.Length > MaxBytes || signature.Length > MaxBytes) throw new FormatException("CMS_SIZE");
            int end = 0, nodes = 0;
            if (signature[0] != 0x30) throw new FormatException("CMS_NOT_SEQUENCE");
            EnvelopeEnd(signature, ref end, 0, ref nodes);
            if (end != signature.Length) throw new FormatException("CMS_TRAILING_BYTES");
            RequireDetachedContent(signature);
            IntPtr message = IntPtr.Zero, store = IntPtr.Zero;
            var certificates = new List<X509Certificate2>();
            try {
                message = CryptMsgOpenToDecode(Encoding, 0, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (message == IntPtr.Zero) Native(false);
                Native(CryptMsgUpdate(message, signature, (uint)signature.Length, true));
                if (Number(message, 1) != 2) throw new FormatException("CMS_NOT_SIGNED");
                string oid = System.Text.Encoding.ASCII.GetString(Bytes(message, 4, 0)).TrimEnd('\0');
                if (oid != "1.2.840.113549.1.7.1" || Bytes(message, 2, 0).Length != 0) throw new FormatException("CMS_NOT_DETACHED_DATA");
                uint count = Number(message, 5), certCount = Number(message, 11);
                if (count < 1 || count > MaxCount || certCount > MaxCount) throw new FormatException("CMS_COUNT");
                // Bound repeated native hashing of an untrusted multi-signer file.
                if ((long)pdf.Length * count > 512L * 1024 * 1024) throw new FormatException("CMS_WORK_LIMIT");
                store = CertOpenStore(new IntPtr(2), 0, IntPtr.Zero, 0x2000, IntPtr.Zero); // memory store
                if (store == IntPtr.Zero) Native(false);
                for (uint i = 0; i < certCount; i++) {
                    byte[] certificate = Bytes(message, 12, i);
                    if (certificate.Length > 1048576) throw new FormatException("CMS_CERTIFICATE_LIMIT");
                    // ADD_ALWAYS preserves ambiguous issuer/serial or key-ID matches.
                    Native(CertAddEncodedCertificateToStore(store, Encoding, certificate, (uint)certificate.Length, 4, IntPtr.Zero));
                }
                for (uint i = 0; i < count; i++) {
                    uint length; IntPtr id = Parameter(message, SignerIdParam, i, out length), context = IntPtr.Zero;
                    X509Certificate2 selected = null; string selectedRaw = null;
                    try {
                        int matches = 0;
                        while (true) {
                            IntPtr previous = context; context = IntPtr.Zero;
                            context = CertFindCertificateInStore(store, Encoding, 0, FindCertId, id, previous);
                            if (context == IntPtr.Zero) {
                                if (unchecked((uint)Marshal.GetLastWin32Error()) != 0x80092004) Native(false);
                                break;
                            }
                            if (++matches > MaxCount) throw new FormatException("CMS_CERTIFICATE_LIMIT");
                            using (var candidate = new X509Certificate2(context)) {
                                string raw = Convert.ToBase64String(candidate.RawData);
                                if (selectedRaw != null && selectedRaw != raw) throw new FormatException("CMS_AMBIGUOUS_SIGNER");
                                if (selected == null) { selected = new X509Certificate2(candidate.RawData); selectedRaw = raw; }
                            }
                        }
                        if (selected == null) throw new FormatException("CMS_MISSING_SIGNER_CERTIFICATE");
                        certificates.Add(selected); selected = null;
                    } finally {
                        if (selected != null) selected.Dispose();
                        if (context != IntPtr.Zero) CertFreeCertificateContext(context);
                        Marshal.FreeHGlobal(id);
                    }
                }
                var result = new NativeCmsSigner[count];
                var pin = GCHandle.Alloc(pdf, GCHandleType.Pinned);
                try {
                    for (uint i = 0; i < count; i++) {
                        var certificate = certificates[(int)i]; IntPtr actual = IntPtr.Zero;
                        var item = new NativeCmsSigner { Thumbprint = certificate.Thumbprint, SignatureStatus = "unverifiable", HResult = "0x00000000", NotBeforeUtc = certificate.NotBefore.ToUniversalTime(), NotAfterUtc = certificate.NotAfter.ToUniversalTime() };
                        try {
                            var parameters = new VerifyPara { Size = (uint)Marshal.SizeOf(typeof(VerifyPara)), Encoding = Encoding };
                            bool verified = CryptVerifyDetachedMessageSignature(ref parameters, i, signature, (uint)signature.Length, 1, new[] { pin.AddrOfPinnedObject() }, new[] { (uint)pdf.Length }, out actual);
                            int error = verified ? 0 : Marshal.GetLastWin32Error();
                            if (verified && actual != IntPtr.Zero) {
                                using (var actualCertificate = new X509Certificate2(actual)) {
                                    if (Convert.ToBase64String(actualCertificate.RawData) != Convert.ToBase64String(certificate.RawData)) throw new FormatException("CMS_SIGNER_MISMATCH");
                                    item.PublicKeyOid = actualCertificate.PublicKey.Oid.Value;
                                }
                                item.SignatureStatus = "valid";
                            } else item.HResult = "0x" + error.ToString("X8");
                        } finally { if (actual != IntPtr.Zero) CertFreeCertificateContext(actual); }
                        result[i] = item;
                    }
                } finally { pin.Free(); }
                return result;
            } finally {
                foreach (var certificate in certificates) certificate.Dispose();
                if (store != IntPtr.Zero) CertCloseStore(store, 0);
                if (message != IntPtr.Zero) CryptMsgClose(message);
            }
        }
    }
}
'@
}

function Get-ActExistingSignatureInfo {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$PdfBytes,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$SignatureBytes
    )
    if ($PdfBytes.Length -gt $script:ActBridgeMaxBytes) { throw 'Размер проверяемого файла не должен превышать 64 МиБ.' }
    try {
        [byte[]]$signature = ConvertTo-ActExistingSignatureDer $SignatureBytes
        Initialize-ActNativeCmsInspector
        $signers = [ActSigner.NativeCmsInspector]::Inspect($PdfBytes, $signature)
        return [pscustomobject]@{
            Status = 'identified'; Signers = @($signers)
            Thumbprints = @($signers | Where-Object { $_.SignatureStatus -ceq 'valid' } | ForEach-Object { $_.Thumbprint })
            TrustStatus = 'not_checked'
            Message = 'Состав подписантов установлен. Математическая проверка выполнена отдельно; доверие, сроки цепочки и отзыв не проверялись.'
        }
    } catch [FormatException] {
        return [pscustomobject]@{ Status = 'unverifiable'; Signers = @(); Thumbprints = @(); TrustStatus = 'not_checked'; Message = $_.Exception.Message }
    } catch {
        $error = $_.Exception
        while ($null -ne $error.InnerException) { $error = $error.InnerException }
        $detail = 'CMS_DECODE'
        if ($error -is [FormatException] -and $error.Message -cmatch '^CMS_[A-Z_]+$') { $detail = $error.Message }
        $hr = '0x{0:X8}' -f ([long]$error.HResult -band 4294967295L)
        if ($error -is [ComponentModel.Win32Exception]) { $hr = '0x{0:X8}' -f ([long]$error.NativeErrorCode -band 4294967295L) }
        return [pscustomobject]@{ Status = 'unverifiable'; Signers = @(); Thumbprints = @(); TrustStatus = 'not_checked'; Message = ('Не удалось надёжно определить всех подписантов CMS. Код {0}; HRESULT {1}. Автоматическое подписание этого файла запрещено.' -f $detail, $hr) }
    }

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
