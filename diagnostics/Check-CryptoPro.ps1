#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Worker,
    [ValidateSet('Info', 'CurrentUserReadOnly', 'ContainerReadOnly', 'DefaultOpen', 'CurrentUserLocationOnly', 'CurrentUserMaximumAllowed', 'MemoryReadOnly')]
    [string]$Case = 'Info'
)

$ErrorActionPreference = 'Stop'
$script:ReportWriter = $null
$script:ProbeRoot = $PSScriptRoot
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding -ArgumentList $false } catch { }

function Write-ProbeLine {
    param([AllowEmptyString()][string]$Text)
    [Console]::WriteLine($Text)
}

function Write-ProbeError {
    param([string]$Stage, [System.Exception]$Exception)
    Write-ProbeLine ($Stage + '.status=ERROR')
    $current = $Exception
    $index = 0
    while (($null -ne $current) -and ($index -lt 8)) {
        $hr = '0x{0:X8}' -f ([long]$current.HResult -band 4294967295L)
        Write-ProbeLine ('{0}.error[{1}].type={2}' -f $Stage, $index, $current.GetType().FullName)
        Write-ProbeLine ('{0}.error[{1}].hresult={2}' -f $Stage, $index, $hr)
        # Do not write Message, Data, Source or StackTrace: they may contain personal data.
        $current = $current.InnerException
        $index++
    }
}

function Get-ProcessArchitecture {
    $value = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')
    switch ($value) {
        'AMD64' { return 'x64' }
        'x86' { return 'x86' }
        'ARM64' { return 'arm64' }
        'ARM' { return 'arm' }
        default { return 'unknown' }
    }
}

function Write-RuntimeInfo {
    Write-ProbeLine ('Runtime.PowerShell={0}' -f $PSVersionTable.PSVersion)
    Write-ProbeLine ('Runtime.CLR={0}' -f [Environment]::Version)
    Write-ProbeLine ('Runtime.ProcessBits={0}' -f ([IntPtr]::Size * 8))
    Write-ProbeLine ('Runtime.ProcessArchitecture={0}' -f (Get-ProcessArchitecture))
    Write-ProbeLine ('Runtime.OS64Bit={0}' -f [Environment]::Is64BitOperatingSystem)
    Write-ProbeLine ('Runtime.Apartment={0}' -f [Threading.Thread]::CurrentThread.GetApartmentState())
    Write-ProbeLine ('Windows.Version={0}' -f [Environment]::OSVersion.Version)
    $baseKey = $null
    $versionKey = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
        $versionKey = $baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion', $false)
        if ($null -eq $versionKey) {
            Write-ProbeLine 'Windows.Registry=NOT_FOUND'
        } else {
            foreach ($name in @('ProductName', 'DisplayVersion', 'CurrentBuildNumber', 'UBR')) {
                $value = $versionKey.GetValue($name, $null)
                if ($null -ne $value) { Write-ProbeLine ('Windows.{0}={1}' -f $name, $value) }
            }
        }
    } catch {
        Write-ProbeError 'Windows.Registry' $_.Exception
    } finally {
        if ($null -ne $versionKey) { $versionKey.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

function Write-ComRegistration {
    $baseKey = $null
    $classKey = $null
    $serverKey = $null
    $curVerKey = $null
    try {
        $view = [Microsoft.Win32.RegistryView]::Registry32
        if ([Environment]::Is64BitProcess) { $view = [Microsoft.Win32.RegistryView]::Registry64 }
        Write-ProbeLine ('COM.RegistryView={0}' -f $view)
        Write-ProbeLine 'COM.ProgID=CAdESCOM.Store'
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::ClassesRoot, $view)
        $classKey = $baseKey.OpenSubKey('CAdESCOM.Store\CLSID', $false)
        if ($null -eq $classKey) {
            $curVerKey = $baseKey.OpenSubKey('CAdESCOM.Store\CurVer', $false)
            if ($null -ne $curVerKey) {
                $versionedProgId = [string]$curVerKey.GetValue('', '')
                if ($versionedProgId -match '^CAdESCOM\.Store\.\d+$') {
                    Write-ProbeLine ('COM.CurVer={0}' -f $versionedProgId)
                    $classKey = $baseKey.OpenSubKey(($versionedProgId + '\CLSID'), $false)
                }
            }
        }
        if ($null -eq $classKey) {
            Write-ProbeLine 'COM.Registration=NOT_FOUND'
            return
        }
        $clsid = [Guid]::Empty
        $rawClsid = [string]$classKey.GetValue('', '')
        if (-not [Guid]::TryParse($rawClsid, [ref]$clsid)) {
            Write-ProbeLine 'COM.Registration=INVALID_CLSID'
            return
        }
        Write-ProbeLine ('COM.CLSID={0}' -f $clsid.ToString('B'))
        $serverKey = $baseKey.OpenSubKey(('CLSID\' + $clsid.ToString('B') + '\InprocServer32'), $false)
        if ($null -eq $serverKey) {
            Write-ProbeLine 'COM.InprocServer32=NOT_FOUND'
            return
        }
        Write-ProbeLine 'COM.InprocServer32=PRESENT'
        $rawPath = [string]$serverKey.GetValue('', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $dllPath = [Environment]::ExpandEnvironmentVariables($rawPath).Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($dllPath)) {
            Write-ProbeLine 'DLL.Path=EMPTY'
            return
        }
        Write-ProbeLine ('DLL.FileName={0}' -f [IO.Path]::GetFileName($dllPath))
        $exists = [IO.File]::Exists($dllPath)
        Write-ProbeLine ('DLL.Exists={0}' -f $exists)
        if ($exists) {
            $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($dllPath)
            Write-ProbeLine ('DLL.FileVersion={0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart)
            Write-ProbeLine ('DLL.ProductVersion={0}.{1}.{2}.{3}' -f $info.ProductMajorPart, $info.ProductMinorPart, $info.ProductBuildPart, $info.ProductPrivatePart)
        }
    } catch {
        Write-ProbeError 'COM.Registration' $_.Exception
    } finally {
        if ($null -ne $serverKey) { $serverKey.Dispose() }
        if ($null -ne $classKey) { $classKey.Dispose() }
        if ($null -ne $curVerKey) { $curVerKey.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

function Write-DotNetStoreCount {
    $store = $null
    $opened = $false
    $stage = 'DotNet.Create'
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList @(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        $flags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
        Write-ProbeLine 'DotNet.Store=CurrentUser/My'
        Write-ProbeLine 'DotNet.Flags=ReadOnly|OpenExistingOnly'
        $stage = 'DotNet.Open'
        $store.Open($flags)
        $opened = $true
        Write-ProbeLine 'DotNet.Open.status=OK'
        $stage = 'DotNet.Certificates.Count'
        $certificates = $store.get_Certificates()
        $count = $certificates.get_Count()
        Write-ProbeLine ('DotNet.Certificates.Count={0}' -f $count)
    } catch {
        Write-ProbeError $stage $_.Exception
    } finally {
        if ($null -ne $store) {
            if ($opened) {
                try {
                    $store.Close()
                    Write-ProbeLine 'DotNet.Close.status=OK'
                } catch { Write-ProbeError 'DotNet.Close' $_.Exception }
            }
            try { $store.Dispose() } catch { Write-ProbeError 'DotNet.Dispose' $_.Exception }
        }
    }
}

function Invoke-DirectComProbe {
    param([string]$ProbeCase)
    $store = $null
    $opened = $false
    $failed = $false
    $stage = 'Create'
    Write-ProbeLine ('Probe.Case={0}' -f $ProbeCase)
    Write-ProbeLine 'Probe.Host=PowerShell'
    Write-ProbeLine ('Probe.ProcessBits={0}' -f ([IntPtr]::Size * 8))
    Write-ProbeLine ('Probe.ProcessArchitecture={0}' -f (Get-ProcessArchitecture))
    try {
        $store = New-Object -ComObject 'CAdESCOM.Store' -ErrorAction Stop
        Write-ProbeLine 'Create.status=OK'
        $stage = 'Open'
        # These are intentionally direct COM calls, independent of the application helpers.
        switch ($ProbeCase) {
            'CurrentUserReadOnly' { [void]$store.Open([int]2, 'My', [int]0) }
            'ContainerReadOnly' { [void]$store.Open([int]100, 'My', [int]0) }
            'DefaultOpen' { [void]$store.Open() }
            'CurrentUserLocationOnly' { [void]$store.Open([int]2) }
            'CurrentUserMaximumAllowed' { [void]$store.Open([int]2, 'My', [int]2) }
            'MemoryReadOnly' { [void]$store.Open([int]0, 'My', [int]0) }
            default { throw (New-Object System.ArgumentException -ArgumentList 'Unknown probe case.') }
        }
        $opened = $true
        Write-ProbeLine 'Open.status=OK'
        $stage = 'Certificates'
        # Calling the PS property getter as a method keeps getter exceptions visible.
        # A plain .Certificates.Count chain can silently turn a failed getter into zero.
        $certificates = $store.PSObject.Properties['Certificates'].get_Value()
        if ($null -eq $certificates) { throw (New-Object InvalidOperationException -ArgumentList 'Certificates returned null.') }
        $stage = 'Certificates.Count'
        $countValue = $certificates.PSObject.Properties['Count'].get_Value()
        if ($null -eq $countValue) { throw (New-Object InvalidOperationException -ArgumentList 'Count returned null.') }
        $count = [int]$countValue
        Write-ProbeLine ('Certificates.Count={0}' -f $count)
    } catch {
        $failed = $true
        Write-ProbeError $stage $_.Exception
    } finally {
        if ($opened) {
            try {
                [void]$store.Close()
                Write-ProbeLine 'Close.status=OK'
            } catch {
                $failed = $true
                Write-ProbeError 'Close' $_.Exception
            }
        }
        # Each worker exits immediately. Its process owns and releases all COM objects.
        $store = $null
    }
    if ($failed) { return 1 }
    return 0
}

function Protect-ReportText {
    param([AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    # Also sanitize unexpected host-level stderr, which can include the script path.
    if (-not [string]::IsNullOrEmpty($script:ProbeRoot)) {
        $Text = [regex]::Replace($Text, [regex]::Escape($script:ProbeRoot), '[SCRIPT_DIR]', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $profilePath = [Environment]::GetEnvironmentVariable('USERPROFILE')
    if (-not [string]::IsNullOrEmpty($profilePath)) {
        $Text = [regex]::Replace($Text, [regex]::Escape($profilePath), '[USERPROFILE]', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $Text = [regex]::Replace($Text, '(?i)[A-Z]:\\Users\\[^\\\r\n"<>]+', '[USERPROFILE]')
    return $Text
}

function Write-ReportLine {
    param([AllowEmptyString()][string]$Text)
    $safeText = Protect-ReportText $Text
    if ($null -ne $script:ReportWriter) { $script:ReportWriter.WriteLine($safeText) }
    [Console]::WriteLine($safeText)
}

function ConvertTo-ProcessArgument {
    param([AllowEmptyString()][string]$Value)
    # Windows CommandLineToArgvW/CRT quoting. No cmd.exe or shell is involved.
    if ($null -eq $Value) { $Value = '' }
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append([char]34)
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) {
            $slashes++
            continue
        }
        if ($character -eq [char]34) {
            [void]$builder.Append([char]92, [int]($slashes * 2 + 1))
            [void]$builder.Append([char]34)
        } else {
            if ($slashes -gt 0) { [void]$builder.Append([char]92, [int]$slashes) }
            [void]$builder.Append($character)
        }
        $slashes = 0
    }
    if ($slashes -gt 0) { [void]$builder.Append([char]92, [int]($slashes * 2)) }
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

function Write-CapturedStream {
    param([string]$Name, $Task)
    if ($null -eq $Task) { return }
    try {
        if (-not $Task.IsCompleted) { [void]$Task.Wait(2000) }
        if ($Task.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion) {
            $content = [string]$Task.Result
            if ($content.Length -gt 0) {
                foreach ($line in [regex]::Split($content.TrimEnd([char[]]"`r`n"), '\r?\n')) {
                    Write-ReportLine ('{0}: {1}' -f $Name, $line)
                }
            }
        } else { Write-ReportLine ($Name + ': CAPTURE_INCOMPLETE') }
    } catch {
        Write-ReportLine ('{0}: CAPTURE_ERROR type={1} hresult=0x{2:X8}' -f $Name, $_.Exception.GetType().FullName, ([long]$_.Exception.HResult -band 4294967295L))
    }
}

function Invoke-ProbeProcess {
    param(
        [string]$Id,
        [string]$Executable,
        [string[]]$Arguments,
        [int]$TimeoutMilliseconds = 30000,
        [switch]$UnicodeOutput
    )
    Write-ReportLine ''
    Write-ReportLine ('BEGIN {0}' -f $Id)
    $process = $null
    $stdoutTask = $null
    $stderrTask = $null
    $started = $false
    try {
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $Executable
        $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' ')
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.WorkingDirectory = $script:ProbeRoot
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $streamEncoding = New-Object Text.UTF8Encoding -ArgumentList $false
        if ($UnicodeOutput) { $streamEncoding = [Text.Encoding]::Unicode }
        $start.StandardOutputEncoding = $streamEncoding
        $start.StandardErrorEncoding = $streamEncoding
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $start
        $started = $process.Start()
        if (-not $started) { throw (New-Object InvalidOperationException -ArgumentList 'Process was not started.') }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            Write-ReportLine ('RESULT {0} TIMEOUT limit_ms={1}' -f $Id, $TimeoutMilliseconds)
            try { $process.Kill() } catch {
                Write-ReportLine ('STOP_ERROR type={0} hresult=0x{1:X8}' -f $_.Exception.GetType().FullName, ([long]$_.Exception.HResult -band 4294967295L))
            }
            [void]$process.WaitForExit(2000)
        }
    } catch {
        Write-ReportLine ('WORKER_ERROR {0} type={1} hresult=0x{2:X8}' -f $Id, $_.Exception.GetType().FullName, ([long]$_.Exception.HResult -band 4294967295L))
    } finally {
        if ($started -and ($null -ne $process)) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                    [void]$process.WaitForExit(2000)
                }
            } catch {
                Write-ReportLine ('CLEANUP_ERROR {0} type={1} hresult=0x{2:X8}' -f $Id, $_.Exception.GetType().FullName, ([long]$_.Exception.HResult -band 4294967295L))
            }
        }
        Write-CapturedStream 'stdout' $stdoutTask
        Write-CapturedStream 'stderr' $stderrTask
        if ($started -and ($null -ne $process)) {
            try {
                if ($process.HasExited) {
                    Write-ReportLine ('EXIT {0} code={1}' -f $Id, $process.ExitCode)
                } else { Write-ReportLine ('EXIT {0} STILL_RUNNING' -f $Id) }
            } catch { Write-ReportLine ('EXIT {0} UNAVAILABLE' -f $Id) }
        }
        if ($null -ne $process) { $process.Dispose() }
        Write-ReportLine ('END {0}' -f $Id)
    }
}

function Get-ProbeHosts {
    $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace($windowsDirectory)) { throw (New-Object InvalidOperationException -ArgumentList 'Windows directory is unavailable.') }
    $directories = @()
    if ([Environment]::Is64BitOperatingSystem) {
        $nativeDirectory = Join-Path $windowsDirectory 'System32'
        if (-not [Environment]::Is64BitProcess) { $nativeDirectory = Join-Path $windowsDirectory 'Sysnative' }
        $nativeArch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
        if ([string]::IsNullOrEmpty($nativeArch)) { $nativeArch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') }
        $nativeLabel = 'native64'
        if ($nativeArch -eq 'AMD64') { $nativeLabel = 'x64' }
        if ($nativeArch -eq 'ARM64') { $nativeLabel = 'arm64' }
        $directories += [pscustomobject]@{ Label = $nativeLabel; Directory = $nativeDirectory }
        $directories += [pscustomobject]@{ Label = 'x86'; Directory = (Join-Path $windowsDirectory 'SysWOW64') }
    } else {
        $directories += [pscustomobject]@{ Label = 'x86'; Directory = (Join-Path $windowsDirectory 'System32') }
    }
    foreach ($item in $directories) {
        [pscustomobject]@{
            Label = $item.Label
            PowerShell = (Join-Path $item.Directory 'WindowsPowerShell\v1.0\powershell.exe')
            CScript = (Join-Path $item.Directory 'cscript.exe')
        }
    }
}

if ($Worker) {
    try {
        if ($Case -eq 'Info') {
            Write-RuntimeInfo
            Write-ComRegistration
            Write-DotNetStoreCount
            exit 0
        }
        $workerExitCode = Invoke-DirectComProbe $Case
        exit $workerExitCode
    } catch {
        Write-ProbeError 'Worker' $_.Exception
        exit 1
    }
}

$mainExitCode = 0
try {
    $reportPath = Join-Path $script:ProbeRoot 'ActSigner-diagnostics.txt'
    $reportEncoding = New-Object Text.UTF8Encoding -ArgumentList $true
    $script:ReportWriter = New-Object IO.StreamWriter -ArgumentList @($reportPath, $false, $reportEncoding)
    $script:ReportWriter.AutoFlush = $true
    Write-ReportLine 'CSPSigner diagnostics 1.0'
    Write-ReportLine ('UTC={0}' -f [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Write-ReportLine 'Проверка КриптоПро: только открытие хранилищ, число сертификатов и закрытие.'
    Write-ReportLine 'Сертификаты, подписи, ключи и настройки системы не изменяются.'
    Write-ReportLine 'Каждая попытка COM выполняется в новом процессе. Лимит попытки: 30 секунд.'
    Write-ReportLine 'Различие версий DLL само по себе не означает неисправность.'
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Write-ReportLine 'UNSUPPORTED_OS: запустите Check-CryptoPro.cmd в Windows, где установлена программа подписания.'
        $mainExitCode = 1
    } else {
        Write-ReportLine ('Controller.PowerShell={0}' -f $PSVersionTable.PSVersion)
        Write-ReportLine ('Controller.ProcessBits={0}' -f ([IntPtr]::Size * 8))
        $psPath = Join-Path $script:ProbeRoot 'Check-CryptoPro.ps1'
        $jsPath = Join-Path $script:ProbeRoot 'Check-CryptoPro.js'
        $cases = @('CurrentUserReadOnly', 'DefaultOpen', 'CurrentUserLocationOnly', 'CurrentUserMaximumAllowed', 'MemoryReadOnly', 'ContainerReadOnly')
        foreach ($hostInfo in @(Get-ProbeHosts)) {
            if ([IO.File]::Exists($hostInfo.PowerShell)) {
                $baseArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $psPath, '-Worker', '-Case')
                Invoke-ProbeProcess ('PowerShell.' + $hostInfo.Label + '.Info') $hostInfo.PowerShell ($baseArguments + @('Info'))
                foreach ($probeCase in $cases) {
                    Invoke-ProbeProcess ('PowerShell.' + $hostInfo.Label + '.' + $probeCase) $hostInfo.PowerShell ($baseArguments + @($probeCase))
                }
            } else { Write-ReportLine ('SKIP PowerShell.{0}: executable not found' -f $hostInfo.Label) }
            if ([IO.File]::Exists($hostInfo.CScript) -and [IO.File]::Exists($jsPath)) {
                foreach ($probeCase in $cases) {
                    Invoke-ProbeProcess ('CScript.' + $hostInfo.Label + '.' + $probeCase) $hostInfo.CScript @('//nologo', '//U', '//E:JScript', $jsPath, $probeCase) -UnicodeOutput
                }
            } else { Write-ReportLine ('SKIP CScript.{0}: executable or Check-CryptoPro.js not found' -f $hostInfo.Label) }
        }
        Write-ReportLine ''
        Write-ReportLine 'COMPLETE: запуск проверок завершён; результаты каждой попытки указаны выше.'
        Write-ReportLine 'Отчёт: ActSigner-diagnostics.txt в папке рядом с Check-CryptoPro.cmd.'
    }
} catch {
    $mainExitCode = 1
    $fatalLine = 'FATAL type={0} hresult=0x{1:X8}' -f $_.Exception.GetType().FullName, ([long]$_.Exception.HResult -band 4294967295L)
    try {
        Write-ReportLine $fatalLine
        Write-ReportLine 'Не удалось завершить отчёт. Если файл уже создан, сохранённые строки остаются в нём.'
        Write-ReportLine 'При ошибке доступа распакуйте пакет в доступную для записи папку и запустите снова.'
    } catch {
        [Console]::WriteLine($fatalLine)
        [Console]::WriteLine('Не удалось записать отчёт. Распакуйте пакет в доступную для записи папку и повторите запуск.')
    }
} finally {
    if ($null -ne $script:ReportWriter) { $script:ReportWriter.Dispose() }
}
exit $mainExitCode
