#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$NoUpdate,
    [switch]$Previous,
    [string]$StateRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$consoleState = $null
$background = $null
$application = $null
$exitCode = 1

function ConvertTo-ActLaunchArgument {
    param([string]$Value)
    if ($Value.Contains('"')) { throw 'Недопустимые кавычки в пути запуска.' }
    # -File arguments are passed straight to the executable, never to a shell.
    return '"' + [regex]::Replace($Value, '(\\+)$', '$1$1') + '"'
}

function Get-ActNativePowerShell {
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $system = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { 'Sysnative' } else { 'System32' }
    $executable = [IO.Path]::Combine($windows, $system, 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    if (-not [IO.File]::Exists($executable)) { throw 'Не найден встроенный Windows PowerShell.' }
    return $executable
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'ActSigner запускается в Windows.' }
    # The guard also covers any launcher output before the signing process starts.
    try {
        Import-Module (Join-Path $PSScriptRoot 'ActSigner.Console.psm1') -Force -DisableNameChecking -ErrorAction Stop
        $consoleState = Disable-ActConsoleQuickEdit
    }
    catch { }
    $nativePowerShell = Get-ActNativePowerShell
    $applicationRoot = $PSScriptRoot
    $canUpdate = $false
    try {
        # Only the bundled verifier is loaded before selecting downloaded code.
        Import-Module (Join-Path $PSScriptRoot 'ActSigner.Update.psm1') -Force -DisableNameChecking -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($StateRoot)) { $StateRoot = Get-ActUpdateStateRoot }
        $selection = Get-ActLaunchSelection -BundledRoot $PSScriptRoot -StateRoot $StateRoot -Previous:$Previous
        if ($null -eq $selection -or [string]::IsNullOrWhiteSpace([string]$selection.ApplicationRoot)) { throw 'Не удалось выбрать установленную версию.' }
        $applicationRoot = [string]$selection.ApplicationRoot
        $canUpdate = $true
        if (-not [string]::IsNullOrWhiteSpace([string]$selection.Notice)) { Write-Host ([string]$selection.Notice) }
    }
    catch {
        # Broken or unwritable update state must not prevent a bundled launch.
        $applicationRoot = $PSScriptRoot
        $canUpdate = $false
        Write-Verbose 'Обновление недоступно. Запускается версия из исходной папки.'
    }
    $entryPoint = Join-Path $applicationRoot 'Sign-Acts.ps1'
    if (-not [IO.File]::Exists($entryPoint)) { throw 'В папке программы отсутствует Sign-Acts.ps1. Распакуйте полный архив ActSigner.' }

    # This invocation's applicationRoot is fixed before the worker can prepare
    # another version. Downloading never holds the foreground application open.
    if ($canUpdate -and -not $NoUpdate -and -not $Previous) {
        try {
            $workerPath = Join-Path $applicationRoot 'Update-ActSigner.ps1'
            if ([IO.File]::Exists($workerPath)) {
                $workerInfo = New-Object Diagnostics.ProcessStartInfo
                $workerInfo.FileName = $nativePowerShell
                $workerInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + (ConvertTo-ActLaunchArgument $workerPath) + ' -StateRoot ' + (ConvertTo-ActLaunchArgument $StateRoot)
                $workerInfo.UseShellExecute = $false
                $workerInfo.CreateNoWindow = $true
                $workerInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
                $workerInfo.RedirectStandardInput = $true
                $workerInfo.RedirectStandardOutput = $true
                $workerInfo.RedirectStandardError = $true
                $background = New-Object Diagnostics.Process
                $background.StartInfo = $workerInfo
                [void]$background.Start()
                $background.StandardInput.Close()
                # Drain unexpected worker output on .NET threads, with no
                # PowerShell callbacks and no inherited foreground output pipe.
                $background.BeginOutputReadLine()
                $background.BeginErrorReadLine()
            }
        }
        catch {
            if ($null -ne $background) { try { $background.Dispose() } catch { }; $background = $null }
            Write-Verbose 'Фоновую проверку обновлений запустить не удалось.'
        }
    }

    $applicationInfo = New-Object Diagnostics.ProcessStartInfo
    $applicationInfo.FileName = $nativePowerShell
    $applicationInfo.Arguments = '-NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File ' + (ConvertTo-ActLaunchArgument $entryPoint)
    $applicationInfo.UseShellExecute = $false
    $applicationInfo.CreateNoWindow = $false
    $application = New-Object Diagnostics.Process
    $application.StartInfo = $applicationInfo
    [void]$application.Start()
    $application.WaitForExit()
    $exitCode = $application.ExitCode
}
catch {
    Write-Host ('Не удалось запустить ActSigner: ' + $_.Exception.Message) -ForegroundColor Red
    $exitCode = 1
}
finally {
    if ($null -ne $application) { try { $application.Dispose() } catch { } }
    # Disposing this handle does not kill the independent, bounded worker.
    if ($null -ne $background) { try { $background.Dispose() } catch { } }
    if ($null -ne $consoleState) { try { Restore-ActConsoleQuickEdit -State $consoleState } catch { } }
}
exit $exitCode
