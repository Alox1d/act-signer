# Native Windows console-mode checks in dedicated child consoles; no signing/data access.
param(
    [string]$ModulePath = (Join-Path $PSScriptRoot 'ActSigner.Console.psm1'),
    [string]$ArtifactDirectory = (Join-Path $PSScriptRoot 'console-test-artifacts'),
    [switch]$Baseline,
    [ValidateSet('Driver', 'Native', 'Detached')][string]$WorkerMode = 'Driver',
    [int]$DriverProcessId = 0
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'These checks require native Windows PowerShell 5.1.'
}
[void][IO.Directory]::CreateDirectory($ArtifactDirectory)
$ArtifactDirectory = [IO.Path]::GetFullPath($ArtifactDirectory)
$ModulePath = [IO.Path]::GetFullPath($ModulePath)

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class ActConsoleTestNative {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb; public string reserved; public string desktop; public string title;
        public int x, y, xSize, ySize, xChars, yChars, fill, flags;
        public short show, reservedBytes; public IntPtr reservedPointer, input, output, error;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr process, thread; public uint processId, threadId; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory,
        ref STARTUPINFO startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool TerminateProcess(IntPtr handle, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetStdHandle(int kind);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetStdHandle(int kind, IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetConsoleMode(IntPtr handle, out uint mode);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleMode(IntPtr handle, uint mode);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint GetConsoleProcessList([Out] uint[] ids, uint count);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CreatePipe(out IntPtr read, out IntPtr write, IntPtr attributes, uint size);
    public static uint RunOwnConsole(string executable, string arguments) {
        STARTUPINFO startup = new STARTUPINFO(); startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        startup.flags = 1; startup.show = 0; // hidden, dedicated console
        PROCESS_INFORMATION process;
        if (!CreateProcess(executable, new StringBuilder("\"" + executable + "\" " + arguments),
            IntPtr.Zero, IntPtr.Zero, false, 0x10, IntPtr.Zero, null, ref startup, out process))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try {
            if (WaitForSingleObject(process.process, 45000) != 0) {
                TerminateProcess(process.process, 124);
                throw new TimeoutException("Dedicated console worker exceeded 45 seconds.");
            }
            uint code;
            if (!GetExitCodeProcess(process.process, out code))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return code;
        } finally { CloseHandle(process.thread); CloseHandle(process.process); }
    }
}
'@

if ($WorkerMode -eq 'Driver') {
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    # All arguments are controlled test paths; reject quote/newline characters.
    foreach ($path in @($PSCommandPath, $ModulePath, $ArtifactDirectory)) {
        if ($path.Contains('"') -or $path.Contains("`r") -or $path.Contains("`n")) { throw 'Unsupported quote/newline in test paths.' }
    }
    $workers = @('Native')
    if (-not $Baseline) { $workers += 'Detached' }
    $failed = $false
    foreach ($worker in $workers) {
        $arguments = '-NoLogo -NoProfile -NonInteractive -STA -ExecutionPolicy Bypass -File "{0}" -WorkerMode {1} -ModulePath "{2}" -ArtifactDirectory "{3}" -DriverProcessId {4}' -f $PSCommandPath, $worker, $ModulePath, $ArtifactDirectory, $PID
        if ($Baseline) { $arguments += ' -Baseline' }
        $code = [ActConsoleTestNative]::RunOwnConsole($powershell, $arguments)
        $reportPath = Join-Path $ArtifactDirectory ($worker.ToLowerInvariant() + '.json')
        if (-not [IO.File]::Exists($reportPath)) { throw ('Worker did not produce its native report: ' + $worker) }
        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
        Write-Host ($report | ConvertTo-Json -Depth 8)
        if ($code -ne 0) { $failed = $true }
    }
    if ($failed) { exit 1 }
    Write-Host 'PASS: dedicated native console QuickEdit guard, restoration, real redirected pipe, and detached-console safety.'
    exit 0
}

$failures = New-Object 'System.Collections.Generic.List[string]'
$checks = New-Object 'System.Collections.Generic.List[string]'
$modes = [ordered]@{}
$scope = $null
$originalMode = [uint32]0
$inputHandle = [IntPtr]::Zero
$canRestoreOriginal = $false
# Positive UInt32 masks avoid PowerShell 5.1 signed hexadecimal literal conversion.
$exceptQuickAndExtended = [uint32]4294967103
$exceptQuick = [uint32]4294967231
function Assert-Native { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Read-NativeMode {
    param([IntPtr]$Handle)
    $value = [uint32]0
    Assert-Native ([ActConsoleTestNative]::GetConsoleMode($Handle, [ref]$value)) 'GetConsoleMode must succeed in the dedicated test console.'
    return $value
}
function Set-NativeMode {
    param([IntPtr]$Handle, [uint32]$Mode)
    Assert-Native ([ActConsoleTestNative]::SetConsoleMode($Handle, $Mode)) 'SetConsoleMode must accept the synthetic console fixture.'
}
try {
    $ids = New-Object uint32[] 16
    $consoleProcesses = [ActConsoleTestNative]::GetConsoleProcessList($ids, $ids.Length)
    Assert-Native ($consoleProcesses -gt 0 -and $ids -contains [uint32]$PID) 'Worker must have its own native console.'
    Assert-Native (-not ($ids -contains [uint32]$DriverProcessId)) 'Worker must not share the driver/runner console.'
    $checks.Add('Dedicated console ownership verified through GetConsoleProcessList.')
    $inputHandle = [ActConsoleTestNative]::GetStdHandle(-10)
    $originalMode = Read-NativeMode $inputHandle
    $canRestoreOriginal = $true
    if (-not $Baseline) { Import-Module $ModulePath -Force }

    if ($WorkerMode -eq 'Detached') {
        Assert-Native ([ActConsoleTestNative]::FreeConsole()) 'Dedicated worker must detach successfully.'
        $canRestoreOriginal = $false
        $detachedMode = [uint32]0
        Assert-Native (-not [ActConsoleTestNative]::GetConsoleMode([ActConsoleTestNative]::GetStdHandle(-10), [ref]$detachedMode)) 'Detached worker must not have console input.'
        $result = @(Disable-ActConsoleQuickEdit)
        Assert-Native ($result.Count -eq 0 -or ($result.Count -eq 1 -and $null -eq $result[0])) 'Detached guard must return null without output.'
        Assert-Native (@(Restore-ActConsoleQuickEdit -State $null).Count -eq 0) 'Null restore must not output anything.'
        Assert-Native (@(Restore-ActConsoleQuickEdit -State $null).Count -eq 0) 'Repeated detached/null restore must remain safe.'
        $checks.Add('Detached console guard/null restoration returned safely without output.')
    }
    else {
        # Establish and verify a real QuickEdit-enabled native console fixture.
        Set-NativeMode $inputHandle ([uint32]($originalMode -bor 0x40 -bor 0x80))
        $before = Read-NativeMode $inputHandle
        $modes['FixtureBeforeDisable'] = $before
        Assert-Native (($before -band 0x40) -ne 0) 'Synthetic fixture must actually enable QuickEdit.'
        if (-not $Baseline) {
            $scope = Disable-ActConsoleQuickEdit
            Assert-Native ($scope -is [IDisposable]) 'Supported native console must return an IDisposable guard scope.'
        }
        # Baseline deliberately exercises the old unguarded entry-point behavior.
        # Its RED is the actual enabled flag, not a missing-module/parser failure.
        $after = Read-NativeMode $inputHandle
        $modes['AfterDisable'] = $after
        Assert-Native (($after -band 0x40) -eq 0) 'QuickEdit remains enabled: native unguarded baseline reproduces the missing selection guard.'
        Assert-Native (($after -band 0x80) -ne 0) 'Guard must set ENABLE_EXTENDED_FLAGS.'
        Assert-Native (($after -band $exceptQuickAndExtended) -eq ($before -band $exceptQuickAndExtended)) 'Guard changed an unrelated native console input flag.'
        $checks.Add('Native QuickEdit flag cleared; ExtendedFlags set; unrelated input flags preserved.')

        # Modify a different real native input flag while guarded; restore must
        # preserve the CURRENT flag rather than overwrite the original mode.
        Set-NativeMode $inputHandle ([uint32]($after -bxor 0x8))
        $current = Read-NativeMode $inputHandle
        $modes['BeforeRestoreWithOtherFlagChange'] = $current
        Assert-Native (@(Restore-ActConsoleQuickEdit -State $scope).Count -eq 0) 'Restore must produce no output.'
        $restored = Read-NativeMode $inputHandle
        $modes['AfterRestore'] = $restored
        Assert-Native (($restored -band 0x40) -ne 0) 'Restore must re-enable originally enabled QuickEdit.'
        Assert-Native (($restored -band $exceptQuick) -eq ($current -band $exceptQuick)) 'Restore overwrote another current input flag.'
        Set-NativeMode $inputHandle ([uint32]($restored -bxor 0x8))
        $beforeRepeat = Read-NativeMode $inputHandle
        Assert-Native (@(Restore-ActConsoleQuickEdit -State $scope).Count -eq 0) 'Repeated restore must produce no output.'
        $scope.Dispose()
        $modes['AfterRepeatedRestore'] = Read-NativeMode $inputHandle
        Assert-Native ($modes['AfterRepeatedRestore'] -eq $beforeRepeat) 'Repeated Restore/Dispose must be idempotent.'
        $scope = $null
        Assert-Native (@(Restore-ActConsoleQuickEdit -State $null).Count -eq 0) 'Null restore must be safe and silent.'
        $checks.Add('Originally enabled QuickEdit restored; current other flags preserved; repeated/null restore silent and idempotent.')

        Set-NativeMode $inputHandle ([uint32]($beforeRepeat -band $exceptQuick))
        $disabledBefore = Read-NativeMode $inputHandle
        $modes['InitiallyDisabledBefore'] = $disabledBefore
        $scope = Disable-ActConsoleQuickEdit
        Assert-Native ($scope -is [IDisposable]) 'Initially disabled native console still needs a disposable scope.'
        $disabledGuarded = Read-NativeMode $inputHandle
        $modes['InitiallyDisabledAfterGuard'] = $disabledGuarded
        Assert-Native ($disabledGuarded -eq $disabledBefore) 'Guard must not change an already-disabled fixture.'
        Set-NativeMode $inputHandle ([uint32]($disabledGuarded -bxor 0x8))
        $disabledCurrent = Read-NativeMode $inputHandle
        Assert-Native (@(Restore-ActConsoleQuickEdit -State $scope).Count -eq 0) 'Disabled-state restore must be silent.'
        $modes['InitiallyDisabledAfterRestore'] = Read-NativeMode $inputHandle
        Assert-Native ($modes['InitiallyDisabledAfterRestore'] -eq $disabledCurrent) 'Restore must retain initially disabled QuickEdit and other current flags.'
        $scope = $null
        $checks.Add('Initially disabled QuickEdit stays disabled through native guard/restore.')

        Set-NativeMode $inputHandle ([uint32]($disabledCurrent -bor 0x40))
        $directBefore = Read-NativeMode $inputHandle
        $scope = Disable-ActConsoleQuickEdit
        Assert-Native (($scope -is [IDisposable]) -and ((Read-NativeMode $inputHandle) -band 0x40) -eq 0) 'Direct IDisposable case must disable QuickEdit.'
        $scope.Dispose()
        $modes['AfterDirectDispose'] = Read-NativeMode $inputHandle
        Assert-Native ($modes['AfterDirectDispose'] -eq $directBefore) 'Direct Dispose must restore the enabled flag.'
        $scope = $null
        $checks.Add('Direct IDisposable.Dispose restored the actual console mode.')

        # Redirect only this dedicated worker's stdin to a real anonymous pipe.
        $readPipe = [IntPtr]::Zero; $writePipe = [IntPtr]::Zero
        Assert-Native ([ActConsoleTestNative]::CreatePipe([ref]$readPipe, [ref]$writePipe, [IntPtr]::Zero, 0)) 'Real redirected pipe fixture must be created.'
        try {
            Assert-Native ([ActConsoleTestNative]::SetStdHandle(-10, $readPipe)) 'Worker stdin must redirect to the synthetic pipe.'
            $pipeMode = [uint32]0
            Assert-Native (-not [ActConsoleTestNative]::GetConsoleMode($readPipe, [ref]$pipeMode)) 'A pipe must not masquerade as console input.'
            $redirectedResult = @(Disable-ActConsoleQuickEdit)
            Assert-Native ($redirectedResult.Count -eq 0 -or ($redirectedResult.Count -eq 1 -and $null -eq $redirectedResult[0])) 'Redirected guard must return null without output.'
            Assert-Native (@(Restore-ActConsoleQuickEdit -State $null).Count -eq 0) 'Redirected null restore must be safe and silent.'
            Assert-Native ((Read-NativeMode $inputHandle) -eq $directBefore) 'Redirected guard must not modify the detached real console handle.'
            $checks.Add('Real pipe stdin returned null safely and left the console mode untouched.')
        }
        finally {
            [void][ActConsoleTestNative]::SetStdHandle(-10, $inputHandle)
            [void][ActConsoleTestNative]::CloseHandle($readPipe)
            [void][ActConsoleTestNative]::CloseHandle($writePipe)
        }
    }
}
catch { $failures.Add($_.Exception.Message) }
finally {
    if ($null -ne $scope) { try { $scope.Dispose() } catch { $failures.Add('Scope disposal unexpectedly threw.') } }
    if ($canRestoreOriginal) { [void][ActConsoleTestNative]::SetConsoleMode($inputHandle, $originalMode) }
    [pscustomobject]@{
        Worker = $WorkerMode; Baseline = [bool]$Baseline; NativeWindows = $true
        PowerShellVersion = $PSVersionTable.PSVersion.ToString(); NativeModes = $modes
        Checks = @($checks.ToArray()); Failures = @($failures.ToArray())
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ArtifactDirectory ($WorkerMode.ToLowerInvariant() + '.json')) -Encoding UTF8
}
if ($failures.Count -gt 0) { exit 1 }
exit 0
