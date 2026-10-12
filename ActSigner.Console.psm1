#requires -Version 5.1
Set-StrictMode -Version 2.0

function Initialize-ActConsoleInterop {
    if ('ActSigner.ConsoleQuickEditScope' -as [type]) { return }
    Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace ActSigner {
    public sealed class ConsoleQuickEditScope : IDisposable {
        private const int StdInputHandle = -10;
        private const uint QuickEdit = 0x0040;
        private const uint ExtendedFlags = 0x0080;
        private readonly IntPtr input;
        private readonly uint previousQuickEdit;
        private bool disposed;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int standardHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetConsoleMode(IntPtr handle, uint mode);

        private ConsoleQuickEditScope(IntPtr handle, uint previousMode) {
            input = handle;
            previousQuickEdit = previousMode & QuickEdit;
        }

        public static ConsoleQuickEditScope TryDisable() {
            IntPtr handle = GetStdHandle(StdInputHandle);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return null;
            uint mode;
            // Redirected input and hosts without a console need no adjustment.
            if (!GetConsoleMode(handle, out mode)) return null;
            ConsoleQuickEditScope scope = new ConsoleQuickEditScope(handle, mode);
            // QuickEdit selection can block synchronous progress writes. Keep
            // Ctrl+C, line input and every unrelated input mode unchanged.
            if (!SetConsoleMode(handle, (mode & ~QuickEdit) | ExtendedFlags)) return null;
            return scope;
        }

        public void Dispose() {
            if (disposed) return;
            disposed = true;
            uint mode;
            if (!GetConsoleMode(input, out mode)) return;
            // Restore only our setting; retain any other changes made while
            // the app ran. ExtendedFlags is required when changing QuickEdit.
            SetConsoleMode(input, (mode & ~QuickEdit) | previousQuickEdit | ExtendedFlags);
        }
    }
}
'@
}

function Disable-ActConsoleQuickEdit {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $null }
    try {
        Initialize-ActConsoleInterop
        return [ActSigner.ConsoleQuickEditScope]::TryDisable()
    }
    catch {
        # Console preferences must not prevent the signing application opening.
        return $null
    }
}

function Restore-ActConsoleQuickEdit {
    param($State)
    if ($null -eq $State) { return }
    try { $State.Dispose() } catch { }
}

Export-ModuleMember -Function Disable-ActConsoleQuickEdit, Restore-ActConsoleQuickEdit
