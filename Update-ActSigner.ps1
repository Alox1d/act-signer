#requires -Version 5.1
[CmdletBinding()]
param([string]$StateRoot)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
Set-StrictMode -Version 2.0
try {
    Import-Module (Join-Path $PSScriptRoot 'ActSigner.Update.psm1') -Force -DisableNameChecking -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($StateRoot)) { $StateRoot = Get-ActUpdateStateRoot }
    $result = Invoke-ActUpdateCheck -ApplicationRoot $PSScriptRoot -StateRoot $StateRoot
}
catch {
    # A release check has no authority to stop the user's signing application.
    # No document paths, certificate data, PINs or signing callbacks are passed.
}
exit 0
