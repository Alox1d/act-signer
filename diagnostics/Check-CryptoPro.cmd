@echo off
setlocal DisableDelayedExpansion
set "ACTDIAG_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "ACTDIAG_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%ACTDIAG_PS%" (
  echo Windows PowerShell was not found.
  pause
  exit /b 1
)
"%ACTDIAG_PS%" -NoLogo -NoProfile -NonInteractive -STA -ExecutionPolicy Bypass -File "%~dp0Check-CryptoPro.ps1"
set "ACTDIAG_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %ACTDIAG_EXIT%
