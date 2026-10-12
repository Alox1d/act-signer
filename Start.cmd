@echo off
setlocal DisableDelayedExpansion
set "ACTSIGNER_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "ACTSIGNER_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%ACTSIGNER_PS%" (
  echo Windows PowerShell was not found.
  pause
  exit /b 1
)
"%ACTSIGNER_PS%" -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Sign-Acts.ps1"
set "ACTSIGNER_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %ACTSIGNER_EXIT%
