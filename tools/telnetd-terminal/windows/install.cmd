@echo off
rem Double-click to install the BBC Micro fonts and the Windows Terminal profiles for TelnetD (this user only).
rem   install.cmd [host]   the Pi's network name or IP address for the profiles; Pi1MHz if none is given
rem Started from PowerShell 7, Windows PowerShell would inherit 7's module path and fail to load its own cmdlets.
setlocal
set PSModulePath=
if "%~1"=="" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -TelnetHost %1
)
pause
