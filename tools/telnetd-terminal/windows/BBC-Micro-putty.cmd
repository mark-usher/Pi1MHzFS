@echo off
rem Double-click: open a PuTTY saved session for TelnetD (add them first with ..\putty\BBC-Micro-telnet.reg).
rem   BBC-Micro-putty.cmd [host] [7]
rem host: the session's own ("Pi1MHz") if none is given, or another name or an IP address.
rem 7: the "BBC Micro MODE 7" session (the teletext font); without it, "BBC Micro" (every MODE in its own shape).
set PUTTY=putty.exe
where putty.exe >nul 2>&1 || set PUTTY="%ProgramFiles%\PuTTY\putty.exe"
set SESSION=BBC Micro
if "%~2"=="7" set "SESSION=BBC Micro MODE 7"
if "%~1"=="" (
    start "" %PUTTY% -load "%SESSION%"
) else (
    start "" %PUTTY% -load "%SESSION%" -telnet %1
)
