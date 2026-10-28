@echo off
rem Double-click: telnet to the Pi1MHz in Windows Terminal with the BBC Micro fonts and colours.
rem   BBC-Micro-telnet.cmd [host] [7]
rem host: "Pi1MHz" (the Pi's network name) if none is given, or another name or an IP address.
rem 7: the "BBC Micro MODE 7" window (40 x 25 in the teletext font: MODE 7 exactly).  Without it, the "BBC Micro"
rem window (80 x 32 in the BBC Micro MOS font), in which TelnetD draws every MODE in its own shape.
rem e.g.  BBC-Micro-telnet.cmd 192.168.1.20 7
set HOST=%~1
if "%HOST%"=="" set HOST=Pi1MHz
set PROFILE=BBC Micro
set TT=env TERM=xterm-bbc 
if "%~2"=="7" (set "PROFILE=BBC Micro MODE 7" & set TT=)
rem the client: WSL's telnet if there is one (it shows UTF-8: the pound sign, the teletext graphics), else telnet.exe
set CLIENT=telnet.exe
wsl.exe -e sh -c "command -v telnet" >nul 2>&1 && set CLIENT=wsl.exe -e %TT%telnet
start "" wt.exe -w new -p "%PROFILE%" %CLIENT% %HOST%
