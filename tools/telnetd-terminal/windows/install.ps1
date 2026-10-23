# install.ps1 - the BBC Micro look for a telnet session to TelnetD, for the current Windows user (no administrator
# rights): the four BBC Micro fonts (one for each width of the Beeb's screen: MODE 7, MODE 0/3, MODE 1/4/6, MODE 2/5),
# and a Windows Terminal profile for each with the BBC's colours.
# Run by install.cmd [host] (the Pi's name or address for the profiles; Pi1MHz if none).  Remove with: install.ps1 -Remove
param([string]$TelnetHost = 'Pi1MHz', [switch]$Remove)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit = Split-Path -Parent $here
$fontDir = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts'
$fontKey = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Fonts'
$fonts = [ordered]@{
    'BBCMicroTeletext.ttf' = 'BBC Micro Teletext'
    'BBCMicroMOS.ttf'      = 'BBC Micro MOS'
    'BBCMicroMOS40.ttf'    = 'BBC Micro MOS 40'
    'BBCMicroMOS20.ttf'    = 'BBC Micro MOS 20'
}
$fragDir = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\Fragments\Pi1MHz TelnetD'
$oldDirs = 'Pi1MHz TelnetD', 'Pi1MHz-TelnetD' | % { Join-Path $env:LOCALAPPDATA $_ }   # earlier kits' helper folders

if ($Remove) {
    foreach ($f in $fonts.Keys) {
        Remove-ItemProperty -Path $fontKey -Name "$($fonts[$f]) Regular (TrueType)" -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $fontDir $f) -ErrorAction SilentlyContinue
    }
    Remove-Item $fragDir -Recurse -ErrorAction SilentlyContinue
    Remove-Item $oldDirs -Recurse -ErrorAction SilentlyContinue
    Write-Host 'Removed the BBC Micro fonts and the Windows Terminal profiles.'
    return
}

# The fonts, for this user.  The registry entries only take effect at the next sign-in: each font is loaded into
# this session now too, and running programs are told (WM_FONTCHANGE to all windows).
Add-Type -Namespace TelnetD -Name Font -MemberDefinition @'
[DllImport("gdi32.dll", CharSet = CharSet.Unicode)] public static extern int AddFontResourceW(string file);
[DllImport("gdi32.dll", CharSet = CharSet.Unicode)] public static extern int RemoveFontResourceW(string file);
[DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr hWnd, uint msg, IntPtr w, IntPtr l, uint flags, uint timeout, out IntPtr result);
'@
New-Item -ItemType Directory -Force $fontDir | Out-Null
foreach ($f in $fonts.Keys) {
    $src = Join-Path $kit $f
    $dst = Join-Path $fontDir $f
    if (-not (Test-Path $dst) -or (Get-FileHash $src).Hash -ne (Get-FileHash $dst).Hash) {
        if (Test-Path $dst) { [void][TelnetD.Font]::RemoveFontResourceW($dst) }    # a new version: unload the old
        try { Copy-Item $src $dst -Force }
        catch {
            Write-Host "$($fonts[$f]) is in use (an open Windows Terminal or PuTTY window): close them and run this again."
            exit 1
        }
    }
    New-ItemProperty -Path $fontKey -Name "$($fonts[$f]) Regular (TrueType)" -Value $dst -PropertyType String -Force | Out-Null
    [void][TelnetD.Font]::AddFontResourceW($dst)
    Write-Host "Font installed: $($fonts[$f])"
}
$r = [IntPtr]::Zero
[void][TelnetD.Font]::SendMessageTimeoutW([IntPtr]0xffff, 0x001D, [IntPtr]::Zero, [IntPtr]::Zero, 2, 1000, [ref]$r)

# The profiles: Windows Terminal picks up "fragments" from this folder by itself.  They run WSL's telnet when WSL has
# one (it shows UTF-8: the pound sign and the teletext graphics), else Windows' telnet.exe.
Remove-Item $oldDirs -Recurse -ErrorAction SilentlyContinue
$wsl = $false
try { & wsl.exe -e sh -c 'command -v telnet' *> $null; $wsl = ($LASTEXITCODE -eq 0) } catch { }
$frag = Get-Content (Join-Path $here 'telnetd-fragment.json') -Raw
if (-not $wsl) { $frag = $frag.Replace('wsl.exe -e telnet', 'telnet.exe') }
$frag = $frag.Replace('telnet Pi1MHz', 'telnet ' + $TelnetHost).Replace('telnet.exe Pi1MHz', 'telnet.exe ' + $TelnetHost)
New-Item -ItemType Directory -Force $fragDir | Out-Null
Set-Content (Join-Path $fragDir 'telnetd.json') $frag -NoNewline
Write-Host "Windows Terminal profiles added: BBC Micro MODE 7, MODE 0/3, MODE 1/4/6, MODE 2/5 (host $TelnetHost)"

# The "BBC Micro" colour scheme into settings.json as well: Windows Terminal does not always take a scheme from a
# fragment, and the profiles then fell back to its default colours (whose black is not the background's, which
# left the cells the Beeb clears showing).  A copy of settings.json is kept beside it first.
$wtSettings = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal*\LocalState\settings.json') -ErrorAction SilentlyContinue | Select-Object -First 1
if ($wtSettings) {
    $raw = Get-Content $wtSettings.FullName -Raw
    $json = ($raw -split "`n" | Where-Object { $_ -notmatch '^\s*//' }) -join "`n" | ConvertFrom-Json
    $scheme = (Get-Content (Join-Path $here 'telnetd-fragment.json') -Raw | ConvertFrom-Json).schemes[0]
    $others = @($json.schemes | Where-Object { $_.name -ne $scheme.name })
    Copy-Item $wtSettings.FullName ($wtSettings.FullName + '.before-bbc-micro') -Force
    $json.schemes = @($others) + $scheme
    $json | ConvertTo-Json -Depth 32 | Set-Content $wtSettings.FullName -Encoding UTF8
    Write-Host 'Colour scheme "BBC Micro" added to Windows Terminal''s settings.'
}
if (-not $wsl) {
    Write-Host ''
    Write-Host "WSL has no telnet client, so the profiles use Windows' own telnet.exe, which cannot show the pound sign"
    Write-Host 'or the teletext graphics (UTF-8).  For those, install telnet in WSL (Debian: sudo apt install telnet) or use PuTTY.'
    if (-not (Get-Command telnet.exe -ErrorAction SilentlyContinue)) {
        Write-Host "Windows' telnet client is not installed either.  Turn it on (as administrator) with:"
        Write-Host '    dism /online /Enable-Feature /FeatureName:TelnetClient'
    }
}
Write-Host ''
Write-Host 'Start it with BBC-Micro-telnet.cmd, or from Windows Terminal''s menu.  Close Windows Terminal first if it is open.'
