# A BBC Micro look for TelnetD sessions

These files make a telnet session to the Pi1MHz's telnet daemon (TelnetD, see
`docs/user/telnetd.md`) look like the Beeb's own screen. They include the BBC
Micro's character sets as fonts, the BBC's eight colours, and ready-made settings
for Windows Terminal, PuTTY and the Debian console or desktop. TelnetD works with
any terminal. These files only change how it looks.

Every setting uses the host name `Pi1MHz`. If your Pi has a different hostname,
or your network does not resolve it, use its IP address instead.

## The fonts: one for each width of the Beeb's screen

A terminal cannot change its font when the Beeb changes MODE. The Beeb's
characters change shape from mode to mode, though, so there is one font for each
width of the screen. The cells of each font have the shape that mode's characters
have on a 4:3 screen:

| Font | File | For | Window | Cell (w:h) |
|---|---|---|---|---|
| BBC Micro Teletext | `BBCMicroTeletext.ttf` | MODE 7 | 40 x 25 | 9:10 |
| BBC Micro MOS | `BBCMicroMOS.ttf` | MODE 0 and 3 | 80 x 32 | 1:2 |
| BBC Micro MOS 40 | `BBCMicroMOS40.ttf` | MODE 1, 4 and 6 | 40 x 32 | 1:1 |
| BBC Micro MOS 20 | `BBCMicroMOS20.ttf` | MODE 2 and 5 | 20 x 32 | 2:1 |

The Beeb starts in MODE 7, so MODE 7 is the default everywhere. A window opened for
one mode still shows the others, in its own font.

The fonts are made from the Pi1MHz framebuffer's own character sets, so a telnet
session shows the same characters as the Pi's screen:

The teletext font shows MODE 7 as a real BBC Micro's teletext chip (SAA5050) draws
it. Each character's 5 x 9 dot matrix was measured from a real Beeb's screen (an HDMI
capture). The chip's "character rounding" then smooths it to 12 x 20 pixels by
adding a half dot wherever two dots meet only at a corner; rounding the measured
dots this way gives back exactly the picture the Beeb drew. As on the chip, it has
`£ ← ½ → ↑ # ― ¼ ‖ ¾ ÷` and the block in place of some ASCII characters. The cell
shapes in the table were measured the same way.

Every TrueType font also has the mosaic graphics TelnetD uses for MODE 7:
- Unicode's 60 sextant characters (U+1FB00-1FB3B) and the full and half blocks, for
  contiguous graphics. They fill the whole cell, so graphics join up as on the Beeb.
- Unicode 16's 63 separated sextants (U+1CE51-1CE8F), for separated graphics.

Both kinds have the chip's own proportions: the three rows of blocks are 3, 4 and 3
lines of the 10 in a character, not equal thirds. Many terminal fonts don't have the
separated sextants yet. With one of those, set `telnetd_separated=0` on the Pi, and
separated graphics are sent as contiguous ones.

`make-fonts.py` makes the fonts from the Pi1MHz framebuffer's own character sets
(`src/framebuffer/fonts/bbc.fnt.h` and `saa5050.fnt.h`). It does not yet add what the
fonts here have beyond those: the MODE pieces for `xterm-bbc`, the separated sextants,
the blocks for characters a program defines, and the chip's mosaic proportions. Until
it does, `make-fonts.py --check` reports these fonts as different, and running it
would take those glyphs out.

`make-fonts.py` writes all eight font files from those tables (the TrueType fonts
need `fontTools`: `apt install python3-fonttools` or `pip install fonttools`). The
font files are committed, so installing them needs neither. After a change to
either table, run `python3 make-fonts.py`. `python3 make-fonts.py --check` fails if
the committed fonts are out of date (a different fontTools version can write the
same glyphs to a different `.ttf` file; these were made with fontTools 4.67).

Each font also comes as a PSF2 console font for the Linux console (`*.psf`): 12 x 20
for MODE 7, and 8 x 16, 16 x 16 and 32 x 16 for the others. The Linux console
supports only the Basic Multilingual Plane, so the console fonts have no sextants.
On the console a mosaic is shown as the nearest block character instead.

## One window for every MODE (recommended)

A program changes MODE as it runs, and a window can't change its font with it. So
the "BBC Micro" profiles tell TelnetD that the window has the "BBC Micro MOS"
font: they send the terminal type `xterm-bbc` (any terminal type with `bbc` in it
does). TelnetD then draws every MODE in its own shape in that one 80 x 32 window.
Every other window gets plain characters, so Windows' telnet client, or a terminal
in its own font, works as before. To turn this off on the Pi, put
`telnetd_font=plain` in its `Pi1MHz.cfg`.

The font holds each MODE's characters as pieces in Unicode's private-use area:
- MODE 0 and 3: a character is one cell;
- MODE 1, 4 and 6: two cells, the left and right halves of the character;
- MODE 2 and 5: four cells, its quarters;
- MODE 7: two cells, with the teletext chip's characters, contiguous and separated
  mosaics, and separate top and bottom pieces for double height. So double height
  isn't double width, as it is with the terminal's own double-height lines.

Use the "BBC Micro" Windows Terminal profile with WSL's telnet, the "BBC Micro" PuTTY
session or `beeb-telnet` in a desktop terminal set to that font. Windows' own telnet
client always says `ANSI`, so it gets plain characters. The window must be at least
80 x 32; TelnetD says so when you connect to a smaller one.

MODE 7 has 25 rows and the other MODEs 32, and one window can't have both heights:
MODE 7 uses the top 25 of the 32 rows, so its characters are shorter than on the Beeb.
For MODE 7 exactly, use the "BBC Micro MODE 7" profile or session (or
`beeb-telnet -m 7`): 40 x 25 in the teletext font, with the other MODEs in that font.

Only send `xterm-bbc` from a window in that font: in any other font the pieces come
out as empty boxes. Text copied out of the window is the pieces' codes, not letters.

## Windows

TelnetD sends the pound sign and the teletext graphics as UTF-8. Windows' own
telnet client (`telnet.exe`) cannot show UTF-8, so in it they come out as the
wrong characters. Everything else works, including the keys. For the full picture
on Windows, use either of these:

- **PuTTY** (see below);
- **the telnet client in WSL**, for example Debian with `sudo apt install telnet`.

Double-click `windows\install.cmd`. It installs, for the current user only (no
administrator rights needed):

- the fonts (each as its name and a hash of its contents, so that a new version is a
  new file to Windows: Windows Terminal crashed on a font replaced under its old name);
- a Windows Terminal colour scheme called "BBC Micro";
- two Windows Terminal profiles: "BBC Micro" (every MODE in its own shape) and
  "BBC Micro MODE 7" (MODE 7 exactly). Each telnets to `Pi1MHz` with WSL's telnet if
  there is one, and with `telnet.exe` if not.

If your Pi has another name, give it to the installer from a command prompt, and the
profiles use it: `install.cmd my-pi-name` (or its IP address). Windows Terminal reads
the profiles and fonts when it starts, so close all its windows first, every one.

Then do either of these:

- choose one of the profiles from Windows Terminal's new-tab menu;
- double-click `windows\BBC-Micro-telnet.cmd`. It opens the "BBC Micro" window.
  You can give a host, and `7` for the MODE 7 one: `BBC-Micro-telnet.cmd 192.168.1.50 7`;
- from a command prompt: `wt -w new -p "BBC Micro"` (or `-p "BBC Micro MODE 7"`).

The profiles use 12.5-point fonts. Windows Terminal 1.25 ignores the window size it
is given on its command line and opens every window at its default size (120 x 30 in
its own font); at 12.5 points that holds 32 rows of the BBC fonts. A bigger font
needs a bigger window, which you can drag to size: TelnetD draws the screen again.

If Windows Terminal closes at once on a BBC Micro profile after an update to the fonts,
Windows' font cache still holds the old version under the same font name. Clear it
from an administrator PowerShell, and the profiles work again:

    Stop-Service FontCache -Force
    Remove-Item "$env:WINDIR\ServiceProfiles\LocalService\AppData\Local\FontCache\*" -Force -Recurse -ErrorAction SilentlyContinue
    Start-Service FontCache

Signing out and in again also works.

Windows' telnet client is an optional feature. To turn it on, run this once from an
administrator command prompt:

    dism /online /Enable-Feature /FeatureName:TelnetClient

To change a profile's host, edit it in Windows Terminal's settings. To undo the
install, run `powershell -ExecutionPolicy Bypass -File windows\install.ps1 -Remove`.

## PuTTY

Install the fonts first with `windows\install.cmd`, or install the `.ttf` files by
hand. Then double-click `putty\BBC-Micro-telnet.reg`. This adds two saved sessions,
"BBC Micro" and "BBC Micro MODE 7" (and removes earlier kits' per-MODE ones), with
these settings:

- telnet to `Pi1MHz`, port 23;
- the window size and font ("BBC Micro": 80 x 32, BBC Micro MOS, terminal type
  `xterm-bbc`; "BBC Micro MODE 7": 40 x 25, BBC Micro Teletext), and the BBC's colours;
- UTF-8, needed for the pound sign and the teletext graphics;
- function keys sent as `ESC [ n ~`, so F12 is BREAK.

Load a session in PuTTY, change the Host Name if you need to, and save it again.
`windows\BBC-Micro-putty.cmd [host] [7]` opens a session in one double-click.

## Debian (bookworm and trixie)

    sh linux/install.sh

The installer:

- installs the `telnet` package if it is missing;
- installs the console fonts in `/usr/share/consolefonts` (it asks for `sudo` for this);
- installs the TrueType fonts in `~/.local/share/fonts`;
- installs the `beeb-telnet` command in `~/.local/bin`.

To connect, run `beeb-telnet [host]` for every MODE in its own shape, or
`beeb-telnet -m 7 [host]` for MODE 7 exactly. What it does depends on where you run it:

- **On the Linux console** (a text login, not a desktop): the console fonts have no
  pieces, so it uses one MODE's font, `-m MODE` (MODE 0 if none is given). It loads that
  console font and the BBC's eight colours for the session. When telnet ends, it
  puts back your own font and colours. The console must be big enough for the
  mode in that font. For example, MODE 0 needs 80 x 32, which an 8 x 16 font gives
  on a 640 x 512 or larger framebuffer.
- **In a desktop terminal** (GNOME Terminal, Konsole, xterm and so on): it runs telnet
  (with terminal type `xterm-bbc` unless `-m 7`), and says which font and window size
  to choose in the terminal's own preferences. In xterm you can do it all on the
  command line: `xterm -fa 'BBC Micro MOS' -fs 12 -geometry 80x32 -e env TERM=xterm-bbc telnet Pi1MHz`.

To remove everything it installed, run `sh linux/install.sh --remove`.

Character mode and line mode (`mode line` in Debian's telnet, also in WSL) both work
the same in every one of these, with and without the BBC font: in line mode the
client shows what you type itself, and TelnetD draws the screen again when you press
RETURN, so the line ends up in the Beeb's place and shape.
