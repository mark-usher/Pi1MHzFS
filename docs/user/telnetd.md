# The telnet daemon: the Beeb's keyboard and screen over the network

Pi1MHz can let you `telnet` to the Pi and sit at the Beeb's keyboard and
screen. What you type arrives as if it had been typed on the Beeb, and what
the Beeb prints comes back to your terminal. Anything that can run telnet -
PuTTY, a Linux or macOS terminal, Windows' telnet client, a script - can
drive the Beeb from another room, and a program can drive it too.

It is written to work on a BBC B, B+ and Master 128, with the real keyboard still
working. It has been run on a Master 128 and, in the first sessions, on a machine
recorded as a BBC B; it has not been run on a B+.
beside it.

## Turning it on

1. In `/Pi1MHz/Pi1MHz.cfg` set the port to listen on and reboot the Pi:

   ```
   telnetd_port=23
   ```

   WiFi has to be set up (see [WiFi setup](wifi.md)). Without the key, or with
   `0`, the daemon is off. `net_enable` is not needed.

2. On the Beeb, run **helper 20**:

   ```
   X%=20:CALL &FC88
   ```

   (or `*FX147,136,20` then `*GO FD00`). It prints ` Telnet: Pi`. This hooks
   the Beeb's keyboard and RS423 output to the Pi (it uses the same stub as
   the [serial redirector](serial-modem.md), helper 19) and sets `*FX3,1`, so
   what the Beeb prints is copied to the Pi.

3. From another machine:

   ```
   telnet 192.168.1.20
   ```

   using the Pi's address. You get a banner and, if the Beeb is hooked,
   `[BBC attached - press RETURN]`. Press RETURN and the Beeb answers with its
   prompt.

To hand things back without a BREAK, enter the page at its second entry:
`*FX147,136,20` then `*GO FD03`. It prints ` Telnet: off` and puts `*FX3` back.

**BREAK undoes it**, as with the other redirectors: run helper 20 again after
every BREAK - or load the auto-start ROM below once and never type it again. A
telnet session that is open when the Beeb is reset stays connected and says
`[BBC not attached: ...]` until the hooks are back.

### Drawing what is already on the screen

The Pi only knows what has been printed since it hooked in, so a terminal that connects after
the Pi was restarted, or after a reset the Pi did not see, would otherwise miss text that is
already on the Beeb's screen. With the auto-start ROM fitted the Pi can simply ask for it, and
nothing shows on the Beeb:

- The ROM takes the Beeb's buffer-remove vector (REMV). Whatever is waiting for a key calls it
  over and over, outside any interrupt, so that is a safe place to run code.
- The Pi puts one byte, `&FF`, in the keyboard buffer. REMV sees it come out and keeps it from
  the program; the ROM reads every character cell of the screen (OSBYTE 135) and sends the ones
  that are not blank to the Pi as `VDU 31,x,y,char` with the screen drivers off, then puts the
  cursor back. The Pi clears the terminal and draws that.
- It is done once whenever a terminal connects, and on F11 or Ctrl-L. It takes a second or two
  (about a millisecond per cell); characters only, not colours.
- It runs on the host machine, so it works with a 6502 second processor on, and on a BBC B
  (MOS 1.2) and a Master 128 (MOS 3.20), which is how it was tested.
- If the Beeb is busy in a program that is not reading the keyboard, the request waits in the
  buffer until the program does. Without the ROM the Pi draws what it saw printed instead.

### Surviving BREAK: the auto-start ROM

`telnetd.rom` is a 16 KB sideways ROM, a few dozen bytes of code, that answers
every reset by running helper 20. The image is `firmware/Pi1MHz/telnetd.rom`.
Burn it into an EPROM, or put it on the SD card (`/Pi1MHz/telnetd.rom`) and load
it into sideways RAM the way you load any ROM image, then press CTRL-BREAK. It
stays there across BREAK, and from then on every BREAK prints `TelnetD` and the
session is back.

**The ROM does not survive switching the Beeb off.** Ordinary sideways RAM is
cleared when the power goes, so after a power-on the ROM is simply not there, and
the daemon is not started until something loads it again (see "Starting at
power-on" below). What the ROM gives you is the daemon back after every BREAK and
CTRL-BREAK for as long as the power stays on. If your sideways RAM is
battery-backed, or the ROM is burnt into an EPROM, it is there at power-on too.

**In an EPROM it is there at power-on.** The image, `firmware/Pi1MHz/telnetd.rom`,
is exactly 16 KiB, so a 27C128 or compatible holds it, and it fits a ROM socket.
A ROM that is present at power-on answers the Beeb's first reset call, before the
Beeb tries its boot disc, and because it waits for the Pi (above) it holds the
whole boot until the Pi is up, which should also give the Pi's emulated hard disc
time to be ready before ADFS looks for it. **That last effect is expected, not yet
measured:** without the ROM, a power-on boot from a Pi-served disc was seen to fail
about as often as it worked (below). Read the chip back after programming; the
image's MD5 is `2B0722122006BCCBE7F730D702A2E82F`.

**On a Master 128 also `*INSERT` the bank** (`*ROMS` shows which one `TelnetD`
went into): the Master only starts ROMs marked as inserted, and a ROM loaded after
the last reset is listed as `unplugged` until it is. The mark is kept in the
Master's battery-backed memory. If your sideways RAM is battery-backed, the ROM
stays in it, and then loading it once is all it takes for the telnet daemon to
start by itself at every power-on and BREAK.

**At power-on the ROM waits for the Pi.** The Pi is normally powered from the
Beeb, so when you switch the Beeb on the Pi is still booting (about two and a
half seconds) while the Beeb checks its ROMs. After a power-on the ROM therefore
waits, up to about six seconds, for the Pi to answer before it starts the daemon;
after a BREAK it does not wait. If no Pi ever answers it gives up and the Beeb
boots on. Power-on is the one place the Beeb pauses for the Pi, so the first boot
of the day takes a little longer. It needs sideways RAM (a Model B needs a
sideways RAM board; a Master 128 has it), is the same
image on a B, B+ and Master 128, and does nothing if no Pi1MHz answers. To
remove it, switch the machine off or `*UNPLUG` its slot. Load it only once per
power-on: a second copy in another bank answers the same reset call.

## What your keys do

| You press | The Beeb gets |
|---|---|
| ordinary keys | the same characters |
| RETURN | RETURN |
| Backspace, Delete | DELETE |
| arrow keys | the cursor keys (the MOS's copy-cursor editing works) |
| End | COPY (copies the character under the copy cursor) |
| F1 to F9, F10 | f1 to f9, f0 |
| F12 | BREAK: a soft reset, the same jump as `CALL !-4`, so it works whatever is running. The terminal is cleared and the cursor put where the Beeb reports it; the session comes back when something hooks the daemon in again (HELPERS or the auto-start ROM). Boot banners printed before the hook are not shown. |
| F11 or Ctrl-L | Draw the screen again: the Pi asks the auto-start ROM for what is on the Beeb's screen (see above). Nothing shows on the Beeb. |
| the pound sign | the Beeb's pound (character 96) |
| ESC | the character 27 (see below) |
| Ctrl-letters | the control code, `Ctrl-A` = 1 and so on |

A lone ESC is held for a tenth of a second to see whether it is the start of
an arrow or function key.

## What you see

The Beeb's output is its VDU stream, and the daemon turns it into ANSI for
your terminal: `CLS` and `MODE` clear the screen, `TAB(x,y)` (VDU 31)
positions the cursor, `COLOUR` sets the text and background colours, and DELETE
rubs out a character. The parameter bytes of the VDU codes a terminal cannot
show (graphics, palette, VDU 23) are swallowed, so they do not print as
rubbish. In Mode 7 the teletext colour codes become colours, and a colour is
reset at the end of each line; in the other modes `COLOUR` stays set from line
to line, as on the Beeb. The colour numbers are the mode's own: in MODE 1 and 5
`COLOUR 1`, `2` and `3` are red, yellow and white, in the two-colour modes `1` is
white, and `VDU 19` changes them, as it does on the Beeb. Text already printed
keeps the colour it was drawn in, which a terminal cannot change afterwards.
Output the operating system prints carries no colour of its own, it just
continues in the colour the Beeb has set, so a terminal that connects is told
that colour before anything else. `VDU 23,1,0` and `VDU 23,1,1` hide and show
the terminal's cursor as they do the Beeb's. A pound sign comes out as UTF-8.

It is text only: what a program draws with graphics or by writing straight to
screen memory does not appear. The window of the terminal should be at least
as large as the Beeb's screen for the positioning to look right.

### The daemon keeps a picture of the Beeb's text screen

The Beeb's screen is not the terminal's. Its size depends on the mode (40, 80 or
20 columns, 25 or 32 rows), it wraps the cursor the moment a line is full where
a terminal waits for the next character, and the MOS scrolls inside a text window
without telling anyone. So the daemon follows every VDU code and keeps its own
copy of the screen, and sends an exact cursor position or a scroll wherever the
terminal would otherwise drift. It does this all the time, whether or not anyone
is connected, so **when you connect, your terminal is drawn from it**: you see
what the Beeb's screen holds, in its colours, and the cursor where the Beeb's is.

It can only follow what it sees. Helper 20 asks the MOS for the screen mode
(OSBYTE 135) and the text cursor (OSBYTE 134) every time it hooks in, and tells
the Pi, so after a CTRL-BREAK the daemon knows the mode and where the cursor is;
what is on the screen it learns as it is printed. If the helper is an older one
that does not report, the daemon assumes `telnetd_mode` (default 7) and does not
trust its cursor position until the Beeb sends a `CLS`, `MODE`, `TAB`, `HOME` or
a text window; type `CLS` once.

What the Beeb prints in the first moments after the helper hooks in is kept (the
first six lines, up to 400 bytes, until a screen-control code). With the
auto-start ROM that is the ADFS and BASIC banners: the ROM hooks in at the first
service call, before they print. A connecting terminal is greeted with them, and
then gets the Beeb's screen drawn under the greeting, as plain lines starting at
the first one that has anything on it and ending at the Beeb's cursor. Nothing
is cleared, so what was already in your terminal stays in its scrollback.

The terminal's rows are then not the Beeb's, so until the Beeb next clears its
screen (`CLS` or `MODE`) the daemon sends only relative moves: lines wrap by a
carriage return and line feed, and the first program that positions the cursor
with `TAB` clears the terminal once and takes it over. The copy cursor's mark needs
the rows to match, so it starts after the first `CLS`.

Text windows narrower than the screen scroll correctly on the Beeb, but the
terminal is not scrolled to match.

### The copy cursor

BASIC's cursor editing has two cursors: the one where typing goes, and the copy
cursor that the arrow keys move over the screen and End (COPY) copies from. The
MOS moves the second one itself and never sends it down the serial line, so a
terminal would show only the first. The daemon follows the arrow keys, End and
RETURN, shows the copy cursor as a reversed character, and moves it as COPY
takes characters, as the MOS does. The mark appears once the Beeb has been quiet
for a few hundredths of a second, so that it follows whatever has just been
typed. RETURN or ESC removes it. It is never put on a cell the daemon has not
seen drawn, so after connecting, `CLS` and `LIST` again if you want to edit a
line that was on the screen before the daemon saw it. `telnetd_copycursor=0`
turns it off (a game that reads the arrow keys would otherwise move a mark
about).

## Things to know

- **ESC and Ctrl-C raise the Beeb's ESCAPE**, so they stop a running BASIC
  program (error 17, "Escape") as the real key does, even when the Beeb is busy
  and its keyboard buffer is full of type-ahead, and they discard what was typed
  ahead. A lone ESC is told from the start of an arrow or function key by waiting
  a tenth of a second. The catch: a program that has set `*FX229,1` so that ESC
  is an ordinary key (a few games) never gets the character 27 from telnet, only
  the ESCAPE condition. The daemon writes the MOS's escape flag directly (bit 7 of
  &FF), which is safe from an interrupt, rather than calling the MOS.
- **One session at a time.** A second connection is told the BBC is in use
  and closed. The exception is a session that has died: if the client's machine
  crashed or the client was killed, the old session may still be holding the
  slot. When the same address connects again and the old session has made no
  progress for 10 seconds while something was waiting on it (output not
  acknowledged, or typing it could not pass on), the old session is dropped and the
  new one takes over. A session that is only quiet is never replaced, nor is one
  from another address. After 30 seconds with no progress a session is dropped
  anyway. The Status page's Telnetd line counts the `replaced` and `dropped`.
- **While helper 20 is in, the modem is off.** The redirected RS423 stream is
  the daemon's, not the [WiFi modem](serial-modem.md)'s; run helper 19 to get
  the modem back.
- **Nobody connected:** the Beeb's output is read and thrown away, so the
  Beeb never stalls waiting for it. Keys you type at the Beeb are unaffected.
- **Printing is a little slower while helper 20 is in.** Everything printed is
  also sent to the Pi: a loop of 1,500 `PRINT`s took 17.8 s against 15.1 s with
  it off (about 18%, measured in the first sessions). It does not depend on whether a
  client is connected. `*FX3,0` turns the copy off and `*FX3,1` back on.
- **Function keys follow your `*KEY` definitions**, as the real keys do, and
  the cursor keys edit with the copy cursor (cursor up, then COPY, which is End
  on a PC keyboard). `*FX4,1` and `*FX225,128` make them return their codes
  instead, for a program that reads them.
- **A vanished client is dropped.** An idle session is sent a telnet NOP every
  30 seconds, which every client ignores; one whose machine has gone away does
  not answer, and the session closes by itself within a few minutes, freeing
  the daemon for the next one.
- **Keys wait for the Beeb.** The Beeb's keyboard buffer holds 32 characters. A
  paste is fed in as the Beeb takes it, so a long paste while a program is
  not reading the keyboard simply waits.

## RS423

The daemon works on the MOS's RS423 *buffers* (what `*FX3,1` copies the screen
into, and what the Pi's redirector empties), not on the serial socket. So:

- **While helper 20 is in, a lead on the Beeb's real RS423 port sees nothing.** The
  6850 chip is silenced (its interrupts off, its baud rate and format left as they
  were, so handing the port back works). Baud-rate settings (`*FX7`, `*FX8`,
  `*CONFIGURE BAUD`) make no difference to the telnet link.
- A program that drives the 6850 directly, not through the MOS, does not see the
  redirect either.
- **A plain serial console on the real port, with no Pi, is a separate thing the MOS
  already does:** `*FX2,1` takes input from RS423 and `*FX3,7` sends the screen to
  it (the Master Reference Manual and the second-serial-port manual describe the
  pair). It cannot run together with the telnet daemon, and the daemon does not
  provide it. Running the two "either one at will" has been designed, not built
  (see the design record).

## Starting at power-on

Something the Beeb reads at power-on has to run helper 20: the Pi cannot start
anything on the Beeb by itself, because it is only a device on the 1MHz bus. The
way that has been tried and works, on a Master 128, is a boot file on the disc the
Master boots from (ADFS, drive 0, boot option 3 = Exec).

**The two files** (on the Master, `*BUILD` makes a text file; type its lines, then
press ESCAPE):

`!BOOT`

```
CHAIN"HELPERS"
```

`HELPERS`, a BASIC program (type it and `SAVE "HELPERS"`):

```
10REM Start the Pi1MHz telnet daemon (helper 20) once the Pi is up
20T%=TIME
30REPEAT UNTIL ?&FC88=&8E OR TIME-T%>1000
40IF ?&FC88=&8E THEN X%=20:CALL &FC88
```

then `*CONFIGURE BOOT`, so that power-on and CTRL-BREAK boot the disc (`*STATUS`
shows `Boot`). If the disc already has a `!BOOT`, keep its lines after the `CHAIN`
line: when `HELPERS` ends, BASIC reads the rest of the exec file as typed input.

- **Use `CHAIN`, not `*RUN`.** A saved BASIC program's execution address is in
  the BASIC ROM, so `*RUN HELPERS` jumps into whichever ROM is paged in at the
  time. On the Master it left the MOS in a state where `*INFO`, `*DUMP` and `*TYPE`
  printed nothing but blank lines until a CTRL-BREAK.
- **The wait matters.** The Pi is powered from the Beeb, so for its first two or
  three seconds `&FC88` does not read `&8E`; line 30 waits up to ten seconds for it,
  and if the Pi never answers the boot goes on without the daemon.
- **The ROM is not part of this.** With `*CONFIGURE BOOT`, every power-on and
  CTRL-BREAK runs `!BOOT` and so re-hooks the daemon. Loading the ROM from `!BOOT`
  as well would add another copy to a free sideways RAM bank every time. The ROM
  still covers a plain BREAK, which does not boot the disc.
- **A boot in progress can be stopped with ESC** from a telnet session once the
  daemon is hooked, as a stuck command can with the keyboard.

Measured on a Master 128: after a CTRL-BREAK with this boot file and
`*CONFIGURE BOOT`, the Pi saw its first helper selection 245 ms after the Beeb's
reset, and its Serial row read `hooked (telnet)` with nothing typed. **Not yet
measured:** the same after a power-off, where the Pi has only just started.

The same two commands work from any other boot file that is `*EXEC`ed (a DFS disc
with `*OPT 4,3`, MMFS) if you start the daemon by `*FX147,136,20` and `*GO FD00`,
but wait for the Pi first; a floppy is slow enough that the wait is rarely needed.

## Security

Telnet is not encrypted, and the daemon is as open as the web interface. If
`webdav_user` and `webdav_password` are both set in `Pi1MHz.cfg`, a session
asks for them first (`login:` and `Password:`; three wrong answers close the
session and refuse new ones for ten seconds). **The password crosses your
network in the clear**, so keep this to a network you trust. With no
password set the daemon lets anyone on the network type on your Beeb.

## Settings

| Key | Default | Meaning |
|---|---|---|
| `telnetd_port` | (off) | TCP port to listen on. `23` is the telnet port. Absent or `0` turns the daemon off. |
| `telnetd_login` | `1` | `0` skips the login even when `webdav_user` and `webdav_password` are set. |
| `telnetd_ansi` | `1` | `0` sends the Beeb's output exactly as it is, with no ANSI. For a program that does its own VDU handling. |
| `telnetd_utf8` | `1` | The pound sign as UTF-8; `0` sends it as Latin-1. |
| `telnetd_mode` | `7` | The Beeb's screen mode (0-7) until it sends a `MODE`. Its size cannot be read, and the daemon needs it to follow the text. |
| `telnetd_copycursor` | `1` | `0` does not mark the copy cursor in the terminal. |

`/status` on the web interface has a **Telnetd** row (the port, whether a
session is live, who from) and the **Serial** row says `hooked (telnet)`
while helper 20 is in.
