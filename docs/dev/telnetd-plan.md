# Telnet daemon - design record

> **STATUS 2026-10-13: built, host-tested, and run on hardware with a Pi Zero W
> (debug kernel). The machine the early runs used was recorded as a BBC B and is
> not confirmed: the later runs were on a Master 128 (see section 12).** The byte translators (`src/telnetd_proto.c`) have 206,188
> host checks (`src/tests/telnetd`), the firmware builds warning-free for `rpi`
> and `rpi3`, release and debug. On the Beeb, over plain telnet, **MEASURED**
> (section 7): remote typing, DELETE, cursor-key copy-cursor editing, a `*KEY`
> expansion, a 247-character paste, CLS/TAB/teletext colour, a typed-in program
> run, a refused second session, no slowdown with nobody connected, ESC and
> Ctrl-C breaking a running program (section 9), the real keyboard beside the
> daemon, and BREAK with recovery (section 10). **Not yet measured:** the
> auto-start ROM running (it loaded and inserted on a Master, but its first
> power-on test stopped the boot, section 10, and the ROM has since been changed
> to wait for the Pi), the login (no credentials were set on the test Pi), a
> release kernel.

Let a `telnet` client sit at the Beeb's keyboard and screen: what it types goes
into the Beeb's keyboard buffer, what the Beeb prints comes back as ANSI. Works
beside the real keyboard, on a BBC B, B+ and Master 128. Replaces the clumsier
"dial out from the Beeb to a listener" arrangement, which needs the Beeb to
place the call.

## 1. Shape

```
telnet client                      Pi (this firmware)                         Beeb
  keys  --> lwIP --> td_recv --> tnd_in_byte --> key ring --> serial_redirect_write
                                                                    |  FRED stub, LDX #0
                                                                    v  JSR INSV
                                                              MOS keyboard buffer (0)
  ANSI  <-- lwIP <-- output buf <-- tnd_out_byte <-- serial_redirect_read
                                                                    ^  INSV hook, buffer 2
                                                                    |  *FX3,1 copies the VDU stream
```

- **`telnetd_proto.c/.h`** - two pure translators, no I/O: client bytes to Beeb
  keys (telnet IAC handling, CR NUL / CR LF, DEL, cursor and function keys, a
  lone-ESC timeout, the pound sign), and the Beeb's VDU stream to ANSI (CLS,
  MODE, TAB, COLOUR, teletext colours, DELETE; parameter bytes of VDU codes
  swallowed; VDU 21 hides everything until VDU 6).
- **`telnetd.c/.h`** - lwIP raw API (as the web server): one session, a login
  against `webdav_user`/`webdav_password`, a key ring that backs the client off
  with `ERR_MEM`, an output buffer pumped with `tcp_write`, and a poll called
  from `serial_redirect_poll`.
- **`serial_redirect.c`** - *telnet mode*: the control port (+28) takes 2 as
  well as 1/0, and the Pi rewrites the operand of the stub's `LDX #1` (+16) to 0
  or 1. The byte stream goes to `telnetd_poll` instead of `modem_poll` while it
  is in telnet mode.
- **Helper 20** (`6502code.asm`, page 20) - the same install code as helper 19,
  writing 2 to the control port and then `*FX3,1`; its `&FD03` entry undoes both.
  Only OSBYTEs and vectors that the B, B+ and Master share.

## 2. Why this and not something simpler (what was tried)

All on the machine the first sessions used (recorded as a BBC B; its MOS version
was not recorded), Pi Zero W, helper 19 as it was. **MEASURED** unless
marked.

1. `*FX3,1` copies the Beeb's output to RS423, and so through the redirect to the
   Pi, exactly as the VDU stream, including the parameter bytes of the control
   codes. (A typed `PRINT "HELLO"` came back as the echo, then `HELLO`, with LF
   CR line ends.) Chosen for the output half: documented, the same on every MOS,
   nothing to hook.
2. `*FX2,2` ("keyboard and RS423") does **not** merge the two for OSRDCH: the
   keyboard stays the input stream and RS423 bytes are only buffered. Bytes sent
   after it were found in the RS423 buffer after `*FX2,1`. So the existing stub
   cannot give keyboard-and-remote with any `*FX2` value.
3. An event-2 handler ("character entering a buffer") to move bytes from the
   RS423 buffer to the keyboard buffer was **never called**: a counter handler
   stayed at 0 over several lines of input, so the MOS does not raise event 2
   for characters the stub inserts through INSV.
4. A vsync (event 4) handler that drained buffer 1 into buffer 0 does run, but
   races BASIC for the bytes while input is still `*FX2,1`. It could work with
   the mode set from inside the same program; it also costs Beeb RAM and is lost
   at BREAK like everything else. Not pursued once the stub itself could insert
   into buffer 0.
5. **Inserting into buffer 0 from the stub** needs one operand changed (the
   stub's `LDX #1`). **MEASURED** to work: typed text, DELETE (127), ESC (27) and
   Ctrl-A (1) arrive as the same codes `GET` returns.
6. **The keyboard buffer does not hold what `GET` returns for special keys.**
   MEASURED with BASIC inserting codes itself (`*FX138,0,n`, no Pi code) and
   reading them back with `INKEY`: under `*FX4,1`, buffer codes 139-143 read back
   as 135-139 (COPY, left, right, down, up) - the MOS subtracts 4 - and under the
   default `*FX4,0` they are consumed as copy-cursor editing; codes 128-137 are
   the function keys, expanded through `*KEY` unless `*FX225,128`. The first
   version of the translator inserted 136-139 for the cursor keys, so up read as
   COPY (139 -> 135) and the others vanished. Fixed to 140-143 (left, right, down,
   up) and 139 (COPY); `tnd_in_*` and its tests now say so.

## 3. The stub operand

`serial_redirect.c` documents the stub. Bytes `A2 01` at +15/+16 load the buffer
number for the `JSR INSV` that delivers a received byte. +16 is the only thing
telnet mode changes. It is flipped like the other flags: one byte between two
whole, valid instructions, so whatever the 6502 fetches is complete. It is
written from the FIQ that handles the control-port write, with the RX gate closed
first and the Pi's receive FIFO emptied - what was queued for one buffer is not
delivered into the other.

Control port values: 0 unhooked (stub back to RS423), 1 hooked for the modem,
2 hooked for telnet. A BBC reset runs `serial_redirect_init`, which puts the stub
back to the RS423 default.

## 4. Behaviour decisions

- **One session**, refused with a message if busy. A single Beeb has one
  keyboard.
- **The Beeb's output is always read** in telnet mode, and dropped when nobody is
  logged in: the Beeb blocks in OSWRCH on a full RS423 buffer, and a Beeb that
  hangs because nobody is listening is worse than lost output.
- **No echo** back to the Beeb - what the Pi sends is typed there (the modem
  echoes because a modem does).
- **Login** reuses the web interface's credentials, so one password covers the
  Pi. Cleartext on the wire, documented.
- **Teletext**: Mode 7 colour codes become ANSI colours, reset at end of line.
- **Telnet**: the server offers WILL ECHO, WILL SGA and DO SGA; any other
  option is refused once (a bitmap stops loops).
- **Dead clients**: lwIP's TCP keepalive is not compiled in (and turning it on
  would change the web server's behaviour too), so an idle session is sent
  `IAC NOP` every 30 s; a client that is gone does not acknowledge it and lwIP
  aborts the connection after its retransmissions, which calls `td_err`.
  That was far too slow: on the owner's Master a client killed mid-output held the
  only slot for over ten minutes (every new connection was accepted, told "in use"
  and closed; BREAK on the Beeb does not touch the Pi). So the daemon keeps its
  own clock, `g_prog_us`, set when the session starts, when an ACK arrives
  (`td_sent`), when the client's data is taken, and when output or a refused
  receive begins to wait. `tnd_stalled()` (telnetd_proto.c, host-tested) is true
  when something is pending (`snd_queuelen != 0` or the receive was refused with
  `ERR_MEM`) and nothing has moved for the limit. At `ABORT_US` (30 s) the poll
  drops the session; at `STALE_US` (10 s) a new connection from the same
  address replaces it. An idle healthy session has nothing pending, so neither
  rule touches it. Counted as `replaced` and `dropped` in the status line.
- **No redirector, no daemon**: with `Serial_addr=-1` nothing calls
  `telnetd_poll`, so `telnetd_init` does not listen at all.

## 5. Known gaps

- **`*FX229,1` programs never see ESC as a character.** ESC and Ctrl-C raise the
  Beeb's ESCAPE condition (section 9); a program that has made ESC an ordinary
  key gets the condition from telnet, not the character 27. The stub cannot read
  `*FX229` (&0275) in its four spare bytes.
- **BREAK drops the hooks.** Helper 20 must be run again, unless the auto-start
  ROM is loaded (section 8). The 1MHz-WiFi ROM could have done the same from its
  own service call 1, but it is a separate project with its own licence, so it
  is untouched.
- Not tried on a Master 128. Nothing in helper 20 is B-specific; the stub was
  hardware-tested on a Master with the modem (`serial-modem-plan.md`).
- Text only: graphics and direct screen writes do not reach the terminal.

## 6. Tests

`src/tests/telnetd/run_tests.sh` (in `run_all.sh`): keys, UTF-8 and Latin-1 pound,
cursor and function keys (CSI and SS3, with modifiers), the ESC timeout
(including ESC ESC and a half-finished sequence), negotiation (replies once, SB
dropped whole, split across reads), every VDU code's parameter count, VDU 21,
teletext, and two fuzz runs (200,000 output bytes; 4,096 input bytes) asserting
the bounds `TND_IN_KEYS`, `TND_IN_REPLY` and `TND_OUT_MAX`. The `helpers` suite
checks the help screen still has a free row. One check failed before its fix
(ESC ESC), so the suite can fail.

## 7. Hardware session (first sessions: machine recorded as a BBC B; Pi Zero W 1.1, debug kernel, 2026-10-13)

**Results.** Run from a Windows PC over plain telnet to the Pi, with
`tools/beebterm.py` and short scripts, each check asserting its result:

- Banner, negotiation accepted, `[BBC not attached ...]` before the helper and
  `[BBC attached - press RETURN]` after; `/status` `Serial: hooked (telnet)` and
  `Telnetd: port 23, listening, n sessions, m refused`.
- 9 of 9 checks: `PRINT 6*7` = 42; DELETE; cursor-up twice then COPY nine times
  re-enters a line (real copy-cursor editing); f1 runs a `*KEY1` definition; a
  UTF-8 pound sign; a 247-character paste in one write arrives whole (LEN = 200);
  `CLS` then `PRINT TAB(5,3)` lands at row 4 column 6 of the client's screen; a
  teletext colour code; a typed-in `FOR` program runs.
- 12 of 12 key codes under `*FX4,1 *FX225,128`: a 97, up 139, down 138, right 137,
  left 136, COPY 135, f1 129, f5 133, pound 96, DEL 127, ESC 27, Ctrl-A 1 - after
  the fix in section 2 item 6. Before it: 5 of 17 in the first run (the 17 included
  checks thrown out of step by a pending `GET`), which is how the encoding was found.
- A second connection while one is live: told "the BBC is in use by another
  session", the first unaffected.
- Output with nobody connected: 1500 `PRINT`s took 1,777 cs with no client and
  1,776 cs with one watching - no stall. With the RS423 copy off (`*FX3,0`) the
  same loop took 1,507 cs: **the copy costs about 18%**.

**Still to do**, in this order:

(The known-good kernel is kept on the card as `debug/kernel-pre-telnetd.img`
and locally; the earlier steps of this list - boot, helper 20, RETURN and
`PRINT`, cursor keys, DELETE, f-keys, the paste, the client closed during a
loop - are the results above.)

7. Type on the Beeb's own keyboard with helper 20 in: it still works.
8. BREAK: the session reports `[BBC not attached ...]`; helper 20 again restores
   it. Then `&FD03`: ` Telnet: off`, `*FX3,0`, the modem (helper 19) works.
9. Repeat the checks above on a Master 128.
10. Load the auto-start ROM (helper 21), CTRL-BREAK: the session comes back
   with nothing typed.
11. Negative control for the stub change: with `telnetd_port` unset and helper
   19 as before, the modem (`ATDT`) behaves exactly as on the previous kernel.

## 8. The auto-start ROM

`beeb/telnetd-rom/telnetd.asm` assembles (beebasm, `build.sh`) to
`firmware/Pi1MHz/telnetd.rom`, 16 KiB. It is a service ROM whose only code is
the reset handler: on service call 1 it checks the helper window answers (the Pi
keeps `STX abs`, &8E, at &FC88) and runs `X%=20:CALL &FC88` as `LDX #20 : JSR
&FC88`, with A, X and Y saved and given back. Call 1, not 3, because a filing
system that claims 3 hides the call from ROMs below it (the reason the WiFi ROM
gives); call 1 is never claimed.
Helper 21 loads it into sideways RAM with the same `LOADFILETOSWR` macro as the
other ROM helpers, so it lands in any free RAM bank on a B or a Master, never
over a bank that already holds a ROM image (none free: "No SWR").

**The ROM cannot start the daemon at power-on on a machine whose sideways RAM is
volatile** (this Master's is: a power cycle clears it - measured, section 10), so
for those machines it is a BREAK re-hook only, and power-on needs a `!BOOT` or a
ROM that persists (user guide, "Starting at power-on"; untried). The wait below
matters only where the ROM is there at power-on: battery-backed RAM or an EPROM.

**Power-on wait.** The Pi is powered from the Beeb (section 10), so at power-on
it is still booting - about 2.5 s - when the Master reaches its ROM scan. After a
power-on reset (OSBYTE &FD, X=1; the 1MHz-WiFi ROM reads the same value) the ROM
polls the helper window for the Pi's opcode (&8E at &FC88) for up to 40 turns of
about 0.16 s each, a little over 6 s, then runs the helper; after any other reset
it looks once and does not wait; with no Pi it gives up and the Beeb boots on. The
turn counter lives on the stack, the ROM owning no workspace. Its one OS call is
OSBYTE &FD.

`src/tests/telnetdrom` (not in the default `run_all.sh`; it needs beebasm and
py65, and `beeb-roms.yml` runs it): the image rebuilds identically from source,
the header is what the helpers' loader looks for, and on an NMOS 6502 the reset
handler selects page 20 once, gives A, X and Y back although the helper clobbers
them, balances the stack, and passes every other reason on untouched; with
nothing at &FC88 it does nothing; after a power-on it waits for the Pi (ready
after 0, 1, 7 and 39 polls) and gives up after about 40 when none comes, and after
a BREAK it never waits. 78 checks. **Negative controls, run:** helper 21 instead
of 20 fails 4 checks; dropping the Y restore fails 8 (it passed until the
stand-in helper was made to clobber the registers, as the real one does); a ROM
that never waits fails 4; one that leaves the wait's counter on the stack does not
return at all.

**INFERRED, not yet run on a Beeb:** that service call 1 arrives after the Pi's
reset re-init of the stub (the Pi's `BREAK` row measures init about 5 ms after
the reset edge, the MOS reaches the ROM scan later), that `OSWRCH` and the
helper work at that point (the WiFi ROM prints its banner there), and that the
ROM scan order puts nothing between a reset and our call that undoes the hooks.

## 9. ESCAPE

**The problem.** The Beeb's ESCAPE is a condition - bit 7 of zero page &FF -
that the keyboard scan raises, not a character in the keyboard buffer. Inserting
27 with INSV is just data: a runaway BASIC loop carries on.

**What was measured on the Beeb first** (BASIC only, no Pi code): OSBYTE 153
(insert into a buffer, checking for ESCAPE) with 27 raises the condition (error
17) and with `*FX229,1` inserts 27 as data, as the keyboard does; OSBYTE 138 does
neither; both report a full buffer in carry after 32 inserts. And `?&FF=&80`
raises the condition and stops a running loop.

**Why a store to &FF and not OSBYTE 153.** The stub runs in IRQ context, and the
MOS keeps an OSBYTE call's A, X and Y in zero page (&EF-&F1): an interrupt that
lands inside an OSBYTE and makes its own call leaves the interrupted one with
changed registers. A store to &FF has no such hazard and is what the keyboard
scan does.

**How.** The stub grows by four bytes at its end (so no existing offset moves):
`STA &FF / CLC / RTS` at +2D. `serial_redirect_escape()` makes the next trip
through the stub an "escape trip": the Pi rewrites the low byte of the JSR's
target (+18) from INSV's trampoline to that routine, gives it &80 as the byte, and
opens the gate; the routine stores &80 in &FF and returns carry clear, so the
stub reports "inserted" and the Pi's consume write arrives as usual, where the Pi
points the JSR back at INSV in the same FIQ. One byte flips, between two whole
call targets, so whatever the 6502 fetches is complete. Nothing is taken from the
FIFO and nothing goes through the keyboard buffer, so a buffer full of type-ahead
cannot hold it up. A trip that is interrupted (the gate closes before the consume)
is asked for again. Like the keyboard's ESCAPE it discards the type-ahead: the Pi
empties its FIFO; the MOS empties its own keyboard buffer when the escape is
acknowledged (measured below).

**Mapping.** A lone ESC (after the 100 ms that tells it from an arrow key) and
Ctrl-C are the ESCAPE request, `TND_KEY_ESCAPE` (0, never a key); ESC then a
letter is an escape request followed by the letter.

**MEASURED, BBC with a Pi Zero W, 2026-10-13:** 7 of 7 - lone ESC stops a runaway
loop, Ctrl-C stops it, ESC gets through 80 characters of type-ahead (the Pi
reported the buffer full 71 times), none of that type-ahead reached the prompt
afterwards, an ESC at an idle prompt does no harm, ten loop-and-ESC rounds in a
row all stop, and the Beeb is normal afterwards. The Pi's `esc` counter went 0 to
14 for the 14 requests sent.

## 10. BREAK, local keyboard and the Master (hardware session, continued)

**MEASURED**, from a log of the daemon's own session (timestamps), with helper 20
in: keys typed at the Beeb's keyboard work, and their echo and results appear in
the telnet session; CTRL-BREAK makes the session report `[BBC not attached ...]`
and the Serial row go to "not hooked"; running helper 20 again re-attaches it.

**The Pi is powered from the Beeb.** A Master power-cycle was seen to reboot the
Pi (its counters zero, `Reset reason: 1000`, boot time 1.5 s + 0.6 s), so after
power-on the helper window does not answer for about 2.5 seconds, longer than
the Master takes to reach its ROM scan. The auto-start ROM therefore waits for the
window after a power-on (section 8). The first version of the ROM did not, and a
Master that was powered on with it inserted stopped after the 1MHz-WiFi ROM's
banner with the MOS error "Channel" and a `*` prompt (the MOS banner and
language never started). **Not resolved:** whether that was this ROM (the wait
that is now in it is the first suspect) or the 1MHz-WiFi ROM, which was also
inserted at the time. A second power-cycle with the sideways RAM cleared booted
normally. The isolating test is a power-cycle with only this ROM inserted.

**Also seen on the Master, not explained:** after helper 21 loaded the ROM, the
Pi kept asking for interrupts and the Beeb did not answer (the Pi's stall counter
climbed, 13 keys queued), and the Beeb's IRQ and INSV vectors read back as the
MOS's defaults (&E5FF and &EA43) with no reset edge counted by the Pi. So
something reset the vectors without a BREAK. A BREAK recovers it.

**Master specifics found:** a ROM loaded into sideways RAM must also be
`*INSERT`ed (see the user guide); with every free RAM bank already holding a
ROM, helper 21 stops with "No SWR" by design (it never overwrites a ROM image).

**Power-on (MEASURED 2026-10-13, Master 128 on a smart plug, driven through Home
Assistant: off, 10 s, on).** After the power cycle the Pi came back with a fresh
boot and `Serial: not hooked`, every counter zero: nothing ran helper 20. The
reason, given by the owner, is that the power cycle cleared the sideways RAM, so
the ROM was no longer in it. The Pi's BeebSCSI0 folder holds no disc image, so
the Master does not boot from the Pi today either. Open: which boot route to use
(a floppy `!BOOT`, a Pi-served ADFS boot disc, an EPROM) and the first test of
it. The earlier power-on stop with `Channel` after the WiFi ROM's banner is still
not explained.

## 11. Starting at power-on from the disc (owner's Master 128, 2026-10-13)

**What the Pi's config can and cannot do.** Reading `docs/user/configuration.md`
and the dev docs for anything that starts code on the Beeb at boot: nothing does.
The keys that act "at power-on" (`SCSIJUKE`, `VFSJUKE`, `fujinet_boot`, the
`JIM_Init.bin` preload) set up something on the Pi for the Beeb to read later; the
Beeb has to run a helper to use it. The Pi is a bus slave and cannot write the
Beeb's memory or raise an unclaimed interrupt that anything would answer, so a
`Pi1MHz.cfg` key cannot make the daemon start by itself. What can be configured is
the boot medium the Pi serves (a BeebSCSI disc set).

**What was built.** On the Master's drive 0 (`L3-63MB`, boot option 3), `!BOOT` is
`CHAIN"HELPERS"` and `HELPERS` is a BASIC program that waits for the Pi to answer
at `&FC88` (10 s bound) and then runs helper 20; `*CONFIGURE BOOT` is set. The
disc's original `!BOOT` (`*DIR FSL3`, `CH."StartFS"`, 23 bytes, the Level 3 file
server's start) is kept as `!BOOTOLD`, verified identical to the original on the
Master, and a copy of its bytes is held off the machine. At the owner's request the
file-server start was then left out of `!BOOT`.

**MEASURED.** The first boot-file flow test (a throwaway file with a harmless
second line): `CHAIN"HELPERS"` ran the helper (` Telnet: Pi`) and the exec file
carried on at the BASIC prompt. After a CTRL-BREAK with `*CONFIGURE BOOT`, the
Pi's BREAK row showed the first helper select 245 ms after the reset, and `Serial`
read `hooked (telnet)`. Not measured: a power-off boot, where the Pi starts at the
same moment.

**Mistakes made on the way, and what they cost** (so the next session does not
repeat them): `*RUN` of a BASIC file jumps to its exec address (&802B) in
whichever ROM is paged, and left the MOS printing blank lines for `*INFO`, `*DUMP`
and `*TYPE` until a CTRL-BREAK; typing a file's lines after `*BUILD` without
seeing BUILD's own `1` prompt can run those lines as commands (here possibly
`CH."StartFS"`, which started the server, and the Beeb stopped reading its keyboard
until an ESC from telnet ended it); `*FX3` with no value sets the output stream to
0 and silently switches off the RS423 copy; `*RENAME` with a `:0.$.` path on the new
name gives "Bad rename" where `*REN. old new` works; `*CAT :0` is not valid ADFS
syntax (`*CAT` alone, or a full path). The scripts now check for BUILD's prompt
before typing and compare the bytes of every file they write.

## 12. Parked: ideas not built, and problems not solved

The branch holds only what was built and tested. These were discussed or came up
and are deliberately not in it.

**Designed, not built**

- **A cfg-driven start list** (`helper_autostart=20` in `Pi1MHz.cfg`). The Pi
  cannot start code on the Beeb, so a cfg key cannot make anything start by itself,
  but it can publish a list that the auto-start ROM reads and acts on, so one EPROM
  serves every mode and the mode is chosen in `Pi1MHz.cfg`. Design: the Pi fills
  page 22 of the helper window (it is a spare, harmless `LDX #&FF : JMP &FC88` page
  in 6502code.asm) with a marker `&A5` at &FD05, a count at &FD06 and the helper
  numbers from &FD07; the ROM selects page 22 with a plain `STX &FC88`, lets the
  Pi map it, copies the list onto the stack under a 0 sentinel, hands the window
  back with `STX &FC88` of `&FF`, and runs each helper with `LDX n : JSR &FC88`
  (a helper cannot call another: the window it runs in is the one the first call
  replaces). A parser with names (`telnet`, `modem`) and a full set of host test
  cases was drafted and then removed; it is trivial to redo. The owner asked to
  finish the present work first.
- **RS423 and telnet "either, never both at once"**: output passes through to the
  real port when no session is connected (one byte flip, `CPX #2` to `CPX #&FF`),
  the stub also moves the MOS's own RS423 input inserts into the keyboard buffer,
  the 6850 stays enabled, and a physical ESC raises ESCAPE as the telnet one does.
  The stub is full (49 bytes to the last address before the JIM registers, the
  last four being the escape routine), so it needs about ten more bytes from
  moving the stub's base or from squeezing; the physical side needs a serial lead
  and terminal to test. A plain serial console with no Pi is a separate, simpler
  thing (user guide, "RS423").
- **A software BREAK over telnet** (`CALL !-4` is a soft BREAK; `*FX200` sets what
  BREAK clears). A soft BREAK resets the vectors, so it would drop the daemon, and
  on a Master with `*CONFIGURE BOOT` only power-on and CTRL-BREAK run `!BOOT`.
  Whether `*FX200,3` then `CALL !-4` counts as a booting reset on the owner's
  Master is untried.

**Not solved**

- **The power-on boot of a Pi-served disc is a race.** Two power-offs through Home
  Assistant: the first hooked the daemon (the Pi answered `/status` at 10 s), the
  second did not (7 s); a CTRL-BREAK then ran `!BOOT` at once. The owner's reading
  is that ADFS looks for the Pi's drive before the Pi is up. `*CONFIGURE DELAY` is
  the keyboard auto-repeat delay, not a disc delay (checked against the Master's
  own option list). What should remove it is a ROM that is present at power-on and
  waits for the Pi - the EPROM - which has not been fitted yet, so that is
  **untested**.
- **The `Channel` stop at power-on** after the 1MHz-WiFi ROM's banner, with both
  that ROM and the telnet ROM inserted. Not reproduced since the sideways RAM was
  cleared; cause unknown.
- **Vectors reset without a BREAK** on the Master after helper 21 loaded the ROM
  (IRQ and INSV read back as &E5FF and &EA43, the Pi stalling): unexplained.
- **The login** (webdav_user and webdav_password) has not been exercised: the test
  Pi has none set.
- **A release kernel** has been built for both boards but only the Pi Zero W debug
  kernel has run on hardware. A Zero 2 W (`kernel7.img`) has not been run at all.
- **Which machine each measurement was taken on is not certain.** The early
  sessions were written up as "a BBC B with a Pi Zero W". Later ones are plainly
  the Master 128: MOS 3.20 in `*HELP`, its ROM list and `*STATUS`, and the plug
  named for it in Home Assistant. Whether the Pi was moved from one to the other
  part-way was never asked. Treat every "BBC B" label in this record as unconfirmed,
  and run the hardware checklist (section 7) on a real BBC B before claiming
  that machine works; nothing has been run on a B+ at all.

## 13. Later in the hardware session: throughput, the receive path, the screen model (2026-10-13)

**Streaming a picture to the Beeb** (a PC rendering frames and typing them at a
52-byte receiver on the Beeb; not part of the branch) showed three faults that
ordinary typing never reaches.

- **The key ring refused whole chains.** `td_recv` took a packet only if the whole
  chain fitted twice over in the 4 KB ring, and returned `ERR_MEM` otherwise.
  lwIP can hand over several queued segments as one chain; one longer than 2 KB
  can never fit, so the receive path stuck for good with the ring empty and the
  window closed (the Telnetd status showed `ring 0, rx refused`). It now takes the
  data (`g_pend`) and turns it into keys as the ring has room, calling
  `tcp_recved` for what it has read, so the window still holds the client back.
  (`net_service.h` records the same lwIP behaviour for its own rings.)
- **`SER_BACKOFF_US` was 20 ms.** The MOS keyboard buffer holds 32 bytes, and the
  stub reports "full" when it is; the Pi then closed the gate for 20 ms. That is
  about 32 bytes per 25 ms: a ceiling of ~1.3 kB/s however fast the Beeb could
  draw. It is 2 ms now; the Beeb's own drawing is the limit (~1.7 kB/s in MODE 1
  with a character per call).
- **The 30 s drop timer** (section 12 and the stale-session text under 4 above)
  has been seen to work on the real Pi: a dead client was dropped and the next
  connection accepted. The status line also says why the last session ended and
  shows the ring fill, the receive window and the TCP state.

**The screen model.** `telnetd_proto.c` now keeps a model of the Beeb's text
screen (size by mode, text window, cursor, colours, the character and colour of
every cell) and `tnd_out_byte` emits an absolute position or a scroll where the
terminal would drift: at the right edge, at the bottom of the window, for TAB
inside a window. The model follows the Beeb whether or not a client is
connected; a connecting terminal is drawn from it (`tnd_out_repaint`, a row per
poll, with the Beeb's output held back meanwhile). It does not know the Beeb's
cursor position until a CLS, MODE, TAB, HOME, window or VDU 26 (`sync`), and
until then nothing is added to the output. The initial mode is `telnetd_mode`.
Teletext colour is reset when the cursor changes row, other modes' `COLOUR`
persists, and `VDU 23,1,n` hides or shows the terminal's cursor. This was found
the hard way: `ADFS *CAT` ends a full-width row with the Beeb's cursor-up, which
the terminal's lazy wrap puts one row too high.

**The copy cursor** the MOS moves internally (RS423 never sees it) is followed
from the keys the daemon sends (139-143, 13, ESC) and drawn as a reversed cell
once the Beeb has been quiet for 40 ms (`tnd_out_copyflush`); cells the model
has not seen drawn are never marked. Host-tested in `test_telnetd_proto.c`; seen
on the hardware in the byte stream, not yet judged by eye.

**The mode and the cursor reach the Pi through helper 20.** At hook time it asks the
MOS (OSBYTE 135 for the MODE, OSBYTE 134 for the cursor) and writes three bytes to
the stub's control port: `&80`+column, `&E0`+row, then `&10`+MODE, which is also what
now means "telnet mode" (`2` still does). The Pi (`ser_control`) takes the first two
as information and the third as the end of the report, and `telnetd_poll` then
starts the model at that mode and cursor (`tnd_out_assume_mode`, `tnd_out_at`).
Helper 20's page had two spare bytes before; the report fits by letting the messages
share one end of line, giving the three failure cases one text and shortening the
success message (" Telnet"). A second page for it was refused: pages are scarce.
The text the Beeb prints after the hook is kept as the boot banner (6 lines, 400
bytes, to the first control code) and printed in the greeting of each new session.
The repaint that follows does not clear: it prints the model's rows as plain lines
under the greeting, from the first with anything on it down to the cursor row, and
puts the cursor back with relative moves (`tnd_out_repaint`). The terminal's rows are
then offset from the Beeb's (`origin_ok` false, `tnd_out_origin_lost`): wraps are
done by hand (CR LF, needs `colok`, the cursor's column), scrolls and absolute moves
are not sent, the first TAB, window or home clears the terminal once and realigns
it (`abs_pos`), CLS and MODE realign it, and the copy cursor waits for that.
(An earlier version drew the banner dimmed on the empty rows of the repaint, after a
clear; a connection with the prompt on row 0 never showed it, and the clear was
unwelcome.)

Things not done: narrow text windows do not scroll the terminal; the screen
contents before the hook are not known (the helper could read them cell by cell with
OSBYTE 135, which needs more room than the page has - the auto-start ROM has 16 KB
and would be the place); `*FX3,0` stops the stream the model follows, so a program
that turns it off hides its output from the model too.

## 14. Helper 21 removed (2026-10-13)

Sections 6 to 11 and 13 above were written when a helper page, 21, loaded
`telnetd.rom` into sideways RAM with the same `LOADFILETOSWR` macro as the other
ROM helpers; they say "helper 21" where it was in use. Loading ROMs is now done by
dp111's new loader, so the page is a free slot again (pages 21 to 30 are reserved)
and the branch no longer carries a loader for this ROM. The ROM itself is
unchanged: put it in an EPROM, or load it into sideways RAM like any other image
(`/Pi1MHz/telnetd.rom` on the SD card) and press CTRL-BREAK, and on a Master
`*INSERT` its bank. Two things that came out of using helper 21 still apply: a copy
loaded a second time goes into another bank (a ROM image counts as taken to the
loader), so load it once per power-on; and helper 21's page had about 15 spare
bytes, too few for an "already loaded" test, which belongs in the new loader.

Helper 20's own message is now `TelnetD`, with no leading space, like the ROM's
title; being a line that starts with a letter it is kept with the boot banners.

