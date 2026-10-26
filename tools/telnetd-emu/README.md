# telnetd-emu - the telnet daemon against an emulated BBC

An end-to-end harness that needs no hardware. An emulated BBC Micro runs the real MOS
1.20, BASIC 2 and the TelnetD auto-start ROM, and beside it runs the Pi's own code:

```
fake TCP client <-> src/telnetd.c + telnetd_proto.c <-> src/serial_redirect.c <-> FRED <-> 6502: MOS, BASIC, TelnetD ROM
                    (the daemon)                     (the stub and its trips)      (beeb.py)
```

- `beeb.py`: an NMOS 6502 (documented opcodes, decimal mode, IRQ and BRK as the chip
  does them) and as much of a Model B as the MOS needs: RAM, sideways ROM banks, the
  system VIA (its timer gives the 100 Hz interrupt; no key is ever pressed), and FRED.
  FRED is the Pi's: a read is the byte the Pi has there, a write goes to the Pi, and the
  Pi's nIRQ joins the VIA's. The CRTC, video ULA, 6850, ADC and user VIA are idle.
- `fakepi.c`: the board around the firmware's files. FRED is 256 bytes; a Beeb write
  calls the callback the Pi registered for its address (the stub's TX, gate, full and
  control ports) and is kept only where the Pi made the address memory (the stub's
  workspace), as on the Pi. The polls run every emulated millisecond. Pi1MHz.cfg is set
  by the checks, and lwIP is a fake with one client connection (the headers are the
  session test's, `src/tests/telnetd/session/`). It is built with `src/serial_redirect.c`,
  `src/telnetd.c`, `src/telnetd_proto.c`, `src/net_telnet.c`, `src/lib/textparse.c` and
  `src/wifi/lwip_util.c` into a shared library that `run.py` loads.
- `run.py`: the transcript checks, and a live session.

So the Beeb boots as on the bench: the ROM finds the stub at &FCCC, hooks it in and
sends *FX3,1, and everything after that is the firmware's code.

## Running it

```
python3 tools/telnetd-emu/run.py --roms DIR                 the transcript checks (exit 1 on a failure)
python3 tools/telnetd-emu/run.py --roms DIR --listen 2323   a live session on 127.0.0.1:2323
         [--cfg telnetd_linemode=shell] [--cfg key=value ...]
python3 tools/telnetd-emu/wrap_check.py [cols] [rounds]     shell mode's edit line in a narrow terminal
```

Linux or WSL, with Python 3 and gcc. `--roms` (or `TELNETD_EMU_ROMS`) names a folder
holding `os12.rom` and `basic2.rom`, searched recursively, so b-em's `roms` folder works
as it is. The TelnetD ROM is the repository's `firmware/Pi1MHz/telnetd.rom`. No other
ROM images are kept here. A run of the checks takes under a minute; time is the
emulated Beeb's (2 MHz cycles), so every timer in the daemon is deterministic.

`--listen` serves one client at a time and runs the emulator flat out. Connect with
`nc 127.0.0.1 2323` (plain line mode), `telnet 127.0.0.1 2323` or PuTTY (screen mode;
Ctrl-\ m for shell mode).

## The checks

| Group | What is checked |
|---|---|
| screen mode | the ROM hooked the stub in (INSV in FRED); the greeting and the screen; `PRINT 2+2` typed and answered; MODE 7's colour codes as ANSI |
| shell mode | Ctrl-\ m; a line edited (Left, Backspace) and sent once; Up; a GET program taking Y, N, Q as single keys; Ctrl-V 81 rendered red; Ctrl-C in a loop; Ctrl-\ m back |
| a 20-column window | a line longer than the window: laid out across the rows after Home, End and Backspaces, and run |
| plain line mode (nc) | answers without the echo; `Mistake`; teletext codes as spaces, no escape codes; Ctrl-C; the status |
| `telnetd_linemode=on` | nothing negotiated; a line answered |
| the raw port | teletype mode: bytes as they are |

`wrap_check.py` drives the shell editor alone (`shpipe.c`) through random edits on lines
longer than the terminal, and checks a terminal model (`tools/beebterm.py`'s Screen,
which wraps as xterm does) after each: the prompt and the line laid out across the rows,
nothing left below, the cursor where the editor has it.

## Not covered

- A second processor: the 6502 here is the Beeb's only. The bench has one.
- The Beebium route of the earlier harness (`beebium_run.py`): Beebium 0.9.1 cannot map
  a device into FRED, and the real ROM looks for the stub at &FCCC, so the stub ran from
  RAM there with a copy of the daemon's glue. This harness runs the firmware's own code
  instead; a Beebium 1MHz-bus extension would be needed to run it there.
- The screen itself: nothing draws the Beeb's display. The checks read what the client
  is sent (through `beebterm.py`'s terminal model), and the Beeb's RAM where needed.
