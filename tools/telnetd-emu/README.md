# telnetd-emu - the telnet daemon against an emulated BBC

An end-to-end harness that needs no hardware. An emulated BBC Micro runs the real MOS
1.20, BASIC 2 and the TelnetD auto-start ROM (with `--tube`, BASIC in a 6502 second
processor), and beside it runs the Pi's own code:

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
- `tube.py` (with `--tube`): a 6502 second processor. The Tube ULA's registers, the host's
  side at &FEE0-&FEE7 and the parasite's at &FEF8-&FEFF, with their flags, FIFOs and
  interrupts as b-em has them (`src/tube.c`), and a 65C02 with 64K of RAM and its client
  ROM, at 3 MHz against the host's 2. The host gets the Tube host code from the Acorn
  1770 DFS 2.26 (TUBE HOST 2.30) in bank 14, the bench's filing system. BASIC is copied
  over at power-on and runs in the parasite, as on the bench; with a HiBASIC image in a
  `--roms` folder it is in bank 5 too, entered with `*FX142,5` as on the bench.
- `run.py`: the transcript checks, and a live session.

So the Beeb boots as on the bench: the ROM finds the stub at &FCCC, hooks it in and
sends *FX3,1, and everything after that is the firmware's code.

## Running it

```
python3 tools/telnetd-emu/run.py --roms DIR                 the transcript checks (exit 1 on a failure)
python3 tools/telnetd-emu/run.py --roms DIR --tube          ... with a 6502 second processor
python3 tools/telnetd-emu/run.py --roms DIR --listen 2323   a live session on 127.0.0.1:2323
         [--tube] [--cfg telnetd_linemode=shell] [--cfg key=value ...]
         [--debug]                                          every Tube register access printed
python3 tools/telnetd-emu/wrap_check.py [cols] [rounds]     shell mode's edit line in a narrow terminal
```

Linux or WSL, with Python 3 and gcc. `--roms` (or `TELNETD_EMU_ROMS`) names a folder
holding `os12.rom` and `basic2.rom`, searched recursively, so b-em's `roms` folder works
as it is; several folders can be given, separated by `:`. `--tube` also needs
`dfs226.rom` (the 1770 DFS 2.26) and `6502tube.rom` (the client ROM), both in b-em's
`roms`, and uses `hibasic.rom` (HiBASIC 4) if one of the folders has it. The TelnetD ROM
is the repository's `firmware/Pi1MHz/telnetd.rom`. No other ROM images are kept here.
Time is the emulated Beeb's (2 MHz cycles), so every timer in the daemon is
deterministic. A run of the checks takes about 75 s (29 checks); with `--tube` under 3 minutes (39 with HiBASIC, 33 without)
(the parasite's instructions are emulated too, one and a half for each of the host's
cycles).

`--listen` serves one client at a time and runs the emulator flat out. Connect with
`nc 127.0.0.1 2323` (plain line mode), `telnet 127.0.0.1 2323` or PuTTY (screen mode;
Ctrl-\ m for shell mode).

## The checks

| Group | What is checked |
|---|---|
| screen mode | the ROM hooked the stub in (INSV in FRED); the greeting and the screen; `PRINT 2+2` typed and answered; MODE 7's colour codes as ANSI |
| screen mode, more | a 125-character line typed and answered; Ctrl-C (ESCAPE) in a loop |
| shell mode | Ctrl-\ m; a line edited (Left, Backspace) and sent once; Up; a GET program taking Y, N, Q as single keys; a 125-character line shown once and answered; Ctrl-V 81 rendered red; Ctrl-C in a loop; Ctrl-\ m back |
| teletext markers | Ctrl-\ t and the status; Ctrl-V 84 in the edit line at once; markers in the output (a blue block, a reversed B); Ctrl-\ t back to rendered; `telnetd_teletext=markers` at a new session's start |
| a 20-column window | a line longer than the window: laid out across the rows after Home, End and Backspaces, and run |
| plain line mode (nc) | answers without the echo; `Mistake`; teletext codes as spaces, no escape codes (with `telnetd_teletext=markers`, which is for shell mode only); Ctrl-C; the status |
| `telnetd_linemode=on` | nothing negotiated; a line answered |
| the raw port | teletype mode: bytes as they are |
| `--tube` | all of the above with BASIC in the parasite, and: the MOS found the Tube and the parasite runs from RAM; BASIC copied to &8000 there; the boot greeting has "Acorn TUBE 6502 64K"; `PRINT ~PAGE,~HIMEM` gives &800 and &8000 |
| `--tube`, HiBASIC | `*FX142,5`: HiBASIC copied to &B800, PAGE &800, HIMEM &B800; in shell mode `PRINT 2+2`, a 125-character line, a GET program, Ctrl-C in a loop |

`wrap_check.py` drives the shell editor alone (`shpipe.c`) through random edits on lines
longer than the terminal, teletext codes typed with Ctrl-V among them (one-cell markers),
and checks a terminal model (`tools/beebterm.py`'s Screen,
which wraps as xterm does) after each: the prompt and the line laid out across the rows,
nothing left below, the cursor where the editor has it. `WRAP_DEBUG=1` prints the keys and
the editor's output of a failure.

## Not covered

- Tube transfers from a filing system (`*LOAD` into the parasite, R3 and its NMIs): there
  is no disc. The second processor's other languages and clients (the Z80, 32016, ARM
  ...), and its BREAK: nothing here presses BREAK.
- The Beebium route of the earlier harness (`beebium_run.py`): Beebium 0.9.1 cannot map
  a device into FRED, and the real ROM looks for the stub at &FCCC, so the stub ran from
  RAM there with a copy of the daemon's glue. This harness runs the firmware's own code
  instead; a Beebium 1MHz-bus extension would be needed to run it there.
- The screen itself: nothing draws the Beeb's display. The checks read what the client
  is sent (through `beebterm.py`'s terminal model), and the Beeb's RAM where needed.
