# telnetd-emu - the telnet daemon against an emulated BBC

A test harness that fakes the Pi. It runs the real MOS 1.20 and BASIC 2 on an
emulated Model B and puts the telnet daemon's own byte logic beside it, so line mode
(and the mode decision) can be tried end to end without the hardware.

```
client bytes --> fakepi.c + src/telnetd_proto.c --> keys --> stub.py --> MOS keyboard buffer
client bytes <--         (the daemon's logic)    <-- Beeb output (*FX3,1) <-- stub.py <-- OSWRCH
```

- `beeb.py`: an NMOS 6502 and as much of a Model B as the MOS needs: RAM, sideways
  ROM banks, the system VIA (its timer gives the MOS its 100 Hz interrupt; no key is
  ever pressed) and FRED. CRTC, video ULA, 6850, ADC and the user VIA are idle. The
  screen is written into RAM as usual and nothing draws it.
- `stub.py`: the Pi's side of the FRED stub, as `src/serial_redirect.c` does it. The
  stub's bytes are the firmware's, at `&FCCC`, and the Beeb runs them. TX port, RX gate,
  consume and full writes, the RTI/JMP exit, the 2 ms back-off and the ESCAPE trip are
  modelled. Not modelled: the RS423 idle trip, BREAK and the auto-start ROM's reports.
  When BASIC first asks for a line, the harness hooks INSV and IRQ1V as helper 20 does,
  then types `*FX3,1` through the stub.
- `fakepi.c`: the glue `src/telnetd.c` has around the translators (key ring, mode
  decision, line mode pacing and echo, GA, ESCAPE), without lwIP. It is compiled with
  the firmware's `src/telnetd_proto.c` into a shared library, so the code under test is
  the daemon's own. Not here: the login, the banners, the repaint, the copy cursor and
  the screen scan.
- `run.py`: builds the library with gcc, boots the Beeb and runs the transcript checks.
  With `--listen` it serves one live session instead.

Time is the Beeb's (2 MHz cycles), not the wall clock, so the timeouts (the 750 ms
mode decision, the 1 s echo give-up, the 300 ms GA) are deterministic.

## Why not b-em or beebium

The b-em build in the bench rig has no way to connect the BBC's RS423 to a socket or
pipe. Its options are discs, paste, VDFS and the debugger. Beebium is not installed.
A Python emulator was the shortest path to a real MOS and BASIC talking to the
daemon's code.

## ROMs

No ROM images are kept here. Point `--roms` (or `TELNETD_EMU_ROMS`) at a folder
holding `os12.rom` (MOS 1.20) and `basic2.rom` (BASIC 2). The folder is searched
recursively, so b-em's `roms` folder works as it is.

## Running

Linux or WSL, Python 3 and gcc:

```
python3 tools/telnetd-emu/run.py --roms /path/to/b-em/roms
python3 tools/telnetd-emu/run.py --roms /path/to/b-em/roms --listen 2323    # then: nc localhost 2323
python3 tools/telnetd-emu/run.py --roms ... --listen 2323 --setting line    # telnetd_linemode=on
```

The checks take about 15 s and exit 1 if any fails. What they cover: the greeting,
the decision (nc, a telnet client that refuses the echo, a terminal that accepts it,
a late DO ECHO, the setting), `PRINT 2+2`, `*HELP`, `Mistake`, typing in a program,
`LIST` and `RUN`, Ctrl-C in a loop (`Escape at line 10`), VDU codes and teletext codes
stripped, INPUT, GET, MODE, a burst of lines (a paste), and IAC GA. Each transcript
is printed.

`--listen` runs the emulator flat out and uses a whole CPU core while it serves.

## Known limits it shows

- A program that reads a key with GET or INKEY and prints that same key followed by
  a new line produces output that cannot be told from the echo of a typed line, so
  it is taken out. `A=GET:PRINT CHR$A` is the case. `PRINT A` is not affected.
- The RETURN at the end of a line given to GET stays in the keyboard buffer and reaches
  BASIC as an empty line, which costs one extra prompt. A real keyboard would not type
  it.
