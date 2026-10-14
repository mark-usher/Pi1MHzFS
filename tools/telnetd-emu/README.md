# telnetd-emu - the telnet daemon against an emulated BBC

Test harnesses that fake the Pi. They run the real MOS 1.20 and BASIC 2 on an
emulated BBC and put the telnet daemon's own byte logic beside it, so line mode
and the mode decision can be tried end to end without the hardware.

```
client bytes --> fakepi.c + src/telnetd_proto.c --> keys --> the stub --> MOS keyboard buffer
client bytes <--         (the daemon's logic)    <-- Beeb output (*FX3,1) <-- the stub <-- OSWRCH
```

`fakepi.c` is the glue `src/telnetd.c` has around the translators: the key ring,
the mode decision, line mode pacing and echo, GA and ESCAPE. It runs without lwIP and
is built with the firmware's `src/telnetd_proto.c`, so the code under test is the
daemon's own. Not here: the login, the banners, the repaint, the copy cursor and the
screen scan. Time is the Beeb's (2 MHz cycles), so the 750 ms decision, the 1 s echo
give-up and the 300 ms GA are deterministic.

Both harnesses run the same transcript checks (`run.scripted`). What they cover: the
greeting; the decision (nc, a telnet client that refuses the echo, a terminal that
accepts it, a late DO ECHO, the setting); `PRINT 2+2`; `*HELP`; `Mistake`; typing in
a program, then `LIST` and `RUN`; Ctrl-C in a loop (`Escape at line 10`); VDU and
teletext codes stripped; INPUT; GET; MODE; a burst of lines (a paste); and IAC GA.
Then shell mode, typed one key at a time as from a terminal and checked through a
small terminal emulator (`Term`, what the user would see): a line, then a history
recall edited with Left, Backspace and a new character and run again; a MODE 7
program with codes typed through Ctrl-V, LISTed as markers and then rendered and
RUN; a GET program taking single keys; Ctrl-C in a loop; and the hot key to screen
mode and back. Each transcript is printed.

## Beebium (primary): `beebium_run.py`

```
py -3.12 tools\telnetd-emu\beebium_run.py
py -3.12 tools\telnetd-emu\beebium_run.py --preset model-b-disc-65c02-copro
py -3.12 tools\telnetd-emu\beebium_run.py --listen 2323          (then: nc localhost 2323)
```

Needs Windows Python with the `beebium` client package (0.9.1), the Beebium server
(`--server`, or `BEEBIUM_SERVER`; default `C:\Beeb\beebium\bin\beebium-model-b.exe`)
with its bundled ROMs, and WSL Debian with gcc. The fake Pi is built there and runs
as a program on a pipe (`fakepi.c` with `-DFAKEPI_MAIN`).

Beebium 0.9.1 cannot take a 1MHz-bus device without a native extension, and its
install has no extension SDK. So the stub does not sit in FRED:

- **The stub runs from RAM** at `&0A40` (the RS423 input buffer page, which telnet
  mode never uses). The bytes are the firmware's, with their own addresses moved
  there. The escape routine the firmware keeps below the stub (it also tells a
  second processor about ESCAPE) is `ESCR_OFF` (13) bytes below it.
- **Each port write is a breakpoint** on the stub's store instruction. The harness
  does what `serial_redirect.c` does for that write and steps over the store, so
  the write never lands, as a write to a Pi port does not.
- **The Pi's nIRQ is a breakpoint** over the whole address space, with the
  condition "the gate is open and I is clear". The harness then takes the interrupt
  as the 6502 does: PC and P are pushed, I is set, and execution goes through &FFFE.
- Everything else is Beebium's: the MOS's IRQ entry, IRQ1V, INSV into the keyboard
  buffer, OSWORD 0, `*FX3,1`, and the Tube with a second processor.

A run takes about 1.5 minutes, roughly 10,000 debugger stops. A native 1MHz-bus
extension serving `&FCCC` with a real nIRQ would be more faithful and faster. It
needs the Beebium source (for the extension API) and a Windows toolchain, neither of
which is installed.

## The Python 6502 (fallback): `run.py`

```
python3 tools/telnetd-emu/run.py --roms /path/to/roms
python3 tools/telnetd-emu/run.py --roms /path/to/roms --listen 2323
```

This harness runs on Linux or WSL with Python 3 and gcc, and needs no Beebium.

- `beeb.py`: an NMOS 6502 and as much of a Model B as the MOS needs. That is RAM,
  sideways ROM banks, the system VIA (its timer gives the 100 Hz interrupt, and no
  key is ever pressed) and FRED. The CRTC, video ULA, 6850, ADC and user VIA are
  idle.
- `stub.py`: the Pi's side of the stub, which sits in FRED at `&FCCC` as in the
  firmware. The escape trip uses the stub's own `+2D` routine, which sets `&FF`
  only (no Tube).
- `run.py`: it hooks in when BASIC first asks for a line, as helper 20 does, and
  then types `*FX3,1` through the stub.

A run takes about 15 s. `--roms` (or `TELNETD_EMU_ROMS`) names a folder holding
`os12.rom` and `basic2.rom`. The folder is searched recursively, so b-em's `roms`
folder works as it is.

No ROM images or Beebium binaries are kept in this repository.

`--listen` serves one session on 127.0.0.1 and runs the emulator flat out.

## Known limits the checks show

- A program that reads a key with GET or INKEY and prints that same key followed by
  a new line produces output that cannot be told from the echo of a typed line, so
  it is taken out. `A=GET:PRINT CHR$A` is the case. `PRINT A` is not affected.
- The RETURN at the end of a line given to GET stays in the keyboard buffer and
  reaches BASIC as an empty line, which costs one extra prompt.
