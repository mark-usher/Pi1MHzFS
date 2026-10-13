#!/usr/bin/env python3
"""Run telnetd.rom's service entry on an NMOS 6502 (py65) and check what every
machine with the ROM fitted depends on:

1. reset (service 1) with a Pi1MHz answering runs helper 20, once - the helper
   window at &FC88 gets X=20 - and gives A, X and Y back as they came, with the
   stack as it was, so the MOS still has its slot number and the call is left
   unclaimed for the ROMs below;
2. after a POWER-ON reset it waits for the Pi, which is booting for about two
   seconds while the Beeb runs its ROM scan: it polls the window until it
   answers (up to a bound), then runs the helper; if no Pi ever answers it gives
   up, runs nothing, and still gives everything back;
3. after any other reset (soft BREAK, CTRL-BREAK) it does not wait: the Pi is
   already up;
4. every other reason code is passed on untouched, with no OS call;
5. the image has the header the MOS and the helpers' own loader look for: a
   service ROM with a (C) string, 16 KiB;
6. only NMOS 6502 instructions are executed, so it runs on a B and a Master.

usage: check_rom.py ROM
"""
import sys

try:
    from py65.devices.mpu6502 import MPU
    from py65.memory import ObservableMemory
except ImportError:
    import os
    print("py65 not installed (pip install py65): skipped the telnetd.rom checks")
    sys.exit(1 if os.environ.get("CI") else 0)

ROM_BASE = 0x8000
SERVICE = ROM_BASE + 3
HELPER = 0xFC88
OSBYTE = 0xFFF4
RETURN_TRAP = 0xFF00
WAIT_TURNS = 40            # the ROM's bound on polls after a power-on
# Every opcode the ROM may execute (the service entry's JMP included).
ALLOWED = {0x4C, 0x48, 0x68, 0x8A, 0x98, 0xA8, 0xAA,     # JMP PHA PLA TXA TYA TAY TAX
           0xAD, 0xA9, 0xA2, 0xA0, 0xC9, 0xE0,           # LDA abs/imm LDX# LDY# CMP# CPX#
           0xD0, 0xF0, 0x88, 0xCA, 0x38, 0xE9,           # BNE BEQ DEY DEX SEC SBC#
           0xBD, 0x8D, 0x99, 0xAC,                       # LDA abs,X  STA abs  STA abs,Y  LDY abs
           0xB1, 0xDD, 0x29, 0xB0, 0xC8, 0xE8,           # LDA (zp),Y  CMP abs,X  AND#  BCS  INY  INX
           0xBA, 0xAE, 0x9D, 0x18,                       # TSX  LDX abs  STA abs,X  CLC (claim REMV)
           0x20, 0x60}                                   # JSR RTS

checks = fails = 0


def check(cond, what):
    global checks, fails
    checks += 1
    if not cond:
        fails += 1
        print("  FAIL:", what)


def call(rom, a, x, y, pi_after=0, reset_type=2, pokes=None, watch=()):
    """Run the service entry as the MOS would.

    pi_after   the helper window answers (&8E) from the read after this many
               polls; None: never.  0 means it is up already.
    reset_type what OSBYTE &FD returns in X: 0 soft BREAK, 1 power-on, 2 CTRL-BREAK.
    pokes      {address: byte} set in memory before the call (the MOS vectors, a stub).
    watch      addresses whose writes are recorded in out["writes"], in order.
    Returns a dict of what happened."""
    mem = ObservableMemory()
    out = {"helper_writes": [], "osbytes": [], "reads": 0, "writes": []}

    def on_helper_write(addr, value):
        out["helper_writes"].append(value)
        return 0x8E                      # the window's opcode stays in place

    def on_helper_read(addr):
        out["reads"] += 1
        up = pi_after is not None and out["reads"] > pi_after
        return 0x8E if up else 0xFF      # a bus nobody drives reads as 0xFF

    mem.subscribe_to_write([HELPER], on_helper_write)
    mem.subscribe_to_read([HELPER], on_helper_read)
    if watch:
        mem.subscribe_to_write(list(watch), lambda addr, value: out["writes"].append((addr, value)))
    for i, b in enumerate(rom):
        mem[ROM_BASE + i] = b
    for addr, b in (pokes or {}).items():
        mem._subject[addr] = b
    # The window after a page select, and a helper that, like the real one,
    # leaves A, X and Y changed (it ends LDX #&FF, and prints with A and Y):
    # STX &FC88 / LDA #&55 / LDY #&66 / LDX #&FF / RTS
    for i, b in enumerate((0x8E, 0x88, 0xFC, 0xA9, 0x55, 0xA0, 0x66, 0xA2, 0xFF, 0x60)):
        mem._subject[HELPER + i] = b
    mem._subject[OSBYTE] = 0x60          # the MOS's OSBYTE: modelled below, then RTS
    mem._subject[RETURN_TRAP] = 0xEA
    mpu = MPU(memory=mem, pc=SERVICE)
    mpu.a, mpu.x, mpu.y = a, x, y
    mpu.sp = 0xF0
    ret = RETURN_TRAP - 1                # the MOS's JSR: the ROM's RTS lands on RETURN_TRAP
    mem._subject[0x100 + mpu.sp] = ret >> 8
    mem._subject[0x100 + mpu.sp - 1] = ret & 0xFF
    mpu.sp -= 2
    out["sp_before"] = mpu.sp + 2
    opcodes = []
    for _ in range(40_000_000):
        if mpu.pc == RETURN_TRAP:
            break
        if mpu.pc == OSBYTE:             # OSBYTE &FD,0,&FF: X = the last reset type
            out["osbytes"].append((mpu.a, mpu.x, mpu.y))
            if mpu.a == 0xFD:
                mpu.x = reset_type
        elif ROM_BASE <= mpu.pc < ROM_BASE + 0x4000:
            opcodes.append(mem._subject[mpu.pc])
        mpu.step()
    else:
        raise RuntimeError("the ROM did not return")
    out.update(regs=(mpu.a, mpu.x, mpu.y), sp_after=mpu.sp, opcodes=opcodes, mem=mem)
    return out


OSWRCH = 0xFFEE
COLS = (80, 40, 20, 80, 40, 20, 40, 40)
ROWS = (32, 32, 32, 25, 32, 32, 25, 25)


def run_command(rom, line, mode=1, screen=None, cur=(3, 4), hooked=True, stream0=1, slot=6, y0=0):
    """Run service call 4 with a command line, against a model of the MOS: OSBYTE 135 (the
    character at the text cursor, Y the mode), 134 (the cursor), 3 (the output streams) and
    OSWRCH (VDU 31 moves the cursor on the screen; what is sent while bit 0 of the stream is
    set is what the Pi receives)."""
    screen = screen or {}
    mem = ObservableMemory()
    for i, b in enumerate(rom):
        mem[ROM_BASE + i] = b
    text = line.encode() + b"\r"
    for i, b in enumerate(text):
        mem._subject[0x300 + i] = b
    mem._subject[0xF2], mem._subject[0xF3] = 0x00, 0x03
    if hooked:
        mem._subject[0x022A], mem._subject[0x022B] = 0xCC, 0xFC
    for i, b in enumerate((0x8E, 0x88, 0xFC, 0x60)):
        mem._subject[HELPER + i] = b
    helper = []
    mem.subscribe_to_write([HELPER], lambda addr, value: (helper.append(value), 0x8E)[1])
    for addr in (OSBYTE, OSWRCH, RETURN_TRAP):
        mem._subject[addr] = 0x60
    mem._subject[RETURN_TRAP] = 0xEA
    st = {"stream": stream0, "cx": cur[0], "cy": cur[1], "args": [], "pi": [], "streams": [], "calls": 0}
    mpu = MPU(memory=mem, pc=SERVICE)
    mpu.a, mpu.x, mpu.y = 4, slot, y0
    mpu.sp = 0xF0
    ret = RETURN_TRAP - 1
    mem._subject[0x100 + mpu.sp] = ret >> 8
    mem._subject[0x100 + mpu.sp - 1] = ret & 0xFF
    mpu.sp -= 2
    sp_before = mpu.sp + 2
    opcodes = []
    for _ in range(40_000_000):
        if mpu.pc == RETURN_TRAP:
            break
        if mpu.pc == OSBYTE:
            st["calls"] += 1
            if mpu.a == 135:
                mpu.x = screen.get((st["cx"], st["cy"]), 32)
                mpu.y = mode
            elif mpu.a == 134:
                mpu.x, mpu.y = st["cx"], st["cy"]
            elif mpu.a == 3:
                old = st["stream"]
                st["stream"] = mpu.x
                st["streams"].append(mpu.x)
                mpu.x = old
        elif mpu.pc == OSWRCH:
            c = mpu.a
            if st["stream"] & 1:
                st["pi"].append(c)
            if not st["stream"] & 2:                     # the screen drivers are on
                if st["args"]:
                    st["args"].append(c)
                    if len(st["args"]) == 3:
                        st["cx"], st["cy"] = st["args"][1], st["args"][2]
                        st["args"] = []
                elif c == 31:
                    st["args"] = [31]
        elif ROM_BASE <= mpu.pc < ROM_BASE + 0x4000:
            opcodes.append(mem._subject[mpu.pc])
        mpu.step()
    else:
        raise RuntimeError("the ROM did not return")
    st.update(regs=(mpu.a, mpu.x, mpu.y), sp_after=mpu.sp, sp_before=sp_before, helper=helper, opcodes=opcodes)
    return st


def run_remv(rom, x, v, c, old_y, old_c, screen=None, cur=(3, 4), hooked=True, a=0x5A, mode=1):
    """Call the REMV handler the way the MOS's extended vector entry does, with the MOS's own
    routine modelled by a stub that returns Y=old_y and C=old_c.  Returns what happened."""
    boot = call(rom, 1, 6, 0, pi_after=0, reset_type=2)
    handler = boot["mem"]._subject[0x0DE1] | (boot["mem"]._subject[0x0DE2] << 8)
    mem = ObservableMemory()
    for i, b in enumerate(rom):
        mem[ROM_BASE + i] = b
    screen = screen or {}
    mem._subject[0x0D9F], mem._subject[0x0DA0] = 0x00, 0x03          # the MOS's routine at &0300
    old = (0xA0, old_y, 0x38 if old_c else 0x18, 0xEE, 0x10, 0x03, 0x60)   # LDY #y / SEC or CLC / INC &0310 / RTS
    for i, b in enumerate(old):
        mem._subject[0x300 + i] = b
    mem._subject[0x310] = 0
    if hooked:
        mem._subject[0x022A], mem._subject[0x022B] = 0xCC, 0xFC
    for addr in (OSBYTE, OSWRCH, RETURN_TRAP):
        mem._subject[addr] = 0x60
    mem._subject[RETURN_TRAP] = 0xEA
    st = {"stream": 1, "cx": cur[0], "cy": cur[1], "args": [], "pi": [], "calls": 0}
    mpu = MPU(memory=mem, pc=handler)
    mpu.a, mpu.x, mpu.y = a, x, 7
    mpu.p = (mpu.p & ~0x41) | (0x40 if v else 0) | (1 if c else 0)
    mpu.sp = 0xF0
    ret = RETURN_TRAP - 1
    mem._subject[0x100 + mpu.sp] = ret >> 8
    mem._subject[0x100 + mpu.sp - 1] = ret & 0xFF
    mpu.sp -= 2
    sp_before = mpu.sp + 2
    for _ in range(40_000_000):
        if mpu.pc == RETURN_TRAP:
            break
        if mpu.pc == OSBYTE:
            st["calls"] += 1
            if mpu.a == 135:
                mpu.x = screen.get((st["cx"], st["cy"]), 32)
                mpu.y = mode
            elif mpu.a == 134:
                mpu.x, mpu.y = st["cx"], st["cy"]
            elif mpu.a == 3:
                old_stream = st["stream"]
                st["stream"] = mpu.x
                mpu.x = old_stream
        elif mpu.pc == OSWRCH:
            if st["stream"] & 1:
                st["pi"].append(mpu.a)
            if not st["stream"] & 2:
                if st["args"]:
                    st["args"].append(mpu.a)
                    if len(st["args"]) == 3:
                        st["cx"], st["cy"] = st["args"][1], st["args"][2]
                        st["args"] = []
                elif mpu.a == 31:
                    st["args"] = [31]
        mpu.step()
    else:
        raise RuntimeError("the handler did not return")
    st.update(a=mpu.a, x=mpu.x, y=mpu.y, c=mpu.p & 1, v=(mpu.p >> 6) & 1, sp_after=mpu.sp, sp_before=sp_before,
              old_calls=mem._subject[0x310])
    return st


def main(path):
    rom = open(path, "rb").read()

    check(len(rom) == 16384, "the image is 16 KiB")
    check(rom[0:3] == b"\0\0\0", "no language entry")
    check(rom[3] == 0x4C, "service entry is a JMP")
    check(rom[6] == 0x82, "type byte: a service ROM, no language")
    off = rom[7]
    check(rom[off] == 0 and rom[off + 1:off + 4] == b"(C)",
          "the copyright offset points at the 0 before (C), as the helpers' loader tests")
    check(rom[8] == 1, "binary version byte")
    check(rom[9:16] == b"TelnetD", "title")

    # 1. reset with the Pi already up (CTRL-BREAK)
    for a, x, y in ((1, 5, 3), (1, 15, 0), (1, 0, 255), (1, 7, 7)):
        r = call(rom, a, x, y, pi_after=0, reset_type=2)
        check(r["helper_writes"] == [20], f"CTRL-BREAK ({x},{y}): the helper window is selected once with X=20, got {r['helper_writes']}")
        check(r["regs"] == (a, x, y), f"CTRL-BREAK: A,X,Y given back as {(a, x, y)}, got {r['regs']}")
        check(r["sp_after"] == r["sp_before"], f"CTRL-BREAK: stack balanced ({r['sp_before']:#x} -> {r['sp_after']:#x})")
        check(set(r["opcodes"]) <= ALLOWED, f"only NMOS opcodes: {sorted(set(r['opcodes']) - ALLOWED)}")
        check(r["osbytes"] == [(0xFD, 0, 0xFF)], f"the only OS call is OSBYTE &FD,0,&FF: {r['osbytes']}")
        # two reads: the ROM's own look, and the opcode fetch of the JSR into the window
        check(r["reads"] == 2, f"CTRL-BREAK: no waiting - one look at the window and the call, got {r['reads']} reads")

    # 1b. a software BREAK can leave the interrupt vector at the stub the helper installed
    # before it: a stub is recognised and the vector it replaced put back, so the helper
    # does not mistake the old hook for somebody else's; and the Pi is told it was a reset.
    stub = {0xFCCC: 0xE0, 0xFCCD: 0x02, 0xFCD9: 0x34, 0xFCDA: 0xDC}      # the stub at &CC, keeping &DC34 at +0D
    r = call(rom, 1, 4, 0, pi_after=0, reset_type=0,
             pokes={**stub, 0x0204: 0xD8, 0x0205: 0xFC}, watch=(0x0204, 0x0205))
    check(r["writes"] == [(0x0204, 0x34), (0x0205, 0xDC)], f"a stale stub vector is put back: {r['writes']}")
    check(r["helper_writes"] == [20] and r["regs"] == (1, 4, 0) and r["sp_after"] == r["sp_before"],
          "... and the helper still runs and the registers and stack come back")
    r = call(rom, 1, 4, 0, pi_after=0, reset_type=0,
             pokes={0x0204: 0x50, 0x0205: 0xFC, 0xFC44: 0xA9, 0xFC45: 0x00}, watch=(0x0204, 0x0205))
    check(r["writes"] == [], f"a vector into FRED that is not our stub is left alone: {r['writes']}")
    r = call(rom, 1, 4, 0, pi_after=0, reset_type=0, pokes={0x0204: 0x00, 0x0205: 0xD0}, watch=(0x0204, 0x0205))
    check(r["writes"] == [], f"an ordinary vector is left alone: {r['writes']}")
    r = call(rom, 1, 4, 0, pi_after=0, reset_type=0, pokes={0x022A: 0xCC, 0x022B: 0xFC}, watch=(0xFCF4,))
    check(r["writes"] == [(0xFCF4, 0x21)], f"a hooked-in stub is told: the reset marker, with 'can be asked for the screen', goes to its control port: {r['writes']}")
    r = call(rom, 1, 4, 0, pi_after=0, reset_type=0, pokes={0x022A: 0xCC, 0x022B: 0xFC, 0x022D: 0xFF}, watch=(0xFCF4,))
    check(r["writes"] == [(0xFCF4, 0x20)], f"REMV already somebody's extended vector: the marker says it cannot: {r['writes']}")

    # 1c. the claim of REMV: the vector goes through the MOS's extended entry, the table says
    # where, and the MOS's own routine is kept in the unused USERV slot of the table
    r = call(rom, 1, 6, 0, pi_after=0, reset_type=2, pokes={0x022C: 0x34, 0x022D: 0xE5},
             watch=(0x022C, 0x022D, 0x0D9F, 0x0DA0, 0x0DE1, 0x0DE2, 0x0DE3))
    w = dict(r["writes"])
    check(w.get(0x022C) == 0x42 and w.get(0x022D) == 0xFF, f"REMV points at the MOS's extended entry for vector 22 (&FF42): {r['writes']}")
    check(w.get(0x0D9F) == 0x34 and w.get(0x0DA0) == 0xE5, "the MOS's own REMV is kept in the table")
    check(w.get(0x0DE3) == 6 and 0x80 <= w.get(0x0DE2, 0) < 0xC0, "the table entry names this ROM's slot and an address in it")
    r = call(rom, 1, 6, 0, pi_after=0, reset_type=2, pokes={0x022C: 0x42, 0x022D: 0xFF}, watch=(0x022C, 0x022D, 0x0D9F, 0x0DE1))
    check(r["writes"] == [], f"already an extended vector: left alone, nothing kept over: {r['writes']}")
    r = call(rom, 1, 6, 0, pi_after=None, reset_type=2, watch=(0x022C, 0x022D))
    check(r["writes"] == [], "no Pi: no vector is touched")
    r = call(rom, 1, 4, 0, pi_after=0, reset_type=0, pokes={0x022A: 0x00, 0x022B: 0xE0}, watch=(0xFCF4,))
    check(r["writes"] == [], f"no marker if the keyboard vector is not the stub's: {r['writes']}")
    r = call(rom, 1, 4, 0, pi_after=None, reset_type=2, pokes={0x022A: 0xCC, 0x022B: 0xFC}, watch=(0xFCF4,))
    check(r["writes"] == [], "no Pi: nothing is written")

    # 2. power-on: the Pi comes up while the ROM waits
    for after in (0, 1, 7, WAIT_TURNS - 1):
        r = call(rom, 1, 9, 2, pi_after=after, reset_type=1)
        check(r["helper_writes"] == [20], f"power-on, Pi ready after {after} polls: the helper runs once, got {r['helper_writes']}")
        check(r["regs"] == (1, 9, 2) and r["sp_after"] == r["sp_before"], f"power-on, Pi after {after}: registers and stack intact, got {r['regs']}")

    # ... and when it never does, the ROM gives up after its bound and carries on
    r = call(rom, 1, 9, 2, pi_after=None, reset_type=1)
    check(r["helper_writes"] == [], "power-on, no Pi ever: the helper is not run")
    check(r["regs"] == (1, 9, 2) and r["sp_after"] == r["sp_before"], f"power-on, no Pi: registers and stack intact, got {r['regs']} sp {r['sp_before']:#x}->{r['sp_after']:#x}")
    check(WAIT_TURNS <= r["reads"] <= WAIT_TURNS + 3, f"power-on, no Pi: gave up after about {WAIT_TURNS} polls, not {r['reads']}")

    # 3. a soft BREAK or CTRL-BREAK with no Pi: no waiting at all
    for rt in (0, 2):
        r = call(rom, 1, 9, 2, pi_after=None, reset_type=rt)
        check(r["helper_writes"] == [] and r["reads"] == 1, f"reset type {rt}, no Pi: one look and no wait (reads={r['reads']})")
        check(r["regs"] == (1, 9, 2) and r["sp_after"] == r["sp_before"], f"reset type {rt}, no Pi: registers and stack intact")

    # 4. everything else is passed on, with no OS call and no look at the Pi
    for reason in (0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 17, 254, 255):
        r = call(rom, reason, 6, 4, pi_after=0, reset_type=1)
        check(r["helper_writes"] == [] and r["osbytes"] == [] and r["reads"] == 0, f"service {reason}: no helper, no OS call, no look at the Pi")
        check(r["regs"] == (reason, 6, 4) and r["sp_after"] == r["sp_before"], f"service {reason}: passed on untouched")

    # 5. the request: the screen goes to the Pi, character by character, and nothing else changes
    scr = {(0, 0): 0x41, (5, 0): 0x42, (39, 31): 0x43, (2, 7): 0x44, (3, 3): 0x20, (9, 9): 0x00}
    for mode in range(8):
        cols, rows = COLS[mode], ROWS[mode]
        s2 = {k: v for k, v in scr.items() if k[0] < cols and k[1] < rows}
        r = run_remv(rom, 0, 0, 0, 0xFF, 0, screen=s2, cur=(1, 2), mode=mode)
        expect = [12]
        for y in range(rows):
            for x in range(cols):
                ch = s2.get((x, y), 32)
                if ch not in (0, 32):
                    expect += [31, x, y, ch]
        expect += [31, 1, 2]
        check(r["pi"] == expect, f"mode {mode}: the Pi gets CLS, VDU 31,x,y,char for each character, then the cursor (got {len(r['pi'])} bytes, expected {len(expect)})")
        check((r["cx"], r["cy"]) == (1, 2), f"mode {mode}: the cursor is back where it was on the screen")
        check(r["stream"] == 1, f"mode {mode}: the output streams are put back (stream {r['stream']})")
        check(r["c"] == 1 and r["a"] == 0x5A and r["x"] == 0 and r["sp_after"] == r["sp_before"], f"mode {mode}: reported empty, A and X and the stack come back")

    # 6. the REMV handler: a byte from the keyboard buffer passes through untouched, except the
    # one the Pi uses to ask for the screen, which is swallowed (nothing for the program) and
    # answered by sending the screen
    scr = {(0, 0): 0x41, (5, 2): 0x42}
    r = run_remv(rom, 0, 0, 0, 0x41, 0)
    check(r["y"] == 0x41 and r["c"] == 0 and r["a"] == 0x5A and r["x"] == 0 and r["old_calls"] == 1 and r["pi"] == [] and r["calls"] == 0,
          f"an ordinary key goes through: Y={r['y']:#x} C={r['c']}, one call to the MOS, no screen sent")
    r = run_remv(rom, 0, 0, 1, 0x00, 1)
    check(r["c"] == 1 and r["old_calls"] == 1 and r["pi"] == [] and r["calls"] == 0, "an empty buffer is reported empty and nothing is sent")
    r = run_remv(rom, 0, 0, 0, 0xFE, 0)
    check(r["y"] == 0xFE and r["c"] == 0 and r["pi"] == [], "&FE is a key like any other")
    r = run_remv(rom, 0, 0, 0, 0xFF, 0, screen=scr, cur=(3, 1))
    check(r["c"] == 1 and r["a"] == 0x5A and r["x"] == 0, f"the request is swallowed: the buffer is reported empty, A and X kept (C={r['c']})")
    check(r["pi"][:1] == [12] and 31 in r["pi"] and 0x41 in r["pi"] and 0x42 in r["pi"] and r["pi"][-3:] == [31, 3, 1],
          f"... and the screen is sent: CLS, the characters, the cursor back ({len(r['pi'])} bytes)")
    check(r["stream"] == 1 and (r["cx"], r["cy"]) == (3, 1) and r["sp_after"] == r["sp_before"], "... with the output streams and the cursor as they were, and the stack balanced")
    r = run_remv(rom, 0, 1, 0, 0xFF, 0, screen=scr)
    check(r["y"] == 0xFF and r["c"] == 0 and r["pi"] == [] and r["old_calls"] == 1, "looking at the byte (V set) leaves it, and sends nothing")
    for x in (1, 2, 3, 9):
        r = run_remv(rom, x, 0, 0, 0xFF, 0, screen=scr)
        check(r["y"] == 0xFF and r["c"] == 0 and r["pi"] == [] and r["old_calls"] == 1 and r["x"] == x,
              f"buffer {x} is not the keyboard: passed to the MOS untouched")
    r = run_remv(rom, 0, 0, 0, 0xFF, 0, screen=scr, hooked=False)
    check(r["c"] == 1 and r["pi"] == [], "with no Pi hooked in, the request byte is still not shown to the program, and nothing is sent")
    for x, v, c in ((0, 0, 0), (0, 0, 1), (0, 1, 0), (2, 0, 1), (3, 1, 1)):
        r = run_remv(rom, x, v, c, 0x41, 0 if c == 0 else 1)
        check(r["sp_after"] == r["sp_before"], f"REMV X={x} V={v} C={c}: stack balanced")

    print(f"{checks} checks, {fails} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
