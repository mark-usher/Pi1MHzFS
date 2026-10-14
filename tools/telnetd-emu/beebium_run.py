#!/usr/bin/env python3
"""Fake the Pi on Beebium: the telnet daemon's byte logic against an emulated BBC.

    py -3.12 beebium_run.py                         the transcript checks on a Model B
    py -3.12 beebium_run.py --preset model-b-disc-65c02-copro    ... with a 6502 second processor
    py -3.12 beebium_run.py --listen 2323            a live session: nc / telnet to it

Windows Python with the beebium client package; the server is found from
--server or BEEBIUM_SERVER (default C:\\Beeb\\beebium\\bin\\beebium-model-b.exe), its
own ROMs are used.  The fake Pi is fakepi.c with the firmware's src/telnetd_proto.c,
built and run in WSL (gcc) as a program on a pipe.  See README.md.

How the Pi is faked.  Beebium 0.9.1 has no way to add a 1MHz-bus device without a
native extension (no SDK in the install), so the stub cannot sit in FRED.  It sits in
RAM instead (STUB_BASE, the RS423 input buffer page, which telnet mode never uses), as
the firmware's bytes with their own addresses moved there; the routine the firmware
keeps below the stub (ESCR_OFF) for ESCAPE (which also tells a second processor) is
there too.  The Pi's side of each port write is a breakpoint on the stub's store
instruction: the harness does what serial_redirect.c does for that write and steps
over the store, so the write never lands, as a write to a Pi port does not.  The Pi's
nIRQ is a breakpoint over the whole address space whose condition is "the gate is
open and interrupts are enabled"; it fires at an instruction boundary and the harness
then takes the interrupt as the 6502 does (PC and P pushed, I set, through &FFFE).
Everything else - the MOS's IRQ entry, IRQ1V, INSV into the keyboard buffer, OSWORD 0,
*FX3,1 and the Tube - is Beebium's.
"""
import argparse
import os
import socket
import select
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from beebium.client import Beebium            # noqa: E402

import run as harness                         # noqa: E402  (the transcript checks)
from stub import (STUB, REL, OP_JMP, OP_BIT, OP_RTI, CHAIN_EVERY, BACKOFF_US,   # noqa: E402
                  GATE, RX_BYTE, INBUF, JSR_LO, EXIT, EXIT_OLD, TRAMP, INSV_OLD, IRQ1V_OLD, FIFO)

STUB_BASE = 0x0A40                             # the stub, in RAM (page &0A: RS423 input buffer)
ESCR_OFF = 13                                  # the escape routine this far below it (serial_redirect.c SER_ESCR_OFF)
ESCR = STUB_BASE - ESCR_OFF
ESCR_BYTES = bytes([0x85, 0xFF, 0x2C, 0x7A, 0x02, 0x10, 0x03, 0x4C, 0x03, 0x04, 0x60])
PC_TX, PC_FULL, PC_CONSUME = STUB_BASE + 0x05, STUB_BASE + 0x1C, STUB_BASE + 0x21
SLICE_CYCLES = 4000                            # 2 ms: the Pi's poll, in emulated time
CLOCK = 2000000
DEFAULT_SERVER = r"C:\Beeb\beebium\bin\beebium-model-b.exe"
WSL_SRC = "/mnt/c" + HERE[2:].replace("\\", "/") if HERE[1] == ":" else HERE


class FakePiPipe:
    """fakepi.c's main(), in WSL: the daemon's logic on a pipe."""

    def __init__(self):
        src = WSL_SRC
        fw = src + "/../../src"
        exe = "/tmp/telnetd-emu-fakepi"
        subprocess.check_call(["wsl", "-d", "Debian", "--", "gcc", "-std=gnu2x", "-O2", "-Wall", "-Wextra",
                               "-DFAKEPI_MAIN", "-I" + fw, "-o", exe, src + "/fakepi.c", fw + "/telnetd_proto.c"])
        self.p = subprocess.Popen(["wsl", "-d", "Debian", "--", exe], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, bufsize=1)
        self.mode = 0
        self.kq = 0

    def call(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        taken, keys, out, esc, mode, kq = self.p.stdout.readline().split()
        self.mode = int(mode)
        self.kq = int(kq)
        return (int(taken), b"" if keys == "-" else bytes.fromhex(keys),
                b"" if out == "-" else bytes.fromhex(out), esc == "1")


class BeebiumRig:
    """The same face as run.Rig, on Beebium."""

    def __init__(self, server, preset):
        args = ["--speed", "unlimited"]
        self.ctx = Beebium.launch(server=server, preset=preset, extra_args=args)
        self.bbc = self.ctx.__enter__()
        self.dbg = self.bbc.debugger
        self.mem = self.bbc.memory.address.bus
        self.cpu = self.bbc.cpu
        self.pi = FakePiPipe()
        self.connected = False
        self.out = bytearray()
        self.tx = bytearray()                   # Beeb -> Pi, not yet given to the daemon
        self.rx = bytearray()                   # Pi -> Beeb keys
        self.gate_open = False
        self.esc_req = False
        self.esc_active = False
        self.backoff_until = None
        self.rx_count = 0
        self.hooked = False
        self.stops = 0
        for pc in (PC_TX, PC_FULL, PC_CONSUME):
            self.dbg.add_breakpoint(pc)

    def close(self):
        self.ctx.__exit__(None, None, None)

    # ---- time ----
    @property
    def cycles(self):
        return self.dbg.cycle_count

    @property
    def now(self):
        return (self.cycles // 2) & 0xFFFFFFFF

    def seconds(self):
        return self.cycles / CLOCK

    # ---- the stub in RAM ----
    def w(self, off, v):
        self.mem[STUB_BASE + off] = v

    def install(self):
        """Helper 20, from outside: the stub, the vectors, telnet mode."""
        self.dbg.ensure_stopped()
        stub = bytearray(STUB)
        for r in REL:                            # its own addresses, moved to its page
            stub[r] = (STUB_BASE + STUB[r]) & 0xFF
            stub[r + 1] = (STUB_BASE + STUB[r]) >> 8
        stub[0x2E], stub[0x2F] = 0xFF, 0x00
        self.mem[ESCR:ESCR + len(ESCR_BYTES)] = ESCR_BYTES
        self.mem[STUB_BASE:STUB_BASE + len(stub)] = bytes(stub)
        insv = self.mem[0x22A] | self.mem[0x22B] << 8
        irq1v = self.mem[0x204] | self.mem[0x205] << 8
        self.w(INSV_OLD, insv & 0xFF); self.w(INSV_OLD + 1, insv >> 8)
        self.w(IRQ1V_OLD, irq1v & 0xFF); self.w(IRQ1V_OLD + 1, irq1v >> 8)
        self.w(EXIT_OLD, irq1v & 0xFF); self.w(EXIT_OLD + 1, irq1v >> 8)
        self.w(INBUF, 0)
        self.w(EXIT, OP_RTI)
        self.w(GATE, OP_JMP)
        self.mem[0x22A] = STUB_BASE & 0xFF; self.mem[0x22B] = STUB_BASE >> 8
        self.mem[0x204] = (STUB_BASE + GATE) & 0xFF; self.mem[0x205] = STUB_BASE >> 8
        self.hooked = True

    def gate_close(self):
        self.w(GATE, OP_JMP)
        self.gate_open = False
        if self.esc_active:
            self.esc_active = False
            self.esc_req = True
            self.w(JSR_LO, (STUB_BASE + TRAMP) & 0xFF)

    def arm_next(self):
        if self.esc_req:
            self.esc_req = False
            self.esc_active = True
            self.w(JSR_LO, ESCR & 0xFF)
            self.w(RX_BYTE, 0x80)
        elif self.rx:
            self.w(RX_BYTE, self.rx[0])
        else:
            return False
        return True

    def on_consume(self):
        if not self.gate_open:
            return
        if self.esc_active:
            self.esc_active = False
            self.w(JSR_LO, (STUB_BASE + TRAMP) & 0xFF)
        else:
            if not self.rx:
                return
            del self.rx[0]
            self.rx_count += 1
        self.w(EXIT, OP_JMP if self.rx_count % CHAIN_EVERY == 0 else OP_RTI)
        if not self.arm_next():
            self.gate_close()

    def on_full(self):
        if self.esc_active:
            self.on_consume()
            return
        self.gate_close()
        self.backoff_until = self.now + BACKOFF_US

    def escape(self):
        self.gate_close()
        self.rx.clear()
        self.esc_req = True
        self.backoff_until = None

    def stub_poll(self):
        if self.gate_open or not self.hooked:
            return
        if self.backoff_until is not None:
            if self.now < self.backoff_until:
                return
            self.backoff_until = None
        if (self.rx or self.esc_req) and self.arm_next():
            self.w(GATE, OP_BIT)
            self.gate_open = True

    def take_irq(self):
        """The 6502's response to nIRQ: PC and P (B clear) pushed, I set, through &FFFE."""
        pc, p, sp = self.cpu.pc, self.cpu.p, self.cpu.sp
        self.mem[0x100 + sp] = pc >> 8
        self.mem[0x100 + ((sp - 1) & 0xFF)] = pc & 0xFF
        self.mem[0x100 + ((sp - 2) & 0xFF)] = (p | 0x20) & ~0x10
        self.cpu.update(sp=(sp - 3) & 0xFF, p=p | 0x04,
                        pc=self.mem[0xFFFE] | self.mem[0xFFFF] << 8)

    # ---- one pass of the main loop ----
    def run_slice(self):
        """Run the Beeb to the end of a slice, answering the stub on the way."""
        target = self.cycles + SLICE_CYCLES
        cond = f"cycles >= {target}"
        if self.gate_open:
            cond += f" || (I == 0 && mem[{STUB_BASE + GATE:#x}] == {OP_BIT:#x})"
        with self.dbg.breakpoint(0x0000, end_address=0x10000, condition=cond):
            while True:
                self.dbg.run_and_wait_for_stop(timeout=60)
                self.stops += 1
                pc = self.cpu.pc
                if pc == PC_TX:                   # STA b+0: a byte for the Pi
                    self.tx.append(self.cpu.a)
                    self.cpu.pc = pc + 3
                elif pc == PC_CONSUME:            # STA b+C
                    self.cpu.pc = pc + 3
                    self.on_consume()
                elif pc == PC_FULL:               # STA b+F
                    self.cpu.pc = pc + 3
                    self.on_full()
                elif self.gate_open and not (self.cpu.p & 0x04) and self.cycles < target:
                    self.take_irq()
                else:
                    return                        # the end of the slice

    def step(self):
        self.run_slice()
        now = self.now
        if self.connected:
            taken, keys, out, esc = self.pi.call(f"P {now} {FIFO - len(self.rx)} {self.tx.hex() or '-'}")
            del self.tx[:taken]
            self.rx += keys
            self.out += out
            if esc:
                self.escape()
        else:
            self.tx.clear()
        self.stub_poll()

    # ---- run.Rig's face ----
    def boot(self):
        self.dbg.run_to_cycle(int(1.5 * CLOCK), clock_hz=CLOCK, wall_timeout=60)
        self.install()
        self.rx += b"*FX3,1\r"
        for _ in range(300):
            self.step()

    def run_ms(self, ms):
        for _ in range(int(ms * 1000 / (SLICE_CYCLES / 2))):
            self.step()

    def connect(self, setting="auto", ttx="rendered"):
        _, _, out, _ = self.pi.call(f"S {harness.SETTINGS[setting]} 7 {self.now} {harness.TTX[ttx]}")
        self.connected = True
        self.out = bytearray(out)

    def send(self, data):
        if isinstance(data, str):
            data = data.encode("latin-1")
        _, _, out, esc = self.pi.call(f"C {self.now} {data.hex() or '-'}")
        self.out += out
        if esc:
            self.escape()

    def collect(self):
        pass                                     # every answer carries the client's bytes

    def mode(self):
        return harness.MODES[self.pi.mode]

    def wait_quiet(self, quiet_ms=400, limit_ms=20000):
        quiet = t = 0.0
        slice_ms = SLICE_CYCLES / 2 / 1000
        while t < limit_ms and quiet < quiet_ms:
            before = len(self.out)
            self.step()
            pending = self.pi.kq or self.rx or self.tx
            quiet = 0 if (len(self.out) != before or pending) else quiet + slice_ms
            t += slice_ms
        return t

    def transact(self, line, quiet_ms=400):
        start = len(self.out)
        self.send(line + "\n")
        self.wait_quiet(quiet_ms)
        return bytes(self.out[start:])


def listen(r, port, setting):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    print(f"listening on 127.0.0.1:{port} (one session at a time)")
    while True:
        conn, _ = srv.accept()
        r.connect(setting)
        try:
            while True:
                ready, _, _ = select.select([conn], [], [], 0)
                if ready:
                    data = conn.recv(4096)
                    if not data:
                        break
                    r.send(data)
                r.step()
                if r.out:
                    conn.sendall(bytes(r.out))
                    r.out.clear()
        except OSError:
            pass
        conn.close()
        r.connected = False


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # the transcripts hold block characters
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default=os.environ.get("BEEBIUM_SERVER", DEFAULT_SERVER))
    ap.add_argument("--preset", default="model-b")
    ap.add_argument("--listen", type=int)
    ap.add_argument("--setting", default="auto", choices=harness.SETTINGS)
    a = ap.parse_args()
    r = BeebiumRig(a.server, a.preset)
    try:
        r.boot()
        print(f"preset {a.preset}: Tube {'present' if r.mem[0x27A] & 0x80 else 'absent'} (&27A)")
        if a.listen:
            listen(r, a.listen, a.setting)
        ok = harness.scripted(r)
        print(f"({r.stops} debugger stops)")
    finally:
        r.close()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
