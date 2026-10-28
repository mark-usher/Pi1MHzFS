#!/usr/bin/env python3
"""The telnet daemon end to end on an emulated BBC Micro: the real MOS 1.20, BASIC 2 and TelnetD ROM on a
6502 (beeb.py), and the Pi's own code beside it - src/serial_redirect.c (the stub in FRED), src/telnetd.c
and src/telnetd_proto.c - built into a shared library with fakepi.c.  The Beeb boots and the ROM hooks the
stub in, as on the bench; a fake TCP client connects to the daemon.

    python3 run.py --roms DIR                 the transcript checks (exit 1 on a failure)
    python3 run.py --roms DIR --listen 2323   a live session on 127.0.0.1:2323 (nc, telnet, PuTTY)
           [--cfg key=value ...]              more Pi1MHz.cfg settings (telnetd_linemode=shell, ...)

DIR holds os12.rom (MOS 1.20) and basic2.rom (BASIC 2), searched recursively (b-em's roms folder works);
or set TELNETD_EMU_ROMS.  The TelnetD ROM is the repository's (firmware/Pi1MHz/telnetd.rom).  Linux or WSL
with Python 3 and gcc.  See README.md.
"""
import argparse
import ctypes
import os
import select
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from beeb import Beeb                          # noqa: E402
from beebterm import Screen                    # noqa: E402

FIRMWARE = ["serial_redirect.c", "telnetd.c", "telnetd_proto.c", "net_telnet.c",
            os.path.join("lib", "textparse.c"), os.path.join("wifi", "lwip_util.c")]
NAWS = lambda c, r: bytes([255, 250, 31, 0, c, 0, r, 255, 240])   # noqa: E731
BLUE_MARK = b"\x1b[34m\xe2\x96\x88"            # &84 as a marker: a solid block in blue


def find_rom(root, name):
    for d, _, files in os.walk(root):
        for f in files:
            if f.lower() == name:
                return os.path.join(d, f)
    raise SystemExit(f"{name} not found under {root}")


class Pi:
    """fakepi.c and the firmware's files, built here (gcc) and loaded."""

    def __init__(self):
        out = os.path.join(tempfile.gettempdir(), "telnetd-emu-fakepi-%d.so" % os.getpid())
        cmd = ["gcc", "-std=gnu2x", "-O2", "-Wall", "-Wextra", "-shared", "-fPIC", "-funsigned-char",
               "-I" + os.path.join(SRC, "tests", "telnetd", "session"), "-I" + SRC, "-I" + os.path.join(SRC, "wifi"),
               "-o", out, os.path.join(HERE, "fakepi.c")] + [os.path.join(SRC, f) for f in FIRMWARE]
        subprocess.check_call(cmd)
        lib = self.lib = ctypes.CDLL(out)
        os.unlink(out)
        u8p = ctypes.POINTER(ctypes.c_uint8)
        lib.fp_cfg.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.fp_start.argtypes = [ctypes.c_uint32]
        lib.fp_fred.restype = u8p
        lib.fp_nirq.restype = ctypes.c_bool
        lib.fp_write.argtypes = [ctypes.c_uint8, ctypes.c_uint8]
        lib.fp_poll.argtypes = [ctypes.c_uint32]
        lib.fp_connect.argtypes = [ctypes.c_uint16, ctypes.c_bool]
        lib.fp_send.argtypes = [ctypes.c_char_p, ctypes.c_int]
        lib.fp_recv.argtypes = [u8p, ctypes.c_int]
        lib.fp_client_open.restype = ctypes.c_bool
        lib.fp_status.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self._fred = lib.fp_fred()
        self._rbuf = (ctypes.c_uint8 * 65536)()

    def cfg(self, k, v): self.lib.fp_cfg(k.encode(), str(v).encode())
    def start(self, us): self.lib.fp_start(us)
    def fred(self): return ctypes.string_at(self._fred, 256)
    def nirq(self): return self.lib.fp_nirq()
    def write(self, a, v): self.lib.fp_write(a, v)
    def poll(self, us): self.lib.fp_poll(us & 0xFFFFFFFF)
    def connect(self, port, telnet): return self.lib.fp_connect(port, telnet)
    def send(self, b): self.lib.fp_send(b, len(b))
    def close(self): self.lib.fp_close()
    def open(self): return self.lib.fp_client_open()

    def recv(self):
        n = self.lib.fp_recv(self._rbuf, len(self._rbuf))
        return bytes(self._rbuf[:n])

    def status(self):
        b = ctypes.create_string_buffer(1024)
        self.lib.fp_status(b, len(b))
        return b.value.decode("latin-1")


class Rig:
    """The emulated Beeb and the Pi, and one client at a time."""

    def __init__(self, roms, cfg):
        self.pi = Pi()
        for k, v in cfg.items():
            self.pi.cfg(k, v)
        self.pi.start(0)
        mos = open(find_rom(roms, "os12.rom"), "rb").read()
        basic = open(find_rom(roms, "basic2.rom"), "rb").read()
        tdrom = open(os.path.join(ROOT, "firmware", "Pi1MHz", "telnetd.rom"), "rb").read()
        self.beeb = Beeb(mos, {15: basic, 1: tdrom}, self.pi)
        self.out = b""
        self.screen = None

    def run_ms(self, ms):
        self.beeb.run(int(ms * 2000))
        got = self.pi.recv()
        if got:
            self.out += got
            if self.screen is not None:
                self.screen.feed(got)
        return got

    def boot(self):
        """Power on: the ROM waits for the Pi, hooks the stub in, and BASIC's prompt comes."""
        for _ in range(60):
            self.run_ms(100)
            if "attached" in self.pi.status() or self.beeb.mem[0x0B00] != 0xFF and self._at_prompt():
                break
        self.run_ms(300)

    def _at_prompt(self):
        return False

    def connect(self, port=23, telnet=True, cols=80, rows=32):
        self.out = b""
        self.screen = Screen(rows, cols)
        self.pi.connect(port, telnet)
        if telnet and port == 23:
            self.pi.send(NAWS(cols, rows))
        self.run_ms(1500)
        for _ in range(100):                           # a window too small is told so first, for a while
            if "live" in self.pi.status() or "listening" in self.pi.status():
                break
            self.run_ms(100)

    def type(self, s, per_key_ms=40, after_ms=600):
        b = s.encode("latin-1") if isinstance(s, str) else s
        for i in range(len(b)):
            self.pi.send(b[i:i + 1])
            self.run_ms(per_key_ms)
        self.run_ms(after_ms)

    def send(self, s, after_ms=800):
        self.pi.send(s.encode("latin-1") if isinstance(s, str) else s)
        self.run_ms(after_ms)

    def close(self):
        self.pi.close()
        self.run_ms(1200)

    def rows(self):
        return ["".join(r).rstrip() for r in self.screen.grid]

    def text(self):
        return "\n".join(r for r in self.rows() if r)


# ---- the transcript checks ---------------------------------------------------------------------------------

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("  PASS " if ok else "  FAIL ") + name + ("" if ok else "\n         " + detail.replace("\n", "\n         ")))


def show(rig, title, last=8):
    rows = [r for r in rig.rows()]
    end = max([i for i, r in enumerate(rows) if r] or [0])
    print("  .. %s" % title)
    for r in rows[max(0, end - last + 1):end + 1]:
        print("     |%s" % r)


def checks(roms):
    print("== screen mode: a telnet client")
    rig = Rig(roms, {"telnetd_port": 23, "telnetd_login": 0, "telnetd_raw_port": 2323})
    rig.boot()
    insv = rig.beeb.mem[0x22A] | rig.beeb.mem[0x22B] << 8
    check("the ROM hooked the stub in (INSV at &%04X, in FRED)" % insv, 0xFC00 <= insv < 0xFD00, "INSV &%04X" % insv)
    rig.connect()
    check("the greeting and the screen", b"telnet" in rig.out, repr(rig.out[:200]))
    rig.type("PRINT 2+2\r")
    show(rig, "PRINT 2+2")
    check("PRINT 2+2 typed and answered", ">PRINT 2+2" in rig.text() and "4" in rig.text(), rig.text())
    rig.type("MODE 7\r", after_ms=800)
    rig.type('PRINT CHR$129;"RED"\r')
    check("MODE 7's red as ANSI", b"\x1b[31m" in rig.out or b"31m" in rig.out, repr(rig.out[-200:]))

    print("== shell mode: Ctrl-\\ m")
    rig.send("\x1cm")
    rig.type("PRINT 6*7", per_key_ms=60)
    show(rig, "PRINT 6*7 in the edit line")
    rig.send("\x1b[D\x1b[D\x7f8", after_ms=300)
    rig.send("\r", after_ms=1000)
    show(rig, "edited to PRINT 8*7, RETURN")
    t = rig.text()
    check("the edited line sent and answered once", t.count("PRINT 8*7") == 1 and "56" in t, t)
    rig.run_ms(300)
    rig.send("\x1b[A", after_ms=300)
    check("Up: the last line again", rig.rows()[rig.screen.r].endswith("PRINT 8*7"), rig.text())
    rig.send("\x15", after_ms=200)                     # Ctrl-U: the line gone
    rig.type('10 A$=GET$:PRINT "GOT ";A$:IF A$<>"Q" GOTO 10\r', per_key_ms=20)
    rig.type("RUN\r", per_key_ms=40, after_ms=800)
    for k in "YNQ":
        rig.send(k, after_ms=600)
    show(rig, "a GET program, Y N Q")
    t = rig.text()
    check("a GET program gets single keys", "GOT Y" in t and "GOT N" in t and "GOT Q" in t, t)
    rig.type("MODE 7\r", per_key_ms=40, after_ms=800)
    rig.type('PRINT "', per_key_ms=40, after_ms=100)
    rig.send("\x16" "81", after_ms=100)
    rig.type('RED"', per_key_ms=40, after_ms=100)
    rig.send("\r", after_ms=1000)
    check("Ctrl-V 81: a red code, rendered", b"\x1b[0;31mRED" in rig.out or b"31mRED" in rig.out, repr(rig.out[-160:]))
    rig.type("20 GOTO 20\r", per_key_ms=20)
    rig.type("RUN\r", per_key_ms=40, after_ms=500)
    rig.send("\x03", after_ms=1500)
    check("Ctrl-C stops a loop", "Escape at line" in rig.text(), rig.text())
    rig.type("NEW\r", per_key_ms=40, after_ms=600)
    rig.send("\x1ct", after_ms=300)
    check("Ctrl-\\ t: markers, the status says so", "teletext markers" in rig.pi.status(), rig.pi.status())
    rig.out = b""
    rig.type('PRINT "', per_key_ms=40, after_ms=100)
    rig.send("\x16" "84", after_ms=200)
    check("Ctrl-V 84: its marker in the edit line at once", BLUE_MARK in rig.out, repr(rig.out))
    rig.type('BLUE', per_key_ms=40, after_ms=100)
    rig.send("\x16" "9D", after_ms=100)
    rig.type('"', per_key_ms=40, after_ms=100)
    rig.out = b""
    rig.send("\r", after_ms=1200)
    answer = rig.out.split(b"\r\n", 1)[-1]
    check("markers in the output: a blue block, BLUE, a reversed B", BLUE_MARK + b"\x1b[39mBLUE\x1b[7mB\x1b[27m" in answer,
          repr(rig.out))
    show(rig, "markers", 3)
    rig.send("\x1ct", after_ms=300)
    rig.out = b""
    rig.send("\x1b[A\r", after_ms=1200)
    answer = rig.out.split(b"\r\n", 1)[-1]
    check("Ctrl-\\ t again: rendered, the status says so", b"\x1b[0;34mBLUE" in answer and BLUE_MARK not in answer
          and "teletext rendered" in rig.pi.status(), repr(rig.out) + "\n" + rig.pi.status())
    rig.send("\x1cm", after_ms=1500)
    check("Ctrl-\\ m: back to screen mode", "(shell mode" not in rig.pi.status(), rig.pi.status())
    rig.type("NEW\r")
    rig.close()

    print("== telnetd_teletext=markers: taken at the session's start")
    rig.pi.cfg("telnetd_teletext", "markers")
    rig.connect()
    rig.send("\x1cm", after_ms=1500)
    check("a new session in markers, the status says so", "teletext markers" in rig.pi.status(), rig.pi.status())
    rig.out = b""
    rig.type('PRINT CHR$132;"B";CHR$141;"D"\r', per_key_ms=30, after_ms=1200)
    answer = rig.out.split(b"\r\n", 1)[-1]
    check("a program's codes as markers", BLUE_MARK + b"\x1b[39mB\x1b[7m2\x1b[27mD" in answer, repr(rig.out))
    rig.send("\x1cm", after_ms=1500)
    rig.close()
    rig.pi.cfg("telnetd_teletext", "rendered")

    print("== shell mode in a 20-column window: a line longer than the window")
    rig.connect(cols=20, rows=24)
    rig.run_ms(3500)                                   # the "window too small" warning, then the screen
    rig.send("\x1cm")
    long = "PRINT " + "1+" * 12 + "1"
    rig.type(long, per_key_ms=30, after_ms=300)
    rig.send("\x1b[H", after_ms=200)                   # Home, then add at the start
    rig.send("\x1b[F", after_ms=200)                   # End
    rig.send("\x7f\x7f", after_ms=200)                 # two Backspaces: ...1+1 -> ...1+
    rig.send("2", after_ms=300)
    show(rig, "the edit line wrapped over rows", 6)
    want = ">" + long[:-2] + "2"
    lay = "".join(r.ljust(20) for r in rig.rows()).rstrip()
    check("the edit line laid out across the rows, no pieces left", want in lay.replace(" " * 20, ""), "\n".join(rig.rows()))
    rig.send("\r", after_ms=1500)
    check("and its answer", "        23" in rig.text(), rig.text())
    rig.send("\x1cm", after_ms=1200)
    rig.close()

    print("== plain line mode: nc (telnetd_teletext=markers, which is for shell mode only)")
    rig.pi.cfg("telnetd_teletext", "markers")
    rig.connect(telnet=False)
    rig.screen = Screen(32, 80)
    rig.out = b""
    rig.send("PRINT 2+2\n", after_ms=1500)
    check("nc: the answer without the echo", b"         4" in rig.out and b"PRINT 2+2" not in rig.out, repr(rig.out))
    rig.out = b""
    rig.send("PRIMT\n", after_ms=1500)
    check("nc: Mistake", b"Mistake" in rig.out and b"\x1b" not in rig.out, repr(rig.out))
    rig.out = b""
    rig.send('MODE 7:PRINT CHR$129;"RED"\n', after_ms=2000)
    check("nc: teletext codes as spaces, no escape codes", b" RED" in rig.out and b"\x1b" not in rig.out, repr(rig.out))
    rig.out = b""
    rig.send("10 GOTO 10\nRUN\n", after_ms=1500)
    rig.send("\x03", after_ms=1500)
    check("nc: Ctrl-C is ESCAPE", b"Escape at line 10" in rig.out, repr(rig.out))
    rig.send("NEW\n", after_ms=800)
    st = rig.pi.status()
    check("the status says line mode", "line mode" in st, st)
    rig.close()
    rig.pi.cfg("telnetd_teletext", "rendered")

    print("== telnetd_linemode=on: no negotiation")
    rig2 = Rig(roms, {"telnetd_port": 23, "telnetd_login": 0, "telnetd_linemode": "on"})
    rig2.boot()
    rig2.connect(telnet=False)
    check("nothing negotiated (no IAC)", b"\xff" not in rig2.out, repr(rig2.out[:80]))
    rig2.send("PRINT 3*3\n", after_ms=1500)
    check("a line answered", b"         9" in rig2.out, repr(rig2.out))
    rig2.close()

    print("== teletype mode: the raw port")
    rig.connect(port=2323, telnet=False)
    rig.out = b""
    rig.send("PRINT 7\r", after_ms=1500)
    check("bytes as they are, the Beeb's echo too", b"PRINT 7" in rig.out and b"7" in rig.out, repr(rig.out))
    rig.close()

    bad = [n for n, ok in results if not ok]
    print("\n%d checks, %d failed" % (len(results), len(bad)))
    for n in bad:
        print("  FAILED:", n)
    return 1 if bad else 0


# ---- a live session ----------------------------------------------------------------------------------------

def listen(roms, port, cfg):
    rig = Rig(roms, cfg)
    rig.boot()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    print("listening on 127.0.0.1:%d (the emulated Beeb is up)" % port)
    while True:
        c, _ = srv.accept()
        c.setblocking(False)
        rig.pi.connect(23, False)                      # the client's own bytes decide: telnet answers, nc does not
        while True:
            r, _, _ = select.select([c], [], [], 0)
            if r:
                d = c.recv(4096)
                if not d:
                    break
                rig.pi.send(d)
            rig.beeb.run(2000)
            got = rig.pi.recv()
            if got:
                c.sendall(got)
            if not rig.pi.open():
                break
        rig.pi.close()
        c.close()
        rig.run_ms(1200)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--roms", default=os.environ.get("TELNETD_EMU_ROMS"))
    ap.add_argument("--listen", type=int)
    ap.add_argument("--cfg", action="append", default=[])
    a = ap.parse_args()
    if not a.roms:
        raise SystemExit("--roms DIR (or TELNETD_EMU_ROMS): a folder with os12.rom and basic2.rom")
    if a.listen:
        cfg = {"telnetd_port": 23, "telnetd_login": 0}
        for kv in a.cfg:
            k, v = kv.split("=", 1)
            cfg[k] = v
        listen(a.roms, a.listen, cfg)
        return 0
    t0 = time.time()
    rc = checks(a.roms)
    print("%.0f s" % (time.time() - t0))
    return rc


if __name__ == "__main__":
    sys.exit(main())
