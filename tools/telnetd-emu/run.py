#!/usr/bin/env python3
"""Fake the Pi: run the telnet daemon's byte logic against a real BBC MOS and BASIC.

This is the light fallback: its own Python 6502.  The primary harness is
beebium_run.py (the Beebium emulator); both run the same transcript checks (scripted).

    python3 run.py --roms DIR            the scripted transcript checks (exit 1 on a failure)
    python3 run.py --roms DIR --listen 2323 [--setting auto|screen|line]
                                         a live session: nc localhost 2323, or telnet

DIR holds the ROM images (searched recursively): os12.rom (MOS 1.20) and basic2.rom
(BASIC 2), e.g. b-em's roms folder.  Or set TELNETD_EMU_ROMS.  No ROM images are kept
in this repository.

The pieces: beeb.py (a 6502 and as much of a Model B as the MOS needs), stub.py (the
Pi's side of the FRED stub, as serial_redirect.c), and fakepi.c built with the
firmware's src/telnetd_proto.c into a shared library (gcc, here) - the daemon's own
translators and mode decision, with telnetd.c's glue around them.  See README.md.
"""
import argparse
import ctypes
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from beeb import Beeb                          # noqa: E402
from stub import Stub                          # noqa: E402

SRC = os.path.normpath(os.path.join(HERE, "..", "..", "src"))
SETTINGS = {"auto": 0, "screen": 1, "line": 2, "shell": 3}
TTX = {"spaces": 0, "rendered": 1, "markers": 2}
MODES = {0: "deciding", 1: "screen", 2: "line", 3: "shell"}
OSWORD = 0xFFF1


def find_rom(root, name):
    for d, _, files in os.walk(root):
        for f in files:
            if f.lower() == name:
                return os.path.join(d, f)
    raise SystemExit(f"{name} not found under {root}")


def build_shim():
    out = os.path.join(tempfile.gettempdir(), "telnetd-emu-fakepi.so")
    srcs = [os.path.join(HERE, "fakepi.c"), os.path.join(SRC, "telnetd_proto.c")]
    subprocess.check_call(["gcc", "-std=gnu2x", "-O2", "-Wall", "-Wextra", "-shared", "-fPIC",
                           "-I" + SRC, "-o", out] + srcs)
    lib = ctypes.CDLL(out)
    u8p = ctypes.POINTER(ctypes.c_uint8)
    lib.fp_start.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint32, ctypes.c_int]
    lib.fp_client.argtypes = [u8p, ctypes.c_int, ctypes.c_uint32]
    lib.fp_beeb.argtypes = [ctypes.c_uint8, ctypes.c_uint32]
    lib.fp_poll.argtypes = [ctypes.c_uint32, u8p, ctypes.c_int]
    lib.fp_out.argtypes = [u8p, ctypes.c_int]
    return lib


class Rig:
    """A booted Beeb with the stub hooked in, and the fake Pi beside it."""

    TICK_US = 500                               # the main loop's pass, in emulated time

    def __init__(self, roms, lib):
        mos = open(find_rom(roms, "os12.rom"), "rb").read()
        basic = open(find_rom(roms, "basic2.rom"), "rb").read()
        self.stub = Stub()
        self.stub.now = 0
        self.beeb = Beeb(mos, {15: basic}, self.stub)
        self.lib = lib
        self.connected = False
        self.beeb.hooks[OSWORD] = self._osword
        self.hooked = False

    def _osword(self, b):
        if b.a == 0 and not self.hooked:        # BASIC wants its first line: hook in, as helper 20
            self.hooked = True
            self.stub.install(b.mem)
            self.stub.rx.extend(b"*FX3,1\r")    # the VDU stream to RS423 as well

    def seconds(self):
        return self.beeb.us / 1e6

    @property
    def now(self):
        return self.beeb.us & 0xFFFFFFFF

    def boot(self):
        for _ in range(4000):                   # 2 s of Beeb time at most
            self.step()
            if self.hooked and not self.stub.rx and self.beeb.us > 200000:
                break
        self.run_ms(300)                        # the prompt after *FX3,1, dropped (nobody connected)
        if not self.hooked:
            raise SystemExit("the MOS never asked for a line")

    def step(self):
        self.beeb.run(self.TICK_US * 2)
        now = self.now
        st = self.stub
        if self.connected:
            while st.tx:
                c = st.tx[0]
                if not self.lib.fp_beeb(c, now):
                    break
                st.tx.popleft()
            room = st.room()
            buf = (ctypes.c_uint8 * 1024)()
            n = self.lib.fp_poll(now, buf, min(room, 1024))
            st.rx.extend(bytes(buf[:n]))
            if self.lib.fp_escape():
                st.escape()
        else:
            st.tx.clear()                       # nobody connected: read and dropped
        st.poll(now)

    def run_ms(self, ms):
        for _ in range(int(ms * 1000 / self.TICK_US)):
            self.step()

    # ---- the client's side ----
    def connect(self, setting="auto", ttx="rendered"):
        self.lib.fp_start(SETTINGS[setting], 7, self.now, TTX[ttx])
        self.connected = True
        self.out = bytearray()

    def send(self, data):
        if isinstance(data, str):
            data = data.encode("latin-1")
        buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        self.lib.fp_client(buf, len(data), self.now)

    def collect(self):
        buf = (ctypes.c_uint8 * 4096)()
        while True:
            n = self.lib.fp_out(buf, 4096)
            if n == 0:
                break
            self.out += bytes(buf[:n])

    def mode(self):
        return MODES[self.lib.fp_mode()]

    def wait_quiet(self, quiet_ms=400, limit_ms=20000):
        """Run until nothing has reached the client for quiet_ms and no keys wait."""
        quiet = 0
        t = 0
        while t < limit_ms and quiet < quiet_ms:
            before = len(self.out)
            self.step()
            self.collect()
            pending = self.lib.fp_keys() or self.stub.rx or self.stub.tx
            quiet = 0 if (len(self.out) != before or pending) else quiet + self.TICK_US / 1000
            t += self.TICK_US / 1000
        return t

    def transact(self, line, quiet_ms=400):
        """Type a line as nc does (LF at the end); what came back."""
        start = len(self.out)
        self.send(line + "\n")
        self.wait_quiet(quiet_ms)
        return bytes(self.out[start:])


# ---- the transcript checks ------------------------------------------------------

def show(b):
    return b.decode("latin-1").encode("unicode_escape").decode()


class Checks:
    def __init__(self):
        self.n = 0
        self.failed = 0
        self.log = []

    def check(self, ok, what, got=b""):
        self.n += 1
        if not ok:
            self.failed += 1
        line = f"  {'ok  ' if ok else 'FAIL'} {what}" + ("" if ok else f"\n       got: {show(got)}")
        print(line)


def strip_ga(b):
    return b.replace(b"\xff\xf9", b"")


def transcript(r, lines, title):
    print(f"--- {title}")
    out = b""
    for l in lines:
        got = r.transact(l)
        print("  >" + l)
        for t in strip_ga(got).decode("latin-1").split("\r\n"):
            print("  | " + t)
        out += got
    return out


def scripted(r):
    """The transcript checks, on a booted rig (this file's, or beebium_run.py's)."""
    ck = Checks()
    print(f"booted: hooked at {r.seconds():.2f} s of Beeb time")

    # 1. A raw client (nc): line mode as soon as it types.
    r.connect("auto")
    r.collect()
    greet = bytes(r.out)
    ck.check(greet == b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x03", "the greeting is the negotiation only", greet)
    ck.check(r.mode() == "deciding", "nothing said yet: deciding")
    got = r.transact("PRINT 2+2")
    ck.check(r.mode() == "line", "nc's first line: line mode")
    ck.check(got == b"         4\r\n>", "PRINT 2+2: the answer and the prompt, no echo", got)

    got = r.transact("*HELP")
    ck.check(b"OS 1.20" in got and got.endswith(b">") and b"*HELP" not in got, "*HELP: the MOS's answer", got)

    got = r.transact("PRIMT")
    ck.check(got == b"\r\nMistake\r\n>" or got == b"Mistake\r\n>", "an error: Mistake", got)

    out = transcript(r, ["NEW", "10 FOR I=1 TO 3", "20 PRINT I", "30 NEXT", "LIST"], "a program")
    ck.check(b"   10 FOR I=1 TO 3\r\n   20 PRINT I\r\n   30 NEXT\r\n>" in out, "LIST shows the program", out)
    got = r.transact("RUN")
    ck.check(got == b"         1\r\n         2\r\n         3\r\n>", "RUN", got)

    # ESCAPE: Ctrl-C while a program loops.
    transcript(r, ["NEW", "10 GOTO 10"], "a loop")
    start = len(r.out)
    r.send("RUN\n")
    r.run_ms(300)
    r.send("\x03")
    r.wait_quiet()
    got = bytes(r.out[start:])
    ck.check(b"Escape at line 10" in got and got.endswith(b">"), "Ctrl-C stops the loop: Escape at line 10", got)

    # The VDU stream: positioning, colours, MODE 7 codes and a VDU 23 stripped.
    out = transcript(r, ["NEW",
                         '10 PRINT TAB(5,3);"AT";CHR$17;CHR$1;"X";',
                         '20 VDU 31,1,1,23,1,0;0;0;0;',
                         '30 PRINT CHR$129;"RED";CHR$135;"WHITE"',
                         '40 VDU 7:PRINT "POUND `"'], "VDU codes")
    got = r.transact("RUN")
    ck.check(got == b"ATX RED WHITE\r\n\x07POUND \xc2\xa3\r\n>", "VDU codes stripped, teletext codes spaces, bell and pound kept", got)

    # INPUT: the answer line's echo goes, the program's output stays.
    transcript(r, ["NEW", '10 INPUT "NAME"N$', '20 PRINT "HI ";N$'], "INPUT")
    got = r.transact("RUN")
    ck.check(got == b"NAME", "INPUT's prompt (no ? without a comma)", got)
    got = r.transact("BOB")
    ck.check(got == b"HI BOB\r\n>", "the typed answer is not echoed back", got)

    # GET: no echo; the expected echo is given up and the program's text is not eaten.
    # (A program that prints the key it read and then a new line looks exactly like the
    # echo of that key and RETURN, and loses them: a known limit, see the README.)
    transcript(r, ["NEW", '10 A=GET:PRINT "GOT ";A'], "GET")
    got = r.transact("RUN")
    ck.check(got == b"", "GET waits, nothing printed", got)
    got = r.transact("Y")
    ck.check(got == b"GOT 89\r\n>\r\n>", "GET takes the Y; the line's RETURN then reaches BASIC as an empty line", got)

    # MODE: a clear screen starts a line; the MODE bytes do not show.
    got = r.transact("MODE 4:PRINT \"FOUR\"")
    ck.check(got == b"FOUR\r\n>", "MODE 4 then text", got)
    got = r.transact("MODE 7")
    ck.check(got == b">", "MODE 7 back", got)

    # Lines typed ahead, sent as one burst (a paste through nc).
    start = len(r.out)
    r.send("NEW\n10 PRINT \"A\"\n20 PRINT \"B\"\nRUN\n")
    r.wait_quiet()
    got = bytes(r.out[start:])
    ck.check(got == b">>>A\r\nB\r\n>", "four lines in one burst: three prompts, no echoes, the output", got)

    # 2. A telnet client that refuses the echo: line mode and IAC GA.
    r.connect("auto")
    r.send(b"\xff\xfe\x01\xff\xfe\x03")
    r.wait_quiet()
    ck.check(r.mode() == "line", "DONT ECHO, DONT SGA: line mode")
    start = len(r.out)
    got = r.transact("PRINT 6*7")
    ck.check(got == b"        42\r\n>\xff\xf9", "the answer, the prompt, then IAC GA", got)

    # 3. A terminal: DO ECHO -> screen mode, the Beeb's own echo comes back.
    r.connect("auto")
    r.send(b"\xff\xfd\x01\xff\xfd\x03\xff\xfb\x03")
    r.wait_quiet()
    ck.check(r.mode() == "screen", "DO ECHO: screen mode")
    got = r.transact("PRINT 2+2")
    ck.check(b"PRINT 2+2" in got and b"4" in got, "screen mode: the echo is the Beeb's", got)

    # 4. Late negotiation: a client that says nothing for a second, then DO ECHO.
    r.connect("auto")
    r.run_ms(1000)
    ck.check(r.mode() == "line", "no answer in 750 ms: line mode")
    r.send(b"\xff\xfd\x01")
    r.wait_quiet()
    ck.check(r.mode() == "screen", "a late DO ECHO: screen mode after all")

    # 5. The setting: line mode with no negotiation at all.
    r.connect("line")
    r.collect()
    ck.check(bytes(r.out) == b"" and r.mode() == "line", "telnetd_linemode=on: nothing negotiated", bytes(r.out))
    got = r.transact("PRINT 1")
    ck.check(got == b"         1\r\n>", "and line mode works", got)

    shell_checks(r, ck)

    print(f"{ck.n} checks, {ck.failed} failed; {r.seconds():.1f} s of Beeb time")
    return ck.failed == 0


# ---- shell mode: a terminal, and what it would show ---------------------------------

class Term:
    """Just enough of a terminal to see what a user would: printable text, CR, LF, BS,
    CSI n C / n D / K, SGR (ignored), BEL (counted).  UTF-8 decoded."""

    def __init__(self):
        self.rows = [[]]
        self.r = 0
        self.c = 0
        self.bells = 0

    def _put(self, ch):
        row = self.rows[self.r]
        while len(row) < self.c:
            row.append(" ")
        if self.c < len(row):
            row[self.c] = ch
        else:
            row.append(ch)
        self.c += 1

    def feed(self, data):
        text = bytes(data).replace(b"\xff\xf9", b"").decode("utf-8", "replace")
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "\x1b" and i + 1 < len(text) and text[i + 1] == "[":
                j = i + 2
                while j < len(text) and not ("@" <= text[j] <= "~"):
                    j += 1
                params, final = text[i + 2:j], text[j] if j < len(text) else ""
                n = int(params) if params.isdigit() else 1
                if final == "D":
                    self.c = max(0, self.c - n)
                elif final == "C":
                    self.c += n
                elif final == "K":
                    del self.rows[self.r][self.c:]
                i = j + 1
                continue
            if ch == "\x1b":                         # ESC x (not CSI): skip both
                i += 2
                continue
            if ch == "\r":
                self.c = 0
            elif ch == "\n":
                self.r += 1
                if self.r == len(self.rows):
                    self.rows.append([])
            elif ch == "\b":
                self.c = max(0, self.c - 1)
            elif ch == "\a":
                self.bells += 1
            elif ch >= " ":
                self._put(ch)
            i += 1

    def lines(self):
        return ["".join(r).rstrip() for r in self.rows]


def term_keys(r, keys, gap_ms=40):
    """Type keys one at a time, as a person at a terminal does."""
    for k in keys:
        r.send(k)
        r.run_ms(gap_ms)


def shell_session(r, ck, title):
    """Connect as a terminal that accepts the echo, in shell mode."""
    r.connect("shell")
    r.send(b"\xff\xfd\x01\xff\xfd\x03\xff\xfb\x03")
    r.wait_quiet()
    print(f"--- {title}")
    return len(r.out)


def show_term(r, start):
    t = Term()
    t.feed(r.out[start:])
    for line in t.lines():
        print("  | " + line)
    return t


UP, LEFT, BS = "\x1b[A", "\x1b[D", "\x7f"
HOT = "\x1c"


def shell_checks(r, ck):
    start = shell_session(r, ck, "shell mode: a line, history, an edit")
    ck.check(r.mode() == "shell", "telnetd_linemode=shell, a terminal: shell mode")
    term_keys(r, ["\r"])                        # the Beeb's prompt
    r.wait_quiet()
    term_keys(r, list("PRINT 2+2") + ["\r"])
    r.wait_quiet()
    term_keys(r, [UP, LEFT, BS, "*", "\r"])      # recall, edit 2+2 to 2*2, run
    r.wait_quiet()
    t = show_term(r, start)
    lines = t.lines()
    ck.check(">PRINT 2+2" in lines and "         4" in lines, "typed on the Pi's editor, shown once, the answer below", "\n".join(lines).encode())
    ck.check(">PRINT 2*2" in lines and lines.count("         4") == 2, "Up, Left, Backspace, *, RETURN: the edited line runs", "\n".join(lines).encode())
    ck.check(lines[-1] == ">" and sum(1 for l in lines if "PRINT 2+2" in l) == 1, "no echo twice, a prompt at the end", "\n".join(lines).encode())

    # A MODE 7 program with codes typed through Ctrl-V, then LIST as markers and rendered.
    start = len(r.out)
    print("--- shell mode: teletext codes")
    term_keys(r, list("NEW\r"))
    r.wait_quiet()
    term_keys(r, list('10 PRINT "') + ["\x16", "8", "1"] + list("RED") + ["\x16", "8", "2"] + list('GREEN"') + ["\r"])
    r.wait_quiet()
    term_keys(r, [HOT, "t"] + list("LIST\r"))   # markers
    r.wait_quiet()
    marked = bytes(r.out[start:])
    show_term(r, start)
    ck.check(b"\x1b[31m\xe2\x96\x88\x1b[39mRED\x1b[32m\xe2\x96\x88\x1b[39mGREEN" in marked,
             "LIST with markers: a red and a green block where the codes are", marked)
    t = Term(); t.feed(marked)
    ck.check(any(l == '   10 PRINT "█RED█GREEN"' for l in t.lines()), "markers keep the columns", "\n".join(t.lines()).encode())
    start = len(r.out)
    term_keys(r, [HOT, "t"] + list("LIST\r"))   # rendered again
    r.wait_quiet()
    term_keys(r, list("RUN\r"))
    r.wait_quiet()
    rend = bytes(r.out[start:])
    show_term(r, start)
    ck.check(b"\x1b[0;31mRED" in rend and b"\x1b[0;32mGREEN" in rend, "rendered: the codes colour the text, in LIST and RUN", rend)
    t = Term(); t.feed(rend)
    ck.check(any(l == '   10 PRINT " RED GREEN"' for l in t.lines()) and any(l == " RED GREEN" for l in t.lines()),
             "rendered: code cells are spaces", "\n".join(t.lines()).encode())

    # GET: single keys reach the program.
    start = len(r.out)
    print("--- shell mode: GET")
    term_keys(r, list('NEW\r'))
    r.wait_quiet()
    term_keys(r, list('10 A=GET:PRINT "GOT ";A:IF A<>81 GOTO 10\r'))
    r.wait_quiet()
    term_keys(r, list("RUN\r"))
    r.wait_quiet()
    term_keys(r, ["Y"], gap_ms=400)
    term_keys(r, ["N"], gap_ms=400)
    term_keys(r, ["Q"], gap_ms=400)
    r.wait_quiet()
    t = show_term(r, start)
    text = "\n".join(t.lines())
    ck.check("GOT 89" in text and "GOT 78" in text and "GOT 81" in text and t.lines()[-1] == ">",
             "GET in shell mode: each key reaches the program", text.encode())

    # Ctrl-C in a loop.
    start = len(r.out)
    term_keys(r, list("NEW\r"))
    r.wait_quiet()
    term_keys(r, list("10 GOTO 10\r") + list("RUN\r"))
    r.run_ms(300)
    term_keys(r, ["\x03"])
    r.wait_quiet()
    t = show_term(r, start)
    ck.check(any("Escape at line 10" in l for l in t.lines()), "Ctrl-C in shell mode: Escape at line 10", "\n".join(t.lines()).encode())

    # The hot key: to screen mode and back.
    start = len(r.out)
    print("--- the hot key")
    term_keys(r, [HOT, "m"])
    r.wait_quiet()
    ck.check(r.mode() == "screen", "Ctrl-\\ m: screen mode")
    term_keys(r, list("PRINT 7\r"))
    r.wait_quiet()
    scr = bytes(r.out[start:])
    ck.check(b"PRINT 7" in scr and b"7" in scr, "screen mode: the Beeb's own echo", scr)
    term_keys(r, [HOT, "m"])
    r.wait_quiet()
    ck.check(r.mode() == "shell", "Ctrl-\\ m again: shell mode")
    start2 = len(r.out)
    term_keys(r, ["\r"] + list("PRINT 8") + ["\r"])
    r.wait_quiet()
    t = show_term(r, start2)
    ck.check(sum(1 for l in t.lines() if "PRINT 8" in l) == 1 and "         8" in t.lines(), "shell again: one echo, the answer", "\n".join(t.lines()).encode())


def listen(roms, lib, port, setting):
    import select
    import socket
    r = Rig(roms, lib)
    r.boot()
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
                for _ in range(4):
                    r.step()
                r.collect()
                if r.out:
                    conn.sendall(bytes(r.out))
                    r.out.clear()
        except OSError:
            pass
        conn.close()
        r.connected = False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--roms", default=os.environ.get("TELNETD_EMU_ROMS"))
    ap.add_argument("--listen", type=int)
    ap.add_argument("--setting", default="auto", choices=SETTINGS)
    a = ap.parse_args()
    if not a.roms:
        raise SystemExit("give --roms DIR or set TELNETD_EMU_ROMS")
    lib = build_shim()
    if a.listen:
        listen(a.roms, lib, a.listen, a.setting)
    r = Rig(a.roms, lib)
    r.boot()
    sys.exit(0 if scripted(r) else 1)


if __name__ == "__main__":
    main()
