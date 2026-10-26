"""A BBC Micro Model B, just enough of one to run the real MOS 1.20, BASIC 2 and the TelnetD ROM.

An NMOS 6502 (documented opcodes, decimal mode, IRQ and BRK as the chip does them), 32K
of RAM, sideways ROM banks paged through &FE30, the system VIA (its timers raise the
MOS's 100 Hz interrupt; port A answers "no key pressed"; a vsync on CA1 every 20 ms),
and FRED (&FC00-&FCFF), which is the Pi's: fakepi.c with the firmware's own stub
(src/serial_redirect.c) and daemon (src/telnetd.c).  A read of FRED is the Pi's byte, a
write goes to the Pi (stored, and the stub's callback for it), the Pi's nIRQ joins the
VIA's, and the Pi's main loop runs every emulated millisecond.  The rest of SHEILA -
CRTC, video ULA, the 6850, the user VIA, ADC - reads as idle and ignores writes: the
MOS writes the screen into RAM as usual, and nothing here draws it.

Time is the 6502's: two cycles per microsecond.  Nothing runs in real time.
"""

C, Z, I, D, B, U, V, N = 1, 2, 4, 8, 16, 32, 64, 128

# Base cycles per opcode (page-crossing penalties ignored: the timers do not need them).
CYCLES = [
    7, 6, 2, 2, 3, 3, 5, 2, 3, 2, 2, 2, 4, 4, 6, 2, 2, 5, 2, 2, 4, 4, 6, 2, 2, 4, 2, 2, 4, 4, 7, 2,
    6, 6, 2, 2, 3, 3, 5, 2, 4, 2, 2, 2, 4, 4, 6, 2, 2, 5, 2, 2, 4, 4, 6, 2, 2, 4, 2, 2, 4, 4, 7, 2,
    6, 6, 2, 2, 3, 3, 5, 2, 3, 2, 2, 2, 3, 4, 6, 2, 2, 5, 2, 2, 4, 4, 6, 2, 2, 4, 2, 2, 4, 4, 7, 2,
    6, 6, 2, 2, 3, 3, 5, 2, 4, 2, 2, 2, 5, 4, 6, 2, 2, 5, 2, 2, 4, 4, 6, 2, 2, 4, 2, 2, 4, 4, 7, 2,
    2, 6, 2, 2, 3, 3, 3, 2, 2, 2, 2, 2, 4, 4, 4, 2, 2, 6, 2, 2, 4, 4, 4, 2, 2, 5, 2, 2, 5, 5, 5, 2,
    2, 6, 2, 2, 3, 3, 3, 2, 2, 2, 2, 2, 4, 4, 4, 2, 2, 5, 2, 2, 4, 4, 4, 2, 2, 4, 2, 2, 4, 4, 4, 2,
    2, 6, 2, 2, 3, 3, 5, 2, 2, 2, 2, 2, 4, 4, 6, 2, 2, 5, 2, 2, 4, 4, 6, 2, 2, 4, 2, 2, 4, 4, 7, 2,
    2, 6, 2, 2, 3, 3, 5, 2, 2, 2, 2, 2, 4, 4, 6, 2, 2, 5, 2, 2, 4, 4, 6, 2, 2, 4, 2, 2, 4, 4, 7, 2,
]


class Unimplemented(Exception):
    pass


class Via:
    """The system VIA: what the MOS needs of it."""

    def __init__(self):
        self.r = bytearray(16)
        self.t1 = 0xFFFF
        self.t1l = 0xFFFF
        self.t1run = False
        self.t2 = 0xFFFF
        self.t2run = False
        self.ifr = 0
        self.ier = 0
        self.ora = 0
        self.orb = 0
        self.ddra = 0
        self.ddrb = 0
        self.acr = 0
        self.t2lo = 0
        self.vsync = 20000.0

    def irq(self):
        return (self.ifr & self.ier & 0x7F) != 0

    def tick(self, us):
        self.t1 -= us
        if self.t1 < 0:
            while self.t1 < 0:
                if self.acr & 0x40:                  # free running: reload
                    self.t1 += self.t1l + 2
                    self.ifr |= 0x40
                else:
                    if self.t1run:
                        self.ifr |= 0x40
                        self.t1run = False
                    self.t1 += 0x10000
        self.t2 -= us
        if self.t2 < 0:
            if self.t2run:
                self.ifr |= 0x20
                self.t2run = False
            self.t2 += 0x10000
        self.vsync -= us
        if self.vsync <= 0:
            self.vsync += 20000.0
            self.ifr |= 0x02                         # CA1: vertical sync

    def read(self, reg):
        if reg == 0:
            return (self.orb & self.ddrb) | (0xFF & ~self.ddrb)    # PB: no speech, no buttons
        if reg in (1, 15):
            return self.ora & 0x7F                   # the key the MOS asked about is not pressed
        if reg == 2:
            return self.ddrb
        if reg == 3:
            return self.ddra
        if reg == 4:
            self.ifr &= ~0x40
            return int(self.t1) & 0xFF
        if reg == 5:
            return (int(self.t1) >> 8) & 0xFF
        if reg == 6:
            return self.t1l & 0xFF
        if reg == 7:
            return self.t1l >> 8
        if reg == 8:
            self.ifr &= ~0x20
            return int(self.t2) & 0xFF
        if reg == 9:
            return (int(self.t2) >> 8) & 0xFF
        if reg == 11:
            return self.acr
        if reg == 13:
            v = self.ifr & 0x7F
            return v | (0x80 if self.irq() else 0)
        if reg == 14:
            return self.ier | 0x80
        return self.r[reg]

    def write(self, reg, v):
        self.r[reg] = v
        if reg == 0:
            self.orb = v
        elif reg in (1, 15):
            self.ora = v
            self.ifr &= ~0x03
        elif reg == 2:
            self.ddrb = v
        elif reg == 3:
            self.ddra = v
        elif reg in (4, 6):
            self.t1l = (self.t1l & 0xFF00) | v
        elif reg == 5:
            self.t1l = (self.t1l & 0xFF) | (v << 8)
            self.t1 = self.t1l + 1
            self.ifr &= ~0x40
            self.t1run = True
        elif reg == 7:
            self.t1l = (self.t1l & 0xFF) | (v << 8)
            self.ifr &= ~0x40
        elif reg == 8:
            self.t2lo = v
        elif reg == 9:
            self.t2 = (v << 8) | self.t2lo
            self.t2 += 1
            self.ifr &= ~0x20
            self.t2run = True
        elif reg == 11:
            self.acr = v
        elif reg == 13:
            self.ifr &= ~(v & 0x7F)
        elif reg == 14:
            if v & 0x80:
                self.ier |= v & 0x7F
            else:
                self.ier &= ~v & 0x7F


class Beeb:
    POLL_CYCLES = 2000                               # the Pi's main loop: every millisecond

    def __init__(self, mos, roms, pi):
        """mos: 16K MOS image; roms: {bank: 16K image}; pi: the fakepi library (run.py's Pi)."""
        self.mem = bytearray(0x10000)
        self.mem[0xC000:0x10000] = mos
        self.banks = {b: bytes(r) for b, r in roms.items()}
        self.empty = bytes([0xFF]) * 0x4000
        self.bank = -1
        self.page(15)
        self.via = Via()
        self.pi = pi
        self.a = self.x = self.y = 0
        self.s = 0xFD
        self.p = I | U
        self.pc = self.mem[0xFFFC] | self.mem[0xFFFD] << 8
        self.cycles = 0
        self.next_poll = 0
        self.nirq = False
        self.hooks = {}                              # pc -> fn(beeb), called before the instruction
        self.sync()

    def sync(self):
        """FRED as the Pi has it (code runs from it: the stub), and its nIRQ."""
        self.mem[0xFC00:0xFD00] = self.pi.fred()
        self.nirq = self.pi.nirq()

    def pi_poll(self):
        self.pi.poll(self.us)
        self.sync()

    # ---- memory ----
    def page(self, b):
        b &= 15
        if b != self.bank:
            self.bank = b
            self.mem[0x8000:0xC000] = self.banks.get(b, self.empty)

    def rd(self, a):
        if 0xFC00 <= a < 0xFF00:
            return self.io_rd(a)
        return self.mem[a]

    def wr(self, a, v):
        if a < 0x8000:
            self.mem[a] = v
        elif 0xFC00 <= a < 0xFF00:
            self.io_wr(a, v)

    def io_rd(self, a):
        if a < 0xFD00:
            return self.mem[a]                       # the Pi's FRED, as last synced
        if a < 0xFE00:
            return 0xFF                              # JIM: nothing
        if 0xFE40 <= a < 0xFE60:
            return self.via.read(a & 15)
        if 0xFE60 <= a < 0xFE80:
            return 0                                 # user VIA: no interrupts
        if 0xFE08 <= a < 0xFE10:
            return 0x02                              # 6850: nothing received, transmit register empty
        if 0xFEE0 <= a < 0xFF00:
            return 0                                 # no Tube
        return 0xFE

    def io_wr(self, a, v):
        if a < 0xFD00:
            self.pi.write(a & 0xFF, v)               # the Pi's: stored, and the stub's callback
            self.sync()
        elif 0xFE30 <= a < 0xFE40:
            self.page(v)
        elif 0xFE40 <= a < 0xFE60:
            self.via.write(a & 15, v)

    # ---- the CPU ----
    def push(self, v):
        self.mem[0x100 + self.s] = v & 0xFF
        self.s = (self.s - 1) & 0xFF

    def pull(self):
        self.s = (self.s + 1) & 0xFF
        return self.mem[0x100 + self.s]

    def irq_line(self):
        return self.via.irq() or self.nirq

    def interrupt(self, vector, brk):
        self.push(self.pc >> 8)
        self.push(self.pc & 0xFF)
        self.push((self.p | U | (B if brk else 0)) & ~(0 if brk else B))
        self.p |= I
        self.pc = self.mem[vector] | self.mem[vector + 1] << 8

    def run(self, cycles):
        """Run for about this many cycles, the Pi's main loop every millisecond."""
        end = self.cycles + cycles
        mem = self.mem
        rd = self.rd
        wr = self.wr
        via = self.via
        hooks = self.hooks
        while self.cycles < end:
            if self.cycles >= self.next_poll:
                self.next_poll = self.cycles + self.POLL_CYCLES
                self.pi_poll()
            if not (self.p & I) and self.irq_line():
                self.interrupt(0xFFFE, False)
                self.cycles += 7
            pc = self.pc
            if pc in hooks:
                hooks[pc](self)
                pc = self.pc
            op = mem[pc]
            self.pc = (pc + 1) & 0xFFFF
            OPS[op](self, mem, rd, wr)
            c = CYCLES[op]
            self.cycles += c
            via.tick(c / 2.0)

    @property
    def us(self):
        return self.cycles // 2


# ---- the instruction set -------------------------------------------------------

def _nz(cpu, v):
    cpu.p = (cpu.p & ~(N | Z)) | (v & N) | (0 if v else Z)
    return v


def _fetch(cpu, mem):
    v = mem[cpu.pc]
    cpu.pc = (cpu.pc + 1) & 0xFFFF
    return v


def _fetch16(cpu, mem):
    pc = cpu.pc
    cpu.pc = (pc + 2) & 0xFFFF
    return mem[pc] | mem[(pc + 1) & 0xFFFF] << 8


# Addressing modes return an address.
def am_zp(cpu, mem):  return _fetch(cpu, mem)
def am_zpx(cpu, mem): return (_fetch(cpu, mem) + cpu.x) & 0xFF
def am_zpy(cpu, mem): return (_fetch(cpu, mem) + cpu.y) & 0xFF
def am_abs(cpu, mem): return _fetch16(cpu, mem)
def am_abx(cpu, mem): return (_fetch16(cpu, mem) + cpu.x) & 0xFFFF
def am_aby(cpu, mem): return (_fetch16(cpu, mem) + cpu.y) & 0xFFFF


def am_izx(cpu, mem):
    z = (_fetch(cpu, mem) + cpu.x) & 0xFF
    return mem[z] | mem[(z + 1) & 0xFF] << 8


def am_izy(cpu, mem):
    z = _fetch(cpu, mem)
    return ((mem[z] | mem[(z + 1) & 0xFF] << 8) + cpu.y) & 0xFFFF


MODES = {'zp': am_zp, 'zpx': am_zpx, 'zpy': am_zpy, 'abs': am_abs, 'abx': am_abx,
         'aby': am_aby, 'izx': am_izx, 'izy': am_izy}


def _adc(cpu, v):
    a = cpu.a
    c = cpu.p & C
    if cpu.p & D:
        lo = (a & 0x0F) + (v & 0x0F) + c
        hi = (a >> 4) + (v >> 4)
        if lo > 9:
            lo += 6
            hi += 1
        z = ((a + v + c) & 0xFF) == 0
        n = (hi << 4) & 0x80
        ov = (~(a ^ v) & (a ^ (hi << 4)) & 0x80) != 0
        if hi > 9:
            hi += 6
        r = ((hi << 4) | (lo & 0x0F)) & 0xFF
        cpu.p = (cpu.p & ~(C | Z | N | V)) | (C if hi > 15 else 0) | (Z if z else 0) | n | (V if ov else 0)
        cpu.a = r
        return
    r = a + v + c
    ov = (~(a ^ v) & (a ^ r) & 0x80) != 0
    cpu.p = (cpu.p & ~(C | V)) | (C if r > 0xFF else 0) | (V if ov else 0)
    cpu.a = _nz(cpu, r & 0xFF)


def _sbc(cpu, v):
    a = cpu.a
    c = cpu.p & C
    r = a - v - (1 - c)
    ov = ((a ^ v) & (a ^ r) & 0x80) != 0
    if cpu.p & D:
        lo = (a & 0x0F) - (v & 0x0F) - (1 - c)
        hi = (a >> 4) - (v >> 4)
        if lo < 0:
            lo -= 6
            hi -= 1
        if hi < 0:
            hi -= 6
        cpu.p = (cpu.p & ~(C | V)) | (C if r >= 0 else 0) | (V if ov else 0)
        _nz(cpu, r & 0xFF)
        cpu.a = ((hi << 4) | (lo & 0x0F)) & 0xFF
        return
    cpu.p = (cpu.p & ~(C | V)) | (C if r >= 0 else 0) | (V if ov else 0)
    cpu.a = _nz(cpu, r & 0xFF)


def _cmp(cpu, reg, v):
    r = reg - v
    cpu.p = (cpu.p & ~C) | (C if r >= 0 else 0)
    _nz(cpu, r & 0xFF)


OPS = [None] * 256


def _bad(cpu, mem, rd, wr):
    raise Unimplemented(f"opcode {mem[(cpu.pc - 1) & 0xFFFF]:02X} at {(cpu.pc - 1) & 0xFFFF:04X}")


for _i in range(256):
    OPS[_i] = _bad


def _def(code, fn):
    OPS[code] = fn


def _alu(base, kind):
    imm = {'ora': 0x09, 'and': 0x29, 'eor': 0x49, 'adc': 0x69, 'lda': 0xA9, 'cmp': 0xC9, 'sbc': 0xE9}[kind]
    table = {'izx': base + 0x01, 'zp': base + 0x05, 'abs': base + 0x0D, 'izy': base + 0x11,
             'zpx': base + 0x15, 'aby': base + 0x19, 'abx': base + 0x1D}

    def apply(cpu, v):
        if kind == 'ora':
            cpu.a = _nz(cpu, cpu.a | v)
        elif kind == 'and':
            cpu.a = _nz(cpu, cpu.a & v)
        elif kind == 'eor':
            cpu.a = _nz(cpu, cpu.a ^ v)
        elif kind == 'adc':
            _adc(cpu, v)
        elif kind == 'lda':
            cpu.a = _nz(cpu, v)
        elif kind == 'cmp':
            _cmp(cpu, cpu.a, v)
        else:
            _sbc(cpu, v)

    _def(imm, lambda cpu, mem, rd, wr: apply(cpu, _fetch(cpu, mem)))
    for mode, code in table.items():
        am = MODES[mode]
        _def(code, (lambda am: lambda cpu, mem, rd, wr: apply(cpu, rd(am(cpu, mem))))(am))


for _base, _kind in ((0x00, 'ora'), (0x20, 'and'), (0x40, 'eor'), (0x60, 'adc'),
                     (0xA0, 'lda'), (0xC0, 'cmp'), (0xE0, 'sbc')):
    _alu(_base, _kind)


def _sta(am):
    return lambda cpu, mem, rd, wr: wr(am(cpu, mem), cpu.a)


for _code, _mode in ((0x81, 'izx'), (0x85, 'zp'), (0x8D, 'abs'), (0x91, 'izy'), (0x95, 'zpx'),
                     (0x99, 'aby'), (0x9D, 'abx')):
    _def(_code, _sta(MODES[_mode]))
for _code, _mode in ((0x86, 'zp'), (0x8E, 'abs'), (0x96, 'zpy')):
    _def(_code, (lambda am: lambda cpu, mem, rd, wr: wr(am(cpu, mem), cpu.x))(MODES[_mode]))
for _code, _mode in ((0x84, 'zp'), (0x8C, 'abs'), (0x94, 'zpx')):
    _def(_code, (lambda am: lambda cpu, mem, rd, wr: wr(am(cpu, mem), cpu.y))(MODES[_mode]))


def _ldx(cpu, v): cpu.x = _nz(cpu, v)
def _ldy(cpu, v): cpu.y = _nz(cpu, v)


_def(0xA2, lambda cpu, mem, rd, wr: _ldx(cpu, _fetch(cpu, mem)))
_def(0xA0, lambda cpu, mem, rd, wr: _ldy(cpu, _fetch(cpu, mem)))
for _code, _mode in ((0xA6, 'zp'), (0xAE, 'abs'), (0xB6, 'zpy'), (0xBE, 'aby')):
    _def(_code, (lambda am: lambda cpu, mem, rd, wr: _ldx(cpu, rd(am(cpu, mem))))(MODES[_mode]))
for _code, _mode in ((0xA4, 'zp'), (0xAC, 'abs'), (0xB4, 'zpx'), (0xBC, 'abx')):
    _def(_code, (lambda am: lambda cpu, mem, rd, wr: _ldy(cpu, rd(am(cpu, mem))))(MODES[_mode]))

_def(0xE0, lambda cpu, mem, rd, wr: _cmp(cpu, cpu.x, _fetch(cpu, mem)))
_def(0xE4, lambda cpu, mem, rd, wr: _cmp(cpu, cpu.x, rd(am_zp(cpu, mem))))
_def(0xEC, lambda cpu, mem, rd, wr: _cmp(cpu, cpu.x, rd(am_abs(cpu, mem))))
_def(0xC0, lambda cpu, mem, rd, wr: _cmp(cpu, cpu.y, _fetch(cpu, mem)))
_def(0xC4, lambda cpu, mem, rd, wr: _cmp(cpu, cpu.y, rd(am_zp(cpu, mem))))
_def(0xCC, lambda cpu, mem, rd, wr: _cmp(cpu, cpu.y, rd(am_abs(cpu, mem))))


def _bit(cpu, v):
    cpu.p = (cpu.p & ~(N | V | Z)) | (v & (N | V)) | (0 if (cpu.a & v) else Z)


_def(0x24, lambda cpu, mem, rd, wr: _bit(cpu, rd(am_zp(cpu, mem))))
_def(0x2C, lambda cpu, mem, rd, wr: _bit(cpu, rd(am_abs(cpu, mem))))


def _rmw(base, fn):
    # accumulator, zp, abs, zpx, abx
    def acc(cpu, mem, rd, wr):
        cpu.a = fn(cpu, cpu.a)
    _def(base + 0x0A, acc)
    for off, mode in ((0x06, 'zp'), (0x0E, 'abs'), (0x16, 'zpx'), (0x1E, 'abx')):
        am = MODES[mode]

        def f(cpu, mem, rd, wr, am=am):
            a = am(cpu, mem)
            wr(a, fn(cpu, rd(a)))
        _def(base + off, f)


def _asl(cpu, v):
    cpu.p = (cpu.p & ~C) | (v >> 7)
    return _nz(cpu, (v << 1) & 0xFF)


def _lsr(cpu, v):
    cpu.p = (cpu.p & ~C) | (v & 1)
    return _nz(cpu, v >> 1)


def _rol(cpu, v):
    r = ((v << 1) | (cpu.p & C)) & 0xFF
    cpu.p = (cpu.p & ~C) | (v >> 7)
    return _nz(cpu, r)


def _ror(cpu, v):
    r = (v >> 1) | ((cpu.p & C) << 7)
    cpu.p = (cpu.p & ~C) | (v & 1)
    return _nz(cpu, r)


_rmw(0x00, _asl)
_rmw(0x20, _rol)
_rmw(0x40, _lsr)
_rmw(0x60, _ror)


def _incdec(code, mode, d):
    am = MODES[mode]

    def f(cpu, mem, rd, wr):
        a = am(cpu, mem)
        wr(a, _nz(cpu, (rd(a) + d) & 0xFF))
    _def(code, f)


for _code, _mode in ((0xE6, 'zp'), (0xEE, 'abs'), (0xF6, 'zpx'), (0xFE, 'abx')):
    _incdec(_code, _mode, 1)
for _code, _mode in ((0xC6, 'zp'), (0xCE, 'abs'), (0xD6, 'zpx'), (0xDE, 'abx')):
    _incdec(_code, _mode, -1)


def _set(attr, val):
    def f(cpu, mem, rd, wr):
        setattr(cpu, attr, _nz(cpu, val(cpu) & 0xFF))
    return f


_def(0xE8, _set('x', lambda c: c.x + 1))
_def(0xCA, _set('x', lambda c: c.x - 1))
_def(0xC8, _set('y', lambda c: c.y + 1))
_def(0x88, _set('y', lambda c: c.y - 1))
_def(0xAA, _set('x', lambda c: c.a))
_def(0x8A, _set('a', lambda c: c.x))
_def(0xA8, _set('y', lambda c: c.a))
_def(0x98, _set('a', lambda c: c.y))
_def(0xBA, _set('x', lambda c: c.s))


def _txs(cpu, mem, rd, wr):
    cpu.s = cpu.x


_def(0x9A, _txs)


def _flag(code, mask, on):
    def f(cpu, mem, rd, wr):
        cpu.p = (cpu.p | mask) if on else (cpu.p & ~mask)
    _def(code, f)


_flag(0x18, C, False); _flag(0x38, C, True); _flag(0x58, I, False); _flag(0x78, I, True)
_flag(0xB8, V, False); _flag(0xD8, D, False); _flag(0xF8, D, True)


def _branch(code, mask, on):
    def f(cpu, mem, rd, wr):
        off = _fetch(cpu, mem)
        if bool(cpu.p & mask) == on:
            cpu.pc = (cpu.pc + (off - 256 if off & 0x80 else off)) & 0xFFFF
            cpu.cycles += 1
    _def(code, f)


_branch(0x10, N, False); _branch(0x30, N, True); _branch(0x50, V, False); _branch(0x70, V, True)
_branch(0x90, C, False); _branch(0xB0, C, True); _branch(0xD0, Z, False); _branch(0xF0, Z, True)


def _jmp(cpu, mem, rd, wr):
    cpu.pc = _fetch16(cpu, mem)


def _jmpi(cpu, mem, rd, wr):
    a = _fetch16(cpu, mem)
    hi = (a & 0xFF00) | ((a + 1) & 0xFF)             # the NMOS page wrap
    cpu.pc = rd(a) | rd(hi) << 8


def _jsr(cpu, mem, rd, wr):
    t = _fetch16(cpu, mem)
    r = (cpu.pc - 1) & 0xFFFF
    cpu.push(r >> 8)
    cpu.push(r & 0xFF)
    cpu.pc = t


def _rts(cpu, mem, rd, wr):
    lo = cpu.pull()
    cpu.pc = ((cpu.pull() << 8 | lo) + 1) & 0xFFFF


def _rti(cpu, mem, rd, wr):
    cpu.p = (cpu.pull() | U) & ~B
    lo = cpu.pull()
    cpu.pc = cpu.pull() << 8 | lo


def _brk(cpu, mem, rd, wr):
    cpu.pc = (cpu.pc + 1) & 0xFFFF
    cpu.interrupt(0xFFFE, True)


def _pha(cpu, mem, rd, wr): cpu.push(cpu.a)
def _php(cpu, mem, rd, wr): cpu.push(cpu.p | B | U)
def _pla(cpu, mem, rd, wr): cpu.a = _nz(cpu, cpu.pull())
def _plp(cpu, mem, rd, wr): cpu.p = (cpu.pull() | U) & ~B
def _nop(cpu, mem, rd, wr): pass


for _code, _fn in ((0x4C, _jmp), (0x6C, _jmpi), (0x20, _jsr), (0x60, _rts), (0x40, _rti),
                   (0x00, _brk), (0x48, _pha), (0x08, _php), (0x68, _pla), (0x28, _plp), (0xEA, _nop)):
    _def(_code, _fn)
