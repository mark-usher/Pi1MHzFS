"""The 6502 second processor on the Tube, for beeb.py: the Tube ULA and a 65C02 with 64K of RAM and its
client ROM.

The Tube ULA follows b-em (src/tube.c): four registers each way, R1 parasite to host a 24-byte FIFO, R3
one or two bytes (the V flag), and the control flags S T P V M J I Q written through the host's &FEE0.
The host sees it at &FEE0-&FEE7 (mirrored to &FEFF), the parasite at &FEF8-&FEFF.  Q gives the host an
IRQ while R4 holds a byte for it; I gives the parasite an IRQ while R1 does, J while R4 does; M its NMI
for R3.  Clearing the flags with P set resets the parasite, as b-em does it.

The parasite is a 65C02 (the CMOS opcodes, and the Rockwell bit ones as b-em has them) at 3 MHz against
the host's 2: Beeb.run brings it up to time after every host instruction, so the transfers the host
times by itself (R3 without a status check) are read in time.  Its client ROM (2K) covers &F000-&FFFF
from reset until it first reads R1's status, as on the board; writes there meanwhile go to the RAM
beneath.  No ROM image is kept here: run.py loads the one from --roms.
"""
from beeb import (B, CYCLES, D, I, OPS, U, Z, _adc, _bad, _bit, _cmp, _fetch, _fetch16, _nz, _sbc,
                  am_abs, am_abx, am_zp, am_zpx)


class Tube:
    PH1 = 24

    def __init__(self, para, debug=False):
        self.para = para
        self.debug = debug                            # every register access printed (--debug)
        self.reset()

    def reset(self):
        self.r1stat = 0
        self.ph1 = bytearray(self.PH1)
        self.ph1head = self.ph1tail = self.ph1count = 0
        self.hp1 = self.hp2 = self.ph2 = self.hp4 = self.ph4 = 0
        self.hp3 = bytearray(2)
        self.ph3 = bytearray(2)
        self.hp3pos = 0
        self.ph3pos = 1
        self.hstat = [0x40, 0x40, 0xC0, 0x40]
        self.pstat = [0x40, 0x7F, 0x7F, 0x7F]
        self.update()

    def update(self):
        r = self.r1stat
        self.hirq = bool(r & 1 and self.hstat[3] & 0x80)
        self.pirq = bool((r & 2 and self.pstat[0] & 0x80) or (r & 4 and self.pstat[3] & 0x80))
        self.pnmi = bool(r & 8 and (self.ph3pos == 0 or self.hp3pos > (1 if r & 16 else 0)))

    def _log(self, side, rw, reg, v):
        print("tube: %s %s R%d%s %02X" % (side, rw, reg // 2 + 1, "" if reg & 1 else " status", v))

    def host_read(self, reg):
        if reg == 0:
            v = (self.hstat[0] & 0xC0) | self.r1stat
        elif reg == 1:
            v = self.ph1[self.ph1head]
            if self.ph1count:
                self.ph1count -= 1
                if not self.ph1count:
                    self.hstat[0] &= ~0x80
                self.ph1head = (self.ph1head + 1) % self.PH1
                self.pstat[0] |= 0x40
        elif reg == 2:
            v = self.hstat[1]
        elif reg == 3:
            v = self.ph2
            if self.hstat[1] & 0x80:
                self.hstat[1] &= ~0x80
                self.pstat[1] |= 0x40
        elif reg == 4:
            v = self.hstat[2]
        elif reg == 5:
            v = self.ph3[0]
            if self.ph3pos:
                self.ph3[0] = self.ph3[1]
                self.ph3pos -= 1
                self.pstat[2] |= 0xC0
                if not self.ph3pos:
                    self.hstat[2] &= ~0x80
        elif reg == 6:
            v = self.hstat[3]
        else:
            v = self.ph4
            if self.hstat[3] & 0x80:
                self.hstat[3] &= ~0x80
                self.pstat[3] |= 0x40
        if self.debug and reg & 1:
            self._log("host", "read", reg, v)
        self.update()
        return v

    def host_write(self, reg, v):
        if self.debug:
            self._log("host", "write", reg, v)
        if reg == 0:
            if v & 0x80:
                self.r1stat |= v & 0x3F
            elif self.r1stat & 0x20:
                self.reset()
                self.para.reset()
            else:
                self.r1stat &= ~(v & 0x3F)
            self.hstat[0] = (self.hstat[0] & 0xC0) | (v & 0x3F)
        elif reg == 1:
            self.hp1 = v
            self.pstat[0] |= 0x80
            self.hstat[0] &= ~0x40
        elif reg == 3:
            self.hp2 = v
            self.pstat[1] |= 0x80
            self.hstat[1] &= ~0x40
        elif reg == 5:
            if self.r1stat & 16:
                if self.hp3pos < 2:
                    self.hp3[self.hp3pos] = v
                    self.hp3pos += 1
                if self.hp3pos == 2:
                    self.pstat[2] |= 0x80
                    self.hstat[2] &= ~0x40
            else:
                self.hp3[0] = v
                self.hp3pos = 1
                self.pstat[2] |= 0x80
                self.hstat[2] &= ~0x40
        elif reg == 7:
            self.hp4 = v
            self.pstat[3] |= 0x80
            self.hstat[3] &= ~0x40
        self.update()

    def para_read(self, reg):
        if reg == 0:
            self.para.rom_out()
            v = self.pstat[0] | self.r1stat
        elif reg == 1:
            v = self.hp1
            if self.pstat[0] & 0x80:
                self.pstat[0] &= ~0x80
                self.hstat[0] |= 0x40
        elif reg == 2:
            v = self.pstat[1]
        elif reg == 3:
            v = self.hp2
            if self.pstat[1] & 0x80:
                self.pstat[1] &= ~0x80
                self.hstat[1] |= 0x40
        elif reg == 4:
            v = self.pstat[2]
        elif reg == 5:
            v = self.hp3[0]
            if self.hp3pos:
                self.hp3[0] = self.hp3[1]
                self.hp3pos -= 1
                if not self.hp3pos:
                    self.hstat[2] |= 0x40
                    self.pstat[2] &= ~0x80
        elif reg == 6:
            v = self.pstat[3]
        else:
            v = self.hp4
            if self.pstat[3] & 0x80:
                self.pstat[3] &= ~0x80
                self.hstat[3] |= 0x40
        if self.debug and reg & 1:
            self._log("para", "read", reg, v)
        self.update()
        return v

    def para_write(self, reg, v):
        if self.debug and reg & 1:
            self._log("para", "write", reg, v)
        if reg == 1:
            if self.ph1count < self.PH1:
                self.ph1[self.ph1tail] = v
                self.ph1tail = (self.ph1tail + 1) % self.PH1
                self.hstat[0] |= 0x80
                self.ph1count += 1
                if self.ph1count == self.PH1:
                    self.pstat[0] &= ~0x40
        elif reg == 3:
            self.ph2 = v
            self.hstat[1] |= 0x80
            self.pstat[1] &= ~0x40
        elif reg == 5:
            if self.r1stat & 16:
                if self.ph3pos < 2:
                    self.ph3[self.ph3pos] = v
                    self.ph3pos += 1
                if self.ph3pos == 2:
                    self.hstat[2] |= 0x80
                    self.pstat[2] &= ~0x40
            else:
                self.ph3[0] = v
                self.ph3pos = 1
                self.hstat[2] |= 0x80
                self.pstat[2] &= ~0xC0
        elif reg == 7:
            self.ph4 = v
            self.hstat[3] |= 0x80
            self.pstat[3] &= ~0x40
        self.update()


class Parasite:
    """The 6502 second processor.  rom: the client ROM (2K, or the last 2K of a bigger image)."""

    RATIO = 1.5                                      # parasite cycles per host cycle: 3 MHz to 2

    def __init__(self, rom, debug=False):
        self.rom = bytes(rom[-0x800:]) * 2           # mirrored over &F000-&FFFF
        self.mem = bytearray(0x10000)
        self.shadow = bytearray(0x1000)              # the RAM under the ROM
        self.tube = Tube(self, debug)
        self.cycles = 0
        self.resets = 0
        self.reset()

    def reset(self):
        self.resets += 1
        self.rom_in = True
        self.mem[0xF000:0x10000] = self.rom
        self.a = self.x = self.y = 0
        self.s = 0xFF
        self.p = I | U
        self.pc = self.mem[0xFFFC] | self.mem[0xFFFD] << 8
        self.nmi_old = False

    def rom_out(self):
        if self.rom_in:
            self.rom_in = False
            self.mem[0xF000:0x10000] = self.shadow

    def rd(self, a):
        if (a & 0xFFF8) == 0xFEF8:
            return self.tube.para_read(a & 7)
        return self.mem[a]

    def wr(self, a, v):
        if (a & 0xFFF8) == 0xFEF8:
            self.tube.para_write(a & 7, v)
        elif a >= 0xF000 and self.rom_in:
            self.shadow[a - 0xF000] = v
        else:
            self.mem[a] = v

    def push(self, v):
        self.mem[0x100 + self.s] = v & 0xFF
        self.s = (self.s - 1) & 0xFF

    def pull(self):
        self.s = (self.s + 1) & 0xFF
        return self.mem[0x100 + self.s]

    def interrupt(self, vector, brk):
        self.push(self.pc >> 8)
        self.push(self.pc & 0xFF)
        self.push((self.p | U | (B if brk else 0)) & ~(0 if brk else B))
        self.p = (self.p | I) & ~D                   # the 65C02 clears D
        self.pc = self.mem[vector] | self.mem[vector + 1] << 8

    def run_to(self, host_cycles):
        end = host_cycles * self.RATIO
        mem = self.mem
        rd = self.rd
        wr = self.wr
        tube = self.tube
        ops = OPS_C02
        cyc = CYCLES_C02
        while self.cycles < end:
            if tube.pnmi != self.nmi_old:            # NMI: on the edge
                self.nmi_old = tube.pnmi
                if tube.pnmi:
                    self.interrupt(0xFFFA, False)
                    self.cycles += 7
            if tube.pirq and not (self.p & I):
                self.interrupt(0xFFFE, False)
                self.cycles += 7
            op = mem[self.pc]
            self.pc = (self.pc + 1) & 0xFFFF
            ops[op](self, mem, rd, wr)
            self.cycles += cyc[op]


# ---- the 65C02's instructions: the NMOS table, and what the CMOS chip adds -------------

OPS_C02 = list(OPS)
CYCLES_C02 = list(CYCLES)


def _c02(code, fn, cycles):
    OPS_C02[code] = fn
    CYCLES_C02[code] = cycles


def am_izp(cpu, mem):
    z = _fetch(cpu, mem)
    return mem[z] | mem[(z + 1) & 0xFF] << 8


def _apply_for(kind):
    def f(cpu, v):
        if kind == 'ora':
            cpu.a = _nz(cpu, cpu.a | v)
        elif kind == 'and':
            cpu.a = _nz(cpu, cpu.a & v)
        elif kind == 'eor':
            cpu.a = _nz(cpu, cpu.a ^ v)
        elif kind == 'adc':
            _adc(cpu, v)
            _nz(cpu, cpu.a)                          # the 65C02's N and Z are the result's, decimal too
        elif kind == 'lda':
            cpu.a = _nz(cpu, v)
        elif kind == 'cmp':
            _cmp(cpu, cpu.a, v)
        else:
            _sbc(cpu, v)
            _nz(cpu, cpu.a)
    return f


for _base, _kind in ((0x00, 'ora'), (0x20, 'and'), (0x40, 'eor'), (0x60, 'adc'),
                     (0xA0, 'lda'), (0xC0, 'cmp'), (0xE0, 'sbc')):
    _c02(_base + 0x12, (lambda f: lambda cpu, mem, rd, wr: f(cpu, rd(am_izp(cpu, mem))))(_apply_for(_kind)), 5)
_c02(0x92, lambda cpu, mem, rd, wr: wr(am_izp(cpu, mem), cpu.a), 5)


def _bitimm(cpu, mem, rd, wr):
    v = _fetch(cpu, mem)
    cpu.p = (cpu.p & ~Z) | (0 if (cpu.a & v) else Z)


def _ld(attr, get):
    def f(cpu, mem, rd, wr):
        setattr(cpu, attr, _nz(cpu, get(cpu) & 0xFF))
    return f


_c02(0x89, _bitimm, 2)
_c02(0x34, lambda cpu, mem, rd, wr: _bit(cpu, rd(am_zpx(cpu, mem))), 4)
_c02(0x3C, lambda cpu, mem, rd, wr: _bit(cpu, rd(am_abx(cpu, mem))), 4)
_c02(0x1A, _ld('a', lambda c: c.a + 1), 2)
_c02(0x3A, _ld('a', lambda c: c.a - 1), 2)
_c02(0x5A, lambda cpu, mem, rd, wr: cpu.push(cpu.y), 3)
_c02(0xDA, lambda cpu, mem, rd, wr: cpu.push(cpu.x), 3)
_c02(0x7A, _ld('y', lambda c: c.pull()), 4)
_c02(0xFA, _ld('x', lambda c: c.pull()), 4)
_c02(0x64, lambda cpu, mem, rd, wr: wr(am_zp(cpu, mem), 0), 3)
_c02(0x74, lambda cpu, mem, rd, wr: wr(am_zpx(cpu, mem), 0), 4)
_c02(0x9C, lambda cpu, mem, rd, wr: wr(am_abs(cpu, mem), 0), 4)
_c02(0x9E, lambda cpu, mem, rd, wr: wr(am_abx(cpu, mem), 0), 5)


def _bra(cpu, mem, rd, wr):
    off = _fetch(cpu, mem)
    cpu.pc = (cpu.pc + (off - 256 if off & 0x80 else off)) & 0xFFFF


_c02(0x80, _bra, 3)


def _tsb_trb(am, setting):
    def f(cpu, mem, rd, wr):
        a = am(cpu, mem)
        v = rd(a)
        cpu.p = (cpu.p & ~Z) | (0 if (cpu.a & v) else Z)
        wr(a, (v | cpu.a) if setting else (v & ~cpu.a & 0xFF))
    return f


_c02(0x04, _tsb_trb(am_zp, True), 5)
_c02(0x0C, _tsb_trb(am_abs, True), 6)
_c02(0x14, _tsb_trb(am_zp, False), 5)
_c02(0x1C, _tsb_trb(am_abs, False), 6)


def _jmpi(cpu, mem, rd, wr):
    a = _fetch16(cpu, mem)
    cpu.pc = rd(a) | rd((a + 1) & 0xFFFF) << 8      # no page wrap on the 65C02


def _jmpix(cpu, mem, rd, wr):
    a = (_fetch16(cpu, mem) + cpu.x) & 0xFFFF
    cpu.pc = rd(a) | rd((a + 1) & 0xFFFF) << 8


_c02(0x6C, _jmpi, 6)
_c02(0x7C, _jmpix, 6)


def _rsmb(bit, setting):
    def f(cpu, mem, rd, wr):
        z = _fetch(cpu, mem)
        wr(z, (rd(z) | (1 << bit)) if setting else (rd(z) & ~(1 << bit) & 0xFF))
    return f


def _bbrs(bit, setting):
    def f(cpu, mem, rd, wr):
        z = _fetch(cpu, mem)
        off = _fetch(cpu, mem)
        if bool(rd(z) & (1 << bit)) == setting:
            cpu.pc = (cpu.pc + (off - 256 if off & 0x80 else off)) & 0xFFFF
    return f


for _b in range(8):
    _c02(0x07 + 16 * _b, _rsmb(_b, False), 5)
    _c02(0x87 + 16 * _b, _rsmb(_b, True), 5)
    _c02(0x0F + 16 * _b, _bbrs(_b, False), 5)
    _c02(0x8F + 16 * _b, _bbrs(_b, True), 5)


def _skip(n):
    def f(cpu, mem, rd, wr):                         # n bytes in all: the opcode is already taken
        cpu.pc = (cpu.pc + n - 1) & 0xFFFF
    return f


# What is left undefined is a NOP on the 65C02: two bytes in column 2 and &44, &54, &D4, &F4, three
# for &5C, &DC, &FC, else one.
for _i in range(256):
    if OPS_C02[_i] is _bad:
        _c02(_i, _skip(2 if (_i & 0x0F) == 0x02 or _i in (0x44, 0x54, 0xD4, 0xF4)
                       else 3 if _i in (0x5C, 0xDC, 0xFC) else 1), 2)
