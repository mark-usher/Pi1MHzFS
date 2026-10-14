"""The Pi's side of the serial stub in FRED, as src/serial_redirect.c does it.

The stub's bytes are the firmware's (serial_redirect_init), at its default place &FCCC,
and the Pi's answers to the Beeb's writes follow serial_redirect.c: the TX port (+00)
takes the Beeb's output, the consume (+0C) and full (+0F) writes end a trip through the
RX gate, the exit (+2A) is RTI with a JMP to the MOS every 16th byte, a full keyboard
buffer backs off for 2 ms.  ESCAPE is a trip through the stub's own routine at +2D
storing &80 in &FF (the firmware's generic trip; the routine it keeps below the stub
for the Tube is not modelled, and nothing here depends on where that is).  Not
modelled: the RS423 idle trip (only the cassette and ROM filing systems need it),
BREAK, and the control port's reports from the auto-start ROM.

install() does what helper 20 does to the vectors, from outside: the harness calls it
when BASIC first asks for a line.  *FX3,1 is then typed through the stub itself.
"""
from collections import deque

BASE = 0xCC
OP_CLC, OP_SEC, OP_JMP, OP_BIT, OP_RTI = 0x18, 0x38, 0x4C, 0x2C, 0x40
TX, TXFLAG, INSV_OLD, GATE, IRQ1V_OLD, FULL = 0x00, 0x04, 0x0A, 0x0C, 0x0D, 0x0F
RX_BYTE, INBUF, JSR_LO, CONTROL, EXIT, EXIT_OLD = 0x14, 0x16, 0x18, 0x28, 0x2A, 0x2B
TRAMP, ROUTINE, TRIP_ADDR = 0x09, 0x2D, 0x2E
FIFO = 1024
CHAIN_EVERY = 16
BACKOFF_US = 2000

STUB = bytes([
    0xE0, 0x02, 0xD0, 0x05, OP_CLC, 0x8D, 0x00, 0xFC, 0x60,
    OP_JMP, 0x00, 0x00, OP_JMP, 0x00, 0x00, 0x8A, 0x48, 0x98, 0x48,
    0xA9, 0x00, 0xA2, 0x01, 0x20, 0x09, 0xFC, 0x90, 0x05, 0x8D, 0x0F, 0xFC,
    0xB0, 0x03, 0x8D, 0x0C, 0xFC, 0x68, 0xA8, 0x68, 0xAA, 0xA5, 0xFC,
    OP_JMP, 0x00, 0x00, 0x8D, 0xFF, 0x00, 0x60])
REL = (0x06, 0x18, 0x1D, 0x22)          # low bytes relative to the base


class Stub:
    def __init__(self):
        self.fred = bytearray([0xFF] * 256)
        self.fred[BASE:BASE + len(STUB)] = STUB
        for r in REL:
            self.fred[BASE + r] = (BASE + STUB[r]) & 0xFF
        self.tx = deque()               # Beeb -> Pi
        self.rx = deque()               # Pi -> Beeb (keys)
        self.irq = False
        self.gate_open = False
        self.esc_req = False
        self.esc_active = False
        self.backoff_until = None
        self.rx_count = 0
        self.hooked = False
        self.escapes = 0
        self.fulls = 0
        self.now = 0

    def w(self, off, v):
        self.fred[BASE + off] = v

    # ---- the bus ----
    def read(self, a):
        return self.fred[a]

    def write(self, a, v):
        off = a - BASE
        if off == TX:
            self.tx.append(v)
        elif off == GATE:
            self.consume()
        elif off == FULL:
            self.full()
        elif off == CONTROL:
            pass                                    # install() has done what helper 20 says here
        elif off in (INSV_OLD, INSV_OLD + 1, IRQ1V_OLD, IRQ1V_OLD + 1, EXIT_OLD, EXIT_OLD + 1):
            self.fred[a] = v

    # ---- serial_redirect.c ----
    def gate_close(self):
        self.w(GATE, OP_JMP)
        self.gate_open = False
        self.irq = False
        if self.esc_active:
            self.esc_active = False
            self.esc_req = True
            self.w(JSR_LO, BASE + TRAMP)

    def arm_next(self):
        if self.esc_req:
            self.esc_req = False
            self.esc_active = True
            self.w(TRIP_ADDR, 0xFF)
            self.w(TRIP_ADDR + 1, 0x00)
            self.w(JSR_LO, BASE + ROUTINE)
            self.w(RX_BYTE, 0x80)
        elif self.rx:
            self.w(RX_BYTE, self.rx[0])
        else:
            return False
        return True

    def consume(self):
        if not self.gate_open:
            return
        if self.esc_active:
            self.esc_active = False
            self.escapes += 1
            self.w(JSR_LO, BASE + TRAMP)
        else:
            if not self.rx:
                return
            self.rx.popleft()
            self.rx_count += 1
        self.w(EXIT, OP_JMP if self.rx_count % CHAIN_EVERY == 0 else OP_RTI)
        if not self.arm_next():
            self.gate_close()

    def full(self):
        if self.esc_active:
            self.consume()
            return
        self.fulls += 1
        self.gate_close()
        self.backoff_until = self.now + BACKOFF_US

    def escape(self):
        """serial_redirect_escape: the FIFO goes, the next trip raises ESCAPE."""
        self.gate_close()
        self.rx.clear()
        self.esc_req = True
        self.backoff_until = None

    def room(self):
        return FIFO - len(self.rx)

    def poll(self, now):
        self.now = now
        if self.gate_open:
            return
        if self.backoff_until is not None:
            if now < self.backoff_until:
                return
            self.backoff_until = None
        if self.hooked and (self.rx or self.esc_req) and self.arm_next():
            self.w(GATE, OP_BIT)
            self.gate_open = True
            self.irq = True

    # ---- helper 20, from outside ----
    def install(self, mem):
        """Hook INSV and IRQ1V into the stub, telnet mode (keys into buffer 0)."""
        INSV, IRQ1V = 0x22A, 0x204
        self.w(INSV_OLD, mem[INSV]); self.w(INSV_OLD + 1, mem[INSV + 1])
        self.w(IRQ1V_OLD, mem[IRQ1V]); self.w(IRQ1V_OLD + 1, mem[IRQ1V + 1])
        self.w(EXIT_OLD, mem[IRQ1V]); self.w(EXIT_OLD + 1, mem[IRQ1V + 1])
        mem[INSV] = BASE; mem[INSV + 1] = 0xFC
        mem[IRQ1V] = BASE + GATE; mem[IRQ1V + 1] = 0xFC
        self.w(INBUF, 0)                            # telnet mode: the keyboard buffer
        self.w(EXIT, OP_RTI)
        self.hooked = True
