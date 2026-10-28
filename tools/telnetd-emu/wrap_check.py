"""wrap_check.py [cols] [rounds]: shell mode's edit line in a narrow terminal, the editor alone (shpipe.c with
src/telnetd_proto.c, built here).  The Beeb prints a prompt; the editor takes a probe
key (echoed), then random edits make lines longer than the terminal is wide, with teletext codes typed with
Ctrl-V among them (each a one-cell marker, coloured or reversed).  After every key the terminal (beebterm's
Screen, wrapping as xterm does) must show the prompt and the edit line laid out from the prompt across its rows, nothing
else below, and the cursor where the editor's is.  Linux or WSL, Python 3 and gcc."""
import os, random, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.normpath(os.path.join(HERE, "..", "..", "src"))
sys.path.insert(0, os.path.join(HERE, ".."))
from beebterm import Screen
SHPIPE = os.path.join(tempfile.gettempdir(), "telnetd-emu-shpipe")
subprocess.check_call(["gcc", "-std=gnu2x", "-O1", "-I" + SRC, "-o", SHPIPE, os.path.join(HERE, "shpipe.c"),
                       os.path.join(SRC, "telnetd_proto.c")])
COLS = int(sys.argv[1]) if len(sys.argv) > 1 else 20
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 200
LEFT, RIGHT, HOME, END, DEL, BS = 0x8C, 0x8D, 0xF7, 0x8B, 0xF6, 0x7F
MARKS = {0x81: "█", 0x84: "█", 0x93: "▒", 0x8D: "2", 0x9D: "B", 0x88: "F"}   # code: its marker
random.seed(7)
fails = 0
for rnd in range(ROUNDS):
    prompt = random.choice([">", "*", "Name? ", "?" * random.randint(1, COLS + 5)])
    cmds = ["b %02x" % ord(c) for c in prompt] + ["t 200000", "k %02x" % ord("A"), "b %02x" % ord("A"), "b 7f", "t 50000"]
    model, cur = ["A"], 1                        # what the edit line should hold
    steps = []
    for _ in range(random.randint(5, 60)):
        r = random.random()
        if r < 0.47:
            ch = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")
            cmds.append("k %02x" % ord(ch)); model.insert(cur, ch); cur += 1
        elif r < 0.55:                           # Ctrl-V and two hex digits: a teletext code, a marker
            code = random.choice(list(MARKS))
            cmds += ["k 16"] + ["k %02x" % ord(h) for h in "%02X" % code]; model.insert(cur, MARKS[code]); cur += 1
        elif r < 0.65 and cur > 0:
            cmds.append("k %02x" % LEFT); cur -= 1
        elif r < 0.72 and cur < len(model):
            cmds.append("k %02x" % RIGHT); cur += 1
        elif r < 0.77:
            cmds.append("k %02x" % HOME); cur = 0
        elif r < 0.82:
            cmds.append("k %02x" % END); cur = len(model)
        elif r < 0.9 and cur > 0:
            cmds.append("k %02x" % BS); model.pop(cur - 1); cur -= 1
        elif cur < len(model):
            cmds.append("k %02x" % DEL); model.pop(cur)
        else:
            continue
        steps.append(("".join(model), cur, len(cmds)))
    # one run of the whole stream, then check each step by running its prefix (cheap: the editor is small)
    for line, c, n in steps[-3:] + steps[::max(1, len(steps) // 4)]:
        out = subprocess.run([SHPIPE, str(COLS)], input=("\n".join(cmds[:n]) + "\n").encode(),
                             capture_output=True).stdout
        sc = Screen(30, COLS)
        sc.feed(out)
        text = prompt + line
        want_rows = [text[i:i + COLS] for i in range(0, max(len(text), 1), COLS)]
        got_rows = ["".join(r).rstrip() for r in sc.grid]
        first = next((i for i, r in enumerate(got_rows) if r), 0)
        got = got_rows[first:first + len(want_rows)]
        rest = [r for r in got_rows[first + len(want_rows):] if r]
        pos = len(prompt) + c
        want_rc = (first + pos // COLS, pos % COLS)
        got_rc = (sc.r, sc.c if sc.c < COLS else COLS)    # beebterm keeps a waiting wrap as c == cols
        ok = got == [r.rstrip() for r in want_rows] and not rest and (got_rc == want_rc or
              (pos % COLS == 0 and pos and got_rc == (want_rc[0] - 1, COLS)))
        if not ok:
            fails += 1
            if fails <= 3:
                print("round %d prompt %r line %r cur %d" % (rnd, prompt, line, c))
                print("  want", [r.rstrip() for r in want_rows], want_rc)
                print("  got ", got, "rest", rest, got_rc)
                if os.environ.get("WRAP_DEBUG"):
                    print("  keys", " ".join(cmds[:n]))
                    print("  out ", repr(out))
print("cols %d: rounds %d, failures %d" % (COLS, ROUNDS, fails))
sys.exit(1 if fails else 0)
