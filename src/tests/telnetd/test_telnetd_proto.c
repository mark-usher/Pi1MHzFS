/* test_telnetd_proto.c - host tests for the telnet daemon's byte translators
   (telnetd_proto.c): what a telnet client's keys become on the Beeb, and what
   the Beeb's VDU stream becomes on a terminal. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net_telnet.h"
#include "telnetd_proto.h"

static int failures, checks;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; \
   printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* ---- client -> Beeb ---------------------------------------------------- */

static uint8_t keys[64]; static size_t nkeys;
static uint8_t reply[64]; static size_t nreply;
static uint32_t now;

static void in_reset(void) { nkeys = nreply = 0; now = 1000; }

static void feed(tnd_in_t *s, const void *data, size_t len)
{
   const uint8_t *p = data;
   for (size_t i = 0; i < len; i++) {
      uint8_t k[TND_IN_KEYS], r[TND_IN_REPLY];
      size_t rl, n = tnd_in_byte(s, p[i], now, k, r, &rl);
      CHECK(n <= TND_IN_KEYS, "one byte released %u keys, more than TND_IN_KEYS", (unsigned)n);
      if (n > TND_IN_KEYS || nkeys + n > sizeof keys)
         n = 0;
      memcpy(keys + nkeys, k, n);         nkeys += n;
      memcpy(reply + nreply, r, rl);      nreply += rl;
   }
}
#define FEED(s, lit) feed(s, lit, sizeof(lit) - 1)

static void tick(tnd_in_t *s, uint32_t advance_us)
{
   uint8_t k[TND_IN_KEYS];
   now += advance_us;
   size_t n = tnd_in_tick(s, now, k);
   CHECK(n <= TND_IN_KEYS, "a tick released %u keys, more than TND_IN_KEYS", (unsigned)n);
   if (n > TND_IN_KEYS || nkeys + n > sizeof keys)
      n = 0;
   memcpy(keys + nkeys, k, n);
   nkeys += n;
}

/* The login's rules (PR review): per address, a hold after every failure, longer lockouts, and
   timers that survive the 32-bit microsecond clock wrapping. */
static void test_login(void)
{
   tnd_login_t l;
   const uint32_t A = 0x0A00000Au, B = 0x0B00000Bu;
   uint32_t t = 0xFFFFFF00u;                    /* just before the clock wraps */

   tnd_login_reset(&l);
   tnd_login_tick(&l, t);
   CHECK(!tnd_login_locked(&l, A) && !tnd_login_held(&l), "login: nothing against anybody at the start");
   CHECK(!tnd_login_fail(&l, A) && tnd_login_held(&l), "login: a wrong password holds every prompt ...");
   tnd_login_tick(&l, t += TND_HOLD_US - 1u);
   CHECK(tnd_login_held(&l), "... until TND_HOLD_US has gone ...");
   tnd_login_tick(&l, t += 2u);
   CHECK(!tnd_login_held(&l) && !tnd_login_locked(&l, A), "... and then not, across the clock's wrap");
   CHECK(!tnd_login_fail(&l, A) && tnd_login_fail(&l, A), "login: the third wrong password from an address locks it");
   CHECK(tnd_login_locked(&l, A) && !tnd_login_locked(&l, B), "login: ... that address only: another can still log in");
   tnd_login_tick(&l, t += TND_LOCK_US - 1u);
   CHECK(tnd_login_locked(&l, A), "login: locked for TND_LOCK_US ...");
   tnd_login_tick(&l, t += 2u);
   CHECK(!tnd_login_locked(&l, A), "login: ... then free");
   tnd_login_fail(&l, A); tnd_login_fail(&l, A);
   CHECK(tnd_login_fail(&l, A), "login: three more: locked again ...");
   tnd_login_tick(&l, t += TND_LOCK_US + 1u);
   CHECK(tnd_login_locked(&l, A), "... for twice as long the second time");
   tnd_login_tick(&l, t += TND_LOCK_US);
   CHECK(!tnd_login_locked(&l, A), "... and then free");
   tnd_login_ok(&l, A);
   tnd_login_fail(&l, A);
   tnd_login_fail(&l, A);
   CHECK(!tnd_login_locked(&l, A), "login: a right login clears the count (two after it do not lock)");
   tnd_login_tick(&l, t += TND_FAIL_DECAY_US + 1u);
   CHECK(!tnd_login_fail(&l, A), "login: failures are forgotten after TND_FAIL_DECAY_US (one more does not lock)");
   for (int i = 0; i < 30; i++) {               /* the lockout stops growing at TND_LOCK_MAX_US */
      tnd_login_fail(&l, A); tnd_login_fail(&l, A); tnd_login_fail(&l, A);
   }
   tnd_login_tick(&l, t += TND_LOCK_MAX_US - 1u);
   CHECK(tnd_login_locked(&l, A), "login: a much repeated lockout lasts TND_LOCK_MAX_US ...");
   tnd_login_tick(&l, t += 2u);
   CHECK(!tnd_login_locked(&l, A), "login: ... and no longer");
   tnd_login_reset(&l);                         /* more addresses than the table holds: a lock is kept */
   tnd_login_tick(&l, t);
   tnd_login_fail(&l, A); tnd_login_fail(&l, A); tnd_login_fail(&l, A);
   for (uint32_t i = 1u; i <= 3u * TND_LOGIN_ADDRS; i++)
      tnd_login_fail(&l, 0x0C000000u + i);
   CHECK(tnd_login_locked(&l, A), "login: many other addresses do not push a locked one out of the table");
   CHECK(tnd_login_may_replace(A, A, 0u) && !tnd_login_may_replace(A, B, TND_REPLACE_IDLE_US - 1u)
         && tnd_login_may_replace(A, B, TND_REPLACE_IDLE_US),
         "login: a session at the prompt is replaced by its own address, or by another once idle");
}

/* PR review: one input byte released up to 5 keys into a 3-key array (a lone Latin-1 lead byte, ESC,
   then a high byte; or ESC P after one), before any login.  Every call, on random input and on the
   worst cases found, stays within TND_IN_KEYS, with the array exactly that size (ASan sees past it). */
static void test_input_key_bound(void)
{
   tnd_in_t s;
   uint32_t seed = 12345u, worst = 0u, t = 1000u;
   static const uint8_t worst_cases[][4] = {
      { 0xE9, 0xF5, 0, 0 }, { 0xE9, 0x1B, 0xF5, 0 }, { 0xE9, 0x1B, 'P', 0xF5 }, { 0xC3, 0x1B, 'P', 0xE9 },
      { 0x1B, 'P', 0xC0, 0 }, { 0x1B, 0xFE, 0, 0 }, { 0xF0, 0x9F, 0x1B, 0xFF },
   };
   for (int lit = 0; lit < 2; lit++)
      for (int tele = 0; tele < 2; tele++) {
         for (size_t w = 0; w < sizeof worst_cases / sizeof worst_cases[0]; w++) {
            tnd_in_reset(&s);
            s.lit_ok = lit != 0;
            s.tele = tele != 0;
            for (size_t i = 0; i < 4 && (i == 0 || worst_cases[w][i] != 0); i++) {
               uint8_t k[TND_IN_KEYS], r[TND_IN_REPLY];
               size_t  rl, n = tnd_in_byte(&s, worst_cases[w][i], t, k, r, &rl);
               if (n > worst) worst = (uint32_t)n;
               CHECK(n <= TND_IN_KEYS, "case %u byte %u: %u keys", (unsigned)w, (unsigned)i, (unsigned)n);
            }
            {
               uint8_t k[TND_IN_KEYS];
               size_t  n = tnd_in_tick(&s, t + 1000000u, k);  /* whatever was left waiting, timed out */
               CHECK(n <= TND_IN_KEYS, "case %u tick: %u keys", (unsigned)w, (unsigned)n);
            }
         }
         tnd_in_reset(&s);
         s.lit_ok = lit != 0;
         s.tele = tele != 0;
         for (unsigned i = 0; i < 2000000u; i++) {
            uint8_t k[TND_IN_KEYS], r[TND_IN_REPLY], c;
            size_t  rl, n;
            seed = seed * 1103515245u + 12345u;
            c = (uint8_t)(seed >> 16);
            if ((seed >> 8 & 7u) == 0u) c = 0x1B;              /* plenty of ESCs, Ps and high bytes */
            else if ((seed >> 8 & 7u) == 1u) c = 'P';
            t += (seed >> 24 & 3u) == 0u ? 300000u : 10u;      /* now and then long enough to time out */
            n = tnd_in_byte(&s, c, t, k, r, &rl);
            if (n > worst) worst = (uint32_t)n;
            if (n > TND_IN_KEYS) { CHECK(0, "random input: %u keys from one byte", (unsigned)n); break; }
            n = tnd_in_tick(&s, t, k);
            if (n > TND_IN_KEYS) { CHECK(0, "random input: %u keys from one tick", (unsigned)n); break; }
         }
      }
   CHECK(worst <= TND_IN_KEYS, "the most keys from one byte: %u (TND_IN_KEYS %u)", (unsigned)worst, (unsigned)TND_IN_KEYS);
}

static bool keys_are(const char *expect, size_t len)
{
   return nkeys == len && memcmp(keys, expect, len) == 0;
}
#define KEYS(lit) keys_are(lit, sizeof(lit) - 1)

static void dump(void)
{
   printf("    keys:");
   for (size_t i = 0; i < nkeys; i++) printf(" %02X", keys[i]);
   printf("\n    reply:");
   for (size_t i = 0; i < nreply; i++) printf(" %02X", reply[i]);
   printf("\n");
}

static void test_plain_keys(void)
{
   tnd_in_t s; tnd_in_reset(&s); in_reset();

   FEED(&s, "PRINT 6*7");
   CHECK(KEYS("PRINT 6*7"), "ordinary keys pass through"); if (!KEYS("PRINT 6*7")) dump();

   in_reset();
   FEED(&s, "A\r\0B");
   CHECK(nkeys == 3 && keys[0] == 'A' && keys[1] == 13 && keys[2] == 'B',
         "CR NUL is one RETURN, the NUL swallowed"); if (nkeys != 3) dump();

   in_reset();
   FEED(&s, "A\r\nB");
   CHECK(nkeys == 3 && keys[1] == 13 && keys[2] == 'B', "CR LF is one RETURN");

   in_reset();
   FEED(&s, "A\nB");
   CHECK(nkeys == 3 && keys[1] == 13, "a lone LF is a RETURN (netcat, printf)");

   in_reset();
   FEED(&s, "\r\r");
   CHECK(nkeys == 2 && keys[0] == 13 && keys[1] == 13, "two RETURNs are two");

   in_reset();
   FEED(&s, "x\x08y\x7f");
   CHECK(nkeys == 4 && keys[1] == 127 && keys[3] == 127, "BS and DEL both give the Beeb's DELETE");

   in_reset();
   FEED(&s, "\x01\x1a");
   CHECK(nkeys == 2 && keys[0] == 1 && keys[1] == 26, "control keys pass");

   in_reset();
   FEED(&s, "\x03");
   CHECK(nkeys == 1 && keys[0] == TND_KEY_ESCAPE, "Ctrl-C is the ESCAPE request");
}

static void test_pound_and_high_bytes(void)
{
   tnd_in_t s; tnd_in_reset(&s); in_reset();

   FEED(&s, "\xc2\xa3");
   CHECK(nkeys == 1 && keys[0] == 96, "UTF-8 pound sign is the Beeb's 96");

   in_reset();
   FEED(&s, "\xa3");
   CHECK(nkeys == 1 && keys[0] == 96, "Latin-1 pound sign too");

   in_reset();
   FEED(&s, "a\xc3\xa9z");
   CHECK(KEYS("az"), "another UTF-8 character is dropped whole"); if (!KEYS("az")) dump();

   in_reset();
   FEED(&s, "a\xe2\x82\xacz");
   CHECK(KEYS("az"), "a three-byte character is dropped whole"); if (!KEYS("az")) dump();

   /* T-18: with a ROM that reads bytes as they are (build 13), characters above 127 go through */
   tnd_in_reset(&s); s.lit_ok = true; in_reset();
   FEED(&s, "a\xc3\xa9z");
   CHECK(nkeys == 4 && keys[0] == 'a' && keys[1] == TND_KEY_LIT && keys[2] == 0xE9 && keys[3] == 'z',
         "lit_ok: UTF-8 e-acute is LIT and &E9"); if (nkeys != 4) dump();
   in_reset();
   FEED(&s, "\xc2\x81\xc2\x9d");
   CHECK(nkeys == 4 && keys[0] == TND_KEY_LIT && keys[1] == 0x81 && keys[2] == TND_KEY_LIT && keys[3] == 0x9D,
         "lit_ok: U+0081 and U+009D (teletext red, new background) are their bytes"); if (nkeys != 4) dump();
   in_reset();
   FEED(&s, "\xc2\xa3");
   CHECK(nkeys == 1 && keys[0] == 96, "lit_ok: the pound sign is still the Beeb's 96");
   in_reset();
   FEED(&s, "x\xe9y");
   CHECK(nkeys == 4 && keys[1] == TND_KEY_LIT && keys[2] == 0xE9, "lit_ok: a Latin-1 client's byte &E9 too"); if (nkeys != 4) dump();
   /* Windows' telnet (terminal type ANSI) types in code page 850: the pound sign is &9C, e-acute &82 */
   tnd_in_reset(&s); s.lit_ok = true; strcpy(s.ttype, "ANSI"); s.ttype_got = true; in_reset();
   FEED(&s, "a\x9c" "b");
   CHECK(KEYS("a`b"), "Windows telnet: &9C is the pound sign, the Beeb's 96"); if (!KEYS("a`b")) dump();
   in_reset();
   FEED(&s, "\x82");
   CHECK(nkeys == 2 && keys[0] == TND_KEY_LIT && keys[1] == 0xE9, "Windows telnet: &82 is e-acute, &E9"); if (nkeys != 2) dump();
   in_reset();
   FEED(&s, "\xc6" "z");                        /* a-tilde: a UTF-8 lead byte with nothing after it */
   CHECK(nkeys == 3 && keys[0] == TND_KEY_LIT && keys[1] == 0xE3 && keys[2] == 'z', "Windows telnet: &C6 is a-tilde, &E3");
   if (nkeys != 3) dump();
   in_reset();
   FEED(&s, "\xc2\xa3");
   CHECK(nkeys == 1 && keys[0] == 96, "Windows telnet in a UTF-8 console (chcp 65001): UTF-8 still");
   tnd_in_reset(&s); s.lit_ok = true; in_reset();
   FEED(&s, "\xe2\x86\x91");
   CHECK(nkeys == 0, "not MODE 7: an up arrow is no Beeb byte");
   s.tele = true; in_reset();
   FEED(&s, "\xe2\x86\x91\xc2\xbd\xc3\xb7\xe2\x80\x95");
   CHECK(KEYS("^\\~`"), "MODE 7: the glyphs the daemon prints come back as their codes (up arrow, 1/2, divide, dash)");
   if (!KEYS("^\\~`")) dump();
   in_reset();
   FEED(&s, "\xc3\xa9");
   CHECK(nkeys == 2 && keys[0] == TND_KEY_LIT && keys[1] == 0xE9, "MODE 7: other characters as their bytes");
   in_reset();
   FEED(&s, "\xf0\x9f\x98\x80" "q");
   CHECK(KEYS("q"), "a four-byte character (emoji) is dropped whole"); if (!KEYS("q")) dump();

   tnd_in_reset(&s); in_reset();
   FEED(&s, "\xc2" "a");
   CHECK(KEYS("a"), "a lead byte then ASCII: the ASCII kept (the lone byte, without lit_ok, dropped)");
}

static void test_cursor_and_function_keys(void)
{
   tnd_in_t s; tnd_in_reset(&s); in_reset();

   FEED(&s, "\x1b[A\x1b[B\x1b[C\x1b[D");
   CHECK(nkeys == 4 && keys[0] == 143 && keys[1] == 142 && keys[2] == 141 && keys[3] == 140,
         "CSI arrows are the buffer's codes: up 143, down 142, right 141, left 140"); if (nkeys != 4) dump();

   in_reset();
   FEED(&s, "\x1bOA\x1bOB\x1bOC\x1bOD");
   CHECK(nkeys == 4 && keys[0] == 143 && keys[3] == 140, "SS3 arrows (application mode) too");

   in_reset();
   FEED(&s, "\x1b[1;5A");
   CHECK(nkeys == 1 && keys[0] == 0xAF, "Ctrl-Up is the keyboard's CTRL-up, &AF");

   in_reset();
   FEED(&s, "\x1b[3~");
   CHECK(nkeys == 1 && keys[0] == 127, "Delete is the Beeb's DELETE");

   in_reset();
   FEED(&s, "\x1b[F");
   CHECK(nkeys == 1 && keys[0] == 139, "End is COPY (139 in the buffer)");
   in_reset();
   FEED(&s, "\x1b[4~");
   CHECK(nkeys == 1 && keys[0] == 139, "End (VT220) is COPY");

   in_reset();
   FEED(&s, "\x1bOP\x1bOQ\x1bOR\x1bOS");
   CHECK(nkeys == 4 && keys[0] == 0x81 && keys[1] == 0x82 && keys[2] == 0x83 && keys[3] == 0x84,
         "F1-F4 are f1-f4");

   /* SHIFT and CTRL: the keyboard scan's codes, &10 and &20 above the key's */
   in_reset();
   FEED(&s, "\x1b[1;2P\x1b[1;5Q\x1b[1;6S\x1b[15;2~\x1b[21;5~\x1b[20;6~\x1b[1;3P");
   CHECK(nkeys == 7 && keys[0] == 0x91 && keys[1] == 0xA2 && keys[2] == 0xB4 && keys[3] == 0x95 && keys[4] == 0xA0
         && keys[5] == 0xB9 && keys[6] == 0x81,
         "SHIFT-F1 &91, CTRL-F2 &A2, CTRL-SHIFT-F4 &B4, SHIFT-F5 &95, CTRL-F10 &A0, CTRL-SHIFT-F9 &B9, Alt-F1 f1");
   if (nkeys != 7) dump();
   in_reset();
   FEED(&s, "\x1b[1;2A\x1b[1;5D\x1b[1;6C\x1b[1;2F\x1b[4;5~\x1b[1;3B");
   CHECK(nkeys == 6 && keys[0] == 0x9F && keys[1] == 0xAC && keys[2] == 0xBD && keys[3] == 0x9B && keys[4] == 0xAB
         && keys[5] == 142, "SHIFT-up &9F, CTRL-left &AC, CTRL-SHIFT-right &BD, SHIFT-End (COPY) &9B, CTRL-End &AB, Alt-down down");
   if (nkeys != 6) dump();
   in_reset();
   FEED(&s, "\x1b[3;2~\x1b[6;2~");
   CHECK(nkeys == 2 && keys[0] == 127 && keys[1] == TND_KEY_SHIFT, "SHIFT-Delete is DELETE, SHIFT-Page Down still SHIFT");
   if (nkeys != 2) dump();

   in_reset();
   FEED(&s, "\x1b[15~\x1b[17~\x1b[18~\x1b[19~\x1b[20~\x1b[21~");
   CHECK(nkeys == 6 && keys[0] == 0x85 && keys[1] == 0x86 && keys[2] == 0x87 && keys[3] == 0x88
         && keys[4] == 0x89 && keys[5] == 0x80, "F5-F9 are f5-f9, F10 is f0"); if (nkeys != 6) dump();

   in_reset();
   FEED(&s, "\x1b[2~\x1b[5~\x1b[6~\x1b[H\x1b[1~");
   CHECK(nkeys == 1 && keys[0] == TND_KEY_SHIFT, "Insert, PgUp, Home: no Beeb key, nothing leaks; PgDn is SHIFT");
   if (nkeys != 1) dump();

   in_reset();
   FEED(&s, "\x1b[?25h" "k");
   CHECK(KEYS("k"), "a private sequence is swallowed, the next key survives"); if (!KEYS("k")) dump();
}

static void test_escape_key(void)
{
   tnd_in_t s; tnd_in_reset(&s); in_reset();

   FEED(&s, "\x1b");
   CHECK(nkeys == 0, "a lone ESC waits to see if a sequence follows");
   tick(&s, TND_ESC_US - 1);
   CHECK(nkeys == 0, "... not yet");
   tick(&s, 2);
   CHECK(nkeys == 1 && keys[0] == TND_KEY_ESCAPE, "... then it is the ESCAPE request");
   tick(&s, 1000000);
   CHECK(nkeys == 1, "and only once");

   in_reset();
   FEED(&s, "\x1bx");
   CHECK(nkeys == 2 && keys[0] == TND_KEY_ESCAPE && keys[1] == 'x', "ESC then a letter: both, in order");

   in_reset();
   FEED(&s, "\x1b\r");
   CHECK(nkeys == 2 && keys[0] == TND_KEY_ESCAPE && keys[1] == 13, "ESC then RETURN: both");

   in_reset();
   FEED(&s, "\x1b\x1b");
   CHECK(nkeys == 1 && keys[0] == TND_KEY_ESCAPE, "ESC ESC: the first is a request, the second still waiting");
   tick(&s, TND_ESC_US);
   CHECK(nkeys == 2 && keys[1] == TND_KEY_ESCAPE, "... and then it is one too");

   in_reset();
   FEED(&s, "\x1b[");
   tick(&s, 400000);
   FEED(&s, "A");
   CHECK(nkeys == 1 && keys[0] == 143, "a slow sequence still completes");
   in_reset();
   FEED(&s, "\x1b[");
   tick(&s, 600000);
   FEED(&s, "A");
   CHECK(KEYS("A"), "a sequence abandoned for half a second is dropped; the next key is plain");
}

static void test_blank(void)
{
   tnd_out_t o;
   uint8_t   buf[TND_OUT_MAX];
   tnd_out_reset(&o, false);
   tnd_out_assume_mode(&o, 7);
   tnd_out_at(&o, 0, 0);
   CHECK(tnd_out_blank(&o), "a model that has seen nothing is blank");
   (void)tnd_out_byte(&o, 'A', buf);
   CHECK(!tnd_out_blank(&o), "...and one with a character is not");
   (void)tnd_out_byte(&o, 12, buf);
   CHECK(tnd_out_blank(&o), "...until the screen is cleared");
}

static void test_break_key(void)
{
   tnd_in_t s; tnd_in_reset(&s); in_reset();
   FEED(&s, "\x1b[24~");
   CHECK(nkeys == 1 && keys[0] == TND_KEY_BREAK, "F12 is the BREAK request");
   in_reset();
   FEED(&s, "\x1b[24;2~\x1b[24;5~\x1b[24;6~\x1b[24;3~");
   CHECK(nkeys == 4 && keys[0] == TND_KEY_SHIFTBREAK && keys[1] == TND_KEY_CTRLBREAK && keys[2] == TND_KEY_CTRLBREAK
         && keys[3] == TND_KEY_BREAK, "SHIFT-F12 SHIFT-BREAK, CTRL-F12 and CTRL-SHIFT-F12 CTRL-BREAK, ALT-F12 BREAK"); if (nkeys != 4) dump();
   in_reset();
   FEED(&s, "\x1b[21~\x1b[23~");
   CHECK(nkeys == 2 && keys[0] == 0x80 && keys[1] == TND_KEY_REFRESH, "F10 is f0 and F11 is the redraw request");
   in_reset();
   FEED(&s, "ab\xff\xf3" "c");
   CHECK(nkeys == 4 && keys[2] == TND_KEY_BREAK && keys[3] == 'c', "IAC BRK is the BREAK request"); if (nkeys != 4) dump();
   in_reset();
   FEED(&s, "ab\xff\xf4" "c");
   CHECK(nkeys == 4 && keys[2] == TND_KEY_ESCAPE && keys[3] == 'c', "IAC IP (Ctrl-C in line mode) is ESCAPE"); if (nkeys != 4) dump();
   /* A line-mode client's ESC is IAC IP (its interrupt character, set by us): read as the ESC byte. */
   in_reset();
   FEED(&s, "\xff\xf4");
   CHECK(nkeys == 0, "IAC IP alone: an ESC, waiting");
   tick(&s, TND_ESC_US + 1000u);
   CHECK(nkeys == 1 && keys[0] == TND_KEY_ESCAPE, "IAC IP alone: ESCAPE once nothing follows");
   in_reset();
   FEED(&s, "\xff\xf4\xff\xfd\x06" "[24~");
   static const uint8_t wont_tm[] = { 255, 252, 6 };
   CHECK(nkeys == 1 && keys[0] == TND_KEY_BREAK && nreply == 3 && memcmp(reply, wont_tm, 3) == 0,
         "IAC IP, DO TM, [24~ (F12 from a line-mode client): BREAK, and the TM answered"); if (nkeys != 1) dump();
   in_reset();
   FEED(&s, "\xff\xf4" "[6~");
   CHECK(nkeys == 1 && keys[0] == TND_KEY_SHIFT, "IAC IP [6~ (Page Down from a line-mode client): SHIFT"); if (nkeys != 1) dump();
   in_reset();
   FEED(&s, "\xff\xee" "x");
   CHECK(nkeys == 2 && keys[0] == TND_KEY_ESCAPE && keys[1] == 'x', "IAC ABORT (Ctrl-C in line mode): ESCAPE at once");
   in_reset();
   FEED(&s, "\x1b[2\xff\xf1" "4~");
   CHECK(nkeys == 1 && keys[0] == TND_KEY_BREAK, "a NOP inside a CSI sequence: the sequence goes on"); if (nkeys != 1) dump();
   in_reset();
   FEED(&s, "\x1b[6~");
   CHECK(nkeys == 1 && keys[0] == TND_KEY_SHIFT, "Page Down is SHIFT, for paged mode");
   in_reset();
   FEED(&s, "\x1b[5~");
   CHECK(nkeys == 0, "Page Up is nothing");
   in_reset();
   FEED(&s, "");
   CHECK(nkeys == 1 && keys[0] == TND_KEY_REFRESH, "Ctrl-L is the redraw request too");
}

static void test_negotiation(void)
{
   tnd_in_t s; tnd_in_reset(&s); in_reset();
   uint8_t g[TND_GREETING_LEN];

   CHECK(tnd_greeting(g) == TND_GREETING_LEN, "greeting length");
   static const uint8_t want[] = { 255, 251, 1, 255, 251, 3, 255, 253, 3, 255, 253, 31, 255, 253, 24 };
   CHECK(sizeof want == TND_GREETING_LEN && memcmp(g, want, sizeof want) == 0, "greeting: WILL ECHO, WILL SGA, DO SGA, DO NAWS, DO TTYPE");

   /* The client's answers to our offer need no reply. */
   FEED(&s, "\xff\xfd\x01\xff\xfd\x03\xff\xfb\x03");
   CHECK(nreply == 0 && nkeys == 0, "DO ECHO, DO SGA, WILL SGA: accepted silently"); if (nreply || nkeys) dump();

   /* Things we do not offer are refused, once. */
   in_reset();
   FEED(&s, "\xff\xfd\x18");
   static const uint8_t wont24[] = { 255, 252, 24 };
   CHECK(nreply == 3 && memcmp(reply, wont24, 3) == 0, "DO TTYPE: WONT TTYPE"); if (nreply != 3) dump();
   FEED(&s, "\xff\xfd\x18");
   CHECK(nreply == 3, "asked again: no second reply (no loop)");

   /* NAWS: asked for in the greeting, so WILL NAWS is accepted silently, and the sizes kept. */
   in_reset();
   FEED(&s, "\xff\xfb\x1f");
   CHECK(nreply == 0 && nkeys == 0 && s.win_gen == 0u, "WILL NAWS: accepted silently");
   FEED(&s, "\xff\xfa\x1f\x00\x64\x00\x1e\xff\xf0" "a");
   CHECK(s.win_cols == 100u && s.win_rows == 30u && s.win_gen == 1u && nkeys == 1 && keys[0] == 'a' && nreply == 0,
         "NAWS 100 x 30 (Windows telnet's answer): kept, nothing leaks, the next key goes through");
   FEED(&s, "\xff\xfa\x1f\x00\xff\xff\x01\x00\xff\xf0");
   CHECK(s.win_cols == 255u && s.win_rows == 256u && s.win_gen == 2u, "a 255 in the size is doubled (IAC IAC)");
   FEED(&s, "\xff\xfa\x1f\x00\x50\xff\xf0");
   CHECK(s.win_cols == 255u && s.win_gen == 2u, "a short NAWS is ignored");
   FEED(&s, "\xff\xfa\x18\x00VT100\xff\xf0");
   CHECK(s.win_gen == 2u, "another option's subnegotiation is not a size");
   tnd_in_reset(&s); in_reset();
   FEED(&s, "\xff\xfc\x1f");
   CHECK(s.naws_no && nreply == 0, "WONT NAWS: noted, no reply");

   /* TTYPE: asked for in the greeting; WILL TTYPE is answered with SEND, once; IS is kept. */
   tnd_in_reset(&s); in_reset();
   FEED(&s, "\xff\xfb\x18");
   static const uint8_t send24[] = { 255, 250, 24, 1, 255, 240 };
   CHECK(nreply == 6 && memcmp(reply, send24, 6) == 0, "WILL TTYPE: SB TTYPE SEND"); if (nreply != 6) dump();
   FEED(&s, "\xff\xfb\x18");
   CHECK(nreply == 6, "... once");
   FEED(&s, "\xff\xfa\x18\x00" "ANSI" "\xff\xf0" "x");
   CHECK(s.ttype_got && strcmp(s.ttype, "ANSI") == 0 && nkeys == 1 && keys[0] == 'x', "TTYPE IS ANSI (Windows telnet): kept, nothing leaks");
   FEED(&s, "\xff\xfa\x18\x00" "XTERM-256COLOR-AND-A-VERY-LONG-NAME-INDEED" "\xff\xf0");
   CHECK(strlen(s.ttype) == sizeof s.ttype - 1u && strncmp(s.ttype, "XTERM-256COLOR", 14) == 0, "a long name is cut, still ended");

   in_reset();
   FEED(&s, "\xff\xfc\x01\xff\xfc\x03");
   CHECK(nreply == 0, "WONT ECHO, WONT SGA need no reply");

   /* Line mode (Linux telnet's "mode line"): DONT SGA and DONT ECHO after the client agreed to
      both, answered WONT once each and counted; character mode again: DO, answered WILL. */
   in_reset();
   FEED(&s, "\xff\xfd\x03\xff\xfd\x01");
   CHECK(nreply == 0, "DO SGA, DO ECHO as the answers to the greeting: no reply");
   in_reset();
   uint8_t gen0 = s.mode_gen;
   FEED(&s, "\xff\xfe\x03\xff\xfe\x01\xff\xfe\x01");
   static const uint8_t wonts[] = { 255, 252, 3, 255, 252, 1 };
   CHECK(nreply == 6 && memcmp(reply, wonts, 6) == 0 && s.echo_off && s.sga_off, "DONT SGA, DONT ECHO: WONT each, once"); if (nreply != 6) dump();
   CHECK((uint8_t)(s.mode_gen - gen0) == 2u, "line mode: counted (%u)", (unsigned)(uint8_t)(s.mode_gen - gen0));
   uint8_t lines0 = s.line_gen;
   FEED(&s, "AB\r\nCD\r\n");
   CHECK((uint8_t)(s.line_gen - lines0) == 2u, "line mode: each line the client sent (and echoed) counted (%u)",
         (unsigned)(uint8_t)(s.line_gen - lines0));
   in_reset();
   FEED(&s, "\xff\xfd\x01\xff\xfd\x03\xff\xfd\x01");
   static const uint8_t wills[] = { 255, 251, 1, 255, 251, 3 };
   CHECK(nreply == 6 && memcmp(reply, wills, 6) == 0 && !s.echo_off && !s.sga_off, "DO ECHO, DO SGA again: WILL each, once"); if (nreply != 6) dump();
   CHECK((uint8_t)(s.mode_gen - gen0) == 4u, "character mode: counted");
   lines0 = s.line_gen;
   FEED(&s, "AB\r\n");
   CHECK(s.line_gen == lines0, "character mode: RETURN is not a client's line");
   in_reset();
   FEED(&s, "\xff\xfb\x01");
   static const uint8_t dont1[] = { 255, 254, 1 };
   CHECK(nreply == 3 && memcmp(reply, dont1, 3) == 0, "WILL ECHO from the client: refused (DONT)");

   /* LINEMODE: the offer Linux telnet makes as it connects is refused, so the session starts in
      character mode; the next ("mode line") is taken: DO, MODE EDIT|TRAPSIG, and the special
      characters ESC, Ctrl-C and "~"; once. */
   in_reset();
   FEED(&s, "\xff\xfb\x22");
   static const uint8_t dont34a[] = { 255, 254, 34 };
   CHECK(nreply == 3 && memcmp(reply, dont34a, 3) == 0 && !s.lm, "the first WILL LINEMODE (at connect): DONT");
   in_reset();
   FEED(&s, "\xff\xfb\x22");
   static const uint8_t lm[] = { 255, 253, 34, 255, 250, 34, 1, 3, 255, 240,
                                 255, 250, 34, 3, 3, 0x42, 27, 7, 0x42, 3, 17, 2, '~', 255, 240 };
   CHECK(nreply == sizeof lm && memcmp(reply, lm, sizeof lm) == 0 && s.lm, "WILL LINEMODE: DO, MODE, SLC (%u bytes)", (unsigned)nreply);
   CHECK(sizeof lm <= TND_IN_REPLY, "the LINEMODE answer fits TND_IN_REPLY");
   FEED(&s, "\xff\xfb\x22\xff\xfa\x22\x01\x07\xff\xf0\xff\xfa\x22\x03\x03\xc2\x1b\xff\xf0" "k");
   CHECK(nreply == sizeof lm && nkeys == 1 && keys[0] == 'k', "WILL again, the client's MODE ack and SLC: no reply, nothing leaks");
   in_reset();
   FEED(&s, "\xff\xfc\x22");
   static const uint8_t dont34[] = { 255, 254, 34 };
   CHECK(nreply == 3 && memcmp(reply, dont34, 3) == 0 && !s.lm, "WONT LINEMODE (mode character): DONT");

   /* After IP a client flushes its output until DO TIMING-MARK is answered: every time. */
   in_reset();
   FEED(&s, "\xff\xfd\x06\xff\xfd\x06");
   static const uint8_t wont6[] = { 255, 252, 6, 255, 252, 6 };
   CHECK(nreply == 6 && memcmp(reply, wont6, 6) == 0, "DO TM: WONT TM, every time"); if (nreply != 6) dump();

   /* Subnegotiation is dropped entirely, even with an escaped 0xFF inside. */
   in_reset();
   FEED(&s, "a\xff\xfa\x18\x00VT100\xff\xff\xff\xf0" "b");
   CHECK(KEYS("ab") && nreply == 0, "SB ... IAC SE is dropped, the keys around it survive"); if (!KEYS("ab")) dump();

   in_reset();
   FEED(&s, "a\xff\xff" "b");
   CHECK(KEYS("ab"), "IAC IAC is a literal 0xFF, which is not a Beeb key");

   in_reset();
   FEED(&s, "a\xff\xf1\xff\xf6" "b");
   CHECK(KEYS("ab") && nreply == 0, "NOP and AYT are ignored");

   in_reset();
   FEED(&s, "\xff");
   FEED(&s, "\xfd");
   FEED(&s, "\x2d");
   CHECK(nreply == 3, "a command split across reads still parses");
}

static void test_input_robustness(void)
{
   tnd_in_t s; tnd_in_reset(&s); in_reset();
   uint8_t junk[4096];
   unsigned seed = 12345;
   for (size_t i = 0; i < sizeof junk; i++) {
      seed = seed * 1103515245u + 12345u;
      junk[i] = (uint8_t)(seed >> 16);
   }
   /* Any byte stream: no key beyond what a byte can release, replies bounded. */
   size_t maxkeys = 0;
   for (size_t i = 0; i < sizeof junk; i++) {
      uint8_t k[TND_IN_KEYS], r[TND_IN_REPLY];
      size_t rl, n = tnd_in_byte(&s, junk[i], (uint32_t)i * 50u, k, r, &rl);
      if (n > maxkeys) maxkeys = n;
      CHECK(n <= TND_IN_KEYS && rl <= TND_IN_REPLY, "bounds at byte %zu", i);
      for (size_t j = 0; j < n; j++)
         CHECK(k[j] != 0u || k[j] == TND_KEY_ESCAPE, "a NUL key is only ever the ESCAPE request");
   }
   CHECK(maxkeys <= TND_IN_KEYS, "fuzz: key bound holds");
}

/* ---- Beeb -> terminal ---------------------------------------------------- */

static char outbuf[8192];
static const char *render(const void *data, size_t len, bool utf8, tnd_out_t *keep)
{
   tnd_out_t local;
   tnd_out_t *s = keep ? keep : &local;
   const uint8_t *p = data;
   size_t o = 0;
   if (!keep) tnd_out_reset(s, utf8);
   for (size_t i = 0; i < len; i++) {
      uint8_t d[TND_OUT_MAX];
      size_t n = tnd_out_byte(s, p[i], d);
      if (n > TND_OUT_MAX) { outbuf[0] = '!'; outbuf[1] = 0; return outbuf; }
      memcpy(outbuf + o, d, n);
      o += n;
   }
   outbuf[o] = '\0';
   return outbuf;
}
#define RENDER(lit) render(lit, sizeof(lit) - 1, true, NULL)
#define OUT_IS(lit, expect) (strcmp(RENDER(lit), expect) == 0)

/* A narrow text window: the terminal cannot scroll or clear part of a line, so the model does
   and the rectangle is drawn again, a row at a time, from the model. */
static void test_narrow_window(void)
{
   tnd_out_t o;
   uint8_t   d[TND_REPAINT_MAX];
   tnd_out_reset(&o, true);
   tnd_out_assume_mode(&o, 7);
   (void)render("\x0c" "TOP", 4, true, &o);                     /* a full CLS: the rows are the Beeb's */
   const char *r = render("\x1c\x02\x0a\x14\x03" "\x0c", 6, true, &o);  /* VDU 28,2,10,20,3 then CLS */
   CHECK(strstr(r, "\x1b[2J") == NULL, "a CLS in a narrow window does not clear the whole terminal");
   CHECK(o.dirty && o.dl == 2 && o.dt == 3 && o.dr == 20 && o.db == 10, "... the window is marked to be drawn again");
   CHECK(o.ch[0][0] == 'T' && o.ch[0][1] == 'O', "... and what is outside it is kept");
   CHECK(o.cx == 2 && o.cy == 3, "... the cursor is at the window's corner");
   r = render("ab\r", 3, true, &o);
   CHECK(strstr(r, "\r\x1b[2C") != NULL, "a CR in the window goes to its left edge, not the terminal's");
   unsigned rows = 0;
   size_t   n;
   char     first[TND_REPAINT_MAX + 1];
   first[0] = 0;
   while ((n = tnd_out_dirty_row(&o, d)) != 0u) {
      if (rows == 0u) { memcpy(first, d, n); first[n] = 0; }
      rows++;
      CHECK(n <= TND_REPAINT_MAX, "a drawn row fits");
      if (rows > 40u) break;
   }
   CHECK(rows == 8u, "the window's eight rows are drawn");
   CHECK(strncmp(first, "\x1b[4;3H", 6) == 0, "... from its top left corner");
   CHECK(!o.dirty, "... and then nothing is left to draw");

   /* scrolling inside it: the rows move in the model and are drawn again */
   for (int i = 1; i <= 12; i++) {
      char line[8];
      int  len = snprintf(line, sizeof line, "W%d\r\n", i);
      (void)render(line, (size_t)len, true, &o);
   }
   CHECK(o.dirty, "a scroll in the window marks it");
   CHECK(o.ch[10][2] == ' ' && o.ch[9][2] == 'W' && o.ch[9][3] == '1' && o.ch[9][4] == '2', "the model has scrolled: W12 on the window's last row but one");
   CHECK(o.ch[0][0] == 'T', "the line above the window did not move");
   while (tnd_out_dirty_row(&o, d) != 0u) {}
   CHECK(!o.dirty, "drawn again");

   /* a CLS while the terminal's rows are not yet the Beeb's starts them, and the rest comes back */
   tnd_out_origin_lost(&o);
   r = render("\x0c", 1, true, &o);
   CHECK(strstr(r, "\x1b[2J") != NULL && o.origin_ok, "without an origin the terminal is cleared and gets one");
   CHECK(o.dirty && o.dl == 0 && o.dt == 0 && o.db == o.rows - 1u, "... and the whole screen is drawn again");
}

static void test_output_text(void)
{
   CHECK(OUT_IS("PRINT 42", "PRINT 42"), "text passes");
   CHECK(OUT_IS(">*FX2,1\r\n", ">*FX2,1\r\n"), "CR LF passes");
   CHECK(OUT_IS("a\n\rb", "a\n\rb"), "the Beeb's LF CR passes in its own order");
   CHECK(OUT_IS("ab\x7f", "ab\x08 \x08"), "DELETE (127) is back, blank, back");
   CHECK(OUT_IS("\x08", "\x08"), "cursor left is BS");
   CHECK(OUT_IS("\x09", "\x1b[C"), "cursor right");
   CHECK(OUT_IS("\x0b", "\x1b[A"), "cursor up");
   CHECK(OUT_IS("\x07", "\x07"), "bell");
   CHECK(OUT_IS("\x0c", "\x1b[2J\x1b[H"), "CLS clears and homes");
   CHECK(OUT_IS("\x1e", "\x1b[1;1H"), "VDU 30 homes");
   CHECK(strcmp(render("a`b", 3, true, NULL), "a\xc2\xa3" "b") == 0, "the Beeb's pound (96) is UTF-8");
   CHECK(strcmp(render("a`b", 3, false, NULL), "a\xa3" "b") == 0, "... or Latin-1");
}

static void test_output_params(void)
{
   const char *r;

   r = RENDER("\x1f\x05\x03" "X");
   CHECK(strcmp(r, "\x1b[4;6HX") == 0, "VDU 31,5,3 is row 4, column 6 (1-based, y first)"); if (strcmp(r, "\x1b[4;6HX")) printf("    got [%s]\n", r);
   r = RENDER("\x1f\x00\x00");
   CHECK(strcmp(r, "\x1b[1;1H") == 0, "VDU 31,0,0 is the corner");
   r = RENDER("\x1f\xff\xff");
   CHECK(strcmp(r, "") == 0, "VDU 31 outside the screen is ignored, as the Beeb does");

   r = RENDER("\x16\x07" "OK");
   CHECK(strcmp(r, "\x1b[2J\x1b[HOK") == 0, "MODE n clears the screen and its parameter vanishes"); if (strcmp(r, "\x1b[2J\x1b[HOK")) printf("    got [%s]\n", r);

   r = RENDER("\x11\x01R\x11\x82G");
   CHECK(strcmp(r, "\x1b[31mR\x1b[42mG") == 0, "COLOUR 1 is red text, 130 is green background"); if (strcmp(r, "\x1b[31mR\x1b[42mG")) printf("    got [%s]\n", r);
   r = RENDER("\x11\x0f" "x");
   CHECK(strcmp(r, "\x1b[37mx") == 0, "colour 15 (flashing white) is white");

   /* Parameters nobody shows are swallowed whole, so no junk reaches the terminal. */
   r = RENDER("\x12\x00\x01" "a");                 /* GCOL */
   CHECK(strcmp(r, "a") == 0, "GCOL eats 2");
   r = RENDER("\x13\x01\x02\x00\x00\x00" "a");     /* palette */
   CHECK(strcmp(r, "a") == 0, "palette eats 5");
   r = RENDER("\x17\x01\x00\x00\x00\x00\x00\x00\x00\x00" "a");   /* VDU 23,1: cursor off */
   CHECK(strcmp(r, "\x1b[?25la") == 0, "VDU 23 eats 9, and VDU 23,1,0 hides the terminal's cursor too");
   r = RENDER("\x17\x01\x01\x00\x00\x00\x00\x00\x00\x00" "a");
   CHECK(strcmp(r, "\x1b[?25ha") == 0, "VDU 23,1,1 shows it");
   r = RENDER("\x17\x00\x0a\x00\x00\x00\x00\x00\x00\x00" "a");
   CHECK(strcmp(r, "a") == 0, "other VDU 23 (character definitions) stay silent");
   r = RENDER("\x18\x01\x02\x03\x04\x05\x06\x07\x08" "a");
   CHECK(strcmp(r, "a") == 0, "VDU 24 eats 8");
   r = RENDER("\x19\x04\x00\x01\x00\x02" "a");     /* PLOT */
   CHECK(strcmp(r, "a") == 0, "VDU 25 eats 5");
   r = RENDER("\x1c\x00\x18\x27\x00" "a");         /* text window */
   CHECK(strcmp(r, "\x1b[1;1Ha") == 0, "VDU 28 eats 4 and homes the cursor in the window");
   r = RENDER("\x1d\x00\x01\x02\x03" "a");
   CHECK(strcmp(r, "a") == 0, "VDU 29 eats 4");
   r = RENDER("\x01\x41" "a");                      /* VDU 1: next char to printer */
   CHECK(strcmp(r, "a") == 0, "VDU 1 eats 1");

   /* Control bytes as parameters must not act as codes. */
   r = RENDER("\x11\x0c" "x");                      /* COLOUR 12: the 12 is a colour, not CLS */
   CHECK(strcmp(r, "\x1b[34mx") == 0, "a parameter that looks like CLS is just a number"); if (strcmp(r, "\x1b[34mx")) printf("    got [%s]\n", r);
   r = RENDER("\x16\x0d" "x");
   CHECK(strcmp(r, "\x1b[2J\x1b[Hx") == 0, "MODE 13: the 13 is not a RETURN");

   /* Codes that do nothing on a terminal take no parameters and print nothing. */
   r = RENDER("\x00\x02\x03\x04\x05\x0e\x0f\x10\x14\x1b" "z");
   CHECK(strcmp(r, "z") == 0, "VDU 0,2-5,14-16,20,27: silent"); if (strcmp(r, "z")) printf("    got [%s]\n", r);
}

/* ---- the screen model and the copy cursor ------------------------------- */

/* Windows' telnet client gets three CSI sequences wrong (checked against the client, Oct 2026): CHA
   (ESC [ n G) puts the cursor on the next line; SU and SD (ESC [ n S / T) do nothing and garble what
   follows.  No byte of output may contain them.  (A sequence split between two calls is not seen:
   the translator writes each sequence in one call.) */
static void wintelnet_check(const uint8_t *d, size_t n)
{
   for (size_t i = 0; i + 1 < n; i++) {
      if (d[i] != 27u || d[i + 1] != '[')
         continue;
      size_t j = i + 2;
      while (j < n && ((d[j] >= '0' && d[j] <= '9') || d[j] == ';'))
         j++;
      if (j < n && (d[j] == 'G' || d[j] == 'S' || d[j] == 'T'))
         CHECK(false, "no CHA, SU or SD in the output (Windows telnet gets them wrong)");
   }
}

static size_t feed_out(tnd_out_t *s, const char *data, size_t len, char *dst, size_t cap)
{
   size_t o = 0;
   for (size_t i = 0; i < len; i++) {
      uint8_t d[TND_OUT_MAX];
      size_t n = tnd_out_byte(s, (uint8_t)data[i], d);
      CHECK(n <= TND_OUT_MAX, "a byte of output never exceeds TND_OUT_MAX");
      wintelnet_check(d, n);
      if (o + n < cap) { memcpy(dst + o, d, n); o += n; }
   }
   dst[o] = '\0';
   return o;
}
#define FEED_OUT(s, lit, dst) feed_out(s, lit, sizeof(lit) - 1, dst, sizeof dst)

static void test_model_wrap_scroll(void)
{
   tnd_out_t s;
   char out[2048];
   char want[2048];

   /* Not synced: exactly what the translator always did. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "0123456789012345678901234567890123456789ABC", out);
   CHECK(strcmp(out, "0123456789012345678901234567890123456789ABC") == 0,
         "before the Beeb's cursor is known nothing is added");

   /* MODE 7 is 40 columns: the 41st character starts the next row. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07" "0123456789012345678901234567890123456789ABC", out);
   strcpy(want, "\x1b[2J\x1b[H0123456789012345678901234567890123456789\x1b[2;1HABC");
   CHECK(strcmp(out, want) == 0, "a 40-column line wraps where the Beeb wraps"); if (strcmp(out, want)) printf("    got [%s]\n", out);

   /* MODE 3 is 80 columns by 25 rows. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x03", out);
   {
      char line[100];
      memset(line, 'x', 80); line[80] = '\0';
      strcpy(out, ""); size_t o = 0;
      for (int i = 0; i < 80; i++) {
         uint8_t d[TND_OUT_MAX];
         size_t n = tnd_out_byte(&s, 'x', d);
         memcpy(out + o, d, n); o += n;
      }
      out[o] = '\0';
      CHECK(strstr(out, "\x1b[2;1H") != NULL && out[strlen(out) - 1] == 'H', "MODE 3 wraps after 80");
   }

   /* LF at the bottom scrolls the Beeb's window, and the terminal's. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x1f\x00\x18x\n", out);
   strcpy(want, "\x1b[2J\x1b[H\x1b[25;1Hx\x1b[1;25r\x1b[25;1H\x1b" "D\x1b[r\x1b[25;2H");
   CHECK(strcmp(out, want) == 0, "LF on the last row scrolls the terminal too"); if (strcmp(out, want)) printf("    got [%s]\n", out);

   /* A text window: TAB is relative to it and it scrolls on its own. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x03\x1c\x0a\x14\x1d\x05\x1f\x00\x00y", out);
   strcpy(want, "\x1b[2J\x1b[H\x1b[6;11H\x1b[6;11Hy");
   CHECK(strcmp(out, want) == 0, "VDU 28 sets the window and TAB(0,0) is its corner"); if (strcmp(out, want)) printf("    got [%s]\n", out);

   /* Writing in the last cell of the screen scrolls. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x1f\x27\x18z", out);
   strcpy(want, "\x1b[2J\x1b[H\x1b[25;40Hz\x1b[1;25r\x1b[25;1H\x1b" "D\x1b[r\x1b[25;1H");
   CHECK(strcmp(out, want) == 0, "a character in the bottom right cell scrolls"); if (strcmp(out, want)) printf("    got [%s]\n", out);

   /* Teletext starts each row white. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x1f\x00\x00\x81" "R\x1f\x00\x01" "W", out);
   CHECK(strstr(out, "\x1b[0;31mR") != NULL && strstr(out, "\x1b[2;1H\x1b[0mW") != NULL,
         "a colour does not carry to the next row in MODE 7");
   if (strstr(out, "\x1b[2;1H\x1b[0mW") == NULL) printf("    got [%s]\n", out);
}

static void test_copy_cursor(void)
{
   tnd_out_t s;
   char out[2048];
   uint8_t d[TND_COPY_MAX];
   size_t n;
   uint32_t t = 1000000;

   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c" ">HELLO\r\n>", out);            /* CLS, >HELLO, and BASIC's prompt on row 2 */
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 143);                            /* up */
   n = tnd_out_copyflush(&s, t + 1000, d);
   CHECK(n == 0, "the mark waits until the Beeb has been quiet");
   n = tnd_out_copyflush(&s, t + 50000, d);
   CHECK(n > 0 && n <= TND_COPY_MAX, "... then it is drawn");
   d[n] = 0;
   /* As the Beeb shows it: a solid block where typing goes, the flashing cursor on the copy cursor. */
   CHECK(strstr((char *)d, "\x1b[2;2H") != NULL && strstr((char *)d, "\x1b[7m ") != NULL && s.hl_on && s.hlx == 1u && s.hly == 1u,
         "up: a block (a reversed space) where typing goes"); if (!strstr((char *)d, "\x1b[7m ")) printf("    got [%s]\n", d);
   CHECK(strstr((char *)d, "\x1b[7mH") == NULL, "... and the H above is not reversed");
   CHECK(n >= 6 && strcmp((char *)d + n - 6, "\x1b[1;2H") == 0 && s.parked,
         "the terminal's cursor is left on the H, the copy cursor"); if (n >= 6 && strcmp((char *)d + n - 6, "\x1b[1;2H")) printf("    got [%s]\n", d);
   CHECK(tnd_out_copyflush(&s, t + 60000, d) == 0, "... and stays there: nothing more is sent");
   tnd_out_copykey(&s, 141);                            /* right: the copy cursor moves, the block does not */
   n = tnd_out_copyflush(&s, t + 61000, d);
   d[n] = 0;
   CHECK(n >= 6 && strcmp((char *)d + n - 6, "\x1b[1;3H") == 0 && strstr((char *)d, "\x1b[7m") == NULL && s.parked,
         "a second key moves the terminal's cursor with the copy cursor"); if (n < 6 || strcmp((char *)d + n - 6, "\x1b[1;3H")) printf("    got [%s]\n", d);
   tnd_out_copykey(&s, 140);                            /* and back left, onto the H */
   n = tnd_out_copyflush(&s, t + 62000, d);
   d[n] = 0;
   CHECK(n >= 6 && strcmp((char *)d + n - 6, "\x1b[1;2H") == 0, "... and back");

   {                                                    /* the Beeb prints: the cursor goes back first */
      uint8_t u[TND_UNPARK_MAX + 1];
      size_t un = tnd_out_unpark(&s, u);
      u[un] = 0;
      CHECK(strcmp((char *)u, "\x1b[2;2H") == 0 && !s.parked, "before output the cursor goes back where typing goes");
      CHECK(tnd_out_unpark(&s, u) == 0, "... once");
   }
   FEED_OUT(&s, "H", out);                              /* COPY's echo */
   tnd_out_touch(&s, t + 70000);
   tnd_out_copykey(&s, 139);                            /* COPY: the copy cursor moves on to the E */
   n = tnd_out_copyflush(&s, t + 120000, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[2;2H\x1b[0mH") != NULL && strstr((char *)d, "\x1b[2;3H") != NULL
         && strstr((char *)d, "\x1b[7m ") != NULL && strcmp((char *)d + n - 6, "\x1b[1;3H") == 0,
         "COPY: the old block shows the H copied, the block moves on, the cursor on the E"); if (strcmp((char *)d + n - 6, "\x1b[1;3H")) printf("    got [%s]\n", d);

   /* Output with no key (a program printing, a row drawn again): the block and the cursor follow. */
   (void)tnd_out_unpark(&s, d);
   FEED_OUT(&s, "X", out);
   tnd_out_touch(&s, t + 130000);
   CHECK(tnd_out_copyflush(&s, t + 140000, d) == 0, "after output the block waits for quiet");
   n = tnd_out_copyflush(&s, t + 180000, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[2;3H\x1b[0mX") != NULL && strstr((char *)d, "\x1b[2;4H") != NULL && s.hlx == 3u
         && s.parked && strcmp((char *)d + n - 6, "\x1b[1;3H") == 0,
         "... then it moves to where typing goes and the cursor goes back on the copy cursor"); if (!s.parked) printf("    got [%s]\n", d);

   tnd_out_copykey(&s, 13);                             /* RETURN ends it */
   n = tnd_out_copyflush(&s, t + 250000, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[2;4H\x1b[0m ") != NULL && strstr((char *)d, "\x1b[7m") == NULL && !s.parked && !s.hl_on,
         "RETURN removes the block"); if (strstr((char *)d, "\x1b[7m")) printf("    got [%s]\n", d);
   CHECK(n >= 6 && strstr((char *)d, "\x1b[2;4H") != NULL, "... and the cursor is where typing goes");
   CHECK(tnd_out_copyflush(&s, t + 300000, d) == 0, "and nothing more is sent");

   /* The mark moves with the text when the screen scrolls, and never stays on a cell the model has not seen. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07" ">AB\r\n>", out);
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 143);
   n = tnd_out_copyflush(&s, t + 50000, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[7m") != NULL && s.hl_on && s.hlx == 1u && s.hly == 1u && s.parked
         && strcmp((char *)d + n - 6, "\x1b[1;2H") == 0, "MODE 7: the block where typing goes, the cursor on the A");
   (void)tnd_out_unpark(&s, d);
   FEED_OUT(&s, "\x1f\x00\x18\n", out);                 /* TAB to the bottom row and a LF: the screen scrolls */
   tnd_out_touch(&s, t + 60000);
   tnd_out_copykey(&s, 141);
   n = tnd_out_copyflush(&s, t + 120000, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[7m") == NULL || strstr((char *)d, "\x1b[7mB") == NULL,
         "after a scroll the mark is not left on the old row");

   /* T-13: a listing waiting in paged mode (the cursor at the start of its row, nothing typed
      there): COPY or a cursor key just waits in the Beeb's buffer, so no mark is started. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x0e" "  10PRINT\r\n  20END\r\n", out);
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 139);
   n = tnd_out_copyflush(&s, t + 50000, d);
   CHECK(n == 0 && !s.cc_on && !s.hl_on, "T-13: COPY with the cursor at the start of a row (a paged listing): no mark");
   tnd_out_copykey(&s, 143);
   n = tnd_out_copyflush(&s, t + 100000, d);
   CHECK(n == 0 && !s.cc_on, "T-13: ... nor for a cursor key");
   FEED_OUT(&s, ">", out);                              /* the listing ends: BASIC's prompt */
   tnd_out_touch(&s, t + 150000);
   tnd_out_copykey(&s, 143);
   n = tnd_out_copyflush(&s, t + 250000, d);
   d[n] = 0;
   CHECK(s.cc_on && strstr((char *)d, "\x1b[7m") != NULL, "T-13: at the prompt the copy cursor starts as before");

   /* T-13 on the Beeb: in MODE 7 a paged listing also waits where a long line wraps, its cursor at
      column 39: in paged mode the copy cursor starts only on a row that begins with ">" or "?". */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x0e" "  10PRINT\r\n" "  20PRINT\"ABCDEFGHIJKLMNOPQRSTUVWXYZ012", out);   /* cursor at column 39 */
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 139);
   n = tnd_out_copyflush(&s, t + 50000, d);
   CHECK(n == 0 && !s.cc_on && s.paged && s.cx > 30u, "T-13: paged, waiting mid-row at a wrap: COPY starts no mark");
   FEED_OUT(&s, "\r\n?", out);                          /* an INPUT prompt */
   tnd_out_touch(&s, t + 60000);
   tnd_out_copykey(&s, 143);
   n = tnd_out_copyflush(&s, t + 150000, d);
   CHECK(s.cc_on, "T-13: paged, at INPUT's ? the copy cursor starts");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x0e\x0f" "  20PRINT\"ABCDEFGHIJKLMNOPQRSTUVWXYZ012", out);   /* VDU 15: paged off */
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 140);
   n = tnd_out_copyflush(&s, t + 50000, d);
   CHECK(!s.paged && s.cc_on, "T-13: VDU 15 ends paged mode: the plain rule again");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x0e", out);
   tnd_out_assume_mode(&s, 7u);
   CHECK(!s.paged, "T-13: a reset ends paged mode");

   /* With ROM build 11 the keys come only when the Beeb has taken them (cc_exact): no guessing
      from the screen, so a program's own prompt in paged mode ("Option (y/n)") works too. */
   tnd_out_reset(&s, true);
   s.cc_exact = true;
   FEED_OUT(&s, "\x16\x07\x0e" "  10PRINT\r\n" "Option (y/n)", out);
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 143);
   n = tnd_out_copyflush(&s, t + 50000, d);
   CHECK(s.cc_on && s.ccy == 0u, "cc_exact: paged, a program's own prompt: the copy cursor starts (the Beeb took the key)");
   tnd_out_reset(&s, true);
   s.cc_exact = true;
   FEED_OUT(&s, "\x16\x07" "\r\n", out);               /* INPUT with no prompt: the cursor at column 0 */
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 143);
   n = tnd_out_copyflush(&s, t + 50000, d);
   CHECK(s.cc_on, "cc_exact: at column 0 too");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07" ">", out);
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 139);
   n = tnd_out_copyflush(&s, t + 50000, d);
   CHECK(!s.cc_on && n == 0, "COPY with no copy cursor: nothing (the MOS only beeps)");

   /* Not synced: no mark at all. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "abc", out);
   tnd_out_copykey(&s, 143);
   CHECK(tnd_out_copyflush(&s, t + 500000, d) == 0, "with the cursor position unknown there is no mark");

   /* A cell the model has not seen is never marked (it could be anything). */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x1f\x05\x05" "x", out);               /* TAB syncs; the rest of the screen is unknown */
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 143);
   tnd_out_copykey(&s, 143);
   n = tnd_out_copyflush(&s, t + 60000, d);
   CHECK(n == 0, "an unseen cell is not marked");
}

/* A copy cursor key, applied at once (the model only; whatever is drawn is not looked at). */
static void cc_key(tnd_out_t *s, uint8_t k)
{
   uint8_t cb[TND_COPY_MAX];
   tnd_out_copykey(s, k);
   (void)tnd_out_copyflush(s, 100000000u, cb);
}

static void test_session(void)
{
   tnd_out_t s;
   char out[2048];
   uint8_t d[TND_REPAINT_MAX];

   /* Is a line on the screen? */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c Telnet\r\n>", out);
   CHECK(tnd_out_has_line(&s, " Telnet", 7u) && !tnd_out_has_line(&s, "Telnet", 6u) && !tnd_out_has_line(&s, "Acorn", 5u),
         "a row is found only when it is exactly that text");

   /* The rows are the Beeb's no longer: relative moves only, and a clear before the first absolute one. */
   tnd_out_reset(&s, true);
   tnd_out_assume_mode(&s, 7u);
   FEED_OUT(&s, "\x0c", out);
   tnd_out_origin_lost(&s);
   FEED_OUT(&s, "0123456789012345678901234567890123456789ab", out);
   CHECK(strstr(out, "\x1b[") == NULL && strstr(out, "0123456789012345678901234567890123456789\r\nab") != NULL,
         "a 40-column line is wrapped by hand: CR LF, no absolute position"); if (strstr(out, "\x1b[")) printf("    got [%s]\n", out);
   FEED_OUT(&s, "\x1f\x05\x03" "T", out);
   CHECK(strcmp(out, "\x1b[2J\x1b[4;6HT") == 0, "the first TAB clears once and positions"); if (strcmp(out, "\x1b[2J\x1b[4;6HT")) printf("    got [%s]\n", out);
   FEED_OUT(&s, "\x1f\x01\x01" "U", out);
   CHECK(strcmp(out, "\x1b[2;2HU") == 0, "... and not again");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c", out);
   tnd_out_origin_lost(&s);
   FEED_OUT(&s, "\x0c", out);
   FEED_OUT(&s, "\x1f\x02\x02" "V", out);
   CHECK(strcmp(out, "\x1b[3;3HV") == 0, "a CLS puts the rows right: no extra clear");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c", out);
   tnd_out_origin_lost(&s);
   FEED_OUT(&s, "\x1f\x00\x02" "AB\r\n" "CD", out);
   tnd_out_origin_lost(&s);
   tnd_out_copykey(&s, 143);
   {
      uint8_t cb[TND_COPY_MAX + 1];
      size_t cn = tnd_out_copyflush(&s, 100000000u, cb);
      cb[cn] = 0;
      CHECK(strncmp((char *)cb, "\x1b[0m\x1b[2J", 8) == 0 && strstr((char *)cb, "\x1b[7m") == NULL && s.origin_ok && s.dirty,
            "T-11: a copy key under the greeting: the terminal is cleared and the rows put to be drawn again, no mark yet");
      if (strncmp((char *)cb, "\x1b[0m\x1b[2J", 8)) printf("    got [%s]\n", cb);
      CHECK(s.npend == 1u && tnd_out_copyflush(&s, 100000000u, cb) == 0u, "... the key kept while the rows are drawn");
      out[0] = 0;
      for (int i = 0; i < 64 && s.dirty; i++) {
         size_t dn = tnd_out_dirty_row(&s, d);
         d[dn] = 0;
         strcat(out, (char *)d);
      }
      CHECK(!s.dirty && strstr(out, "AB") != NULL && strstr(out, "CD") != NULL, "... the screen drawn again from the model");
      cn = tnd_out_copyflush(&s, 100000000u, cb);
      cb[cn] = 0;
      CHECK(strstr((char *)cb, "\x1b[4;3H") != NULL && strstr((char *)cb, "\x1b[7m") != NULL && s.hl_on && s.hly == 3u
            && strcmp((char *)cb + cn - 6, "\x1b[3;3H") == 0,
            "... then the block, and the cursor one row up from it"); if (strcmp((char *)cb + cn - 6, "\x1b[3;3H")) printf("    got [%s]\n", cb);
   }

   /* The copy cursor wraps as the MOS's does (OS 1.20 &D8F0, &CD3F): inside the text window,
      off the top to the bottom row, off the bottom to the top, off a side to the other side of
      the row above or below. */
   tnd_out_reset(&s, true);
   tnd_out_assume_mode(&s, 7u);
   FEED_OUT(&s, "\x0c" "TOP\x1f\x00\x18" "BOTTOM\x1f\x00\x00>", out);   /* the prompt on row 0 */
   cc_key(&s, 143u);
   CHECK(s.ccx == 1u && s.ccy == 24u, "up off the top: the bottom row");
   cc_key(&s, 142u);
   CHECK(s.ccy == 0u, "down off the bottom: the top row");
   cc_key(&s, 140u);
   cc_key(&s, 140u);
   CHECK(s.ccx == 39u && s.ccy == 24u, "left off row 0's first column: the last column of the bottom row");
   cc_key(&s, 141u);
   CHECK(s.ccx == 0u && s.ccy == 0u, "right off the last cell: the first of the top row");
   cc_key(&s, 139u);
   CHECK(s.ccx == 1u && s.ccy == 0u, "COPY moves on one");
   tnd_out_reset(&s, true);
   tnd_out_assume_mode(&s, 7u);
   FEED_OUT(&s, "\x0c\x1c\x05\x14\x1e\x0a" "x", out);     /* VDU 28,5,20,30,10: rows 10-20, columns 5-30 */
   cc_key(&s, 143u);
   CHECK(s.ccy == 20u, "inside a text window: up off its top row goes to its bottom row");
   s.ccx = 5u;
   cc_key(&s, 140u);
   CHECK(s.ccx == 30u && s.ccy == 19u, "... and left off its left edge to its right edge, a row up");

   /* A mark belongs to a terminal: a new one starts without. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c" ">HI\r\n>", out);
   tnd_out_touch(&s, 100u);
   tnd_out_copykey(&s, 143);
   (void)tnd_out_copyflush(&s, 100000u, d);
   CHECK(s.hl_on && s.parked, "the copy cursor is shown");
   tnd_out_session(&s);
   CHECK(!s.hl_on && !s.cc_on && !s.parked && s.npend == 0, "a new session starts with no mark");

   /* ... but the Beeb's colours go on, and the new terminal is told them. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01\x11\x03x", out);
   tnd_out_session(&s);
   {
      uint8_t cb[16];
      size_t cn = tnd_out_colours(&s, cb);
      cb[cn] = 0;
      CHECK(strcmp((char *)cb, "\x1b[0m\x1b[37m") == 0, "a new terminal is brought to COLOUR 3, which is white in MODE 1's own palette");
   }

   /* The palette: logical colours are not the terminal's colours outside MODE 7. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01\x11\x02x", out);
   CHECK(strstr(out, "\x1b[33mx") != NULL, "MODE 1: COLOUR 2 is yellow");
   FEED_OUT(&s, "\x13\x02\x02\x00\x00\x00y", out);     /* VDU 19,2,2: logical 2 is now green */
   CHECK(strstr(out, "\x1b[32m") != NULL && out[strlen(out) - 1] == 'y', "VDU 19 changes what a logical colour shows as, and the colour already set follows"); if (!strstr(out, "\x1b[32m")) printf("    got [%s]\n", out);
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x00\x11\x01x", out);
   CHECK(strstr(out, "\x1b[37mx") != NULL, "a two-colour mode: COLOUR 1 is white");
   FEED_OUT(&s, "\x11\x81z", out);
   CHECK(strstr(out, "\x1b[47mz") != NULL, "... and 129 is a white background");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x11\x03x", out);
   CHECK(strstr(out, "\x1b[33m") == NULL && out[strlen(out) - 1] == 'x', "MODE 7: COLOUR does nothing, as on the Beeb"); if (strstr(out, "\x1b[33m")) printf("    got [%s]\n", out);

   /* The Beeb's cursor read from the MOS: followed from there, but nothing is known to be on the screen. */
   tnd_out_reset(&s, true);
   tnd_out_assume_mode(&s, 3u);
   tnd_out_at(&s, 5u, 24u);
   FEED_OUT(&s, "x\n", out);
   CHECK(strstr(out, "\x1b[1;25r\x1b[25;1H\x1b" "D\x1b[r") != NULL, "from a known cursor on the last row an LF scrolls the terminal too"); if (!strstr(out, "\x1b" "D")) printf("    got [%s]\n", out);
}

/* Full review 2026-10-20: teletext colour codes only in MODE 7, and a reset ends a VDU 21 or a
   VDU sequence half collected. */
static void test_review_fixes_full(void)
{
   tnd_out_t s;
   char out[2048];
   const char *r = RENDER("\x16\x04\x81Hi");
   CHECK(strstr(r, "\x1b[31m") == NULL && strstr(r, " Hi") != NULL, "MODE 4: 0x81 is a space, not red"); if (strstr(r, "\x1b[31m")) printf("    got [%s]\n", r);
   r = RENDER("\x16\x04" "<\xc1\xe1\xff>");
   CHECK(strstr(r, "<   >") != NULL, "MODE 4: 193, 225 and 255 are user-defined characters, blank (not A, a, DEL)");
   if (strstr(r, "<   >") == NULL) printf("    got [%s]\n", r);
   r = RENDER("\x16\x07" "<\xc1>");
   CHECK(strstr(r, "<A>") != NULL, "MODE 7: 193 is still the teletext chip's A"); if (strstr(r, "<A>") == NULL) printf("    got [%s]\n", r);

   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x15", out);                    /* VDU 21, then a BREAK */
   tnd_out_assume_mode(&s, 7u);
   FEED_OUT(&s, "ok", out);
   CHECK(strstr(out, "ok") != NULL, "a reset ends VDU 21: what is printed after it shows"); if (!strstr(out, "ok")) printf("    got [%s]\n", out);

   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x1f\x05", out);                /* VDU 31 with one of its two parameters, then a BREAK */
   tnd_out_assume_mode(&s, 7u);
   FEED_OUT(&s, "ok", out);
   CHECK(strstr(out, "ok") != NULL, "a reset ends a VDU sequence half collected"); if (!strstr(out, "ok")) printf("    got [%s]\n", out);
}

/* The second review's fixes (2026-10-21): each check failed on 4d96b12's telnetd_proto.c. */
static void test_review_fixes_2(void)
{
   tnd_in_t in;
   tnd_out_t s;
   char out[4096];
   size_t n;
   const char *r;

   /* A telnet command inside an escape sequence is read as one, and the sequence carries on. */
   tnd_in_reset(&in); in_reset();
   FEED(&in, "\x1bO\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0" "A");
   CHECK(nkeys == 1 && keys[0] == 143u, "ESC O, a NAWS, then A: the up arrow and nothing else"); if (nkeys != 1 || keys[0] != 143u) dump();
   CHECK(in.win_cols == 80u && in.win_rows == 24u, "... and the window size is taken");
   tnd_in_reset(&in); in_reset();
   FEED(&in, "\x1b[1\xff\xf1" "5~");
   CHECK(nkeys == 1 && keys[0] == 0x85u, "an IAC NOP inside ESC [ 15 ~: still f5"); if (nkeys != 1) dump();

   /* IAC SB with no IAC SE: dropped after a while, and the keys after it are keys. */
   tnd_in_reset(&in); in_reset();
   FEED(&in, "\xff\xfa\x1f\x01\x02");
   tick(&in, 3000000u);
   FEED(&in, "x");
   CHECK(nkeys == 1 && keys[0] == 'x', "an unended subnegotiation does not swallow every later key"); if (nkeys != 1) dump();

   /* A Latin-1 client's lone byte (&E9) is given once nothing follows it. */
   tnd_in_reset(&in); in_reset(); in.lit_ok = true;
   FEED(&in, "\xe9");
   tick(&in, 200000u);
   CHECK(nkeys == 2 && keys[0] == TND_KEY_LIT && keys[1] == 0xE9u, "a lone &E9 reaches the Beeb without another key"); if (nkeys != 2) dump();

   /* An agreed option taken back is acknowledged; a refusal of the offer is not answered. */
   tnd_in_reset(&in); in_reset();
   FEED(&in, "\xff\xfe\x01");
   CHECK(nreply == 0, "DONT ECHO as the answer to WILL ECHO: no reply");
   FEED(&in, "\xff\xfd\x01");
   CHECK(nreply == 3 && memcmp(reply, "\xff\xfb\x01", 3) == 0, "DO ECHO after the refusal: a new request, WILL ECHO (RFC 1143)");
   in_reset();
   FEED(&in, "\xff\xfd\x01");
   CHECK(nreply == 0, "DO ECHO again: agreed, no reply");
   FEED(&in, "\xff\xfe\x01");
   CHECK(nreply == 3 && memcmp(reply, "\xff\xfc\x01", 3) == 0, "DONT ECHO after DO ECHO: WONT ECHO");
   in_reset();
   FEED(&in, "\xff\xfb\x03\xff\xfc\x03");
   CHECK(nreply == 3 && memcmp(reply, "\xff\xfe\x03", 3) == 0, "WONT SGA after WILL SGA: DONT SGA");

   /* VDU 21 still counts parameters: a 6 among them does not end it. */
   r = RENDER("\x15\x1f\x06\x0a" "hi" "\x06" "b");
   CHECK(strcmp(r, "b") == 0, "VDU 21,31,6,10 hides the TAB's parameters and the text after it"); if (strcmp(r, "b")) printf("    got [%s]\n", r);

   /* VDU 20: the default colours. */
   r = RENDER("\x16\x01\x11\x01" "x" "\x14" "y");
   CHECK(strstr(r, "x\x1b[0my") != NULL, "VDU 20 puts the terminal's colours back"); if (!strstr(r, "x\x1b[0my")) printf("    got [%s]\n", r);
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x04", out);
   CHECK(s.fg == 1u, "MODE 4: the text colour is logical 1, the highest there"); if (s.fg != 1u) printf("    got %u\n", s.fg);

   /* A read that agrees with the model but has another cursor: the cursor is taken. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "HI\r\n\x11\x01YO", out);
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "\x1a\x0c" "\x1f\x00\x00" "H" "\x1f\x01\x00" "I" "\x1f\x00\x01" "Y" "\x1f\x01\x01" "O"
                    "\x1c\x00\x1f\x27\x00" "\x1f\x05\x03", out);
   CHECK(n != 0u && s.cx == 5u && s.cy == 3u, "a read that agrees but moved the cursor: the cursor is the Beeb's"); if (s.cx != 5u || s.cy != 3u) printf("    got %u,%u\n", s.cx, s.cy);
   CHECK(s.ch[1][0] == 'Y' && (s.at[1][0] & 0x40u) == 0u, "... and the red YO keeps its colour");

   /* VDU 8 in the window's top left corner: the window scrolls down, the cursor to the row's end. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "A\r\x08", out);
   CHECK(s.cx == 39u && s.cy == 0u && s.ch[1][0] == 'A', "VDU 8 at the top left scrolls down"); if (s.cx != 39u) printf("    got %u,%u [%c]\n", s.cx, s.cy, s.ch[1][0]);

   /* A redraw in MODE 7 sends line attributes for the 25 rows only. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07", out);
   {
      uint8_t d[TND_COPY_MAX];
      bool clean = true;
      tnd_out_redraw(&s, d);
      for (unsigned y = 25u; y < TND_ROWS_MAX; y++)
         if (s.lattr[y] != 0u) clean = false;
      CHECK(clean, "a MODE 7 redraw leaves no line attribute owed below row 25");
   }

   /* A Beeb reset ends a screen read half sent. */
   tnd_out_reset(&s, true);
   tnd_out_scan_merge(&s);
   FEED_OUT(&s, "\x1a\x0c", out);
   tnd_out_beeb_reset(&s);
   CHECK(!s.smerge, "a reset ends a screen read");
}

/* The daemon's look ahead for a lone ESC behind a backlog (was telnetd.c esc_ahead, which always
   started from nothing: a backlog cut inside a NAWS whose size is 27, or a DCS reply's ESC \,
   read as the ESCAPE key, and every key after it was dropped). */
static bool ahead(tnd_in_t *in, const char *data, size_t len, bool *esc_end)
{
   tnd_ahead_t a;
   tnd_in_ahead_start(in, &a);
   for (size_t i = 0; i < len; i++)
      if (tnd_in_ahead_byte(&a, (uint8_t)data[i])) { *esc_end = false; return true; }
   *esc_end = tnd_in_ahead_esc_end(&a);
   return false;
}
#define AHEAD(in, lit, e) ahead(in, lit, sizeof(lit) - 1, e)

static void test_esc_ahead(void)
{
   tnd_in_t in;
   bool e;

   tnd_in_reset(&in); in_reset();
   CHECK(AHEAD(&in, "abc\x1b" "x", &e), "a lone ESC before a letter is found");
   CHECK(!AHEAD(&in, "ab\x1b[A\x1bOP", &e) && !e, "cursor and function keys are not");
   CHECK(!AHEAD(&in, "ab\x1b", &e) && e, "an ESC at the end: lone once nothing more comes");
   CHECK(!AHEAD(&in, "\xff\xfa\x1f\x00\x50\x00\x1b\xff\xf0" "a", &e) && !e, "a NAWS 27 rows high is not an ESC");

   FEED(&in, "\xff\xfa\x1f\x00\x50");              /* the backlog cut inside a NAWS: the rest is ahead */
   CHECK(!AHEAD(&in, "\x00\x1b\xff\xf0" "a", &e) && !e, "... nor when the read stopped inside it");
   tnd_in_reset(&in); in_reset();
   FEED(&in, "\x1bP>|XTerm(3");                    /* inside the terminal's DCS reply */
   CHECK(!AHEAD(&in, "79)\x1b\\" "a", &e) && !e, "a DCS reply's ESC \\ is not the ESCAPE key");
   tnd_in_reset(&in); in_reset();
   FEED(&in, "\x1b[1");
   CHECK(!AHEAD(&in, "5~a", &e), "the rest of a CSI is not");
   CHECK(AHEAD(&in, "5~\x1b" "a", &e), "but a lone ESC after it is");
   tnd_in_reset(&in); in_reset(); in.raw = true; in.notelnet = true;
   CHECK(AHEAD(&in, "a\x1b[", &e), "teletype mode: any ESC is the key");

   /* The other keys that cut through a backlog: BREAK (F12 in its three forms, IAC BRK), IAC ABORT,
      and IAC IP, a line-mode client's ESC. */
   tnd_in_reset(&in); in_reset();
   CHECK(AHEAD(&in, "ab\x1b[24~cd", &e), "F12");
   CHECK(AHEAD(&in, "ab\x1b[24;2~", &e), "SHIFT-F12");
   CHECK(AHEAD(&in, "ab\x1b[24;5~", &e), "CTRL-F12");
   CHECK(!AHEAD(&in, "ab\x1b[23~\x1b[2~\x1b[4~\x1b[24A\x1b[124~", &e) && !e, "not F11, Insert, F12's neighbours");
   CHECK(AHEAD(&in, "ab\xff\xf3" "cd", &e), "IAC BRK");
   CHECK(AHEAD(&in, "ab\xff\xee" "cd", &e), "IAC ABORT");
   CHECK(AHEAD(&in, "ab\xff\xf4" "x", &e), "IAC IP then a letter: ESCAPE");
   CHECK(!AHEAD(&in, "ab\xff\xf4\xff\xfd\x06[6~", &e) && !e, "IP, DO TIMING-MARK, [6~: Page Down, not ESCAPE");
   CHECK(AHEAD(&in, "ab\xff\xf4\xff\xfd\x06[24~", &e), "IP, DO TIMING-MARK, [24~: F12");
   CHECK(!AHEAD(&in, "ab\xff\xf4", &e) && e, "IP at the end: a lone ESC once nothing more comes");
   tnd_in_reset(&in); in_reset(); in.raw = true;
   CHECK(AHEAD(&in, "a\xff\xf4", &e), "teletype mode: IP is the key");
}

/* More addresses than the table holds cannot push a lockout out and get fresh tries. */
static void test_login_many_addrs(void)
{
   tnd_login_t l;
   uint32_t t = 1000u;
   tnd_login_reset(&l);
   tnd_login_tick(&l, t);
   for (uint32_t a = 1u; a <= TND_LOGIN_ADDRS; a++) {     /* every slot locked out */
      tnd_login_fail(&l, a); tnd_login_fail(&l, a);
      CHECK(tnd_login_fail(&l, a), "address %u locked", (unsigned)a);
      tnd_login_tick(&l, t += TND_HOLD_US);
   }
   tnd_login_fail(&l, 100u);                               /* a 9th, 10th ... address */
   tnd_login_fail(&l, 101u);
   CHECK(tnd_login_fail(&l, 102u), "the addresses beyond the table share one count: the third failure locks them");
   CHECK(tnd_login_locked(&l, 103u), "... and a new address is refused while it lasts");
   bool kept = true;
   for (uint32_t a = 1u; a <= TND_LOGIN_ADDRS; a++)
      if (!tnd_login_locked(&l, a)) kept = false;
   CHECK(kept, "no lockout was pushed out to make room");
   tnd_login_tick(&l, t += TND_LOCK_US);
   CHECK(!tnd_login_locked(&l, 103u), "once the locks run out a new address may try");
}

static void test_output_vdu21(void)
{
   tnd_out_t s; tnd_out_reset(&s, true);
   static const char text[] = "a\x15" "hidden\x1f\x01\x02\x0c" "more\x06" "b";
   const char *r = render(text, sizeof text - 1, true, &s);
   CHECK(strcmp(r, "ab") == 0, "VDU 21 hides everything, including codes, until VDU 6"); if (strcmp(r, "ab")) printf("    got [%s]\n", r);
   r = render("c", 1, true, &s);
   CHECK(strcmp(r, "c") == 0, "and output resumes");
}

/* MODE 7 once the cursor is known: every cell drawn as the SAA5050 draws it. */
static void ttx_feed(tnd_out_t *s, bool utf8, const char *data, size_t len, char *out, size_t cap)
{
   tnd_out_reset(s, utf8);
   feed_out(s, "\x16\x07", 2, out, cap);
   feed_out(s, data, len, out, cap);
}
#define TTX(lit) ttx_feed(&s, true, lit, sizeof(lit) - 1, out, sizeof out)
#define TTX_ASCII(lit) ttx_feed(&s, false, lit, sizeof(lit) - 1, out, sizeof out)

static void test_output_teletext_chip(void)
{
   tnd_out_t s;
   char out[4096];
   size_t n;

   TTX("\x97\xff");
   CHECK(strstr(out, "\xe2\x96\x88") != NULL, "MODE 7 graphics: &FF (all six cells) is a full block"); if (!strstr(out, "\xe2\x96\x88")) printf("    got [%s]\n", out);
   TTX("\x94" "5");
   CHECK(strstr(out, "\x1b[0;34m\xe2\x96\x8c") != NULL, "graphics blue '5' (the left column) is a blue left half block"); if (!strstr(out, "\x1b[0;34m\xe2\x96\x8c")) printf("    got [%s]\n", out);
   TTX("\x97" "j");
   CHECK(strstr(out, "\xe2\x96\x90") != NULL, "'j' (the right column) is the right half block");
   TTX("\x97!");
   CHECK(strstr(out, "\xf0\x9f\xac\x80") != NULL, "'!' (the top left cell) is the first sextant, U+1FB00"); if (!strstr(out, "\xf0\x9f\xac\x80")) printf("    got [%s]\n", out);
   TTX("\x97" "A");
   CHECK(out[strlen(out) - 1] == 'A', "capitals blast through in graphics");
   TTX("\x97\x9a!\xff");
   CHECK(strstr(out, "\xf0\x9c\xb9\x91" "\xf0\x9c\xba\x8f") != NULL,
         "separated graphics: '!' is U+1CE51, &FF U+1CE8F (Unicode 16's separated sextants)");
   if (!strstr(out, "\xf0\x9c\xb9\x91")) printf("    got [%s]\n", out);
   TTX("\x97\x9a!\x99!");
   CHECK(strstr(out, "\xf0\x9c\xb9\x91") != NULL && strstr(out, "\xf0\x9f\xac\x80") != NULL,
         "contiguous again after &99");
   tnd_out_reset(&s, true);
   s.sep_glyphs = false;
   feed_out(&s, "\x16\x07", 2, out, sizeof out);
   feed_out(&s, "\x97\x9a!", 3, out, sizeof out);
   CHECK(strstr(out, "\xf0\x9f\xac\x80") != NULL, "telnetd_separated=0: separated graphics as contiguous sextants");

   TTX("`#_{}~[]^\\|");
   CHECK(strstr(out, "\xc2\xa3#\xe2\x80\x95\xc2\xbc\xc2\xbe\xc3\xb7\xe2\x86\x90\xe2\x86\x92\xe2\x86\x91\xc2\xbd\xe2\x80\x96") != NULL,
         "the SAA5050's own characters: pound # dash 1/4 3/4 divide left right up 1/2 double bar"); if (!strstr(out, "\xc2\xa3#")) printf("    got [%s]\n", out);

   TTX("\x81\x9d\x87X");
   CHECK(strstr(out, "\x1b[0;37;41m") != NULL && out[strlen(out) - 1] == 'X', "new background: white X on red (the row after the code is red)"); if (!strstr(out, "\x1b[0;37;41m")) printf("    got [%s]\n", out);
   TTX("\x88X");
   CHECK(strstr(out, "\x1b[0;37;5mX") != NULL, "flash is the terminal's blink"); if (!strstr(out, "\x1b[0;37;5mX")) printf("    got [%s]\n", out);
   TTX("\x98X");
   CHECK(strchr(out, 'X') == NULL, "conceal hides the text");

   TTX(" ABC\x1f\x00\x00\x82");
   CHECK(strstr(out, "\x1b[0;32mABC") != NULL, "a colour code put in front of text colours the text after it"); if (!strstr(out, "\x1b[0;32mABC")) printf("    got [%s]\n", out);
   CHECK(strstr(out, "\r\x1b[1C") != NULL, "... and the cursor goes back to the cell after the code");

   TTX("\x97\x9e\xff\x93X");
   {
      unsigned blocks = 0;
      for (const char *p = out; (p = strstr(p, "\xe2\x96\x88")) != NULL; p += 3)
         blocks++;
      CHECK(blocks == 2, "hold graphics: the control code after a mosaic shows the mosaic again (%u blocks)", blocks);
   }

   TTX("\x8d" "AB");
   CHECK(strstr(out, "\x1b#3\x1b[1;1H AB") != NULL, "the double height code's own cell stays a space: the line attribute goes first"); if (!strstr(out, "\x1b#3\x1b[1;1H AB")) printf("    got [%s]\n", out);
   TTX("\x8d" "AB\r\n\x8d" "AB");
   CHECK(strstr(out, "\x1b[1;1H\x1b#3") != NULL && strstr(out, "\x1b[2;1H\x1b#4") != NULL,
         "double height: the first row is the top half, the next the bottom"); if (!strstr(out, "\x1b#4")) printf("    got [%s]\n", out);
   feed_out(&s, "\x0c", 1, out, sizeof out);
   CHECK(strstr(out, "\x1b#5") != NULL && strstr(out, "\x1b[2J") != NULL, "a CLS puts the rows back to single height");
   TTX("\x8d" "AB\x1f\x00\x00 ");
   CHECK(strstr(out, "\x1b#5") != NULL, "a double height code overwritten: the row goes back to single height"); if (!strstr(out, "\x1b#5")) printf("    got [%s]\n", out);

   TTX("AB\x7f");
   CHECK(strstr(out, "\b \r\x1b[1C") != NULL, "DELETE draws the cell as a space and the cursor stays on it"); if (!strstr(out, "\b \r\x1b[1C")) printf("    got [%s]\n", out);

   TTX_ASCII("`");
   CHECK(strchr(out, '\xa3') != NULL, "no UTF-8: the pound is Latin-1");
   TTX_ASCII("\x97!");
   CHECK(out[strlen(out) - 1] == '#', "no UTF-8: a mosaic is a #");

   /* Anything at all, in MODE 7 with the cursor known: the output bound holds. */
   tnd_out_reset(&s, true);
   feed_out(&s, "\x16\x07", 2, out, sizeof out);
   {
      uint32_t x = 12345u;
      size_t   worst = 0u;
      for (unsigned i = 0; i < 200000u; i++) {
         uint8_t b[TND_OUT_MAX];
         x = x * 1103515245u + 12345u;
         uint8_t c = (uint8_t)(x >> 16);
         if (c == 22u || c == 12u) c = 0x8D;      /* fewer clears: the rows fill up */
         n = tnd_out_byte(&s, c, b);
         if (n > worst) worst = n;
         if (n > TND_OUT_MAX) break;
      }
      CHECK(worst <= TND_OUT_MAX, "MODE 7 noise: no byte's output exceeds TND_OUT_MAX (worst %u)", (unsigned)worst);
   }
}

/* Graphics in xterm's Tektronix 4014 window, once the terminal has said it is xterm. */
static void test_tek(void)
{
   tnd_out_t s;
   char out[4096];
   tnd_in_t in;
   uint8_t keys[TND_IN_KEYS], rep[TND_IN_REPLY];
   size_t replen, nk = 0;

   /* MOVE 0,0 : DRAW 1279,1023 : then text */
   static const char draw[] = "\x16\x04" "\x19\x04\x00\x00\x00\x00" "\x19\x05\xff\x04\xff\x03" "A";
   tnd_out_reset(&s, true);
   feed_out(&s, draw, sizeof draw - 1, out, sizeof out);
   CHECK(strstr(out, "\x1b[?38h") == NULL && strchr(out, 0x1d) == NULL, "graphics are swallowed when the terminal is not xterm");
   tnd_out_reset(&s, true);
   tnd_out_tek(&s, true);
   feed_out(&s, draw, sizeof draw - 1, out, sizeof out);
   CHECK(strstr(out, "\x1b[?38h\x1d" "\x20\x60\x20\x40" "\x38\x6b\x3f\x5f") != NULL,
         "MOVE 0,0 DRAW 1279,1023: the Tek window, one vector corner to corner (0,0 to 1023,779)");
   if (!strstr(out, "\x1b[?38h\x1d")) printf("    got [%s]\n", out);
   CHECK(strstr(out, "\x1b\x03" "A") != NULL, "text afterwards goes back to the text screen");
   CHECK(strstr(out, "\x3f\x5f" "\x1f\x1b\x03") != NULL,
         "... with US before ESC ETX, or xterm drops the last vector (T-19, seen in a real xterm)");

   /* PLOT 21 (dotted): the line in the tube's dotted style, and solid again after */
   static const char dot[] = "\x16\x04" "\x19\x04\x00\x00\x00\x00" "\x19\x15\xff\x04\x00\x00";
   tnd_out_reset(&s, true);
   tnd_out_tek(&s, true);
   feed_out(&s, dot, sizeof dot - 1, out, sizeof out);
   CHECK(strstr(out, "\x1b[?38h\x1b" "a\x1d" "\x20\x60\x20\x40" "\x20\x60\x3f\x5f" "\x1b`") != NULL,
         "PLOT 21: ESC a (dotted), the vector, ESC ` (solid)");

   /* relative moves follow the graphics cursor; the origin applies to absolute ones */
   static const char rel[] = "\x16\x04" "\x1d\x80\x02\x00\x02" "\x19\x04\x00\x00\x00\x00" "\x19\x01\x00\x00\x80\x00";
   tnd_out_reset(&s, true);
   tnd_out_tek(&s, true);
   feed_out(&s, rel, sizeof rel - 1, out, sizeof out);
   CHECK(s.gx == 640 && s.gy == 640, "VDU 29 sets the origin, PLOT 1 is relative to the cursor (%d,%d)", s.gx, s.gy);

   /* CLG clears the Tek page; a background-colour draw only moves */
   tnd_out_reset(&s, true);
   tnd_out_tek(&s, true);
   feed_out(&s, "\x10", 1, out, sizeof out);
   CHECK(strstr(out, "\x1b[?38h\x1b\x0c") != NULL, "CLG clears the Tek page");
   feed_out(&s, "\x19\x07\x10\x00\x10\x00", 6, out, sizeof out);
   CHECK(strchr(out, 0x1d) == NULL && s.gx == 16, "PLOT 7 (background) moves without drawing");

   /* a MODE clears it too, and the text screen comes back */
   feed_out(&s, "\x16\x07", 2, out, sizeof out);
   CHECK(strstr(out, "\x1b\x0c") != NULL && strstr(out, "\x1b\x03") != NULL && strstr(out, "\x1b[2J") != NULL,
         "MODE clears the Tek page and goes back to the text screen");

   /* the terminal's answer to CSI > q */
   tnd_in_reset(&in);
   {
      static const char reply[] = "\x1bP>|XTerm(379)\x1b\\x";
      for (size_t i = 0; i < sizeof reply - 1; i++)
         nk += tnd_in_byte(&in, (uint8_t)reply[i], 0, keys, rep, &replen);
   }
   CHECK(in.xterm && nk == 1 && keys[0] == 'x', "XTVERSION's answer from xterm is taken, not typed, and what follows is a key");
   tnd_in_reset(&in);
   {
      static const char reply[] = "\x1bP>|WezTerm 2024\x1b\\";
      for (size_t i = 0; i < sizeof reply - 1; i++)
         tnd_in_byte(&in, (uint8_t)reply[i], 0, keys, rep, &replen);
   }
   CHECK(!in.xterm, "another terminal's answer: no Tek");
   tnd_in_reset(&in);
   nk = 0;
   {
      uint8_t all[8]; size_t na = 0;
      static const char altp[] = "\x1bPa";
      for (size_t i = 0; i < sizeof altp - 1; i++) {
         size_t k = tnd_in_byte(&in, (uint8_t)altp[i], 0, keys, rep, &replen);
         for (size_t j = 0; j < k && na < sizeof all; j++) all[na++] = keys[j];
      }
      CHECK(na == 3 && all[0] == TND_KEY_ESCAPE && all[1] == 'P' && all[2] == 'a', "Alt-P is ESCAPE and P, not a DCS (%u keys)", (unsigned)na);
   }
}

static void test_output_teletext(void)
{
   const char *r;

   r = RENDER("\x81Hi");
   CHECK(strcmp(r, "\x1b[31m Hi") == 0, "0x81 (alpha red) is a red space"); if (strcmp(r, "\x1b[31m Hi")) printf("    got [%s]\n", r);
   r = RENDER("\x97X");
   CHECK(strcmp(r, "\x1b[37m X") == 0, "0x97 (graphics white) is a white space");
   r = RENDER("\x88\x89\x8c\x8d\x9f" "x");
   CHECK(strcmp(r, "     x") == 0, "other teletext controls are plain spaces");
   r = RENDER("\x82ok\r\n");
   CHECK(strcmp(r, "\x1b[32m ok\x1b[0m\r\n") == 0, "colour is reset at the end of the line"); if (strcmp(r, "\x1b[32m ok\x1b[0m\r\n")) printf("    got [%s]\n", r);
   r = RENDER("\x16\x01\x11\x01x\r\ny");
   CHECK(strcmp(r, "\x1b[2J\x1b[H\x1b[31mx\r\ny") == 0, "outside MODE 7 COLOUR carries over to the next line"); if (strcmp(r, "\x1b[2J\x1b[H\x1b[31mx\r\ny")) printf("    got [%s]\n", r);
   r = RENDER("\x11\x01x\x16\x01");
   CHECK(strcmp(r, "\x1b[31mx\x1b[0m\x1b[2J\x1b[H") == 0, "a MODE puts the colours back"); if (strcmp(r, "\x1b[31mx\x1b[0m\x1b[2J\x1b[H")) printf("    got [%s]\n", r);
   r = RENDER("\xc1\xc2");
   CHECK(strcmp(r, "AB") == 0, "from 0xA0 the chip ignores bit 7: 0xC1 shows A");
   r = RENDER("plain\r\n");
   CHECK(strcmp(r, "plain\r\n") == 0, "no colour used, no reset sent");
}

static void test_output_robustness(void)
{
   tnd_out_t s; tnd_out_reset(&s, true);
   unsigned seed = 777;
   for (unsigned i = 0; i < 200000; i++) {
      uint8_t d[TND_OUT_MAX];
      seed = seed * 1103515245u + 12345u;
      uint8_t c = (uint8_t)(seed >> 16);
      size_t n = tnd_out_byte(&s, c, d);
      CHECK(n <= TND_OUT_MAX, "output bound at %u", i);
      if (n > TND_OUT_MAX) return;
      for (size_t j = 0; j < n; j++)
         if (d[j] == 0xFF) { CHECK(0, "0xFF in the output at %u", i); return; }
   }
   CHECK(true, "fuzz ran");
}

static void test_stalled(void)
{
   CHECK(!tnd_stalled(false, 100000000u, 0u, 10000000u), "an idle session is never stalled");
   CHECK(!tnd_stalled(true, 5000000u, 0u, 10000000u), "waiting, but not for long enough");
   CHECK(tnd_stalled(true, 10000000u, 0u, 10000000u), "waiting for the limit: stalled");
   CHECK(tnd_stalled(true, 50000000u, 1000u, 10000000u), "long overdue");
   CHECK(tnd_stalled(true, 5000u, 0xFFFFF000u, 9000u), "the counter wrapped, 9.1 ms later");
   CHECK(!tnd_stalled(true, 4000u, 0xFFFFF000u, 9000u), "wrapped, and not yet");
}

/* Teletype mode joins with the Beeb's current line (its prompt) from the model. */
static void test_cursor_line(void)
{
   tnd_out_t s;
   char out[4096], cl[TND_COLS_MAX + 1];

   tnd_out_reset(&s, true);
   CHECK(tnd_out_cursor_line(&s, cl, sizeof cl) == 0u, "nothing known: no line");
   FEED_OUT(&s, "\x16\x07" "BASIC\r\n\r\n>", out);
   CHECK(tnd_out_cursor_line(&s, cl, sizeof cl) == 1u && strcmp(cl, ">") == 0, "MODE 7, the prompt: >");
   FEED_OUT(&s, "\r\nName? ", out);
   CHECK(tnd_out_cursor_line(&s, cl, sizeof cl) == 6u && strcmp(cl, "Name? ") == 0, "an INPUT prompt, up to the cursor");
   FEED_OUT(&s, "\r\n", out);
   CHECK(tnd_out_cursor_line(&s, cl, sizeof cl) == 0u, "the start of a line: nothing to show");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "\x81" ">", out);
   CHECK(tnd_out_cursor_line(&s, cl, sizeof cl) == 2u && cl[0] == ' ' && cl[1] == '>', "MODE 1: a byte above 127 shows as a space");
}

/* A new session's screen read, compared with the model (tnd_out_scan_merge). */
static void test_scan_merge(void)
{
   tnd_out_t s;
   char out[4096];
   uint8_t d[TND_REPAINT_MAX];
   size_t n;
   uint8_t at_h;

   /* The read agrees: nothing is drawn, the colours stay. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "HI\r\n\x11\x01YO", out);      /* MODE 1: HI, then YO in red */
   at_h = s.at[0][0];
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "\x1a\x0c" "\x1f\x00\x00" "H" "\x1f\x01\x00" "I" "\x1f\x00\x01" "Y" "\x1f\x01\x01" "O"
                    "\x1c\x00\x1f\x27\x00" "\x1f\x02\x01", out);
   CHECK(n == 0u, "a read that agrees with the model draws nothing"); if (n) printf("    got %u bytes\n", (unsigned)n);
   CHECK(!s.smerge && !s.rescan && !s.dirty, "... and is finished, with nothing to draw again");
   CHECK(s.ch[1][0] == 'Y' && (s.at[1][0] & 0x40u) == 0u, "... and the red YO keeps its colour");

   /* The read differs (a program changed the screen where the Pi could not see). */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "HI\r\n\x11\x01YO", out);
   at_h = s.at[0][0];
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "\x1a\x0c" "\x1f\x00\x00" "H" "\x1f\x01\x00" "I" "\x1f\x05\x03" "X"
                    "\x1c\x00\x1f\x27\x00" "\x1f\x06\x03", out);
   CHECK(strstr(out, "\x1b[2J") != NULL, "a read that differs clears the terminal");
   CHECK(s.ch[1][0] == ' ' && s.ch[1][1] == ' ' && s.ch[3][5] == 'X', "... the model takes the Beeb's characters");
   CHECK(s.ch[0][0] == 'H' && s.at[0][0] == at_h, "... the cells that agree keep what they had");
   CHECK(s.cx == 6u && s.cy == 3u, "... the cursor is the Beeb's");
   CHECK(s.dirty, "... and the screen is to be drawn again from the model");
   {
      char all[8192] = "";
      size_t k = 0u;
      while ((n = tnd_out_dirty_row(&s, d)) != 0u && k + n < sizeof all) {
         memcpy(all + k, d, n);
         k += n;
      }
      all[k] = 0;
      CHECK(strstr(all, "HI") != NULL && strstr(all, "X") != NULL && strstr(all, "YO") == NULL,
            "... which shows HI and X and no longer YO");
   }

   /* VDU 31 only where a run of cells starts; the cells after it follow on. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "HI\r\n\x11\x01YO", out);
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "\x1a\x0c" "\x1f\x00\x00" "HI" "\x1f\x00\x01" "YO" "\x1c\x00\x1f\x27\x00" "\x1f\x02\x01", out);
   CHECK(n == 0u && !s.smerge && !s.rescan, "a read with runs (VDU 31 at each run's start) that agrees draws nothing");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "HI\r\n\x11\x01YO", out);
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "\x1a\x0c" "\x1f\x00\x00" "HI" "\x1f\x03\x01" "ABC" "\x1c\x00\x1f\x27\x00" "\x1f\x06\x01", out);
   CHECK(s.ch[0][1] == 'I' && s.ch[1][0] == ' ' && s.ch[1][3] == 'A' && s.ch[1][5] == 'C' && s.cx == 6u,
         "... one that differs puts each run's cells one after another from its VDU 31");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "HI", out);
   tnd_out_scan_merge(&s);
   FEED_OUT(&s, "\x1a\x0c" "H", out);
   CHECK(!s.smerge && s.rescan, "... a character before any VDU 31 is not a read: an ordinary one is asked for");

   /* An inverse heading (COLOUR 0 on COLOUR 129): OSBYTE 135 cannot read text on a background, so
      the read has blanks there; the model's heading stands (such headings went blank). */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x00" "\x1f\x03\x02" "\x11\x00\x11\x81" "HEAD" "\x11\x01\x11\x80" "\x1f\x00\x05", out);
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "\x1a\x0c" "\x1f\x05\x08" "X" "\x1c\x00\x1f\x4f\x00" "\x1f\x06\x08", out);
   CHECK(s.ch[2][3] == 'H' && s.ch[2][6] == 'D' && (s.at[2][3] & 0x40u) == 0u,
         "a heading on a background, read as blanks, stays in the model with its colours");
   CHECK(s.ch[8][5] == 'X', "... while what the read found elsewhere is taken");

   /* Not a read at all: the program printed first. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "HI", out);
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "A", out);
   CHECK(n >= 1u && strchr(out, 'A') != NULL && !s.smerge && !s.rescan, "output that is not a read is shown as usual, and no read is asked for again");

   /* A read cut short: an ordinary one is asked for. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x01" "HI", out);
   tnd_out_scan_merge(&s);
   FEED_OUT(&s, "\x1a\x0c\x1f\x05" "Z", out);                 /* a row number of 90 */
   CHECK(!s.smerge && s.rescan, "a read cut short asks for an ordinary read");

   /* MODE 7: the read gives each character's code as printed (OSBYTE 135); # _ and the pound are
      stored swapped and from &A0 without bit 7, as printing them stores them.  Connecting showed
      a REM with e-acute (233) as a space where the Beeb shows i. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07" "#_`\xe9" "A", out);
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "\x1a\x0c" "\x1f\x00\x00" "#" "\x1f\x01\x00" "_" "\x1f\x02\x00" "`" "\x1f\x03\x00" "\xe9"
                    "\x1f\x04\x00" "A" "\x1c\x00\x18\x27\x00" "\x1f\x05\x00", out);
   CHECK(n == 0u, "MODE 7: a read of # _ pound and &E9 agrees with the model: nothing drawn");
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07", out);
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "\x1a\x0c" "\x1f\x00\x00" "\xe9" "\x1f\x01\x00" "#" "\x1c\x00\x18\x27\x00" "\x1f\x02\x00", out);
   CHECK(s.ch[0][0] == 'i' && s.ch[0][1] == 0x5Fu, "MODE 7: a read's &E9 is stored as i, its # as printing stores it");

   /* MODE 7: colour codes compared as they are stored. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07" "\x81" "RED", out);
   tnd_out_scan_merge(&s);
   n = FEED_OUT(&s, "\x1a\x0c" "\x1f\x00\x00" "\x81" "\x1f\x01\x00" "R" "\x1f\x02\x00" "E" "\x1f\x03\x00" "D"
                    "\x1c\x00\x18\x27\x00" "\x1f\x04\x00", out);
   CHECK(n == 0u, "MODE 7: a read with the same colour code and text draws nothing"); if (n) printf("    got %u bytes\n", (unsigned)n);
}

/* An ordinary screen read (tnd_out_scan_full): a character in the bottom right cell is placed,
   not printed, so nothing scrolls.  Anything else still scrolls there as the Beeb does. */
static void test_scan_full(void)
{
   tnd_out_t s;
   char out[4096];

   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07", out);
   tnd_out_scan_full(&s);
   FEED_OUT(&s, "\x1a\x0c" "\x1f\x00\x00" "A" "\x1f\x26\x18" "YZ" "\x1c\x00\x18\x27\x00" "\x1f\x00\x00", out);
   CHECK(s.ch[0][0] == 'A' && s.ch[24][38] == 'Y' && s.ch[24][39] == 'Z', "a read: the bottom right cell does not scroll");
   CHECK(strstr(out, "\x1b" "D") == NULL, "a read: the terminal is not scrolled either");
   CHECK(s.sread == 0u && s.cx == 0u && s.cy == 0u, "a read ends at its VDU 28, the cursor put back");
   FEED_OUT(&s, "\x1f\x27\x18" "Q", out);
   CHECK(s.ch[23][39] == 'Q' && s.ch[23][38] == 'Y', "after the read, the bottom right cell scrolls again");

   /* Asked for, but the program prints first: not a read, so it scrolls as before. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07", out);
   tnd_out_scan_full(&s);
   FEED_OUT(&s, "\x1f\x00\x00" "A" "\x1a\x0c" "\x1f\x27\x18" "Z", out);
   CHECK(s.ch[23][39] == 'Z' && s.sread == 0u, "output before the read's VDU 26 ends it");

   /* A control code that is not the read's ends it: the program's printing scrolls. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07", out);
   tnd_out_scan_full(&s);
   FEED_OUT(&s, "\x1a\x0c" "\r" "\x1f\x27\x18" "Z", out);
   CHECK(s.ch[23][39] == 'Z' && s.sread == 0u, "a CR in the read ends it");
}

/* The boot banners (tnd_banner_byte). */
static bool banner_feed(tnd_banner_t *b, const char *data, size_t len, bool open)
{
   bool prompt = false;
   for (size_t i = 0; i < len; i++)
      prompt |= tnd_banner_byte(b, (uint8_t)data[i], open);
   return prompt;
}
#define BANNER(b, lit, open) banner_feed(b, lit, sizeof(lit) - 1, open)

static void test_banner(void)
{
   tnd_banner_t b;
   bool prompt;

   tnd_banner_reset(&b);
   prompt = BANNER(&b, "BBC Computer 32K\r\n\r\nAcorn DFS\r\n\r\nBASIC\r\n\r\n>", true);
   b.text[b.len] = 0;
   CHECK(strcmp(b.text, "BBC Computer 32K\nAcorn DFS\nBASIC\n") == 0, "the start-up's banners are kept, a line each"); if (strcmp(b.text, "BBC Computer 32K\nAcorn DFS\nBASIC\n")) printf("    got [%s]\n", b.text);
   CHECK(prompt, "... and the prompt ends the start-up");

   tnd_banner_reset(&b);
   BANNER(&b, "LATER TEXT\r\n", false);
   CHECK(b.len == 0u, "text after the start-up is not a banner");

   tnd_banner_reset(&b);
   BANNER(&b, "\x15" "HIDDEN BANNER\r\n" "\x06", true);
   b.text[b.len] = 0;
   CHECK(strcmp(b.text, "HIDDEN BANNER\n") == 0, "a VDU 21 ... VDU 6 block just after a start is kept");
   tnd_banner_reset(&b);
   BANNER(&b, "\x15" "Acorn File Server Level 3\r\nTesting Memory\r\n" "\x06", false);
   CHECK(b.len == 0u, "a VDU 21 block later (a program's, e.g. a file server starting) is not a banner");

   /* A screen read after the start-up: VDU 31,x,y,c for cells in row 21 and column 6.  The 21 and 6
      are parameters, not VDU 21 and VDU 6: no block, nothing kept. */
   tnd_banner_reset(&b);
   BANNER(&b, "\x1a\x0c" "\x1f\x05\x15" "A" "\x1f\x06\x02" "B" "\x1f\x00\x15" "C" "TEXT\r\n" "\x1f\x06\x06" "D"
              "\x1c\x00\x1f\x27\x00" "\x1f\x00\x15" "MORE\r\n", false);
   CHECK(b.len == 0u && !b.blk, "a screen read's row 21 and column 6 are not a banner block"); if (b.len) { b.text[b.len] = 0; printf("    got [%s]\n", b.text); }

   /* VDU 23 and VDU 19 carry 21s and 6s in their parameters too. */
   tnd_banner_reset(&b);
   BANNER(&b, "\x17\x80\x15\x06\x15\x06\x00\x00\x00\x00" "\x13\x01\x15\x06\x00\x00" "AFTER\r\n", false);
   CHECK(b.len == 0u && !b.blk, "VDU 23 and VDU 19 parameters do not open a banner block");

   /* ... and a real block after them, while the banners are read, still counts. */
   BANNER(&b, "\x15" "KEPT\r\n" "\x06", true);
   b.text[b.len] = 0;
   CHECK(strcmp(b.text, "KEPT\n") == 0, "a real VDU 21 block after them is still kept");
}

/* Teletype mode (raw): the client asks with telnet BINARY; then every byte is a key as it is. */
static void test_teletype(void)
{
   tnd_in_t s;

   tnd_in_reset(&s); in_reset();
   FEED(&s, "\xff\xfd\x00");                    /* DO BINARY */
   CHECK(s.bin_out && nreply == 3 && memcmp(reply, "\xff\xfb\x00", 3) == 0, "teletype: DO BINARY is agreed (WILL BINARY)");
   in_reset();
   FEED(&s, "\xff\xfb\x00");                    /* WILL BINARY */
   CHECK(s.bin_in && nreply == 3 && memcmp(reply, "\xff\xfd\x00", 3) == 0, "teletype: WILL BINARY is agreed (DO BINARY)");
   in_reset();
   FEED(&s, "\xff\xfb\x00");
   CHECK(nreply == 0, "teletype: asked again, no answer (no negotiation loop)");

   tnd_in_reset(&s); in_reset();
   s.raw = true; s.lit_ok = true;
   FEED(&s, "A\x1b[A\x01");                    /* a cursor-key sequence is just bytes: ESC, [, A */
   CHECK(KEYS("A\x00[A\x01"), "teletype: bytes are keys as they are, ESC is the ESCAPE key"); if (!KEYS("A\x00[A\x01")) dump();
   in_reset();
   FEED(&s, "\xe9\xff\xff");                    /* e-acute (Latin-1), and IAC IAC: the byte 255 */
   CHECK(KEYS("\xfa\xe9\xfa\xff"), "teletype: bytes above 127 go behind TND_KEY_LIT, IAC IAC is 255"); if (!KEYS("\xfa\xe9\xfa\xff")) dump();
   in_reset();
   {
      static const uint8_t nul[1] = { 0 };
      feed(&s, nul, 1);
   }
   CHECK(nkeys == 2 && keys[0] == 0xFA && keys[1] == 0, "teletype: NUL is a byte (behind LIT), not ESCAPE");
   in_reset();
   FEED(&s, "\r\n\r");
   {
      static const uint8_t z[1] = { 0 };
      feed(&s, z, 1);
   }
   CHECK(KEYS("\r\r"), "teletype: telnet's CR LF and CR NUL are one RETURN each"); if (!KEYS("\r\r")) dump();
   in_reset();
   s.bin_in = true;
   FEED(&s, "\r\n");
   CHECK(KEYS("\r\n"), "teletype, binary: CR and LF are both bytes"); if (!KEYS("\r\n")) dump();
   in_reset();
   s.lit_ok = false;
   FEED(&s, "x\xe9y");
   CHECK(KEYS("xy"), "teletype: without the ROM's LITKEY a byte above 127 is dropped"); if (!KEYS("xy")) dump();

   tnd_in_reset(&s); in_reset();                /* a raw TCP port: not even IAC */
   s.raw = true; s.notelnet = true; s.lit_ok = true;
   FEED(&s, "\xff\xfd\x00\r\n");
   CHECK(nreply == 0 && nkeys == 8, "teletype, raw port: IAC is a byte like any other, no answer (%u keys)", (unsigned)nkeys);
   CHECK(keys[0] == 0xFA && keys[1] == 0xFF && keys[2] == 0xFA && keys[3] == 0xFD && keys[4] == 0xFA && keys[5] == 0x00
         && keys[6] == '\r' && keys[7] == '\n', "teletype, raw port: ... behind LIT, NUL too, CR and LF as they are");
   if (nkeys != 8) dump();
}

/* telnetd_font=bbc: each MODE in its own shape in an 80-column terminal, a Beeb character as 1, 2 or 4 of
   the BBC Micro MOS font's private-use pieces. */
static void test_bbcfont(void)
{
   tnd_out_t s;
   char out[4096];

#define BBC(mode, lit) (tnd_out_reset(&s, true), s.bbcfont = true, feed_out(&s, mode, 2, out, sizeof out), \
                        feed_out(&s, lit, sizeof(lit) - 1, out, sizeof out))
   BBC("\x16\x00", "A");
   CHECK(strchr(out, 'A') != NULL && strchr(out, '\xee') == NULL, "MODE 0: plain characters");
   BBC("\x16\x01", "A");
   CHECK(strstr(out, "\xee\xa6\x82\xee\xa6\x83") != NULL, "MODE 1: 'A' is its two halves, U+E982 U+E983");
   if (!strstr(out, "\xee\xa6\x82")) printf("    got [%s]\n", out);
   BBC("\x16\x01", "\x1f\x05\x03");
   CHECK(strstr(out, "\x1b[4;11H") != NULL, "MODE 1: TAB(5,3) is the terminal's column 11");
   BBC("\x16\x02", "A");
   CHECK(strstr(out, "\xee\x88\x84\xee\x88\x85\xee\x88\x86\xee\x88\x87") != NULL, "MODE 2: 'A' is its four quarters, U+E204-E207");
   BBC("\x16\x01", "AB\x7f");
   CHECK(strstr(out, "\x08\x08\xee\xa5\x80\xee\xa5\x81\x08\x08") != NULL, "MODE 1: DELETE is two cells back, a blank of two halves, back");

   /* Characters a program defines (VDU 23): 128-255 blank until defined, never teletext colours, and a
      defined one drawn as blocks of its bitmap. */
#define PLN(mode, lit) (tnd_out_reset(&s, true), feed_out(&s, mode, 2, out, sizeof out), \
                        feed_out(&s, lit, sizeof(lit) - 1, out, sizeof out))
   PLN("\x16\x01", "\x81" "AB");
   CHECK(strstr(out, "\x1b[31m") == NULL && strstr(out, " AB") != NULL, "MODE 1: CHR$129 is a blank character, no red");
   PLN("\x16\x01", "\xc1");
   CHECK(strchr(out, 'A') == NULL, "MODE 1: CHR$193 undefined is blank, not an A");
   static const char top[] = "\x17\xe0\xff\xff\xff\xff" "\x00\x00\x00\x00" "\xe0";   /* the top half lit */
   PLN("\x16\x00", top);
   CHECK(strstr(out, "\xe2\x96\x80") != NULL, "MODE 0: a defined character's top half is U+2580");
   BBC("\x16\x00", top);
   CHECK(strstr(out, "\xee\xa8\x8f") != NULL, "MODE 0, BBC font: its top half is blocks 0-3, U+EA0F");
   BBC("\x16\x01", top);
   CHECK(strstr(out, "\xee\xa8\x8f\xee\xa8\x8f") != NULL, "MODE 1, BBC font: two cells of U+EA0F");
   static const char line[] = "\x17\xe1\x80\x80\x80\x80\x80\x80\x80\x80" "\xe1";   /* one dot wide, at the left */
   BBC("\x16\x00", line);
   CHECK(strstr(out, "\xee\xa9\x95") != NULL, "MODE 0, BBC font: a line one dot wide still shows (U+EA55)");
   BBC("\x16\x02", line);
   CHECK(strstr(out, "\xee\xa9\x95\xee\xa8\x80\xee\xa8\x80\xee\xa8\x80") != NULL, "MODE 2, BBC font: in the first of four cells only");
#undef PLN
   BBC("\x16\x07", "A");
   CHECK(strstr(out, "\xee\x8e\x82\xee\x8e\x83") != NULL, "MODE 7: 'A' is the teletext font's two halves, U+E382 U+E383");
   BBC("\x16\x07", "\x8d" "A\r\n\x8d" "A");
   CHECK(strstr(out, "\xee\x96\x82") != NULL && strstr(out, "\xee\x9e\x82") != NULL,
         "MODE 7 double height: the top halves (U+E582) on the first row, the bottom (U+E782) on the second");
   CHECK(strstr(out, "\x1b#3") == NULL && strstr(out, "\x1b#4") == NULL, "MODE 7 double height: no DECDHL, so no double width");
   BBC("\x16\x07", "\x97\x9a!");
   CHECK(strstr(out, "\xee\x92\x82") != NULL, "MODE 7: a separated mosaic is cell 193, U+E482");
#undef BBC
}

static void test_mode_decision(void)
{
   const uint32_t t0 = 5000000u;
   tnd_in_t s;

   tnd_in_reset(&s); in_reset();
   CHECK(tnd_decide(&s, TND_SET_AUTO, t0, t0) == TND_MODE_UNDECIDED, "nothing yet: undecided");
   CHECK(tnd_decide(&s, TND_SET_AUTO, t0 + TND_DECIDE_US - 1u, t0) == TND_MODE_UNDECIDED, "just inside the window");
   CHECK(tnd_decide(&s, TND_SET_AUTO, t0 + TND_DECIDE_US, t0) == TND_MODE_LINE, "no answer in the window: line (nc)");
   CHECK(tnd_decide(&s, TND_SET_AUTO, 100u, 0xFFFFFF00u) == TND_MODE_UNDECIDED, "the clock wrapped, 356 us in");
   CHECK(tnd_decide(&s, TND_SET_AUTO, TND_DECIDE_US, 0xFFFFFF00u) == TND_MODE_LINE, "the clock wrapped, past the window");
   CHECK(tnd_decide(&s, TND_SET_SCREEN, t0, t0) == TND_MODE_SCREEN, "the setting: screen");
   CHECK(tnd_decide(&s, TND_SET_LINE, t0, t0) == TND_MODE_LINE, "the setting: line");
   CHECK(!tnd_ga_wanted(&s), "nothing said: no GA");

   /* A telnet client: any answer to the greeting. */
   tnd_in_reset(&s); in_reset();
   FEED(&s, "\xff\xfd\x01\xff\xfd\x03\xff\xfb\x03");
   CHECK(tnd_decide(&s, TND_SET_AUTO, t0, t0) == TND_MODE_SCREEN, "DO ECHO, DO SGA: screen");
   CHECK(tnd_decide(&s, TND_SET_AUTO, t0 + 10u * TND_DECIDE_US, t0) == TND_MODE_SCREEN, "... and stays so");
   CHECK(tnd_decide(&s, TND_SET_LINE, t0, t0) == TND_MODE_LINE, "the setting still wins");
   CHECK(s.telnet && s.sga_do && !tnd_ga_wanted(&s), "SGA agreed: no GA");
   FEED(&s, "PRINT\r");
   CHECK(tnd_decide(&s, TND_SET_AUTO, t0, t0) == TND_MODE_SCREEN, "typing does not change a terminal");

   /* A telnet client that refuses the echo (Linux telnet's "mode line" at the start) is still a terminal. */
   tnd_in_reset(&s); in_reset();
   FEED(&s, "\xff\xfe\x01\xff\xfe\x03\xff\xfc\x03");
   CHECK(tnd_decide(&s, TND_SET_AUTO, t0, t0) == TND_MODE_SCREEN, "DONT ECHO, DONT SGA: screen (its own line mode)");
   CHECK(tnd_ga_wanted(&s), "it speaks telnet and did not agree SGA: GA wanted");

   /* A raw client: its first bytes are data. */
   tnd_in_reset(&s); in_reset();
   FEED(&s, "PRINT 2+2\n");
   CHECK(KEYS("PRINT 2+2\r"), "nc's line: keys, LF a RETURN");
   CHECK(tnd_decide(&s, TND_SET_AUTO, t0, t0) == TND_MODE_LINE, "data before any answer: line at once");
   CHECK(!s.telnet && !tnd_ga_wanted(&s), "a raw client: no GA (it would be junk)");

   /* Line mode by the setting: the server will not echo. */
   tnd_in_reset(&s); in_reset();
   s.refuse_echo = true;
   FEED(&s, "\xff\xfd\x01");
   static const uint8_t wont1[] = { 255, 252, 1 };
   CHECK(nreply == 3 && memcmp(reply, wont1, 3) == 0, "forced line mode: DO ECHO is refused"); if (nreply != 3) dump();
   in_reset();
   FEED(&s, "\xff\xfd\x01");
   CHECK(nreply == 0, "... once");
   CHECK(tnd_decide(&s, TND_SET_LINE, t0, t0) == TND_MODE_LINE, "the setting holds");

   /* An IAC IAC is data (a literal 0xFF), not a sign of telnet; any command is. */
   tnd_in_reset(&s); in_reset();
   FEED(&s, "\xff\xff");
   CHECK(!s.telnet && s.data, "IAC IAC: data, not telnet");
   tnd_in_reset(&s); in_reset();
   FEED(&s, "\xff\xf1");
   CHECK(s.telnet && !s.data, "IAC NOP: telnet, not data");
   CHECK(tnd_decide(&s, TND_SET_AUTO, t0, t0) == TND_MODE_SCREEN, "a NOP: a telnet client");
   tnd_in_reset(&s); in_reset();
   FEED(&s, "\xff\xfa\x18\x00xterm\xff\xf0");
   CHECK(s.telnet && !s.data, "a subnegotiation is not data");
}

/* The line translator, fed a byte at a time; keys typed first. */
static uint8_t lout[1 << 16]; static size_t nlout;
static uint32_t lnow;

static void lfeed(tnd_line_t *s, const void *data, size_t len)
{
   const uint8_t *p = data;
   for (size_t i = 0; i < len; i++) {
      uint8_t d[TND_LINE_OUT_MAX];
      size_t n = tnd_line_beeb(s, p[i], lnow, d);
      CHECK(n <= TND_LINE_OUT_MAX, "line output bound");
      memcpy(lout + nlout, d, n); nlout += n;
      lnow += 100u;
   }
}
#define LFEED(s, lit) lfeed(s, lit, sizeof(lit) - 1)

static void ltype(tnd_line_t *s, const void *data, size_t len)
{
   const uint8_t *p = data;
   for (size_t i = 0; i < len; i++)
      tnd_line_typed(s, p[i], lnow);
}
#define LTYPE(s, lit) ltype(s, lit, sizeof(lit) - 1)

static void ltick(tnd_line_t *s, uint32_t advance)
{
   uint8_t d[TND_LINE_OUT_MAX];
   lnow += advance;
   size_t n = tnd_line_tick(s, lnow, d);
   memcpy(lout + nlout, d, n); nlout += n;
}

static bool lout_is(const char *expect, size_t len)
{
   return nlout == len && memcmp(lout, expect, len) == 0;
}
#define LOUT(lit) lout_is(lit, sizeof(lit) - 1)

static void ldump(void)
{
   printf("    out (%zu):", nlout);
   for (size_t i = 0; i < nlout; i++)
      printf(lout[i] >= 32 && lout[i] < 127 ? " %c" : " %02X", lout[i]);
   printf("\n");
}

static void lstart(tnd_line_t *s, uint8_t mode)
{
   tnd_line_reset(s, true, mode);
   nlout = 0;
   lnow = 1000000u;
}

#define LCHECK(s, data, want, ...) do { nlout = 0; LFEED(s, data); \
   CHECK(LOUT(want), __VA_ARGS__); if (!LOUT(want)) ldump(); } while (0)

static void test_line_text(void)
{
   tnd_line_t s;

   lstart(&s, 3);
   LCHECK(&s, "HELLO", "HELLO", "text passes");
   LCHECK(&s, "\n\r", "\r\n", "the MOS's LF CR: one CR LF");
   LCHECK(&s, "A\r\nB", "A\r\nB", "CR LF: one CR LF");
   LCHECK(&s, "\r\n\n\r", "\r\n\r\n", "a blank line survives");
   LCHECK(&s, "W\r", "W", "a CR alone: held");
   LCHECK(&s, "X", "\r\nX", "... text after it starts a new line (the Beeb would overwrite)");
   LCHECK(&s, "\n\r\r\r", "\r\n", "CRs at the start of a line do nothing");
   LCHECK(&s, "a\x07" "b", "a\x07" "b", "BEL passes");
   LCHECK(&s, "a`b", "a\xc2\xa3" "b", "96 is the pound sign, UTF-8");
   LCHECK(&s, "\n\rx\x7f\x7f", "\r\nx\b \b", "DELETE backs over what is on the line, not past its start");
   LCHECK(&s, "\n\rab\x09" "c", "\r\nab c", "VDU 9 (cursor right) is a space");
   LCHECK(&s, "q\x08\x0b\x1e\x1a\x0e\x0f\x10\x14\x02\x03\x04\x05\x06\x00", "q", "single-byte VDU codes are dropped");
   LCHECK(&s, "\x0c", "\r\n", "CLS after text: a new line");
   LCHECK(&s, "\x0c", "", "CLS at the start of a line: nothing");
   LCHECK(&s, "\xc1\xff\x80", "", "outside MODE 7, user-defined characters are dropped");

   tnd_line_reset(&s, false, 3);
   LCHECK(&s, "`", "\xa3", "the pound sign in Latin-1");
}

static void test_line_vdu_params(void)
{
   tnd_line_t s;

   lstart(&s, 3);
   LCHECK(&s, "A\x1f\x41\x42" "B", "AB", "VDU 31 (TAB) and its two bytes, even when they are text");
   LCHECK(&s, "\x11\x41" "C\x11\x81", "C", "VDU 17 (COLOUR) and its byte");
   LCHECK(&s, "\x12\x0a\x0d" "D", "D", "VDU 18 (GCOL): parameter bytes 10 and 13 are not new lines");
   LCHECK(&s, "\x13\x01\x02\x03\x04\x05" "E", "E", "VDU 19: five");
   LCHECK(&s, "\x17\x01\x00\x00\x00\x00\x00\x00\x00\x00" "F", "F", "VDU 23: nine");
   LCHECK(&s, "\x17\xe0\x0d\x0a\x07\x7f\x15\x06\x60\x41" "G", "G", "VDU 23 parameters that look like codes");
   LCHECK(&s, "\x18\x00\x00\x00\x00\x10\x00\x10\x00" "H", "H", "VDU 24: eight");
   LCHECK(&s, "\x19\x04\x00\x00\x00\x00\x19\x05\x10\x00\x10\x00" "I", "I", "VDU 25 (MOVE, DRAW): five each");
   LCHECK(&s, "\x1c\x00\x18\x27\x00" "J", "J", "VDU 28: four");
   LCHECK(&s, "\x1d\x00\x00\x00\x00" "K", "K", "VDU 29: four");
   LCHECK(&s, "\x01\x41" "L", "L", "VDU 1 (to the printer only): one");

   /* Split across calls: each byte is its own call already; feed in two slices too. */
   nlout = 0;
   LFEED(&s, "M\x1f\x05");
   LFEED(&s, "\x06N");
   CHECK(LOUT("MN"), "a VDU 31 split across two reads"); if (!LOUT("MN")) ldump();

   LCHECK(&s, "\x16\x07", "\r\n", "MODE after text: a new line (the screen was cleared)");
   LCHECK(&s, "\x16\x07", "", "MODE at the start of a line: nothing");
   CHECK(s.tele, "MODE 7 noted");
   LCHECK(&s, "\x16\x01" "\xc1", "", "MODE 1: high bytes are user-defined again");
   CHECK(!s.tele, "MODE 1 noted");

   /* VDU 21: nothing until VDU 6, parameters still counted. */
   LCHECK(&s, "\n\rP\x15" "hidden\x1f\x06\x06" "more\x06" "Q", "\r\nPQ",
          "VDU 21 hides everything until VDU 6, whose byte inside a VDU 31 does not count");
}

static void test_line_teletext(void)
{
   tnd_line_t s;

   lstart(&s, 7);
   LCHECK(&s, "\x81" "RED\x82" "GREEN", " RED GREEN", "colour codes are spaces, as on the screen");
   LCHECK(&s, "\n\r\x8d" "BIG", "\r\n BIG", "double height: a space");
   LCHECK(&s, "\n\r\xc8\xc9", "\r\nHI", "from 0xA0 bit 7 is ignored");
   LCHECK(&s, "\n\r\x94\x7e\x2c\xa3" "AB\x87" "ab", "\r\n    AB ab",
          "graphics: mosaics are spaces, capitals blast through, alpha again after 0x87");
   LCHECK(&s, "\n\r\x97\x23\n\r" "#", "\r\n  \r\n#", "graphics end with the line");
   LCHECK(&s, "\xff", " ", "0xFF is never written: a mosaic or DEL cell is a space");
}

static void test_line_echo(void)
{
   tnd_line_t s;

   /* What BASIC does: the echo of the line, the MOS's new line, the answer, the prompt. */
   lstart(&s, 7);
   LTYPE(&s, "PRINT 2+2\r");
   LCHECK(&s, "PRINT 2+2\n\r         4\n\r>", "         4\r\n>", "the echo is taken out, the answer stays");
   CHECK(s.en == 0 && s.matched == 0, "nothing left expected");

   lstart(&s, 7);
   LTYPE(&s, "PRINT 2+2\r");
   LCHECK(&s, "PRINT 2+2\r\n\r4", "4", "an echo ending CR LF CR");
   lstart(&s, 7);
   LTYPE(&s, "PRINT 2+2\r");
   LCHECK(&s, "PRINT 2+2\r4", "4", "an echo ending CR alone");
   lstart(&s, 7);
   LTYPE(&s, "X\r");
   LCHECK(&s, "X\n\r\n\rA", "\r\nA", "after the echo's new line, a blank line of output stays");

   lstart(&s, 7);
   LCHECK(&s, ">", ">", "the prompt");
   LTYPE(&s, "\r");
   LCHECK(&s, "\n\r>", ">", "an empty line: its new line is the echo; the client is already on a new line");

   /* Typed ahead: two lines, the second echoed after the first's output. */
   lstart(&s, 7);
   LTYPE(&s, "A\rB\r");
   LCHECK(&s, "A\n\rout A\n\r>B\n\rout B\n\r>", "out A\r\n>out B\r\n>", "two lines typed ahead");

   /* Output that only starts like the echo is not held for long. */
   lstart(&s, 7);
   LTYPE(&s, "PRINT 1\r");
   LCHECK(&s, "PRINTER\n\r>PRINT 1\n\r1\n\r>", "PRINTER\r\n>1\r\n>",
          "a near match is written after all; the real echo later is still taken out");
   CHECK(s.en == 0, "and it was");

   lstart(&s, 7);
   LTYPE(&s, "PP\r");
   LCHECK(&s, "PPP\n\r", "PPP\r\n", "a match that breaks on its last key is written whole");
   CHECK(s.en == 3, "and the echo is still expected");

   /* Divergence: the echo is not what was typed (the line editor refused a key). */
   lstart(&s, 7);
   LTYPE(&s, "ABC\r");
   LCHECK(&s, "AB\x07" "C\n\r", "AB\x07" "C\r\n", "a diverging echo is written in full");
   ltick(&s, TND_ECHO_US);
   CHECK(s.en == 0, "and given up once the Beeb is quiet");

   /* No echo at all: a program reading with GET. */
   lstart(&s, 7);
   LTYPE(&s, "Y\r");
   nlout = 0;
   ltick(&s, TND_ECHO_US - 1u);
   CHECK(s.en == 2, "not given up yet");
   ltick(&s, 1u);
   CHECK(s.en == 0 && nlout == 0, "given up after TND_ECHO_US");
   LCHECK(&s, "You said Y\n\r", "You said Y\r\n", "so the program's text is not taken for an echo");

   /* A line read without an echo (GET took its key) does not block the next one. */
   lstart(&s, 7);
   LTYPE(&s, "Y\rAB\r");
   LCHECK(&s, "x\n\r>AB\n\r>", "x\r\n>>", "the next line's echo is matched past the unechoed one");
   CHECK(s.en == 0 && s.skip == 0, "and both are forgotten");

   lstart(&s, 7);
   LTYPE(&s, "Y\rAB\r");
   LCHECK(&s, "AC", "AC", "a near match of a later line is written");
   CHECK(s.en == 5 && s.skip == 0 && s.matched == 0, "and the earlier line is still expected");
   LCHECK(&s, "Y\n\rAB\n\r>", ">", "so its echo is still taken out, then the later one's");

   /* Half an echo, then nothing. */
   lstart(&s, 7);
   LTYPE(&s, "PRINT\r");
   LCHECK(&s, "PRI", "", "held");
   nlout = 0;
   ltick(&s, TND_ECHO_US);
   CHECK(LOUT("PRI") && s.en == 0, "written when the echo stops coming"); if (!LOUT("PRI")) ldump();

   /* The echo of a key cannot be a parameter byte. */
   lstart(&s, 7);
   LTYPE(&s, "PR\r");
   LCHECK(&s, "\x1fPR", "", "VDU 31,80,82: parameters, not the echo");
   CHECK(s.en == 3 && s.matched == 0, "still expected");
   LCHECK(&s, "PR\n\rPR", "PR", "the echo, then output");

   /* DELETE in the line, and the pound sign. */
   lstart(&s, 7);
   LTYPE(&s, "AB\x7f" "C`\r");
   LCHECK(&s, "AB\x7f" "C`\n\r>", ">", "DELETE and the pound sign echo as typed");

   /* ESCAPE: the type-ahead is gone. */
   lstart(&s, 7);
   LTYPE(&s, "10 PRINT\r");
   tnd_line_escape(&s);
   CHECK(s.en == 0, "ESCAPE forgets the expected echo");
   LCHECK(&s, "\n\rEscape\n\r>", "\r\nEscape\r\n>", "and the Beeb's answer is written");

   /* Room: no more keys than can be matched. */
   lstart(&s, 7);
   CHECK(tnd_line_room(&s) == TND_LINE_EXP, "room for TND_LINE_EXP keys");
   for (unsigned i = 0; i < TND_LINE_EXP + 5u; i++)
      tnd_line_typed(&s, 'Z', lnow);
   CHECK(tnd_line_room(&s) == 0 && s.en == TND_LINE_EXP, "full, and the extra keys not recorded");

   /* The ring wraps: many lines through it. */
   lstart(&s, 7);
   nlout = 0;
   for (unsigned i = 0; i < 500; i++) {
      char line[16];
      int len = snprintf(line, sizeof line, "%u", i * 7u);
      ltype(&s, line, (size_t)len);
      tnd_line_typed(&s, 13, lnow);
      lfeed(&s, line, (size_t)len);
      lfeed(&s, "\n\r>", 3);
   }
   CHECK(nlout == 500 && s.en == 0, "500 lines through the ring: only the prompts are left"); if (nlout != 500) ldump();
}

static void test_line_ga(void)
{
   tnd_line_t s;

   lstart(&s, 7);
   CHECK(!tnd_line_ga_due(&s, lnow + 10u * TND_GA_US, false), "nothing happened: no GA");
   LFEED(&s, ">");
   CHECK(!tnd_line_ga_due(&s, lnow + TND_GA_US - 101u, false), "not quiet for long enough");
   CHECK(!tnd_line_ga_due(&s, lnow + TND_GA_US, true), "keys still waiting for the Beeb");
   CHECK(tnd_line_ga_due(&s, lnow + TND_GA_US, false), "quiet, keys taken: GA");
   CHECK(!tnd_line_ga_due(&s, lnow + 5u * TND_GA_US, false), "once");

   LTYPE(&s, "A");
   CHECK(!tnd_line_ga_due(&s, lnow + TND_GA_US - 1u, false), "a key typed: not quiet yet");
   CHECK(tnd_line_ga_due(&s, lnow + TND_GA_US, false), "a key typed and nothing printed: GA after the quiet");

   lstart(&s, 7);
   LTYPE(&s, "PRINT\r");
   LFEED(&s, "PRI");
   CHECK(!tnd_line_ga_due(&s, lnow + TND_GA_US, false), "half an echo held: no GA");

   lstart(&s, 7);
   LTYPE(&s, "A\r");
   LFEED(&s, "A\n\r");
   CHECK(tnd_line_ga_due(&s, lnow + TND_GA_US, false), "an echo with nothing after it still ends with GA (the line was typed)");
   lstart(&s, 7);
   lnow = 0xFFFFFFF0u;
   LFEED(&s, "x");
   CHECK(!tnd_line_ga_due(&s, 0x100u, false), "the clock wrapped, not long enough");
   CHECK(tnd_line_ga_due(&s, TND_GA_US, false), "the clock wrapped, quiet");
}

static void test_line_robustness(void)
{
   tnd_line_t s;
   unsigned seed = 4242;
   tnd_line_reset(&s, true, 7);
   lnow = 0;
   for (unsigned i = 0; i < 200000; i++) {
      uint8_t d[TND_LINE_OUT_MAX];
      size_t n;
      seed = seed * 1103515245u + 12345u;
      uint8_t c = (uint8_t)(seed >> 16);
      if ((seed >> 8 & 7u) == 0u)
         tnd_line_typed(&s, (uint8_t)(seed >> 24), lnow);
      if ((seed >> 4 & 63u) == 0u)
         c = (uint8_t)(seed >> 24);
      n = tnd_line_beeb(&s, c, lnow, d);
      CHECK(n <= TND_LINE_OUT_MAX, "line output bound at %u", i);
      if (n > TND_LINE_OUT_MAX) return;
      for (size_t j = 0; j < n; j++)
         if (d[j] == 0xFF) { CHECK(0, "0xFF in the line output at %u", i); return; }
      if ((i & 1023u) == 0u) {
         lnow += TND_ECHO_US;
         n = tnd_line_tick(&s, lnow, d);
         CHECK(n <= TND_LINE_OUT_MAX, "tick bound");
         if ((seed & 3u) == 0u)
            tnd_line_escape(&s);
      }
      CHECK(s.en <= TND_LINE_EXP && s.skip + s.matched <= s.en, "the echo ring stays consistent");
      lnow += 7u;
   }
   /* The largest release: a full ring matched and then broken. */
   tnd_line_reset(&s, true, 3);
   for (unsigned i = 0; i < TND_LINE_EXP; i++)
      tnd_line_typed(&s, '`', 0u);
   {
      uint8_t d[TND_LINE_OUT_MAX];
      size_t n = 0;
      for (unsigned i = 0; i < TND_LINE_EXP; i++)
         n += tnd_line_beeb(&s, '`', 0u, d);
      CHECK(n == 0 && s.matched == TND_LINE_EXP, "a whole ring held");
      tnd_line_reset(&s, true, 3);
      for (unsigned i = 0; i < TND_LINE_EXP; i++)
         tnd_line_typed(&s, '`', 0u);
      for (unsigned i = 0; i + 1u < TND_LINE_EXP; i++)
         (void)tnd_line_beeb(&s, '`', 0u, d);
      s.cr = true; s.col = 1;
      n = tnd_line_beeb(&s, 'x', 0u, d);
      CHECK(n <= TND_LINE_OUT_MAX && n == 2u * (TND_LINE_EXP - 1u) + 2u + 1u, "the biggest release fits (%zu)", n);
   }
}

/* ---- shell mode ------------------------------------------------------------------ */

static tnd_shell_t sh;
static tnd_in_t    shin;
static uint8_t     scli[1 << 18]; static size_t nscli;
static uint8_t     skey[1 << 14]; static size_t nskey;
static int         sesc;
static uint32_t    snow;
static uint8_t     iocli[TND_SH_CLI_MAX], iokeys[TND_SH_KEYS_MAX];

static void sh_take(tnd_sh_io_t *io)
{
   CHECK(io->ncli <= TND_SH_CLI_MAX && io->nkeys <= TND_SH_KEYS_MAX, "shell io bounds");
   memcpy(scli + nscli, io->cli, io->ncli); nscli += io->ncli;
   memcpy(skey + nskey, io->keys, io->nkeys); nskey += io->nkeys;
   if (io->escape) sesc++;
}

static void sh_newio(tnd_sh_io_t *io)
{
   io->cli = iocli; io->ncli = 0; io->keys = iokeys; io->nkeys = 0; io->escape = false;
}

static void sstart(uint8_t ttx)
{
   tnd_shell_reset(&sh, true, 7, ttx);
   tnd_in_reset(&shin);
   shin.edit_keys = true;
   nscli = nskey = 0; sesc = 0;
   snow = 50000000u;                             /* the Beeb long quiet */
}

/* Client bytes, through tnd_in as the daemon does. */
static void stype(const void *data, size_t len)
{
   const uint8_t *p = data;
   for (size_t i = 0; i < len; i++) {
      uint8_t k[TND_IN_KEYS], r[TND_IN_REPLY];
      size_t rl, n = tnd_in_byte(&shin, p[i], snow, k, r, &rl);
      for (size_t j = 0; j < n; j++) {
         tnd_sh_io_t io; sh_newio(&io);
         tnd_shell_key(&sh, k[j], snow, &io);
         sh_take(&io);
      }
      snow += 1000u;
   }
}
#define STYPE(lit) stype(lit, sizeof(lit) - 1)

static void sbeeb(const void *data, size_t len)
{
   const uint8_t *p = data;
   for (size_t i = 0; i < len; i++) {
      tnd_sh_io_t io; sh_newio(&io);
      tnd_shell_beeb(&sh, p[i], snow, &io);
      sh_take(&io);
      snow += 100u;
   }
}
#define SBEEB(lit) sbeeb(lit, sizeof(lit) - 1)

static void stick(uint32_t advance)
{
   uint32_t end = snow + advance;
   while (snow < end) {                          /* the daemon's passes, every 5 ms here */
      uint32_t step = end - snow < 5000u ? end - snow : 5000u;
      tnd_sh_io_t io; sh_newio(&io);
      snow += step;
      tnd_shell_tick(&sh, snow, &io);
      sh_take(&io);
   }
}

static bool skeys_are(const char *expect, size_t len)
{
   return nskey == len && memcmp(skey, expect, len) == 0;
}
#define SKEYS(lit) skeys_are(lit, sizeof(lit) - 1)

static bool sline_is(const char *expect)
{
   return sh.len == strlen(expect) && memcmp(sh.line, expect, sh.len) == 0;
}

/* The client's screen, roughly: what is left after the escape sequences are taken out. */
static const char *scli_text(void)
{
   static char t[1 << 18];
   size_t n = 0;
   for (size_t i = 0; i < nscli; i++) {
      if (scli[i] == 27 && i + 1 < nscli && scli[i + 1] == '[') {
         i += 2;
         while (i < nscli && !(scli[i] >= 0x40 && scli[i] <= 0x7E)) i++;
         continue;
      }
      t[n++] = (char)scli[i];
   }
   t[n] = 0;
   return t;
}

static bool scli_has(const char *needle)
{
   size_t n = strlen(needle);
   for (size_t i = 0; i + n <= nscli; i++)
      if (memcmp(scli + i, needle, n) == 0) return true;
   return false;
}

static void sdump(void)
{
   printf("    state %u line [%.*s] cur %u keys:", sh.state, sh.len, sh.line, sh.cur);
   for (size_t i = 0; i < nskey; i++) printf(" %02X", skey[i]);
   printf("\n    cli: %s\n", scli_text());
}

static void test_shell_in_keys(void)
{
   tnd_in_t s; tnd_in_reset(&s); in_reset();
   s.edit_keys = true;
   FEED(&s, "\x1b[1~\x1b[7~\x1b[H\x1bOH");
   CHECK(nkeys == 4 && keys[0] == TND_KEY_HOME && keys[3] == TND_KEY_HOME, "shell: Home in its four forms"); if (nkeys != 4) dump();
   in_reset();
   FEED(&s, "\x1b[3~\x1b[4~\x1b[F\x1bOF\x7f\x08");
   CHECK(nkeys == 6 && keys[0] == TND_KEY_DELFWD && keys[1] == 139 && keys[2] == 139 && keys[3] == 139
         && keys[4] == 127 && keys[5] == 127, "shell: Delete forwards; End (VT220, xterm, SS3); BS and DEL back"); if (nkeys != 6) dump();
   in_reset();
   FEED(&s, "\x1b[A\x1b[B\x1b[C\x1b[D\x1bOA");
   CHECK(nkeys == 5 && keys[0] == 143 && keys[1] == 142 && keys[2] == 141 && keys[3] == 140 && keys[4] == 143, "shell: arrows, CSI and SS3");

   tnd_in_reset(&s); in_reset();
   FEED(&s, "\x1b[1~\x1b[3~\x1b[H");
   CHECK(nkeys == 1 && keys[0] == 127, "screen mode unchanged: Home nothing, Delete is DELETE"); if (nkeys != 1) dump();
}

static void test_hotkey(void)
{
   bool armed = false;
   CHECK(tnd_hotkey(&armed, 'm') == TND_HOT_NONE && !armed, "an ordinary key");
   CHECK(tnd_hotkey(&armed, 0x1C) == TND_HOT_SWALLOW && armed, "Ctrl-\\ arms");
   CHECK(tnd_hotkey(&armed, 'm') == TND_HOT_MODE && !armed, "then m: the mode");
   (void)tnd_hotkey(&armed, 0x1C);
   CHECK(tnd_hotkey(&armed, 'T') == TND_HOT_TTX, "then T: teletext");
   (void)tnd_hotkey(&armed, 0x1C);
   CHECK(tnd_hotkey(&armed, 0x1C) == TND_HOT_LITERAL && !armed, "Ctrl-\\ twice: one for the Beeb");
   (void)tnd_hotkey(&armed, 0x1C);
   CHECK(tnd_hotkey(&armed, 'x') == TND_HOT_SWALLOW && !armed, "anything else: dropped");
   CHECK(tnd_hotkey(&armed, 'x') == TND_HOT_NONE, "and keys are keys again");
}

static void test_key_for_char(void)
{
   CHECK(tnd_key_for_char('A') == 'A' && tnd_key_for_char(28) == 28 && tnd_key_for_char(0) == 0, "ASCII and controls as they are, not NUL");
   CHECK(tnd_key_for_char(0x81) == 0x91 && tnd_key_for_char(0x8A) == 0x9A, "&80-&8A: SHIFT and a function key");
   CHECK(tnd_key_for_char(0x94) == 0xA4 && tnd_key_for_char(0x9A) == 0xAA, "&90-&9A: CTRL and a function key");
   CHECK(tnd_key_for_char(0x8D) == 0 && tnd_key_for_char(0x9D) == 0 && tnd_key_for_char(0x9F) == 0, "&8B-&8F, &9B-&9F: no key gives them");
   CHECK(tnd_key_for_char(0xA1) == 0 && tnd_key_for_char(0xC5) == 0, "&A0-&CF: none");
   CHECK(tnd_key_for_char(0xD3) == 0xD3 && tnd_key_for_char(0xFA) == 0xFA && tnd_key_for_char(0xFF) == 0 && tnd_key_for_char(0xFB) == 0, "&D0-&DA, &E0-&EA, &F0-&FA themselves; not &FF");
}

static void test_shell_probe_and_line(void)
{
   sstart(TND_TTX_RENDERED);
   STYPE("P");
   CHECK(sh.state == TND_SH_PROBE && SKEYS("P"), "a quiet Beeb: the key goes as a probe"); if (!SKEYS("P")) sdump();
   SBEEB("P");
   CHECK(sh.state == TND_SH_EDIT && SKEYS("P\x7f") && sline_is("P"), "echoed: the editor has it, a DELETE takes it back"); if (!SKEYS("P\x7f")) sdump();
   CHECK(strcmp(scli_text(), "P") == 0, "the client sees the P (drawn by the editor)"); if (strcmp(scli_text(), "P")) sdump();
   SBEEB("\x7f");
   CHECK(strcmp(scli_text(), "P") == 0, "the DELETE's echo is dropped");
   STYPE("RINT 2+2");
   CHECK(sline_is("PRINT 2+2") && SKEYS("P\x7f"), "the rest is edited on the Pi, nothing sent"); if (!sline_is("PRINT 2+2")) sdump();
   nscli = 0;
   STYPE("\r");
   CHECK(SKEYS("P\x7fPRINT 2+2\r") && sh.state == TND_SH_IDLE, "RETURN: the line and RETURN to the Beeb"); if (!SKEYS("P\x7fPRINT 2+2\r")) sdump();
   CHECK(strstr(scli_text(), "PRINT 2+2\r\n") != NULL, "and the client is on a new line"); if (!strstr(scli_text(), "PRINT 2+2\r\n")) sdump();
   nscli = 0;
   SBEEB("PRINT 2+2\n\r         4\n\r>");
   CHECK(strcmp(scli_text(), "         4\r\n>") == 0, "the Beeb's echo is taken out, the answer stays"); if (strcmp(scli_text(), "         4\r\n>")) sdump();
   CHECK(sh.hn == 1 && sh.hlen[0] == 9, "the line is in the history");

   /* Typed fast: the probe's outcome decides for the keys behind it. */
   sstart(TND_TTX_RENDERED);
   STYPE("PRINT 1\r");
   CHECK(SKEYS("P") && sh.nq == 7, "keys behind a probe wait"); if (!SKEYS("P")) sdump();
   SBEEB("P");
   CHECK(SKEYS("P\x7fPRINT 1\r") && sh.state == TND_SH_IDLE, "the echo: the waiting keys are the line, RETURN sends it"); if (!SKEYS("P\x7fPRINT 1\r")) sdump();

   /* A program reading keys: no echo. */
   sstart(TND_TTX_RENDERED);
   STYPE("Y");
   CHECK(sh.state == TND_SH_PROBE, "a probe");
   STYPE("N");
   stick(TND_SH_PROBE_US);
   CHECK(sh.state == TND_SH_PASS && SKEYS("YN"), "no echo in time: keys go straight, the held one too"); if (!SKEYS("YN")) sdump();
   STYPE("\x1b[A" "Q\r");
   CHECK(SKEYS("YN\x8fQ\r"), "while passing: the arrow as the Beeb's key, RETURN too"); if (!SKEYS("YN\x8fQ\r")) sdump();
   stick(TND_SH_PASS_US);
   CHECK(sh.state == TND_SH_IDLE, "idle again after TND_SH_PASS_US with no keys");

   /* A program that prints something else first. */
   sstart(TND_TTX_RENDERED);
   STYPE("Y");
   SBEEB("GOT 89\n\r");
   CHECK(sh.state == TND_SH_PASS && strstr(scli_text(), "GOT 89") != NULL, "other output: a program took it"); if (sh.state != TND_SH_PASS) sdump();

   /* A Beeb that is busy printing: keys go straight, no probe. */
   sstart(TND_TTX_RENDERED);
   SBEEB("LISTING...");
   STYPE("A");
   CHECK(sh.state == TND_SH_PASS && SKEYS("A"), "output just now: straight through");

   /* An editing key at a quiet Beeb opens the editor without a probe. */
   sstart(TND_TTX_RENDERED);
   STYPE("\x1b[A");
   CHECK(sh.state == TND_SH_EDIT && nskey == 0, "Up at a quiet Beeb: the editor, nothing sent");
   STYPE("\r");
   CHECK(SKEYS("\r") && strstr(scli_text(), "\r\n"), "an empty line: RETURN alone");
}

static void sedit_start(const char *text)
{
   sstart(TND_TTX_RENDERED);
   stype("\x1b[D", 3);                           /* Left: into the editor, empty */
   stype(text, strlen(text));
}

static void test_shell_editing(void)
{
   sedit_start("HELLO");
   CHECK(sline_is("HELLO") && sh.cur == 5, "typed");
   STYPE("\x1b[D\x1b[D" "X");
   CHECK(sline_is("HELXLO") && sh.cur == 4, "left twice, insert mid-line"); if (!sline_is("HELXLO")) sdump();
   STYPE("\x01" "A");
   CHECK(sline_is("AHELXLO") && sh.cur == 1, "Ctrl-A, insert at the start");
   STYPE("\x05" "Z");
   CHECK(sline_is("AHELXLOZ") && sh.cur == 8, "Ctrl-E, at the end");
   STYPE("\x1b[1~" "1" "\x1b[4~" "4");
   CHECK(sline_is("1AHELXLOZ4"), "PuTTY's Home and End"); if (!sline_is("1AHELXLOZ4")) sdump();
   STYPE("\x1b[H" "\x1b[3~");
   CHECK(sline_is("AHELXLOZ4") && sh.cur == 0, "xterm Home, VT220 Delete deletes forwards");
   STYPE("\x1bOF\x7f\x08");
   CHECK(sline_is("AHELXLO"), "SS3 End, then DEL and BS delete backwards"); if (!sline_is("AHELXLO")) sdump();
   STYPE("\x1b[D\x1b[D\x1b[D\x0b");
   CHECK(sline_is("AHEL") && sh.cur == 4, "Ctrl-K: to the end");
   STYPE("\x1b[D\x15");
   CHECK(sline_is("L") && sh.cur == 0, "Ctrl-U: to the start");
   sedit_start("PRINT A B  ");
   STYPE("\x17");
   CHECK(sline_is("PRINT A ") , "Ctrl-W: spaces, then the word"); if (!sline_is("PRINT A ")) sdump();
   STYPE("\x17\x17");
   CHECK(sline_is(""), "Ctrl-W twice more: empty");
   STYPE("\x7f\x1b[3~\x1b[D\x1b[C");
   CHECK(sline_is("") && sh.cur == 0, "editing keys on an empty line do nothing");
   sedit_start("AB");
   STYPE("\x02\x02\x06" "x" "\x04");
   CHECK(sline_is("AxB") || sline_is("Ax"), "Ctrl-B, Ctrl-F, Ctrl-D");
   CHECK(sline_is("Ax"), "Ctrl-D deletes under the cursor"); if (!sline_is("Ax")) sdump();

   /* A full line: the extra keys are dropped. */
   sstart(TND_TTX_RENDERED);
   stype("\x1b[D", 3);
   for (unsigned i = 0; i < TND_SH_LINE + 10u; i++) stype("x", 1);
   CHECK(sh.len == TND_SH_LINE, "the line holds TND_SH_LINE characters");

   /* Ctrl-L: the line drawn again. */
   sedit_start("AB");
   nscli = 0;
   STYPE("\x0c");
   CHECK(strcmp(scli_text(), "AB") == 0 && scli_has("\x1b[K"), "Ctrl-L redraws"); if (strcmp(scli_text(), "AB")) sdump();
}

static void submit(const char *line)
{
   stype("\x1b[D", 3);
   stype(line, strlen(line));
   stype("\r", 1);
   SBEEB("\n\r>");                                /* (no echo: the expectation is given up later) */
   stick(TND_ECHO_US + 10000u);
}

static void test_shell_history(void)
{
   sstart(TND_TTX_RENDERED);
   submit("ONE"); submit("TWO"); submit("THREE");
   CHECK(sh.hn == 3, "three lines");
   STYPE("\x1b[A");
   CHECK(sline_is("THREE"), "Up: the newest");
   STYPE("\x1b[A\x1b[A");
   CHECK(sline_is("ONE"), "Up twice more: the oldest");
   nscli = 0;
   STYPE("\x1b[A");
   CHECK(sline_is("ONE") && scli_has("\a"), "past the oldest: a bell");
   STYPE("\x1b[B\x1b[B\x1b[B");
   CHECK(sline_is(""), "Down past the newest: the line being typed (empty)");
   STYPE("NEW" "\x1b[A\x1b[B");
   CHECK(sline_is("NEW"), "a part-typed line comes back under the history");
   STYPE("\x1b[A" "!" "\r");
   CHECK(sh.hn == 4 && sh.hlen[0] == 6 && memcmp(sh.hist[0], "THREE!", 6) == 0, "a recalled line edited and sent is a new entry");
   SBEEB("\n\r>"); stick(TND_ECHO_US + 10000u);
   submit("TWO");
   CHECK(sh.hn == 4 && memcmp(sh.hist[0], "TWO", 3) == 0 && memcmp(sh.hist[3], "ONE", 3) == 0, "a repeated line moves to the front, not a copy");
   submit("");
   CHECK(sh.hn == 4, "empty lines are not kept");
   for (unsigned i = 0; i < 40; i++) {
      char l[8]; snprintf(l, sizeof l, "L%u", i);
      submit(l);
   }
   CHECK(sh.hn == TND_SH_HIST && memcmp(sh.hist[0], "L39", 3) == 0, "bounded: the newest TND_SH_HIST");

   /* Ctrl-R: older lines with what was typed in them. */
   sstart(TND_TTX_RENDERED);
   submit("PRINT 1"); submit("LIST"); submit("PRINT 2"); submit("RUN");
   stype("\x1b[D", 3);
   STYPE("PRI\x12");
   CHECK(sline_is("PRINT 2"), "Ctrl-R: the newest with PRI"); if (!sline_is("PRINT 2")) sdump();
   STYPE("\x12");
   CHECK(sline_is("PRINT 1"), "again: the next older");
   nscli = 0;
   STYPE("\x12");
   CHECK(sline_is("PRINT 1") && scli_has("\a"), "none older: a bell");
   STYPE("\x1b[B\x1b[B\x1b[B\x1b[B");
   CHECK(sline_is("PRI"), "Down to the end: back to what was typed");
}

static void test_shell_ctrlv(void)
{
   sedit_start("A");
   STYPE("\x16" "81" "B" "\x16" "9d" "\x16" "zz");
   CHECK(sh.len == 4 && sh.line[1] == 0x81 && sh.line[2] == 'B' && sh.line[3] == 'z', "Ctrl-V 81: &81; &9D (no key gives it) and Ctrl-V z refused"); if (sh.len != 4) sdump();
   CHECK(scli_has("\a"), "with a bell");
   nscli = 0;
   STYPE("\x1b[D\x1b[D\x0c");
   CHECK(scli_has("\x1b[31m\xe2\x96\x88\x1b[39m"), "the code shown as its marker, a red block"); if (!scli_has("\x1b[31m")) sdump();
   nskey = 0;
   STYPE("\r");
   CHECK(SKEYS("A\x91" "Bz\r"), "sent as the key that gives &81: SHIFT f1 (&91)"); if (!SKEYS("A\x91" "Bz\r")) sdump();
   nscli = 0;
   SBEEB("A\x81" "Bz\n\r>");
   CHECK(strcmp(scli_text(), ">") == 0, "the echo is &81 itself, and is taken out"); if (strcmp(scli_text(), ">")) sdump();
}

static void test_shell_redraw(void)
{
   sedit_start("PRI");
   nscli = 0;
   SBEEB("TICK\n\r");
   CHECK(scli_has("\x1b[3D\x1b[K" "TICK\r\n"), "output while typing: the edit line comes off first"); if (!scli_has("\x1b[3D\x1b[K")) sdump();
   CHECK(!sh.shown, "and is not shown meanwhile");
   stick(TND_SH_REDRAW_US / 2u);
   CHECK(!sh.shown, "not while the output may go on");
   stick(TND_SH_REDRAW_US);
   CHECK(sh.shown && strcmp(scli_text(), "TICK\r\nPRI") == 0, "once quiet: drawn again under it"); if (strcmp(scli_text(), "TICK\r\nPRI")) sdump();
   STYPE("NT");
   CHECK(sline_is("PRINT"), "and editing carries on");

   /* ESCAPE: the line goes, the request is made. */
   sedit_start("PRINT");
   STYPE("\x03");
   CHECK(sesc == 1 && sh.state == TND_SH_IDLE && sh.len == 0, "Ctrl-C: ESCAPE, the line dropped");
   sedit_start("PRINT");
   STYPE("\x1b");
   stick(TND_ESC_US + 1000u);
   {  /* a lone ESC, after the wait */
      uint8_t k[TND_IN_KEYS];
      size_t n = tnd_in_tick(&shin, snow, k);
      for (size_t j = 0; j < n; j++) { tnd_sh_io_t io; sh_newio(&io); tnd_shell_key(&sh, k[j], snow, &io); sh_take(&io); }
   }
   CHECK(sesc == 1 && sh.len == 0, "a lone ESC: ESCAPE too");
}

static void test_line_teletext_styles(void)
{
   tnd_line_t s;
   uint8_t d[TND_LINE_GLYPH_MAX];

   CHECK(tnd_marker(0x81, true, d) == 13 && memcmp(d, "\x1b[31m\xe2\x96\x88\x1b[39m", 13) == 0, "marker: alpha red, a red block");
   CHECK(tnd_marker(0x94, true, d) == 13 && memcmp(d, "\x1b[34m\xe2\x96\x92\x1b[39m", 13) == 0, "marker: graphics blue, a shaded block");
   CHECK(tnd_marker(0x8D, true, d) == 10 && memcmp(d, "\x1b[7m" "2" "\x1b[27m", 10) == 0, "marker: double height, a reversed 2");
   CHECK(tnd_marker(0x9D, true, d) == 10 && d[4] == 'B', "marker: new background, B");
   CHECK(tnd_marker(0x81, false, d) == 11 && d[5] == '#', "marker, no UTF-8: #");
   CHECK(tnd_marker(96, true, d) == 2 && d[0] == 0xC2, "the pound sign");

   /* Markers: the columns kept. */
   lstart(&s, 7); tnd_line_ttx(&s, TND_TTX_MARKERS);
   nlout = 0;
   LFEED(&s, "10 PRINT \"\x81" "RED\x8d" "BIG\"\n\r");
   {
      char t[256]; size_t n = 0;
      for (size_t i = 0; i < nlout; i++) {
         if (lout[i] == 27) { while (i < nlout && !(lout[i] >= 0x40 && lout[i] <= 0x7E && lout[i] != '[')) i++; continue; }
         if ((lout[i] & 0xC0) == 0x80) continue;     /* UTF-8 continuation: one column */
         t[n++] = (char)lout[i];
      }
      t[n] = 0;
      CHECK(strcmp(t, "10 PRINT \"\xe2RED2BIG\"\r\n") == 0, "markers keep each code's column"); if (strcmp(t, "10 PRINT \"\xe2RED2BIG\"\r\n")) ldump();
   }

   /* Rendered: the codes take effect. */
   lstart(&s, 7); tnd_line_ttx(&s, TND_TTX_RENDERED);
   LCHECK(&s, "\x81RED\x82GRN\n\r", " \x1b[0;31mRED \x1b[0;32mGRN\x1b[0m\r\n", "rendered: colour from the next cell, reset at the end of the line");
   LCHECK(&s, "\x94\x7e\x2c" "A\n\r", " \x1b[0;34m\xf0\x9f\xac\xbb\xf0\x9f\xac\x8b" "A\x1b[0m\r\n", "rendered: mosaics as sextants, capitals blast through");
   LCHECK(&s, "#_`\n\r", "#\xe2\x80\x95\xc2\xa3\r\n", "rendered: # _ and the pound as MODE 7 shows them");
   LCHECK(&s, "\x81\x9d" "X\n\r", " \x1b[0;31;41m X\x1b[0m\r\n" , "rendered: new background");
   /* the Beeb's 40-column rows: a new row starts plain */
   {
      char row[64];
      memset(row, 'a', 39); row[0] = (char)0x81; row[39] = 'b';
      nlout = 0;
      lfeed(&s, row, 40);
      LFEED(&s, "c");
      CHECK(nlout > 0 && lout[nlout - 1] == 'c' && memcmp(lout + nlout - 5, "\x1b[0m", 4) == 0, "row 2 of a wrapped line starts plain"); if (lout[nlout - 1] != 'c') ldump();
   }
   /* plain: tnd_line_plain resets the colours for someone else's text */
   lstart(&s, 7); tnd_line_ttx(&s, TND_TTX_RENDERED);
   nlout = 0; LFEED(&s, "\x81X");
   CHECK(tnd_line_plain(&s, d) == 4 && tnd_line_plain(&s, d) == 0, "plain once, then nothing to do");
   nlout = 0; LFEED(&s, "Y");
   CHECK(nlout > 1 && lout[0] == 27, "and the colour comes back before the next text");

   /* Spaces (raw line mode): unchanged. */
   lstart(&s, 7);
   LCHECK(&s, "\x81" "RED\n\r", " RED\r\n", "spaces: as before");
}

static void test_shell_robustness(void)
{
   unsigned seed = 99;
   static const char *seqs[] = { "\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D", "\x1b[1~", "\x1b[3~", "\x1b[4~",
                                 "\x01", "\x05", "\x0b", "\x15", "\x17", "\x12", "\x16", "\r", "\x7f", "\x0c" };
   for (unsigned ttx = 0; ttx < 3; ttx++) {
      sstart((uint8_t)ttx);
      for (unsigned i = 0; i < 30000; i++) {
         seed = seed * 1103515245u + 12345u;
         unsigned r = seed >> 16;
         nscli = nskey = 0;
         if ((r & 7u) == 0u) {
            const char *q = seqs[(r >> 3) % (sizeof seqs / sizeof seqs[0])];
            stype(q, strlen(q));
         } else if ((r & 7u) < 4u) {
            uint8_t c = (uint8_t)(32u + (r >> 4) % 95u);
            stype(&c, 1);
         } else if ((r & 7u) < 7u) {
            uint8_t c = (uint8_t)(r >> 5);
            sbeeb(&c, 1);
         } else {
            stick((r >> 4) % 400000u);
         }
         for (size_t j = 0; j < nscli; j++)
            if (scli[j] == 0xFF) { CHECK(0, "0xFF to the client"); return; }
         CHECK(sh.len <= TND_SH_LINE && sh.cur <= sh.len && sh.nq <= TND_SH_QUEUE && sh.hn <= TND_SH_HIST, "editor state stays sane");
      }
   }
   CHECK(true, "shell fuzz ran");
}

int main(void)
{
   test_plain_keys();
   test_pound_and_high_bytes();
   test_cursor_and_function_keys();
   test_escape_key();
   test_negotiation();
   test_break_key();
   test_blank();
   test_narrow_window();
   test_input_robustness();
   test_input_key_bound();
   test_login();
   test_teletype();
   test_output_text();
   test_output_params();
   test_output_vdu21();
   test_output_teletext();
   test_review_fixes_full();
   test_review_fixes_2();
   test_esc_ahead();
   test_login_many_addrs();
   test_output_teletext_chip();
   test_bbcfont();
   test_mode_decision();
   test_line_text();
   test_line_vdu_params();
   test_line_teletext();
   test_line_echo();
   test_line_ga();
   test_line_robustness();
   test_shell_in_keys();
   test_hotkey();
   test_key_for_char();
   test_shell_probe_and_line();
   test_shell_editing();
   test_shell_history();
   test_shell_ctrlv();
   test_shell_redraw();
   test_line_teletext_styles();
   test_shell_robustness();
   test_tek();
   test_output_robustness();
   test_model_wrap_scroll();
   test_copy_cursor();
   test_session();
   test_scan_merge();
   test_scan_full();
   test_cursor_line();
   test_banner();
   test_stalled();

   printf("%d checks, %d failed\n", checks, failures);
   return failures ? 1 : 0;
}
