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
   memcpy(keys + nkeys, k, n);
   nkeys += n;
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

   in_reset();
   FEED(&s, "\xc2" "a");
   CHECK(nkeys == 0, "a lead byte then ASCII: the ASCII is lost with it, no crash");
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
   CHECK(nkeys == 1 && keys[0] == 143, "modifier parameters are ignored: Ctrl-Up is Up");

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

   in_reset();
   FEED(&s, "\x1b[15~\x1b[17~\x1b[18~\x1b[19~\x1b[20~\x1b[21~");
   CHECK(nkeys == 6 && keys[0] == 0x85 && keys[1] == 0x86 && keys[2] == 0x87 && keys[3] == 0x88
         && keys[4] == 0x89 && keys[5] == 0x80, "F5-F9 are f5-f9, F10 is f0"); if (nkeys != 6) dump();

   in_reset();
   FEED(&s, "\x1b[2~\x1b[5~\x1b[6~\x1b[H\x1b[1~");
   CHECK(nkeys == 0, "Insert, PgUp, PgDn, Home: no Beeb key, nothing leaks"); if (nkeys) dump();

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
   FEED(&s, "\x1b[21~\x1b[23~");
   CHECK(nkeys == 2 && keys[0] == 0x80 && keys[1] == TND_KEY_REFRESH, "F10 is f0 and F11 is the redraw request");
   in_reset();
   FEED(&s, "");
   CHECK(nkeys == 1 && keys[0] == TND_KEY_REFRESH, "Ctrl-L is the redraw request too");
}

static void test_negotiation(void)
{
   tnd_in_t s; tnd_in_reset(&s); in_reset();
   uint8_t g[TND_GREETING_LEN];

   CHECK(tnd_greeting(g) == TND_GREETING_LEN, "greeting length");
   static const uint8_t want[] = { 255, 251, 1, 255, 251, 3, 255, 253, 3 };
   CHECK(memcmp(g, want, sizeof want) == 0, "greeting: WILL ECHO, WILL SGA, DO SGA");

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

   in_reset();
   FEED(&s, "\xff\xfb\x1f");
   static const uint8_t dont31[] = { 255, 254, 31 };
   CHECK(nreply == 3 && memcmp(reply, dont31, 3) == 0, "WILL NAWS: DONT NAWS");
   FEED(&s, "\xff\xfb\x1f");
   CHECK(nreply == 3, "once");

   in_reset();
   FEED(&s, "\xff\xfe\x01\xff\xfc\x01");
   CHECK(nreply == 0, "DONT and WONT need no reply");

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

static char outbuf[256];
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

static size_t feed_out(tnd_out_t *s, const char *data, size_t len, char *dst, size_t cap)
{
   size_t o = 0;
   for (size_t i = 0; i < len; i++) {
      uint8_t d[TND_OUT_MAX];
      size_t n = tnd_out_byte(s, (uint8_t)data[i], d);
      CHECK(n <= TND_OUT_MAX, "a byte of output never exceeds TND_OUT_MAX");
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
   strcpy(want, "\x1b[2J\x1b[H\x1b[25;1Hx\x1b[1;25r\x1b[1S\x1b[r\x1b[25;2H");
   CHECK(strcmp(out, want) == 0, "LF on the last row scrolls the terminal too"); if (strcmp(out, want)) printf("    got [%s]\n", out);

   /* A text window: TAB is relative to it and it scrolls on its own. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x03\x1c\x0a\x14\x1d\x05\x1f\x00\x00y", out);
   strcpy(want, "\x1b[2J\x1b[H\x1b[6;11H\x1b[6;11Hy");
   CHECK(strcmp(out, want) == 0, "VDU 28 sets the window and TAB(0,0) is its corner"); if (strcmp(out, want)) printf("    got [%s]\n", out);

   /* Writing in the last cell of the screen scrolls. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x1f\x27\x18z", out);
   strcpy(want, "\x1b[2J\x1b[H\x1b[25;40Hz\x1b[1;25r\x1b[1S\x1b[r\x1b[25;1H");
   CHECK(strcmp(out, want) == 0, "a character in the bottom right cell scrolls"); if (strcmp(out, want)) printf("    got [%s]\n", out);

   /* Teletext starts each row white. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07\x1f\x00\x00\x81" "R\x1f\x00\x01" "W", out);
   CHECK(strstr(out, "\x1b[31m") != NULL && strstr(out, "\x1b[0m\x1b[2;1HW") != NULL,
         "a colour does not carry to the next row in MODE 7");
   if (strstr(out, "\x1b[0m\x1b[2;1HW") == NULL) printf("    got [%s]\n", out);
}

static void test_copy_cursor(void)
{
   tnd_out_t s;
   char out[2048];
   uint8_t d[TND_COPY_MAX];
   size_t n;
   uint32_t t = 1000000;

   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c" "HELLO\r\n", out);               /* CLS, then HELLO, and the cursor at the start of row 2 */
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 143);                            /* up */
   n = tnd_out_copyflush(&s, t + 1000, d);
   CHECK(n == 0, "the mark waits until the Beeb has been quiet");
   n = tnd_out_copyflush(&s, t + 50000, d);
   CHECK(n > 0 && n <= TND_COPY_MAX, "... then it is drawn");
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[1;1H") != NULL && strstr((char *)d, "\x1b[7mH") != NULL,
         "up from the cursor marks the H above it, reversed"); if (!strstr((char *)d, "\x1b[7mH")) printf("    got [%s]\n", d);
   CHECK(n >= 6 && strstr((char *)d + n - 12, "\x1b[2;1H") != NULL, "and the cursor goes back to where typing goes");

   tnd_out_copykey(&s, 139);                            /* COPY: the mark moves on to the E */
   n = tnd_out_copyflush(&s, t + 100000, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[1;1H\x1b[0mH") != NULL && strstr((char *)d, "\x1b[7mE") != NULL,
         "COPY puts the H back and marks the E"); if (!strstr((char *)d, "\x1b[7mE")) printf("    got [%s]\n", d);

   tnd_out_copykey(&s, 13);                             /* RETURN ends it */
   n = tnd_out_copyflush(&s, t + 150000, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[1;2H\x1b[0mE") != NULL && strstr((char *)d, "\x1b[7m") == NULL,
         "RETURN removes the mark"); if (strstr((char *)d, "\x1b[7m")) printf("    got [%s]\n", d);
   CHECK(tnd_out_copyflush(&s, t + 200000, d) == 0, "and nothing more is sent");

   /* The mark moves with the text when the screen scrolls, and never stays on a cell the model has not seen. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x16\x07" "AB\r\n", out);
   tnd_out_touch(&s, t);
   tnd_out_copykey(&s, 143);
   n = tnd_out_copyflush(&s, t + 50000, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[7mA") != NULL, "MODE 7: the mark is on the A");
   FEED_OUT(&s, "\x1f\x00\x18\n", out);                 /* TAB to the bottom row and a LF: the screen scrolls */
   tnd_out_touch(&s, t + 60000);
   tnd_out_copykey(&s, 141);
   n = tnd_out_copyflush(&s, t + 120000, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[7m") == NULL || strstr((char *)d, "\x1b[7mB") == NULL,
         "after a scroll the mark is not left on the old row");

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

static void test_repaint(void)
{
   tnd_out_t s;
   char out[2048];
   uint8_t d[TND_REPAINT_MAX];
   size_t n;

   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c" "HI\r\n\x11\x01YO", out);          /* CLS, HI, a new line, then YO in red */
   n = tnd_out_repaint(&s, 0u, d);
   d[n] = 0;
   CHECK(strcmp((char *)d, "\x1b[0mHI\x1b[0m\r\n") == 0, "repaint draws row 0 as a plain line, with no clear and no positioning"); if (strcmp((char *)d, "\x1b[0mHI\x1b[0m\r\n")) printf("    got [%s]\n", d);
   n = tnd_out_repaint(&s, 1u, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[31mYO") != NULL && strstr((char *)d, "\r\n") == NULL,
         "row 1, the last, comes back in its colour with no line end"); if (!strstr((char *)d, "\x1b[31mYO")) printf("    got [%s]\n", d);
   CHECK(tnd_out_repaint(&s, 5u, d) == 0u, "a row with nothing on it needs nothing");
   n = tnd_out_repaint(&s, s.rows, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[3G") != NULL && strstr((char *)d, "\x1b[1A") == NULL, "after the last row the cursor goes to the Beeb's column"); if (!strstr((char *)d, "\x1b[3G")) printf("    got [%s]\n", d);

   /* A screen with something below the cursor: the cursor is moved back up to its row. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c" "A\r\nB\r\nC\x1f\x01\x00", out);   /* the cursor is on row 0 again, at column 1 */
   n = tnd_out_repaint(&s, s.rows, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[2A") != NULL && strstr((char *)d, "\x1b[2G") != NULL, "the cursor is moved up to its row and across"); if (!strstr((char *)d, "\x1b[2A")) printf("    got [%s]\n", d);

   /* Blank rows above the first thing on the screen are not drawn. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c\x1f\x00\x0a" "Z", out);
   CHECK(tnd_out_repaint(&s, 3u, d) == 0u && tnd_out_repaint(&s, 10u, d) > 0u, "the empty rows at the top are skipped");

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
   tnd_out_copykey(&s, 143);
   CHECK(tnd_out_copyflush(&s, 100000000u, d) == 0u, "no copy cursor mark until the rows are the Beeb's");

   /* A mark belongs to a terminal: a new one starts without. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "\x0c" "HI\r\n", out);
   tnd_out_touch(&s, 100u);
   tnd_out_copykey(&s, 143);
   n = tnd_out_copyflush(&s, 100000u, d);
   CHECK(s.hl_on, "the copy cursor is marked");
   tnd_out_session(&s);
   CHECK(!s.hl_on && !s.cc_on && s.npend == 0, "a new session starts with no mark");

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
   n = tnd_out_repaint(&s, s.rows, d);
   d[n] = 0;
   CHECK(strstr((char *)d, "\x1b[37m") != NULL, "and so is the last step of a repaint"); if (!strstr((char *)d, "\x1b[37m")) printf("    got [%s]\n", d);

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
   CHECK(strstr(out, "\x1b[33mx") != NULL, "MODE 7: the numbers are the colours");

   /* The Beeb's cursor read from the MOS: followed from there, but nothing is known to be on the screen. */
   tnd_out_reset(&s, true);
   tnd_out_assume_mode(&s, 3u);
   tnd_out_at(&s, 5u, 24u);
   FEED_OUT(&s, "x\n", out);
   CHECK(strstr(out, "\x1b[1;25r\x1b[1S\x1b[r") != NULL, "from a known cursor on the last row an LF scrolls the terminal too"); if (!strstr(out, "\x1b[1S")) printf("    got [%s]\n", out);

   /* Not synced: nothing is known, so nothing is drawn. */
   tnd_out_reset(&s, true);
   FEED_OUT(&s, "abc", out);
   CHECK(tnd_out_repaint(&s, 0u, d) == 0u, "an unsynced model draws nothing");
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

int main(void)
{
   test_plain_keys();
   test_pound_and_high_bytes();
   test_cursor_and_function_keys();
   test_escape_key();
   test_negotiation();
   test_break_key();
   test_blank();
   test_input_robustness();
   test_output_text();
   test_output_params();
   test_output_vdu21();
   test_output_teletext();
   test_output_robustness();
   test_model_wrap_scroll();
   test_copy_cursor();
   test_repaint();
   test_stalled();

   printf("%d checks, %d failed\n", checks, failures);
   return failures ? 1 : 0;
}
