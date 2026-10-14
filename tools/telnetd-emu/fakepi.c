/* fakepi.c - the network half of telnetd.c, without lwIP, for the emulator harness.

   Built as a shared library (run.py builds it) from this file and the firmware's own
   src/telnetd_proto.c, so what is tested is the daemon's byte logic itself.  This file
   is only the glue telnetd.c has around it, kept in the same shape: one session, a key
   ring, the mode decision after every client byte and on every poll, the Beeb's output
   held while the mode is not decided, line mode keys paced by tnd_line_room and recorded
   as typed when given to the Beeb, ESCAPE as a request (the harness raises it the way
   the Pi does), IAC GA when tnd_line_ga_due and tnd_ga_wanted.  Screen mode goes through
   tnd_out_byte, as in the daemon.  Not here: the login, the banners, the repaint, the
   copy cursor, the ROM's screen scan. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "telnetd_proto.h"

#define RING 4096u
#define OUTB 65536u

static tnd_in_t   g_in;
static tnd_out_t  g_out;
static tnd_line_t g_lm;
static uint8_t    g_setting, g_sm;
static uint32_t   g_start;
static uint8_t    g_ring[RING];
static uint32_t   g_kh, g_kt;
static uint8_t    g_ob[OUTB];
static uint32_t   g_on;
static int        g_escape, g_break;

static void o_put(const uint8_t *p, size_t n)
{
   if (n > OUTB - g_on)
      n = OUTB - g_on;
   memcpy(g_ob + g_on, p, n);
   g_on += (uint32_t)n;
}

static void decide(uint32_t now)
{
   uint8_t m = tnd_decide(&g_in, g_setting, now, g_start);
   if (m == TND_MODE_UNDECIDED || m == g_sm)
      return;
   if (g_sm == TND_MODE_SCREEN)                 /* a switch from screen: colours back, a new line */
      o_put((const uint8_t *)"\x1b[0m\x1b[?25h\r\n", 12u);
   else if (g_sm == TND_MODE_LINE)
      o_put((const uint8_t *)"\r\n", 2u);
   if (m == TND_MODE_LINE)
      tnd_line_reset(&g_lm, true, g_out.mode);
   else
      tnd_out_session(&g_out);
   g_sm = m;
}

void fp_start(int setting, int beeb_mode, uint32_t now)
{
   tnd_in_reset(&g_in);
   tnd_out_reset(&g_out, true);
   tnd_out_assume_mode(&g_out, (uint8_t)beeb_mode);
   tnd_line_reset(&g_lm, true, (uint8_t)beeb_mode);
   g_setting = (uint8_t)setting;
   g_sm = TND_MODE_UNDECIDED;
   g_start = now;
   g_kh = g_kt = 0u;
   g_on = 0u;
   g_escape = g_break = 0;
   if (g_setting == TND_SET_LINE) {
      g_in.refuse_echo = true;
      g_in.echo_opt = g_in.sga_opt = TND_OPT_OFF;
   } else {
      uint8_t g[TND_GREETING_LEN];
      o_put(g, tnd_greeting(g));
   }
   decide(now);
}

static void key(uint8_t k)
{
   if (k == TND_KEY_ESCAPE) {
      g_kh = g_kt;
      g_escape = 1;
      tnd_line_escape(&g_lm);
   } else if (k == TND_KEY_BREAK) {
      g_kh = g_kt;
      g_break = 1;
      tnd_line_escape(&g_lm);
   } else if (k == TND_KEY_REFRESH) {
      /* the ROM's screen scan: not in the harness */
   } else if (g_kt - g_kh < RING) {
      g_ring[g_kt++ % RING] = k;
   }
}

void fp_client(const uint8_t *p, int n, uint32_t now)
{
   for (int i = 0; i < n; i++) {
      uint8_t keys[TND_IN_KEYS], rep[TND_IN_REPLY];
      size_t  rl, nk = tnd_in_byte(&g_in, p[i], now, keys, rep, &rl);
      o_put(rep, rl);
      if (g_setting == TND_SET_AUTO)
         decide(now);
      for (size_t j = 0; j < nk; j++)
         key(keys[j]);
   }
}

/* 0: hold the byte (the mode is not decided), 1: taken. */
int fp_beeb(uint8_t c, uint32_t now)
{
   if (g_sm == TND_MODE_UNDECIDED)
      return 0;
   if (g_sm == TND_MODE_LINE) {
      uint8_t d[TND_LINE_OUT_MAX], m[TND_OUT_MAX];
      (void)tnd_out_byte(&g_out, c, m);         /* the model follows too, as in the daemon */
      o_put(d, tnd_line_beeb(&g_lm, c, now, d));
   } else {
      uint8_t d[TND_OUT_MAX];
      o_put(d, tnd_out_byte(&g_out, c, d));
      tnd_out_touch(&g_out, now);
   }
   return 1;
}

/* The poll: returns how many keys (at most room) go to the Beeb now. */
int fp_poll(uint32_t now, uint8_t *keys, int room)
{
   int n = 0;

   if (g_setting == TND_SET_AUTO)
      decide(now);
   if (g_sm == TND_MODE_UNDECIDED)
      return 0;
   {
      uint8_t k[TND_IN_KEYS];
      size_t  nk = tnd_in_tick(&g_in, now, k);
      for (size_t j = 0; j < nk; j++)
         key(k[j]);
   }
   if (g_sm == TND_MODE_LINE) {
      uint8_t lb[TND_LINE_OUT_MAX];
      o_put(lb, tnd_line_tick(&g_lm, now, lb));
      if (tnd_line_ga_due(&g_lm, now, g_kh != g_kt) && tnd_ga_wanted(&g_in))
         o_put((const uint8_t *)"\xff\xf9", 2u);
      if ((size_t)room > tnd_line_room(&g_lm))
         room = (int)tnd_line_room(&g_lm);
   }
   while (n < room && g_kh != g_kt) {
      uint8_t k = g_ring[g_kh++ % RING];
      keys[n++] = k;
      if (g_sm == TND_MODE_LINE)
         tnd_line_typed(&g_lm, k, now);
   }
   return n;
}

int fp_out(uint8_t *buf, int max)
{
   int n = (int)g_on < max ? (int)g_on : max;
   memcpy(buf, g_ob, (size_t)n);
   memmove(g_ob, g_ob + n, g_on - (uint32_t)n);
   g_on -= (uint32_t)n;
   return n;
}

int fp_escape(void) { int e = g_escape; g_escape = 0; return e; }
int fp_mode(void)   { return g_sm; }
int fp_keys(void)   { return (int)(g_kt - g_kh); }

#ifdef FAKEPI_MAIN
/* The same, as a program on a pipe, for a driver that cannot load a shared library
   built here (beebium_run.py: Windows Python, this built in WSL).  One command a line,
   one answer a line:
      S <setting> <mode> <now>           start a session
      C <now> <hex>                      bytes from the client
      P <now> <room> <hex>               the Beeb's output since the last poll, and the poll
   answer: <beeb bytes taken> <keys hex or -> <client bytes hex or -> <escape> <mode> <keys queued> */
#include <stdio.h>
#include <stdlib.h>

static size_t unhex(const char *h, uint8_t *dst, size_t max)
{
   size_t n = 0;
   while (h[0] && h[1] && h[0] != '-' && n < max) {
      unsigned v;
      if (sscanf(h, "%2x", &v) != 1)
         break;
      dst[n++] = (uint8_t)v;
      h += 2;
   }
   return n;
}

static void hexout(const uint8_t *p, size_t n)
{
   if (n == 0)
      putchar('-');
   for (size_t i = 0; i < n; i++)
      printf("%02x", p[i]);
}

int main(void)
{
   static char    line[1 << 18];
   static uint8_t data[1 << 17], keys[2048], out[OUTB];

   setvbuf(stdout, NULL, _IOFBF, 1 << 16);
   while (fgets(line, sizeof line, stdin)) {
      unsigned long now = 0, a = 0, b = 0;
      char  hex[8];
      int   taken = 0, nk = 0;
      char *h = NULL;

      if (line[0] == 'S' && sscanf(line + 1, "%lu %lu %lu", &a, &b, &now) == 3) {
         fp_start((int)a, (int)b, (uint32_t)now);
      } else if (line[0] == 'C' && sscanf(line + 1, "%lu %7s", &now, hex) >= 1) {
         h = strchr(line + 2, ' ');
         size_t n = h ? unhex(h + 1, data, sizeof data) : 0;
         fp_client(data, (int)n, (uint32_t)now);
      } else if (line[0] == 'P' && sscanf(line + 1, "%lu %lu", &now, &a) == 2) {
         h = strchr(line + 2, ' ');
         h = h ? strchr(h + 1, ' ') : NULL;
         size_t n = h ? unhex(h + 1, data, sizeof data) : 0;
         while ((size_t)taken < n && fp_beeb(data[taken], (uint32_t)now))
            taken++;
         nk = fp_poll((uint32_t)now, keys, a > sizeof keys ? (int)sizeof keys : (int)a);
      }
      printf("%d ", taken);
      hexout(keys, (size_t)nk);
      putchar(' ');
      hexout(out, (size_t)fp_out(out, (int)sizeof out));
      printf(" %d %d %d\n", fp_escape(), fp_mode(), fp_keys());
      fflush(stdout);
   }
   return 0;
}
#endif
