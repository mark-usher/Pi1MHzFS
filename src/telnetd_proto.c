/*
  telnetd_proto.c - the telnet daemon's two byte translators (see the header)

  Client -> Beeb.  A telnet client sends keys as bytes, with IAC command
  sequences mixed in and the terminal's own escape sequences for the cursor and
  function keys.  What the Beeb's keyboard buffer wants is the byte the key
  would have produced there:

     CR NUL, CR LF, lone LF   -> 13
     BS, DEL                  -> 127   (the Beeb's DELETE)
     cursor left/right/down/up-> 140/141/142/143 in the keyboard buffer (what the
                                keyboard scan stores: 136-139 + 4; *FX4 and the
                                copy-cursor editing work from these)
     End                      -> 139   (COPY)     Delete -> 127
     F1-F9, F10               -> 129-137, 128 (f1-f9, f0; the MOS expands *KEY
                                definitions, as for the real keys)
     a lone ESC, Ctrl-C       -> TND_KEY_ESCAPE (the Beeb's ESCAPE condition; a
                                lone ESC is only that after TND_ESC_US with
                                nothing behind it)
     the pound sign           -> 96    (UTF-8 C2 A3, or Latin-1 A3)
     other bytes 0x80 and up  -> dropped
  Telnet negotiation is answered once per option, so a peer cannot start a loop:
  WILL ECHO/SGA and DO ECHO/SGA are ours; anything else is refused.

  Beeb -> terminal.  The Beeb's RS423 output (*FX3,1) is the VDU byte stream:
  text, plus control codes some of which take parameter bytes.  A terminal gets
  ANSI for the ones it can show, and the parameter bytes of all the others are
  swallowed.  Teletext colour codes (Mode 7) become colour changes.
*/
#include <string.h>
#include "net_telnet.h"
#include "telnetd_proto.h"

/* ---- client -> Beeb ---------------------------------------------------- */

enum { I_NORMAL, I_CR, I_IAC, I_OPT, I_SB, I_SBIAC, I_ESC, I_CSI, I_SS3, I_C2 };

#define ESC_STUCK_US  500000u    /* an escape sequence that never finished */

static bool seen(const uint8_t *map, uint8_t o)
{
   return (((unsigned)map[o >> 3] >> (o & 7u)) & 1u) != 0u;
}

static void mark(uint8_t *map, uint8_t o)
{
   map[o >> 3] = (uint8_t)(map[o >> 3] | (1u << (o & 7u)));
}

void tnd_in_reset(tnd_in_t *s)
{
   memset(s, 0, sizeof *s);
}

size_t tnd_greeting(uint8_t *out)
{
   static const uint8_t g[TND_GREETING_LEN] = {
      TN_IAC, TN_WILL, TN_OPT_ECHO,
      TN_IAC, TN_WILL, TN_OPT_SGA,
      TN_IAC, TN_DO,   TN_OPT_SGA
   };
   memcpy(out, g, sizeof g);
   return sizeof g;
}

/* A byte that is not part of a command or an escape sequence. */
static size_t plain_byte(tnd_in_t *s, uint8_t c, uint8_t *keys)
{
   if (s->state == I_CR) {
      s->state = I_NORMAL;
      if (c == 0u || c == '\n')                 /* the second half of CR NUL / CR LF */
         return 0u;
   } else if (s->state == I_C2) {
      s->state = I_NORMAL;
      if (c == 0xA3u) {                         /* UTF-8 pound sign */
         keys[0] = 96u;
         return 1u;
      }
      return 0u;                                /* any other two-byte character */
   }

   if (c == TN_IAC) {
      s->state = I_IAC;
      return 0u;
   }
   if (c == '\r') {
      s->state = I_CR;
      keys[0] = 13u;
      return 1u;
   }
   if (c == '\n') {
      keys[0] = 13u;
      return 1u;
   }
   if (c == 0u)
      return 0u;
   if (c == 3u) {                               /* Ctrl-C: what a terminal user means by ESCAPE */
      keys[0] = TND_KEY_ESCAPE;
      return 1u;
   }
   if (c == 12u) {                              /* Ctrl-L: what a terminal user means by "draw it again" */
      keys[0] = TND_KEY_REFRESH;
      return 1u;
   }
   if (c == 8u || c == 127u) {
      keys[0] = 127u;
      return 1u;
   }
   if (c == 0xC2u) {
      s->state = I_C2;
      return 0u;
   }
   if (c >= 0x80u) {
      if (c == 0xA3u) {                         /* Latin-1 pound sign */
         keys[0] = 96u;
         return 1u;
      }
      return 0u;
   }
   keys[0] = c;
   return 1u;
}

/* The Beeb key for a function key's CSI number (ESC [ n ~), 0 for none. */
static uint8_t fkey_csi(unsigned n)
{
   switch (n) {
   case 11: return 0x81u;  case 12: return 0x82u;  case 13: return 0x83u;
   case 14: return 0x84u;  case 15: return 0x85u;  case 17: return 0x86u;
   case 18: return 0x87u;  case 19: return 0x88u;  case 20: return 0x89u;
   case 21: return 0x80u;
   case 23: return TND_KEY_REFRESH;              /* F11 */
   case 24: return TND_KEY_BREAK;                /* F12 */
   default: return 0u;
   }
}

/* What the keyboard scan puts in the MOS keyboard buffer for the cursor keys
   and COPY: the codes GET returns under *FX4,1 (135-139) plus 4.  The MOS takes
   the 4 off again, or, with *FX4,0, treats them as copy-cursor editing - so
   these, and not 135-139, are what to insert (measured on a BBC B: inserting 139
   read back as 135, COPY). */
static uint8_t arrow(uint8_t f)
{
   switch (f) {
   case 'A': return 143u;                       /* up    */
   case 'B': return 142u;                       /* down  */
   case 'C': return 141u;                       /* right */
   case 'D': return 140u;                       /* left  */
   case 'F': return 139u;                       /* COPY  */
   default:  return 0u;
   }
}

/* The final byte of ESC [ params f. */
static uint8_t csi_key(const tnd_in_t *s, uint8_t f)
{
   if (f == '~') {
      switch (s->param[0]) {
      case 3: return 127u;
      case 4: case 8: return 139u;                /* End: COPY */
      default: return fkey_csi(s->param[0]);
      }
   }
   return arrow(f);
}

size_t tnd_in_byte(tnd_in_t *s, uint8_t c, uint32_t now_us,
                   uint8_t keys[TND_IN_KEYS], uint8_t rep[TND_IN_REPLY],
                   size_t *replen)
{
   *replen = 0u;

   switch (s->state) {
   case I_IAC:
      switch (c) {
      case TN_IAC:                              /* a literal 0xFF: not a Beeb key */
         s->state = I_NORMAL;
         break;
      case TN_WILL: case TN_WONT: case TN_DO: case TN_DONT:
         s->cmd = c;
         s->state = I_OPT;
         break;
      case TN_SB:
         s->state = I_SB;
         break;
      default:                                  /* NOP, AYT, GA, ... */
         s->state = I_NORMAL;
         break;
      }
      return 0u;

   case I_OPT:
      s->state = I_NORMAL;
      if (s->cmd == TN_DO) {
         if (c != TN_OPT_ECHO && c != TN_OPT_SGA && !seen(s->seen_do, c)) {
            mark(s->seen_do, c);
            rep[0] = TN_IAC; rep[1] = TN_WONT; rep[2] = c;
            *replen = 3u;
         }
      } else if (s->cmd == TN_WILL) {
         if (c != TN_OPT_SGA && !seen(s->seen_will, c)) {
            mark(s->seen_will, c);
            rep[0] = TN_IAC; rep[1] = TN_DONT; rep[2] = c;
            *replen = 3u;
         }
      }
      return 0u;

   case I_SB:
      if (c == TN_IAC)
         s->state = I_SBIAC;
      return 0u;

   case I_SBIAC:
      s->state = (c == TN_SE) ? I_NORMAL : I_SB;
      return 0u;

   case I_ESC:
      if (c == '[') {
         s->state = I_CSI;
         s->nparam = 0u;
         s->param[0] = s->param[1] = s->param[2] = 0u;
         return 0u;
      }
      if (c == 'O') {
         s->state = I_SS3;
         return 0u;
      }
      /* Not a sequence: the ESC was the ESCAPE key after all, and this byte is a key. */
      keys[0] = TND_KEY_ESCAPE;
      if (c == 27u) {                           /* ... or the start of the next one */
         s->esc_us = now_us;
         return 1u;
      }
      s->state = I_NORMAL;
      return 1u + plain_byte(s, c, keys + 1);

   case I_CSI:
      if (c >= '0' && c <= '9') {
         uint16_t v = (uint16_t)(s->param[s->nparam] * 10u + (unsigned)(c - '0'));
         s->param[s->nparam] = v > 999u ? 999u : v;
         return 0u;
      }
      if (c == ';') {
         if (s->nparam < 2u)
            s->nparam++;
         return 0u;
      }
      if (c >= 0x40u && c <= 0x7Eu) {           /* the final byte */
         uint8_t k = csi_key(s, c);
         s->state = I_NORMAL;
         if (k != 0u) {
            keys[0] = k;
            return 1u;
         }
      }
      return 0u;                                /* a parameter or intermediate byte */

   case I_SS3:
      s->state = I_NORMAL;
      if (c >= 'P' && c <= 'S') {               /* F1-F4 */
         keys[0] = (uint8_t)(0x81u + (unsigned)c - (unsigned)'P');
         return 1u;
      }
      {
         uint8_t k = arrow(c);
         if (k != 0u) {
            keys[0] = k;
            return 1u;
         }
      }
      return 0u;

   default:
      if (c == 27u) {
         s->state = I_ESC;
         s->esc_us = now_us;
         return 0u;
      }
      return plain_byte(s, c, keys);
   }
}

size_t tnd_in_tick(tnd_in_t *s, uint32_t now_us, uint8_t keys[TND_IN_KEYS])
{
   if (s->state == I_ESC && (now_us - s->esc_us) >= TND_ESC_US) {
      s->state = I_NORMAL;
      keys[0] = TND_KEY_ESCAPE;
      return 1u;
   }
   if ((s->state == I_CSI || s->state == I_SS3) && (now_us - s->esc_us) >= ESC_STUCK_US)
      s->state = I_NORMAL;
   return 0u;
}

/* ---- Beeb -> terminal ---------------------------------------------------- */

/* How many parameter bytes follow each VDU code (the Beeb User Guide's VDU
   table). */
static uint8_t vdu_params(uint8_t c)
{
   switch (c) {
   case 1:  return 1u;
   case 17: return 1u;
   case 18: return 2u;
   case 19: return 5u;
   case 22: return 1u;
   case 23: return 9u;
   case 24: return 8u;
   case 25: return 5u;
   case 28: return 4u;
   case 29: return 4u;
   case 31: return 2u;
   default: return 0u;
   }
}

#define AT_KNOWN 0x80u       /* the model has seen what is in this cell */
#define AT_DEF   0x40u       /* no colour was set: the terminal's own */

/* ---- the text screen model ---------------------------------------------------
   The terminal tracks its own cursor, which is enough while the Beeb prints
   along a line.  It is not enough once the Beeb's screen is a different size
   (the Beeb wraps at 40 columns in MODE 7, the terminal at 80 or more), scrolls
   inside its text window, or has the copy cursor, which the MOS moves without
   telling the RS423 stream.  So the model follows every VDU code, and the
   translator sends an absolute cursor position or a scroll wherever the
   terminal would otherwise drift.  Until a CLS, MODE, TAB or similar fixes the
   Beeb's cursor position the model does not know where it is, and the output is
   what it was before the model existed. */

/* What each logical colour shows as after a MODE: the Beeb's default palette. */
static void scr_default_palette(tnd_out_t *s)
{
   static const uint8_t four[4] = { 0u, 1u, 3u, 7u };     /* black, red, yellow, white */

   switch (s->mode) {
   case 0: case 3: case 4: case 6:              /* two colours */
      s->ncol = 2u;
      s->pal[0] = 0u; s->pal[1] = 7u;
      break;
   case 1: case 5:
      s->ncol = 4u;
      memcpy(s->pal, four, sizeof four);
      break;
   case 2:                                      /* sixteen, the upper eight flashing: shown steady */
      s->ncol = 16u;
      for (unsigned i = 0u; i < 16u; i++)
         s->pal[i] = (uint8_t)(i & 7u);
      break;
   default:                                     /* teletext: the colours are the colours */
      s->ncol = 8u;
      for (unsigned i = 0u; i < 16u; i++)
         s->pal[i] = (uint8_t)(i & 7u);
      break;
   }
}

/* The terminal's colour for a logical one. */
static uint8_t phys(const tnd_out_t *s, uint8_t logical)
{
   return (uint8_t)(s->pal[logical & 15u] & 7u);
}

void tnd_out_set_mode(tnd_out_t *s, uint8_t mode)
{
   static const uint8_t cols[8] = { 80u, 40u, 20u, 80u, 40u, 20u, 40u, 40u };
   static const uint8_t rows[8] = { 32u, 32u, 32u, 25u, 32u, 32u, 25u, 25u };

   mode &= 7u;                                  /* 128-135 are the shadow modes: the same sizes */
   s->mode = mode;
   s->cols = cols[mode];
   s->rows = rows[mode];
   s->tele = (mode == 7u);
   s->wl = 0u; s->wt = 0u;
   s->wr = (uint8_t)(s->cols - 1u);
   s->wb = (uint8_t)(s->rows - 1u);
   s->cx = s->cy = 0u;
   s->fg = 7u; s->bg = 0u;
   scr_default_palette(s);
   s->cc_on = s->hl_on = false;
   s->npend = 0u;
   memset(s->ch, ' ', sizeof s->ch);
   memset(s->at, AT_KNOWN | AT_DEF, sizeof s->at);
}

void tnd_out_assume_mode(tnd_out_t *s, uint8_t mode)
{
   tnd_out_set_mode(s, mode);
   memset(s->at, AT_DEF, sizeof s->at);          /* nothing on the screen is known yet */
   s->sync = false;
}

void tnd_out_at(tnd_out_t *s, uint8_t x, uint8_t y)
{
   if (x <= s->wr && y <= s->wb) {
      s->cx = x;
      s->cy = y;
      s->sync = true;
      s->colok = true;
   }
}

void tnd_out_reset(tnd_out_t *s, bool utf8)
{
   memset(s, 0, sizeof *s);
   s->utf8 = utf8;
   tnd_out_assume_mode(s, 7u);
   s->origin_ok = true;
}

void tnd_out_touch(tnd_out_t *s, uint32_t now_us)
{
   s->last_us = now_us;
}

void tnd_out_session(tnd_out_t *s)
{
   s->hl_on = false;
   s->cc_on = false;
   s->npend = 0u;                                /* (the Beeb's own colours, `coloured`, carry on) */
}

static size_t put_str(uint8_t *dst, const char *str);

static size_t put_str(uint8_t *dst, const char *str)
{
   size_t n = 0u;
   while (str[n] != '\0') {
      dst[n] = (uint8_t)str[n];
      n++;
   }
   return n;
}

/* ESC [ n m for a single-digit n. */
static size_t sgr(uint8_t *dst, char kind, uint8_t colour)
{
   dst[0] = 27u; dst[1] = '['; dst[2] = (uint8_t)kind;
   dst[3] = (uint8_t)('0' + (colour & 7u)); dst[4] = 'm';
   return 5u;
}

static size_t put_num(uint8_t *dst, unsigned v)
{
   size_t n = 0u;
   if (v >= 100u)
      dst[n++] = (uint8_t)('0' + v / 100u);
   if (v >= 10u)
      dst[n++] = (uint8_t)('0' + (v / 10u) % 10u);
   dst[n++] = (uint8_t)('0' + v % 10u);
   return n;
}

/* ESC [ row ; col H for the zero-based cell x, y. */
static size_t put_pos(uint8_t *dst, unsigned x, unsigned y)
{
   size_t n = 0u;
   dst[n++] = 27u;
   dst[n++] = '[';
   n += put_num(dst + n, y + 1u);
   dst[n++] = ';';
   n += put_num(dst + n, x + 1u);
   dst[n++] = 'H';
   return n;
}

/* An absolute cursor move.  If the terminal's rows are not the Beeb's yet (a terminal
   that was drawn under its greeting), it is cleared first, once, and they are. */
static size_t abs_pos(tnd_out_t *s, uint8_t *dst, unsigned x, unsigned y)
{
   size_t n = 0u;

   if (!s->origin_ok) {
      n += put_str(dst, "\x1b[2J");
      s->origin_ok = true;
   }
   n += put_pos(dst + n, x, y);
   return n;
}

static uint8_t cur_attr(const tnd_out_t *s)
{
   return s->coloured ? (uint8_t)((s->fg & 7u) | ((s->bg & 7u) << 3)) : AT_DEF;
}

/* The terminal's colours for a cell's attribute. */
static size_t put_attr(const tnd_out_t *s, uint8_t *dst, uint8_t at)
{
   size_t n = put_str(dst, "\x1b[0m");
   if ((at & AT_DEF) == 0u) {
      n += sgr(dst + n, '3', phys(s, at & 7u));
      if (phys(s, (uint8_t)((at >> 3) & 7u)) != 0u)
         n += sgr(dst + n, '4', phys(s, (uint8_t)((at >> 3) & 7u)));
   }
   return n;
}

/* A stored cell character as the terminal wants it: 96 is the Beeb's pound. */
static size_t put_glyph(const tnd_out_t *s, uint8_t *dst, uint8_t ch)
{
   if (ch == 96u) {
      if (s->utf8) {
         dst[0] = 0xC2u; dst[1] = 0xA3u;
         return 2u;
      }
      dst[0] = 0xA3u;
      return 1u;
   }
   dst[0] = ch;
   return 1u;
}

/* Put the terminal's colours back to what the Beeb has set, and its cursor to the Beeb's. */
static size_t put_finish(const tnd_out_t *s, uint8_t *dst)
{
   size_t n = put_pos(dst, s->cx, s->cy);
   n += put_str(dst + n, "\x1b[0m");
   if (s->coloured) {
      n += sgr(dst + n, '3', phys(s, s->fg));
      if (phys(s, s->bg) != 0u)
         n += sgr(dst + n, '4', phys(s, s->bg));
   }
   return n;
}

/* The terminal's colours set to the Beeb's: for a new terminal that is not being repainted. */
size_t tnd_out_colours(const tnd_out_t *s, uint8_t dst[16])
{
   size_t n = put_str(dst, "\x1b[0m");
   if (s->coloured) {
      n += sgr(dst + n, '3', phys(s, s->fg));
      if (phys(s, s->bg) != 0u)
         n += sgr(dst + n, '4', phys(s, s->bg));
   }
   return n;
}

static void scr_clear(tnd_out_t *s, unsigned x0, unsigned y0, unsigned x1, unsigned y1)
{
   for (unsigned y = y0; y <= y1; y++)
      for (unsigned x = x0; x <= x1; x++) {
         s->ch[y][x] = ' ';
         s->at[y][x] = AT_KNOWN | AT_DEF;
      }
}

/* Teletext starts every row white: a colour set on the row above does not carry
   over.  Called when the cursor goes to another row. */
static size_t row_changed(tnd_out_t *s, uint8_t *dst)
{
   if (s->tele && s->coloured) {
      s->coloured = false;
      s->fg = 7u;
      return put_str(dst, "\x1b[0m");
   }
   return 0u;
}

static bool full_width(const tnd_out_t *s)
{
   return s->wl == 0u && s->wr == s->cols - 1u;
}

/* The text window scrolls up one line.  The terminal is told to as well when the
   window is as wide as the screen; for a narrower one it is left to drift. */
static size_t scr_scroll_up(tnd_out_t *s, uint8_t *dst)
{
   size_t n = 0u;

   for (unsigned y = s->wt; y < s->wb; y++)
      for (unsigned x = s->wl; x <= s->wr; x++) {
         s->ch[y][x] = s->ch[y + 1u][x];
         s->at[y][x] = s->at[y + 1u][x];
      }
   scr_clear(s, s->wl, s->wb, s->wr, s->wb);
   if (s->hl_on) {
      if (s->hly > s->wt) s->hly--; else s->hl_on = false;
   }
   if (s->cc_on) {
      if (s->ccy > s->wt) s->ccy--; else s->cc_on = false;
   }
   if (s->sync && s->origin_ok && full_width(s)) {
      dst[n++] = 27u; dst[n++] = '[';
      n += put_num(dst + n, (unsigned)s->wt + 1u);
      dst[n++] = ';';
      n += put_num(dst + n, (unsigned)s->wb + 1u);
      dst[n++] = 'r';
      n += put_str(dst + n, "\x1b[1S\x1b[r");
   }
   return n;
}

static size_t scr_scroll_down(tnd_out_t *s, uint8_t *dst)
{
   size_t n = 0u;

   for (unsigned y = s->wb; y > s->wt; y--)
      for (unsigned x = s->wl; x <= s->wr; x++) {
         s->ch[y][x] = s->ch[y - 1u][x];
         s->at[y][x] = s->at[y - 1u][x];
      }
   scr_clear(s, s->wl, s->wt, s->wr, s->wt);
   if (s->hl_on) {
      if (s->hly < s->wb) s->hly++; else s->hl_on = false;
   }
   if (s->cc_on) {
      if (s->ccy < s->wb) s->ccy++; else s->cc_on = false;
   }
   if (s->sync && s->origin_ok && full_width(s)) {
      dst[n++] = 27u; dst[n++] = '[';
      n += put_num(dst + n, (unsigned)s->wt + 1u);
      dst[n++] = ';';
      n += put_num(dst + n, (unsigned)s->wb + 1u);
      dst[n++] = 'r';
      n += put_str(dst + n, "\x1b[1T\x1b[r");
   }
   return n;
}

/* The cursor moves to the start of the next line, scrolling at the bottom. */
static size_t scr_newline(tnd_out_t *s, uint8_t *dst)
{
   size_t n = 0u;

   s->cx = s->wl;
   if (s->cy >= s->wb)
      n += scr_scroll_up(s, dst + n);
   else
      s->cy++;
   if (s->sync && s->origin_ok) {
      n += row_changed(s, dst + n);
      n += put_pos(dst + n, s->cx, s->cy);
   } else if (s->colok) {                        /* the column is known: a CR LF is the Beeb's wrap */
      dst[n++] = 13u;
      dst[n++] = 10u;
      n += row_changed(s, dst + n);
   }
   return n;
}

static size_t finish_code(tnd_out_t *s, uint8_t dst[TND_OUT_MAX])
{
   uint8_t code = s->code;
   size_t  n = 0u;

   s->code = 0u;
   switch (code) {
   case 17:                                     /* COLOUR: 0-127 text, 128-255 background */
      if (s->p[0] < 128u) {
         s->fg = (uint8_t)(s->p[0] & (s->ncol - 1u));
         n = sgr(dst, '3', phys(s, s->fg));
      } else {
         s->bg = (uint8_t)((s->p[0] - 128u) & (s->ncol - 1u));
         n = sgr(dst, '4', phys(s, s->bg));
      }
      s->coloured = true;
      break;
   case 19:                                     /* palette: logical colour p0 shows as physical p1 */
      if (!s->tele) {
         s->pal[s->p[0] & (s->ncol - 1u)] = (uint8_t)(s->p[1] & 7u);
         if (s->coloured) {                     /* the colours already set may have changed */
            n += sgr(dst + n, '3', phys(s, s->fg));
            n += sgr(dst + n, '4', phys(s, s->bg));
         }
      }
      break;
   case 22:                                     /* MODE: the screen is cleared */
      if (s->coloured)
         n += put_str(dst + n, "\x1b[0m");
      tnd_out_set_mode(s, s->p[0]);
      s->sync = true;
      s->colok = true;
      s->origin_ok = true;
      s->coloured = false;
      n += put_str(dst + n, "\x1b[2J\x1b[H");
      break;
   case 23:                                     /* VDU 23,1,n: the cursor off (0) or on */
      if (s->p[0] == 1u) {
         s->curoff = (s->p[1] & 1u) == 0u;
         n = put_str(dst, s->curoff ? "\x1b[?25l" : "\x1b[?25h");
      }
      break;
   case 28: {                                   /* text window: left, bottom, right, top */
      unsigned l = s->p[0], b = s->p[1], r = s->p[2], t = s->p[3];
      if (l <= r && t <= b && r < s->cols && b < s->rows) {
         s->wl = (uint8_t)l; s->wb = (uint8_t)b; s->wr = (uint8_t)r; s->wt = (uint8_t)t;
         s->cx = s->wl; s->cy = s->wt;
         s->sync = true;
         s->colok = true;
         n += row_changed(s, dst + n);
         n += abs_pos(s, dst + n, s->cx, s->cy);
      }
      break;
   }
   case 31: {                                   /* TAB(x,y), relative to the text window */
      unsigned x = (unsigned)s->wl + s->p[0], y = (unsigned)s->wt + s->p[1];
      if (x <= s->wr && y <= s->wb) {
         s->cx = (uint8_t)x; s->cy = (uint8_t)y;
         s->sync = true;
         s->colok = true;
         n += row_changed(s, dst + n);
         n += abs_pos(s, dst + n, s->cx, s->cy);
      }
      break;
   }
   default:                                     /* the rest take parameters we ignore */
      break;
   }
   return n;
}

/* A character the Beeb prints, a cell at a time: what the terminal gets, what is
   remembered for the cell, and the colour it sets (teletext control codes). */
static size_t glyph(tnd_out_t *s, uint8_t c, uint8_t *dst, uint8_t *stored, int *newfg)
{
   size_t n;

   *newfg = -1;
   if (c < 127u) {
      *stored = c;
      return put_glyph(s, dst, c);
   }
   /* 128 and up.  Mode 7: 0x81-0x87 and 0x91-0x97 are colour codes, shown as a
      space; the other controls are spaces too.  From 0xA0 the teletext chip
      ignores bit 7 and shows the character. */
   if (c < 0xA0u) {
      uint8_t colour = (uint8_t)(c & 0x0Fu);   /* 0x81-0x87 alpha, 0x91-0x97 graphics */
      n = 0u;
      if (colour >= 1u && colour <= 7u && (c == (0x80u | colour) || c == (0x90u | colour))) {
         n = sgr(dst, '3', colour);
         *newfg = colour;
      }
      dst[n++] = ' ';
      *stored = ' ';
      return n;
   }
   {
      uint8_t ch = (uint8_t)(c & 0x7Fu);
      if (ch == 127u || ch < 32u)
         ch = ' ';
      *stored = ch;
      return put_glyph(s, dst, ch);
   }
}

size_t tnd_out_byte(tnd_out_t *s, uint8_t c, uint8_t dst[TND_OUT_MAX])
{
   size_t n = 0u;

   if (s->code != 0u) {                         /* a parameter byte of a VDU code */
      if (s->got < 4u)
         s->p[s->got] = c;
      s->got++;
      if (s->got >= vdu_params(s->code))
         return finish_code(s, dst);
      return 0u;
   }

   if (s->disabled) {                           /* VDU 21: only VDU 6 gets through */
      if (c == 6u)
         s->disabled = false;
      return 0u;
   }

   if (c < 32u) {
      switch (c) {
      case 6:
         break;
      case 7:  dst[n++] = 7u; break;
      case 8:                                   /* cursor left; at the edge, the end of the line above */
         if (s->cx > s->wl) {
            s->cx--;
            dst[n++] = 8u;
         } else if (s->cy > s->wt) {
            s->cx = s->wr;
            s->cy--;
            if (s->sync && s->origin_ok) {
               n += row_changed(s, dst + n);
               n += put_pos(dst + n, s->cx, s->cy);
            } else {
               dst[n++] = 8u;
            }
         } else {
            dst[n++] = 8u;
         }
         break;
      case 9:                                   /* cursor right; at the edge, the start of the next line */
         if (s->cx < s->wr) {
            s->cx++;
            n = put_str(dst, "\x1b[C");
         } else if (s->sync && s->origin_ok) {
            n += scr_newline(s, dst + n);
         } else {
            n = put_str(dst, "\x1b[C");
         }
         break;
      case 10:                                  /* down; at the bottom the window scrolls */
         if (s->cy >= s->wb) {
            n += scr_scroll_up(s, dst + n);
            if (s->sync && s->origin_ok)
               n += put_pos(dst + n, s->cx, s->cy);
            else
               dst[n++] = 10u;
         } else {
            s->cy++;
            dst[n++] = 10u;
            if (s->sync)
               n += row_changed(s, dst + n);
         }
         break;
      case 11:                                  /* up; at the top the window scrolls down */
         if (s->cy <= s->wt) {
            n += scr_scroll_down(s, dst + n);
            if (s->sync && s->origin_ok)
               n += put_pos(dst + n, s->cx, s->cy);
            else
               n += put_str(dst + n, "\x1b[A");
         } else {
            s->cy--;
            n = put_str(dst, "\x1b[A");
            if (s->sync)
               n += row_changed(s, dst + n);
         }
         break;
      case 12:                                  /* CLS: the window is cleared, the cursor to its corner */
         if (full_width(s) && s->wt == 0u && s->wb == s->rows - 1u) {
            scr_clear(s, 0u, 0u, (unsigned)s->cols - 1u, (unsigned)s->rows - 1u);
            s->sync = true;
         } else {
            scr_clear(s, s->wl, s->wt, s->wr, s->wb);
         }
         s->cx = s->wl; s->cy = s->wt;
         s->hl_on = s->cc_on = false;
         s->npend = 0u;
         s->colok = true;
         s->origin_ok = true;
         n = put_str(dst, "\x1b[2J\x1b[H");
         if (s->tele)
            s->coloured = false;
         break;
      case 13:
         s->cx = s->wl;
         s->colok = true;
         if (s->coloured && s->tele) {          /* teletext colour ends with the line; COLOUR does not */
            n = put_str(dst, "\x1b[0m");
            s->coloured = false;
            s->fg = 7u;
            s->bg = 0u;
         }
         dst[n++] = 13u;
         break;
      case 21: s->disabled = true; break;
      case 26:                                  /* default windows, cursor home */
         s->wl = 0u; s->wt = 0u;
         s->wr = (uint8_t)(s->cols - 1u);
         s->wb = (uint8_t)(s->rows - 1u);
         s->cx = 0u; s->cy = 0u;
         s->sync = true;
         s->colok = true;
         n += row_changed(s, dst + n);
         n += abs_pos(s, dst + n, 0u, 0u);
         break;
      case 30:                                  /* home: the corner of the text window */
         s->cx = s->wl; s->cy = s->wt;
         s->sync = true;
         s->colok = true;
         n += row_changed(s, dst + n);
         n += abs_pos(s, dst + n, s->cx, s->cy);
         break;
      default:
         if (vdu_params(c) != 0u) {
            s->code = c;
            s->got = 0u;
         }
         break;
      }
      return n;
   }

   if (c == 127u) {                             /* DELETE: back, blank, back */
      if (s->cx > s->wl) {
         s->cx--;
      } else if (s->cy > s->wt) {               /* from the start of a line: the end of the one above */
         s->cx = s->wr;
         s->cy--;
         s->ch[s->cy][s->cx] = ' ';
         s->at[s->cy][s->cx] = AT_KNOWN | cur_attr(s);
         if (s->sync && s->origin_ok) {
            n += put_pos(dst + n, s->cx, s->cy);
            dst[n++] = ' ';
            n += put_pos(dst + n, s->cx, s->cy);
            return n;
         }
         dst[0] = 8u; dst[1] = ' '; dst[2] = 8u;
         return 3u;
      }
      s->ch[s->cy][s->cx] = ' ';
      s->at[s->cy][s->cx] = AT_KNOWN | cur_attr(s);
      dst[0] = 8u; dst[1] = ' '; dst[2] = 8u;
      return 3u;
   }

   {
      uint8_t stored;
      int     newfg;
      uint8_t at = cur_attr(s);

      n = glyph(s, c, dst, &stored, &newfg);
      s->ch[s->cy][s->cx] = stored;
      s->at[s->cy][s->cx] = AT_KNOWN | at;
      if (newfg >= 0) {
         s->fg = (uint8_t)newfg;
         s->coloured = true;
      }
      if (s->cx < s->wr)
         s->cx++;
      else                                       /* the last column: on to the next line */
         n += scr_newline(s, dst + n);
      return n;
   }
}

/* ---- the copy cursor -------------------------------------------------------
   The BBC's cursor editing has two cursors: the one where typing goes, which is
   the terminal's cursor, and the copy cursor that the cursor keys move over the
   text and COPY copies from.  The MOS moves the second one itself and never
   sends it down the serial line, so the translator follows it from the keys the
   daemon sends and shows it as a reversed cell.  The keys are queued and acted
   on once the Beeb has been quiet for a moment, so that it is the write cursor
   after the echo of whatever was typed before. */

#define COPY_QUIET_US 40000u

bool tnd_out_blank(const tnd_out_t *s)
{
   for (unsigned y = 0u; y < s->rows; y++)
      for (unsigned x = 0u; x < s->cols; x++)
         if ((s->at[y][x] & AT_KNOWN) != 0u && s->ch[y][x] != ' ')
            return false;
   return true;
}

bool tnd_out_has_line(const tnd_out_t *s, const char *text, size_t len)
{
   if (len == 0u || len > s->cols)
      return false;
   for (unsigned y = 0u; y < s->rows; y++) {
      unsigned x = 0u;
      while (x < len && s->ch[y][x] == (uint8_t)text[x] && (s->at[y][x] & AT_KNOWN) != 0u)
         x++;
      if (x != len)
         continue;
      while (x < s->cols && s->ch[y][x] == ' ')
         x++;
      if (x == s->cols)
         return true;
   }
   return false;
}

void tnd_out_origin_lost(tnd_out_t *s)
{
   s->origin_ok = false;
   s->colok = true;                              /* the cursor's column is the Beeb's */
   s->hl_on = s->cc_on = false;
   s->npend = 0u;
}

size_t tnd_out_repaint(const tnd_out_t *s, unsigned row, uint8_t dst[TND_REPAINT_MAX])
{
   size_t n = 0u;
   int first = -1, last = -1;

   if (!s->sync)                                 /* the cursor is not known: nothing to draw under */
      return 0u;
   for (unsigned y = 0u; y < s->rows; y++)
      for (unsigned x = 0u; x < s->cols; x++)
         if ((s->at[y][x] & AT_KNOWN) != 0u && s->ch[y][x] != ' ') {
            if (first < 0)
               first = (int)y;
            last = (int)y;
            break;
         }
   if (first < 0 || (int)s->cy < first)
      first = (int)s->cy;
   if (last < (int)s->cy)
      last = (int)s->cy;

   if (row == s->rows) {                         /* the end: back to the Beeb's cursor and colours */
      if ((unsigned)last > s->cy) {
         dst[n++] = 27u; dst[n++] = '[';
         n += put_num(dst + n, (unsigned)last - s->cy);
         dst[n++] = 'A';
      }
      n += put_str(dst + n, "\x1b[0m");
      if (s->coloured) {
         n += sgr(dst + n, '3', phys(s, s->fg));
         if (phys(s, s->bg) != 0u)
            n += sgr(dst + n, '4', phys(s, s->bg));
      }
      n += put_str(dst + n, s->curoff ? "\x1b[?25l" : "\x1b[?25h");
      dst[n++] = 27u; dst[n++] = '[';           /* the column last: nothing follows it that a client */
      n += put_num(dst + n, (unsigned)s->cx + 1u);   /* might show as text ("[0m" after the prompt) */
      dst[n++] = 'G';
      return n;
   }
   if (row >= s->rows || (int)row < first || (int)row > last)
      return 0u;

   int end = -1;                                 /* the row, without its trailing blanks */
   for (unsigned x = 0u; x < s->cols; x++)
      if ((s->at[row][x] & AT_KNOWN) != 0u && s->ch[row][x] != ' ')
         end = (int)x;
   uint8_t prev = AT_DEF;
   n += put_str(dst + n, "\x1b[0m");
   for (int x = 0; x <= end; x++) {
      uint8_t at = (s->at[row][x] & AT_KNOWN) != 0u ? (uint8_t)(s->at[row][x] & ~AT_KNOWN) : AT_DEF;
      if (n + 24u > TND_REPAINT_MAX - 8u)
         break;                                  /* a row of colour changes at every cell: cut it off */
      if (at != prev) {
         n += put_attr(s, dst + n, at);
         prev = at;
      }
      n += put_glyph(s, dst + n, s->ch[row][x]);
   }
   n += put_str(dst + n, "\x1b[0m");
   if ((int)row < last) {
      dst[n++] = 13u;
      dst[n++] = 10u;
   }
   return n;
}

void tnd_out_copykey(tnd_out_t *s, uint8_t key)
{
   if (!s->sync)
      return;
   if (s->npend < sizeof s->pend)
      s->pend[s->npend++] = key;
}

static void cc_apply(tnd_out_t *s, uint8_t op)
{
   if (op == 13u || op == 27u) {                /* RETURN or ESCAPE ends the editing */
      s->cc_on = false;
      return;
   }
   if (!s->cc_on) {
      s->cc_on = true;
      s->ccx = s->cx;
      s->ccy = s->cy;
   }
   switch (op) {
   case 143u:                                   /* up */
      if (s->ccy > 0u) s->ccy--;
      break;
   case 142u:                                   /* down */
      if (s->ccy + 1u < s->rows) s->ccy++;
      break;
   case 140u:                                   /* left */
      if (s->ccx > 0u) {
         s->ccx--;
      } else if (s->ccy > 0u) {
         s->ccy--;
         s->ccx = (uint8_t)(s->cols - 1u);
      }
      break;
   case 141u:                                   /* right, and COPY: it moves on past what it copied */
   case 139u:
      if (s->ccx + 1u < s->cols) {
         s->ccx++;
      } else if (s->ccy + 1u < s->rows) {
         s->ccy++;
         s->ccx = 0u;
      }
      break;
   default:
      break;
   }
}

size_t tnd_out_copyflush(tnd_out_t *s, uint32_t now_us, uint8_t dst[TND_COPY_MAX])
{
   size_t n = 0u;

   if (s->npend == 0u)
      return 0u;
   if (!s->sync || !s->origin_ok) {              /* the marks are drawn at absolute positions */
      s->npend = 0u;
      return 0u;
   }
   if ((uint32_t)(now_us - s->last_us) < COPY_QUIET_US)
      return 0u;

   for (unsigned i = 0u; i < s->npend; i++)
      cc_apply(s, s->pend[i]);
   s->npend = 0u;

   if (s->hl_on) {                              /* the old mark goes: the cell as it was */
      n += put_pos(dst + n, s->hlx, s->hly);
      n += put_attr(s, dst + n, s->at[s->hly][s->hlx]);
      n += put_glyph(s, dst + n, s->ch[s->hly][s->hlx]);
      s->hl_on = false;
   }
   if (s->cc_on && (s->ccx != s->cx || s->ccy != s->cy)
       && (s->at[s->ccy][s->ccx] & AT_KNOWN) != 0u) {
      n += put_pos(dst + n, s->ccx, s->ccy);
      n += put_attr(s, dst + n, s->at[s->ccy][s->ccx]);
      n += put_str(dst + n, "\x1b[7m");
      n += put_glyph(s, dst + n, s->ch[s->ccy][s->ccx]);
      s->hl_on = true;
      s->hlx = s->ccx;
      s->hly = s->ccy;
   }
   if (n != 0u)
      n += put_finish(s, dst + n);
   return n;
}

bool tnd_stalled(bool pending, uint32_t now_us, uint32_t progress_us, uint32_t limit_us)
{
   return pending && (uint32_t)(now_us - progress_us) >= limit_us;
}
