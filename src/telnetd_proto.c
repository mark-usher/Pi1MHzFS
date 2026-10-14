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

enum { I_NORMAL, I_CR, I_IAC, I_OPT, I_SB, I_SBIAC, I_ESC, I_CSI, I_SS3, I_C2, I_DCS0, I_DCS, I_DCSESC };

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

/* The final byte of ESC [ params f.  Shell mode (edit_keys) also has Home (ESC [ 1 ~,
   ESC [ 7 ~, ESC [ H) and Delete as the key that deletes forwards (ESC [ 3 ~). */
static uint8_t csi_key(const tnd_in_t *s, uint8_t f)
{
   if (f == '~') {
      switch (s->param[0]) {
      case 3: return s->edit_keys ? TND_KEY_DELFWD : 127u;
      case 4: case 8: return 139u;                /* End: COPY */
      case 1: case 7: return s->edit_keys ? TND_KEY_HOME : 0u;
      default: return fkey_csi(s->param[0]);
      }
   }
   if (f == 'H' && s->edit_keys)
      return TND_KEY_HOME;
   return arrow(f);
}

/* The terminal's name, in its answer to XTVERSION (CSI > q): "|XTerm(379)" from xterm, which has a
   Tektronix 4014 mode for the Beeb's graphics. */
static void tnd_in_dcs_done(tnd_in_t *s)
{
   static const char xt[] = "|XTerm(";
   if (s->ndcs >= sizeof xt - 1u && memcmp(s->dcs, xt, sizeof xt - 1u) == 0)
      s->xterm = true;
}

size_t tnd_in_byte(tnd_in_t *s, uint8_t c, uint32_t now_us,
                   uint8_t keys[TND_IN_KEYS], uint8_t rep[TND_IN_REPLY],
                   size_t *replen)
{
   *replen = 0u;

   switch (s->state) {
   case I_IAC:
      if (c != TN_IAC)
         s->telnet = true;                      /* a command: the client speaks telnet */
      switch (c) {
      case TN_IAC:                              /* a literal 0xFF: not a Beeb key */
         s->state = I_NORMAL;
         s->data = true;
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
         if (c == TN_OPT_ECHO && s->refuse_echo) {  /* line mode by the setting: the client echoes */
            s->echo_opt = TND_OPT_OFF;
            if (!seen(s->seen_do, c)) {
               mark(s->seen_do, c);
               rep[0] = TN_IAC; rep[1] = TN_WONT; rep[2] = c;
               *replen = 3u;
            }
         } else if (c == TN_OPT_ECHO || c == TN_OPT_SGA) {
            /* Our offer accepted needs no reply; asked for again after a DONT, it is
               agreed to (RFC 854: a reply only where the state changes). */
            uint8_t *o = (c == TN_OPT_ECHO) ? &s->echo_opt : &s->sga_opt;
            if (*o == TND_OPT_OFF) {
               rep[0] = TN_IAC; rep[1] = TN_WILL; rep[2] = c;
               *replen = 3u;
            }
            *o = TND_OPT_ON;
         } else if (!seen(s->seen_do, c)) {
            mark(s->seen_do, c);
            rep[0] = TN_IAC; rep[1] = TN_WONT; rep[2] = c;
            *replen = 3u;
         }
      } else if (s->cmd == TN_DONT) {
         if (c == TN_OPT_ECHO || c == TN_OPT_SGA) {
            /* Refusing the offer needs no reply; turning it off once it was on is
               acknowledged (WONT), as RFC 854 asks. */
            uint8_t *o = (c == TN_OPT_ECHO) ? &s->echo_opt : &s->sga_opt;
            if (*o == TND_OPT_ON) {
               rep[0] = TN_IAC; rep[1] = TN_WONT; rep[2] = c;
               *replen = 3u;
            }
            *o = TND_OPT_OFF;
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
      if (c == 'P') {                           /* a DCS: the terminal answering CSI > q, or Alt-P */
         s->state = I_DCS0;
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

   case I_DCS0:                                 /* only a reply to CSI > q is taken as one: DCS > | ... */
      if (c == '>') {
         s->state = I_DCS;
         s->ndcs = 0u;
         return 0u;
      }
      s->state = I_NORMAL;                      /* ESC P was Alt-P: the ESCAPE key, a P, and this */
      keys[0] = TND_KEY_ESCAPE;
      {
         size_t k = 1u + plain_byte(s, 'P', keys + 1);
         if (c == 27u) {                         /* ... or the start of the next sequence */
            s->state = I_ESC;
            s->esc_us = now_us;
         } else if (k < TND_IN_KEYS) {
            k += plain_byte(s, c, keys + k);
         }
         return k;
      }

   case I_DCS:                                  /* up to the string terminator (ESC \, or BEL) */
      if (c == 27u) {
         s->state = I_DCSESC;
      } else if (c == 7u) {
         s->state = I_NORMAL;
         tnd_in_dcs_done(s);
      } else if (s->ndcs < sizeof s->dcs) {
         s->dcs[s->ndcs++] = c;
      }
      return 0u;

   case I_DCSESC:
      s->state = I_NORMAL;
      tnd_in_dcs_done(s);
      return 0u;

   case I_SS3:
      s->state = I_NORMAL;
      if (c >= 'P' && c <= 'S') {               /* F1-F4 */
         keys[0] = (uint8_t)(0x81u + (unsigned)c - (unsigned)'P');
         return 1u;
      }
      {
         uint8_t k = (c == 'H' && s->edit_keys) ? TND_KEY_HOME : arrow(c);
         if (k != 0u) {
            keys[0] = k;
            return 1u;
         }
      }
      return 0u;

   default:
      if (c != TN_IAC)
         s->data = true;                        /* not negotiation: a key */
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
   if ((s->state == I_CSI || s->state == I_SS3 || s->state == I_DCS || s->state == I_DCSESC)
       && (now_us - s->esc_us) >= ESC_STUCK_US)
      s->state = I_NORMAL;
   if (s->state == I_DCS0 && (now_us - s->esc_us) >= TND_ESC_US) {   /* Alt-P with nothing after it */
      s->state = I_NORMAL;
      keys[0] = TND_KEY_ESCAPE;
      return 1u + plain_byte(s, 'P', keys + 1);
   }
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
#define TTX_SGR_PLAIN 0x07u  /* MODE 7, the terminal's colours: white on black, steady, its own (ESC [0m) */
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
   s->dirty = false;                             /* a new screen: nothing left to draw again */
   memset(s->ch, ' ', sizeof s->ch);
   memset(s->at, AT_KNOWN | AT_DEF, sizeof s->at);
   memset(s->lattr, 0, sizeof s->lattr);
   s->tsgr = TTX_SGR_PLAIN;
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
   s->tsgr = 0xFFu;                              /* a new terminal: its colours are not known */
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

/* ---- teletext (MODE 7) ------------------------------------------------------
   The SAA5050 draws a row from left to right, and what a cell shows depends on
   the control codes to its left: each row starts white on black, alphanumerics,
   single height, and a control code changes that for the cells after it (colours,
   graphics, flash, double height, release) or from its own cell (new and black
   background, steady, normal height, conceal, contiguous and separated, hold).  A
   control code's own cell is a space, or under hold graphics the last mosaic.

   So once the model knows where the cursor is, each MODE 7 cell holds the byte
   the screen holds (the MOS swaps #, _ and the pound as it stores them) and is
   drawn from the state of the cells to its left: a character is one cell, a
   control code (or a cell that held one) redraws the rest of its row.  Mosaics
   are Unicode's sextants (the block U+1FB00, with the half and full blocks that
   Unicode already had); the characters the SAA5050 has in place of ASCII are
   their Unicode ones; double height is the terminal's double height line
   (DECDHL), the first such row of a pair the top half, the next the bottom, as
   the Beeb pairs them.  A terminal that does not do UTF-8 gets Latin-1 or a near
   ASCII character. */

typedef struct {
   uint8_t fg, bg, held;
   bool    gfx, sep, hold, flash, conceal, dh;
} ttx_t;

static void ttx_init(ttx_t *t)
{
   memset(t, 0, sizeof *t);
   t->fg = 7u;
   t->held = ' ';
}

/* The byte MODE 7's screen holds for one the Beeb printed. */
static uint8_t ttx_store(uint8_t c)
{
   if (c >= 0xA0u)
      return (uint8_t)(c & 0x7Fu);              /* the chip ignores bit 7 from &A0 */
   switch (c) {
   case 35u: return 0x5Fu;                      /* # */
   case 95u: return 0x60u;                      /* _ (a long dash on the screen) */
   case 96u: return 0x23u;                      /* the pound */
   default:  return c;
   }
}

static uint32_t ttx_mosaic(uint8_t b)
{
   unsigned v = (b & 0x1Fu) | ((b & 0x40u) >> 1);   /* bits 0-5: the six cells, top left first */
   if (v == 0u)  return ' ';
   if (v == 63u) return 0x2588u;                /* full block */
   if (v == 21u) return 0x258Cu;                /* left half */
   if (v == 42u) return 0x2590u;                /* right half */
   return 0x1FB00u + (v - 1u) - (v > 21u ? 1u : 0u) - (v > 42u ? 1u : 0u);
}

static uint32_t ttx_alpha(uint8_t b)
{
   switch (b) {
   case 0x23u: return 0xA3u;                    /* pound */
   case 0x5Bu: return 0x2190u;                  /* left arrow */
   case 0x5Cu: return 0xBDu;                    /* one half */
   case 0x5Du: return 0x2192u;                  /* right arrow */
   case 0x5Eu: return 0x2191u;                  /* up arrow */
   case 0x5Fu: return '#';
   case 0x60u: return 0x2015u;                  /* long dash */
   case 0x7Bu: return 0xBCu;                    /* one quarter */
   case 0x7Cu: return 0x2016u;                  /* double bar */
   case 0x7Du: return 0xBEu;                    /* three quarters */
   case 0x7Eu: return 0xF7u;                    /* divide */
   case 0x7Fu: return 0x25A0u;                  /* block */
   default:    return (b >= 0x20u && b < 0x7Fu) ? b : ' ';
   }
}

/* One cell: what it shows (in *cp) with which colours, and the state after it. */
static void ttx_step(ttx_t *t, uint8_t b, uint32_t *cp, uint8_t *fg, uint8_t *bg, bool *flash)
{
   if (b >= 0x80u && b < 0xA0u) {
      switch (b) {                              /* set at: from this cell */
      case 0x89u: t->flash = false; break;
      case 0x8Cu: if (t->dh) { t->dh = false; t->held = ' '; } break;
      case 0x98u: t->conceal = true; break;
      case 0x99u: t->sep = false; break;
      case 0x9Au: t->sep = true; break;
      case 0x9Cu: t->bg = 0u; break;
      case 0x9Du: t->bg = t->fg; break;
      case 0x9Eu: t->hold = true; break;
      default: break;
      }
      *cp = (t->hold && t->gfx) ? ttx_mosaic(t->held) : ' ';
      *fg = t->fg; *bg = t->bg; *flash = t->flash;
      if (b >= 0x81u && b <= 0x87u) {           /* set after: from the next cell */
         t->fg = (uint8_t)(b & 7u);
         if (t->gfx) t->held = ' ';
         t->gfx = false;
         t->conceal = false;
      } else if (b >= 0x91u && b <= 0x97u) {
         t->fg = (uint8_t)(b & 7u);
         if (!t->gfx) t->held = ' ';
         t->gfx = true;
         t->conceal = false;
      } else if (b == 0x88u) {
         t->flash = true;
      } else if (b == 0x8Du) {
         if (!t->dh) t->held = ' ';
         t->dh = true;
      } else if (b == 0x9Fu) {
         t->hold = false;
      }
      return;
   }
   if (t->gfx && (b & 0x20u) != 0u) {
      *cp = ttx_mosaic(b);
      t->held = b;
   } else {
      *cp = ttx_alpha(b);                       /* in graphics, &40-&5F blast through as capitals */
   }
   if (t->conceal)
      *cp = ' ';
   *fg = t->fg; *bg = t->bg; *flash = t->flash;
}

/* The state at the start of cell x of a row. */
static void ttx_state(const tnd_out_t *s, unsigned y, unsigned x, ttx_t *t)
{
   uint32_t cp; uint8_t fg, bg; bool fl;
   ttx_init(t);
   for (unsigned i = 0u; i < x; i++)
      ttx_step(t, s->ch[y][i], &cp, &fg, &bg, &fl);
}

static size_t put_cp(bool utf8, uint8_t *dst, uint32_t cp);

static size_t ttx_put_cp(const tnd_out_t *s, uint8_t *dst, uint32_t cp)
{
   return put_cp(s->utf8, dst, cp);
}

/* A character as UTF-8, or Latin-1 / the nearest ASCII. */
static size_t put_cp(bool utf8, uint8_t *dst, uint32_t cp)
{
   if (cp < 0x80u) {
      dst[0] = (uint8_t)cp;
      return 1u;
   }
   if (!utf8) {
      if (cp <= 0xFFu) {
         dst[0] = (uint8_t)cp;
         return 1u;
      }
      switch (cp) {
      case 0x2190u: dst[0] = '<'; break;
      case 0x2192u: dst[0] = '>'; break;
      case 0x2191u: dst[0] = '^'; break;
      case 0x2015u: dst[0] = '-'; break;
      case 0x2016u: dst[0] = '|'; break;
      default:      dst[0] = '#'; break;      /* the block and the mosaics */
      }
      return 1u;
   }
   if (cp < 0x800u) {
      dst[0] = (uint8_t)(0xC0u | (cp >> 6));
      dst[1] = (uint8_t)(0x80u | (cp & 0x3Fu));
      return 2u;
   }
   if (cp < 0x10000u) {
      dst[0] = (uint8_t)(0xE0u | (cp >> 12));
      dst[1] = (uint8_t)(0x80u | ((cp >> 6) & 0x3Fu));
      dst[2] = (uint8_t)(0x80u | (cp & 0x3Fu));
      return 3u;
   }
   dst[0] = (uint8_t)(0xF0u | (cp >> 18));
   dst[1] = (uint8_t)(0x80u | ((cp >> 12) & 0x3Fu));
   dst[2] = (uint8_t)(0x80u | ((cp >> 6) & 0x3Fu));
   dst[3] = (uint8_t)(0x80u | (cp & 0x3Fu));
   return 4u;
}

/* The terminal's colours for a cell, if they are not what it has. */
static size_t ttx_sgr(uint8_t *tsgr, uint8_t *dst, uint8_t fg, uint8_t bg, bool flash)
{
   uint8_t key = (uint8_t)((fg & 7u) | ((bg & 7u) << 3) | (flash ? 0x40u : 0u));
   size_t  n = 0u;

   if (key == *tsgr)
      return 0u;
   *tsgr = key;
   if (fg == 7u && bg == 0u && !flash)
      return put_str(dst, "\x1b[0m");
   n += put_str(dst, "\x1b[0;3");
   dst[n++] = (uint8_t)('0' + (fg & 7u));
   if (bg != 0u) {
      n += put_str(dst + n, ";4");
      dst[n++] = (uint8_t)('0' + (bg & 7u));
   }
   if (flash)
      n += put_str(dst + n, ";5");
   dst[n++] = 'm';
   return n;
}

/* Cells x0 to x1 of row y, from the terminal's cursor on, *tsgr the colours the terminal
   has: at most room bytes.  Returns the bytes written; *done is the last cell drawn (x0 - 1
   if none fitted). */
static size_t ttx_cells(const tnd_out_t *s, uint8_t *tsgr, uint8_t *dst, unsigned y, unsigned x0, unsigned x1,
                        size_t room, unsigned *done)
{
   ttx_t    t;
   size_t   n = 0u;
   uint32_t cp; uint8_t fg, bg; bool fl;

   ttx_state(s, y, x0, &t);
   *done = x0 - 1u;
   for (unsigned x = x0; x <= x1; x++) {
      uint8_t buf[24];
      size_t  k;
      ttx_step(&t, s->ch[y][x], &cp, &fg, &bg, &fl);
      uint8_t save = *tsgr;
      k = ttx_sgr(tsgr, buf, fg, bg, fl);
      k += ttx_put_cp(s, buf + k, cp);
      if (n + k > room) {
         *tsgr = save;
         break;
      }
      memcpy(dst + n, buf, k);
      n += k;
      *done = x;
   }
   return n;
}

/* The last cell of row y that shows something (a character, or a background colour), or -1. */
static int ttx_row_end(const tnd_out_t *s, unsigned y)
{
   ttx_t t; uint32_t cp; uint8_t fg, bg; bool fl;
   int   end = -1;
   ttx_init(&t);
   for (unsigned x = 0u; x < s->cols; x++) {
      ttx_step(&t, s->ch[y][x], &cp, &fg, &bg, &fl);
      if (cp != ' ' || bg != 0u)
         end = (int)x;
   }
   return end;
}

/* Is any cell of row y a double height one?  And does it use hold graphics? */
static bool ttx_row_dh(const tnd_out_t *s, unsigned y)
{
   ttx_t t; uint32_t cp; uint8_t fg, bg; bool fl;
   ttx_init(&t);
   for (unsigned x = 0u; x < s->cols; x++) {
      ttx_step(&t, s->ch[y][x], &cp, &fg, &bg, &fl);
      if (t.dh)
         return true;
   }
   return false;
}

static bool ttx_row_hold(const tnd_out_t *s, unsigned y)
{
   for (unsigned x = 0u; x < s->cols; x++)
      if (s->ch[y][x] == 0x9Eu)
         return true;
   return false;
}

/* The line attribute each row should have: a double height row is the top half, unless
   the row above is a top half, when it is the bottom. */
static uint8_t ttx_lattr(const tnd_out_t *s, unsigned y)
{
   uint8_t prev = 0u;
   for (unsigned r = 0u; r <= y; r++) {
      uint8_t a = ttx_row_dh(s, r) ? (prev == 3u ? 4u : 3u) : 0u;
      if (r == y)
         return a;
      prev = a;
   }
   return 0u;
}

static size_t ttx_put_lattr(uint8_t *dst, uint8_t a)
{
   return put_str(dst, a == 3u ? "\x1b#3" : a == 4u ? "\x1b#4" : "\x1b#5");
}

/* Bring the terminal's line attributes into line with the model's rows, the cursor put back
   after.  Needs absolute positions. */
static size_t ttx_sync_lattr(tnd_out_t *s, uint8_t *dst, size_t room)
{
   size_t n = 0u;
   bool   moved = false;
   uint8_t prev = 0u;

   if (!s->tele || !s->sync || !s->origin_ok)
      return 0u;
   for (unsigned y = 0u; y < s->rows; y++) {
      uint8_t a = ttx_row_dh(s, y) ? (prev == 3u ? 4u : 3u) : 0u;
      prev = a;
      if (a == s->lattr[y])
         continue;
      if (n + 16u > room)
         break;
      n += put_pos(dst + n, 0u, y);
      n += ttx_put_lattr(dst + n, a);
      s->lattr[y] = a;
      moved = true;
   }
   if (moved)
      n += put_pos(dst + n, s->cx, s->cy);
   return n;
}

/* Back to single width and height on every row the terminal has a line attribute on
   (before the screen is cleared: a terminal may keep them through a clear). */
static size_t ttx_clear_lattr(tnd_out_t *s, uint8_t *dst)
{
   size_t n = 0u;
   for (unsigned y = 0u; y < TND_ROWS_MAX; y++)
      if (s->lattr[y] != 0u) {
         n += put_pos(dst + n, 0u, y);
         n += put_str(dst + n, "\x1b#5");
         s->lattr[y] = 0u;
      }
   return n;
}

/* MODE 7: the terminal's own colours again, if a cell left it with others, before anything that
   fills with the background colour (a clear, a scroll). */
static size_t ttx_plain(tnd_out_t *s, uint8_t *dst)
{
   if (!s->tele || s->tsgr == TTX_SGR_PLAIN)
      return 0u;
   s->tsgr = TTX_SGR_PLAIN;
   return put_str(dst, "\x1b[0m");
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

/* A rectangle the terminal now shows wrong, to be drawn again from the model. */
static void mark_dirty(tnd_out_t *s, unsigned l, unsigned t, unsigned r, unsigned b)
{
   if (!s->dirty) {
      s->dl = (uint8_t)l; s->dt = (uint8_t)t; s->dr = (uint8_t)r; s->db = (uint8_t)b;
      s->dirty = true;
      return;
   }
   if (l < s->dl) s->dl = (uint8_t)l;
   if (t < s->dt) s->dt = (uint8_t)t;
   if (r > s->dr) s->dr = (uint8_t)r;
   if (b > s->db) s->db = (uint8_t)b;
}

/* The text window scrolls up one line.  The terminal is told to as well when the
   window is as wide as the screen; a narrower one is drawn again (tnd_out_dirty_row). */
static size_t scr_scroll_up(tnd_out_t *s, uint8_t *dst)
{
   size_t n = 0u;

   for (unsigned y = s->wt; y < s->wb; y++)
      for (unsigned x = s->wl; x <= s->wr; x++) {
         s->ch[y][x] = s->ch[y + 1u][x];
         s->at[y][x] = s->at[y + 1u][x];
      }
   scr_clear(s, s->wl, s->wb, s->wr, s->wb);
   if (full_width(s)) {                          /* the terminal's lines move with their attributes */
      for (unsigned y = s->wt; y < s->wb; y++)
         s->lattr[y] = s->lattr[y + 1u];
      s->lattr[s->wb] = 0u;
   }
   if (s->hl_on) {
      if (s->hly > s->wt) s->hly--; else s->hl_on = false;
   }
   if (s->cc_on) {
      if (s->ccy > s->wt) s->ccy--; else s->cc_on = false;
   }
   if (s->sync && s->origin_ok && full_width(s)) {
      n += ttx_plain(s, dst + n);
      dst[n++] = 27u; dst[n++] = '[';
      n += put_num(dst + n, (unsigned)s->wt + 1u);
      dst[n++] = ';';
      n += put_num(dst + n, (unsigned)s->wb + 1u);
      dst[n++] = 'r';
      n += put_str(dst + n, "\x1b[1S\x1b[r");
      n += ttx_sync_lattr(s, dst + n, 200u);     /* a scroll can change which half a double row is */
   } else if (s->sync && s->origin_ok) {
      mark_dirty(s, s->wl, s->wt, s->wr, s->wb);
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
   if (full_width(s)) {
      for (unsigned y = s->wb; y > s->wt; y--)
         s->lattr[y] = s->lattr[y - 1u];
      s->lattr[s->wt] = 0u;
   }
   if (s->hl_on) {
      if (s->hly < s->wb) s->hly++; else s->hl_on = false;
   }
   if (s->cc_on) {
      if (s->ccy < s->wb) s->ccy++; else s->cc_on = false;
   }
   if (s->sync && s->origin_ok && full_width(s)) {
      n += ttx_plain(s, dst + n);
      dst[n++] = 27u; dst[n++] = '[';
      n += put_num(dst + n, (unsigned)s->wt + 1u);
      dst[n++] = ';';
      n += put_num(dst + n, (unsigned)s->wb + 1u);
      dst[n++] = 'r';
      n += put_str(dst + n, "\x1b[1T\x1b[r");
      n += ttx_sync_lattr(s, dst + n, 200u);     /* a scroll can change which half a double row is */
   } else if (s->sync && s->origin_ok) {
      mark_dirty(s, s->wl, s->wt, s->wr, s->wb);
   }
   return n;
}

/* After a CR the terminal is at column 0: a text window's left edge may be further in. */
static size_t put_left(const tnd_out_t *s, uint8_t *dst)
{
   size_t n = 0u;
   if (s->wl != 0u) {
      dst[n++] = 27u; dst[n++] = '[';
      n += put_num(dst + n, s->wl);
      dst[n++] = 'C';
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
      n += put_left(s, dst + n);
      n += row_changed(s, dst + n);
   }
   return n;
}

/* A character the Beeb prints in MODE 7, the cursor known: stored as the screen holds it and
   drawn - the one cell, or for a control code (or over one, or in a row with hold graphics) the
   rest of the row - and the cursor moved on.  What does not fit is drawn later (the dirty rows). */
static size_t ttx_glyph(tnd_out_t *s, uint8_t c, uint8_t *dst)
{
   uint8_t  b = ttx_store(c);
   uint8_t  old = s->ch[s->cy][s->cx];
   bool     ctl = (b >= 0x80u && b < 0xA0u) || (old >= 0x80u && old < 0xA0u);
   unsigned end = s->cx, done;
   int      before = (ctl || ttx_row_hold(s, s->cy)) ? ttx_row_end(s, s->cy) : -1;
   size_t   n;

   s->ch[s->cy][s->cx] = b;
   s->at[s->cy][s->cx] = AT_KNOWN | AT_DEF;
   if (ctl || (old != b && ttx_row_hold(s, s->cy))) {   /* the rest of the row, as far as it shows anything */
      int after = ttx_row_end(s, s->cy);
      int last = before > after ? before : after;
      if (last > (int)end)
         end = (unsigned)last;
   }
   n = 0u;
   if (b == 0x8Du || old == 0x8Du)              /* first: it leaves the cursor on this cell */
      n += ttx_sync_lattr(s, dst, 200u);
   n += ttx_cells(s, &s->tsgr, dst + n, s->cy, s->cx, end, TND_OUT_MAX - 160u - n, &done);
   if (done < end && s->origin_ok)
      mark_dirty(s, done + 1u, s->cy, end, s->cy);
   if (end > s->cx && s->cx < s->wr) {          /* back to the cell after this one */
      dst[n++] = 27u; dst[n++] = '[';
      n += put_num(dst + n, (unsigned)s->cx + 2u);
      dst[n++] = 'G';
   }
   if (s->cx < s->wr)
      s->cx++;
   else
      n += scr_newline(s, dst + n);
   return n;
}

/* ---- graphics: xterm's Tektronix 4014 mode -----------------------------------------
   MOVE, DRAW and PLOT (VDU 25) cannot be text, but xterm still has the storage tube
   terminal it grew out of: CSI ? 38 h puts it in Tektronix mode (its Tek window), GS
   starts a vector at the first point and draws to each one after, ESC FF clears the
   page, and ESC ETX goes back to the text screen.  The Beeb's 1280 x 1024 is the Tek's
   1024 x 780.  A storage tube cannot rub out, so drawing in the background colour or
   inverting (PLOT 2, 3, 6, 7) only moves.  Lines, points, triangles (outlined) and
   rectangles (outlined, the Master's PLOT 96) are drawn; the rest moves. */

void tnd_out_tek(tnd_out_t *s, bool on)
{
   s->tek = on;
}

static size_t tek_enter(tnd_out_t *s, uint8_t *dst)
{
   if (s->tek_on)
      return 0u;
   s->tek_on = true;
   return put_str(dst, "\x1b[?38h");
}

static size_t tek_leave(tnd_out_t *s, uint8_t *dst)
{
   if (!s->tek_on)
      return 0u;
   s->tek_on = false;
   s->tsgr = 0xFFu;
   return put_str(dst, "\x1b\x03");
}

static size_t tek_xy(uint8_t *dst, int x, int y)
{
   int tx = x * 1024 / 1280, ty = y * 780 / 1024;
   if (tx < 0) tx = 0;
   if (tx > 1023) tx = 1023;
   if (ty < 0) ty = 0;
   if (ty > 779) ty = 779;
   dst[0] = (uint8_t)(0x20 | ((ty >> 5) & 0x1F));
   dst[1] = (uint8_t)(0x60 | (ty & 0x1F));
   dst[2] = (uint8_t)(0x20 | ((tx >> 5) & 0x1F));
   dst[3] = (uint8_t)(0x40 | (tx & 0x1F));
   return 4u;
}

/* A polyline through n points, as one GS vector. */
static size_t tek_lines(tnd_out_t *s, uint8_t *dst, const int16_t *xy, unsigned n)
{
   size_t k = tek_enter(s, dst);
   dst[k++] = 0x1Du;
   for (unsigned i = 0u; i < n; i++)
      k += tek_xy(dst + k, xy[2u * i], xy[2u * i + 1u]);
   return k;
}

static size_t tek_plot(tnd_out_t *s, uint8_t *dst)
{
   uint8_t  k = s->p[0];
   int16_t  x = (int16_t)(s->p[1] | (s->p[2] << 8)), y = (int16_t)(s->p[3] | (s->p[4] << 8));
   unsigned type = k & 0xF8u, how = k & 3u;
   size_t   n = 0u;

   if ((k & 4u) != 0u) {                        /* absolute, from the graphics origin */
      x = (int16_t)(x + s->ox);
      y = (int16_t)(y + s->oy);
   } else {                                     /* relative to the graphics cursor */
      x = (int16_t)(x + s->gx);
      y = (int16_t)(y + s->gy);
   }
   if (s->tek && how == 1u) {                   /* drawn in the foreground: the only kind a tube shows */
      if (type < 64u) {                         /* the lines (solid, dotted, dashed, with or without the end) */
         int16_t v[4] = { s->gx, s->gy, x, y };
         n = tek_lines(s, dst, v, 2u);
      } else if (type == 64u) {                 /* a point */
         int16_t v[4] = { x, y, x, y };
         n = tek_lines(s, dst, v, 2u);
      } else if (type == 80u) {                 /* a triangle, outlined */
         int16_t v[8] = { s->g1x, s->g1y, s->gx, s->gy, x, y, s->g1x, s->g1y };
         n = tek_lines(s, dst, v, 4u);
      } else if (type == 96u) {                 /* a rectangle (Master), outlined */
         int16_t v[10] = { s->gx, s->gy, x, s->gy, x, y, s->gx, y, s->gx, s->gy };
         n = tek_lines(s, dst, v, 5u);
      }
   }
   s->g2x = s->g1x; s->g2y = s->g1y;
   s->g1x = s->gx;  s->g1y = s->gy;
   s->gx = x;       s->gy = y;
   return n;
}

static size_t tek_clear(tnd_out_t *s, uint8_t *dst)
{
   size_t n;
   if (!s->tek)
      return 0u;
   n = tek_enter(s, dst);
   n += put_str(dst + n, "\x1b\x0c");
   return n;
}

static size_t finish_code(tnd_out_t *s, uint8_t dst[TND_OUT_MAX])
{
   uint8_t code = s->code;
   size_t  n = 0u;

   s->code = 0u;
   switch (code) {
   case 17:                                     /* COLOUR: 0-127 text, 128-255 background */
      if (s->tele && s->sync)                    /* MODE 7 has no COLOUR: the control codes do it */
         break;
      if (s->p[0] < 128u) {
         s->fg = (uint8_t)(s->p[0] & (s->ncol - 1u));
         n = sgr(dst, '3', phys(s, s->fg));
      } else {
         s->bg = (uint8_t)((s->p[0] - 128u) & (s->ncol - 1u));
         n = sgr(dst, '4', phys(s, s->bg));
      }
      s->coloured = true;
      s->tsgr = 0xFFu;
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
      else
         n += ttx_plain(s, dst + n);
      n += ttx_clear_lattr(s, dst + n);          /* teletext double height lines back to single */
      if (s->tek) {                              /* the graphics go with the screen */
         n += tek_clear(s, dst + n);
         n += tek_leave(s, dst + n);
      }
      s->gx = s->gy = s->ox = s->oy = 0;
      tnd_out_set_mode(s, s->p[0]);
      s->sync = true;
      s->colok = true;
      s->origin_ok = true;
      s->coloured = false;
      n += put_str(dst + n, "\x1b[2J\x1b[H");
      break;
   case 25:                                     /* PLOT k,x,y */
      n = tek_plot(s, dst);
      break;
   case 29:                                     /* the graphics origin */
      s->ox = (int16_t)(s->p[0] | (s->p[1] << 8));
      s->oy = (int16_t)(s->p[2] | (s->p[3] << 8));
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

static size_t out_byte(tnd_out_t *s, uint8_t c, uint8_t *dst)
{
   size_t n = 0u;


   if (s->code != 0u) {                         /* a parameter byte of a VDU code */
      if (s->got < sizeof s->p)
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
         s->hl_on = s->cc_on = false;
         s->npend = 0u;
         s->colok = true;
         if (full_width(s) && s->wt == 0u && s->wb == s->rows - 1u) {
            scr_clear(s, 0u, 0u, (unsigned)s->cols - 1u, (unsigned)s->rows - 1u);
            s->sync = true;
            s->dirty = false;
            s->cx = s->wl; s->cy = s->wt;
            s->origin_ok = true;
            n = ttx_plain(s, dst);
            n += ttx_clear_lattr(s, dst + n);
            n += put_str(dst + n, "\x1b[2J\x1b[H");
         } else if (s->sync && s->origin_ok) {   /* only the window: drawn again, nothing else touched */
            scr_clear(s, s->wl, s->wt, s->wr, s->wb);
            s->cx = s->wl; s->cy = s->wt;
            mark_dirty(s, s->wl, s->wt, s->wr, s->wb);
            n = put_pos(dst, s->cx, s->cy);
         } else {                                /* the terminal's rows are not the Beeb's yet: start them */
            scr_clear(s, s->wl, s->wt, s->wr, s->wb);
            s->cx = s->wl; s->cy = s->wt;
            s->origin_ok = true;
            n = put_str(dst, "\x1b[2J");
            if (s->sync)                         /* what is outside the window comes back */
               mark_dirty(s, 0u, 0u, (unsigned)s->cols - 1u, (unsigned)s->rows - 1u);
            n += put_pos(dst + n, s->cx, s->cy);
         }
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
         n += put_left(s, dst + n);             /* to the window's left edge */
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

   if (c == 127u && s->tele && s->sync && s->cx > s->wl) {   /* DELETE in MODE 7: the cell drawn again as a space */
      uint8_t  old;
      unsigned end, done;
      int      before;
      s->cx--;
      old = s->ch[s->cy][s->cx];
      before = ttx_row_end(s, s->cy);
      s->ch[s->cy][s->cx] = ' ';
      s->at[s->cy][s->cx] = AT_KNOWN | AT_DEF;
      end = s->cx;
      if (old >= 0x80u && old < 0xA0u && before > (int)end)
         end = (unsigned)before;
      dst[n++] = 8u;
      n += ttx_cells(s, &s->tsgr, dst + n, s->cy, s->cx, end, TND_OUT_MAX - 160u, &done);
      if (done < end && s->origin_ok)
         mark_dirty(s, done + 1u, s->cy, end, s->cy);
      dst[n++] = 27u; dst[n++] = '[';
      n += put_num(dst + n, (unsigned)s->cx + 1u);
      dst[n++] = 'G';
      if (old == 0x8Du)
         n += ttx_sync_lattr(s, dst + n, TND_OUT_MAX - 60u - n);
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

   if (s->tele && s->sync)
      return ttx_glyph(s, c, dst);
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
         s->tsgr = 0xFFu;
      }
      if (s->cx < s->wr)
         s->cx++;
      else                                       /* the last column: on to the next line */
         n += scr_newline(s, dst + n);
      return n;
   }
}

/* Graphics first: anything that is not one of the graphics codes takes the terminal back
   from its Tek window to the text screen, and CLG (VDU 16) clears the Tek page. */
size_t tnd_out_byte(tnd_out_t *s, uint8_t c, uint8_t dst[TND_OUT_MAX])
{
   size_t n = 0u;

   if (s->code == 0u && !s->disabled) {
      if (c == 16u)
         return tek_clear(s, dst);
      if (s->tek_on && c != 18u && c != 25u && c != 29u)
         n = tek_leave(s, dst);
   }
   return n + out_byte(s, c, dst + n);
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
   s->tsgr = s->coloured ? 0xFFu : TTX_SGR_PLAIN;
   s->origin_ok = false;
   s->dirty = false;
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

   if (s->tele) {                                /* teletext: the row as the chip draws it */
      uint8_t  tsgr = TTX_SGR_PLAIN;
      uint8_t  la = ttx_lattr(s, row);
      int      tend = ttx_row_end(s, row);
      unsigned done;
      n += put_str(dst + n, "\x1b[0m");
      if (la != 0u)
         n += ttx_put_lattr(dst + n, la);
      if (tend >= 0)
         n += ttx_cells(s, &tsgr, dst + n, row, 0u, (unsigned)tend, TND_REPAINT_MAX - 24u - n, &done);
      n += put_str(dst + n, "\x1b[0m");
      if ((int)row < last) {
         dst[n++] = 13u;
         dst[n++] = 10u;
      }
      return n;
   }

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

size_t tnd_out_dirty_row(tnd_out_t *s, uint8_t dst[TND_REPAINT_MAX])
{
   size_t n = 0u;

   if (!s->dirty)
      return 0u;
   if (!s->sync || !s->origin_ok || s->dt > s->db || s->dl > s->dr || s->db >= s->rows || s->dr >= s->cols) {
      s->dirty = false;
      return 0u;
   }
   unsigned y = s->dt;
   uint8_t  prev = AT_DEF;
   n += put_pos(dst, s->dl, y);
   n += put_str(dst + n, "\x1b[0m");
   if (s->tele) {
      unsigned done;
      s->tsgr = TTX_SGR_PLAIN;
      n += ttx_cells(s, &s->tsgr, dst + n, y, s->dl, s->dr, TND_REPAINT_MAX - 80u - n, &done);
      n += put_str(dst + n, "\x1b[0m");
      if (s->hl_on && s->hly == y && s->hlx >= s->dl && s->hlx <= s->dr)
         s->hl_on = false;
      n += put_finish(s, dst + n);
      s->tsgr = s->coloured ? 0xFFu : TTX_SGR_PLAIN;
      if (y >= s->db)
         s->dirty = false;
      else
         s->dt = (uint8_t)(y + 1u);
      return n;
   }
   for (unsigned x = s->dl; x <= s->dr; x++) {
      uint8_t at = (s->at[y][x] & AT_KNOWN) != 0u ? (uint8_t)(s->at[y][x] & ~AT_KNOWN) : AT_DEF;
      if (n + 24u > TND_REPAINT_MAX - 48u)
         break;                                  /* a row of colour changes at every cell: cut it off */
      if (at != prev) {
         n += put_attr(s, dst + n, at);
         prev = at;
      }
      n += put_glyph(s, dst + n, s->ch[y][x]);
   }
   n += put_str(dst + n, "\x1b[0m");
   if (s->hl_on && s->hly == y && s->hlx >= s->dl && s->hlx <= s->dr)
      s->hl_on = false;                          /* the copy cursor's mark was drawn over */
   n += put_finish(s, dst + n);                  /* the Beeb's cursor and colours, for what comes next */
   if (y >= s->db)
      s->dirty = false;
   else
      s->dt = (uint8_t)(y + 1u);
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

/* One teletext cell as the chip shows it, reversed for the copy cursor's mark. */
static size_t ttx_mark(const tnd_out_t *s, uint8_t *dst, unsigned x, unsigned y, bool reverse)
{
   ttx_t    t;
   uint32_t cp; uint8_t fg, bg; bool fl;
   uint8_t  tsgr = 0xFFu;
   size_t   n;

   ttx_state(s, y, x, &t);
   ttx_step(&t, s->ch[y][x], &cp, &fg, &bg, &fl);
   n = ttx_sgr(&tsgr, dst, fg, bg, fl);
   if (reverse)
      n += put_str(dst + n, "\x1b[7m");
   n += ttx_put_cp(s, dst + n, cp);
   return n;
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
      if (s->tele) {
         n += ttx_mark(s, dst + n, s->hlx, s->hly, false);
      } else {
         n += put_attr(s, dst + n, s->at[s->hly][s->hlx]);
         n += put_glyph(s, dst + n, s->ch[s->hly][s->hlx]);
      }
      s->hl_on = false;
   }
   if (s->cc_on && (s->ccx != s->cx || s->ccy != s->cy)
       && (s->at[s->ccy][s->ccx] & AT_KNOWN) != 0u) {
      n += put_pos(dst + n, s->ccx, s->ccy);
      if (s->tele) {
         n += ttx_mark(s, dst + n, s->ccx, s->ccy, true);
      } else {
         n += put_attr(s, dst + n, s->at[s->ccy][s->ccx]);
         n += put_str(dst + n, "\x1b[7m");
         n += put_glyph(s, dst + n, s->ch[s->ccy][s->ccx]);
      }
      s->hl_on = true;
      s->hlx = s->ccx;
      s->hly = s->ccy;
   }
   if (n != 0u) {
      n += put_finish(s, dst + n);
      s->tsgr = s->coloured ? 0xFFu : TTX_SGR_PLAIN;
   }
   return n;
}

bool tnd_stalled(bool pending, uint32_t now_us, uint32_t progress_us, uint32_t limit_us)
{
   return pending && (uint32_t)(now_us - progress_us) >= limit_us;
}

/* ---- line mode ------------------------------------------------------------------
   See the header for the decision.  The Beeb -> client half is a second, much smaller
   translator over the same VDU stream: plain text out, every control code and its
   parameter bytes (vdu_params, the same table the screen translator uses) dropped.

   The echo.  The Beeb's line editor (OSWORD 0) prints each key it is given, and a new
   line for RETURN; the client has already shown the line, so that echo is taken out.
   Every key the daemon gives the Beeb is remembered (tnd_line_typed), and output that
   matches them, in order, is held back rather than written.  RETURN matches a CR or an
   LF; the line is then confirmed, what was held is dropped, and the rest of its new
   line (CRs, up to the first LF) is dropped too.  Output that stops matching was not
   the echo: what was held is written after all and matching starts again at the first
   key still expected.  An echo that does not come within TND_ECHO_US of the Beeb last
   doing anything (a program reading with GET, which does not echo) is given up. */

uint8_t tnd_decide(const tnd_in_t *s, uint8_t setting, uint32_t now_us, uint32_t start_us)
{
   if (setting == TND_SET_SCREEN)
      return TND_MODE_SCREEN;
   if (setting == TND_SET_LINE)
      return TND_MODE_LINE;
   if (s->echo_opt == TND_OPT_OFF || s->sga_opt == TND_OPT_OFF)
      return TND_MODE_LINE;
   if (s->echo_opt == TND_OPT_ON)
      return TND_MODE_SCREEN;
   if (s->data || (uint32_t)(now_us - start_us) >= TND_DECIDE_US)
      return TND_MODE_LINE;
   return TND_MODE_UNDECIDED;
}

bool tnd_ga_wanted(const tnd_in_t *s)
{
   return s->telnet && s->sga_opt != TND_OPT_ON;
}

#define TSGR_PLAIN 0x07u          /* ttx_sgr's key for the terminal's own colours */

_Static_assert(sizeof(ttx_t) <= sizeof(((tnd_line_t *)0)->tt), "tnd_line_t.tt holds a ttx_t");

static ttx_t *line_tt(tnd_line_t *s)
{
   return (ttx_t *)(void *)s->tt;
}

void tnd_line_reset(tnd_line_t *s, bool utf8, uint8_t mode)
{
   memset(s, 0, sizeof *s);
   s->utf8 = utf8;
   s->tele = (mode & 7u) == 7u;
   s->tsgr = TSGR_PLAIN;
   ttx_init(line_tt(s));
}

void tnd_line_ttx(tnd_line_t *s, uint8_t ttx_style)
{
   s->ttx = ttx_style;
}

size_t tnd_line_plain(tnd_line_t *s, uint8_t *dst)
{
   if (s->tsgr == TSGR_PLAIN)
      return 0u;
   s->tsgr = TSGR_PLAIN;
   return put_str(dst, "\x1b[0m");
}

/* A teletext control code as a marker: the colour codes as a block in their colour
   (solid for text, shaded for graphics), the others as a reversed letter:
      F flash  S steady  [ ] boxes  1 normal  2 double height  C conceal
      c contiguous  s separated  b black background  B new background  H hold
      R release  K/k black (not on the SAA5050)  ? unused
   From &A0 (and outside MODE 7, where the Beeb shows its own characters) the
   character without bit 7, reversed.  Below &80 the character itself. */
size_t tnd_marker(uint8_t c, bool utf8, uint8_t *dst)
{
   static const char letters[32] = {
      'K', 0, 0, 0, 0, 0, 0, 0, 'F', 'S', ']', '[', '1', '2', '?', '?',
      'k', 0, 0, 0, 0, 0, 0, 0, 'C', 'c', 's', '?', 'b', 'B', 'H', 'R'
   };
   size_t n = 0u;

   if (c < 0x80u) {
      if (c == 96u)
         return put_cp(utf8, dst, 0xA3u);
      dst[0] = (c >= 32u && c < 127u) ? c : (uint8_t)'?';
      if (c >= 32u && c < 127u)
         return 1u;
      n = put_str(dst, "\x1b[7m");               /* a control character: reversed, as ^ letter */
      dst[n++] = (uint8_t)(c == 127u ? '?' : '@' + c);
      return n + put_str(dst + n, "\x1b[27m");
   }
   if (c < 0xA0u && letters[c & 31u] == 0) {     /* a colour: a block in it */
      n = sgr(dst, '3', (uint8_t)(c & 7u));
      n += put_cp(utf8, dst + n, c < 0x90u ? 0x2588u : 0x2592u);
      if (!utf8)
         dst[n - 1u] = c < 0x90u ? (uint8_t)'#' : (uint8_t)'%';
      return n + put_str(dst + n, "\x1b[39m");
   }
   n = put_str(dst, "\x1b[7m");
   if (c < 0xA0u) {
      dst[n++] = (uint8_t)letters[c & 31u];
   } else {
      uint8_t a = (uint8_t)(c & 0x7Fu);
      dst[n++] = (a >= 32u && a < 127u) ? a : (uint8_t)'?';
   }
   return n + put_str(dst + n, "\x1b[27m");
}

size_t tnd_line_room(const tnd_line_t *s)
{
   return TND_LINE_EXP - s->en;
}

/* The place in the ring of the i'th key still expected. */
static unsigned ring_at(const tnd_line_t *s, unsigned i)
{
   return ((unsigned)s->eh + i) % TND_LINE_EXP;
}

void tnd_line_typed(tnd_line_t *s, uint8_t key, uint32_t now_us)
{
   s->typed_us = now_us;
   s->ga_armed = true;
   if (s->en < TND_LINE_EXP) {
      s->exp[ring_at(s, s->en)] = key;
      s->en++;
   }
}

void tnd_line_escape(tnd_line_t *s)
{
   s->eh = s->en = s->matched = s->skip = 0u;
   s->nl = false;
}

static size_t line_newline(tnd_line_t *s, uint8_t *dst)
{
   size_t n = tnd_line_plain(s, dst);           /* colours do not run on into the next line */

   s->col = 0u;
   s->cr = false;
   s->gfx = false;
   s->rowcol = 0u;
   ttx_init(line_tt(s));                        /* a teletext row starts plain */
   dst[n++] = '\r';
   dst[n++] = '\n';
   return n;
}

/* MODE 7, rendered or markers: one character cell, through the screen translator's
   own teletext rules (ttx_step) - the codes take effect, mosaics after a graphics code
   are sextants.  The Beeb's rows are 40 cells, and each starts plain. */
static size_t line_ttx(tnd_line_t *s, uint8_t c, uint8_t *dst)
{
   ttx_t   *t = line_tt(s);
   size_t   n = 0u;
   uint32_t cp;
   uint8_t  fg, bg, b = ttx_store(c);
   bool     flash;

   if (s->cr)
      n = line_newline(s, dst);
   if (s->rowcol >= 40u) {                      /* the Beeb wrapped onto a new row */
      ttx_init(t);
      s->rowcol = 0u;
   }
   if (s->ttx == TND_TTX_MARKERS)
      t->conceal = false;                       /* markers show what is there */
   ttx_step(t, b, &cp, &fg, &bg, &flash);
   if (s->ttx == TND_TTX_MARKERS && b >= 0x80u && b < 0xA0u) {
      n += tnd_marker(b, s->utf8, dst + n);
   } else {
      if (s->ttx == TND_TTX_RENDERED)
         n += ttx_sgr(&s->tsgr, dst + n, fg, bg, flash);
      n += put_cp(s->utf8, dst + n, cp);
   }
   s->rowcol++;
   if (s->col < 255u)
      s->col++;
   return n;
}

/* A character that takes a place on the line. */
static size_t line_glyph(tnd_line_t *s, uint8_t ch, uint8_t *dst)
{
   size_t n = 0u;

   if (s->cr)                                   /* the Beeb went back to overwrite: a new line here */
      n = line_newline(s, dst);
   if (ch == 96u) {                             /* the pound sign (in MODE 7 too: the MOS swaps it in) */
      if (s->utf8)
         dst[n++] = 0xC2u;
      dst[n++] = 0xA3u;
   } else {
      dst[n++] = ch;
   }
   if (s->col < 255u)
      s->col++;
   return n;
}

/* One byte of the VDU stream, the echo already taken out. */
static size_t line_strip(tnd_line_t *s, uint8_t c, uint8_t *dst)
{
   if (s->code != 0u) {                         /* a parameter byte */
      s->got++;
      if (s->code == 22u && s->got == 1u)
         s->tele = (c & 7u) == 7u;              /* MODE: what the codes from 128 mean */
      if (s->got >= vdu_params(s->code)) {
         uint8_t code = s->code;
         s->code = 0u;
         if (code == 22u && !s->disabled && (s->col != 0u || s->cr))
            return line_newline(s, dst);        /* a MODE clears the screen: what follows is a new line */
         if (code == 22u) {
            s->rowcol = 0u;
            ttx_init(line_tt(s));
         }
      }
      return 0u;
   }
   if (vdu_params(c) != 0u) {                   /* parameters are counted even under VDU 21, as the MOS does */
      s->code = c;
      s->got = 0u;
      return 0u;
   }
   if (s->disabled) {
      if (c == 6u)
         s->disabled = false;
      return 0u;
   }
   if (c < 32u) {
      switch (c) {
      case 7:
         dst[0] = 7u;
         return 1u;
      case 9:                                   /* cursor right: a space keeps the columns */
         return line_glyph(s, ' ', dst);
      case 10:
         return line_newline(s, dst);
      case 13:
         if (s->col != 0u)
            s->cr = true;
         return 0u;
      case 12:                                  /* CLS: what follows starts a line */
         if (s->col != 0u || s->cr)
            return line_newline(s, dst);
         return 0u;
      case 21:
         s->disabled = true;
         return 0u;
      default:                                  /* cursor moves, home, windows ...: dropped */
         return 0u;
      }
   }
   if (c == 127u) {                             /* DELETE: back over the last character */
      if (s->col == 0u || s->cr)
         return 0u;
      s->col--;
      dst[0] = 8u; dst[1] = ' '; dst[2] = 8u;
      return 3u;
   }
   if (s->tele && s->ttx != TND_TTX_SPACES)
      return line_ttx(s, c, dst);
   if (c < 128u) {
      if (s->tele && s->gfx && (c < 0x40u || c >= 0x60u))
         return line_glyph(s, ' ', dst);        /* a mosaic: there is no text in it */
      return line_glyph(s, c, dst);
   }
   if (!s->tele) {                              /* user-defined characters: no text either ... */
      if (s->ttx == TND_TTX_SPACES)
         return 0u;
      {                                         /* ... but a marker keeps the columns */
         size_t n = 0u;
         if (s->cr)
            n = line_newline(s, dst);
         if (s->col < 255u)
            s->col++;
         return n + tnd_marker(c, s->utf8, dst + n);
      }
   }
   if (c < 0xA0u) {                             /* a teletext control code: a space on the screen */
      if (c >= 0x91u && c <= 0x97u)
         s->gfx = true;
      else if (c >= 0x81u && c <= 0x87u)
         s->gfx = false;
      return line_glyph(s, ' ', dst);
   }
   c = (uint8_t)(c & 0x7Fu);                    /* from 0xA0 the chip ignores bit 7 */
   if (c == 127u || (s->gfx && (c < 0x40u || c >= 0x60u)))
      c = ' ';
   return line_glyph(s, c, dst);
}

/* What was held back as a possible echo was not one: write it after all. */
static size_t line_release(tnd_line_t *s, uint8_t *dst)
{
   size_t   n = 0u;
   unsigned m = s->matched, k = s->skip;

   s->matched = s->skip = 0u;
   for (unsigned i = 0u; i < m; i++)
      n += line_strip(s, s->exp[ring_at(s, k + i)], dst + n);
   return n;
}

/* Can an echo start with c?  At the first key expected, or at the start of a later
   line: the lines before it may have been read without an echo (by GET or INKEY).
   They are only forgotten once the later line's echo is complete, so a near match
   in the output costs nothing; but one key read silently cannot leave every later
   line's echo unmatched. */
static bool line_restart(tnd_line_t *s, uint8_t c)
{
   for (unsigned k = 0u; k < s->en; k++) {
      if (s->exp[ring_at(s, k)] == c && (k == 0u || s->exp[ring_at(s, k - 1u)] == 13u)) {
         s->skip = (uint16_t)k;
         s->matched = 1u;
         return true;
      }
   }
   return false;
}

size_t tnd_line_beeb(tnd_line_t *s, uint8_t c, uint32_t now_us, uint8_t *dst)
{
   size_t n = 0u;

   s->out_us = now_us;
   if (s->code == 0u && !s->disabled) {         /* a byte that can be part of the echo */
      if (s->nl) {                              /* the end of an echoed line: CRs, then the LF */
         if (c == 13u)
            return 0u;
         s->nl = false;
         if (c == 10u)
            return 0u;
      }
      if (s->en != 0u) {
         unsigned at = (unsigned)s->skip + s->matched;   /* the next key expected */
         uint8_t  want = s->exp[ring_at(s, at)];
         if (at < s->en && want == 13u && (c == 13u || c == 10u)) {
            s->eh = (uint16_t)ring_at(s, at + 1u);      /* the line's echo, all of it (and any before it) */
            s->en = (uint16_t)(s->en - at - 1u);
            s->matched = s->skip = 0u;
            s->col = 0u;                        /* the client's cursor is at the start of a line */
            s->cr = false;
            s->gfx = false;
            s->nl = (c == 13u);
            return 0u;
         }
         if (at < s->en && want == c) {
            s->matched++;
            return 0u;
         }
         if (s->matched != 0u)                  /* it stopped matching: not the echo */
            n = line_release(s, dst);
         if (s->code == 0u && !s->disabled && line_restart(s, c)) {
            if (n != 0u)
               s->ga_armed = true;
            return n;
         }
      }
   }
   n += line_strip(s, c, dst + n);
   if (n != 0u)
      s->ga_armed = true;
   return n;
}

size_t tnd_line_tick(tnd_line_t *s, uint32_t now_us, uint8_t *dst)
{
   size_t n = 0u;

   if (s->en == 0u || (uint32_t)(now_us - s->out_us) < TND_ECHO_US
       || (uint32_t)(now_us - s->typed_us) < TND_ECHO_US)
      return 0u;
   if (s->matched != 0u)
      n = line_release(s, dst);
   s->eh = s->en = s->skip = 0u;
   if (n != 0u)
      s->ga_armed = true;
   return n;
}

bool tnd_line_ga_due(tnd_line_t *s, uint32_t now_us, bool keys_waiting)
{
   if (!s->ga_armed || keys_waiting || s->matched != 0u
       || (uint32_t)(now_us - s->out_us) < TND_GA_US
       || (uint32_t)(now_us - s->typed_us) < TND_GA_US)
      return false;
   s->ga_armed = false;
   return true;
}

/* ---- the hot key ---------------------------------------------------------------- */

uint8_t tnd_hotkey(bool *armed, uint8_t key)
{
   if (!*armed) {
      if (key != TND_HOT_KEY)
         return TND_HOT_NONE;
      *armed = true;
      return TND_HOT_SWALLOW;
   }
   *armed = false;
   switch (key) {
   case TND_HOT_KEY:          return TND_HOT_LITERAL;
   case 'm': case 'M':        return TND_HOT_MODE;
   case 't': case 'T':        return TND_HOT_TTX;
   default:                   return TND_HOT_SWALLOW;
   }
}

/* ---- shell mode -------------------------------------------------------------------
   See the header for who gets a key.  The edit line is drawn where the client's cursor
   is - after the Beeb's prompt - one column per character (codes as markers).  It is
   taken off the screen (cursor back to its start, clear to the end of the line) before
   the Beeb's output is written, so that output lands where the Beeb's cursor is, and
   drawn again once the output has stopped.  The Beeb's echo of a line sent with RETURN
   is taken out by the line matcher, as in line mode; the echo of a probe, and of the
   DELETE that takes it back, by the editor itself. */

uint8_t tnd_key_for_char(uint8_t c)
{
   uint8_t lo = (uint8_t)(c & 15u);

   if (c == 0u)
      return 0u;                                /* the daemon's ESCAPE request, never a key */
   if (c < 0x80u)
      return c;
   if (lo > 10u)
      return 0u;
   switch (c & 0xF0u) {
   case 0x80u: return (uint8_t)(0x90u | lo);   /* SHIFT f0-f10: *FX226 gives &80+n */
   case 0x90u: return (uint8_t)(0xA0u | lo);   /* CTRL f0-f10: *FX227 gives &90+n */
   case 0xD0u: case 0xE0u: case 0xF0u:
      return c == 0xFFu ? 0u : c;
   default:    return 0u;
   }
}

static void io_cli(tnd_sh_io_t *io, const void *p, size_t n)
{
   memcpy(io->cli + io->ncli, p, n);
   io->ncli += n;
}

static void io_str(tnd_sh_io_t *io, const char *str)
{
   io_cli(io, str, strlen(str));
}

static void io_key(tnd_sh_io_t *io, uint8_t k)
{
   if (io->nkeys < TND_SH_KEYS_MAX)
      io->keys[io->nkeys++] = k;
}

/* ESC [ n <f>: n columns left or right. */
static void io_move(tnd_sh_io_t *io, unsigned n, char f)
{
   if (n == 0u)
      return;
   io->cli[io->ncli++] = 27u;
   io->cli[io->ncli++] = '[';
   io->ncli += put_num(io->cli + io->ncli, n);
   io->cli[io->ncli++] = (uint8_t)f;
}

void tnd_shell_reset(tnd_shell_t *s, bool utf8, uint8_t mode, uint8_t ttx_style)
{
   memset(s, 0, sizeof *s);
   tnd_line_reset(&s->lm, utf8, mode);
   tnd_line_ttx(&s->lm, ttx_style);
   s->utf8 = utf8;
   s->hpos = -1;
}

static void sh_hide(tnd_shell_t *s, tnd_sh_io_t *io)
{
   if (!s->shown)
      return;
   io_move(io, s->shown_cur, 'D');
   io_str(io, "\x1b[K");
   s->shown = false;
}

static void sh_draw(tnd_shell_t *s, tnd_sh_io_t *io)
{
   io->ncli += tnd_line_plain(&s->lm, io->cli + io->ncli);
   for (unsigned i = 0u; i < s->len; i++)
      io->ncli += tnd_marker(s->line[i], s->utf8, io->cli + io->ncli);
}

static void sh_show(tnd_shell_t *s, tnd_sh_io_t *io)
{
   sh_draw(s, io);
   io_move(io, (unsigned)(s->len - s->cur), 'D');
   s->shown = true;
   s->shown_cur = s->cur;
}

void tnd_shell_redraw(tnd_shell_t *s, tnd_sh_io_t *io)
{
   sh_hide(s, io);
   if (s->state == TND_SH_EDIT)
      sh_show(s, io);
}

static void sh_load(tnd_shell_t *s, const uint8_t *p, uint16_t n)
{
   memcpy(s->line, p, n);
   s->len = s->cur = n;
}

static void sh_history_add(tnd_shell_t *s)
{
   unsigned i, n = s->hn;

   if (s->len == 0u)
      return;
   for (i = 0u; i < n; i++)                     /* the same line again: it moves to the front */
      if (s->hlen[i] == s->len && memcmp(s->hist[i], s->line, s->len) == 0)
         break;
   if (i == n) {
      if (n < TND_SH_HIST)
         s->hn++;
      i = s->hn - 1u;
   }
   for (; i > 0u; i--) {
      memcpy(s->hist[i], s->hist[i - 1u], s->hlen[i - 1u]);
      s->hlen[i] = s->hlen[i - 1u];
   }
   memcpy(s->hist[0], s->line, s->len);
   s->hlen[0] = s->len;
}

/* Up, Down, Ctrl-R: a history line in the edit line.  The line being typed is kept
   while the history is shown, and comes back below the newest. */
static void sh_hist_go(tnd_shell_t *s, int16_t to)
{
   if (s->hpos < 0) {
      memcpy(s->saved, s->line, s->len);
      s->savedlen = s->len;
   }
   s->hpos = to;
   if (to < 0)
      sh_load(s, s->saved, s->savedlen);
   else
      sh_load(s, s->hist[to], s->hlen[to]);
}

/* Ctrl-R: the next older history line that has what was being typed in it. */
static bool sh_search(tnd_shell_t *s)
{
   const uint8_t *term = s->hpos < 0 ? s->line : s->saved;
   uint16_t       tn = s->hpos < 0 ? s->len : s->savedlen;

   for (int16_t i = (int16_t)(s->hpos + 1); i < (int16_t)s->hn; i++) {
      const uint8_t *h = s->hist[i];
      for (unsigned at = 0u; at + tn <= s->hlen[i]; at++)
         if (memcmp(h + at, term, tn) == 0) {
            sh_hist_go(s, i);
            return true;
         }
   }
   return false;
}

static void sh_insert(tnd_shell_t *s, uint8_t c)
{
   if (s->len >= TND_SH_LINE)
      return;
   memmove(s->line + s->cur + 1u, s->line + s->cur, (size_t)(s->len - s->cur));
   s->line[s->cur++] = c;
   s->len++;
}

static void sh_delete(tnd_shell_t *s, uint16_t from, uint16_t to)
{
   memmove(s->line + from, s->line + to, (size_t)(s->len - to));
   s->len = (uint16_t)(s->len - (to - from));
   s->cur = from;
}

static int hexval(uint8_t c)
{
   if (c >= '0' && c <= '9') return c - '0';
   if (c >= 'a' && c <= 'f') return c - 'a' + 10;
   if (c >= 'A' && c <= 'F') return c - 'A' + 10;
   return -1;
}

/* RETURN: the line to the Beeb, its echo expected, the client on a new line. */
static void sh_submit(tnd_shell_t *s, uint32_t now_us, tnd_sh_io_t *io)
{
   sh_hide(s, io);
   sh_draw(s, io);
   io_str(io, "\r\n");
   for (unsigned i = 0u; i < s->len; i++) {
      io_key(io, tnd_key_for_char(s->line[i]));
      tnd_line_typed(&s->lm, s->line[i], now_us);
   }
   io_key(io, 13u);
   tnd_line_typed(&s->lm, 13u, now_us);
   s->lm.col = 0u;
   s->lm.cr = false;
   sh_history_add(s);
   s->len = s->cur = 0u;
   s->hpos = -1;
   s->state = TND_SH_IDLE;
}

/* A key for the editor: the line changes, and is drawn again. */
static void sh_edit(tnd_shell_t *s, uint8_t k, uint32_t now_us, tnd_sh_io_t *io)
{
   if (s->ctrlv != 0u) {                        /* Ctrl-V and two hex digits: that byte */
      int v = hexval(k);
      if (v < 0) {
         s->ctrlv = 0u;
         io_str(io, "\a");
      } else if (s->ctrlv == 1u) {
         s->vhi = (uint8_t)v;
         s->ctrlv = 2u;
      } else {
         uint8_t c = (uint8_t)(((unsigned)s->vhi << 4) | (unsigned)v);
         s->ctrlv = 0u;
         if (tnd_key_for_char(c) != 0u)
            sh_insert(s, c);
         else
            io_str(io, "\a");                    /* no key gives it: CHR$ in the program instead */
      }
      return;
   }
   switch (k) {
   case 13u:
      sh_submit(s, now_us, io);
      return;
   case 127u: case 8u:
      if (s->cur != 0u)
         sh_delete(s, (uint16_t)(s->cur - 1u), s->cur);
      break;
   case TND_KEY_DELFWD: case 4u:
      if (s->cur < s->len)
         sh_delete(s, s->cur, (uint16_t)(s->cur + 1u));
      break;
   case 140u: case 2u:                          /* left, Ctrl-B */
      if (s->cur != 0u)
         s->cur--;
      break;
   case 141u: case 6u:                          /* right, Ctrl-F */
      if (s->cur < s->len)
         s->cur++;
      break;
   case TND_KEY_HOME: case 1u:
      s->cur = 0u;
      break;
   case 139u: case 5u:                          /* End (COPY's key in screen mode), Ctrl-E */
      s->cur = s->len;
      break;
   case 11u:                                    /* Ctrl-K: to the end */
      s->len = s->cur;
      break;
   case 21u:                                    /* Ctrl-U: to the start */
      sh_delete(s, 0u, s->cur);
      break;
   case 23u: {                                  /* Ctrl-W: the word before the cursor */
      uint16_t from = s->cur;
      while (from > 0u && s->line[from - 1u] == ' ')
         from--;
      while (from > 0u && s->line[from - 1u] != ' ')
         from--;
      sh_delete(s, from, s->cur);
      break;
   }
   case 143u:                                   /* up: older */
      if (s->hpos + 1 < (int)s->hn)
         sh_hist_go(s, (int16_t)(s->hpos + 1));
      else
         io_str(io, "\a");
      break;
   case 142u:                                   /* down: newer, then the line being typed */
      if (s->hpos >= 0)
         sh_hist_go(s, (int16_t)(s->hpos - 1));
      break;
   case 18u:                                    /* Ctrl-R */
      if (!sh_search(s))
         io_str(io, "\a");
      break;
   case 22u:
      s->ctrlv = 1u;
      return;
   case TND_KEY_REFRESH:
      break;
   default:
      if ((k >= 32u && k < 127u))
         sh_insert(s, k);
      else
         return;                                /* function keys, other controls: not in a line */
      break;
   }
   sh_hide(s, io);
   sh_show(s, io);
}

/* Is k a key that edits (rather than a character)? */
static bool sh_editing_key(uint8_t k)
{
   switch (k) {
   case 1u: case 2u: case 4u: case 5u: case 6u: case 11u: case 13u: case 18u: case 21u:
   case 22u: case 23u: case 127u: case 8u:
   case 139u: case 140u: case 141u: case 142u: case 143u:
   case TND_KEY_HOME: case TND_KEY_DELFWD:
      return true;
   default:
      return false;
   }
}

/* The key as screen mode would send it, for a program reading keys. */
static void sh_pass(tnd_shell_t *s, uint8_t k, uint32_t now_us, tnd_sh_io_t *io)
{
   s->key_us = now_us;
   if (k == TND_KEY_DELFWD)
      k = 127u;
   if (k == TND_KEY_HOME || k == TND_KEY_REFRESH)
      return;
   io_key(io, k);
}

static void sh_to_pass(tnd_shell_t *s, uint32_t now_us, tnd_sh_io_t *io)
{
   s->state = TND_SH_PASS;
   for (unsigned i = 0u; i < s->nq; i++)
      sh_pass(s, s->queue[i], now_us, io);
   s->nq = 0u;
   s->key_us = now_us;
}

static void sh_dispatch(tnd_shell_t *s, uint8_t k, uint32_t now_us, tnd_sh_io_t *io);

/* The probe was echoed: the Beeb is in its line editor, and the editor takes over. */
static void sh_to_edit(tnd_shell_t *s, uint32_t now_us, tnd_sh_io_t *io)
{
   uint8_t q[TND_SH_QUEUE], nq = s->nq;

   s->state = TND_SH_EDIT;
   s->len = s->cur = 0u;
   s->hpos = -1;
   sh_insert(s, s->probe);
   io_key(io, 127u);                            /* the probe out of the Beeb's line again */
   s->del_echo = true;
   memcpy(q, s->queue, nq);
   s->nq = 0u;
   sh_hide(s, io);
   sh_show(s, io);
   for (unsigned i = 0u; i < nq; i++)
      sh_dispatch(s, q[i], now_us, io);
}

static bool sh_quiet(const tnd_shell_t *s, uint32_t now_us)
{
   return (uint32_t)(now_us - s->lm.out_us) >= TND_SH_QUIET_US;
}

static void sh_dispatch(tnd_shell_t *s, uint8_t k, uint32_t now_us, tnd_sh_io_t *io)
{
   switch (s->state) {
   case TND_SH_EDIT:
      sh_edit(s, k, now_us, io);
      return;
   case TND_SH_PROBE:
      if (s->nq < TND_SH_QUEUE) {
         s->queue[s->nq++] = k;
      } else {                                  /* typing faster than the Beeb answers: a program */
         sh_to_pass(s, now_us, io);
         sh_pass(s, k, now_us, io);
      }
      return;
   case TND_SH_PASS:
      sh_pass(s, k, now_us, io);
      return;
   default:
      break;
   }
   /* Idle: a quiet Beeb is probably waiting for a line. */
   if (k >= 32u && k < 127u && sh_quiet(s, now_us)) {
      s->state = TND_SH_PROBE;
      s->probe = k;
      s->probe_us = now_us;
      s->nq = 0u;
      io_key(io, k);
   } else if (sh_editing_key(k) && sh_quiet(s, now_us)) {
      s->state = TND_SH_EDIT;
      s->len = s->cur = 0u;
      s->hpos = -1;
      sh_edit(s, k, now_us, io);
   } else {
      s->state = TND_SH_PASS;
      sh_pass(s, k, now_us, io);
   }
}

void tnd_shell_key(tnd_shell_t *s, uint8_t key, uint32_t now_us, tnd_sh_io_t *io)
{
   if (key == TND_KEY_ESCAPE) {                 /* the line goes, the Beeb gets ESCAPE */
      if (s->shown) {
         io_move(io, (unsigned)(s->len - s->shown_cur), 'C');
         s->shown = false;
      }
      s->len = s->cur = 0u;
      s->nq = 0u;
      s->ctrlv = 0u;
      s->hpos = -1;
      s->state = TND_SH_IDLE;
      s->del_echo = false;
      tnd_line_escape(&s->lm);
      io->escape = true;
      return;
   }
   sh_dispatch(s, key, now_us, io);
}

void tnd_shell_beeb(tnd_shell_t *s, uint8_t c, uint32_t now_us, tnd_sh_io_t *io)
{
   bool idle = s->lm.code == 0u && !s->lm.disabled;   /* not a VDU parameter */

   if (idle && s->state == TND_SH_PROBE) {
      if (c == s->probe) {                      /* its echo: a line editor is reading */
         s->lm.out_us = now_us;
         sh_to_edit(s, now_us, io);
         return;
      }
      sh_to_pass(s, now_us, io);                /* a program took it */
   }
   if (idle && s->del_echo) {
      s->del_echo = false;
      if (c == 127u) {
         s->lm.out_us = now_us;
         return;
      }
   }
   {
      uint8_t d[TND_LINE_OUT_MAX];
      size_t  n = tnd_line_beeb(&s->lm, c, now_us, d);
      if (n != 0u) {
         sh_hide(s, io);
         io_cli(io, d, n);
      }
   }
}

void tnd_shell_tick(tnd_shell_t *s, uint32_t now_us, tnd_sh_io_t *io)
{
   uint8_t d[TND_LINE_OUT_MAX];
   size_t  n = tnd_line_tick(&s->lm, now_us, d);

   if (n != 0u) {
      sh_hide(s, io);
      io_cli(io, d, n);
   }
   if (s->state == TND_SH_PROBE && (uint32_t)(now_us - s->probe_us) >= TND_SH_PROBE_US)
      sh_to_pass(s, now_us, io);                /* no echo: a program took it */
   if (s->state == TND_SH_PASS && (uint32_t)(now_us - s->key_us) >= TND_SH_PASS_US)
      s->state = TND_SH_IDLE;
   if (s->state == TND_SH_EDIT && !s->shown     /* the Beeb's output has stopped: the line again */
       && (uint32_t)(now_us - s->lm.out_us) >= TND_SH_REDRAW_US)
      sh_show(s, io);
}
