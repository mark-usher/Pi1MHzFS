/* telnetd_proto.h - the byte-level protocol of the Pi1MHz telnet daemon.
 *
 * Two pure, stateful translators with no I/O, so telnetd.c (lwIP) and the host
 * tests (src/tests/telnetd) drive them with byte vectors:
 *
 *   tnd_in_*   what the telnet client sends -> what the Beeb's keyboard gets
 *   tnd_out_*  what the Beeb prints (its VDU byte stream) -> what a terminal
 *              understands (ANSI)
 *
 * The daemon is a character-at-a-time server: it offers WILL ECHO and WILL SGA
 * (the Beeb does the echoing, the client must not) and the keys go to the Beeb
 * as they are typed.
 */
#ifndef TELNETD_PROTO_H
#define TELNETD_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- client -> Beeb ---------------------------------------------------- */

#define TND_IN_KEYS    3u      /* most keys one input byte can release (Alt-P, then a key) */

/* Not a key but a request: the client pressed ESC (a lone ESC, once it is clear
   no sequence follows) or Ctrl-C.  The Beeb's ESCAPE is a condition the keyboard
   scan raises, not a character in the buffer, so it cannot travel as a key: the
   daemon passes it to serial_redirect_escape().  0 is free for it because NUL is
   never a key. */
#define TND_KEY_ESCAPE 0u

/* Also a request and not a key: F12 is BREAK.  The daemon passes it to serial_redirect_break().
   254 is never a Beeb key the translator makes. */
#define TND_KEY_BREAK  0xFEu

/* F11: draw the screen again.  The daemon types *TELNETD for the Beeb, and the auto-start
   ROM answers by sending what is on the screen. */
#define TND_KEY_REFRESH 0xFDu
#define TND_IN_REPLY   3u      /* most negotiation bytes one input byte needs */
#define TND_GREETING_LEN 9u

/* A lone ESC is only a key once nothing follows it for this long; if more
   arrives first it was the start of a cursor or function key. */
#define TND_ESC_US     100000u

typedef struct {
   uint8_t  state;
   uint8_t  cmd;                /* WILL/WONT/DO/DONT being parsed        */
   uint8_t  nparam;
   uint16_t param[3];
   uint32_t esc_us;             /* when the ESC that opened the sequence arrived */
   uint8_t  seen_will[32];      /* respond-once bitmaps, over 256 options */
   uint8_t  seen_do[32];
   uint8_t  dcs[16];            /* the start of a DCS the terminal sent (its answer to CSI > q) */
   uint8_t  ndcs;
   bool     xterm;              /* the terminal said it is xterm: it can draw in Tektronix 4014 mode */
   /* What the client has said, for choosing screen or line mode (tnd_decide). */
   uint8_t  echo_opt;           /* our WILL ECHO: TND_OPT_OFFERED, TND_OPT_ON (DO ECHO), TND_OPT_OFF (DONT ECHO) */
   uint8_t  sga_opt;            /* our WILL SGA, the same */
   bool     telnet;             /* the client has sent a telnet command (IAC ...): it speaks telnet */
   bool     data;               /* the client has sent data, not only negotiation */
   bool     refuse_echo;        /* line mode by the setting: ECHO was not offered, and DO ECHO is refused */
} tnd_in_t;

#define TND_OPT_OFFERED 0u
#define TND_OPT_ON      1u
#define TND_OPT_OFF     2u

void   tnd_in_reset(tnd_in_t *s);

/* The server's opening offer: IAC WILL ECHO, IAC WILL SGA, IAC DO SGA.
   Writes TND_GREETING_LEN bytes. */
size_t tnd_greeting(uint8_t *out);

/* Feed one byte from the client.  Returns how many Beeb keys it released
   (0 to TND_IN_KEYS, written to keys[]); *replen is how many bytes of telnet
   negotiation (rep[], at most TND_IN_REPLY) go back to the client. */
size_t tnd_in_byte(tnd_in_t *s, uint8_t c, uint32_t now_us,
                   uint8_t keys[TND_IN_KEYS], uint8_t rep[TND_IN_REPLY],
                   size_t *replen);

/* Call regularly: releases a lone ESC once it has waited TND_ESC_US, and drops
   an escape sequence that never finished.  Returns keys released (0 or 1). */
size_t tnd_in_tick(tnd_in_t *s, uint32_t now_us, uint8_t keys[TND_IN_KEYS]);

/* The key codes the translator produces, as the MOS keyboard buffer holds them
   (what OSBYTE 138 / INSV into buffer 0 takes): cursor left/right/down/up are
   140/141/142/143 and COPY is 139 (GET returns 136-139 and 135 under *FX4,1:
   the MOS subtracts 4), DELETE is 127, f0-f9 are 128-137, the pound sign is 96.
   ESC and Ctrl-C are TND_KEY_ESCAPE. */

/* ---- Beeb -> terminal ---------------------------------------------------- */

#define TND_OUT_MAX    640u    /* most bytes one VDU byte can expand to (a teletext row redrawn) */
#define TND_COPY_MAX   96u     /* most bytes tnd_out_copyflush writes */
#define TND_REPAINT_MAX 900u   /* most bytes tnd_out_repaint writes (a teletext row of mosaics) */
#define TND_COLS_MAX   80u
#define TND_ROWS_MAX   32u

typedef struct {
   uint8_t code;                /* the VDU code whose parameters are being collected, 0 = none */
   uint8_t got;                 /* parameters collected so far */
   uint8_t p[5];                /* the ones the translator uses */
   bool    disabled;            /* VDU 21 seen: everything is ignored until VDU 6 */
   bool    coloured;            /* a colour was set: reset it at the end of the line */
   bool    utf8;                /* the pound sign as UTF-8 (else Latin-1) */

   /* a model of the Beeb's text screen: see telnetd_proto.c */
   bool     sync;               /* the cursor position is known (a CLS, MODE, TAB ... was seen) */
   bool     tele;               /* MODE 7 */
   bool     origin_ok;          /* the terminal's row 0 is the Beeb's: absolute positions can be sent */
   bool     colok;              /* the column of the cursor is known, so a line can be wrapped by hand */
   bool     curoff;             /* the Beeb's cursor is off (VDU 23,1,0) */
   uint8_t  mode, cols, rows;
   uint8_t  wl, wb, wr, wt;     /* the text window: left, bottom, right, top */
   uint8_t  cx, cy;             /* where the next character goes */
   uint8_t  fg, bg;             /* the colours set: logical colour numbers */
   uint8_t  ncol;               /* how many logical colours the mode has: 2, 4, 8 or 16 */
   uint8_t  pal[16];            /* the physical colour (0-7) each logical colour shows as */
   bool     cc_on, hl_on;       /* the copy cursor is active; its mark is on the terminal */
   uint8_t  ccx, ccy, hlx, hly;
   uint8_t  pend[8];            /* cursor keys waiting for the Beeb to be quiet */
   uint8_t  npend;
   uint32_t last_us;            /* when the Beeb last printed something */
   bool     dirty;              /* a rectangle the terminal shows wrong (a narrow window scrolled or cleared) */
   uint8_t  dl, dt, dr, db;     /* ... left, top (the next row to draw), right, bottom */
   uint8_t  ch[TND_ROWS_MAX][TND_COLS_MAX];   /* what is on each cell */
   uint8_t  at[TND_ROWS_MAX][TND_COLS_MAX];   /* and its colours; bit 7: seen, bit 6: no colour set */
   uint8_t  lattr[TND_ROWS_MAX];  /* MODE 7: the line attribute the terminal has (0 normal, 3 top, 4 bottom of double height) */
   uint8_t  tsgr;               /* MODE 7: the colours the terminal has (fg | bg << 3 | flash << 6), 0xFF unknown */
   bool     tek;                /* the terminal is xterm: graphics (VDU 25) are drawn in its Tektronix 4014 window */
   bool     tek_on;             /* ... and it is in Tektronix mode now */
   int16_t  gx, gy, ox, oy;     /* the Beeb's graphics cursor and origin (VDU 29), in its 1280 x 1024 units */
   int16_t  g1x, g1y, g2x, g2y; /* the two points visited before it, for a triangle */
} tnd_out_t;

void   tnd_out_reset(tnd_out_t *s, bool utf8);

/* The screen size the model assumes until the Beeb sends a MODE (the daemon's
   telnetd_mode setting): the Beeb's mode at the start cannot be read.  Nothing
   on the screen is known and the cursor position is not (until a CLS, MODE,
   TAB ...).  tnd_out_set_mode is the Beeb's own MODE: a cleared screen. */
void   tnd_out_assume_mode(tnd_out_t *s, uint8_t mode);

/* The Beeb's cursor is known (helper 20 read it from the MOS): the model can
   follow from there, though what is on the screen is not known. */
void   tnd_out_at(tnd_out_t *s, uint8_t x, uint8_t y);

/* Feed one byte of the Beeb's output; writes the terminal's bytes to dst
   (TND_OUT_MAX at most) and returns how many.  Parameter bytes of VDU codes
   are consumed here, so nothing a terminal would print as junk gets through.
   0xFF never appears in the output, so no IAC escaping is needed. */
size_t tnd_out_byte(tnd_out_t *s, uint8_t c, uint8_t dst[TND_OUT_MAX]);

/* A new terminal is connected to a model that has been following the Beeb all
   along: forget what belonged to the last one.  tnd_out_repaint then draws the
   model's screen on it, a row at a time, from the first row that has anything on
   it, as plain lines under whatever the terminal already shows (no clear; one
   row past the last puts the cursor and colours right).  It returns the bytes for
   that row, 0 for a row it does not draw.  The terminal's rows are then no longer
   the Beeb's, so tnd_out_origin_lost: until the Beeb next clears the screen the
   translator sends only relative moves, and clears once before an absolute one. */
void   tnd_out_session(tnd_out_t *s);
void   tnd_out_origin_lost(tnd_out_t *s);

/* Is a row of the screen exactly this text (and blanks after it)? */
bool   tnd_out_has_line(const tnd_out_t *s, const char *text, size_t len);
bool   tnd_out_blank(const tnd_out_t *s);   /* the model knows of no character on the screen */
size_t tnd_out_colours(const tnd_out_t *s, uint8_t dst[16]);
size_t tnd_out_repaint(const tnd_out_t *s, unsigned row, uint8_t dst[TND_REPAINT_MAX]);

/* A text window narrower than the screen cannot be scrolled or cleared on a terminal, which
   scrolls and clears whole lines.  The model does it, and marks the window as drawn wrong;
   the daemon then calls this, a row at a time, until it says nothing is left (0): each call
   draws one row of the rectangle from the model and puts the cursor and colours back. */
size_t tnd_out_dirty_row(tnd_out_t *s, uint8_t dst[TND_REPAINT_MAX]);

/* The terminal can draw Tektronix 4014 graphics (xterm said so): MOVE, DRAW and PLOT (VDU 25)
   and CLG are drawn in its Tek window.  Off by default, and then they are swallowed as before. */
void   tnd_out_tek(tnd_out_t *s, bool on);

void   tnd_out_touch(tnd_out_t *s, uint32_t now_us);
void   tnd_out_copykey(tnd_out_t *s, uint8_t key);
size_t tnd_out_copyflush(tnd_out_t *s, uint32_t now_us, uint8_t dst[TND_COPY_MAX]);

/* ---- line mode ----------------------------------------------------------------
   A client that is not a terminal (nc, a script, a raw socket) or a telnet client that
   refuses the server's echo gets line mode: it types whole lines itself and is sent
   what the Beeb prints as plain text, without the Beeb's echo of the line it typed.

   Choosing the mode (tnd_decide), from what the client has answered to the greeting
   (IAC WILL ECHO, WILL SGA, DO SGA), latest answer first:
      DONT ECHO or DONT SGA                -> line   (it refuses to let the server echo)
      DO ECHO (and SGA not refused)        -> screen (a terminal: character at a time)
      data before any answer, or no answer
      within TND_DECIDE_US                 -> line   (nc, a script)
      otherwise                            -> not yet decided
   The rules are a function of the state, so a late DO ECHO turns a line mode session
   into a screen one, and a DONT ECHO (a client's "mode line") the other way.  The
   setting (telnetd_linemode) overrides them. */

#define TND_MODE_UNDECIDED 0u
#define TND_MODE_SCREEN    1u
#define TND_MODE_LINE      2u
#define TND_SET_AUTO       0u
#define TND_SET_SCREEN     1u
#define TND_SET_LINE       2u
#define TND_DECIDE_US      750000u

uint8_t tnd_decide(const tnd_in_t *s, uint8_t setting, uint32_t now_us, uint32_t start_us);

/* Does an end of output (IAC GA) mean anything to this client?  Only one that speaks
   telnet and has not agreed to suppress go-ahead (DO SGA); to a raw client it is junk. */
bool    tnd_ga_wanted(const tnd_in_t *s);

#define TND_LINE_EXP     160u    /* keys whose echo is waited for */
#define TND_LINE_OUT_MAX (4u * (TND_LINE_EXP + 1u))   /* most bytes one call writes */
#define TND_ECHO_US      1000000u   /* an echo that has not come (or not finished) by then never will */
#define TND_GA_US        300000u    /* the Beeb quiet this long, its keys taken: end of output */

typedef struct {
   uint8_t  code, got;          /* the VDU code whose parameters are being skipped, and how many so far */
   bool     disabled;           /* VDU 21 seen: nothing until VDU 6 */
   bool     utf8;               /* the pound sign as UTF-8 (else Latin-1) */
   bool     tele;               /* MODE 7 */
   bool     gfx;                /* MODE 7: a graphics colour code earlier on this line */
   bool     cr;                 /* a CR that was not followed by LF: a new line before more text */
   uint8_t  col;                /* characters on the client's line (capped): 0 at its start */
   uint8_t  exp[TND_LINE_EXP];  /* the keys given to the Beeb whose echo is still to come */
   uint16_t eh, en;             /* ... the oldest, and how many */
   uint16_t matched;            /* bytes of the Beeb's output that matched them so far, held back */
   uint16_t skip;               /* ... matched from a later line: the keys before it (see line_restart) */
   bool     nl;                 /* a line's echo matched: its new line (CR ... LF) is being dropped */
   bool     ga_armed;           /* something happened since the last end of output */
   uint32_t typed_us, out_us;   /* the last key given, the last byte from the Beeb */
} tnd_line_t;

/* mode is the Beeb's screen MODE as far as it is known (0-7). */
void   tnd_line_reset(tnd_line_t *s, bool utf8, uint8_t mode);

/* How many more keys the echo can be waited for: the daemon gives the Beeb no more than
   this, so that every key it types is matched. */
size_t tnd_line_room(const tnd_line_t *s);

/* A key has been given to the Beeb (into its keyboard buffer): its echo is expected. */
void   tnd_line_typed(tnd_line_t *s, uint8_t key, uint32_t now_us);

/* ESCAPE was sent: what was typed ahead is gone, so its echo will not come. */
void   tnd_line_escape(tnd_line_t *s);

/* One byte the Beeb printed; writes the client's bytes (TND_LINE_OUT_MAX at most).
   Plain text: printable characters, CR LF for a new line, BEL; the pound sign; a
   DELETE as BS SP BS.  Everything else - cursor moves, windows, colours, MODE,
   graphics, teletext control codes (a space), VDU 23 and the parameter bytes of all
   of them - is dropped.  No 0xFF is ever written. */
size_t tnd_line_beeb(tnd_line_t *s, uint8_t c, uint32_t now_us, uint8_t *dst);

/* Call regularly: an echo that has stopped coming is given up (what was held back
   from it is written).  Returns the bytes written (TND_LINE_OUT_MAX at most). */
size_t tnd_line_tick(tnd_line_t *s, uint32_t now_us, uint8_t *dst);

/* True once each time the Beeb has gone quiet: something happened, nothing has been
   printed or typed for TND_GA_US, no key is waiting (keys_waiting: the daemon's and
   the redirect's queues) and no echo is half matched.  The daemon then sends IAC GA
   if tnd_ga_wanted. */
bool   tnd_line_ga_due(tnd_line_t *s, uint32_t now_us, bool keys_waiting);

/* ---- a session that has stopped moving -------------------------------------- */

/* True when something is waiting on the client (`pending`: bytes sent and not yet
   acknowledged, or keys refused for lack of room) and nothing has moved for
   limit_us.  An idle but healthy session has nothing pending, so is never stalled.
   The clock is the 32-bit microsecond counter, so it may wrap. */
bool tnd_stalled(bool pending, uint32_t now_us, uint32_t progress_us, uint32_t limit_us);

#endif /* TELNETD_PROTO_H */
