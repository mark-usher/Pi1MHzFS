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

/* Most keys one input byte can release: Alt-P ended by a character above 127 is ESCAPE, P, then
   TND_KEY_LIT and its byte.  (A UTF-8 or Latin-1 lead byte pending when ESC comes is given at the
   ESC, so it never adds to these; the host tests check every call against this bound.) */
#define TND_IN_KEYS    4u

/* Not a key but a request: the client pressed ESC (a lone ESC, once it is clear
   no sequence follows) or Ctrl-C.  The Beeb's ESCAPE is a condition the keyboard
   scan raises, not a character in the buffer, so it cannot travel as a key: the
   daemon passes it to serial_redirect_escape().  0 is free for it because NUL is
   never a key. */
#define TND_KEY_ESCAPE 0u

/* Also a request and not a key: F12 is BREAK.  The daemon passes it to serial_redirect_break().
   254 is never a Beeb key the translator makes. */
#define TND_KEY_BREAK  0xFEu
/* SHIFT-F12 is SHIFT-BREAK (the boot: the auto-start ROM says SHIFT pressed to the MOS's auto-boot
   test), CTRL-F12 (and CTRL-SHIFT-F12) CTRL-BREAK, as near as software can (see serial_redirect_break). */
#define TND_KEY_SHIFTBREAK 0xF9u
#define TND_KEY_CTRLBREAK  0xF8u

/* F11: draw the screen again.  The daemon types *TELNETD for the Beeb, and the auto-start
   ROM answers by sending what is on the screen. */
#define TND_KEY_REFRESH 0xFDu

/* Page Down: SHIFT, pressed once, for paged mode (VDU 14), which waits for SHIFT at the end of
   each page.  A terminal cannot send SHIFT on its own; the daemon puts SHIFTKEY in the keyboard
   buffer and the auto-start ROM answers the MOS's "is SHIFT pressed" with it (KEYV). */
#define TND_KEY_SHIFT  0xFCu

/* The next key is a byte for the Beeb to read as it is (a character above 127): the daemon sends it
   behind the ROM's LITKEY (ROM build 13), which reads it past the MOS's soft and cursor keys. */
#define TND_KEY_LIT    0xFAu

/* Shell mode only (tnd_in_t.edit_keys): Home, and Delete (the character under the cursor), which
   screen mode does not have (it sends DELETE for both Delete keys). */
#define TND_KEY_HOME   0xF7u
#define TND_KEY_DELFWD 0xF6u
#define TND_IN_REPLY   32u     /* most negotiation bytes one input byte needs (WILL LINEMODE's answer) */
#define TND_GREETING_LEN 15u
#define TND_OPT_LINEMODE 34u  /* telnet option 34: the client edits lines itself (RFC 1184) */
#define TND_OPT_TM     6u      /* telnet option 6: timing mark (RFC 860), asked for after an IP to end a flush */
#define TND_OPT_BINARY 0u      /* telnet option 0: an 8-bit path (RFC 856), how a client asks for teletype mode */
#define TND_OPT_TTYPE  24u     /* telnet option 24: the client's terminal type (RFC 1091) */
#define TND_OPT_NAWS   31u     /* telnet option 31: the client's window size (RFC 1073) */

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
   uint8_t  sb[40];             /* a subnegotiation being read (IAC IAC as one 255) */
   char     ttype[32];          /* the terminal type the client said (TTYPE IS), "" until then */
   bool     ttype_got;
   uint8_t  nsb;
   uint16_t win_cols;           /* the client's window (NAWS), 0 until it says */
   uint16_t win_rows;
   uint8_t  win_gen;            /* counts the window sizes received: a change shows as a new count */
   bool     naws_no;            /* the client will not send its window size (WONT NAWS) */
   uint32_t u8_cp;              /* a UTF-8 character being read */
   uint8_t  u8_need;            /* ... and its continuation bytes still to come */
   uint8_t  u8_lead;            /* its first byte, while nothing has followed it */
   uint32_t u8_us;              /* ... and when it came: a Latin-1 client's lone byte is given after TND_ESC_US */
   uint8_t  after;              /* the state a telnet command inside an escape sequence goes back to */
   uint32_t sb_us;              /* when the subnegotiation being read began: one never ended is dropped */
   uint8_t  agreed;             /* options the client agreed to and could take back (AGREED_* in the .c) */
   bool     lit_ok;             /* set by the daemon: the Beeb can take bytes above 127 (TND_KEY_LIT) */
   bool     tele;               /* set by the daemon: MODE 7, so teletext's glyphs map back to its codes */
   /* Teletype mode: every byte is a key as it is, no escape sequences or UTF-8 decoded: ESC (27) is the
      Beeb's ESCAPE key, a byte above 127 goes behind TND_KEY_LIT (or is dropped if !lit_ok), and only
      telnet's IAC commands are read, unless notelnet (a raw TCP port: no telnet at all). */
   bool     raw;                /* set by the daemon */
   bool     notelnet;           /* set by the daemon: not even IAC */
   bool     bin_in;             /* the client will send binary (it said WILL BINARY, we said DO) */
   bool     bin_out;            /* the client asked us to send binary (DO BINARY, we said WILL) */
   /* A client's line mode (Linux telnet's "mode line") is DONT ECHO (and DONT SGA), its character
      mode DO ECHO again: each is answered once per change, and mode_gen counts the changes, so the
      daemon can show the Beeb's line again (the client's own "telnet>" prompt is over it). */
   bool     echo_off;           /* the client said DONT ECHO, we said WONT */
   bool     sga_off;            /* the client said DONT SGA, we said WONT */
   uint8_t  mode_gen;
   /* In line mode the client echoes the line itself, RETURN as a new line (which at the bottom scrolls its
      window): line_gen counts the lines it sent, so the daemon can draw the screen again from the Beeb's. */
   uint8_t  line_gen;
   /* LINEMODE (RFC 1184), which Linux telnet offers at "mode line": taken, so the client's special
      characters are ours to set - ESC its interrupt (sent at once as IAC IP, read as the ESC byte),
      Ctrl-C its abort (IAC ABORT, ESCAPE) and "~" a forwarding character, so the rest of F12
      (ESC [ 2 4 ~) or Page Down (ESC [ 6 ~) follows the IP at once instead of waiting for RETURN. */
   bool     lm;                 /* the client said WILL LINEMODE, we said DO */
   bool     lm_offered;         /* ... its first WILL LINEMODE, which Linux telnet sends as it connects, was
                                   refused (DONT): only a later one, at "mode line", is taken */
   /* What the client has said, for choosing screen or line mode (tnd_decide). */
   bool     telnet;             /* the client has sent a telnet command (IAC ...): it speaks telnet */
   bool     data;               /* the client has sent data, not only negotiation */
   bool     sga_do;             /* it agreed to our WILL SGA (DO SGA): no IAC GA for it */
   bool     refuse_echo;        /* set by the daemon, line mode by the setting: DO ECHO is refused */
   bool     edit_keys;          /* set by the daemon, shell mode: Home and Delete as TND_KEY_HOME, TND_KEY_DELFWD */
} tnd_in_t;

void   tnd_in_reset(tnd_in_t *s);

/* The server's opening offer: IAC WILL ECHO, IAC WILL SGA, IAC DO SGA, IAC DO NAWS (the client's
   window size, as it is and whenever it changes: tnd_in_t's win_cols, win_rows, win_gen), IAC DO
   TTYPE (its terminal type, asked for once when it agrees: tnd_in_t's ttype).
   Writes TND_GREETING_LEN bytes. */
size_t tnd_greeting(uint8_t *out);

/* Feed one byte from the client.  Returns how many Beeb keys it released
   (0 to TND_IN_KEYS, written to keys[]); *replen is how many bytes of telnet
   negotiation (rep[], at most TND_IN_REPLY) go back to the client. */
size_t tnd_in_byte(tnd_in_t *s, uint8_t c, uint32_t now_us,
                   uint8_t keys[TND_IN_KEYS], uint8_t rep[TND_IN_REPLY],
                   size_t *replen);

/* Call regularly: releases a lone ESC once it has waited TND_ESC_US, and drops
   an escape sequence or subnegotiation that never finished, and a Latin-1 byte held as a
   possible UTF-8 lead.  Returns keys released (0 to TND_IN_KEYS). */
size_t tnd_in_tick(tnd_in_t *s, uint32_t now_us, uint8_t keys[TND_IN_KEYS]);

/* A look ahead through client data not read yet (the daemon's backlog, waiting behind a full key
   ring) for a lone ESC: the ESCAPE key, which is to cut through the backlog, and not the start of a
   cursor key's sequence.  It starts from where tnd_in_byte is, so the bytes of a subnegotiation (a
   window 27 rows high) or of a DCS string (its ESC \ terminator) are not taken for one; telnet
   commands are skipped.  tnd_in_ahead_byte is true at a lone ESC, and at the other keys that cut
   through: F12 (ESC [ 2 4 ~, with SHIFT or CTRL ESC [ 2 4 ; m ~), IAC BRK and IAC ABORT; IAC IP is
   read as an ESC.  tnd_in_ahead_esc_end is true if the data ended just after an ESC (a lone one
   once nothing more comes). */
typedef struct {
   uint8_t st;
   uint8_t ret;                 /* the state a telnet command goes back to */
   bool    raw, notelnet;
} tnd_ahead_t;
void   tnd_in_ahead_start(const tnd_in_t *s, tnd_ahead_t *a);
bool   tnd_in_ahead_byte(tnd_ahead_t *a, uint8_t c);
bool   tnd_in_ahead_esc_end(const tnd_ahead_t *a);

/* The key codes the translator produces, as the MOS keyboard buffer holds them
   (what OSBYTE 138 / INSV into buffer 0 takes): cursor left/right/down/up are
   140/141/142/143 and COPY is 139 (GET returns 136-139 and 135 under *FX4,1:
   the MOS subtracts 4), DELETE is 127, f0-f9 are 128-137, the pound sign is 96.
   ESC and Ctrl-C are TND_KEY_ESCAPE, and so is telnet's IAC IP (Ctrl-C in a client's line mode,
   where its keys wait for RETURN); IAC BRK ("send brk") is TND_KEY_BREAK, as F12 is. */

/* ---- Beeb -> terminal ---------------------------------------------------- */

#define TND_OUT_MAX    640u    /* most bytes one VDU byte can expand to (a teletext row redrawn) */
#define TND_COPY_MAX   512u    /* most bytes tnd_out_copyflush writes (a redraw's line attributes) */
#define TND_REPAINT_MAX 900u   /* most bytes tnd_out_dirty_row writes (a teletext row of mosaics) */
#define TND_COLS_MAX   80u
#define TND_ROWS_MAX   32u

typedef struct {
   uint8_t code;                /* the VDU code whose parameters are being collected, 0 = none */
   uint8_t got;                 /* parameters collected so far */
   uint8_t p[9];                /* the ones the translator uses (VDU 23's character and its 8 rows) */
   bool    disabled;            /* VDU 21 seen: everything is ignored until VDU 6 */
   bool    coloured;            /* a colour was set: reset it at the end of the line */
   bool    utf8;                /* the pound sign as UTF-8 (else Latin-1) */
   bool    sep_glyphs;          /* MODE 7's separated mosaics as separated sextants (U+1CE51-); else as contiguous */
   bool    bbcfont;             /* the terminal (type "...bbc...") has the BBC Micro MOS font with its private-use
                                   pieces, 80 columns wide: each Beeb character is drawn as 80 / cols pieces of
                                   it (halves in 40 columns and MODE 7, quarters in 20), each MODE in its own
                                   shape, and teletext double height as top and bottom pieces, not DECDHL */
   /* Characters a program defined (VDU 23,c, c 32-255; with a second processor the MOS keeps each one's
      own, and 128-255 are blank until defined): drawn as blocks of their bitmap. */
   uint8_t  udg[224][8];
   uint8_t  udg_on[28];         /* bit c - 32: character c has been defined */

   /* a model of the Beeb's text screen: see telnetd_proto.c */
   bool     sync;               /* the cursor position is known (a CLS, MODE, TAB ... was seen) */
   bool     tele;               /* MODE 7 */
   bool     origin_ok;          /* the terminal's row 0 is the Beeb's: absolute positions can be sent */
   bool     colok;              /* the column of the cursor is known, so a line can be wrapped by hand */
   bool     curoff;             /* the Beeb's cursor is off (VDU 23,1,0) */
   bool     paged;              /* paged mode on (VDU 14, until VDU 15 or a reset) */
   bool     cc_exact;           /* copy keys are given only when the Beeb has taken them (ROM build 11):
                                   no guessing from the screen whether it is editing a line */
   uint8_t  mode, cols, rows;
   uint8_t  wl, wb, wr, wt;     /* the text window: left, bottom, right, top */
   uint8_t  cx, cy;             /* where the next character goes */
   uint8_t  fg, bg;             /* the colours set: logical colour numbers */
   uint8_t  ncol;               /* how many logical colours the mode has: 2, 4, 8 or 16 */
   uint8_t  pal[16];            /* the physical colour (0-7) each logical colour shows as */
   bool     cc_on, hl_on;       /* the copy cursor is active; the write cursor's block is on the terminal */
   bool     parked;             /* the terminal's cursor stands on the copy cursor, not where typing goes */
   uint8_t  ccx, ccy, hlx, hly;
   uint8_t  pend[8];            /* cursor keys waiting for the Beeb to be quiet */
   uint8_t  npend;
   uint32_t last_us;            /* when the Beeb last printed something */
   uint32_t drawn;              /* characters written to the model: a key that drew none wrote the screen itself */
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
   bool     smerge;             /* the next screen read is compared with the model (tnd_out_scan_merge) */
   bool     rescan;             /* ... and was cut short: the daemon asks for an ordinary one */
   uint8_t  sread;              /* an ordinary screen read: 1 asked for, 2 between its VDU 26 and 28 (tnd_out_scan_full) */
   uint8_t  sm_st, sm_x, sm_y, sm_n;
   uint8_t  sm_tail[8];         /* the read's last bytes: VDU 28 and its window, VDU 31 and the cursor */
   uint8_t  sh[TND_ROWS_MAX][TND_COLS_MAX];   /* the read's cells */
} tnd_out_t;

/* The boot banners.  A ROM that starts the daemon at the first service call (the auto-start ROM
   does) is hooked in before the MOS prints its banner, so what the Beeb prints in the first few
   seconds afterwards - the MOS, filing system and language banners - is kept, a line at a time,
   for the greeting of the next session.  Lines that start with a space (the helper's own message)
   or ">" (a prompt) are not banners.  A program that has read the banners some other way can send
   them in a block the Beeb's screen does not show: VDU 21, the lines, VDU 6.  Only VDU codes count:
   the parameters of a code (a screen read's VDU 31,x,21,c) are neither text nor codes. */
#define TND_BANNER_MAX 400u
typedef struct {
   char     text[TND_BANNER_MAX];  /* the banner lines, each ended by '\n' */
   unsigned len, lines;
   char     line[80];              /* the line being read */
   unsigned llen;
   bool     blk;                   /* inside a VDU 21 ... VDU 6 block */
   uint8_t  skip;                  /* parameter bytes of a VDU code still to come */
} tnd_banner_t;

void tnd_banner_reset(tnd_banner_t *b);
/* One byte the Beeb printed.  open: the start-up is still going (outside a block, text is kept
   only then).  True when the byte is the language's prompt at the start of a line: the start-up
   is over. */
bool tnd_banner_byte(tnd_banner_t *b, uint8_t c, bool open);

void   tnd_out_reset(tnd_out_t *s, bool utf8);

/* The next screen read (the ROM's answer to the scan key) is compared with the model instead of
   drawn: if every cell agrees nothing is drawn and the terminal keeps its colours; if not, the
   model takes the Beeb's characters (the cells that agree keep their colours) and the terminal is
   cleared and drawn again from it (tnd_out_dirty_row).  For a new session drawn from the model,
   which a program can have left wrong (output with the RS423 copy off, writes to screen memory).
   Anything else arriving first ends it and is handled as usual; if that happens in the middle of
   the read, rescan is set. */
void   tnd_out_scan_merge(tnd_out_t *s);

/* The next screen read is an ordinary one, drawn as it comes.  It places every cell with VDU 31
   and the Beeb is not printing, so a character in the last column does not take the cursor on:
   one in the bottom right cell would scroll the model and the terminal (the read's VDU 31 or 28
   always comes next).  Anything other than the read's own codes ends it. */
void   tnd_out_scan_full(tnd_out_t *s);

/* The screen size the model assumes until the Beeb sends a MODE (the daemon's
   telnetd_mode setting): the Beeb's mode at the start cannot be read.  Nothing
   on the screen is known and the cursor position is not (until a CLS, MODE,
   TAB ...).  (The Beeb's own MODE, a cleared screen, is followed inside the model.) */
void   tnd_out_assume_mode(tnd_out_t *s, uint8_t mode);

/* The Beeb was reset: its colours and cursor are the MOS's defaults again, and a screen read it
   was sending is over.  (Call with tnd_out_assume_mode, which ends VDU 21 and a VDU sequence.) */
void   tnd_out_beeb_reset(tnd_out_t *s);

/* The Beeb's cursor is known (helper 20 read it from the MOS): the model can
   follow from there, though what is on the screen is not known. */
void   tnd_out_at(tnd_out_t *s, uint8_t x, uint8_t y);

/* Feed one byte of the Beeb's output; writes the terminal's bytes to dst
   (TND_OUT_MAX at most) and returns how many.  Parameter bytes of VDU codes
   are consumed here, so nothing a terminal would print as junk gets through.
   0xFF never appears in the output, so no IAC escaping is needed. */
size_t tnd_out_byte(tnd_out_t *s, uint8_t c, uint8_t dst[TND_OUT_MAX]);

/* A new terminal is connected to a model that has been following the Beeb all
   along: forget what belonged to the last one.  The terminal's rows are not the
   Beeb's, so tnd_out_origin_lost: until the Beeb next clears the screen the
   translator sends only relative moves, and clears once before an absolute one. */
void   tnd_out_session(tnd_out_t *s);
void   tnd_out_origin_lost(tnd_out_t *s);

/* Is a row of the screen exactly this text (and blanks after it)? */
bool   tnd_out_has_line(const tnd_out_t *s, const char *text, size_t len);
bool   tnd_out_blank(const tnd_out_t *s);   /* the model knows of no character on the screen */
/* The cursor's row from the window's left edge up to the cursor, as plain text (what a teletype
   joining now would have seen of the line it is on, a prompt such as ">"): 0 if the model does
   not know every cell of it, or there is nothing to show. */
size_t tnd_out_cursor_line(const tnd_out_t *s, char *dst, size_t max);
size_t tnd_out_colours(const tnd_out_t *s, uint8_t dst[16]);

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

/* While the copy cursor is in use the terminal's cursor is left on it, as the Beeb's flashing
   cursor is (tnd_out_copyflush).  Before anything the Beeb prints is sent, this puts the
   terminal's cursor back where the Beeb writes (0 bytes if it is there already). */
#define TND_UNPARK_MAX 16u
size_t tnd_out_unpark(tnd_out_t *s, uint8_t dst[TND_UNPARK_MAX]);

/* The terminal cleared and drawn again from the model, by position (a new window size, or rows
   that are not the Beeb's): writes the clear, MODE 7's line attributes and the cursor, and puts
   every row to be drawn by tnd_out_dirty_row.  0 if the cursor is not known. */
size_t tnd_out_redraw(tnd_out_t *s, uint8_t dst[TND_COPY_MAX]);

/* ---- line mode ----------------------------------------------------------------
   A client that is not a terminal (nc, a script, a raw socket) gets line mode: it types
   whole lines itself and is sent what the Beeb prints as plain text, without the Beeb's
   echo of the line it typed.

   Choosing the mode (tnd_decide), from what the client does after the greeting:
      any telnet command (an answer)       -> screen (a telnet client: a terminal)
      data before any answer, or no answer
      within TND_DECIDE_US                 -> line   (nc, a script)
      otherwise                            -> not yet decided
   A telnet client in its own line mode (Linux telnet's "mode line": DONT ECHO, LINEMODE)
   stays in screen mode, which draws the screen again around its local echo.  The setting
   (telnetd_linemode) overrides the rules; shell mode is a terminal's choice (the setting
   or the hot key). */

#define TND_MODE_UNDECIDED 0u
#define TND_MODE_SCREEN    1u
#define TND_MODE_LINE      2u
#define TND_MODE_SHELL     3u          /* a terminal, with the Pi's line editor (tnd_shell_*) */
#define TND_SET_AUTO       0u
#define TND_SET_SCREEN     1u
#define TND_SET_LINE       2u
#define TND_DECIDE_US      750000u

uint8_t tnd_decide(const tnd_in_t *s, uint8_t setting, uint32_t now_us, uint32_t start_us);

/* Does an end of output (IAC GA) mean anything to this client?  Only one that speaks
   telnet and has not agreed to suppress go-ahead (DO SGA); to a raw client it is junk. */
bool    tnd_ga_wanted(const tnd_in_t *s);

#define TND_LINE_EXP     256u    /* keys whose echo is waited for */
#define TND_LINE_GLYPH_MAX 32u   /* most bytes one Beeb byte becomes (a new line, colours, a glyph) */
#define TND_LINE_OUT_MAX (TND_LINE_GLYPH_MAX * (TND_LINE_EXP + 1u))   /* most bytes one call writes */

/* What teletext control codes (MODE 7, &80-&9F) become in line and shell mode. */
#define TND_TTX_SPACES   0u      /* a space each, no escape codes: raw line mode (nc, scripts) */
#define TND_TTX_RENDERED 1u      /* as on the Beeb: colours, mosaics (ANSI), code cells as spaces */
#define TND_TTX_MARKERS  2u      /* each code a marker in its column: its colour, or a reversed letter */
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
   uint8_t  ttx;                /* TND_TTX_*: spaces, rendered or markers */
   uint16_t tt[12];             /* MODE 7 rendered or markers: the row's teletext state (telnetd_proto.c) */
   uint8_t  tsgr;               /* ... the colours the client has, 0xFF unknown */
   uint8_t  rowcol;             /* ... the column on the Beeb's 40-column row */
} tnd_line_t;

/* mode is the Beeb's screen MODE as far as it is known (0-7).  ttx_style starts at
   TND_TTX_SPACES; tnd_line_ttx changes it (shell mode). */
void   tnd_line_reset(tnd_line_t *s, bool utf8, uint8_t mode);
void   tnd_line_ttx(tnd_line_t *s, uint8_t ttx_style);

/* The client's line is about to be written by someone else (the shell's edit line):
   the colours the line translator set are put back to plain.  Bytes, at most 4. */
size_t tnd_line_plain(tnd_line_t *s, uint8_t *dst);

/* One character as a marker (TND_TTX_MARKERS), as the edit line shows a code typed
   with Ctrl-V: at most TND_LINE_GLYPH_MAX bytes, one column. */
size_t tnd_marker(uint8_t c, bool utf8, uint8_t *dst);

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

/* ---- the hot key -------------------------------------------------------------
   Ctrl-\ is a prefix in a terminal session (screen or shell mode): the key after it is
   a command for the daemon, and Ctrl-\ twice sends one Ctrl-\ (code 28) to the Beeb.
      Ctrl-\ m   screen mode <-> shell mode
      Ctrl-\ t   teletext codes rendered <-> markers (line and shell mode)
      Ctrl-\ Ctrl-\   a Ctrl-\ for the Beeb
   Anything else after it is dropped. */
#define TND_HOT_KEY      0x1Cu
#define TND_HOT_NONE     0u      /* not the hot key: the key as it is */
#define TND_HOT_SWALLOW  1u      /* taken, nothing to do */
#define TND_HOT_MODE     2u
#define TND_HOT_TTX      3u
#define TND_HOT_LITERAL  4u      /* send TND_HOT_KEY to the Beeb */

uint8_t tnd_hotkey(bool *armed, uint8_t key);

/* ---- shell mode: the Pi's line editor ----------------------------------------
   A terminal client in shell mode types into an editor on the Pi (readline-like),
   and the line goes to the Beeb when RETURN is pressed; the Beeb's echo of it is
   taken out (the line mode matcher) and its output is shown as in line mode.

   Who gets a key.  A line being edited owns every key.  Otherwise a printable key is
   a probe if the Beeb has been quiet for TND_SH_QUIET_US: it goes to the Beeb at
   once, and if the Beeb's next output is that same character (OSWORD 0 echoing it:
   a command line, INPUT) the editor takes over - the echo is dropped, a DELETE takes
   the key back out of the Beeb's line, and the key starts the edit line.  If the Beeb
   prints something else, or nothing for TND_SH_PROBE_US, a program took the key (GET,
   INKEY) and keys go straight to the Beeb until none has been typed for
   TND_SH_PASS_US.  Keys typed while a probe waits are held and follow its outcome.
   An editing key (arrows, Home, End, Ctrl-A/E/K/U/W/R, RETURN) at a quiet Beeb opens
   the editor directly; while the Beeb is busy it goes to the Beeb as screen mode
   would send it. */
#define TND_SH_LINE      238u        /* longest line (BASIC's) */
#define TND_SH_HIST      16u
#define TND_SH_QUEUE     32u
#define TND_SH_QUIET_US  100000u
#define TND_SH_PROBE_US  250000u
#define TND_SH_PASS_US   500000u
#define TND_SH_REDRAW_US 30000u     /* the edit line is drawn again once the Beeb has been quiet this long */
#define TND_SH_CLI_MAX   (TND_LINE_OUT_MAX + 16u * TND_SH_LINE + 64u)   /* client bytes one call writes */
#define TND_SH_KEYS_MAX  (2u * TND_SH_LINE + 8u)                     /* keys for the Beeb one call gives (a byte
                                                                       above 127 is two: TND_KEY_LIT and it) */

#define TND_SH_IDLE      0u
#define TND_SH_PROBE     1u
#define TND_SH_EDIT      2u
#define TND_SH_PASS      3u

typedef struct {
   uint8_t *cli;   size_t ncli;     /* bytes for the client */
   uint8_t *keys;  size_t nkeys;    /* keys for the Beeb's keyboard buffer */
   bool     escape;                 /* raise the Beeb's ESCAPE (and drop the keys queued) */
} tnd_sh_io_t;

typedef struct {
   tnd_line_t lm;                   /* the Beeb's output, and the echo matcher */
   uint8_t  state;                  /* TND_SH_* */
   uint8_t  line[TND_SH_LINE];      /* the edit line, as characters (codes included) */
   uint16_t len, cur;
   bool     shown;                  /* the edit line is on the client's screen */
   uint16_t shown_cur;              /* ... and its cursor is this far into it */
   uint8_t  probe;                  /* the key sent as the probe */
   bool     del_echo;               /* the DELETE that took it back: its echo is dropped */
   uint8_t  queue[TND_SH_QUEUE];    /* keys typed while the probe waits */
   uint8_t  nq;
   uint32_t probe_us, key_us;
   uint8_t  ctrlv, vhi;             /* Ctrl-V and the hex digits after it */
   uint8_t  hist[TND_SH_HIST][TND_SH_LINE];
   uint16_t hlen[TND_SH_HIST];
   uint8_t  hn;                     /* lines in the history, newest at index 0 */
   int16_t  hpos;                   /* the history line shown, -1 the line being typed */
   uint8_t  saved[TND_SH_LINE];     /* ... which is kept here meanwhile */
   uint16_t savedlen;
   bool     utf8;
   bool     lit_ok;                 /* set by the daemon: the Beeb takes a byte above 127 behind TND_KEY_LIT */
   bool     lit_next;               /* the key after TND_KEY_LIT: a character above 127, as it is */
} tnd_shell_t;

void   tnd_shell_reset(tnd_shell_t *s, bool utf8, uint8_t mode, uint8_t ttx_style);

/* A key from tnd_in (shell mode: tnd_in_t.edit_keys on).  TND_KEY_ESCAPE is passed
   too: the line goes and io->escape asks the daemon for the Beeb's ESCAPE.  A character above
   127 comes as TND_KEY_LIT and then it, and goes to the Beeb the same way (io->keys). */
void   tnd_shell_key(tnd_shell_t *s, uint8_t key, uint32_t now_us, tnd_sh_io_t *io);

/* One byte the Beeb printed. */
void   tnd_shell_beeb(tnd_shell_t *s, uint8_t c, uint32_t now_us, tnd_sh_io_t *io);

/* Call on every pass: a probe or a passthrough that has run its time, an echo given
   up, and the edit line drawn again after the Beeb's output. */
void   tnd_shell_tick(tnd_shell_t *s, uint32_t now_us, tnd_sh_io_t *io);

/* Draw the edit line again (Ctrl-L, or after the daemon wrote to the client). */
void   tnd_shell_redraw(tnd_shell_t *s, tnd_sh_io_t *io);

/* The keyboard buffer code that gives a program the character c with the MOS's
   default settings (*FX221-228, measured on MOS 1.20): &80-&8A come from SHIFT and
   the function keys (&90-&9A), &90-&9A from CTRL and them (&A0-&AA); &D0-&DA,
   &E0-&EA and &F0-&FA are themselves.  0 for one no key gives (&8B-&8F, &9B-&9F,
   &A0-&CF ...): it cannot be typed into a line, only made with CHR$. */
uint8_t tnd_key_for_char(uint8_t c);

/* ---- a session that has stopped moving -------------------------------------- */

/* True when something is waiting on the client (`pending`: bytes sent and not yet
   acknowledged, or keys refused for lack of room) and nothing has moved for
   limit_us.  An idle but healthy session has nothing pending, so is never stalled.
   The clock is the 32-bit microsecond counter, so it may wrap. */
bool tnd_stalled(bool pending, uint32_t now_us, uint32_t progress_us, uint32_t limit_us);

/* ---- the login's rules ------------------------------------------------------- */

/* Wrong passwords are counted per source address, so nobody can lock the owner out from another
   machine.  Every third from an address locks that address out, for TND_LOCK_US the first time and
   twice as long each time after (to TND_LOCK_MAX_US); a right login clears its count.  After any
   wrong password every login prompt ignores what is typed for TND_HOLD_US, whichever connection.
   An address's failures are forgotten after TND_FAIL_DECAY_US without one; a lockout is never
   forgotten early to make room.  The timers count the
   time left down in tnd_login_tick (every main-loop pass), so the 32-bit microsecond clock wrapping
   cannot make an old failure look recent. */
#define TND_LOGIN_ADDRS    8u
#define TND_HOLD_US        2000000u
#define TND_LOCK_US        60000000u
#define TND_LOCK_MAX_US    3840000000u          /* 64 minutes */
#define TND_FAIL_DECAY_US  600000000u           /* 10 minutes */
#define TND_REPLACE_IDLE_US 10000000u           /* a session at the prompt with no typing this long may be replaced */
typedef struct {
   uint32_t addr;
   uint8_t  fails, lockouts;
   uint32_t lock_left_us, decay_left_us;        /* counted down; 0 = not locked / forgotten */
   bool     used;
} tnd_login_addr_t;
typedef struct {
   tnd_login_addr_t a[TND_LOGIN_ADDRS];
   tnd_login_addr_t over;                       /* every address not in a[] while all of a[] is locked out:
                                                   they share one count, so more addresses than a[] holds
                                                   cannot each get fresh tries by pushing a lockout out */
   uint32_t         hold_left_us;
   uint32_t         last_us;
   bool             started;
} tnd_login_t;

void tnd_login_reset(tnd_login_t *l);
void tnd_login_tick(tnd_login_t *l, uint32_t now_us);
bool tnd_login_locked(const tnd_login_t *l, uint32_t addr);      /* a connection from addr is refused */
bool tnd_login_held(const tnd_login_t *l);                       /* typing at a login prompt is ignored */
/* A wrong password from addr: true if that one locks addr out (the session is then closed). */
bool tnd_login_fail(tnd_login_t *l, uint32_t addr);
void tnd_login_ok(tnd_login_t *l, uint32_t addr);
/* May a new connection from new_addr take the place of a session still at the login prompt, from
   old_addr, with nothing typed for idle_us?  Only the same address, or one left idle. */
bool tnd_login_may_replace(uint32_t old_addr, uint32_t new_addr, uint32_t idle_us);

#endif /* TELNETD_PROTO_H */
