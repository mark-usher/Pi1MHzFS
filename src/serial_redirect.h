#ifndef SERIAL_REDIRECT_H
#define SERIAL_REDIRECT_H

#include <stddef.h>
#include <stdint.h>

void serial_redirect_init(uint8_t instance, uint8_t address);
uint8_t serial_redirect_address(void);      /* stub's FRED offset, 0 = disabled */
void serial_redirect_status(char *buf, size_t len);

/* Main loop only: the bytes the Beeb has sent, and room for / bytes to it. */
size_t serial_redirect_read(uint8_t *dst, size_t max);
bool   serial_redirect_pending(void);       /* the Beeb has printed something not read yet */
size_t serial_redirect_room(void);

/* The Beeb's screen MODE (0-7), reported by helper 20 each time it hooks in, and
   a count that changes with every report. */
uint32_t serial_redirect_mode_gen(void);
bool serial_redirect_scan_ok(void);        /* the ROM can send the Beeb's screen when a byte &FF is put in the keyboard buffer */
uint32_t serial_redirect_reset_gen(void);   /* ... and one that counts the BBC's resets */
uint8_t  serial_redirect_beeb_mode(void);
void     serial_redirect_beeb_cursor(uint8_t *col, uint8_t *row);   /* ... and its text cursor */
size_t serial_redirect_write(const uint8_t *src, size_t len);

/* Telnet mode (helper 20) only, main loop only: raise the Beeb's ESCAPE
   condition and discard what is queued for its keyboard.  A no-op otherwise. */
void serial_redirect_escape(void);
void serial_redirect_break(void);       /* a BREAK, as the BREAK key: see the .c */

#endif
