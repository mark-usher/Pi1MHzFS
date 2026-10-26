/* fakepi.c - the Pi1MHz around the telnet daemon, for the emulator harness (run.py).

   Built into a shared library with the firmware's own src/serial_redirect.c, src/telnetd.c,
   src/telnetd_proto.c, src/net_telnet.c, src/lib/textparse.c and src/wifi/lwip_util.c, so the
   code under test is the Pi's: the stub in FRED and its trips, the session, the translators.
   What is faked here is what those files call into:

   - the Pi1MHz board: FRED (&FC00-&FCFF) as 256 bytes the Beeb reads and writes (a write stores
     the byte and calls the callback registered for its address, as the FIQ does), nIRQ, the polls,
     the microsecond clock (the emulated Beeb's: run.py advances it);
   - Pi1MHz.cfg (fp_cfg) and the network config (the hostname);
   - lwIP: the listening ports and one client connection at a time, whose bytes run.py sends
     (fp_send) and reads (fp_recv); the tests/telnetd/session/ headers stand in for lwIP's.

   The Beeb side (beeb.py) is a 6502 with the real MOS, BASIC and the TelnetD ROM; it boots and
   hooks the stub in itself, exactly as on the bench. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Pi1MHz.h"
#include "rpi/asm-helpers.h"
#include "config.h"
#include "serial_redirect.h"
#include "serial_modem.h"
#include "telnetd.h"
#include "lwip/tcp.h"
#include "lwip/altcp.h"
#include "lwip/priv/tcp_priv.h"
#include "wifi/wifi.h"

/* ---- the board ---------------------------------------------------------------------------- */
uint32_t Pi1MHz_now_us;
static uint8_t fred[256];
static callback_func_ptr cb[256];
static func_ptr polls[8];
static unsigned npolls;
static bool nirq;

void Pi1MHz_MemoryWrite(uint32_t addr, uint8_t data) { fred[addr & 0xFFu] = data; }
void Pi1MHz_MemoryWrite_FIQ(uint32_t addr, uint8_t data) { fred[addr & 0xFFu] = data; }
uint8_t Pi1MHz_MemoryRead(uint32_t addr) { return fred[addr & 0xFFu]; }
void Pi1MHz_EmulatedMemoryByte(unsigned int gpio) { (void)gpio; }
void Pi1MHz_Register_Memory(unsigned int access, unsigned int addr, callback_func_ptr fn)
{
   if (access == WRITE_FRED)
      cb[addr & 0xFFu] = fn;
}
void Pi1MHz_Register_Poll(func_ptr fn, const char *name)
{
   (void)name;
   for (unsigned i = 0; i < npolls; i++)
      if (polls[i] == fn)
         return;
   if (npolls < sizeof polls / sizeof polls[0])
      polls[npolls++] = fn;
}
void Pi1MHz_nIRQ_ASSERT(uint8_t src) { (void)src; nirq = true; }
void Pi1MHz_nIRQ_CLEAR(uint8_t src) { (void)src; nirq = false; }
unsigned int _disable_interrupts_cspr(void) { return 0; }
void _restore_cpsr(unsigned int cpsr) { (void)cpsr; }
uint32_t RPI_GetSystemTime(void) { return Pi1MHz_now_us; }

/* The serial stream's other user, the modem: not run here. */
void modem_reset(void) { }
void modem_attach(void) { }

/* ---- Pi1MHz.cfg and the network ------------------------------------------------------------ */
#define CFG_MAX 32
static char cfg_key[CFG_MAX][40], cfg_val[CFG_MAX][80];
static unsigned ncfg;

const char *config_get(const char *key)
{
   for (unsigned i = 0; i < ncfg; i++)
      if (strcmp(cfg_key[i], key) == 0)
         return cfg_val[i];
   return NULL;
}
bool config_get_flag(const char *key, bool dflt)
{
   const char *v = config_get(key);
   if (v == NULL || v[0] == '\0')
      return dflt;
   return !(v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F');
}
int config_emulator_override(const char *name, uint8_t *addr) { (void)name; (void)addr; return 0; }

static wifi_config_t wcfg;
const wifi_config_t *wifi_get_config(void) { return &wcfg; }

/* ---- lwIP: listeners and one client ---------------------------------------------------------- */
const ip_addr_t ip_addr_any = { 0u };
#define PCB_MAX 16
static struct tcp_pcb *pcbs[PCB_MAX];
static int npcbs;
static struct tcp_pcb *client;                 /* the connection run.py drives */
static uint8_t cout[1u << 20];                  /* what the client was sent, not read yet */
static size_t  cout_n;

char *ip4addr_ntoa(const ip4_addr_t *a)
{
   static char s[16];
   snprintf(s, sizeof s, "%u.%u.%u.%u", (unsigned)(a->addr & 0xFFu), (unsigned)(a->addr >> 8 & 0xFFu),
            (unsigned)(a->addr >> 16 & 0xFFu), (unsigned)(a->addr >> 24));
   return s;
}
struct tcp_pcb *tcp_new_ip_type(u8_t type)
{
   (void)type;
   if (npcbs == PCB_MAX)
      return NULL;
   struct tcp_pcb *p = calloc(1u, sizeof *p);
   p->id = npcbs;
   p->sndbuf = 8192u;
   pcbs[npcbs++] = p;
   return p;
}
err_t tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ip, u16_t port) { (void)ip; pcb->port = port; return ERR_OK; }
struct tcp_pcb *tcp_listen_with_backlog(struct tcp_pcb *pcb, u8_t b) { (void)b; pcb->state = LISTEN; return pcb; }
void  tcp_arg(struct tcp_pcb *pcb, void *arg) { pcb->arg = arg; }
void  tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn f) { pcb->accept = f; }
void  tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn f) { pcb->recv = f; }
void  tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn f) { pcb->sent = f; }
void  tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn f, u8_t i) { (void)pcb; (void)f; (void)i; }
void  tcp_err(struct tcp_pcb *pcb, tcp_err_fn f) { pcb->errf = f; }
err_t tcp_output(struct tcp_pcb *pcb) { (void)pcb; return ERR_OK; }
void  tcp_recved(struct tcp_pcb *pcb, u16_t len) { pcb->recved += len; }
u16_t tcp_sndbuf(const struct tcp_pcb *pcb) { return pcb->sndbuf; }
void  tcp_nagle_disable(struct tcp_pcb *pcb) { (void)pcb; }
void  tcp_rexmit_rto(struct tcp_pcb *pcb) { (void)pcb; }
u16_t altcp_sndbuf(struct altcp_pcb *pcb) { (void)pcb; return 0u; }
err_t altcp_write(struct altcp_pcb *pcb, const void *d, u16_t len, u8_t f) { (void)pcb; (void)d; (void)len; (void)f; return ERR_VAL; }

err_t tcp_write(struct tcp_pcb *pcb, const void *d, u16_t len, u8_t flags)
{
   (void)flags;
   if (pcb->closed || pcb->aborted)
      return ERR_VAL;
   if (pcb == client && cout_n + len <= sizeof cout) {
      memcpy(cout + cout_n, d, len);
      cout_n += len;
   }
   return ERR_OK;                               /* sent and acknowledged at once */
}
err_t tcp_close(struct tcp_pcb *pcb) { pcb->closed = 1; return ERR_OK; }
void  tcp_abort(struct tcp_pcb *pcb) { pcb->aborted = 1; }

static struct pbuf *pbuf_make(const void *d, size_t n)
{
   struct pbuf *p = malloc(sizeof *p + n);
   p->next = NULL;
   p->payload = p + 1;
   p->len = p->tot_len = (u16_t)n;
   memcpy(p->payload, d, n);
   return p;
}
u8_t pbuf_free(struct pbuf *p)
{
   u8_t n = 0u;
   while (p != NULL) {
      struct pbuf *next = p->next;
      free(p);
      p = next;
      n++;
   }
   return n;
}
void pbuf_cat(struct pbuf *h, struct pbuf *t)
{
   struct pbuf *q = h;
   for (; q->next != NULL; q = q->next)
      q->tot_len = (u16_t)(q->tot_len + t->tot_len);
   q->tot_len = (u16_t)(q->tot_len + t->tot_len);
   q->next = t;
}
struct pbuf *pbuf_free_header(struct pbuf *q, u16_t size)
{
   while (q != NULL && size >= q->len) {
      struct pbuf *next = q->next;
      size = (u16_t)(size - q->len);
      free(q);
      q = next;
   }
   return q;
}

/* ---- run.py's side ------------------------------------------------------------------------ */

void fp_cfg(const char *k, const char *v)
{
   for (unsigned i = 0; i < ncfg; i++)
      if (strcmp(cfg_key[i], k) == 0) {
         snprintf(cfg_val[i], sizeof cfg_val[i], "%s", v);
         return;
      }
   if (ncfg < CFG_MAX) {
      snprintf(cfg_key[ncfg], sizeof cfg_key[ncfg], "%s", k);
      snprintf(cfg_val[ncfg], sizeof cfg_val[ncfg], "%s", v);
      ncfg++;
   }
}

/* The Pi starts: the stub written into FRED at &FCCC, the daemon listening. */
void fp_start(uint32_t now_us)
{
   Pi1MHz_now_us = now_us;
   memset(fred, 0xFF, sizeof fred);
   snprintf(wcfg.hostname, sizeof wcfg.hostname, "%s", "Pi1MHz");
   serial_redirect_init(3, 0xCCu);
   telnetd_init();
   telnetd_attach();
}

const uint8_t *fp_fred(void) { return fred; }
bool fp_nirq(void) { return nirq; }

/* The Beeb wrote a FRED byte: as on the Pi, a port's callback is called (the stub's TX, gate, full and
   control ports), and the byte is kept only where the Pi made the address memory
   (Pi1MHz_EmulatedMemoryByte: the stub's workspace).  A write to a port leaves what the Beeb reads there
   - the TX port is also the stub's first instruction. */
void fp_write(uint8_t addr, uint8_t data)
{
   if (cb[addr] == Pi1MHz_EmulatedMemoryByte)
      fred[addr] = data;
   else if (cb[addr] != NULL)
      cb[addr](data);
}

/* The main loop's pass at this time. */
void fp_poll(uint32_t now_us)
{
   Pi1MHz_now_us = now_us;
   for (unsigned i = 0; i < npolls; i++)
      polls[i]();
}

/* A client connects to port (23 or the raw port).  telnet: it answers the greeting at once
   (DO ECHO, DO SGA, WILL SGA) as telnet clients do; otherwise it is raw (nc). */
int fp_connect(uint16_t port, bool telnet)
{
   struct tcp_pcb *l = NULL;
   for (int i = 0; i < npcbs; i++)
      if (pcbs[i]->state == LISTEN && pcbs[i]->port == port)
         l = pcbs[i];
   if (l == NULL || l->accept == NULL)
      return -1;
   client = tcp_new_ip_type(0u);
   if (client == NULL)
      return -1;
   client->remote_ip.addr = 0x0100007Fu;
   client->state = ESTABLISHED;
   cout_n = 0u;
   (void)l->accept(l->arg, client, ERR_OK);
   if (telnet) {
      static const uint8_t answer[] = { 255, 253, 1, 255, 253, 3, 255, 251, 3 };
      if (client->recv != NULL)
         (void)client->recv(client->arg, client, pbuf_make(answer, sizeof answer), ERR_OK);
   }
   return client->id;
}

void fp_send(const uint8_t *d, int n)
{
   if (client != NULL && client->recv != NULL && !client->closed && !client->aborted && n > 0)
      (void)client->recv(client->arg, client, pbuf_make(d, (size_t)n), ERR_OK);
}

int fp_recv(uint8_t *dst, int max)
{
   int n = (int)cout_n < max ? (int)cout_n : max;
   memcpy(dst, cout, (size_t)n);
   memmove(cout, cout + n, cout_n - (size_t)n);
   cout_n -= (size_t)n;
   return n;
}

void fp_close(void)
{
   if (client != NULL && client->recv != NULL && !client->closed && !client->aborted)
      (void)client->recv(client->arg, client, NULL, ERR_OK);
}

bool fp_client_open(void) { return client != NULL && !client->closed && !client->aborted; }

void fp_status(char *dst, int max) { telnetd_status(dst, (size_t)max); }
