/* shpipe COLS: the shell editor (tnd_shell_*) alone.  stdin, one command a line:
     b XX   a byte the Beeb printed (hex)        k XX   a key from the client (hex)
     t N    N microseconds pass (ticks)
   stdout: the client's bytes; stderr: the keys given to the Beeb, as hex. */
#include <stdio.h>
#include <stdlib.h>
#include "telnetd_proto.h"

int main(int argc, char **argv)
{
   static tnd_shell_t s;
   static uint8_t cli[TND_SH_CLI_MAX], keys[TND_SH_KEYS_MAX];
   char line[64];
   uint32_t now = 1000000u;
   tnd_shell_reset(&s, true, 7u, TND_TTX_MARKERS);
   s.cols = (uint16_t)(argc > 1 ? atoi(argv[1]) : 0);
   s.lit_ok = true;
   while (fgets(line, sizeof line, stdin)) {
      tnd_sh_io_t io = { cli, 0u, keys, 0u, false };
      unsigned v = 0u;
      if (line[0] == 't') {
         unsigned long us = strtoul(line + 2, NULL, 10);
         for (unsigned long i = 0; i < us; i += 1000u) {
            now += 1000u;
            io.ncli = io.nkeys = 0u;
            tnd_shell_tick(&s, now, &io);
            fwrite(cli, 1, io.ncli, stdout);
            for (size_t j = 0; j < io.nkeys; j++) fprintf(stderr, "%02x ", keys[j]);
         }
         continue;
      }
      if (sscanf(line + 2, "%x", &v) != 1)
         continue;
      if (line[0] == 'b')
         tnd_shell_beeb(&s, (uint8_t)v, now, &io);
      else if (line[0] == 'k')
         tnd_shell_key(&s, (uint8_t)v, now, &io);
      fwrite(cli, 1, io.ncli, stdout);
      for (size_t j = 0; j < io.nkeys; j++) fprintf(stderr, "%02x ", keys[j]);
      now += 1000u;
   }
   return 0;
}
