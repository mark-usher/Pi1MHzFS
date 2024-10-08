/* cdef.c #define output driver for vasm */
/* (c) in 2020,2024 by Volker Barthelmann */

#include "vasm.h"

static char *copyright="vasm cdef output module 0.2 (c) 2020,2024 Volker Barthelmann";

static void write_output(FILE *f,section *sec,symbol *sym)
{
  for(;sym;sym=sym->next){
    if(!(sym->flags&VASMINTERN)&&*sym->name!=' '&&sym->type==EXPRESSION){
      simplify_expr(sym->expr);
      if(sym->expr->type==NUM)
        fprintf(f,"#define %s\t%#llx\n",sym->name,(unsigned long long)sym->expr->c.val);
    }
  }
}

static int output_args(char *p)
{
  /* no args */
  return 0;
}

int init_output_cdef(char **cp,void (**wo)(FILE *,section *,symbol *),int (**oa)(char *))
{
  *cp=copyright;
  *wo=write_output;
  *oa=output_args;
  asciiout=1;
  return 1;
}

