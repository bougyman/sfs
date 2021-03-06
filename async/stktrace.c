/* $Id: stktrace.c,v 1.12 2004/01/09 21:41:04 dm Exp $ */

/*
 *
 * Copyright (C) 2000 David Mazieres (dm@uun.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#include "sysconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <setjmp.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif /* DMALLOC */
#undef malloc
#undef free

#ifdef __OpenBSD__
# define NO_STACK_TOP 1
#endif /* OpenBSD */

#if __GNUC__ >= 2 && defined (__i386__)

static const char hexdigits[] = "0123456789abcdef";

struct traceback {
  struct traceback *next;
  char *name;
};

#define STKCACHESIZE 509U
static struct traceback *stkcache[STKCACHESIZE];

#if NO_STACK_TOP
static sigjmp_buf segv_env;

static void
segv_handler (int sig)
{
  siglongjmp (segv_env, 1);
}
#endif /* NO_STACK_TOP */

const char *
__backtrace (const char *file)
{
  const void *const *framep;
  size_t filelen;
  char buf[256];
  char *bp = buf + sizeof (buf);
  u_long bucket = 5381;
  struct traceback *tb;
#if NO_STACK_TOP
  struct sigaction segv, osegv;
#endif /* NO_STACK_TOP */

  filelen = strlen (file);
  if (filelen >= sizeof (buf))
    return file;
  bp -= filelen + 1;
  strcpy (bp, file);

#if NO_STACK_TOP
  bzero (&segv, sizeof (segv));
  segv.sa_handler = segv_handler;
#ifdef SA_RESETHAND
  segv.sa_flags |= SA_RESETHAND;
#endif /* SA_RESETHAND */
  if (sigaction (SIGSEGV, &segv, &osegv) < 0)
    return file;
#endif /* NO_STACK_TOP */

  __asm volatile ("movl %%ebp, %0" : "=g" (framep) :);
  while (framep[0] && bp >= buf + 11) {
    int i;
    u_long pc = (u_long) framep[1] - 1;
    bucket = ((bucket << 5) + bucket) ^ pc;
    
    *--bp = ' ';
    *--bp = hexdigits[pc & 0xf];
    pc >>= 4;
    for (i = 0; pc && i < 7; i++) {
      *--bp = hexdigits[pc & 0xf];
      pc >>= 4;
    }
    *--bp = 'x';
    *--bp = '0';
#if NO_STACK_TOP
    if (sigsetjmp (segv_env, 0))
      break;
#endif /* NO_STACK_TOP */
    framep = *framep;
  }

#if NO_STACK_TOP
  sigaction (SIGSEGV, &osegv, NULL);
#endif /* NO_STACK_TOP */

  bucket = (bucket & 0xffffffff) % STKCACHESIZE;

  for (tb = stkcache[bucket]; tb; tb = tb->next)
    if (!strcmp (tb->name, bp))
      return tb->name;

  tb = malloc (sizeof (*tb));
  if (!tb)
    return file;
  tb->name = malloc (1 + strlen (bp));
  if (!tb->name) {
    free (tb);
    return file;
  }
  strcpy (tb->name, bp);
  tb->next = stkcache[bucket];
  stkcache[bucket] = tb;

  return tb->name;
}

#else /* !gcc 2 || !i386 */

const char *
__backtrace (const char *file)
{
  return file;
}

#endif /* !gcc 2 || !i386 */

#ifdef DMALLOC

#if DMALLOC_VERSION_MAJOR < 5
#define dmalloc_logpath _dmalloc_logpath
char *dmalloc_logpath;
#endif /* DMALLOC_VERSION_MAJOR < 5 */


static int stktrace_record;

const char *
stktrace (const char *file)
{
  if (stktrace_record < 0)
    return file;
  else if (!stktrace_record) {
    if (!dmalloc_logpath || !(dmalloc_debug_current () & 2)
	|| !getenv ("STKTRACE")) {
      stktrace_record = -1;
      return file;
    }
    stktrace_record = 1;
  }
  return __backtrace (file);
}

#endif /* DMALLOC */
