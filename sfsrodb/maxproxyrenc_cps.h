/* $Id: maxproxyrenc_cps.h,v 1.2 2004/09/08 17:38:05 fubob Exp $ */

/*
 *
 * Copyright (C) 2004 Kevin Fu (fubob@mit.edu)
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

#include "arpc.h"
#include "crypt.h"
#include "sfsro_prot.h"
#include "sfsmisc.h"
#include "sfsrodb_core.h"

#if USE_PCTR
#include <machine/pctr.h>
#define get_time() rdtsc ()
#define TIME_LABEL "cycles"
#else /* !USE_PCTR */
inline u_int64_t
get_time ()
{
  timeval tv;
  gettimeofday (&tv, NULL);
  return (u_int64_t) tv.tv_sec * 1000000 + tv.tv_usec;
}
#define TIME_LABEL "usec"
#endif /* !USE_PCTR */

class srvcon {
  sfsro_proxyreenc res;

  ptr<axprt_stream> s;
  ptr<aclnt> sfsroc;

  void fail (int err);
  void init ();
  void getsockres (int fd);
  void proxyreenc (int num, clnt_stat err);
  void proxyreenc2 (int num);

public:
  srvcon ()
  { init (); }
};


