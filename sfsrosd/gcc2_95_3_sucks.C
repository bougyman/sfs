/* $Id: gcc2_95_3_sucks.C,v 1.2 2002/12/10 03:47:39 fubob Exp $ */

/*
 *
 * Copyright (C) 2002 Kevin Fu (fubob@mit.edu)
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


#include "sfsmisc.h"
#include "sfsro_prot.h"
#include "arpc.h"
#include "crypt.h"
#include "dbfe.h"
#include "qhash.h"
#include "sysconf.h"
#include "sfsrosd.h"

replicatab_t replicatab;

/* It is necessary to instantiate replicatab in a separate file to
   work around a bug in gcc 2.95.3 found in OpenBSD (perhaps others?)
   that otherwise complains about:

gmake[2]: Entering directory `/disk/scratch/fubob/build/sfsrosd'
c++ -DHAVE_CONFIG_H -I. -I/home/u1/fubob/sfs1/sfsrosd -I..   -I/usr/local/inclu\de -I/usr/local/include -DSLEEPYCAT -I/home/u1/fubob/sfs1 -I/home/u1/fubob/sfs1\/async -I/home/u1/fubob/sfs1/arpc -I/home/u1/fubob/sfs1/crypt -I/home/u1/fubob/\sfs1/sfsmisc -I/home/u1/fubob/sfs1/sfsrodb -I/home/u1/fubob/sfs1/adb -I../svc -\I/home/u1/fubob/sfs1/svc -DEXECDIR=\"/usr/local/lib/sfs-0.6\" -DETCDIR=\"/etc/s\fs\" -DDATADIR=\"/usr/local/share/sfs\" -DPIDDIR=\"/var/run\" -DSFSDIR=\"/var/s\fs\"  -g -O2 -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror  -c /home/u1/\fubob/sfs1/sfsrosd/sfsrosd.C
cc1plus: warnings being treated as errors
/home/u1/fubob/sfs1/async/refcnt.h:149: warning: alignment of `vtable for class\ refcounted<callback_c_1_0<qhash<rpc_str<2147483647>,replica,hashfn<rpc_str<214\7483647> >,equals<rpc_str<2147483647> >,qhash_lookup_return<replica>,&qhash_slo\t<rpc_str<2147483647>,replica>::link> *,qhash<rpc_str<2147483647>,replica,hashf\n<rpc_str<2147483647> >,equals<rpc_str<2147483647> >,qhash_lookup_return<replic\a>,&qhash_slot<rpc_str<2147483647>,replica>::link>,void,qhash_slot<rpc_str<2147\483647>,replica> *>,scalar>' is greater than maximum object file alignment. Usi\ng 4.
gmake[2]: *** [sfsrosd.o] Error 1

*/
