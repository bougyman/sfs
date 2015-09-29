/* $Id: agent_gcc_xxx.C,v 1.1 2002/08/23 21:36:50 dm Exp $ */

/*
 *
 * Copyright (C) 2002 David Mazieres (dm@uun.org)
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

#include "agent.h"

/*
 * If this definition is placed in sfsdir.C instead of its own file,
 * compilation fails with the error::
 *
cc1plus: warnings being treated as errors
/u/dm/src/sfs1/async/refcnt.h:160: warning: alignment of `vtable for class refcounted<callback_c_1_0<qhash<str,str,hashfn<str>,equals<str>,qhash_lookup_return<str>,&qhash_slot<str,str>::link> *,qhash<str,str,hashfn<str>,equals<str>,qhash_lookup_return<str>,&qhash_slot<str,str>::link>,void,qhash_slot<str,str> *>,scalar>' is greater than maximum object file alignment. Using 4.
 *
 */

qhash<str, str> srpnames;
