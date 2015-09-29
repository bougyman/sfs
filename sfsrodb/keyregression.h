/* $Id: keyregression.h,v 1.7 2004/08/20 20:35:03 fubob Exp $ */

/*
 *
 * Copyright (C) 2004 Anjali Prakash (anjali@cs.jhu.edu)
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

#ifndef _KEYREGRESSION_H_
#define _KEYREGRESSION_H_

#include "sfsro_prot.h"
#include "err.h"
#include "sfscrypt.h"


/* Member operations */
class keyregression {
  ptr<sfsro_keyupdate> ku;
  ptr<sfsro_window> w;
#ifdef SFSRO_PROXY
  ptr<rpc_bytes<> > proxy_lox;
#endif
 public:

  keyregression (str infile);
  ptr<rpc_bytes<> > gk (uint32 i);
  uint32 curr_vers ();
  uint32 get_id ();
#ifdef SFSRO_PROXY
  void set_proxy (ref<rpc_bytes<> > l) { proxy_lox = l; }
#endif
};

class keyregression_owner {

  /* krsuite specifies the key regression protocol,
     key size, and chain length if appropriate.  E.g.:
     
     "sha1-16-500" denotes the sha1-based regression protocol
     with 16-byte keys and a chain 500 hashes long. 
  */

 public:

  keyregression_owner (str directory, uint32 id, 
		       sfsro_protocoltype type,
		       uint32 keysize,
		       uint32 chainlen,
		       bool create = false,
		       bool window = false,
		       bool verbose = false);

  /* Add a member by store current group key in outfile */
  bool add (str outfile, uint32 window_startvers = 0, bool verbose = false);

  /* Evict member by storing next group key in outfile */
  bool wind (str outfile, bool verbose = false);
  
private:
  ptr<sfsro_ownerstate> os;
  str osfile;
};

#endif /* _KEYREGRESSION_H_ */


