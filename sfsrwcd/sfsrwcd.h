// -*-c++-*-
/* $Id: sfsrwcd.h,v 1.49 2004/06/03 06:35:35 dm Exp $ */

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
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
#include "sfscd_prot.h"
#include "nfstrans.h"
#include "sfsclient.h"
#include "qhash.h"
#include "itree.h"
#include "crypt.h"
#include "list.h"

class server : public sfsserver_credmap {
protected:
  attr_cache *acp;

  ref<userauth> userauth_alloc (sfs_aid);
  void cbdispatch (svccb *sbp);
  void getreply (time_t rqtime, nfscall *nc, void *res, clnt_stat err);

public:
  typedef sfsserver_auth super;
  ptr<aclnt> nfsc;
  ptr<asrv> nfscbs;

  server (const sfsserverargs &a, attr_cache *acp)
    : sfsserver_credmap (a), acp (acp) {}
  ~server () { warn << path << " deleted\n"; }
  void flushstate ();
  void authclear (sfs_aid aid);
  void setrootfh (const sfs_fsinfo *fsi, callback<void, bool>::ref err_c);
  void dispatch (nfscall *nc);
};

extern bool opt_map_ids;
extern u_int32_t unknown_uid;
extern u_int32_t unknown_gid;
