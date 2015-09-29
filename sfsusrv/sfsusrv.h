/*
 *
 * Copyright (C) 2000 Frans Kaashoek (kaashoek@mit.edu)
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

#ifndef _SFSROSD_H_
#define _SFSROSD_H_

#include "sfscrypt.h"
#include "sfsmisc.h"
#include "nfs3_prot.h"
#include "nfstrans.h"
#include "sfs_prot.h"
#include "arpc.h"
#include "crypt.h"
#include "sfsserv.h"
#include "filesrv.h"

class client : public sfsserv {
  filesrv *fsrv;

  ptr<axprt_crypt> x;
  ptr<asrv> rwsrv;
  //  ptr<asrv> sfssrv;

  bool unixauth;
  uid_t uid;

  bool authid_valid;
  sfs_hash authid;

  void nfs3dispatch (svccb *sbp);
  void nfs3_getattr (svccb *sbp);
  void nfs3_access (svccb *sbp);
  void nfs3_fsinfo (svccb *sbp);
  void nfs3_fsstat (svccb *sbp);
  void nfs3_lookup (svccb *sbp);
  void nfs3_readdir (svccb *sbp);
  void nfs3_read (svccb *sbp);
  void nfs3_create (svccb *sbp);
  void nfs3_write (svccb *sbp);
  void nfs3_commit (svccb *sbp);
  void nfs3_remove (svccb *sbp);
  void nfs3_rmdir (svccb *sbp);
  void nfs3_rename (svccb *sbp);
  void nfs3_link (svccb *sbp);
  void nfs3_mkdir (svccb *sbp);
  void nfs3_symlink (svccb *sbp);
  void nfs3_readlink (svccb *sbp);
  void nfs3_setattr (svccb *sbp);
  uint32 access_check(ex_fattr3 *fa, uint32 access_req);
  bool dirlookup (str dir, filename3 *name);

public:
  client (ref<axprt_crypt> x);
  void sfs_getfsinfo (svccb *sbp);

protected:
  ptr<sfspriv> doconnect (const sfs_connectarg *, sfs_servinfo *);
};

extern filesrv *defsrv;

#endif /*_SFSROSD_H_*/
