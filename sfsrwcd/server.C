/* $Id: server.C,v 1.79 2004/09/19 22:02:33 dm Exp $ */

/*
 *
 * Copyright (C) 1998-2000 David Mazieres (dm@uun.org)
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

#include "sfsrwcd.h"
#include "axprt_crypt.h"

ref<sfsserver_auth::userauth>
server::userauth_alloc (sfs_aid aid)
{
  if (opt_map_ids)
    return sfsserver_credmap::userauth_alloc (aid);
  else
    return sfsserver_auth::userauth_alloc (aid);
}

void
server::getreply (time_t rqtime, nfscall *nc, void *res, clnt_stat err)
{
  auto_xdr_delete axd (ex_nfs_program_3.tbl[nc->proc ()].xdr_res, res);
  if (err) {
    if (err == RPC_CANTSEND || err == RPC_CANTRECV)
      getnfscall (nc);
    else
      nc->reject (SYSTEM_ERR);
    return;
  }

  if (opt_map_ids) {
    xattrvec xv;
    nfs3_getxattr (&xv, nc->proc (), nc->getvoidarg (), res);
    for (xattr *x = xv.base (); x < xv.lim (); x++)
      if (x->fattr)
	mapcred (nc->getaup (), x->fattr, unknown_uid, unknown_gid);
  }

  nfs3_exp_disable (nc->proc (), res);
  nc->reply (res);
}

void
server::cbdispatch (svccb *sbp)
{
  if (!sbp)
    return;

  switch (sbp->proc ()) {
  case ex_NFSCBPROC3_NULL:
    sbp->reply (NULL);
    break;
  case ex_NFSCBPROC3_INVALIDATE:
    {
      ex_invalidate3args *xa = sbp->Xtmpl getarg<ex_invalidate3args> ();
      ex_fattr3 *a = NULL;
      if (xa->attributes.present && xa->attributes.attributes->expire) {
	a = xa->attributes.attributes.addr ();
	a->expire += timenow;
      }
      acp->attr_enter (xa->handle, a, NULL);
      sbp->reply (NULL);
      break;
    }
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

void
server::flushstate ()
{
  acp->flush_attr ();
  nfsc = NULL;
  nfscbs = NULL;
  super::flushstate ();
}

void
server::authclear (sfs_aid aid)
{
  acp->flush_access (aid);
  super::authclear (aid);
}

void
server::setrootfh (const sfs_fsinfo *fsi, callback<void, bool>::ref err_cb)
{
  if (fsi->prog != ex_NFS_PROGRAM || fsi->nfs->vers != ex_NFS_V3) {
    err_cb (true);
    return;
  }
  nfs_fh3 fh (fsi->nfs->v3->root);
  if (fsinfo && rootfh.data != fh.data) {
    err_cb (true);
    return;
  }

  rootfh = fh;
  nfsc = aclnt::alloc (x, ex_nfs_program_3);
  nfscbs = asrv::alloc (x, ex_nfscb_program_3,
			wrap (this, &server::cbdispatch));
  err_cb (false);
}

void
server::dispatch (nfscall *nc)
{
#if 0
  if (nc->proc () == NFSPROC_CLOSE) {
    nfs_fh3 *fhp = nc->getfh3arg ();
    warn << "close 0x" << hexdump (fhp->data.base (), fhp->data.size ())
	 << "\n";
    nfsstat3 ok (NFS3_OK);
    nc->reply (&ok);
    return;
  }
#endif

  if (opt_map_ids && nc->proc () == NFSPROC3_SETATTR
      && !nomap (nc->getaup ())) {
    /* If we are mapping UIDs and GIDs, it's likely that any attempt
     * by the user to chown/chgrp files will do something unwanted. */
    setattr3args *argp = nc->Xtmpl getarg<setattr3args> ();
    if (argp->new_attributes.uid.set || argp->new_attributes.gid.set) {
      nc->error (NFS3ERR_PERM);
      return;
    }
  }

  void *res = ex_nfs_program_3.tbl[nc->proc ()].alloc_res ();
  nfsc->call (nc->proc (), nc->getvoidarg (), res,
	      wrap (mkref (this), &server::getreply, timenow, nc, res),
	      authof (nc->getaid ()));
}
