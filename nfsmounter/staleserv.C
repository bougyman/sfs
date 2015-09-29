/* $Id: staleserv.C,v 1.11 2004/09/19 22:02:24 dm Exp $ */

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

#include "nfsmnt.h"

static mpfsnode *
getnode (mpfsnode *n)
{
  if (n && n->attrvalid)
    return n;
  return NULL;
}

stalesrv::stalesrv (nfsfd *nf)
  : nf (nf)
{
  if (nf->sotype == SOCK_STREAM)
    fdcb (nf->fd, selread, wrap (this, &stalesrv::tcpaccept));
  else {
    ptr<axprt> xh = axprt_dgram::alloc (nf->fd);
    srvelm *s;
    s = New srvelm;
    s->s = asrv::alloc (xh, nfs_program_2,
			wrap (this, &stalesrv::dispatch, s));
    srvs.insert_head (s);
    s = New srvelm;
    s->s = asrv::alloc (xh, nfs_program_3,
			wrap (this, &stalesrv::dispatch, s));
    srvs.insert_head (s);
  }
}

stalesrv::~stalesrv ()
{
  if (nf->sotype == SOCK_STREAM) {
    fdcb (nf->fd, selread, NULL);
    close (nf->fd);
  }
  while (srvelm *s = srvs.first) {
    srvs.remove (s);
    delete s;
  }
}

void
stalesrv::tcpaccept ()
{
  sockaddr_in sin;
  socklen_t len = sizeof (sin);
  bzero (&sin, sizeof (sin));

  int nfd;
  if ((nfd = accept (nf->fd, (sockaddr *) &sin, &len)) >= 0) {
    ptr<axprt> xh = axprt_stream::alloc (nfd);
    srvelm *s;
    s = New srvelm;
    s->s = asrv::alloc (xh, nfs_program_2,
			wrap (this, &stalesrv::dispatch, s));
    srvs.insert_head (s);
    s = New srvelm;
    s->s = asrv::alloc (xh, nfs_program_3,
			wrap (this, &stalesrv::dispatch, s));
    srvs.insert_head (s);
  }
  else if (errno != EAGAIN)
    warn ("stalesrv::tcpaccept:accept: %m\n");
}

void
stalesrv::dispatch (srvelm *s, svccb *sbp)
{
  if (!sbp) {
    srvs.remove (s);
    delete s;
  }

  switch (sbp->vers ()) {
  case 2:
    {
      //warn ("staleserv: %s\n", nfs_program_2.tbl[sbp->proc ()].name);
      nfsmnt_handle h;
      if (sbp->proc () != 0) {
	h.setsize (NFS_FHSIZE);
	memcpy (h.base (), sbp->Xtmpl getarg<nfs_fh> (), NFS_FHSIZE);
      }
      switch (sbp->proc ()) {
      case NFSPROC_GETATTR:
	if (mpfsnode *n = getnode (nf->nfs2nodes[h])) {
	  attrstat res (NFS_OK);
	  *res.attributes = n->getattr2 ();
	  sbp->reply (&res);
	}
	else
	  sbp->replyref (NFSERR_STALE);
	break;
      case NFSPROC_LOOKUP:
	if (mpfsnode *n = getnode (nf->nfs2nodes[h])) {
	  if (sbp->Xtmpl getarg<diropargs> ()->name == "."
	      || (n = n->dir->lookup(sbp->Xtmpl getarg<diropargs> ()
				     ->name))) {
	    diropres res (NFS_OK);
	    memcpy (res.reply->file.data.base (),
		    n->fh.base (), res.reply->file.data.size ());
	    res.reply->attributes = n->getattr2 ();
	    sbp->reply (&res);
	  }
	  else
	    sbp->replyref (NFSERR_NOENT);
	}
	else
	  sbp->replyref (NFSERR_STALE);
	break;
      default:
	sbp->replyref (NFSERR_STALE);
	break;
      }
      break;
    }

  case 3:
    {
      //warn ("staleserv: %s\n", nfs_program_3.tbl[sbp->proc ()].name);
      nfsmnt_handle h;
      if (sbp->proc () != 0)
	h = sbp->Xtmpl getarg<nfs_fh3> ()->data;
      switch (sbp->proc ()) {
      case NFSPROC3_GETATTR:
	if (mpfsnode *n = getnode (nf->nfs3nodes[h])) {
	  getattr3res res (NFS3_OK);
	  *res.attributes = n->getattr3 ();
	  sbp->reply (&res);
	}
	else
	  nfs3_err (sbp, NFS3ERR_STALE);
	break;
      case NFSPROC3_LOOKUP:
	if (mpfsnode *n = getnode (nf->nfs3nodes[h])) {
	  diropargs3 *arg = sbp->Xtmpl getarg<diropargs3> ();
	  if (arg->name == "." || (n = n->dir->lookup(arg->name))) {
	    lookup3res res (NFS3_OK);
	    res.resok->object.data = n->fh;
	    sbp->reply (&res);
	  }
	  else
	    nfs3_err (sbp, NFS3ERR_NOENT);
	}
	else
	  nfs3_err (sbp, NFS3ERR_STALE);
	break;
      case NFSPROC3_ACCESS:
	{
	  access3res res (NFS3_OK);
	  const authunix_parms *aup = sbp->getaup ();
	  if (aup && aup->aup_uid)
	    res.resok->access = 0;
	  else
	    res.resok->access = ACCESS3_READ|ACCESS3_LOOKUP|ACCESS3_EXECUTE;
	  sbp->reply (&res);
	  break;
	}
      default:
	nfs3_err (sbp, NFS3ERR_STALE);
	break;
      }
      break;
    }
  }
}

void
makestaleserv (nfsfd *nf)
{
  if (!nf->server) {
    warn ("launching stale server on %s port %d\n",
	  nf->sotype == SOCK_STREAM ? "TCP" : "UDP",
	  ntohs (nf->sin.sin_port));
    nf->server = New stalesrv (nf);
  }
}
