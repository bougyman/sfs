/* $Id: server.C,v 1.76 2004/09/19 22:02:31 dm Exp $ */

/*
 *
 * Copyright (C) 2000, 2001 Kevin Fu (fubob@mit.edu)
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

#include "sfsrocd.h"
#include "xdr_suio.h"
#include "rxx.h"
#include "sfsrodb_core.h"
#include "stllike.h"
#include "keyregression.h"

cache_stat cstat;
#ifdef MAINTAINER
const int asrvtrace (getenv ("ASRV_TRACE") ? atoi (getenv ("ASRV_TRACE")) : 0);
#else /* !MAINTAINER */
enum { asrvtrace = 0 };
#endif /* !MAINTAINER */

/* Experiment with proxy re-encryption */
#ifdef SFSRO_PROXY
#include "/home/fubob/src/proxyfs/miracl/elliptic.h"
#include "/home/fubob/src/proxyfs/miracl/monty.h"
#include "/home/fubob/src/proxyfs/miracl/zzn2.h"
extern Miracl precision;
#include "/home/fubob/src/proxyfs/pairing.h"
static CurveParams gParams;
extern ProxyPK proxy_PublicKey;
extern ProxySK proxy_SecretKey;
extern ProxyPK proxy_DelegatePublicKey;
extern ProxySK proxy_DelegateSecretKey;
extern CurveParams proxy_params;
extern ECn proxy_delegationKey;
#endif

ptr<keyregression> kr;


/* 
  
   High level functions.
   
*/

void
server::dispatch (nfscall *sbp)
{
  ptr<nfs_fh3> nfh;

  switch(sbp->proc()) {
  case NFSPROC3_READLINK:
  case NFSPROC3_GETATTR: 
  case NFSPROC3_LOOKUP: 
  case NFSPROC3_ACCESS:
  case NFSPROC3_READ:
  case NFSPROC3_READDIR:
  case NFSPROC3_READDIRPLUS:
  case NFSPROC3_FSSTAT:
  case NFSPROC3_FSINFO:
    nfh = New refcounted<nfs_fh3> (*sbp->getfh3arg ());
    break;
  case NFSPROC3_NULL:
    sbp->reply (NULL);
    return;
    break;
  case NFSPROC_CLOSE:
    {
      nfh = New refcounted<nfs_fh3> (*sbp->getfh3arg ());

      warnx << "close 0x" << hexdump (nfh->data.base (), nfh->data.size ())
	   << "\n";
      
      nt->close (nfh);

      nfsstat3 ok (NFS3_OK);
      sbp->reply (&ok);
      return;
    }
    break;
  default:
    sbp->error (NFS3ERR_ROFS);
    return;
    break;
  }

  if (asrvtrace >= 5) {
    warnx << "Unencrypted NFS fh " << hexdump (nfh->data.base (), 
					      nfh->data.size ())
	 << "\n";
  }
  nt->nd (wrap (this, &server::dispatch_helper, sbp, nfh), nfh);  
}

uint32 
access_check (const sfsro_inode *ip, uint32 access_req)
{
  uint32 r = 0;

  switch (ip->type) { 
  case SFSRODIR:
    r = ACCESS3_READ | ACCESS3_LOOKUP;
    break;
  case SFSRODIR_OPAQ:
    r = ACCESS3_LOOKUP;
    break;
  case SFSROREG_EXEC:
    r = ACCESS3_READ | ACCESS3_EXECUTE;
    break;
  case SFSROLNK:
  case SFSROREG:
    r = ACCESS3_READ;
    break;
  }

  return (access_req & r);
}


void
server::dispatch_helper (nfscall *sbp, ref<const nfs_fh3> nfh,
			 ptr<name_dat> nd)
{
  if (nd != NULL) {
    assert (nd->fa != NULL);
    assert (nd->ip != NULL);
  }
    
  switch(sbp->proc()) {
  case NFSPROC3_GETATTR: 
    nfsproc3_getattrres (sbp, nd);
    break;
  case NFSPROC3_LOOKUP: 
    if (nd != NULL) {
      diropargs3 *dirop = sbp->Xtmpl getarg<diropargs3> ();
      str dir_path = nt->path (nfh);
      // XXX what if bad file handle?  then dir_path = ""?
      // what if . or .. ?
      pt->lookup (wrap (this, &server::nfsproc3_lookup1, sbp,
			dir_path, dirop->name, nd, nfh),
		  nd, dir_path, dirop->name);
    } else
      nfsproc3_lookupres (sbp, NFS3ERR_STALE, NULL, NULL, NULL);
    break;
  case NFSPROC3_ACCESS:
    if (nd != NULL) {
      access3args *aa = sbp->Xtmpl getarg<access3args> ();
      nfsproc3_accessres (sbp, access_check (nd->ip, aa->access), 
			  NFS3_OK, nd);
    } else 
      nfsproc3_accessres (sbp, 0, NFS3ERR_STALE, NULL);
    break;
  case NFSPROC3_READLINK:
    nfsproc3_readlinkres (sbp, nd);
    break;
  case NFSPROC3_READ:
    if (nd != NULL) {
      read3args *ra = sbp->Xtmpl getarg<read3args> ();
      nfsproc3_read1 (sbp, nd, ra->offset, ra->count);
    } else
      nfsproc3_readres (sbp, 0, 0, false, NFS3ERR_STALE, NULL, NULL, NULL);
    break;
  case NFSPROC3_READDIR:
    if (nd != NULL) {
      readdir3args *readdirop = sbp->Xtmpl getarg<readdir3args> ();
      // Cookieverf=cookie=0 (initial request) or cookieverf=SFSRO fh
      if ((gethyper (readdirop->cookieverf.base()) == 0 &&
	   readdirop->cookie == 0) ||
	  (gethyper (readdirop->cookieverf.base()) ==
	   gethyper (nd->fh->base ()))) {
	nfsproc3_readdir1 (sbp, nfh, nd, readdirop->cookie, 
			   readdirop->count);
      } else {
	// Stale cookieverf
	sbp->error (NFS3ERR_BAD_COOKIE);
      }
    } else
      sbp->error (NFS3ERR_STALE);
    break;
  case NFSPROC3_READDIRPLUS:
    warnx << "READDIRPLUS!\n";
    sbp->error (NFS3ERR_NOTSUPP);
#if 0
    if (nd != NULL) {
      readdirplus3args *readdirop = sbp->Xtmpl getarg<readdirplus3args> ();

      nfsproc3_readdirplus1 (sbp, nfh, nd, readdirop->cookie, 
			     readdirop->count); /* readdirop->cookieverf, */
    } else
      nfsproc3_readdirres (sbp, 0, 0, NFS3ERR_STALE, NULL, NULL, NULL);
#endif
    break;
  case NFSPROC3_FSSTAT:
    nfsproc3_fsstatres (sbp, nd);
    break;
  case NFSPROC3_FSINFO:
    nfsproc3_fsinfores (sbp, nd);
    break;
  default:
    warnx << "Implementation error.  Should never reach dispatch_helper\n";
    sbp->error (NFS3ERR_ROFS);
    break;
  }
}


void
server::setrootfh (const sfs_fsinfo *fsi, callback<void, bool>::ref err_cb)
{
  const sfsro_fsinfo *rofsi = (sfsro_fsinfo*)fsi;
  if (!rofsi || !si) {
    err_cb (true);
    return;
  }

  if (!sfsrocd_noverify) {
    sfs_pubkey2 pk = si->get_pubkey ();
    if (!sfscrypt.verify (pk, rofsi->v2->sig, xdr2str (rofsi->v2->info))) {
      warn << "failed to verify signature " << path << "\n";
      err_cb (true);
      return;
    }
  }
  
  ptr<sfsro_public> fsinfopub;
  if (rofsi->v2->info.type == SFSRO_PRIVATE) {
    warnx << "Decoding SFSRO_PRIVATE\n";
    
    if (!gk_directory)
      fatal << "gk_directory undefined\n";
    str keyfile = strbuf () 
      << gk_directory << "/" << rofsi->v2->info.priv->gk_id;
    warn << "keyfile " << keyfile << "\n";
    
    kr = New refcounted<keyregression> (keyfile);
    if (!kr) {
      warn << "Unable to open keyfile " << keyfile << "\n";
      err_cb (true);
      return;
    }

    fsinfopub = New refcounted<sfsro_public> ();

#ifdef SFSRO_PROXY
    char *buf = (char*)rofsi->v2->info.priv->ct.lockbox.base ();
    int len;
    ECn c1;
    ZZn2 Zc1;
    memcpy (&len, buf, sizeof (int));
    buf += sizeof (int);
    c1 = charToECn (buf);

    if (proxy_reencrypt(proxy_params, c1, proxy_delegationKey, Zc1) == FALSE) {
      fatal << "Re-encryption failed\n";
    }
#endif

    if (!unseal (kr->gk (rofsi->v2->info.priv->ct.gk_vers),
		 (sfsro_sealed *)&rofsi->v2->info.priv->ct, 
		 (sfsro_public *)fsinfopub
#ifdef SFSRO_PROXY
		 , &Zc1
#endif
		 )) {
      warn << "Unable to unseal fsinfo ciphertext\n";
      err_cb (true);
      return;
    }
  } else {
    warnx << "Decoding SFSRO_PUBLIC\n";
    fsinfopub = New refcounted<sfsro_public> (*rofsi->v2->info.pub);
  }

  time_t end = fsinfopub->start + fsinfopub->duration;
  if (end < time (NULL)) {
    warn << "signature expired" << path << "\n";
    err_cb (false);
    return;
  }
  
  timecb ((sfs_time) (fsinfopub->start + fsinfopub->duration),
	  wrap (this, &server::expired));

  // XXX check expire time
  // Set callback to flush cache at expire time?
  //    timecb (timenow + 1, wrap (this, &srvcon::init));


  // If the sfsro root fh changes, flush filename -> SFSRO handle cache
  // need to make sure we don't flush all these caches
  // if they already exist.
  ref<aclnt> sfsroc = aclnt::alloc (x, sfsro_program_2);
  fs = New refcounted<filesys> (fsinfopub, sfsroc, path, kr);
  ref<namec_t> namec = New refcounted<namec_t> ();
  ref<fhtt_t> fhtt = New refcounted<fhtt_t> ();
  ref<sfs_hash> id = New refcounted<sfs_hash> ();
  if (!si->mkhostid (id)) {
    warn << "Could not marshal own servinfo object\n";
    err_cb (true);
    return;
  }
  pt = New refcounted<pathtrans> (fhtt, namec, fs, 
				  New refcounted <sfs_hash> 
				  (fsinfopub->rootfh), id);
  nt = New refcounted<nfstrans> (fhtt, pt);
  str r = "/";
  pt->nfsfh (&rootfh, r);

  if (asrvtrace >= 5) {
    warnx << "unencrypted NFS rootfh " << hexdump (rootfh.data.base (), 
						  rootfh.data.size ())
	 << "\n";
  }

  err_cb (false);
}


void
server::expired ()
{
  /* Trick the client into reconnecting because the signature expired */
  sfsdispatch (NULL);
}



/* 
   
   Name translation.  Paths to SFSRO file handles
   and NFS file handles to paths.

   Internally these functions call each other, but 
   for all level three functions, X and Y where X is
   declared before Y, Y cannot call X.
   
*/

static void
splitpath (vec<str> &out, const str in)
{
  const char *p = in.cstr ();
  const char *e = p + in.len ();
  const char *n;

  for (;;) {
    while (*p == '/')
      p++;
    for (n = p; n < e && *n != '/'; n++)
      ;
    if (n == p)
      return;
    out.push_back (str (p, n - p));
    p = n;
  }
}


/* Given a path, split it into two pieces:
   the parent directory path and the filename.

   Examples:

   path      parent   filename
   "/"       "/"      ""
   "/a"      "/"      "a"
   "/a/"     "/"      "a"
   "/a/b"    "/a"     "b"
   "/a/b/c"  "/a/b"   "c"
 */
static void
parentpath (str &parent, str &filename, const str inpath)
{
  vec<str> ppv;
  parent = str ("/");
  filename = str ("");

  splitpath (ppv, inpath);

  if (ppv.size () == 0)
    return;

  filename = ppv.pop_back ();
  if (ppv.size () == 0)
    return;

  // What a non-intuitive way to do concatenation!
  parent = strbuf () << "/" << join (str("/"), ppv);
}


static bool
xdr_putentry3 (XDR *x, u_int64_t ino, filename3 name, u_int64_t cookie)
{
  return
    // entry * (non-null):
    xdr_putint (x, 1)
    // uint64 fileid:
    && xdr_puthyper (x, ino)
    // filename3 name:
    && xdr_filename3 (x, &name)
    // uint64 cookie:
    && xdr_puthyper (x, cookie);
}

BOOL
readdir_xdr (XDR *x, void *_uio)
{
  assert (x->x_op == XDR_ENCODE);

  suio *uio = static_cast<suio *> (_uio);
  xsuio (x)->take (uio);

  return true;
}


void
nfsfh2fileid (uint64 *fileid, const nfs_fh3 *nfh)
{
  // Just return first 64 bits of NFH.
  // XX dangerous becaues we expect a collision after about 2^32 opened files
  //  *fileid = gethyper (nfh->data.base ());
  *fileid = getint (nfh->data.base ());
}

void
ro2fattr (fattr3 *ni, const sfsro_inode *ip, const nfs_fh3 *nfh,
	  ref<sfs_hash> id)
{
  if (ip->type == SFSROLNK) {
    ni->nlink = ip->lnk->nlink;
    ni->size = ip->lnk->dest.len ();
    ni->used = 0;
    ni->mtime = ip->lnk->mtime;
    ni->ctime = ip->lnk->ctime;
    ni->atime = ip->lnk->mtime;
  } else {
    ni->nlink = ip->reg->nlink;
    ni->size = ip->reg->size;
    ni->used = ip->reg->used;
    ni->mtime = ip->reg->mtime;
    ni->ctime = ip->reg->ctime;
    ni->atime = ip->reg->mtime;
  }

  /* Below are synthesized attributes */
  ni->mode = 0444;
  
  switch (ip->type) {
  case SFSROREG_EXEC:
    ni->mode = 0555;
  case SFSROREG:
    ni->type = NF3REG;
    break;
  case SFSRODIR:
    ni->mode = 0555;
    ni->type = NF3DIR;
    break;
  case SFSRODIR_OPAQ:
    ni->mode = 0111;
    ni->type = NF3DIR;
    break;
  case SFSROLNK:
    ni->type = NF3LNK;
    break;
  default:
    warnx << "server::ro2nfsattr: unencrypted NFS fh="  << hexdump (nfh, 20) << "\n";
    fatal ("server::ro2nfsattr: Unknown ip->type %X\n",
	   ip->type);
    break;
  }
    
  ni->uid = sfs_uid;
  ni->gid = sfs_gid;
  ni->rdev.minor = 0;
  ni->rdev.major = 0;
  //  ni->fsid = gethyper (id->base ());
  ni->fsid = gethyper (id->base ());

  nfsfh2fileid (&ni->fileid, nfh);
    
  //ni->mtime.seconds = ni->ctime.seconds = static_cast<uint32>(timenow);
  //ni->mtime.nseconds = ni->ctime.nseconds = 0;
  // To fool the attribute cache
 
}


/* 
   
   Should only be called from the high level functions
   These functions reply to NFS.
   
*/

void 
server::nfsproc3_getattrres (nfscall *sbp, ptr<name_dat> nd)
{
  getattr3res nfsres ((nd != NULL) ? NFS3_OK:NFS3ERR_STALE);

  if (nd != NULL) {
    assert (nd->fa != NULL);
    *nfsres.attributes = *nd->fa;
  }

  sbp->reply (&nfsres); 
}


void 
server::nfsproc3_lookupres (nfscall *sbp, 
			    nfsstat3 status,
			    ptr<const nfs_fh3> obj_nfh,
			    ptr<name_dat> obj_nd,
			    ptr<name_dat> dir_nd)
{
  lookup3res nfsres (status);
  post_op_attr *poa;

  if (status == NFS3_OK) {
    assert (obj_nfh != NULL);
    nfsres.resok->object = *obj_nfh;

    if (obj_nd->fa != NULL) {
      nfsres.resok->obj_attributes.set_present (true);
      *nfsres.resok->obj_attributes.attributes = *obj_nd->fa;
    } else
      nfsres.resok->obj_attributes.set_present (false);

    poa = &nfsres.resok->dir_attributes;

  } else 
    poa = nfsres.resfail;


  if (dir_nd != NULL) {
    poa->set_present (true);
    *poa->attributes = *dir_nd->fa;
  } else
    poa->set_present (false);

  sbp->reply (&nfsres); 
}


void
server::nfsproc3_accessres (nfscall *sbp, uint32 ac, 
			    nfsstat3 status,
			    ptr<name_dat> nd)
{
  access3res nfsres (status);

  if (status == NFS3_OK) {
    nfsres.resok->access = ac;
    
    if (nd != NULL) {
      nfsres.resok->obj_attributes.set_present (true);
      *nfsres.resok->obj_attributes.attributes = *nd->fa;
    } else
      nfsres.resok->obj_attributes.set_present (false);

  } else {

    if (nd != NULL) {
      nfsres.resfail->set_present (true);
      *nfsres.resfail->attributes = *nd->fa;
    } else
      nfsres.resfail->set_present (false);
  }
  
  sbp->reply (&nfsres);
}

void
server::nfsproc3_readlinkres (nfscall *sbp, ptr<name_dat> nd)
{
  readlink3res nfsres ((nd != NULL)? NFS3_OK:NFS3ERR_STALE);

  if (nd != NULL) {
    
    nfsres.resok->data = nd->ip->lnk->dest;

    if (nd->fa != NULL) {
      nfsres.resok->symlink_attributes.set_present (true);
      *nfsres.resok->symlink_attributes.attributes = *nd->fa;
    } else
      nfsres.resok->symlink_attributes.set_present (false);
    
  } else 
    nfsres.resfail->set_present (false);
  
  sbp->reply (&nfsres);
}


void 
server::nfsproc3_readres (nfscall *sbp, uint32 count, uint64 start,
			  bool eof, nfsstat3 status,
			  ptr<const rpc_bytes<RPC_INFINITY> > fdat_start,
			  ptr<const rpc_bytes<RPC_INFINITY> > fdat,
			  ptr<name_dat> nd)
{
  /* If fdat_start is non-null: 
      fdat_start contains the 1st block, fdat contains the 2nd block
     If fdat_start is null:
      fdat contains the 1st block
     If both null:
       no data
  */

  read3res nfsres (status);

  if (status == NFS3_OK) {
    assert (nd != NULL);
    assert (nd->fa != NULL);
    assert (fdat != NULL);

    nfsres.resok->file_attributes.set_present (true);
    *nfsres.resok->file_attributes.attributes = *nd->fa;
    nfsres.resok->count = count;
    nfsres.resok->eof = eof;

    nfsres.resok->data.setsize (count);

    /* XXX can we avoid this memcpy? */
    if (fdat_start) {
      memcpy (nfsres.resok->data.base (), 
	      fdat_start->base () + start,
	      fdat_start->size () - start); 
      memcpy (nfsres.resok->data.base () + (fdat_start->size () - start), 
	      fdat->base (),
	      count - (fdat_start->size () - start)); 
    } else {
      memcpy (nfsres.resok->data.base (), 
	      fdat->base () + start,
	      count); 
    }
  } else {
    if ((nd != NULL) && (nd->fa != NULL)) {
      nfsres.resfail->set_present (true);
      *nfsres.resfail->attributes = *nd->fa;
    } else
      nfsres.resfail->set_present (false);
  }

  sbp->reply (&nfsres);
}


/* Our cookies are of the form:
     entrynum . blocknum

   where the entrynum is a 16-bit value and the
   blocknum is a 16-bit number

   note that we do not use the whole 64-bit range
   of cookies because Linux will fail when presented
   with large cookies (errno=75)

   Dot and dotdot have special entrynum's of 0 and 1
   respectively in blocknum 0.  The non-synthesized
   directory entries start with entrynum 2.  The cookie in
   the last entry of a block points to the next blocknum.
   
  
 */
void
server::nfsproc3_readdirres (nfscall *sbp, uint64 cookie, uint32 count,
			     nfsstat3 status,
			     ptr<const sfsro_directory> dir,
			     ptr<const nfs_fh3> dir_nfh,
			     ptr<name_dat> nd)
{
  uint32 start = DIR_OFFSET (cookie);
  uint64 dir_block = DIR_BLOCK (cookie);
  //  warnx << "start = " << start << "\n";

  /* When encoding . and .. in an XDR, we want to make sure the string
   * memory doesn't get freed before the XDR uses it.  */
  static const filename3 dot (".");
  static const filename3 dotdot ("..");

  bool errors = false;

  xdrsuio x (XDR_ENCODE, true);

  if (!xdr_putint (&x, NFS3_OK))
    errors = true;

  assert (nd != NULL);
  assert (dir_nfh != NULL);
  assert (nd->fa != NULL);

  post_op_attr poa;
  poa.set_present (true);
  *poa.attributes.addr () = *nd->fa;
  // The cookieverf is the truncated SFSRO fh of the directory.
  // When the directory contents change, so will the SFSRO fh.
  // This will cause false positives when files beneath a directory
  // change.  The directory's SFSRO fh will also change, even though
  // The NFS translation of the directory will not.  But if a new file
  // appears in the directory itself, the cookieverf will trigger
  // the kernel to reload the whole directory.
  if (!xdr_post_op_attr (&x, &poa)
      || !xdr_puthyper (&x, gethyper (nd->fh->base ())))  // the cookieverf
    errors = true;

  sfsro_dirent *roe = NULL;
  if (dir != NULL) {
    roe = dir->entries;
  }

  uint64 fileid;
  str s;
  str dir_path = nt->path (dir_nfh);

  if (dir_block == 0) {
    switch (start) {
    case 0:
      if (XDR_GETPOS (&x) + 24 + ((dot.len () + 3) & ~3) <= count) {
	nfsfh2fileid (&fileid, dir_nfh);
	if (!xdr_putentry3 (&x, fileid, dot,
			    DIR_COOKIE (INT64 (1), 0)))
	  errors = true;
      }
    case 1:
      {
	if (XDR_GETPOS (&x) + 24 + ((dotdot.len () + 3) & ~3) <= count) {
	  str temp;
	  parentpath (s, temp, dir_path);
	  
	  nfs_fh3 nfh;    
	  pt->nfsfh (&nfh, s);
	  
	  nfsfh2fileid (&fileid, &nfh);
	  if (!xdr_putentry3 (&x, fileid, dotdot, 
			      DIR_COOKIE (INT64 (0), 1)))
	    errors = true;
	}
      }
      break;
    default:
      {
	//   cookie out of range of the block.  invalid. 
	warn ("sfsrocd::readdirres bad cookie entry 0x%x\n", start);
	sbp->error (NFS3ERR_BAD_COOKIE);
	return;
      } 
    }
  } else {   
    
    if (!roe) {
      // cookie out of range of the block.  valid requests should
      // never reach this code
      warn ("sfsrocd::readdirres bad cookie entry 0x%x\n", start);
      sbp->error (NFS3ERR_BAD_COOKIE);
      return;
    }

    uint32 i = 0;
    while (start > i) {
      roe = roe->nextentry;
      i++;
      if (!roe) {
	//   cookie out of range of the block.  invalid. 
	warn ("sfsrocd::readdirres bad cookie entry 0x%x\n", start);
	sbp->error (NFS3ERR_BAD_COOKIE);
	return;
      }
    }  
    
    //XXX deal with opaque directories
    // note the 3 & ~3 business is to round up the marshalled
    // structure to a 4-byte multiple.
    
    // XXX make sure not to exceed entrynum > 2^16 or block > 2^16

    for (uint32 entrynum = start + 1;
	 roe && (XDR_GETPOS (&x) + 24 + 
		 (roe->name.len () + 3) & ~3) <= count;
	 entrynum++) {
      
      if (dir_path == "/") {
	s = strbuf () << dir_path << roe->name;
      } else {
	s = strbuf () << dir_path << str ("/") << roe->name;
      }
      
      //      warn << "readdir file path: " << s << "\n";
      nfs_fh3 nfh;
      pt->nfsfh (&nfh, s);
      nfsfh2fileid (&fileid, &nfh);
      
      if (roe->nextentry == NULL) {
	dir_block++;
	entrynum = 0; // The first real entry in every block is #0 
      }
      
      if (!xdr_putentry3 (&x, fileid,  roe->name, 
			  DIR_COOKIE ((uint64)(entrynum), dir_block)))
	errors = true;
      
      // warnx << "readdirres start+j=" << start+j << "\n"; 
      
      roe = roe->nextentry;
      
    }
  }  


  if (!xdr_putint (&x, 0)) // NULL entry *
    errors = true;

  // !dir = empty directory
  if (!dir || dir->eof) {
    if (!xdr_putint (&x, !roe)) // bool eof
      errors = true;
  } else if (!xdr_putint (&x, 0))
    errors = true;
  
  if (!errors) {
    
    // Hack to print READDIR debugging info
    if (asrvtrace >= 10) {
      readdir3res res (NFS3_OK);
      size_t calllen = x.uio ()->resid ();
      char *callbuf = suio_flatten (x.uio ());
      xdrmem xx (callbuf, calllen, XDR_DECODE);
      
      if (xdr_readdir3res (xx.xdrp (), &res)) {
	strbuf sb;
	rpc_print (sb, res);
	warnx << "nfs3res " << sb << "\n";
      }
      xfree (callbuf);
    }
    
    sbp->reply (x.uio (), &readdir_xdr);
  } else
  sbp->error (NFS3ERR_IO);
}


void
server::nfsproc3_fsstatres (nfscall *sbp, ptr<name_dat> nd)
{
  fsstat3res res (NFS3_OK);
  rpc_clear (res);
  if (nd != NULL) {
    res.resok->obj_attributes.set_present (true);
    *res.resok->obj_attributes.attributes = *nd->fa;
  } else
    res.resok->obj_attributes.set_present (false);    
  sbp->reply (&res);
}

void
server::nfsproc3_fsinfores (nfscall *sbp, ptr<name_dat> nd)
{
  fsinfo3res res (NFS3_OK);
  if (nd != NULL) {
    res.resok->obj_attributes.set_present (true);
    *res.resok->obj_attributes.attributes = *nd->fa;
  } else
    res.resok->obj_attributes.set_present (false);
    

  // We should modify sfsro_fsinfo to set these at database creation time */
  res.resok->rtmax = SFSRO_BLKSIZE;
  res.resok->rtpref = SFSRO_BLKSIZE;
  res.resok->rtmult = 512;
  res.resok->wtmax = 0;
  res.resok->wtpref = 0;
  res.resok->wtmult = 0;
  res.resok->dtpref = SFSRO_BLKSIZE;
  res.resok->maxfilesize = INT64 (0x7fffffffffffffff);
  res.resok->time_delta.seconds = 0;
  res.resok->time_delta.nseconds = 1;
  res.resok->properties = (FSF3_LINK | FSF3_SYMLINK | FSF3_HOMOGENEOUS);
  sbp->reply (&res);
}


/* 
   
   should only be called from the NFS functions
   Intermediate callbacks.
   
*/


void
server::nfsproc3_lookup1 (nfscall *sbp, 
			  str dir_path, str filename,
			  ref<name_dat> dir_nd, 
			  ref<const nfs_fh3> dir_nfh,
			  ptr<name_dat> obj_nd)
{
  if (obj_nd == NULL) {
    nfsproc3_lookupres (sbp, NFS3ERR_NOENT, NULL, NULL, dir_nd);
  } else {

    str file_path;
    
    if ((filename == ".") 
	|| ((filename == "..") && (dir_path == "/"))) {
      file_path = strbuf () << dir_path; 
    } else if (filename == "..") {
      str fn;
      parentpath (file_path, fn, dir_path);
    } else  if (dir_path == "/") {
      file_path = strbuf () << dir_path << filename;
    } else {
      file_path = strbuf () << dir_path << str ("/") << filename;
    }

    if (asrvtrace >= 5) {
      warnx << "nfsproc3_lookup1: file_path = " << file_path << "\n";
    }

    nfs_fh3 nfh;
    pt->nfsfh (&nfh, file_path);
    ptr<const nfs_fh3> obj_nfh (New refcounted<nfs_fh3> (nfh));

    nfsproc3_lookupres (sbp, NFS3_OK, obj_nfh, obj_nd, dir_nd);
  }
    
  // What about NFS3_NOTDIR and NFS3ERR_NAMETOOLONG
}


/*

given the inode, offset in bytes, and a count,
retreive all the data blocks necessary.  cache
these blocks?  then mash together into a rpc_bytes
and return.  follow direct and indirect blocks.

*/

void
server::nfsproc3_read1 (nfscall *sbp, ref<name_dat> nd,
			uint64 offset, uint32 count)
{
  if (nd->ip->type != SFSROREG
      && nd->ip->type != SFSROREG_EXEC)
    sbp->error (NFS3ERR_IO);
  else if (offset >= nd->ip->reg->size) {
    read3res nfsres(NFS3_OK);
    
    nfsres.resok->count = 0;
    nfsres.resok->eof = 1;
    nfsres.resok->file_attributes.set_present(1);
    *nfsres.resok->file_attributes.attributes = *nd->fa;
    sbp->reply(&nfsres);
  } else {
    uint64 blknr = offset / SFSRO_BLKSIZE;
    
    /* XX This will break if the NFS client is trying
       to read data that spans more than two blocks.
       SFSRO will respond with a short read if it spans
       more than two blocks.
    */
    fs->getblock (wrap (fs, &filesys::getfiledata,
			(wrap (this, &server::nfsproc3_read2, 
			       sbp, nd, offset, count, blknr))),
		  nd->ip, blknr);
  }
}

void
server::nfsproc3_read2 (nfscall *sbp, ref<name_dat> nd,
 			uint64 offset, uint32 count, uint64 blknr, 
			ref<const rpc_bytes<RPC_INFINITY> > fdat)
{
  /* Check if the read spans one more block */
  if ((offset + count)/ SFSRO_BLKSIZE > blknr) {
    fs->getblock (wrap (fs, &filesys::getfiledata,
			(wrap (this, &server::nfsproc3_read3, 
			       sbp, nd, offset, count, fdat))),
			       nd->ip, blknr+1);
  } else {
    nfsproc3_read3 (sbp, nd, offset, count, NULL, fdat);
  }
}

void
server::nfsproc3_read3 (nfscall *sbp, ref<name_dat> nd,
 			uint64 offset, uint32 count, 
			ptr<const rpc_bytes<RPC_INFINITY> > fdat_start,
			ref<const rpc_bytes<RPC_INFINITY> > fdat)
{
  /* If fdat_start is non-null: 
      fdat_start contains the 1st block, fdat contains the 2nd block
     If fdat_start is null:
      fdat contains the 1st block
  */
  size_t start = offset % SFSRO_BLKSIZE;
  size_t actual_count;
  if (fdat_start) {
    actual_count = min<size_t> (count, fdat_start->size() - start); 
    actual_count = actual_count + (min<size_t> (fdat->size(), count-actual_count));
  }  else
    actual_count = min<size_t> (count, fdat->size() - start);

  bool eof;
  assert (nd->fa->size >= offset + actual_count);
  if (nd->fa->size == offset + actual_count)
    eof = true;
  else 
    eof = false;
  
  nfsproc3_readres (sbp, actual_count, start, eof, NFS3_OK, fdat_start, fdat, nd);
}

void
server::nfsproc3_readdir1 (nfscall *sbp, ref<const nfs_fh3> dir_nfh,
			   ref<name_dat> nd,
			   uint64 cookie, /* cookieverf3 &cv,*/ 
			   uint32 count)
{
  // dir_block denotes which directory block to read.
  uint64 dir_block = DIR_BLOCK (cookie);
  //  warnx << "dir_block = " << dir_block << "\n";

  // Mask the case of . or .. in block 0
  if (dir_block > 0) 
    dir_block--;

  // empty directory?
  if (nd->ip->reg->size > 0) {
    fs->getblock (wrap (fs, &filesys::getdirectory,
			(wrap (this, &server::nfsproc3_readdir2, 
			       sbp, cookie, dir_nfh, nd, count))),
		  nd->ip, dir_block);
  } else {
    nfsproc3_readdirres (sbp, cookie, count, NFS3_OK, NULL, dir_nfh, nd);
  }
}

void
server::nfsproc3_readdir2 (nfscall *sbp, uint64 cookie,
			   ref<const nfs_fh3> dir_nfh, ref<name_dat> nd,
			   uint32 count, ptr<const sfsro_directory> dir)
{
  //XXX broken, only works for directories consisting of a single block
  assert (nd->fa != NULL);
  nfsproc3_readdirres (sbp, cookie, count, NFS3_OK, dir, dir_nfh, nd);
}



// assumes that path came from either "/" or nfsfh2path
void 
pathtrans::nd (cb_ptr_name_dat_t cb, const str file_path)
{
  ptr<name_dat> nd = (*namec)[file_path];
  
  cstat.namec_tot++;

  if (nd != NULL) {
    cstat.namec_hit++;
    cb (nd);    
  } else {
    cstat.namec_miss++;

    if (file_path == "/") {
      fs->getinode (wrap (this, &pathtrans::add_entry, cb, str ("/"),
			  rootrofh),
		    rootrofh);
      return; 
    }

    if (asrvtrace >= 5) {
      warnx << "pathtrans::nd: nd not in cache.\n";
    }
    // Traverse the fhtt to find sfsro handle
    str parent, filename;
    ref<vec<str> > suffix (New refcounted<vec<str> > ());

    // Find the longest path prefix in our name cache
    // XXX Long paths might cause DoS.
    while (nd == NULL) {
      parentpath (parent, filename, file_path);
      nd = (*namec)[parent];
      suffix->push_back (filename);

      if (asrvtrace >= 5) {
	warnx << "path2nd: parent=" << parent << " filename=" << filename 
	      << "\n";
	if (nd==NULL)
	  warnx << "path2nd: nd=NULL\n";
	else
	  warnx << "path2nd: nd=Defn\n";
	warnx << "path2nd: suffix=" << join (str(", "), *suffix) << "\n\n";      
      }
    }

    nd1 (cb, suffix, file_path, nd);

  }
}


void 
pathtrans::nfsfh (nfs_fh3 *nfh, const str file_path)
{
  assert (nfh != NULL);

  nfh->data.setsize (SFSRO_FHSIZE);
  bzero(nfh->data.base (), nfh->data.size ());

  struct iovec iov[2];
  iov[0].iov_base = static_cast<char *> (nfs_fh3_IV);
  iov[0].iov_len = SFSRO_IVSIZE;  
  iov[1].iov_base = const_cast <char *> (file_path.cstr ());
  iov[1].iov_len = file_path.len ();

  sha1_hashv (nfh->data.base(), iov, 2);

  fhtt->insert (*nfh, file_path);
}


void
pathtrans::lookup (cb_ptr_name_dat_t cb, ptr<name_dat> dir_nd, 
		   str dir_path, str filename)
{
  if ((filename == ".") 
      || ((filename == "..") && (dir_path == "/"))) {
    cb (dir_nd);
    return;
  }
  
  if (filename == "..") {
    str parent, fn;
    parentpath (parent, fn, dir_path);
    nd (cb, parent);
    return;
  }

  // empty directories
  if (dir_nd->ip->reg->size == 0)
    cb ((ptr<name_dat>) NULL);
  else
    lookup1 (cb, dir_nd, dir_path, filename);
}


void
pathtrans::add_entry (cb_ptr_name_dat_t cb, 
		      str file_path,
		      ref<const sfs_hash> fh,
		      ref<const sfsro_inode> ip)
{
  if (asrvtrace >= 5) {
    warnx << "pathtrans::add_entry file_path = " << file_path << "\n";
  }

  nfs_fh3 nfh;
  nfsfh (&nfh, file_path);
  fhtt->insert (nfh, file_path);

  fattr3 fa;
  ro2fattr (&fa, ip, &nfh, id);

  ref<name_dat> nd = New refcounted<name_dat> 
    (fh, ip,
     New refcounted<fattr3> (fa));
     
  if (!namec->insert (file_path, nd)) {
    warnx << "pathtrans::add_entry: file_path already cached\n";
  }

  cb (nd);
}


void 
pathtrans::nd1 (cb_ptr_name_dat_t cb, ref<vec<str> > suffix,
		str dir_path, ptr<name_dat> dir_nd)
{
  assert (dir_nd != NULL);

  if (suffix->empty ()) {
    if (asrvtrace >= 5) {
      warnx << "path2nd1: suffix empty. good\n";
    }

    cb (dir_nd);
  } else {
    str filename = suffix->pop_back ();
    if (asrvtrace >= 5) {
      warnx << "pathtrans::nd1: looking up filename=" << filename << "\n";
    }
    lookup1 (wrap (this, 
		   &pathtrans::nd1, cb, suffix, dir_path),
	     dir_nd, dir_path, filename);
  }
}



void
pathtrans::lookup1 (cb_ptr_name_dat_t cb, ptr<name_dat> dir_nd, 
		    str dir_path, str filename)
{
  fs->getblock (wrap (fs, &filesys::getdirectory,
		      wrap (this, &pathtrans::lookup2, cb, dir_nd,
			    dir_path, filename, 0)),
		dir_nd->ip, 0);
}

void 
pathtrans::lookup2 (cb_ptr_name_dat_t cb, ptr<name_dat> dir_nd, 
		    str dir_path, str filename, 
		    uint64 blocknum,
		    ptr<const sfsro_directory> dir)
{
  assert (filename != ".");
  assert (filename != "..");

  if (dir == NULL) {
    cb ((ptr<name_dat>) NULL);
  } else {
    sfsro_dirent *e = NULL, *e_prev = NULL;
    ptr<name_dat> nd = NULL;
    
    if (asrvtrace >= 5) {
      warn << "dirent_lookup: name is " << filename << "\n";
    }
    
    for (e = e_prev = dir->entries; e; e = e->nextentry) {
      if (filename == e->name)
	{
	  ref<const sfs_hash> fh = 
	    New refcounted<sfs_hash> (e->fh);
	  str file_path;
	  if (dir_path == "/") 
	    file_path = strbuf () << dir_path << filename;
	  else
	    file_path = strbuf () << dir_path << str ("/") << filename;
	  fs->getinode (wrap (this, &pathtrans::add_entry,
			      cb, file_path, fh),
			fh);
	  return;
	}

      /* Disable optimized search for now...may be out of order
      if ((e_prev->name < filename) &&
	  (filename < e->name))
	{
	  warn << "dirent_lookup: no match\n";
	  cb ((ptr<name_dat>) NULL);
	}

      e_prev = e;
      */

    }
    


    // this above only works for directories of 1 block
    // XX below is broken.  fails if the filename does not exist.
    if (dir->eof != true) {
      fs->getblock (wrap (fs, &filesys::getdirectory,
			  wrap (this, &pathtrans::lookup2, cb, dir_nd,
				dir_path, filename, blocknum +1)),
		    dir_nd->ip, blocknum + 1);
    } else {
      cb ((ptr<name_dat>) NULL);
    }
  } 
}


/*

  Functions to convert raw SFSRO blocks into data structures
  like directories, file blocks, indir blocks, etc

*/


inline void
filesys::getdirectory (cb_sfsro_directory_t cb, ptr<const sfs_hash> fh)
{
  if (fh == NULL) {
    // XXX fix
    warn << "filesys::getdirectory null hash\n";
    return;
  } else {
 
    ptr<const sfsro_directory> dir = directoryc[*fh];
    
    cstat.directoryc_tot++;
    if (dir != NULL) {
      cstat.directoryc_hit++;
      cb (dir);
    } else {
      cstat.directoryc_miss++;
      if (asrvtrace >= 5) {
	warnx << "filesys::getdirectory: SFSROFH="  << hexdump (fh, 20) << "\n";
      }
      
      gd->fetch (wrap (this, &filesys::getdirectory1, cb, fh), fh);
    }
  }
}

inline void
filesys::getfiledata (cb_rpc_bytes_t cb, ptr<const sfs_hash> fh)
{
  if (fh == NULL) {
    // XXX fix
    warn << "filesys::getfiledata null hash\n";
    return;
  } else {
    
    ptr<const rpc_bytes<RPC_INFINITY> > fdat = blockc[*fh];
    
    cstat.blockc_tot++;
    if (fdat != NULL) {
      cstat.blockc_hit++;
      cb (fdat);
    } else {
      cstat.blockc_miss++;
      gd->fetch (wrap (this, &filesys::getfiledata1, cb, fh), fh);
    }
  }
}

inline void
filesys::getinode (cb_sfsro_inode_t cb, ptr<const sfs_hash> fh)
{
 
  if (fh == NULL) {
    // XXX fix
    warn << "filesys::getinode null hash\n";
    return;
  } else 
    gd->fetch (wrap (this, &filesys::getinode1, cb, fh), fh);
}

inline void
filesys::getindir (cb_sfsro_indirect_t cb, ptr<const sfs_hash> fh)
{
  if (fh == NULL) {
    // XXX fix
    warn << "filesys::getindir null hash\n";
    return;
  } else {

    ptr<const sfsro_indirect> indir = iblockc[*fh];
    
    cstat.iblockc_tot++;
    if (indir != NULL) {
      cstat.iblockc_hit++;
      cb (indir);
    } else {
      cstat.iblockc_miss++;
      gd->fetch (wrap (this, &filesys::getindir1, cb, fh), fh);
    }
  }
}

void
filesys::getblock (cb_ptr_sfs_hash_t cb, ref<const sfsro_inode> ip, uint64 b)
{  
  if (b < SFSRO_NDIR) {
    assert (ip->reg->direct.size () > b);
    cb (New refcounted<sfs_hash> (ip->reg->direct[b]));
  } else {
    size_t i = (b - SFSRO_NDIR);
    
    if (i < SFSRO_NFH) {
      getindir(wrap (this,
		     &filesys::single_indirectres, cb, i, ip),
	       (New refcounted<sfs_hash> (ip->reg->indirect)));
    }
    else {
      i -= SFSRO_NFH;
      
      if (i < SFSRO_NFH * SFSRO_NFH)
	getindir(wrap (this,
		       &filesys::double_indirectres, cb, i, ip),
		 (New refcounted<sfs_hash> 
		  (ip->reg->double_indirect)));
      else { 
	i -= SFSRO_NFH * SFSRO_NFH;
	
	if (i < SFSRO_NFH * SFSRO_NFH * SFSRO_NFH)
	  getindir(wrap (this, 
			 &filesys::triple_indirectres, cb, i, ip),
		   (New refcounted<sfs_hash> 
		    (ip->reg->triple_indirect)));
 	else {
	   assert(0);  // too big
	   // XX should fail gracefully?  hang?
	}
      }
    } 
  }
  //    puthyper (temp.data.base (), cookie);
}



/*

  helps filesys public functions

*/

void
filesys::getdirectory1 (cb_sfsro_directory_t cb, ref<const sfs_hash> fh, 
		       ref<const sfsro_data> data)
{
  // If this assertion fails, the publisher is malicious.  
  // We should recover gracefully, but we currently do not.      
  if (asrvtrace >= 5) {
    warnx << "filesys::getdirectory1: SFSROFH="  << hexdump (fh, 20) << "\n";
  }

  assert (data->type == SFSRO_DIRBLK);

  ref<const sfsro_directory> dir
    = New refcounted<sfsro_directory> (*data->dir);

  if (!sfsrocd_nocache) 
    if (!directoryc.insert (*fh, dir))
      warnx << "getdirectory1: fh already cached\n";
  
  cb (dir);

}

void
filesys::getfiledata1 (cb_rpc_bytes_t cb, ref<const sfs_hash> fh, 
		      ref<const sfsro_data> data)
{
  // If this assertion fails, the publisher is malicious.  
  // We should recover gracefully, but we currently do not.      
  assert(data->type == SFSRO_FILEBLK);

  ref<const rpc_bytes<RPC_INFINITY> > fdat
    = New refcounted<rpc_bytes<RPC_INFINITY> > (*data->data);

  if (!sfsrocd_nocache) 
    if (!blockc.insert (*fh, fdat))
      warnx << "getfiledata1: fh already cached\n";
  
  cb (fdat);
}

void
filesys::getinode1 (cb_sfsro_inode_t cb, ref<const sfs_hash> fh,
		    ref<const sfsro_data> data)
{
  // If this assertion fails, the publisher is malicious.  
  // We should recover gracefully, but we currently do not.      
  assert(data->type == SFSRO_INODE);

  ref<const sfsro_inode> i
    = New refcounted<sfsro_inode> (*data->inode);
  
  cb (i);
}

void
filesys::getindir1 (cb_sfsro_indirect_t cb, ref<const sfs_hash> fh, 
		   ref<const sfsro_data> data)
{
  // If this assertion fails, the publisher is malicious.  
  // We should recover gracefully, but we currently do not.      
  assert(data->type == SFSRO_INDIR);

  ref<const sfsro_indirect> indir
    = New refcounted<sfsro_indirect> (*data->indir);

  if (!sfsrocd_nocache) 
    if (!iblockc.insert (*fh, indir))
      warnx << "getindir1: fh already cached\n";
  
  cb (indir);
}



void
filesys::single_indirectres (cb_ptr_sfs_hash_t cb, size_t i, 
			   ref<const sfsro_inode> ip,
			   ref<const sfsro_indirect> indirect)
{
  assert (i < SFSRO_NFH);
  assert (indirect->handles.size () > i);

  cb (New refcounted<sfs_hash> (indirect->handles[i]));
}

void
filesys::double_indirectres (cb_ptr_sfs_hash_t cb, size_t i, 
			     ref<const sfsro_inode> ip,
			     ref<const sfsro_indirect> indirect)
{
  assert (i < (SFSRO_NFH * SFSRO_NFH));

  size_t b = i % SFSRO_NFH;
  i = i / SFSRO_NFH;

  assert (indirect->handles.size () > i);
  getindir (wrap (this,
		  &filesys::single_indirectres, cb, b, ip),
	    New refcounted<sfs_hash> (indirect->handles[i]));
}

void
filesys::triple_indirectres (cb_ptr_sfs_hash_t cb, size_t i,
			     ref<const sfsro_inode> ip,
			     ref<const sfsro_indirect> indirect)
{
  assert (i < (SFSRO_NFH * SFSRO_NFH * SFSRO_NFH));

  size_t b = i % (SFSRO_NFH * SFSRO_NFH);
  i = i / (SFSRO_NFH * SFSRO_NFH);

  assert (indirect->handles.size () > i);

  getindir(wrap (this,
		 &filesys::double_indirectres, cb, b, ip),
	   New refcounted<sfs_hash> (indirect->handles[i]));
}

/* 
   
   Should only be called from the filesys functions
   Functions that communicate directly with SFSRO servers.
   
*/



/* Get the data associated with the handle fh.  Verify secure */
void
getdata::fetch (cb_sfsro_data_t cb, ref<const sfs_hash> fh)
{
  sfsro_datares *res = New sfsro_datares ();

  if (asrvtrace >= 5) {
    warnx << "getdata::fetch with sname " << sname << "\n";
  }
  sfsro_getdataargs gdargs;
  gdargs.sname = sname;
  gdargs.fh = *fh;

  sfsroc->call (SFSROPROC2_GETDATA, &gdargs, res, 
		wrap (this, &getdata::fetch1, cb, fh, res));
}

/* Verify integrity, unmarshall, then make callback */
// XX only getdata should call this.
void
getdata::fetch1 (cb_sfsro_data_t cb, ref<const sfs_hash> fh,
		   sfsro_datares *res, clnt_stat err)
{
  auto_xdr_delete axd (sfsro_program_2.tbl[SFSROPROC2_GETDATA].xdr_res, res);

  if (err) {
    fatal << "getdata::fetch1 failed\n";
    // Handle error
  }

  char *resbuf = res->resok->data.base ();
  size_t reslen = res->resok->data.size ();

  /* verify integrity of unmarshalled data */
  if (!sfsrocd_noverify &&
      !verify_sfsrofh (IV, SFSRO_IVSIZE, fh, resbuf, reslen)) {
    // XXX Handle error gracefully, we don't yet
    fatal ("Bad hash.");
    return;
  }

  ref<sfsro_data> data = New refcounted<sfsro_data> ();
  xdrmem x (resbuf, reslen, XDR_DECODE);
  bool ok = xdr_sfsro_data (x.xdrp (), data);
  if (!ok) {
    warn << "fetch1: couldn't unmarshall data\n";
    // XXX need to handle error gracefully
    fatal ("Bad unmarshall.");
    return;
  }

  if (data->type == SFSRO_SEALED) {
    if (!kr) {
      fatal ("no key regression structure for unsealing.");
    }

#ifdef SFSRO_PROXY
    if (data->ct->lt == SFSRO_PROXY_REENC && !sfsrocd_proxymaster) {
      if (sfsrocd_proxylocal) { 
	char *buf = (char*)data->ct->lockbox.base ();
	int len;
	ECn c1;
	ZZn2 Zc1;
	memcpy (&len, buf, sizeof (int));
	buf += sizeof (int);
	c1 = charToECn (buf);
	
	if (proxy_reencrypt(proxy_params, c1, proxy_delegationKey, Zc1) == FALSE) {
	  fatal << "Re-encryption failed\n";
	}
	sfsro_data decres;
	if (!unseal (kr->gk (data->ct->gk_vers), (sfsro_sealed *)data->ct, 
		     &decres, &Zc1)) {
	  fatal << "Unable to unseal block\n";
	}
	*data = decres;
	cb (data);
	return;
      } else {
	sfsro_proxyreenc *res = New sfsro_proxyreenc ();
	sfsro_proxyreenc pargs;
	
	char *buf = (char*)data->ct->lockbox.base ();
	int len;
	ECn c1;
	ZZn2 Zc1;
	memcpy (&len, buf, sizeof (int));
	buf += sizeof (int);
	c1 = charToECn (buf);
	pargs.data.setsize (len);
	len = ECnTochar (c1, pargs.data.base (), pargs.data.size ());
	
	sfsroc->call (SFSROPROC2_PROXYREENC, &pargs, res, 
		      wrap (this, &getdata::fetch2, cb, fh, data, res));
	return;
      }
    }
#endif
    sfsro_data decres;
    if (!unseal (kr->gk (data->ct->gk_vers), (sfsro_sealed *)data->ct, 
		 &decres)) {
      fatal << "Unable to unseal block\n";
    }
    *data = decres;
  }
  
  cb (data);
}    

void
getdata::fetch2 (cb_sfsro_data_t cb, ref<const sfs_hash> fh,
		 ref<sfsro_data> data,
		 sfsro_proxyreenc *res, clnt_stat err)
{
  auto_xdr_delete axd (sfsro_program_2.tbl[SFSROPROC2_PROXYREENC].xdr_res, res);
  sfsro_data decres;

#ifdef SFSRO_PROXY
  ZZn2 Zc1 = charToZZn2 (res->data.base ());

  if (!unseal (kr->gk (data->ct->gk_vers), (sfsro_sealed *)data->ct, 
	       &decres, &Zc1)) {
    fatal << "Unable to unseal block\n";
  }
  *data = decres;
  cb (data);
 
#else
  fatal << "SHould never get here\n";
#endif
}
