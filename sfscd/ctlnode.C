/* $Id: ctlnode.C,v 1.8 2004/09/19 22:02:28 dm Exp $ */

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

#include "sfscd.h"
#include "ctlnode.h"

enum { maxctlfile = 0x4000 };
enum { closetimeout = 2 };

static tailq<msgnode, &msgnode::tlink> msgnode_closeq;
static timecb_t *msgnode_timecb;

void
fh2bytes (fhbytes *data, const svccb *sbp)
{
  if (sbp->vers () == 2)
    *data = sbp->Xtmpl getarg<nfs_fh> ()->data;
  else
    *data = sbp->Xtmpl getarg<nfs_fh3> ()->data;
}

inline afsnode::inum_t
fhb2extra (const fhbytes &data)
{
  assert (data.size ()
	  == 2 * sizeof (afsnode::inum_t) + sizeof (afsnode::fhsecret));
  return gethyper (&data[sizeof (afsnode::inum_t)
			+ sizeof (afsnode::fhsecret)]);
}

void
getsattr3 (sattr3 *s, svccb *sbp)
{
  assert (sbp->prog () == NFS_PROGRAM);
  switch (sbp->vers ()) {
  case 2:
    {
      sattr *sp = &sbp->Xtmpl getarg<sattrargs> ()->attributes;
      const u_int32_t nochange ((u_int32_t) -1);
      if (sp->mode != nochange) {
	s->mode.set_set (true);
	*s->mode.val = sp->mode;
      }
      if (sp->uid != nochange) {
	s->uid.set_set (true);
	*s->uid.val = sp->uid;
      }
      if (sp->gid != nochange) {
	s->gid.set_set (true);
	*s->gid.val = sp->gid;
      }
      if (sp->size != nochange) {
	s->size.set_set (true);
	*s->size.val = sp->size;
      }
      if (sp->atime.seconds != nochange) {
	s->atime.set_set (SET_TO_CLIENT_TIME);
	s->atime.time->seconds = sp->atime.seconds;
	s->atime.time->nseconds = 1000 * sp->atime.useconds;
      }
      if (sp->mtime.seconds != nochange) {
	s->mtime.set_set (SET_TO_CLIENT_TIME);
	s->mtime.time->seconds = sp->mtime.seconds;
	s->mtime.time->nseconds = 1000 * sp->mtime.useconds;
      }
    }
  case 3:
    *s = sbp->Xtmpl getarg<setattr3args> ()->new_attributes;
    break;
  default:
    panic ("getsattr3: bad NFS version %d\n", sbp->vers ());
    break;
  }
}

void
msgnode::tmosched (bool expired)
{
  if (expired)
    msgnode_timecb = NULL;
  msgnode *mp, *nmp;
  for (mp = msgnode_closeq.first; mp && mp->closetime <= tsnow; mp = nmp) {
    nmp = msgnode_closeq.next (mp);
    mp->destroy ();
  }
  if (mp && !msgnode_timecb)
    msgnode_timecb = timecb (mp->closetime, wrap (&tmosched, true));
}

msgnode::msgnode (ctlnode *c, const fhbytes &fh)
  : afsnode (NF3REG, geninum (fhb2extra (fh))), fhextra (fhb2extra (fh)),
    ctl (c), dirty (false)
{
  size = maxsize = ctl->read ().len ();
  if (size)
    buf = static_cast<char *> (xmalloc (size));
  else
    buf = NULL;
  memcpy (buf, ctl->read ().cstr (), size);
  closetime.tv_sec = tsnow.tv_sec + closetimeout;
  closetime.tv_nsec = tsnow.tv_nsec;
  msgnode_closeq.insert_tail (this);
  tmosched ();
}

msgnode::~msgnode ()
{
  msgnode_closeq.remove (this);
}

bool
msgnode::setsize (u_int s)
{
  if (s <= size)
    size = s;
  else if (s > maxctlfile)
    return false;
  else {
    if (s > maxsize) {
      maxsize = s;
      buf = static_cast<char *> (xrealloc (buf, maxsize));
    }
    bzero (buf + size, s - size);
    size = s;
  }
  return true;
}

void
msgnode::touch ()
{
  closetime.tv_sec = tsnow.tv_sec + closetimeout;
  closetime.tv_nsec = tsnow.tv_nsec;
  msgnode_closeq.remove (this);
  msgnode_closeq.insert_tail (this);
}

void
msgnode::destroy ()
{
#if 0
  bool mytime = (mtime.seconds > ctl->mtime.seconds
		 || (mtime.seconds == ctl->mtime.seconds 
		     && mtime.nseconds > ctl->mtime.nseconds));
  ctl->setcontents (str (buf, size));
  if (mytime)
    ctl->mtime = mtime;
#endif
  if (dirty && ctl->isfilecomplete (true, buf, size))
    ctl->doclose (str (buf, size), cbi_null);
  ctl->ntab.remove (fhextra);
}

void
msgnode::mkfattr3 (fattr3 *f, sfs_aid a)
{
  ctl->mkfattr3 (f, a);
  f->fileid = ino; 
  f->size = size;
  f->used = (size + 0x1fff) & ~0x1fff;
}

void
msgnode::nfs_setattr (svccb *sbp)
{
  touch ();
  sattr3 arg;
  getsattr3 (&arg, sbp);
  /* XXX - do something about guard? */
  if (arg.mode.set || arg.uid.set || arg.gid.set) {
    nfs_error (sbp, NFSERR_PERM);
    return;
  }
  switch (arg.mtime.set) {
  case SET_TO_CLIENT_TIME:
    mtime = *arg.mtime.time;
    bumpctime ();
    break;
  case SET_TO_SERVER_TIME:
    getnfstime (&mtime);
    break;
  default:
    break;
  }
  if (arg.size.set && !setsize (*arg.size.val)) {
    bumpctime ();
    nfs_error (sbp, NFSERR_DQUOT);
    return;
  }

  if (sbp->vers () == 2) {
    attrstat *resp = sbp->Xtmpl getres<attrstat> ();
    resp->set_status (NFS_OK);
    mkfattr (resp->attributes.addr (), sbp2aid (sbp));
  }
  else {
    wccstat3 *resp = sbp->Xtmpl getres<wccstat3> ();
    resp->set_status (NFS3_OK);
    mkpoattr (resp->wcc->after, sbp2aid (sbp));
  }

  dirty = arg.size.set;
  if (arg.size.set && ctl->isfilecomplete (false, buf, size)) {
    ctl->doclose (str (buf, size), wrap (mkref (ctl), &ctlnode::closecb, sbp));
    dirty = false;
  }
  else
    sbp->reply (sbp->getvoidres ());
}

void
msgnode::nfs_write (svccb *sbp)
{
  touch ();

  size_t off, len;
  const char *data;

  if (sbp->vers () == 2) {
    writeargs *argp = sbp->Xtmpl getarg<writeargs> ();
    off = argp->offset;
    len = argp->data.size ();
    data = argp->data.base ();
  }
  else {
    write3args *argp = sbp->Xtmpl getarg<write3args> ();
    off = argp->offset;
    len = argp->data.size ();
    data = argp->data.base ();
  }

  if (off > maxctlfile || len > maxctlfile
      || (off + len > maxsize && !setsize (off + len))) {
    nfs_error (sbp, NFSERR_DQUOT);
    return;
  }

  getnfstime (&mtime);
  if (size < off + len)
    size = off + len;
  memcpy (buf + off, data, len);

  if (sbp->vers () == 2) {
    attrstat *resp = sbp->Xtmpl getres<attrstat> ();
    resp->set_status (NFS_OK);
    mkfattr (resp->attributes.addr (), sbp2aid (sbp));
  }
  else {
    write3res *resp = sbp->Xtmpl getres<write3res> ();
    resp->set_status (NFS3_OK);
    resp->resok->count = len;
    // resp->resok->committed = sbp->Xtmpl getarg<write3args> ()->stable;
    resp->resok->committed = FILE_SYNC;
  }

  if (ctl->isfilecomplete (false, buf, size)) {
    ctl->doclose (str (buf, size), wrap (mkref (ctl), &ctlnode::closecb, sbp));
    dirty = false;
  }
  else {
    sbp->reply (sbp->getvoidres ());
    dirty = true;
  }
}

void
msgnode::nfs_read (svccb *sbp)
{
  touch ();

  size_t off, len;
  if (sbp->vers () == 2) {
    readargs *argp = sbp->Xtmpl getarg<readargs> ();
    off = argp->offset;
    len = argp->count;
  }
  else {
    read3args *argp = sbp->Xtmpl getarg<read3args> ();
    off = argp->offset;
    len = argp->count;
  }

  bool eof = true;
  if (off >= size || len >= size)
    off = len = 0;
  else if (off + len >= size)
    len = size - off;
  else
    eof = false;

  if (sbp->vers () == 2) {
    readres res (NFS_OK);
    mkfattr (&res.reply->attributes, sbp2aid (sbp));
    if (len > NFS_MAXDATA)
      len = NFS_MAXDATA;
    res.reply->data.set (buf + off, len);
    sbp->reply (&res);
  }
  else {
    read3res res (NFS3_OK);
    mkpoattr (res.resok->file_attributes, sbp2aid (sbp));
    res.resok->count = len;
    res.resok->eof = eof;
    res.resok->data.set (buf + off, len);
    sbp->reply (&res);
  }

}


ctlnode::ctlnode (sfs_aid a, str n)
  : afsreg (""), aid (a), name (n)
{
  ctime.seconds = ctime.nseconds = 0;
}

void
ctlnode::closecb (svccb *sbp, int err)
{
  if (err)
    nfs_error (sbp, err);
  else
    sbp->reply (sbp->getvoidres ());
}

msgnode *
ctlnode::getmsgnode (svccb *sbp)
{
  fhbytes fh;
  fh2bytes (&fh, sbp);
  inum_t fhextra = fhextra = fhb2extra (fh);
  ptr <msgnode> n = ntab[fhextra];
  if (!n) {
    n = New refcounted<msgnode> (this, fh);
    ntab.insert (fhextra, n);
  }
  return n;
}

void
ctlnode::mkfh (nfs_fh *fhp)
{
  afsnode::mkfh (fhp);
  lastino = geninum ();
  puthyper (&fhp->data[sizeof (inum_t) + sizeof (fhsecret)], lastino);
}

void
ctlnode::mkfattr3 (fattr3 *f, sfs_aid a)
{
  ctime.seconds++;
  afsreg::mkfattr3 (f, a);
  f->mode = 0644;
  f->uid = aid;
  f->gid = aid >> 32;
  f->gid = f->gid ? f->gid - 1 + sfs_resvgid_start : sfs_gid;
  f->fileid = lastino;
}

void
ctlnode::nfs_read (svccb *sbp)
{
  fhbytes fh;
  fh2bytes (&fh, sbp);
  inum_t fhextra = fhb2extra (fh);
  ptr <msgnode> n = ntab[fhextra];
  if (n)
    n->nfs_read (sbp);
  else
    afsreg::nfs_read (sbp);
}

void
ctlnode::nfs3_access (svccb *sbp)
{
  access3res res (NFS3_OK);
  mkpoattr (res.resok->obj_attributes, sbp2aid (sbp));
  if (sbp2aid (sbp) == aid)
    res.resok->access = ((ACCESS3_READ | ACCESS3_LOOKUP
			  | ACCESS3_MODIFY | ACCESS3_EXTEND)
			 & sbp->Xtmpl getarg<access3args> ()->access);
  else
    res.resok->access = 0;
  sbp->reply (&res);
}

class ctldir : public afsdir {
protected:
  const sfs_aid aid;
  ctldir (afsdir *parent, sfs_aid a) : afsdir (parent), aid (a) {}
public:
  void mkfattr3 (fattr3 *f, sfs_aid a);
  void nfs_create (svccb *sbp);
  void nfs_remove (svccb *sbp);
  void nfs3_access (svccb *sbp);
};

ref<afsreg>
ctlnodealloc (sfs_aid aid, str name)
{
  ref<afsreg> cn = New refcounted<testnode> (aid, name);
  cn->setcontents (strbuf ("# file ") << name << ", aid " << aid << "\n");
  return cn;
}

void
ctldir::mkfattr3 (fattr3 *f, sfs_aid rqaid)
{
  afsdir::mkfattr3 (f, rqaid);
  f->mode = 0755;
  f->uid = aid;
  f->gid = aid >> 32;
  f->gid = f->gid ? f->gid - 1 + sfs_resvgid_start : sfs_gid;
}

void
ctldir::nfs_remove (svccb *sbp)
{
  str name = sbp->vers () == 2
    ? str (sbp->Xtmpl getarg<diropargs> ()->name)
    : str (sbp->Xtmpl getarg<diropargs3> ()->name);

  if (!unlink (name))
    nfs_error (sbp, NFSERR_NOENT);
  else if (sbp->vers () == 2)
    sbp->replyref (NFS_OK);
  else
    sbp->replyref (wccstat3 (NFS3_OK));
}

void
ctldir::nfs_create (svccb *sbp)
{
  str name;

  if (sbp->vers () == 2) {
    createargs *ca = sbp->Xtmpl getarg<createargs> ();
    name = ca->where.name;
  }
  else {
    create3args *ca = sbp->Xtmpl getarg<create3args> ();
    name = ca->where.name;
    if (ca->how.mode == GUARDED && lookup (name, sbp2aid (sbp))) {
      nfs3_err (sbp, NFS3ERR_EXIST);
      return;
    }
    if (ca->how.mode == EXCLUSIVE) {
      nfs3_err (sbp, NFS3ERR_NOTSUPP);
      return;
    }
  }

  if (!nameok (name)) {
    nfs_error (sbp, NFSERR_ACCES);
    return;
  }

  afsnode *e = lookup (name, sbp2aid (sbp));
  if (!e) {
    ref<afsnode> er = ctlnodealloc (sbp2aid (sbp), name);
    link (er, name);
    e = er;
  }
  dirop_reply (sbp, e);
}

void
ctldir::nfs3_access (svccb *sbp)
{
  access3res res (NFS3_OK);
  mkpoattr (res.resok->obj_attributes, sbp2aid (sbp));
  res.resok->access = ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_EXECUTE;
  if (sbp2aid (sbp) == aid)
    res.resok->access |= ACCESS3_DELETE | ACCESS3_EXTEND | ACCESS3_MODIFY;
  res.resok->access &= sbp->Xtmpl getarg<access3args> ()->access;
  sbp->reply (&res);
}

ref<afsdir>
ctldiralloc (afsdir *p, sfs_aid aid)
{
  return New refcounted<ctldir> (p, aid);
}
