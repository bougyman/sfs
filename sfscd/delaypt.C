/* $Id: delaypt.C,v 1.31 2002/05/28 13:53:13 dm Exp $ */

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

#include "sfscd.h"

const u_int maxmnt = 2;

class mntfs : public afsdir {
  typedef callback<void, ref<mntfs> >::ref mcb;

  static u_int namectr;
  static vec<mcb> waitq;

  void mntcb (int, u_int64_t);
  static void makecbs ();

protected:
  mntfs ();
  void finalize ();

public:
  tailq_entry<mntfs> qlink;
  const str name;

  static void alloc (mcb);
};

static tailq<mntfs, &mntfs::qlink> mntfs_free;

u_int mntfs::namectr;
vec<mntfs::mcb> mntfs::waitq;

mntfs::mntfs ()
  : afsdir (NULL), name (strbuf ("%d", namectr++))
{
  afs_mnt->mkdir (name);

  str path = strbuf ("%s/.mnt/%s", sfsroot, name.cstr ());
  nfs_fh fh;
  mkfh (&fh);
  str mntname (strbuf ("(sfsmnt/%s)", name.cstr ()));
  mnt_mount (dup (afsfd), mntname, path,
	     v3flag | NMOPT_NOAC | NMOPT_RO | NMOPT_SOFT,
	     nfs_fh2tobytes (fh), wrap (this, &mntfs::mntcb));
}

void
mntfs::mntcb (int err, u_int64_t)
{
  if (err)
    fatal ("mount (%s/.mnt/%s): %s\n", sfsroot, name.cstr (), strerror (err));
  mntfs_free.insert_tail (this);
  makecbs ();
}

void
mntfs::makecbs ()
{
  while (waitq.size () && mntfs_free.first)
    (*waitq.pop_front ()) (mkref (mntfs_free.remove (mntfs_free.first)));
}

void
mntfs::finalize ()
{
  mntfs_free.insert_tail (this);
}

void
mntfs::alloc (mntfs::mcb cb)
{
  if (mntfs_free.first)
    (*cb) (mkref (mntfs_free.remove (mntfs_free.first)));
  else {
    waitq.push_back (cb);
    if (namectr < maxmnt)
      vNew refcounted<mntfs>;
  }
}

delaypt::delaypt ()
  : afsnode (NF3LNK), name (strbuf ("%032" U64F "d", ino)),
    wlink (afslink::alloc ()), resok (false), mdirok (false),
    finalized (false),
    delaypath (strbuf () << sfsroot << "/.mnt/wait/" << name),
    lastaid (0)
{
  ctime.seconds = ctime.nseconds = 0;
  bool res = afs_wait->link (wlink, name);
  assert (res);
  mntfs::alloc (wrap (this, &delaypt::getmntfs));
}

delaypt::~delaypt ()
{
  afs_wait->unlink (name);
  if (mdir)
    mdir->unlink (name);
}

void
delaypt::finalize ()
{
  assert (resok);
  finalized = true;
  trydel ();
}

bool
delaypt::trydel ()
{
  if (!finalized || !mdirok)
    return false;
  delaycb (8, wrap (this, &delaypt::delthis));
  return true;
}

void
delaypt::getmntfs (ref<mntfs> m)
{
  mdirok = true;
  if (resok) {
    trydel ();
    return;
  }
  mdir = m;
  mlink = afslink::alloc ();
  bool res = mdir->link (mlink, name);
  assert (res);
  delaypath = strbuf () << sfsroot << "/.mnt/"
			<< mdir->name << "/" << name;
  wlink->setres ("../" << mdir->name << "/" << name);
}

void
delaypt::nfs_readlink (svccb *sbp)
{
  if (sbp->vers () == 2) {
    readlinkres res (NFS_OK);
    *res.data = delaypath;
    if (isnfsmounter (sbp))
      res.set_status (NFSERR_STALE);
    sbp->reply (&res);
  }
  else {
    readlink3res res (NFS3_OK);
    if (isnfsmounter (sbp))
      res.set_status (NFS3ERR_STALE);
    else {
      res.resok->data = delaypath;
      mkpoattr (res.resok->symlink_attributes, sbp2aid (sbp));
    }
    sbp->reply (&res);
  }
}

void
delaypt::nfs_getattr (svccb *sbp)
{
  if (isnfsmounter (sbp))
    nfs_error (sbp, NFSERR_STALE);
  else
    afsnode::nfs_getattr (sbp);
}

void
delaypt::mkfattr3 (fattr3 *f, sfs_aid aid)
{
  /* BSD needs the seconds (not just milliseconds/nanoseconds) of the
   * ctime to change on every lookup/getattr in order to defeat the
   * name cache. */
  if (aid != lastaid) {
    lastaid = aid;
    bumpctime ();
  }

  afsnode::mkfattr3 (f, aid);
}

void
delaypt::setres (str path)
{
  assert (!resok);
  resok = true;
  if (path.len () && path[0] != '/')
    path = strbuf () << "../../" << path;
  wlink->setres (path);
  if (mdir) {
    mlink->setres (path);
    trydel ();
  }
}

void
delaypt::setres (nfsstat err)
{
  assert (!resok);
  resok = true;
  if (mdir) {
    mlink->setres (err);
    trydel ();
  }
  else
    wlink->setres (err);
}
