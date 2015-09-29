/* $Id: mpfsnode.C,v 1.26 2004/05/03 20:52:50 dm Exp $ */

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
#include "rxx.h"

static dev_t baddev;

#if 1
/* XXX - functions to work around g++ bugs */
typedef callback<void, mpfsnode *, int>::ref xxx_lcb_t;
static aclnt_cb
xxx_wrap_1 (mpfsnode *c,
	    void (mpfsnode::*f) (str, void *, xxx_lcb_t, clnt_stat),
	    str a1, void *a2, xxx_lcb_t a3)
{
  return wrap (c, f, a1, a2, a3);
}
static aclnt_cb
xxx_wrap_2 (mpfsnode *c,
	    void (mpfsnode::*f) (void *, cbid, mountarg *, clnt_stat),
	    void *a1, cbid a2, mountarg *a3)
{
  return wrap (c, f, a1, a2, a3);
}
#else
#define xxx_wrap_1 wrap
#define xxx_wrap_2 wrap
#endif

class mpfsref {
  mpfsnode *const n;
  mpfsref &operator= (const mpfsref &r);
  mpfsref (const mpfsref &r) : n (r.n) { n->incref (); }
public:
  mpfsref (mpfsnode *nn) : n (nn) { n->incref (); }
  ~mpfsref () { n->decref (); }
};

const char *
basename (const char *s)
{
  const char *p = strrchr (s, '/');
  return p ? p + 1 : s;
}

str
strip_double_slash (str s)
{
  if (s[0] != '/' || s[1] != '/')
    return s;
  const char *p = s.cstr () + 1;
  while (p[1] == '/')
    p++;
  return str (p, s.cstr () + s.len () - p);
}

inline int
umounterr (int e1, int e2)
{
  if (!e1)
    return e2;
  if (!e2)
    return e1;
  if (e1 == EBUSY || e2 == EBUSY)
    return EBUSY;
  if (e1 == EINVAL)
    return e2;
  return e1;
}

mpfsnode::mpfsnode (str nm, mpfsnode::mpfsnode_type t, mpfsnode *par,
		    ptr<nfsfd> n, const nfsmnt_handle *hp,
		    mpfsnode *mntdir, str hn)
  : fullpath (strip_double_slash (nm)), type (t),
    parent (par ? par : mntdir), mp (NULL), hostname (hn),
    refcnt (0), lock_flag (false), nf (n),
    dir (New mpfsdir), fh (t == LOCAL || t == XFS ? nfsmnt_handle () : *hp),
    fname (basename (fullpath)), attrvalid (false), devname ("")
{
  assert (!par || !mntdir);
  assert (!mntdir || hostname);
  attrbase.init ();
  switch (type) {
  case NFS2:
    attr2.select ();
    assert (fh.size () == NFS_FHSIZE);
    nf->nfs2nodes.insert (this);
    break;
  case NFS3:
    attr3.select ();
    nf->nfs3nodes.insert (this);
    break;
  default:
    assert (!nf);
    break;
  }

  if (par)
    parent->dir->insert (this);
  else if (mntdir)
    parent->mp = this;
}

mpfsnode::~mpfsnode ()
{
  if (parent) {
    if (parent->mp == this)
      parent->mp = NULL;
    else
      parent->dir->remove (this);
  }

  switch (type) {
  case NFS2:
    nf->nfs2nodes.remove (this);
    break;
  case NFS3:
    nf->nfs3nodes.remove (this);
    break;
  default:
    break;
  }
  attrbase.destroy ();
  delete dir;
}

static rxx pathsplit ("^/*([^/]+)(/.*)?$");

mpfsnode *
mpfsnode::lookup (str p)
{
  if (!p || !pathsplit.search (p))
    return this;
  else if (mp)
    return mp->lookup (p);
  else if (mpfsnode *n = dir->lookup(pathsplit[1]))
    return n->lookup (pathsplit[2]);
  else
    return NULL;
}

mpfsnode *
mpfsnode::mkdir_local (str p)
{
  if (type != LOCAL)
    return NULL;
  else if (!p || !pathsplit.search (p))
    return this;
  else if (locked () || mp)
    return NULL;
  else {
    str first = pathsplit[1];
    str rest = pathsplit[2];
    if (mpfsnode *n = dir->lookup(first))
      return n->mkdir_local (rest);
    else {
      n = New mpfsnode (fullpath << "/" << first, LOCAL, this);
      return n->mkdir_local (rest);
    }
  }
}

void
mpfsnode::mkdir (str path, lcb_t cb)
{
  if (!path || !pathsplit.search (path)) {
    (*cb) (this, 0);
    return;
  }

  str first = pathsplit[1];
  str rest = pathsplit[2];

  if (first == "" || first == "." || first == "..")
    (*cb) (NULL, EPERM);
  else if (locked ())
    waiters.push_back (wrap (this, &mpfsnode::mkdir, path, cb));
  else if (mp)
    mp->mkdir (path, cb);
  else if (type == UVFS || type == XFS)
    (*cb) (NULL, EINVAL);
  else if (mpfsnode *n = dir->lookup (first))
    n->mkdir (rest, cb);
  else if (type == LOCAL)
    (*cb) (NULL, EPERM);
  else if (type == NFS2) {
    diropargs arg;
    assert (arg.dir.data.size () == fh.size ());
    memcpy (arg.dir.data.base (), fh.base (), arg.dir.data.size ());
    arg.name = first;

    if (ptr<aclnt> c = nf->mkclnt (2)) {
      lock ();
      diropres *resp = New diropres;
      c->call (NFSPROC_LOOKUP, &arg, resp,
	       xxx_wrap_1 (this, &mpfsnode::lookupres, path, resp, cb),
	       myauthunix);
    }
    else
      (*cb) (NULL, EIO);
  }
  else if (type == NFS3) {
    diropargs3 arg;
    arg.dir.data = fh;
    arg.name = first;

    if (ptr<aclnt> c = nf->mkclnt (3)) {
      lock ();
      lookup3res *resp = New lookup3res;
      c->call (NFSPROC3_LOOKUP, &arg, resp,
	       xxx_wrap_1 (this, &mpfsnode::lookupres, path, resp, cb),
	       myauthunix);
    }
    else
      (*cb) (NULL, EIO);
  }
  else
    panic ("mpfsnode: bad type\n");
}

void
mpfsnode::lookupres (str path, void *_resp, lcb_t cb, clnt_stat err)
{
  pathsplit.search (path);
  str first = pathsplit[1];
  str rest = pathsplit[2];

  if (type == NFS2) {
    auto_ptr<diropres> resp (static_cast<diropres *> (_resp));
    if (err)
      (*cb) (NULL, EIO);
    else if (resp->status)
      (*cb) (NULL, resp->status);
    else {
      nfsmnt_handle h;
      h.setsize (NFS_FHSIZE);
      memcpy (h.base (), resp->reply->file.data.base (), h.size ());
      mpfsnode *n = New mpfsnode (fullpath << "/" << first,
				  NFS2, this, nf, &h);
      *n->attr2 = resp->reply->attributes;
      n->attrvalid = true;
      mpfsref r (n);
      n->mkdir (rest, cb);
    }
  }
  else if (type == NFS3) {
    auto_ptr<lookup3res> resp (static_cast<lookup3res *> (_resp));
    if (err)
      (*cb) (NULL, EIO);
    else if (resp->status)
      (*cb) (NULL, resp->status);
    else {
      mpfsnode *n = New mpfsnode (fullpath << "/" << first, NFS3, this, nf,
				  &resp->resok->object.data);
      if (resp->resok->obj_attributes.present) {
	*n->attr3 = implicit_cast<fattr3 &>
	  (*resp->resok->obj_attributes.attributes); // XXX - gcc 2.9
	n->attrvalid = true;
	mpfsref r (n);
	n->mkdir (rest, cb);
      }
      else if (ptr<aclnt> c = nf->mkclnt (3)) {
	nfs_fh3 arg;
	getattr3res *resp = New getattr3res;
	arg.data = n->fh;
	n->lock ();
	c->call (NFSPROC3_GETATTR, &arg, resp,
		 wrap (n, &mpfsnode::attr3mkdir, resp, rest, cb),
		 myauthunix);
      }
      else
	(*cb) (NULL, EIO);
    }
  }
  else
    panic ("mpfsnode: bad type\n");

  unlock ();
}

void
mpfsnode::attr3mkdir (getattr3res *resp, str rest, lcb_t cb, clnt_stat err)
{
  auto_ptr<getattr3res> _resdel (resp);

  if (err) {
    unlock ();
    (*cb) (NULL, EIO);
  }
  else if (resp->status) {
    unlock ();
    (*cb) (NULL, resp->status);
  }
  else {
    *attr3 = implicit_cast<fattr3 &> (*resp->attributes); // XXX - gcc 2.9
    attrvalid = true;
    mpfsref r (this);
    unlock ();
    mkdir (rest, cb);
  }
}

#ifdef HAVE_DEV_XFS
void
mpfsnode::mount_xfs (mountarg *a, str devname, cbid cb)
{
  a->flags &= NMOPT_VALID;
  if (mp || dir->dir.size ()) {
    (*cb) (EBUSY, baddev);
    return;
  }
  else if (locked ()) {
    waiters.push_back (wrap (this, &mpfsnode::mount_xfs, a, devname, cb));
    return;
  }

  lock ();

  vNew mpfsnode (fullpath, XFS, NULL, NULL, NULL, this, devname);

  int fds[2];
  if (pipe (fds) < 0) {
    (*cb) (errno, baddev);
    delete mp;
    unlock ();
    return;
  }

  pid_t pid = afork ();
  switch (pid) {
  case -1:
    delete mp;
    (*cb) (errno, baddev);
    close (fds[0]);
    close (fds[1]);
    unlock ();
    break;
  case 0:
    close (fds[0]);
    domount_xfs (fullpath, devname, a->flags, fds[1]);
    panic ("domount_uvfs returned\n");
  default:
    close (fds[1]);
    chldcb (pid, wrap (this, &mpfsnode::mountres, fds[0], cb,
		       (mountarg *) NULL));
    break;
  }
}
#endif /* HAVE_DEV_XFS */

void
mpfsnode::mount (mountarg *a, ref<nfsfd> n, cbid cb)
{
  a->flags &= NMOPT_VALID;
  if (n->sotype == SOCK_STREAM)
    a->flags |= NMOPT_TCP;

  if (mp || dir->dir.size ())
    (*cb) (EBUSY, baddev);
  else if (locked ())
    waiters.push_back (wrap (this, &mpfsnode::mount, a, n, cb));
#ifndef HAVE_NFS_V3
  else if (a->flags & NMOPT_NFS3)
    (*cb) (EPROTONOSUPPORT, baddev);
#endif /* !HAVE_NFS_V3 */
  else if (!(a->flags & NMOPT_NFS3) && a->handle.size () != NFS_FHSIZE)
    (*cb) (EINVAL, baddev);
  else if (a->flags & NMOPT_NFS3) {
    if (ptr<aclnt> c = n->mkclnt (3)) {
      lock ();
      vNew mpfsnode (fullpath, NFS3, NULL, n, &a->handle, this, a->hostname);
      getattr3res *resp = New getattr3res;
      c->call (NFSPROC3_GETATTR, &a->handle, resp, 
	       xxx_wrap_2 (this, &mpfsnode::getattrres, resp, cb, a),
	       myauthunix);
    }
    else
      (*cb) (EIO, baddev);
  }
  else {
    if (ptr<aclnt> c = n->mkclnt (2)) {
      lock ();
      vNew mpfsnode (fullpath, NFS2, NULL, n, &a->handle, this, a->hostname);
      attrstat *resp = New attrstat;
      c->call (NFSPROC_GETATTR, a->handle.base (), resp,
	       xxx_wrap_2 (this, &mpfsnode::getattrres, resp, cb, a),
	       myauthunix);
    }
    else
      (*cb) (EIO, baddev);
  }
}

void
mpfsnode::getattrres (void *_resp, cbid cb, mountarg *a, clnt_stat err)
{
  if (err) {
    if (mp->type == NFS2)
      delete static_cast<attrstat *> (_resp);
    else
      delete static_cast<getattr3res *> (_resp);
    delete mp;
    (*cb) (EIO, baddev);
    unlock ();
    return;
  }
  else if (mp->type == NFS2) {
    attrstat *resp = static_cast<attrstat *> (_resp);
    if (resp->status) {
      delete mp;
      (*cb) (resp->status, baddev);
      delete resp;
      unlock ();
      return;
    }
    *mp->attr2 = *resp->attributes;
    mp->attrvalid = true;
    delete resp;
  }
  else if (mp->type == NFS3) {
    getattr3res *resp = static_cast<getattr3res *> (_resp);
    if (resp->status) {
      delete mp;
      (*cb) (resp->status, baddev);
      delete resp;
      unlock ();
      return;
    }
    *mp->attr3 = implicit_cast<fattr3 &> (*resp->attributes); // XXX - 2.9
    mp->attrvalid = true;
    delete resp;
  }

  int fds[2];
  if (pipe (fds) < 0) {
    (*cb) (errno, baddev);
    delete mp;
    unlock ();
    return;
  }

  pid_t pid = afork ();
  switch (pid) {
  case -1:
    delete mp;
    (*cb) (errno, baddev);
    close (fds[0]);
    close (fds[1]);
    unlock ();
    break;
  case 0:
    close (fds[0]);
    domount (fullpath, &mp->nf->sin, &mp->fh, a->flags, a->hostname, fds[1],
	     type == LOCAL || opt_mount_full_path);
    panic ("domount returned\n");
  default:
    close (fds[1]);
#if MOUNT_REMOUNT_FULLPATH
    chldcb (pid, wrap (this, &mpfsnode::mountres, fds[0], cb,
		       /* Triggering a remount on some OSes (including
			* Solaris) make the output of the mount
			* command look nicer (show mounted on path,
			* instead of "." or the last component of
			* pathname). */
		       (type == LOCAL || opt_mount_full_path)
		       ? (mountarg *) NULL : a));
#else /* !MOUNT_REMOUNT_FULLPATH */
    chldcb (pid, wrap (this, &mpfsnode::mountres, fds[0], cb,
		       (mountarg *) NULL));
#endif /* !MOUNT_REMOUNT_FULLPATH */
    break;
  };
}

static void
mkmountrescb (cbid cb, int err, dev_t dev, int status)
{
  /* We don't care if the remount failed, file system still mounted */
  (*cb) (err, dev);
}

void
mpfsnode::mountres (int fd, cbid cb, mountarg *a, int status)
{
  int err = WIFEXITED (status) ? WEXITSTATUS (status) : EFAULT;
  if (err) {
    warn << "mount " << fullpath << ": " << strerror (err) << "\n";
    delete mp;
  }
  else
    warn << "mounted " << fullpath << "\n";
  unlock ();

  dev_t dev;
  bzero (&dev, sizeof (dev));
  if (fd >= 0) {
    if (!err && read (fd, &dev, sizeof (dev)) == sizeof (dev)) {
#if defined (major) && defined (minor)
      devname = strbuf (" (dev %d,%d)", major (dev), minor (dev));
#endif /* defined (major) && defined (minor) */
    }
    close (fd);
  }

  pid_t pid;
  if (!a || (pid = fork ()) == -1)
    (*cb) (err, dev);
  else if (pid)
    chldcb (pid, wrap (mkmountrescb, cb, err, dev));
  else {
    int flags = (a->flags & NMOPT_VALID) | NMOPT_UPDATE;
    domount (fullpath, &mp->nf->sin, &mp->fh, flags, mp->hostname, -1,
	     type == LOCAL);
    panic ("domount returned\n");
  }
}

void
mpfsnode::remount (int flags, cbi cb)
{
  if (!mp || (mp->type == NFS3) != bool (flags & NMOPT_NFS3)) {
    (*cb) (EINVAL);
    return;
  }
  if (locked ()) {
    waiters.push_back (wrap (this, &mpfsnode::remount, flags, cb));
    return;
  }
  lock ();

  flags &= NMOPT_VALID;
  flags |= NMOPT_UPDATE;
  if (mp->nf->sotype == SOCK_STREAM)
    flags |= NMOPT_TCP;

  pid_t pid = afork ();
  switch (pid) {
  case -1:
    (*cb) (errno);
    unlock ();
    break;
  case 0:
    domount (fullpath, &mp->nf->sin, &mp->fh, flags, mp->hostname, -1,
#if MOUNT_REMOUNT_FULLPATH
	     true
#else /* !MOUNT_REMOUNT_FULLPATH */
	     type == LOCAL
#endif /* !MOUNT_REMOUNT_FULLPATH */
	     );
    panic ("domount returned\n");
  default:
    chldcb (pid, wrap (this, &mpfsnode::remountres, cb));
    break;
  };
}

void
mpfsnode::remountres (cbi cb, int status)
{
  int err = WIFEXITED (status) ? WEXITSTATUS (status) : EFAULT;
  if (err)
    warn << "remount " << fullpath << ": " << strerror (err) << "\n";
  else
    warn << "remounted " << fullpath << "\n";
  unlock ();
  (*cb) (err);
}


void
mpfsnode::unmount (int flags, cbi cb)
{
  if (locked ()) {
    (*cb) (EBUSY);
    return;
  }
  if (!mp) {
    (*cb) (EINVAL);
    return;
  }
  if (mp->dir->dir.size ()) {
    (*cb) (EAGAIN);
    return;
  }

  pid_t pid = afork ();
  switch (pid) {
  case -1:
    (*cb) (errno);
    break;
  case 0:
    doumount (fullpath, flags);
    panic ("doumount returned\n");
  default:
    lock ();
    chldcb (pid, wrap (this, &mpfsnode::unmountres, cb, flags));
    break;
  }
}

void
mpfsnode::unmountres (cbi cb, int flags, int status)
{
  int err = WIFEXITED (status) ? WEXITSTATUS (status) : EFAULT;
  if (err) {
    if (!(flags & NUOPT_NLOG))
      warn << "unmount " << fullpath << devname << ": "
	   << strerror (err) << "\n";
  }
  else {
    warn << "unmounted " << fullpath << "\n";
    delete mp;
  }
  unlock ();
  (*cb) (err);
}

void
mpfsnode::unmountall (int flags, cbi cb)
{
  if (locked ())
    (*cb) (EBUSY);
  else if (mp) {
    lock ();
    mp->unmountall (flags, wrap (this, &mpfsnode::unmountallres1, flags, cb));
  }
  else if (mpfsnode *n = dir->dir.first ()) {
    n->incref ();
    lock ();
    unmountallres2 (n, 0, flags, cb, 0);
  }
  else
    (*cb) (0);
}

void
mpfsnode::unmountallres1 (int flags, cbi cb, int status)
{
  if (status || !mp) {
    unlock ();
    (*cb) (status);
  }
  else {
    mpfsref r (this);
    unlock ();
    unmount (flags, cb);
  }
}

void
mpfsnode::unmountallres2 (mpfsnode *n, int ostatus,
			  int flags, cbi cb, int status)
{
  ostatus = umounterr (ostatus, status);
  if (n) {
    mpfsnode *nn = dir->dir.next (n);
    if (nn)
      nn->incref ();
    n->unmountall (flags, wrap (this, &mpfsnode::unmountallres2,
				nn, ostatus, flags, cb));
    n->decref ();
  }
  else {
    unlock ();
    (*cb) (ostatus);
  }
}

void
mpfsnode::maybe_delete ()
{
  mpfsnode *p = parent;
  if (!locked () && !refcnt && p && this != p->mp
      && type != LOCAL && !mp && !dir->dir.size ()) {
    delete this;
    p->maybe_delete ();
  }
}

void
mpfsnode::unlock ()
{
  assert (lock_flag);
  lock_flag = false;
  if (waiters.empty ())
    maybe_delete ();
  else {
    incref ();
    (*waiters.pop_front ()) ();
    decref ();
  }
}
