/* $Id: uvfsmount.C,v 1.5 2001/04/06 02:32:32 dm Exp $ */

/*
 *
 * Copyright (C) 1999 David Mazieres (dm@uun.org)
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

#ifdef USE_UVFS

#include "nfsmnt.h"

static dev_t baddev;

mpfsnode::mpfsnode (str nm, ptr<uvfsfd> dev, const nfsmnt_handle *hp,
			 mpfsnode *mntdir)
  : fullpath (strip_double_slash (nm)), type (UVFS),
    parent (mntdir), mp (NULL), refcnt (0), lock_flag (false),
    dir (New mpfsdir), fh (*hp), fname (basename (fullpath)),
    attrvalid (false), devname (""), uvfs_devno (dev->devno)
{
  parent->mp = this;
}

void
mpfsnode::mount_uvfs (mountarg *a, ref<uvfsfd> u, cbid cb)
{
  a->flags &= NMOPT_VALID;

  if (mp || dir->dir.size ()) {
    (*cb) (EBUSY, baddev);
    return;
  }
  else if (locked ()) {
    waiters.push_back (wrap (this, &mpfsnode::mount_uvfs, a, u, cb));
    return;
  }

  int fds[2];
  if (pipe (fds) < 0) {
    (*cb) (errno, baddev);
    delete mp;
    return;
  }

  lock ();
  vNew mpfsnode (fullpath, u, &a->handle, this);

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
    domount_uvfs (fullpath, uvfs_devno, &mp->fh, a->flags, fds[1]);
    panic ("domount_uvfs returned\n");
  default:
    close (fds[1]);
    chldcb (pid, wrap (this, &mpfsnode::mountres, fds[0], cb));
    break;
  }
}

ptr<uvfsfd>
uvfsfd::lookup (int fd)
{
  struct stat fdsb, uvfssb;
  if (fstat (fd, &fdsb) < 0 || !S_ISCHR (fdsb.st_mode))
    return NULL;
  if (stat ("/dev/uvfs0", &uvfssb) < 0)
    return NULL;
  if (major (fdsb.st_rdev) != major (uvfssb.st_rdev))
    return NULL;
  close (fd);
  return New refcounted<uvfsfd> (minor (fdsb.st_rdev));
}

#endif /* USE_UVFS */
