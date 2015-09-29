/* $Id: mnt.C,v 1.18 2004/04/10 18:49:44 dm Exp $ */

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

#include "sfscd.h"

bool root_is_nfsmounter;

static ptr<axprt_unix> mntx;
static ptr<aclnt> mntc;

static void
mnt_dead ()
{
  fatal ("nfsmounter died\n");
}

static void
mnt_res (cbi cb, int *res, clnt_stat stat)
{
  if (stat)
    fatal ("nfsmounter: %s\n", clnt_sperrno (stat));
  (*cb) (*res);
  delete res;
}

static void
mnt_mountres (callback<void, int, u_int64_t>::ref cb,
	      mountres *res, clnt_stat stat)
{
  if (stat)
    fatal ("nfsmounter: %s\n", clnt_sperrno (stat));
  (*cb) (res->status, res->status ? (u_int64_t) -1 : *res->fsid);
  delete res;
}

void
mnt_mount (int s, const str hostname, str path,
	   int flags, const nfsmnt_handle &fh,
	   callback<void, int, u_int64_t>::ref cb)
{
  mountarg ma = { hostname, path, flags, fh };
  mntx->sendfd (s);
  mountres *res = new mountres;
  mntc->call (NFSMOUNTER_MOUNT, &ma, res, wrap (mnt_mountres, cb, res));
}

void
mnt_remount (str path, int flags, cbi cb)
{
  remountarg ua = { path, flags };
  int *res = new int;
  mntc->call (NFSMOUNTER_REMOUNT, &ua, res, wrap (mnt_res, cb, res));
}

void
mnt_umount (str path, int flags, cbi cb)
{
  umountarg ua = { path, flags };
  int *res = new int;
  mntc->call (NFSMOUNTER_UMOUNT, &ua, res, wrap (mnt_res, cb, res));
}

void
mnt_umountall (int flags, cbi cb)
{
  int *res = new int;
  mntc->call (NFSMOUNTER_UMOUNTALL, &flags, res, wrap (mnt_res, cb, res));
}

static void
init_ids ()
{
  setgroups (0, NULL);
  setgid (sfs_gid);

  /* On MacOS, at least, it appears that the first element of the
   * group list is the effective group ID, and if you void the group
   * list, the egid just becomes 0. */
  if (getegid () != sfs_gid) {
    GETGROUPS_T group_hack = sfs_gid;
    setgroups (1, &group_hack);
  }
}

void
mnt_init ()
{
  vec<str> avs;
  avs.push_back ("nfsmounter");
#ifdef __APPLE__
  avs.push_back ("-P");
#endif /* __APPLE__ */
  avs.push_back (sfsroot);
  mntx = axprt_unix_spawnv (fix_exec_path ("nfsmounter"), avs, 0,
			    wrap (init_ids));
  if (axprt_unix_spawn_connected) {
    warn << "file access by root will not initiate automounting\n";
    root_is_nfsmounter = true;
  }
  if (!mntx)
    fatal ("could not spawn nfsmounter\n");
  mntc = aclnt::alloc (mntx, nfsmounter_prog_1);
  mntc->seteofcb (wrap (mnt_dead));
}
