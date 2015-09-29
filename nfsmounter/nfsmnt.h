// -*-c++-*-
/* $Id: nfsmnt.h,v 1.28 2004/04/10 18:49:44 dm Exp $ */

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

#define basename __stupid_linux_non_ansi_string_h_basename

#include "nfsmounter.h"

#define NMOPT_VALID 0xffff	// Valid external flags
#define NMOPT_TCP 0x10000	// Internal flag: use TCP NFS when set
#define NMOPT_UPDATE 0x20000	// Internal flag: remount/update existing mount

#ifndef NMOPT_ONLY

#include "sfsmisc.h"
#include "arpc.h"
#include "qhash.h"

typedef callback<void, int, dev_t>::ref cbid;

extern bool opt_no_force_unmount;
extern bool nomounting;
extern AUTH *myauthunix;

class nfsfd;
class mntpt;

#ifdef USE_UVFS
struct uvfsfd {
  u_int devno;
  explicit uvfsfd (u_int d) : devno (d) {}
  static ptr<uvfsfd> lookup (int fd);
};
#endif /* USE_UVFS */

class stalesrv {
  struct srvelm {
    ptr<asrv> s;
    list_entry<srvelm> link;
  };

  nfsfd *const nf;
  list<srvelm, &srvelm::link> srvs;

  void tcpaccept ();
  void dispatch (srvelm *, svccb *);

public:
  explicit stalesrv (nfsfd *);
  ~stalesrv ();
};

struct mpfsdir;

class mpfsnode {
  typedef callback<void, mpfsnode *, int>::ref lcb_t;
  enum mpfsnode_type { LOCAL = 0, NFS2 = 2, NFS3 = 3,
		       UVFS = 16, XFS = 17 };
  friend class mpfsref;

  const str fullpath;
  const mpfsnode_type type;
  union {
    union_entry_base attrbase;
    union_entry<fattr> attr2;
    union_entry<fattr3> attr3;
  };
  mpfsnode *const parent;
  mpfsnode *mp;
  const str hostname;

  int refcnt;
  bool lock_flag;
  vec<cbv> waiters;

  void lookupres (str path, void *resp, lcb_t cb, clnt_stat);
  void getattrres (void *, cbid cb, mountarg *, clnt_stat);
  void attr3mkdir (getattr3res *, str, lcb_t, clnt_stat);
  void mountres (int fd, cbid cb, mountarg *a, int status);
  void remountres (cbi cb, int status);
  void unmountres (cbi cb, int flags, int status);

  void unmountallres1 (int flags, cbi, int status);
  void unmountallres2 (mpfsnode *, int ostatus, int flags, cbi, int status);

  void maybe_delete ();

  void incref () { refcnt++; }
  void decref () { if (!--refcnt) maybe_delete (); }

  void lock () { assert (!lock_flag); lock_flag = true; }
  void unlock ();
  bool locked () const { return lock_flag; }

protected:
  ~mpfsnode ();

public:
  const ptr<nfsfd> nf;
  mpfsdir *const dir;
  const nfsmnt_handle fh;
  const str fname;
  ihash_entry<mpfsnode> fh_link;
  ihash_entry<mpfsnode> dir_link;
  bool attrvalid;
  str devname;

#ifdef USE_UVFS
  u_int uvfs_devno;
  mpfsnode (str path, ptr<uvfsfd>, const nfsmnt_handle *hp, mpfsnode *mntdir);
  void mount_uvfs (mountarg *, ref<uvfsfd>, cbid);
#endif /* USE_UVFS */

#ifdef HAVE_DEV_XFS
  void mount_xfs (mountarg *, str devname, cbid);
#endif /* HAVE_DEV_XFS */

  mpfsnode (str path, mpfsnode_type t = LOCAL, mpfsnode *parent = NULL,
	    ptr<nfsfd> nf = NULL, const nfsmnt_handle *hp = NULL,
	    mpfsnode *mntdir = NULL, str hostname = NULL);

  void mount (mountarg *, ref<nfsfd>, cbid);
  void remount (int flags, cbi);
  void unmount (int flags, cbi);
  void unmountall (int flags, cbi);
  bool ismp () const { return parent && parent->mp == this; }

  mpfsnode *getmp () { return mp; }
  mpfsnode *lookup (str path);
  mpfsnode *mkdir_local (str path);
  void mkdir (str path, lcb_t cb);

  const fattr &getattr2 () { return *attr2; }
  const fattr3 &getattr3 () { return *attr3; }
};

// XXX - Stupid g++ (and egcs before 1.2) doesn't let you declare a
//  "ihash<const str, mpfsnode, &mpfsnode::dirname, &mpfsnode::hlink>"
// as a member of the mpfsnode structure.
struct mpfsdir {
  typedef ihash<const str, mpfsnode,
    &mpfsnode::fname, &mpfsnode::dir_link> dir_t;
  dir_t dir;

  mpfsnode *lookup (const str &n) { return dir[n]; }
  void insert (mpfsnode *n) { dir.insert (n); }
  void remove (mpfsnode *n) { dir.remove (n); }
};

typedef ihash<const nfsmnt_handle, mpfsnode,
  &mpfsnode::fh, &mpfsnode::fh_link> mpfsnode_tab;

class nfsfd : public virtual refcount {
protected:
  nfsfd (int fd, int type, const sockaddr_in *);
  virtual ~nfsfd ();

public:
  const int fd;
  const int sotype;
  const sockaddr_in sin;
  ihash_entry <nfsfd> hlink;
  stalesrv *server;
  mpfsnode_tab nfs2nodes;
  mpfsnode_tab nfs3nodes;

  ptr<aclnt> mkclnt (int nfsvers);

  static ptr<nfsfd> lookup (int);
  static void traverse (callback<void, nfsfd *>::ref);
};

void makestaleserv (nfsfd *nf);

#undef basename
const char *basename (const char *s);
str strip_double_slash (str s);

#endif /* !NMOPT_ONLY */

extern bool opt_mount_full_path;

void domount (str path, const sockaddr_in *sinp,
	      const nfsmnt_handle *fh, int fl,
	      str hostname, int fd, bool trustpath) __attribute__ ((noreturn));
#ifdef USE_UVFS
void domount_uvfs (str path, u_int dev, const nfsmnt_handle *fh,
		   int fl, int fd) __attribute__ ((noreturn));
#endif /* USE_UVFS */
#ifdef HAVE_DEV_XFS
str xfsdev (int fd);
void domount_xfs (str path, str dev, int fl, int fd)
  __attribute__ ((noreturn));
#endif /* HAVE_DEV_XFS */
void doumount (str path, int flags) __attribute__ ((noreturn));

int safechdir (str);
