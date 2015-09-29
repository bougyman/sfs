// -*-c++-*-
/* $Id: sfscd.h,v 1.69 2003/12/15 04:54:26 dm Exp $ */

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

#include "arpc.h"
#include "afsnode.h"
#include "nfsmounter.h"
#include "sfscd_prot.h"
#include "sfsmisc.h"
#include "crypt.h"
#include "rabin.h"
#include "qhash.h"
#include "afsroot.h"
#include "rxx.h"
#include "sfsconnect.h"

#ifndef FIX_MNTPOINT
#if defined (__linux__)
/* The linux mount system call hangs file systems off name cache
 * entries rather than inodes.  If a mount point is ever evicted from
 * the name cache, game over.  You can never reach the file system
 * again.  Thus, we need to fix mount points in every user's view of
 * the /sfs directory (yuck). */
#define FIX_MNTPOINT 1
#endif /* __linux__ */
#endif /* FIX_MNTPOINT */

#if FIX_MNTPOINT
#define MPDOT ".linuxmnt/"
extern bool opt_fix_mntpoint;
extern ptr<afsdir> afs_linuxbug;
#endif /* FIX_MNTPOINT */

extern int v3flag;
extern bool terminating;
extern bool nomounting;
extern u_int64_t root_dev;

extern ptr<afsroot> afs_root;	// Files everyone sees in root directory
extern ptr<afsusrdir> afs_sfsroot; // Files seen by root during mount syscalls
extern ptr<afsdir> afs_naroot;	// Files seen by users with no agents

extern ptr<afsdir> afs_wait;	// Places people get "stuck" in readlink...
extern ptr<afsdir> afs_mnt;	// ...to avoid locking the root directory

extern int afsfd;

const time_t agent_timeout = 60;

void afs_init (cbv);

inline nfsmnt_handle
nfs_fh2tobytes (const nfs_fh &fh)
{
  nfsmnt_handle res;
  res = fh.data;
  return res;
}

extern bool root_is_nfsmounter;
void mnt_init ();
void mnt_mount (int s, str hostname, str path,
		int flags, const nfsmnt_handle &fh,
		callback<void, int, u_int64_t>::ref cb);
void mnt_remount (str path, int flags, cbi cb);
void mnt_umount (str path, int flags, cbi cb);
void mnt_umountall (int flags, cbi cb);

struct usrinfo : public virtual refcount {
  const sfs_aid aid;

  ref<afsusrdir> root;
  ihash_entry<usrinfo> hlink;
  ptr<axprt_unix> x;
  ptr<asrv> sh;
  ptr<aclnt> ch;
  bool clonelock;

  usrinfo (sfs_aid);
  ~usrinfo ();
  void dispatch (svccb *sbp);
  void authreq (sfscd_authreq *ar, svccb *sbp);
  void clonelock_clear () { clonelock = false; }
};
extern qhash<sfs_aid, ref<usrinfo> > &usrtab;

struct cdaemon;
struct afslink;

class srvinfo {
  typedef callback<void, int>::ref alloccb_t;

  timecb_t *tmo;
  vec<alloccb_t> waitq;
  sfs_connectarg conarg;
  sfs_connectres conres;
  sfscd_mountres mntres;
  bool waiting;
  bool destroyed;
  bool cdmounted;
  ptr<srvlist> srvl;

  srvinfo (const str &pathname, bool namedprot = false);
  PRIVDEST ~srvinfo ();

  void timeout (bool start = true);
  void fail (int);
  void connected (int);
  void sendconnect (ref<aclnt>);
  void gotconres (ref<aclnt>, clnt_stat);
  void gotmntres (clnt_stat);
  void gotnfsmntres (int, u_int64_t);
  void ready ();
  void unmountcb (cbi::ptr, int);
  static void printdev (strbuf *sb, bool donfsinfo, srvinfo *si);

public:
  bool visible_flag;
  u_int64_t devno;
  int error;

  str path;
  str oldpath;
  str nfsinfo;
  cdaemon *cdp;
  int vers;   /* sfs_hostinfo or sfs_hostinfo2 */
  str dnsname;
  u_int16_t port;

  ihash_entry<srvinfo> hlink;
  ihash_entry<srvinfo> ohlink;
  list_entry<srvinfo> cdlink;

  void unmount (int flags, cbi::ptr cb = NULL);
  void destroy (bool stale);
  static srvinfo *lookup (const str &path);
  static void alloc (const str &path, alloccb_t cb);
  static void idle (const str &path, cdaemon *cdp);
  static void destroy (const str &path, cdaemon *cdp, bool stale);
  static void show (const str &path, cdaemon *cdp, bool showit);
  static void revoke (const str &path);
  static int geterr (const str &path);
  static str devlist ();
  static str nfslist ();
};

class revocation : public afslink {
protected:
  revocation (sfs_pathrevoke_w *w);
  ~revocation ();
  void update (sfs_pathrevoke_w *w);

public:
  sfs_pathrevoke_w *prw;
  sfs_hash hostid;
  ihash_entry<revocation> hlink;

  void nop () {}
  static ptr<revocation> alloc (const sfs_pathrevoke &c);
  static ptr<revocation> lookup (const str &path);
};

class cdaemon {
  void eof ();
  void dispatch (svccb *sbp);

public:
  str name;
  vec<str> argv;
  ptr<axprt_unix> x;
  ptr<aclnt> c;
  ptr<asrv> s;
  list<srvinfo, &srvinfo::cdlink> servers;
  ihash_entry<cdaemon> hlink;

  cdaemon (const vec<str> &argv);
  ~cdaemon ();

  bool launch (bool synchronous);
};
extern ihash<vec<str>, cdaemon, &cdaemon::argv, &cdaemon::hlink> &daemontab;
extern vec<sfs_extension> sfs_extensions;
extern bhash<in_addr> badaddrs;

class release {
  PRIVDEST ~release ();

public:
  struct prot {
    const u_int32_t prog;
    const u_int32_t vers;
    cdaemon *const cdp;
    ihash_entry<prot> link;
    prot (u_int32_t p, u_int32_t v, cdaemon *c)
      : prog (p), vers (v), cdp (c) {}
  };

  const u_int32_t rel;
  str libdir;
  ihash2<const u_int32_t, const u_int32_t, prot,
    &prot::prog, &prot::vers, &prot::link> prots;
  itree_entry<release> link;

  release (u_int32_t rel);
  static release *lookup (u_int32_t rel);
  static cdaemon *cdlookup (u_int32_t rel, u_int32_t prog, u_int32_t vers);
};

extern rxx namedprotrx;
struct named_protocol {
  const str name;
  cdaemon *const cdp;
  ihash_entry<named_protocol> link;
  named_protocol (const str &n, cdaemon *c) : name (n), cdp (c) {}
};
extern ihash<const str, named_protocol,
  &named_protocol::name, &named_protocol::link> &nptab;

void update_devdb ();

sfs_aid sbp2aid (const svccb *sbp);
void usrinfo_init ();
void flushpath (str path);
bool cd_parsepath (str path, str *host = NULL, sfs_hash *hostid = NULL,
		   u_int16_t *port = NULL);


inline bool
isnfsmounter (const svccb *sbp)
{
  return sbp2aid (sbp) == sfsaid_sfs;
}
