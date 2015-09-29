/* $Id: afs.C,v 1.40 2004/05/22 17:12:57 dm Exp $ */

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

bool terminating;
u_int64_t root_dev;

ptr<afsroot> afs_root;		// Files everybody sees in /sfs
ptr<afsusrdir> afs_sfsroot;	// Files in /sfs that users must access to see
ptr<afsdir> afs_naroot;		// Root directory for users not running agents

ptr<afsdir> afs_mnt;
ptr<afsdir> afs_wait;
#if FIX_MNTPOINT
ptr<afsdir> afs_linuxbug;
#endif /* FIX_MNTPOINT */


int afsfd;
ptr<asrv> afssrv;
ptr<asrv> afssrv3;

class idlink : public afslink {
  u_int32_t fhctr;
public:
  idlink () : fhctr (0) {}

  void mkfh (nfs_fh *fhp) {
    afsnode::mkfh (fhp);
    ((u_int32_t *) fhp)[2] = ++fhctr;
  }
  bool chkfh (const nfs_fh *) { return true; }

  void nfs_readlink (svccb *sbp) {
    if (const authunix_parms *aup = sbp->getaup ())
      setres (strbuf ("%d", int (aup->aup_uid)));
    else
      setres (NFSERR_ACCES);
    sendreply (sbp);
  }
};

static void
afs_dispatch (svccb *sbp)
{
  if (sbp->vers () == 3)
    afsnode::dispatch3 (sbp);
  else
    afsnode::dispatch (sbp);
}

void afs_shutdown (bool);
void
afs_shutdown_cb (int stat = 0)
{
  if (!stat)
    exit (0);
  warn ("unmountall: %s\n", strerror (stat));
  timecb (time (NULL) + 5, wrap (afs_shutdown, false));
}
void
afs_shutdown (bool start)
{
  static int started;
  terminating = true;
  if (start) {
    if (started)
      return;
    started = 1;
    warn << "received signal, shutting down\n";
  }
  mnt_umountall (NUOPT_FORCE, wrap (afs_shutdown_cb));
}

static void
exit1 (int)
{
  exit (1);
}
static void afs_init2 (cbv, int, u_int64_t);
static void afs_init3 (cbv, int, u_int64_t);
void
afs_init (cbv cb)
{
  tzset ();
  sfs_hosttab_init ();

  afsnode::sbp2aid = sbp2aid;

  afs_root = afsroot::alloc ();
  afs_root.Xleak ();		// Avoid global destruction order worries
  afs_sfsroot = afsusrdir::alloc (afs_root, sfsaid_sfs);
  afs_sfsroot.Xleak ();
  afs_naroot = afsusrroot::alloc (afs_root, sfsaid_nobody);
  afs_naroot.Xleak ();

  afs_mnt = afs_root->mkdir (".mnt");
  afs_wait = afsdir::alloc ();
  afs_wait.Xleak ();

  afs_mnt->mkdir ("wait");
  afs_sfsroot->link (afsreg::alloc (), ".root");
  afs_root->link (afsreg::alloc (VERSION "\n"), ".version");
  afs_root->link (afsreg::alloc (strbuf ("%d\n", int (getpid ()))), ".pid");
#if FIX_MNTPOINT
  if (opt_fix_mntpoint)
    afs_linuxbug = afs_root->mkdir (".linuxmnt");
#endif /* FIX_MNTPOINT */

  afsfd = inetsocket (SOCK_DGRAM, nomounting ? 2490 : 0, INADDR_LOOPBACK);
  if (afsfd < 0)
    fatal ("afs_init: inetsocket: %m\n");
  ref<axprt> x (axprt_dgram::alloc (afsfd));
  afssrv = asrv::alloc (x, nfs_program_2, wrap (afs_dispatch));
  afssrv3 = asrv::alloc (x, nfs_program_3, wrap (afs_dispatch));

  sigcb (SIGINT, wrap (afs_shutdown, true));
  sigcb (SIGTERM, wrap (afs_shutdown, true));

  nfs_fh fh;
  afs_root->mkfh (&fh);
  mnt_mount (dup (afsfd), "(sfs)", sfsroot,
	     v3flag | NMOPT_NOAC | NMOPT_SOFT,
	     nfs_fh2tobytes (fh), wrap (afs_init2, cb));
}
static void
afs_init2 (cbv cb, int stat, u_int64_t dev)
{
  if (stat)
    fatal ("mount (%s): %s\n", sfsroot, strerror (stat));
  root_dev = dev;
  update_devdb ();

  nfs_fh fh;
  afs_wait->mkfh (&fh);
  mnt_mount (dup (afsfd), "(sfswait)", strbuf ("%s/.mnt/wait", sfsroot),
	     v3flag | NMOPT_NOAC | NMOPT_RO | NMOPT_SOFT,
	     nfs_fh2tobytes (fh), wrap (afs_init3, cb));
}
static void
afs_init3 (cbv cb, int stat, u_int64_t)
{
  if (stat) {
    warn << "fatal: mount (" << sfsroot << "/.mnt/wait" << "): "
	 << strerror (stat) << "\n";
    mnt_umountall (NUOPT_FORCE, wrap (exit1));
  }
  (*cb) ();
}
