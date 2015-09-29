/* $Id: nfsmounter.C,v 1.36 2004/09/19 22:02:23 dm Exp $ */

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

bool opt_no_force_unmount;
bool opt_mount_full_path;
bool nomounting;
AUTH *myauthunix = authunix_create_default ();

mpfsnode *mpfs_root = New mpfsnode ("/");

static ptr<axprt_unix> nmx;
static ptr<asrv> nms;
static bool umountall;

bool
checkpath (str path)
{
  int len = path.len ();
  if (!len || path[0] != '/'
      || strstr (path, "/./")
      || strstr (path, "/../")
      || strstr (path, "//")
      || path[len - 1] == '/'
      || (len >= 2 && !strcmp (path + len - 2, "/."))
      || (len >= 3 && !strcmp (path + len - 3, "/..")))
    return false;
  return true;
}

static time_t fail_time;
static u_int32_t fail_log_thresh;
static u_int32_t fail_count;
static void fail ();
static void
end (bool logit, int stat)
{
  bool doexit = !stat
    || (stat != EBUSY && stat != EAGAIN && timenow >= fail_time + 60);
  if (stat && (logit || doexit))
    warn ("can't unmount some file systems (%s)\n", strerror (stat));
  if (doexit) {
    warn ("exiting\n");
    exit (0);
  }
  delaycb (5, wrap (fail));
}

static void
fail ()
{
  if (nms) {
    nmx = NULL;
    nms = NULL;
    nfsfd::traverse (wrap (makestaleserv));
  }
  if (!fail_time)
    fail_time = timenow;
  if (fail_count++ >= fail_log_thresh) {
    if (fail_log_thresh < 128)
      fail_log_thresh = 2 * fail_count;
    fail_count = 0;
    mpfs_root->unmountall (NUOPT_FORCE, wrap (end, true));
  }
  else
    mpfs_root->unmountall (NUOPT_FORCE|NUOPT_NLOG, wrap (end, false));

}

static void
sigterm (int sig)
{
  warn << "received signal " << sig << ", unmounting all file systems\n";
  fail ();
}

inline void
reply (svccb *sbp, int32_t val)
{
  sbp->reply (&val);
}

static void
proc_mount_3 (svccb *sbp, int closefd, int err, dev_t dev)
{
  mountres res (err);
  if (!err) {
#ifdef __linux__
    /* Because linux has a non-primitive dev_t.. */
    memcpy (res.fsid.addr (), &dev, 8);
#else /* !linux */
    *res.fsid = dev;
#endif /* !linux */
  }
  sbp->reply (&res);
  if (closefd >= 0)
    close (closefd);
}
static void
proc_mount_2n (svccb *sbp, ref<nfsfd> nf, mpfsnode *n, int err)
{
  mountarg *ma = sbp->Xtmpl getarg<mountarg> ();
  if (err) {
    warn << "mount " << ma->path << ": " << strerror (errno) << "\n";
    reply (sbp, err);
  }
  else
    n->mount (ma, nf, wrap (proc_mount_3, sbp, -1));
}
#ifdef USE_UVFS
static void
proc_mount_2u (svccb *sbp, ref<uvfsfd> u, mpfsnode *n, int err)
{
  mountarg *ma = sbp->template getarg<mountarg> ();
  if (err) {
    warn << "mount " << ma->path << ": " << strerror (errno) << "\n";
    reply (sbp, err);
  }
  else
    n->mount_uvfs (ma, u, wrap (proc_mount_3, sbp, -1));
}
#endif /* USE_UVFS */
#ifdef HAVE_DEV_XFS
static void
proc_mount_2x (svccb *sbp, int devfd, str devname, mpfsnode *n, int err)
{
  close (devfd);
  mountarg *ma = sbp->Xtmpl getarg<mountarg> ();
  if (err) {
    warn << "mount " << ma->path << ": " << strerror (errno) << "\n";
    reply (sbp, err);
    return;
  }
  else
    n->mount_xfs (ma, devname, wrap (proc_mount_3, sbp, -1));
}
#endif /* HAVE_DEV_XFS */
static void
proc_mount (svccb *sbp, mountarg *ma)
{
  int fd = nmx->recvfd ();
  if (fd < 0) {
    warn ("failed to receive file descriptor\n");
    reply (sbp, EBADF);
  }
  else if (!checkpath (ma->path)) {
    warn ("received bad path %s\n", ma->path.cstr ());
    reply (sbp, EINVAL);
  }
#ifdef USE_UVFS
  else if (ptr<uvfsfd> u = uvfsfd::lookup (fd))
    mpfs_root->mkdir (ma->path, wrap (proc_mount_2u, sbp, u));
#endif /* USE_UVFS */
#ifdef HAVE_DEV_XFS
  else if (str devname = xfsdev (fd))
    mpfs_root->mkdir (ma->path, wrap (proc_mount_2x, sbp, fd, devname));
#endif /* HAVE_DEV_XFS */
  else if (ptr<nfsfd> nf = nfsfd::lookup (fd))
    mpfs_root->mkdir (ma->path, wrap (proc_mount_2n, sbp, nf));
  else {
    warn ("received bad file descriptor\n");
    close (fd);
    reply (sbp, EBADF);
  }
}

static void
proc_remount (svccb *sbp, remountarg *ma)
{
  mpfsnode *n = mpfs_root->lookup (ma->path);
  if (n)
    n->remount (ma->flags, wrap (reply, sbp));
  else
    reply (sbp, ENOENT);
}

static void
proc_unmount (svccb *sbp, umountarg *ma)
{
  mpfsnode *n = mpfs_root->lookup (ma->path);
  if (n && n->getmp ()) {
    if (ma->flags & NUOPT_STALE && n->getmp ()->nf)
      makestaleserv (n->getmp ()->nf);
    if (umountall)
      reply (sbp, EBUSY);
    else if (ma->flags & NUOPT_NOOP)
      reply (sbp, 0);
    else
      n->unmount (ma->flags, wrap (reply, sbp));
  }
  else
    reply (sbp, ENOENT);
}

static void
proc_umountall_2 (svccb *sbp, int err)
{
  umountall = false;
  reply (sbp, err);
}

static void
proc_umountall (svccb *sbp, const int *flagsp)
{
  if (*flagsp & NUOPT_STALE)
    nfsfd::traverse (wrap (makestaleserv));
  if (umountall)
    reply (sbp, EBUSY);
  else {
    umountall = true;
    mpfs_root->unmountall (*flagsp, wrap (proc_umountall_2, sbp));
  }
}

static void
dispatch (svccb *sbp)
{
  if (!sbp) {
    warn ("received EOF, unmounting all file systems\n");
    fail ();
    return;
  }

  switch (sbp->proc ()) {
  case NFSMOUNTER_NULL:
    sbp->reply (NULL);
    break;
  case NFSMOUNTER_MOUNT:
    proc_mount (sbp, sbp->Xtmpl getarg<mountarg> ());
    break;
  case NFSMOUNTER_REMOUNT:
    proc_remount (sbp, sbp->Xtmpl getarg<remountarg> ());
    break;
  case NFSMOUNTER_UMOUNT:
    proc_unmount (sbp, sbp->Xtmpl getarg<umountarg> ());
    break;
  case NFSMOUNTER_UMOUNTALL:
    proc_umountall (sbp, sbp->Xtmpl getarg<int> ());
    break;
  }
}

static void
usage ()
{
  warnx ("usage: %s [-F] [-P] /prefix\n", progname.cstr ());
  exit (1);
}

static bool
ismntpoint (str path)
{
  str dd = path << "/..";
  struct stat sb1, sb2;
  return !stat (path, &sb1) && (stat (dd, &sb2) || sb1.st_dev != sb2.st_dev);
}

static str prefix;

int
main (int argc, char **argv)
{
  umask (0);

  setprogname (argv[0]);

  sfsconst_init ();
#ifdef MAINTAINER
  if (getenv ("SFS_NOMOUNTING"))
    nomounting = true;
#endif /* MAINTAINER */

  int ch;
  while ((ch = getopt (argc, argv, "FP")) != -1)
    switch (ch) {
    case 'F':
      opt_no_force_unmount = true;
      break;
    case 'P':
      opt_mount_full_path = true;
      break;
    case '?':
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;

  if (argc != 1 || argv[0][0] != '/')
    usage ();

  prefix = argv[0];
  if (ismntpoint (prefix))
    fatal << prefix << ": appears already to be a mount point\n";
  if (prefix[prefix.len () - 1] != '/')
    prefix = prefix << "/";
  if (!mpfs_root->mkdir_local (prefix))
    fatal << prefix << ": invalid prefix\n";

  if (setsid () < 0 && !runinplace)
    switch (fork ()) {
    case -1:
      fatal ("fork: %m\n");
    case 0:
      if (setsid () < 0)
	fatal ("setsid: %m\n");
      break;
    default:
      _exit (0);
    }

  warn ("version %s, pid %d\n", VERSION, int (getpid ()));

  sigcb (SIGINT, wrap (sigterm, SIGINT));
  sigcb (SIGTERM, wrap (sigterm, SIGTERM));

  if ((nmx = axprt_unix_stdin ())
      && (nms = asrv::alloc (nmx, nfsmounter_prog_1, wrap (dispatch))))
    amain ();
  exit (1);
}
