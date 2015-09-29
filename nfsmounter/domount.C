/* $Id: domount.C,v 1.46 2004/06/03 06:35:34 dm Exp $ */

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

#define NMOPT_ONLY 1

#ifdef __osf__
#define _SOCKADDR_LEN
#endif /* __osf__ */

#include "xdrmisc.h"
#include "nfsconf.h"
#include "async.h"
#ifdef USE_UVFS
#include "uvfs.h"
#endif /* USE_UVFS */
#include "nfsmnt.h"

#ifdef NO_NOSUID
# error Cannot disable setuid on NFS file systems -- massive security hole
#endif /* NO_NOSUID */

#if 0				// NOSUID implies NODEVS at least on solaris
#ifdef NO_NODEVS
# error Cannot disable devices on NFS file systems -- massive security hole
#endif /* NO_NODEVS */
#endif

extern "C" void _exit (int) __attribute__ ((noreturn));

extern bool opt_no_force_unmount;
extern bool nomounting;

struct cptr {
  void *const p;
  cptr (const void *pp) : p (const_cast<void *> (pp)) {}
  operator void *() { return p; }
  operator char *() { return (char *) p; }
  operator u_char *() { return (u_char *) p; }
};

struct sptr {
  void *const p;
  sptr (const void *pp) : p (const_cast<void *> (pp)) {}
  operator void *() { return p; }
  operator sockaddr *() { return (sockaddr *) p; }
  operator sockaddr_in *() { return (sockaddr_in *) p; }
};

static void
set_nfs_args (nfs_args *na, const sockaddr_in *sinp,
	      const nfsmnt_handle *fh, int flags, str hostname)
{
  int nfsflags = 0;

  bzero (na, sizeof (*na));
#ifdef NFS_ARGSVERSION
  na->version = NFS_ARGSVERSION;
#endif /* NFS_ARGSVERSION */
#ifndef HAVE_NFSARG_ADDR_PTR
  na->addr = *sinp;
#elif !defined (HAVE_NFSARG_ADDR_NETBUF)
  /* OSF/1 has some weird sa_len related problems... */
  static sockaddr_in sin;
  bzero (&sin, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = sinp->sin_port;
  sin.sin_addr = sinp->sin_addr;
  na->addr = sptr (&sin);
  //na->addr = sptr (sinp);
#else /* HAVE_NFSARG_ADDR_PTR && HAVE_NFSARG_ADDR_NETBUF */
  static netbuf nb;
  nb.len = nb.maxlen = sizeof (*sinp);
  nb.buf = cptr (sinp);
  na->addr = &nb;
#endif /* HAVE_NFSARG_ADDR_PTR && HAVE_NFSARG_ADDR_NETBUF */
#ifdef NFSMNT_KNCONF
  static knetconfig knc;
  bzero (&knc, sizeof (knc));
  knc.knc_semantics = NC_TPI_CLTS;
  knc.knc_protofmly = NC_INET;
  knc.knc_proto = NC_UDP;
  {
    struct stat sb;
    if (stat ("/dev/udp", &sb) < 0) {
      warn ("/dev/udp: %m\n");
      err_flush ();
      _exit (errno);
    }
    knc.knc_rdev = sb.st_rdev;
  }

  na->knconf = &knc;
  nfsflags |= NFSMNT_KNCONF;
#endif /* NFSMNT_KNCONF */
#ifdef HAVE_NFSMNT_ADDRLEN
  na->addrlen = sizeof (*sinp);
#endif /* HAVE_NFSMNT_ADDRLEN */
#ifdef HAVE_NFSMNT_SOTYPE
  na->sotype = (flags & NMOPT_TCP) ? SOCK_STREAM : SOCK_DGRAM;
#endif /* HAVE_NFSMNT_SOTYPE */
#ifdef HAVE_NFSMNT_PROTO
  na->proto = (flags & NMOPT_TCP) ? IPPROTO_TCP : IPPROTO_UDP;
#endif /* HAVE_NFSMNT_PROTO */

#ifdef HAVE_NFSMNT_FH
#ifdef HAVE_NFSMNT_FHSIZE
  na->fh = cptr (fh->base ());
  na->fhsize = fh->size ();
#else /* !HAVE_NFSMNT_FHSIZE */
#ifdef HAVE_SVR4_FH3
  static nfs_fh3 fh3;
  if (flags & NMOPT_NFS3) {
    bzero (&fh3, sizeof (fh3));
    fh3.fh3_length = fh->size ();
    memcpy (fh3.fh3_u.data, fh->base (), fh->size ());
    na->fh = cptr (&fh3);
  }
  else
#endif /* HAVE_SVR4_FH3 */
    na->fh = cptr (fh->base ());
#endif /* !HAVE_NFSMNT_FHSIZE */

#elif HAVE_NFSMNT_ROOT

#ifdef HAVE_NFSMNT_OLD_ROOT
  /* This is basically just for linux. */
  /* We'd ideally like be timeo = 10 and retrans = 5.  Unfortunately,
   * 3 seems to be the only value of retrans the kernel accepts. */
  na->timeo = 80;
  na->retrans = 3;
  if (!(flags & NMOPT_NOAC)) {
    na->acregmin = 3;
    na->acregmax = 60;
    na->acdirmin = 30;
    na->acdirmax = 60;
  }
  na->root.size = min (sizeof (na->root.data), fh->size ());
  memcpy (&na->root.data, fh->base (), na->root.size);
  if (!(flags & NMOPT_NFS3))
    memcpy (&na->old_root, fh->base (), 
	    min (sizeof (na->old_root), fh->size ()));
  else
    memset (&na->old_root, 0, sizeof (na->old_root));
#else /* !HAVE_NFSMNT_OLD_ROOT */
  memcpy (&na->root, fh->base (), min (sizeof (na->root), fh->size ()));
#endif /* !HAVE_NFSMNT_OLD_ROOT */
  
#else /* !HAVE_NFSMNT_FH && !HAVE_NFSMNT_ROOT */
#error No root file handle in nfs_args structure.
#endif /* !HAVE_NFSMNT_FH && !HAVE_NFSMNT_ROOT */

#ifdef HAVE_NFSMNT_FD
  if ((na->fd = inetsocket ((flags & NMOPT_TCP) ? SOCK_STREAM : SOCK_DGRAM,
			    0, INADDR_LOOPBACK)) < 0
      || connect (na->fd, (sockaddr *) sinp, sizeof (*sinp)) < 0)
    _exit (errno);
#endif /* HAVE_NFSMNT_FD */

#ifdef NFSMNT_SOFT
  if (flags & NMOPT_SOFT)
    nfsflags |= NFSMNT_SOFT;
#endif /* NFSMNT_SOFT */
#ifdef NFSMNT_HOSTNAME
  nfsflags |= NFSMNT_HOSTNAME;
#endif /* NFSMNT_HOSTNAME */
#ifdef NFSMNT_INT
  nfsflags |= NFSMNT_INT;
#endif /* NFSMNT_INT */
#ifdef NFSMNT_RESVPORT
  nfsflags |= NFSMNT_RESVPORT;
#endif /* NFSMNT_RESVPORT */
#ifdef NFSMNT_NODEVS
  nfsflags |= NFSMNT_NODEVS;
#endif /* NFSMNT_NODEVS */
  if (flags & NMOPT_NOAC) {
#ifdef NFSMNT_NOAC
    nfsflags |= NFSMNT_NOAC;
#else /* !NFSMNT_NOAC */
#ifdef NFSMNT_ACREGMIN
    nfsflags |= NFSMNT_ACREGMIN;
#endif /* NFSMNT_ACREGMIN */
#ifdef NFSMNT_ACREGMAX
    nfsflags |= NFSMNT_ACREGMAX;
#endif /* NFSMNT_ACREGMAX */
#ifdef NFSMNT_ACDIRMIN
    nfsflags |= NFSMNT_ACDIRMIN;
#endif /* NFSMNT_ACDIRMIN */
#ifdef NFSMNT_ACDIRMAX
    nfsflags |= NFSMNT_ACDIRMAX;
#endif /* NFSMNT_ACDIRMAX */
#endif /* !NFSMNT_NOAC */
  }
#ifdef NFSMNT_LLOCK
  nfsflags |= NFSMNT_LLOCK;
#endif /* NFSMNT_LLOCK */
#ifdef NFSMNT_DUMBTIMR
  nfsflags |= NFSMNT_DUMBTIMR;
#endif /* NFSMNT_DUMBTIMR */
#ifdef NFSMNT_TCP
  if (flags & NMOPT_TCP)
    nfsflags |= NFSMNT_TCP;
#endif /* NFSMNT_TCP */
#ifdef NFSMNT_NFSV3
  if (flags & NMOPT_NFS3)
    nfsflags |= NFSMNT_NFSV3;
#endif /* !NFSMNT_NFSV3 */
#ifdef NFSMNT_RDIRPLUS
  if (flags & NMOPT_RDPLUS)
    nfsflags |= NFSMNT_RDIRPLUS;
#endif /* NFSMNT_RDIRPLUS */
#ifdef NFSMNT_SENDCLOSE
  if (flags & NMOPT_SENDCLOSE)
    nfsflags |= NFSMNT_SENDCLOSE;
#endif
  na->flags = nfsflags;

#if HAVE_NFSARG_HOSTNAME_ARRAY
  strncpy (na->hostname, hostname, sizeof (na->hostname) - 1);
  na->hostname[sizeof (na->hostname) - 1] = '\0';
#else /* !HAVE_NFSARG_HOSTNAME_ARRAY */
  na->hostname = const_cast<char *> (hostname.cstr ());
#endif /* !HAVE_NFSARG_HOSTNAME_ARRAY */
}

static void
getalarm (int)
{
  alarm (5);
}

static void
setalarm (u_int t = 30)
{
  struct sigaction sa;
  bzero (&sa, sizeof (sa));
  sa.sa_handler = getalarm;
  sigaction (SIGALRM, &sa, NULL);
  alarm (t);
}

static void mountok (const char *path, int fd) __attribute__ ((noreturn));
static void
mountok (const char *path, int fd)
{
  if (fd < 0)
    _exit (0);
  struct stat sb;
  alarm (30);
  if (lstat (path, &sb) < 0) {
    warn ("cannot lstat %s\n", path);
    _exit (0);
  }
  alarm (0);
  write (fd, &sb.st_dev, sizeof (sb.st_dev));
  _exit (0);
}

static str
cdgetump (str path)
{
  if (path[0] != '/') {
    err_flush ();
    exit (EINVAL);
  }

  // XXX - bug in gcc 2.95.3 -O2 on Gentoo Linux
  const char *c = path.cstr ();
  int len = path.len ();
  //const char *mp = c + len - 1; // XXX - doesn't work
  const char *mp = &c[len - 1];    // XXX - works!

  while (mp > path.cstr () && *mp == '/')
    mp--;
  while (mp > path.cstr () && *mp != '/')
    mp--;

  str prefix = substr (path, 0, mp - path + 1);
  if ((errno = safechdir (prefix))) {
    warn ("safechdir (%s) failed\n", prefix.cstr ());
    err_flush ();
    _exit (errno);
  }
  return mp + 1;
}

static str
cdgetmp (str path)
{
#if MOUNT_DOT
  if ((errno = safechdir (path))) {
    err_flush ();
    _exit (errno);
  }
  return ".";
#else /* !MOUNT_DOT */
  str mp = cdgetump (path);
  /* open forces a lookup in modern-day NFS, thwarting a stale name
   * cache.  We don't even care if this open it succeeds.  The name
   * cache will be flushed anyway. */
  int fd = open (mp.cstr (), O_RDONLY);
  if (fd >= 0)
    close (fd);
  return mp;
#endif /* !MOUNT_DOT */
}

void
domount (str path, const sockaddr_in *sinp, const nfsmnt_handle *fh,
	 int fl, str hostname, int fd, bool trustpath)
{
#ifdef MAINTAINER
  if (nomounting) {
    warn ("NOMOUNTING: skipping mount of %s on %s\n",
	  hostname.cstr (), path.cstr ());
    warn ("NOMOUNTING:");
    for (size_t i = 0; i < fh->size (); i++)
      warnx (" %02x", u_char (fh->at(i)));
    warnx ("\n");
    err_flush ();
    _exit (0);
  };
#endif /* MAINTAINER */

  int mfl = MNT_NOSUID | MNT_NODEV;
  if (fl & NMOPT_RO)
    mfl |= MNT_RDONLY;
  if (fl & NMOPT_UPDATE)
    mfl |= MNT_UPDATE;
#ifdef MNT_UNKNOWNPERMISSIONS
  mfl |= MNT_UNKNOWNPERMISSIONS;
#endif /* MNT_UNKNOWNPERMISSIONS */

  nfs_args na;
  if (!(fl & NMOPT_NFS3) && fh->size () != 32)
    _exit (EINVAL);
  set_nfs_args (&na, sinp, fh, fl, hostname);

  setalarm ();

  str mp = trustpath ? path : cdgetmp (path);

  errno = -1;

  if (fl & NMOPT_NFS3) {
    if (SYS_NFS_MOUNT (MOUNT_NFS3, const_cast<char *> (mp.cstr ()),
		       mfl, &na) < 0)
      _exit (errno);
  }
  else if (SYS_NFS_MOUNT (MOUNT_NFS, const_cast<char *> (mp.cstr ()),
			  mfl, &na) < 0)
    _exit (errno);
  mountok (path, fd);
}

#ifdef USE_UVFS
void
domount_uvfs (str path, u_int dev, const nfsmnt_handle *fh, int fl, int fd)
{
  uvfs_args ua;

  if (fh->size () != sizeof (ua.uvfs_root_fh)) {
    warn ("Bad uvfs handle is %d bytes (should be %d)\n",
	  fh->size (), sizeof (ua.uvfs_root_fh));
    err_flush ();
    _exit (EINVAL);
  }

  bzero (&ua, sizeof (ua));
  ua.uvfs_dev = dev;
  memcpy (&ua.uvfs_root_fh, fh->base (), sizeof &ua.uvfs_root_fh);

#ifdef MAINTAINER
  if (nomounting) {
    warn ("NOMOUNTING: skipping mount of uvfs #%d on %s\n",
	  ua.uvfs_root_fh, path.cstr ());
    err_flush ();
    _exit (0);
  };
#endif /* MAINTAINER */

  int mfl = MNT_NOSUID | MNT_NODEV;
  if (fl & NMOPT_RO)
    mfl |= MNT_RDONLY;
  if (fl & NMOPT_UPDATE)
    mfl |= MNT_UPDATE;

  setalarm ();

  str mp = cdgetmp (path); 

  if (SYS_MOUNT ("uvfs", MOUNT_UVFS, const_cast<char *> (mp.cstr ()),
		 mfl, &ua) < 0)
    _exit (errno);
  mountok (path, fd);
}
#endif /* USE_UVFS */

#ifdef HAVE_DEV_XFS
str
xfsdev (int fd)
{
  static int initialized;
  static int xfsmajor;

  if (!initialized) {
    struct stat sb;
    if (stat ("/dev/xfs0", &sb) < 0)
      initialized = -1;
    else {
      initialized = 1;
      xfsmajor = major (sb.st_rdev);
    }
  }
  if (initialized <= 0)
    return NULL;

  struct stat fdsb;
  if (fstat (fd, &fdsb) < 0 || !S_ISCHR (fdsb.st_mode)
      || major (fdsb.st_rdev) != xfsmajor)
    return NULL;

  str devpath (strbuf ("/dev/xfs%d", minor (fdsb.st_rdev)));
  struct stat devsb;
  if (stat (devpath, &devsb) < 0) {
    warn ("%s: %m\n", devpath.cstr ());
    return NULL;
  }
  if (!S_ISCHR (devsb.st_mode)) {
    warn ("%s: not a character device\n", devpath.cstr ());
    return NULL;
  }
  /* Argh... Linux fucks over non-gcc compilers with non-primitive
   * dev_t. */
  if (memcmp (&devsb.st_rdev, &fdsb.st_rdev, sizeof (devsb.st_rdev))) {
    warn ("%s: expected minor device number %d\n", devpath.cstr (),
	  minor (devsb.st_rdev));
    return NULL;
  }
  return devpath;
}

void
domount_xfs (str path, str dev, int fl, int fd)
{
#ifdef MAINTAINER
  if (nomounting) {
    warn ("NOMOUNTING: skipping mount of %s on %s\n",
	  dev.cstr (), path.cstr ());
    err_flush ();
    _exit (0);
  };
#endif /* MAINTAINER */

  int mfl = MNT_NOSUID | MNT_NODEV;
  if (fl & NMOPT_RO)
    mfl |= MNT_RDONLY;
  if (fl & NMOPT_UPDATE)
    mfl |= MNT_UPDATE;

  setalarm ();

  str mp = cdgetmp (path); 

  if (SYS_MOUNT ("xfs", MOUNT_XFS, const_cast<char *> (mp.cstr ()),
		 mfl, const_cast<char *> (dev.cstr ())) < 0)
    _exit (errno);
  mountok (path, fd);
}
#endif /* HAVE_DEV_XFS */

void
doumount (str path, int flags)
{
#ifdef MAINTAINER
  if (nomounting) {
    warn ("NOMOUNTING: skipping unmount of %s\n", path.cstr ());
    err_flush ();
    _exit (0);
  }
#endif /* MAINTAINER */

  int mfl = 0;
  if ((flags & NUOPT_FORCE) && !opt_no_force_unmount)
    mfl = MNT_FORCE;

  setalarm ();

  str mp = cdgetump (path);

  errno = -1;
  if (SYS_UNMOUNT (const_cast<char *> (mp.cstr ()), mfl) < 0)
    _exit (errno);
  _exit (0);
}
