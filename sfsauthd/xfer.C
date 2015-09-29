/* $Id: xfer.C,v 1.4 2003/01/28 04:19:44 dm Exp $ */

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

#include "amisc.h"
#include "parseopt.h"

#ifndef S_BLKSIZE
#define S_BLKSIZE 512
#endif /* !S_BLKSIZE */

time_t timeout = 60;

const char *tmofile;
const char *tmppath;

static void
usage ()
{
  warnx << "usage: " << progname << " [-f] [-t timeout] src dst\n";
  exit (1);
}

static void
cleanup (int sig = 0)
{
  alarm (0);
  struct sigaction sa;
  bzero (&sa, sizeof (sa));
  sa.sa_handler = SIG_DFL;
  sigaction (SIGALRM, &sa, NULL);

  if (sig == SIGALRM) {
    if (tmofile)
      fprintf (stderr, "%s: %s: timeout\n", progname.cstr (), tmofile);
    else
      fprintf (stderr, "%s: timeout\n", progname.cstr ());
  }

  if (tmppath) {
    alarm (5);
    unlink (tmppath);
    alarm (0);
  }

  exit (1);
}

static bool
outofdate (const char *src, const char *dst)
{
  int r;
  struct stat ssb, dsb;

  alarm (timeout);
  tmofile = src;
  r = stat (src, &ssb);
  alarm (0);
  if (r < 0)
    fatal ("%s: %m\n", src);

  alarm (timeout);
  tmofile = dst;
  r = stat (dst, &dsb);
  alarm (0);
  if (r < 0 && errno == ENOENT)
    return true;
  else if (r < 0)
    fatal ("%s: %m\n", dst);
  tmofile = NULL;

  if (dsb.st_mtime != ssb.st_mtime
#ifdef SFS_HAVE_STAT_ST_MTIMESPEC
      || dsb.st_mtimespec.tv_nsec / 1000 != ssb.st_mtimespec.tv_nsec / 1000
#endif /* SFS_HAVE_STAT_ST_MTIMESPEC */
      || dsb.st_size != ssb.st_size
      || dsb.st_size > implicit_cast<off_t> (dsb.st_blocks) * S_BLKSIZE)
    return true;
  return false;
}

static void
docopy (const char *src, const char *dst)
{
  str tdst = strbuf ("%s#%d~", dst, int (getpid ()));
  tmppath = tdst.cstr ();

  tmofile = src;
  alarm (timeout);
  int sfd = open (src, O_RDONLY);
  struct stat sb;
  if (fstat (sfd, &sb) < 0) {
    close (sfd);
    sfd = -1;
  }
  alarm (0);
  if (sfd < 0)
    fatal ("%s: %m\n", src);

  tmofile = tmppath;
  alarm (timeout);
  unlink (tdst);
  int dfd = open (tdst, O_WRONLY|O_CREAT|O_TRUNC, 0444);
  alarm (0);
  if (dfd < 0)
    fatal ("%s: %m\n", tmppath);

  for (;;) {
    int n;
    char buf[65536];

    tmofile = src;
    alarm (timeout);
    n = read (sfd, buf, sizeof (buf));
    alarm (0);
    if (n == 0)
      break;
    else if (n < 0) {
      warn ("fatal: %s: %m\n", src);
      cleanup ();
    }

    tmofile = tdst;
    alarm (timeout);
    int nw = write (dfd, buf, n);
    alarm (0);
    if (nw != n) {
      warn ("fatal: %s: %m\n", tmppath);
      cleanup ();
    }
  }

  close (sfd);

  int r;

  tmofile = tdst;
  alarm (timeout);
  r = fsync (dfd);
  if (r >= 0)
    r = close (dfd);
  if (r >= 0) {
    struct timeval tvs[2];
    tvs[0].tv_sec = sb.st_atime;
    tvs[1].tv_sec = sb.st_mtime;
#ifdef SFS_HAVE_STAT_ST_MTIMESPEC
    tvs[0].tv_usec = sb.st_atimespec.tv_nsec / 1000;
    tvs[1].tv_usec = sb.st_mtimespec.tv_nsec / 1000;
#else /* !SFS_HAVE_STAT_ST_MTIMESPEC */
    tvs[0].tv_usec = tvs[1].tv_usec = 0;
#endif /* !SFS_HAVE_STAT_ST_MTIMESPEC */
    r = utimes (tmppath, tvs);
  }
  alarm (0);
  if (r < 0) {
    warn ("fatal: %s: %m\n", tmppath);
    cleanup ();
  }

  tmofile = dst;
  alarm (timeout);
  r = rename (tmppath, dst);
  alarm (0);
  if (r < 0) {
    warn ("fatal: %s: %m\n", tmppath);
    cleanup ();
  }
  tmofile = tmppath = NULL;
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);

  bool opt_force = false;
  int ch;
  while ((ch = getopt (argc, argv, "ft:")) != -1)
    switch (ch) {
    case 'f':
      opt_force = true;
      break;
    case 't':
      if (!convertint (optarg, &timeout))
	usage ();
      break;
    default:
      usage ();
      break;
    }
  argc -= optind;
  argv += optind;
  if (argc != 2)
    usage ();

  struct sigaction sa;
  bzero (&sa, sizeof (sa));
  sa.sa_handler = cleanup;
#ifdef SA_RESETHAND
  sa.sa_flags = SA_NODEFER | SA_RESETHAND;
#endif /* SA_RESETHAND */
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  sigaction (SIGALRM, &sa, NULL);

  if (!opt_force && !outofdate (argv[0], argv[1]))
    exit (0);

  docopy (argv[0], argv[1]);
  warn ("copied %s -> %s\n", argv[0], argv[1]);
  return 0;
}
