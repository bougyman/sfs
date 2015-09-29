/* $Id: pty.C,v 1.7 2002/07/31 21:42:16 dm Exp $ */

/*

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

/*
 * This code derived from ossh-1.2.16, Copyright (c) 1995 Tatu Ylonen.
 * It is additionally covered by the following licence:
 *
 *    As far as I am concerned, the code I have written for this
 *    software can be used freely for any purpose.  Any derived
 *    versions of this software must be clearly marked as such, and if
 *    the derived work is incompatible with the protocol description
 *    in the RFC file, it must be called by a name other than "ssh" or
 *    "Secure Shell".
 *
 * The code is not compatible with ssh, and doesn't really implement
 * any protocol.  It's just the standard way of opening pty's on
 * various operating systems.
 */


#include "ptyd.h"

/* Pty allocated with _getpty gets broken if we do I_PUSH:es to it. */
#if defined (HAVE__GETPTY) || defined (HAVE_OPENPTY)
#undef HAVE_DEV_PTMX
#endif

#ifdef HAVE_DEV_PTMX
#define strbuf hide_native_strbuf
#include <sys/stream.h>
#include <stropts.h>
#include <sys/conf.h>
#undef strbuf
#endif /* HAVE_DEV_PTMX */

#ifdef HAVE_UTIL_H
#include <util.h>
#elif defined (HAVE_LIBUTIL_H)
#include <libutil.h>
#elif defined (HAVE_PTY_H)
#include <pty.h>
#endif /* !HAVE_UTIL_H && !HAVE_LIBUTIL_H && HAVE_PTY_H */


#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

/* Allocates and opens a pty.  Returns 0 if no pty could be allocated,
   or nonzero if a pty was successfully allocated.  On success, open file
   descriptors for the pty and tty sides and the name of the tty side are 
   returned (the buffer must be able to hold at least 64 characters). */

bool
pty_alloc (int *fdp, str *ttyp)
{
#ifdef HAVE_OPENPTY
  char path[65];
  int sfd;
  if (openpty (fdp, &sfd, path, NULL, NULL) < 0)
    return false;
  close (sfd);
  *ttyp = path;
  return true;

#else /* !HAVE_OPENPTY */
#ifdef HAVE__GETPTY
  /* _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
   * pty's automagically when needed */
  return *ttyp = _getpty (fdp, O_RDWR, 0622, 0);

#else /* !HAVE__GETPTY */
#ifdef HAVE_DEV_PTMX
  /* This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3 also has
     bsd-style ptys, but they simply do not work.) */
  if ((*fdp = open ("/dev/ptmx", O_RDWR | O_NOCTTY)) < 0)
    return false;
  if (grantpt (*fdp) < 0 || unlockpt (*fdp) < 0
      || !(*ttyp = ptsname (*fdp))) {
    close (*fdp);
    return false;
  }

  /* Push the appropriate streams modules, as described in Solaris pts(7). */
  int ttyfd = open (ttyp->cstr (), O_RDWR | O_NOCTTY);
  if (ttyfd < 0) {
    close (*fdp);
    return false;
  }
  if (ioctl (ttyfd, I_PUSH, "ptem") < 0
      || ioctl (ttyfd, I_PUSH, "ldterm") < 0
      || ioctl (ttyfd, I_PUSH, "ttcompat") < 0) {
    close (*fdp);
    close (ttyfd);
    return false;
  }
  close (ttyfd);
  return true;

#else /* !HAVE_DEV_PTMX */
#ifdef HAVE_DEV_PTS_AND_PTC
  /* AIX-style pty code. */
  if (*fdp = open ("/dev/ptc", O_RDWR | O_NOCTTY) < 0)
    return false;
  if (!(*ttyp = ttyname (*fdp))) {
    close (*fdp);
    return false;
  }
  return true;

#else /* !HAVE_DEV_PTS_AND_PTC */
#ifdef CRAY
  for (int i = 0; i < 128; i++) {
    char buf[64];
    sprintf (buf, "/dev/pty/%03d", i);
    *ftp = open (buf, O_RDWR | O_NOCTTY);
    if (*ftp < 0)
      continue;
    sprintf (buf, "/dev/ttyp%03d", i);
    *ttyp = buf;
    return true;
  }
  return false;

#else /* !CRAY */
  /* BSD-style pty code. */
  const char c1[] = "pqrstuvwxyzabcdefghijklmnoABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const char c2[] = "0123456789abcdef";
  char ptypath[] = "/dev/ptyp0";
  for (size_t i1 = 0; i1 < sizeof (c1) - 1; i1++)
    for (size_t i2 = 0; i2 < sizeof (c2) - 1; i2++) {
      ptypath[sizeof (ptypath) - 3] = c1[i1];
      ptypath[sizeof (ptypath) - 2] = c2[i2];
      if ((*fdp = open (buf, O_RDWR | O_NOCTTY)) < 0)
	continue;
      *ttyp = strbuf ("/dev/tty%c%c", c1[i1], c2[i2]);
      return true;
    }
  return false;

#endif /* !CRAY */
#endif /* !HAVE_DEV_PTS_AND_PTC */
#endif /* !HAVE_DEV_PTMX */
#endif /* !HAVE__GETPTY */
#endif /* !HAVE_OPENPTY */
}
