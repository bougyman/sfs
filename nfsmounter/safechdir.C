/* $Id: safechdir.C,v 1.7 2001/01/13 19:46:11 dm Exp $ */

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
#include "qhash.h"

static bool
path2vec (vec<str> &out, str in)
{
  const char *p = in.cstr ();
  const char *e = p + in.len ();
  const char *n;

  if (*p != '/')
    return false;
  for (;;) {
    while (*p == '/')
      p++;
    for (n = p; n < e && *n != '/'; n++)
      ;
    if (n == p)
      return true;
    out.push_back (str (p, n - p));
    if (out.back () == "." || out.back () == "..")
      return false;
    p = n;
  }
}

static int
return_err (str pp, int curdir, int err = errno)
{
  int saved_errno = err;
  if (pp)
    warn << pp << ": " << strerror (saved_errno) << "\n";
  if (fchdir (curdir) < 0) {
    warn ("fchdir: %m\n");
    chdir ("/");
  }
  close (curdir);
  return saved_errno;
}

struct devino {
  const dev_t dev;
  const ino_t ino;
  devino (dev_t d, ino_t i) : dev (d), ino (i) {}
  operator hash_t () const
    { return ino ^ *reinterpret_cast<const u_int16_t *> (&dev); }
  bool operator== (const devino &di) const
    { return dev == di.dev && ino == di.ino; }
};

struct autofd {
  int fd;
  operator int &() { return fd; }
  autofd () { fd = -1; }
  explicit autofd (int f) : fd (f) {}
  ~autofd () { if (fd >= 0) close (fd); }
};

int
safechdir (str path)
{
  vec<str> dirs;
  if (!path2vec (dirs, path)) {
    warn << "safechdir: invalid path " << path << "\n";
    return EINVAL;
  }

  int curdir = open (".", O_RDONLY);
  if (curdir < 0) {
    warn ("open (\".\"): %m\n");
    return errno;
  }

  str pp = "";
  chdir ("/");
  bhash<devino> dicache;
  {
    struct stat sb;
    if (stat (".", &sb) < 0)
      return return_err ("/", curdir);
    dicache.insert (devino (sb.st_dev, sb.st_ino));
  }

  while (!dirs.empty ()) {
    str dir = dirs.pop_front ();
    pp = pp << "/" << dir;

    /* We open and fchdir because open never uses the attribute cache.
     * The problem is that on some systems, the name cache may contain
     * incorrect data (particularly if the directory we are mounting
     * on was just recently a symbolic link).  Using open will at the
     * very least force a getattr, which we hope will, when it gets a
     * stale file handle error, cause a lookup. */

    struct stat sb1, sb2;
    autofd fd (open (dir, O_RDONLY));
    if (fd < 0 || lstat (dir, &sb1) < 0 || fstat (fd, &sb2) < 0)
      return return_err (pp, curdir);
    if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino) {
      warn << pp << ": file system changed during safechdir\n";
      return return_err (NULL, curdir, EXDEV);
    }
    if (!dicache.insert (devino (sb2.st_dev, sb2.st_ino)))
      return return_err (pp, curdir, ELOOP);
    if (!S_ISDIR (sb1.st_mode))
      return return_err (pp, curdir, ENOTDIR);
    if (fchdir (fd) < 0)
      return return_err (pp, curdir);
  }

  close (curdir);
  return 0;
}
