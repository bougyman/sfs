/* $Id: dirsearch.c,v 1.11 2002/11/28 09:23:55 dm Exp $ */

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

#include "sysconf.h"

#if 1
/* XXX - work around possibly weird Linux shared library bug.  exit is
 * obviously supposed to fflush all FILE streams, but apparently
 * sometimes when running with libtool it doesn't.
 */
static void flush_and_exit (int status) __attribute__ ((noreturn));
static void
flush_and_exit (int status)
{
  fflush (stdout);
  exit (status);
}
#else
#define flush_and_exit exit
#endif

static void
usage ()
{
  fprintf (stderr, "usage: dirsearch [-clpq] dir [dir ...] filename\n");
  flush_and_exit (1);
}

static int
checklen (const char *name)
{
  if (strlen (name) > PATH_MAX) {
    fprintf (stderr, "%s: name too long\n", name);
    return -1;
  }
  return 0;
}

static void
docat (const char *name)
{
  char buf[8192];
  int n, fd = open (name, O_RDONLY);
  if (fd < 0) {
    if (errno != ENOENT)
      perror (name);
    return;
  }
  while ((n = read (fd, buf, sizeof (buf))) > 0)
    write (1, buf, n);
  flush_and_exit (0);
}

static void
dolink (const char *name)
{
  char buf[1024];
  int n = readlink (name, buf, sizeof (buf));
  if (n < 0) {
    if (errno != ENOENT && errno != EINVAL)
      perror (name);
    return;
  }
  if (n > 0 && buf[0] != '/') {
    char *p = strrchr (name, '/');
    if (p) {
      while (p > name && p[-1] == '/')
	p--;
      printf ("%.*s/%.*s\n", (int) (p - name), name, n, buf);
    }
    else
      printf ("%.*s\n", n, buf);
  }
  else
    printf ("%.*s\n", n, buf);
  flush_and_exit (0);
}

static void
dopath (const char *name)
{
  struct stat sb;
  if (lstat (name, &sb) < 0) {
    if (errno != ENOENT)
      perror (name);
    return;
  }
  printf ("%s\n", name);
  flush_and_exit (0);
}

static void
dosimple (const char *name)
{
  struct stat sb;
  if (lstat (name, &sb) < 0) {
    if (errno != ENOENT)
      perror (name);
    return;
  }
  flush_and_exit (0);
}

int
main (int argc, char **argv)
{
  void (*fn) (const char *) = dopath;
  char *name;
  int ch;
  char path[2*PATH_MAX + 2];

  /* XXX - work around possibly weird Linux shared library bug.  exit is
   * obviously supposed to fflush all FILE streams, but apparently
   * sometimes when running with libtool it doesn't. */
  setvbuf (stdout, NULL, _IONBF, 0);

  putenv ("POSIXLY_CORRECT=1"); /* Prevents Linux from reordering options */
  while ((ch = getopt (argc, argv, "clpq")) != -1)
    switch (ch) {
    case 'c':
      fn = docat;
      break;
    case 'l':
      fn = dolink;
      break;
    case 'p':
      fn = dopath;
      break;
    case 'q':
      fn = dosimple;
      break;
    default:
      usage ();
      break;
    }

  name = argv[--argc];
  if (optind >= argc)
    usage ();

  if (checklen (name) < 0)
    flush_and_exit (1);

  for (; optind < argc; optind++) {
    if (checklen (argv[optind]) < 0)
      continue;
    sprintf (path, "%s/%s", argv[optind], name);
    fn (path);
  }

  flush_and_exit (1);
}
