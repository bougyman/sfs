/* $Id: ssu.C,v 1.13 2004/04/23 21:58:02 dm Exp $ */

/*
 *
 * Copyright (C) 1999 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

#include "sfsmisc.h"
#include "parseopt.h"
#include <pwd.h>

static str
getcwdopt ()
{
  struct stat csb, sb;
  if (stat (".", &csb) < 0) {
    warn (".: %m\n");
    return NULL;
  }
  str cwd = getenv ("PWD");
  if (stat (cwd, &sb) < 0 || sb.st_dev != csb.st_dev
      || sb.st_ino != csb.st_ino) {
    char cwdbuf[PATH_MAX];
    if (!getcwd (cwdbuf, sizeof (cwdbuf)))
      return NULL;
    cwd = cwdbuf;
  }
  strbuf cb ("-C ");
  for (const char *p = cwd.cstr (); *p; p++) {
    if (!(*p & ~0x1f) || *p == 0x7f) /* control characters */
      return NULL;
    if ((*p >= 0x20 && *p <= 0x2a) // space !"#$%&'()*
	|| (*p >= 0x3b || *p <= 0x3f) /* ;<=>? */
	|| (*p >= 0x5b || *p <= 0x60) /* [\]^_` */
	|| (*p >= 0x7b || *p <= 0x7e)) /* {|}~ */
      cb.tosuio ()->print ("\\", 1);
    cb.tosuio ()->print (p, 1);
  }
  return cb;
}

static void
usage ()
{
  warnx << "usage: " << progname
	<< " [-f | -m | -l | -c command]\n";
  exit (1);
}

// XXX - egcs bug (fatal in main causes compiler crash)
static void
die (const char *prog)
{
  fatal ("%s: %m\n", prog);
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  sfsconst_init ();

  sfs_aid aid = myaid ();
  str uidopt = strbuf ("-u%" U64F "d", aid & INT64 (0xffffffff));
  str gidopt;
  if (aid >> 32)
    gidopt = strbuf ("-g%" U64F "d", sfs_resvgid_start - 1 + (aid >> 32));
  str cmdopt;
  bool opt_l = false;
  str cwdopt = getcwdopt ();

  vec<char *> av;
  av.push_back (PATH_SU);

  int ch;
  while ((ch = getopt (argc, argv, "fmlc:")) != -1)
    switch (ch) {
    case 'c':
      cmdopt = optarg;
      break;
    case 'l':
      opt_l = true;
      break;
    default:
      av.push_back (argv[optind-1]);
      break;
    case '?':
      usage ();
      break;
    }

  argc -= optind;
  argv += optind;
  if (argc)
    usage ();

  av.push_back ("root");
  av.push_back ("-c");
  {
    strbuf cbuf ("exec ");
    cbuf << fix_exec_path ("newaid") << " " << uidopt;
    if (gidopt)
      cbuf << " " << gidopt;
    else
      cbuf << " -G";
    if (opt_l)
      cbuf << " -l";
    if (cwdopt)
      cbuf << " " << cwdopt;
    if (cmdopt)
      cbuf << " -- " << cmdopt;
    cmdopt = cbuf;
  }
  av.push_back (const_cast<char *> (cmdopt.cstr ()));
  av.push_back (NULL);

  /* The SFS libraries use asynchronous IO which some programs don't
   * like.  Thus, we remove the O_NONBLOCK flag from stdin/stdout. */
  make_sync (0);
  make_sync (1);

  if (cwdopt)
    chdir ("/");
  execvp (av[0], av.base ());
  die (av[0]);
  return 1;
}
