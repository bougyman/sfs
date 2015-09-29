/* $Id: sfsrwcd.C,v 1.33 2004/06/03 06:57:41 dm Exp $ */

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

#include "sfsrwcd.h"
#include "parseopt.h"

bool opt_map_ids;
u_int32_t unknown_uid;
u_int32_t unknown_gid;

static void usage () __attribute__ ((noreturn));
static void
usage ()
{
  fatal ("usage: %s [-u <unknown-username>]\n", progname.cstr ());
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  warn ("version %s, pid %d\n", VERSION, int (getpid ()));

  int ch;
  while ((ch = getopt (argc, argv, "u:")) != -1)
    switch (ch) {
    case 'u':
      opt_map_ids = true;
      if (struct passwd *pw = getpwnam (optarg)) {
	unknown_uid = pw->pw_uid;
	unknown_gid = pw->pw_gid;
      }
      else
	fatal ("user '%s' does not exist\n", optarg);
      break;
    default:
      usage ();
    }

  if (argc != optind)
    usage ();

  sfsconst_init ();
  random_init_file (sfsdir << "/random_seed");
  server::keygen ();

  if (ptr<axprt_unix> x = axprt_unix_stdin ())
    //vNew sfsprog (x, &sfsserver_alloc<server>);
    vNew sfsprog (x, &sfsserver_cache_alloc<server>);
  else
    fatal ("could not get connection to sfscd.\n");

  amain ();
}
