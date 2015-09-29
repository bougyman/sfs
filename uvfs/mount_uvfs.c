/* $Id: mount_uvfs.c,v 1.5 1999/10/02 20:06:38 cblake Exp $ */

/*
 * User level VFS driver for OpenBSD
 * Copyright 1999 Michael Kaminsky <kaminsky@lcs.mit.edu>.
 * Copyright 1998 David Mazieres <dm@uun.org>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project (for instance by leaving this copyright notice
 * intact).
 */

#include "uvfs.h"

const char *progname;

int
main (int argc, char **argv)
{
  struct uvfs_args arg;

  if ((progname = strrchr (argv[0], '/')))
    progname++;
  else
    progname = argv[0];

  if (argc != 2) {
    fprintf (stderr, "usage: %s <dir>\n", progname);
    exit (1);
  }

  bzero (&arg, sizeof (arg));
  arg.uvfs_dev = 0;
  arg.uvfs_root_fh = 1;
#if defined (__OpenBSD__)
  if (mount (MOUNT_UVFS, argv[1], 0, &arg) < 0)
#endif
#if defined (__linux__)
  if (mount ("uvfs", argv[1], MOUNT_UVFS, MS_MGC_VAL, &arg) < 0)
#endif
    perror (progname);

  exit (0);
}
