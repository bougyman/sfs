/* $Id: funmount.c,v 1.1 1999/03/19 07:53:12 dm Exp $ */

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

#ifdef __osf__
#define _SOCKADDR_LEN
#endif /* __osf__ */

#include "sysconf.h"
#include "nfsconf.h"

int
main (int argc, char **argv)
{
  if (argc != 2) {
    fprintf (stderr,  "usage: %s mountpoint\n", argv[0]);
    exit (1);
  }
  if (SYS_UNMOUNT (argv[1], MNT_FORCE)) {
    perror (argv[1]);
    exit (1);
  }
  return 0;
}
