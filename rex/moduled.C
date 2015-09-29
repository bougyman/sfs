/* $Id: moduled.C,v 1.5 2002/11/19 20:23:29 kaminsky Exp $ */

/*
 *
 * Copyright (C) 2002 Michael Kaminsky (kaminsky@lcs.mit.edu)
 * Copyright (C) 2001 Eric Peterson (ericp@lcs.mit.edu)
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

#include "async.h"

int
main (int argc, char **argv)
{
  setprogname (argv[0]);

  if (!isunixsocket (0))
    fatal << "stdin must be a unix domain socket\n";
  if (argc < 2)
    fatal << "usage: " << progname << " command [arg1 arg2 ... ]\n";

  char **cmdargv = argv + 1;
  str path = find_program_plus_libsfs (cmdargv[0]);
  if (!path)
    fatal << "Could not locate program: " << cmdargv[0] << "\n";

  make_sync (0);

  char buf[1024];
  int fd;
  while (readfd (0, buf, 1024, &fd) > 0)
    if (fd >= 0) {
      aspawn (path, cmdargv, fd, fd, errfd);
      close (fd);
    }
  
  return 0;
}
