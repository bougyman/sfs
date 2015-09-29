/* $Id: sfskeyhostid.C,v 1.11 2003/12/12 01:35:06 dm Exp $ */

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

#include "sfskey.h"

void
hostidprint (str host, str service, bool secure, int v,
	     ptr<sfscon> sc, str err)
{
  if (!sc) {
    if (host == "-")
      host = "localhost";
    warn ("Could not contact service `%s' on host `%s'\n", 
	  service.cstr (), host.cstr ());
    exit (1);
  }
  if (!secure)
    warnx << "WARNING: RETRIEVING HOSTID INSECURELY OVER THE NETWORK\n";
  err_flush ();
  strbuf msg;
  switch (v) {
  case 1:
    msg << sc->servinfo->mkpath (1, 0) << "\n";
    break;
  default:
    msg << sc->path << "\n";
    break;
  }
  make_sync (1);
  msg.tosuio ()->output (1);
  exit (0);
}

sfs_service
getservice (const char *optarg)
{
  int sn;
  if (convertint (optarg, &sn))
    return sfs_service (sn);
  else if (!strcasecmp (optarg, "sfs"))
    return SFS_SFS;
  else if (!strcasecmp (optarg, "authserv"))
    return SFS_AUTHSERV;
  else if (!strcasecmp (optarg, "rex"))
    return SFS_REX;
  else
    fatal << "service must be an integer or one of\n"
	  << "   sfs\n"
	  << "   authserv\n"
	  << "   rex\n";
}

void
sfskey_hostid (int argc, char **argv)
{
  int ch;
  str opt_service ("sfs");
  str host;
  int v = 2;

  while ((ch = getopt (argc, argv, "12s:")) != -1)
    switch (ch) {
    case 's':
      opt_service = optarg;
      break;
    case '1':
      v = 1;
      break;
    case '2':
      v = 2;
      break;
    default:
      usage ();
      break;
    }
  if (optind + 1 != argc)
    usage ();
  host = argv[optind];

#if 0
  if (host == "-" && strcasecmp (opt_service, "authserv")) {
    warn << "Host `-' (localhost) implies service `authserv'..."
         << "Overriding your choice of `" << opt_service << "'.\n";
    opt_service = "authserv";
  }
#endif

  sfs_connect_host (host, getservice (opt_service),
		    wrap (hostidprint, host, opt_service,
		          host == "-" || opt_quiet, v),
		    false);
}
