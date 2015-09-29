/* $Id: sfskeyconf.C,v 1.2 2004/03/10 21:34:41 kaminsky Exp $ */

/*
 *
 * Copyright (C) 2003 Michael Kaminsky (kaminsky@lcs.mit.edu)
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
sfskey_confclear (int argc, char **argv)
{
  nularg (argc, argv);
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_CLRCONFIRMPROG, NULL, NULL))
    fatal << "agent: " << err << "\n";
  exit (0);
}

void
sfskey_conflist (int argc, char **argv)
{
  bool opt_q = false;
  int ch;
  while ((ch = getopt (argc, argv, "q")) != -1)
    switch (ch) {
    case 'q':
      opt_q = true;
      break;
    default:
      usage ();
      break;
    }
  if (optind < argc)
    usage ();

  sfsagent_confprog res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_DUMPCONFIRMPROG, NULL, &res))
    fatal << "agent: " << err << "\n";

  strbuf list;
  if (!opt_q)
    list.fmt ("%s\n", "PROGRAM");
  if (res.size () > 0) {
    for (sfsagent_progarg *a = res.base (); a < res.lim (); a++)
      list << *a << " ";
    list << "\n";
  }
  else if (!opt_q)
    list << "(none)\n";

  make_sync (1);
  list.tosuio ()->output (1);
  exit (0);
}

void
sfskey_confprog (int argc, char **argv)
{
  sfsagent_confprog arg;

  int ch;
  while ((ch = getopt (argc, argv, "")) != -1)
    switch (ch) {
    default:
      usage ();
      break;
    }
  if (optind >= argc)
    usage ();

  arg.setsize (argc - optind);
  for (int i = optind; i < argc; i++)
    arg[i - optind] = argv[i];
  bool res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_ADDCONFIRMPROG, &arg, &res))
    fatal << "agent: " << err << "\n";
  if (!res)
    fatal << "agent refused confirmation program\n";
  exit (0);
}
