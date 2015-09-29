/* $Id: sfskeycert.C,v 1.7 2002/04/12 03:25:37 kaminsky Exp $ */

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
sfskey_certclear (int argc, char **argv)
{
  nularg (argc, argv);
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_CLRCERTPROGS, NULL, NULL))
    fatal << "agent: " << err << "\n";
  exit (0);
}

void
sfskey_certlist (int argc, char **argv)
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

  sfsagent_certprogs res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_DUMPCERTPROGS, NULL, &res))
    fatal << "agent: " << err << "\n";

  strbuf list;
  if (!opt_q)
    list.fmt ("%-30s %-8s %-8s %s\n", 
	      "PREFIX", "FILTER", "EXCLUDE", "PROGRAM");
  for (sfsagent_certprog *p = res.base (); p < res.lim (); p++) {
    list.fmt ("%-30s %-8s %-8s", p->prefix.cstr (),
	      p->filter.cstr (), p->exclude.cstr ());
    for (sfsagent_progarg *a = p->av.base (); a < p->av.lim (); a++)
      list << " " << *a;
    list << "\n";
  }

  make_sync (1);
  list.tosuio ()->output (1);
  exit (0);
}

void
sfskey_certprog (int argc, char **argv)
{
  sfsagent_certprog arg;

  int ch;
  while ((ch = getopt (argc, argv, "p:f:e:")) != -1)
    switch (ch) {
    case 'p':
      if (arg.prefix.len () > 0)
	usage ();
      arg.prefix = optarg;
      break;
    case 'f':
      if (arg.filter.len () > 0)
	usage ();
      arg.filter = optarg;
      break;
    case 'e':
      if (arg.exclude.len () > 0)
	usage ();
      arg.exclude = optarg;
      break;
    default:
      usage ();
      break;
    }
  if (optind >= argc)
    usage ();

  if (!arg.prefix)
    arg.prefix = "";
  if (!arg.filter)
    arg.filter = "";
  if (!arg.exclude)
    arg.exclude = "";

  arg.av.setsize (argc - optind);
  for (int i = optind; i < argc; i++)
    arg.av[i - optind] = argv[i];
  bool res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_ADDCERTPROG, &arg, &res))
    fatal << "agent: " << err << "\n";
  if (!res)
    fatal << "agent refused certification program\n";
  exit (0);
}
