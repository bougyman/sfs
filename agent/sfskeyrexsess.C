/* $Id: sfskeyrexsess.C,v 1.6 2003/12/14 07:07:14 kaminsky Exp $ */

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
sfskey_sesskill (int argc, char **argv)
{
  if (getopt (argc, argv, "") != -1 || optind + 1 != argc)
    usage ();

  sfs_hostname arg = argv[optind];
  bool res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_KILLSESS, &arg, &res))
    fatal << "agent: " << err << "\n";

  if (res)
    exit (0);
  else
    fatal << "no rexsessions connected to " << argv[optind] << "\n";
}

void
sfskey_sesslist (int argc, char **argv)
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

  rex_sessvec sv;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_LISTSESS, NULL, &sv))
    fatal << "agent: " << err << "\n";
  
  strbuf list;
  if (!opt_q)
    list.fmt ("%-60s %-10s %s\n", "TO", "FROM", "AGENT?");

  for (size_t i = 0; i < sv.size (); i++) {
    const char *agentstatus = sv[i].agentforwarded ? "yes" : "no";
    list.fmt ("%-40s (%s) %-10s %s\n", sv[i].schost.cstr (), 
	      sv[i].dest.cstr (), sv[i].created_from.cstr (), agentstatus);
  }

  make_sync (1);
  list.tosuio ()->output (1);
  exit (0);
}

void
sfskey_srplist (int argc, char **argv)
{
  nularg (argc, argv);

  sfsagent_srpname_pairs res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_DUMPSRPNAMES, NULL, &res))
    fatal << "agent: " << err << "\n";

  strbuf list;
  if (!opt_quiet)
    list.fmt ("%-30s %s\n", "SRP Name", "Self-Certifying Hostname");
  for (sfsagent_srpname_pair *p = res.base (); p < res.lim (); p++) {
    if (p->srpname && p->sfsname)
      list.fmt ("%-30s %s", p->srpname.cstr (), p->sfsname.cstr ());
    else
      list.fmt ("--Error--");
    list << "\n";
  }

  make_sync (1);
  list.tosuio ()->output (1);
  exit (0);
}

void
sfskey_srpclear (int argc, char **argv)
{
  nularg (argc, argv);
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_CLRSRPNAMES, NULL, NULL))
    fatal << "agent: " << err << "\n";
  exit (0);
}
