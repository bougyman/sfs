/* $Id: sfskeygroup.C,v 1.17 2004/04/15 05:39:48 dm Exp $ */

/*
 *
 * Copyright (C) 2003 Michael Kaminsky (kaminsky@lcs.mit.edu)
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
#include "srp.h"
#include "rxx.h"
#include "sfskeymgr.h"
#include "sfsgroupmgr.h"

static void
print_group (bool expanded, ptr<sfsauth2_query_res> aqr, str sfshost)
{
  if (!aqr)
    exit (1);
  if (aqr->type == SFSAUTH_ERROR)
    fatal << "Error: " << *aqr->errmsg << "\n";

#if 0
  strbuf refresh, timeout;
  refresh << aqr->groupinfo->refresh << " seconds ("
          << seconds2str (aqr->groupinfo->refresh) << ")\n";
  timeout << aqr->groupinfo->timeout << " seconds ("
          << seconds2str (aqr->groupinfo->timeout) << ")\n";
#endif

  strbuf s;
  unsigned int i;
  s << "       Group Name: " << aqr->groupinfo->name
                            << (sfshost ? sfshost.cstr () : "") << "\n";
  s << "               ID: " << aqr->groupinfo->id << "\n";
  s << "          Version: " << aqr->groupinfo->vers << "\n";
#if 0
  s << "          Refresh: " << refresh;
  s << "          Timeout: " << timeout;
#endif

  s << (expanded ? "  Expanded Owners: " : "           Owners: ");
  i = aqr->groupinfo->owners.size ();
  s << (i > 0 ? aqr->groupinfo->owners[0].cstr () : "<none>") << "\n";
  for (i = 1; i < aqr->groupinfo->owners.size (); i++)
    s << "                   " << aqr->groupinfo->owners[i] << "\n";

  s << (expanded ? " Expanded Members: " : "          Members: ");
  i = aqr->groupinfo->members.size ();
  s << (i > 0 ? aqr->groupinfo->members[0].cstr () : "<none>") << "\n";
  for (i = 1; i < aqr->groupinfo->members.size (); i++)
    s << "                   " << aqr->groupinfo->members[i] << "\n";

  s << "            Audit: " << aqr->groupinfo->audit << "\n";
  warnx << s;

  exit (0);
}

static void
print_changelog (ptr<sfsauth2_query_res> aqr, str sfshost)
{
  if (!aqr)
    exit (1);
  if (aqr->type == SFSAUTH_ERROR)
    fatal << "Error: " << *aqr->errmsg << "\n";

  if (aqr->type == SFSAUTH_GROUP) {
    print_group (false, aqr, sfshost);
    return;
  }

  strbuf refresh, timeout;
  refresh << aqr->logentry->refresh << " seconds ("
          << seconds2str (aqr->logentry->refresh) << ")\n";
  timeout << aqr->logentry->timeout << " seconds ("
          << seconds2str (aqr->logentry->timeout) << ")\n";

  strbuf s;
  unsigned int i;
  s << "            Audit: " << aqr->logentry->audit << "\n";
  s << "          Version: " << aqr->logentry->vers << "\n";
  s << "          Refresh: " << refresh;
  s << "          Timeout: " << timeout;
  for (i = 0; i < aqr->logentry->members.size (); i++)
    s << "                   " << aqr->logentry->members[i] << "\n";
  warnx << s;

  exit (0);
}

static str
srp_prepend (const str &in)
{
  if (!strchr (in, '@')) {
    warnx << "Prepending '@' to '" << in << "' and using SRP\n";
    return strbuf () << "@" << in;
  } else {
    return in;
  }
}

struct groupcmd {
  bool create;
  bool expanded;
  int version;
  vec<str> keys;
  str group;
  str gname;
  str ghost;
  vec<str> members;
  vec<str> owners;
  ptr<sfskeymgr> kmgr;
  ptr<sfsgroupmgr> gmgr;

  groupcmd () : create (false), expanded (false), version (-1) {}

  void query ()
  {
    kmgr = New refcounted<sfskeymgr> (str (NULL), KM_NOHM);
    kmgr->add_keys (keys);
  
    gmgr = New refcounted<sfsgroupmgr> (kmgr);
    if (expanded)
      gmgr->expandedquery (group, wrap (print_group, expanded));
    else
      gmgr->query (group, wrap (print_group, expanded));
  }

  void changelog ()
  {
    kmgr = New refcounted<sfskeymgr> (str (NULL), KM_NOHM);
    kmgr->add_keys (keys);
  
    gmgr = New refcounted<sfsgroupmgr> (kmgr);
    gmgr->changelogquery (group, version, wrap (print_changelog));
  }

  void update ()
  {
    kmgr = New refcounted<sfskeymgr> ();
    kmgr->add_keys (keys);

    vec<str> v;
    v.push_back (ghost);
    kmgr->check_connect (v, wrap (this, &groupcmd::update_cb));
  }
  void update_cb ()
  {
    gmgr = New refcounted<sfsgroupmgr> (kmgr);
    gmgr->update (group, &members, &owners, create);
  }
};

void
sfskey_group (int argc, char **argv)
{
  groupcmd *gc = New groupcmd ();

  int ch;
  while ((ch = getopt (argc, argv, "L:ECa:m:o:")) != -1)
    switch (ch) {
    case 'a':
      gc->keys.push_back (optarg);
      break;
    case 'm':
      if (optarg[0] != '+' && optarg[0] != '-') {
	warn ("Member names must begin with + (add) or - (remove)\n");
	usage ();
      }
      if (strlen (optarg) > sfs_groupmember::maxsize) {
	warn ("Member name is too long (max 256 characters): %s\n", optarg);
	usage ();
      }
      gc->members.push_back (optarg);
      break;
    case 'o':
      if (optarg[0] != '+' && optarg[0] != '-') {
	warn ("Owner names must begin with + (add) or - (remove)\n");
	usage ();
      }
      if (strlen (optarg) > sfs_groupmember::maxsize) {
	warn ("Owner name is too long (max 256 characters): %s\n", optarg);
	usage ();
      }
      gc->owners.push_back (optarg);
      break;
    case 'C':
      gc->create = true;
      break;
    case 'E':
      gc->expanded = true;
      break;
    case 'L':
      if (!convertint (optarg, &gc->version) || gc->version < 0)
	usage ();
      break;
     default:
      usage ();
      break;
    }

  if ((optind + 1 != argc)
      || (!sfsgroupmgr::parsegroup (argv[optind], &gc->gname, &gc->ghost)))
    usage ();
  gc->group = argv[optind];

  if (!(gc->ghost == "-") && issrpkey (gc->ghost)) 
    gc->keys.push_back (srp_prepend (gc->ghost));

  if (gc->members.size () == 0 && gc->owners.size () == 0)
    if (gc->create)
      gc->update ();
    else
      if (gc->version >= 0) {
	if (gc->expanded)
	  warn << "Expanded (-E) option doesn't apply to changelog queries.  Ignoring...\n";
	gc->changelog ();
      }
      else
	gc->query ();
  else {
    if (gc->expanded)
      warn << "Expanded (-E) option doesn't apply to updates.  Ignoring...\n";
    if (gc->version >= 0)
      warn << "Changelog (-L) option doesn't apply to updates.  Ignoring...\n";
    if (gc->owners.size () > 250)
      fatal << "Owners list is too big (> 250 entries) for a single update\n"
	    << "and I don't want to split it up arbitrarily.  Please issue\n"
	    << "multiple `sfskey group' commands with the owners list split\n"
	    << "up to provide the correct permissions semantics.\n";
    if (gc->create)
      fatal << "Cannot use Create (-C) option with an owners/members list.\n";
    gc->update ();
  }
}
