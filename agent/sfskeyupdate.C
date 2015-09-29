/* $Id: sfskeyupdate.C,v 1.48 2003/02/14 16:27:40 kaminsky Exp $ */

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
#include "srp.h"
#include "sfskeymgr.h"

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

struct updatecmd {
  str nkeyname;
  str srpfile;
  bool realmup;
  u_int32_t opts;
  vec<str> keys;
  vec<str> servers;
  sfskeymgr *kmgr;
  sfskeyinfo *nki;
  sfskey *nk;
  u_int ncb;
  bool cberr;

  updatecmd () : realmup (false), opts (0), ncb (0), cberr (false) {}

  void setupargs ()
  {
    size_t sz = servers.size ();
    if (!sz)
      fatal << "At least one target server must be specified\n\t"
	    << "(use '-' for localhost)\n";

    if (realmup) {

      if (sz != 1 || !issrpkey (servers[0])) 
	fatal << "Exactly one SRP key must be used with -r\n";
      if (keys.size () || opts & (KM_NOESK | KM_NOSRP))
	fatal << "-r flag cannot be used with -akS flags\n";
      nkeyname = srp_prepend (servers[0]);

    } else 
      for (u_int i = 0; i < sz; i++) 
	if (!(servers[i] == "-") && issrpkey (servers[i])) 
	  keys.push_back (srp_prepend (servers[i]));
  }

  void start ()
  {
    setupargs ();
    opts |= KM_REALM;

    kmgr = New sfskeymgr ();
    if (servers.size () == 0)
      fatal << "Must specify at least one server to update\n";
    str err;
    if (!(nki = kmgr->getkeyinfo (nkeyname, opts))) 
      fatal << "No suitable new key found\n";
    if (!(opts & KM_NOSRP) && !kmgr->getsrp (srpfile))
      fatal << "Cannot find suitable SRP parameters.\n";
    if (!(nk = kmgr->fetch (nki, &err, opts))) 
      fatal << err << "\n";
    kmgr->add (nk->key);
    kmgr->add_keys (keys);
    kmgr->check_connect (servers, wrap (this, &updatecmd::update));
  }

  void update ()
  {
    ncb = servers.size ();
    for (u_int i = 0; i < ncb; i++)
      kmgr->update (nk, NULL, servers[i], opts,
		    wrap (this, &updatecmd::updatecb, servers[i]));
  }

  void updatecb (str server, str err, bool gotconf)
  {
    if (err) {
      warn << server << ": update failed:\n" << err << "\n";
      cberr = true;
    }
    if (--ncb == 0) {
      if (cberr)
	warn << "WARNING: Not all servers were successfully updated.\n";
      exit (cberr);
    }
  }
};



void
sfskey_update (int argc, char **argv)
{
  updatecmd *uc = New updatecmd ();
  u_int32_t opts = 0;

  int ch;
  while ((ch = getopt (argc, argv, "fESs:a:k:r")) != -1)
    switch (ch) {
    case 'E':
      opts |= KM_NOESK;
      break;
    case 'S':
      opts |= KM_NOSRP;
      break;
    case 's':
      uc->srpfile = optarg;
      break;
    case 'f':
      opts |= KM_FRC;
      break;
    case 'a':
      uc->keys.push_back (optarg);
      break;
    case 'r':
      uc->realmup = true;
      break;
    case 'k':
      if (uc->nkeyname)
	fatal << "-k can only be supplied once\n";
      uc->nkeyname = optarg;
      break;
    default:
      usage ();
      break;
    }

  for (int i = optind; i < argc; i++)
    uc->servers.push_back (argv[i]);
  uc->opts = opts;
  uc->start ();
}
