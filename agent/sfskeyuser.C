/* $Id: sfskeyuser.C,v 1.3 2004/04/15 05:39:48 dm Exp $ */

/*
 *
 * Copyright (C) 2004 Michael Kaminsky (kaminsky@lcs.mit.edu)
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
#include "sfsusermgr.h"

static void
print_user (ptr<sfsauth2_query_res> aqr, str sfshost)
{
  if (!aqr)
    exit (1);
  if (aqr->type == SFSAUTH_ERROR)
    fatal << "Error: " << *aqr->errmsg << "\n";

  str owner;
  if (aqr->userinfo->owner)
    owner = *aqr->userinfo->owner ;
  else 
    owner = "<none>";

  str pkhash;
  ptr<sfspub> pk = sfscrypt.alloc (aqr->userinfo->pubkey);
  if (!pk)
    pkhash = "<no public key returned from server>";
  else {
    pkhash = pk->get_pubkey_hash ();
    if (!pkhash)
      pkhash = "<error in sha1_hashxdr of public key>";
    else
      pkhash = armor32 (pkhash);
  }

#if 0
  strbuf refresh, timeout;
  refresh << aqr->userinfo->refresh << " seconds ("
          << seconds2str (aqr->userinfo->refresh) << ")\n";
  timeout << aqr->userinfo->timeout << " seconds ("
          << seconds2str (aqr->userinfo->timeout) << ")\n";
#endif

  strbuf s;
  s << "        User Name: " << aqr->userinfo->name
                             << (sfshost ? sfshost.cstr () : "") << "\n";
  s << "               ID: " << aqr->userinfo->id << "\n";
  s << "          Version: " << aqr->userinfo->vers << "\n";
  s << "              GID: " << aqr->userinfo->gid << "\n";
  s << "            Owner: " << owner << "\n";
  s << "  Public Key Hash: " << pkhash << "\n";
  s << "       Properties: " << aqr->userinfo->privs << "\n";
#if 0
  s << "          Refresh: " << refresh;
  s << "          Timeout: " << timeout;
#endif
  s << "            Audit: " << aqr->userinfo->audit << "\n";
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

struct usercmd {
  vec<str> keys;
  str user;
  str name;
  str host;
  ptr<sfskeymgr> kmgr;
  ptr<sfsusermgr> umgr;

  usercmd () {}

  void query ()
  {
    kmgr = New refcounted<sfskeymgr> (str (NULL), KM_NOHM);
    kmgr->add_keys (keys);
  
    umgr = New refcounted<sfsusermgr> (kmgr);
    umgr->query (user, wrap (print_user));
  }

#if 0
  void update ()
  {
    kmgr = New refcounted<sfskeymgr> ();
    kmgr->add_keys (keys);

    vec<str> v;
    v.push_back (ghost);
    kmgr->check_connect (v, wrap (this, &usercmd::update_cb));
  }
  void update_cb ()
  {
    gmgr = New refcounted<sfsusermgr> (kmgr);
    gmgr->update (user, &members, &owners, create);
  }
#endif
};

void
sfskey_user (int argc, char **argv)
{
  usercmd *uc = New usercmd ();

  int ch;
  while ((ch = getopt (argc, argv, "a:")) != -1)
    switch (ch) {
    case 'a':
      uc->keys.push_back (optarg);
      break;
    default:
      usage ();
      break;
    }

  if ((optind + 1 != argc)
      || (!sfsusermgr::parseuser (argv[optind], &uc->name, &uc->host)))
    usage ();
  uc->user = argv[optind];

  if (!(uc->host == "-") && issrpkey (uc->host)) 
    uc->keys.push_back (srp_prepend (uc->host));

  uc->query ();
}
