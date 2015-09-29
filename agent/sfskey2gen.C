/* $Id: sfskey2gen.C,v 1.14 2002/11/05 20:36:36 max Exp $ */

/*
 *
 * Copyright (C) 2002 Maxwell Krohn (max@cs.nyu.edu)
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


struct schnorr2gen_state {
  str user;
  str keylabel;
  str nkeyname;
  str okeyname;
  str wkeyname;
  str srpfile;
  u_int cost;
  u_int nbits;
  u_int32_t opts;
  vec<str> keys;
  vec<str> servers;
  vec< sfskey * > splits;
  sfskey *k;
  sfskeymgr *kmgr;
  sfskeyinfo *ki, *nki, *wki;

  u_int ncb;
  bool cberr;

  schnorr2gen_state () : cost (0), nbits (0), wki (NULL), ncb (0), 
			 cberr (false) {}

  void dogen () 
  {
    if (servers.size () == 0) 
      servers.push_back ("-");
    opts |= (KM_PROAC | KM_SKH);
    str err;
    kmgr = New sfskeymgr (user);

    if (!(nki = kmgr->getkeyinfo (nkeyname, opts)))
      fatal << "Cannot output to given keyname\n";
    nki->keylabel = keylabel;
    if (nki->kt == SFSKI_NONE && servers.size () > 1)
      fatal << nkeyname << ": refusing to write more than once to "
	    << "the same file\n";
    if (!(opts & KM_NOSRP) && !kmgr->getsrp (srpfile))
      fatal << "Cannot find suitable SRP parameters.\n";
    if (wkeyname && (!(wki = kmgr->getkeyinfo (wkeyname, opts)) || 
		     wki->kt != SFSKI_NONE))
      fatal << "Must supply a Unix pathname with -w option\n";

    kmgr->add_keys (keys);
    kmgr->check_connect (servers, wrap (this, &schnorr2gen_state::keygen));
  }

  void keygen () 
  {
    sfskey *nk;
    ptr<sfspriv> wk, kh;
    str err;
    if (!(nk = kmgr->fetch_or_gen (nki, &err, nbits, cost, opts)))
      fatal << err << "\n";
    if (wki) {
      kh = nk->key;
      if (!(wk = kh->wholekey ()))
	fatal << "No complete key returned\n";
      nk->key = wk;
      if (!kmgr->save (nk, wki, opts | KM_NOLNK))
	fatal << "Could not save complete key -- key generation aborted\n";
      nk->key = kh;
    }
    ncb = servers.size ();
    for (u_int i = 0 ; i < ncb; i++) {
      if (i > 0) {
	ptr<sfspriv> key = nk->key;
	nk = New sfskey (*nk);
	nk->key = key->regen ();
      }
      kmgr->update (nk, NULL, servers[i], opts | KM_CHNGK, 
		    wrap (this, &schnorr2gen_state::updatecb, servers[i]));
      splits.push_back (nk);
    }
  }

  void updatecb (str server, str err, bool gotconf)
  {
    if (err) {
      warn << server << ": update failed:\n" << err << "\n";
      cberr = true;
    }
    if (--ncb == 0) {
      if (cberr)
	warn << "WARNING: Not all servers were successfully updated\n";
      savekeys ();
    }
  }

  void savekeys ()
  {
    sfskey *nk;
    bool err = false;
    u_int32_t topts = opts;
    if (!keylabel)
      topts |= KM_CHNGK;
    for (u_int i = 0 ; i < servers.size (); i++) {
      nk = splits[i];
      nki->setpriority (i+1); 
      if (i > 0) 
	opts |= KM_NOLNK;
      if (!kmgr->save (nk, nki, topts))
	err = true;
    }
    exit (err ? 1 : 0);
  }
};

void
sfskey_2gen (int argc, char **argv)
{
  int ch;
  u_int32_t opts = KM_FGEN;
  schnorr2gen_state *s2g = New schnorr2gen_state ();
  while ((ch = getopt (argc, argv, "a:b:c:k:l:s:w:BEKPS")) != -1) {
    switch (ch) {
    case 'a':
      s2g->servers.push_back (optarg);
      break;
    case 'b':
      if (!convertint (optarg, &s2g->nbits))
	usage ();
      break;
    case 'c':
      if (!convertint (optarg, &s2g->cost))
	usage ();
      break;
    case 'k':
      s2g->keys.push_back (optarg);
      break;
    case 'l':
      s2g->keylabel = optarg;
      break;
    case 's':
      s2g->srpfile = optarg;
      break;
    case 'w':
      s2g->wkeyname = optarg;
      break;
    case 'E':
      opts |= KM_NOESK;
      break;
    case 'B':
      opts |= KM_NOPK;
      break;
    case 'K':
      opts |= KM_NOKBD;
      break;
    case 'P':
      opts |= KM_NOPWD;
      break;
    case 'S':
      opts |= KM_NOSRP;
      break;
    default:
      usage ();
      break;
    }
  }
  if (argc == optind + 1)
    s2g->nkeyname = argv[optind];
  else if (optind != argc)
    usage ();
  s2g->opts = opts;
  random_set_seedfile (RANDOM_SEED);
  s2g->dogen ();
}
