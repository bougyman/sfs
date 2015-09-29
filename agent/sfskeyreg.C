/* $Id: sfskeyreg.C,v 1.56 2004/03/22 18:07:42 max Exp $ */

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
#include "sfscrypt.h"
#include "sfsschnorr.h"
#include "sfskeymgr.h"

struct keyregstate {
  u_int32_t opts;
  u_int nbits;
  str keyname;
  str wkeyname;
  str keylabel;
  str user;
  u_int cost;
  str srpfile;
  sfskeymgr *keymgr;
  sfskeyinfo *ki, *wki;
  sfskey *k;

  keyregstate () : opts (0), nbits (0), cost (0), wki (NULL) {}

  void doreg () {
    str err;
    ptr<sfspriv> kh, wk;
    keymgr = New sfskeymgr (user);
    if (!(ki = keymgr->getkeyinfo (keyname, opts)))
      fatal << "No suitable key found\n";
    if (wkeyname && (!(wki = keymgr->getkeyinfo (wkeyname, opts)) || 
		     wki->kt != SFSKI_NONE))
	fatal << "No changes made -- Need valid Unix filename with -w flag\n";

    ki->keylabel = keylabel;
    if (!(k = keymgr->fetch_or_gen (ki, &err, nbits, cost, opts)))
      fatal << "No changes made\n" << err << "\n";
    if (wki) {
      kh = k->key;
      if (!(wk = kh->wholekey ()))
	fatal << "No changes made -- cannot get complete key\n";
      k->key = wk;
      if (!keymgr->save (k, wki, opts | KM_NOLNK))
	fatal << "No changes made -- cannot save complete key\n";
      k->key = kh;
    }
    if (!(opts & KM_NOSRP) && !keymgr->getsrp (srpfile))
      fatal << "No changes made\nCannot find suitable SRP parameters.\n";
    u_int32_t topts = opts;
    if (ki->gen && (ki->is_proactive () || (opts & KM_PROAC)))
      topts |= KM_CHNGK;
    keymgr->update (k, NULL, "-", topts, wrap (this, &keyregstate::didupdate));
  }

  void didupdate (str err, bool gotconf) {
    if (err) 
      fatal << "No changes made\n" << err << "\n";
    if (!keymgr->save (k, ki, opts))
      fatal << "WARNING: Changes registered but could not save key\n";
    exit (0);
  }
};

void
sfskey_reg (int argc, char **argv)
{
  keyregstate *kr = New keyregstate ();
  int ch;
  u_int32_t opts = KM_UNX | KM_GEN;
  while ((ch = getopt (argc, argv, "fpgEKSPs:b:c:l:u:w:")) != -1)
    switch (ch) {
    case 'E':
      opts |= KM_NOESK;
      break;
    case 'g':
      opts |= KM_FGEN;
      break;
    case 'l':
      kr->keylabel = optarg;
      break;
    case 'p':
      opts |= ( KM_FGEN | KM_PROAC | KM_SKH );
      break;
    case 'P':
      opts |=  ( KM_NOPWD | KM_FGEN );
      break;
    case 'f':
      opts |= KM_REREG;
      break;
    case 'K':
      opts |= KM_NOKBD;
      break;
    case 'S':
      opts |= KM_NOSRP;
      break;
    case 's':
      kr->srpfile = optarg;
      break;
    case 'b':
      opts |= KM_FGEN;
      if (!convertint (optarg, &kr->nbits))
	usage ();
      break;
    case 'c':
      if (!convertint (optarg, &kr->cost))
	usage ();
      break;
    case 'u':
      kr->user = optarg;
      break;
    case 'w':
      kr->wkeyname = optarg;
      break;
    default:
      usage ();
      break;
    }
  if (optind + 1 < argc)
    usage ();

  if (!(opts & KM_NOSRP)) {
    if (opts & KM_NOPWD) 
      fatal << "Cannot use SRP without a password (i.e., -P flag "
	    << "requires -S)\n";
  }
  if (kr->wkeyname && !(opts & KM_PROAC)) 
    fatal << "Can only use the -w flag with the -p flag\n";

  kr->opts = opts;

  if (optind + 1 == argc)
    kr->keyname = argv[optind];
  else if (optind != argc)
    usage ();

  random_set_seedfile (RANDOM_SEED);
  kr->doreg ();
}

