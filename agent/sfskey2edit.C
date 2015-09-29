/* $Id: sfskey2edit.C,v 1.8 2002/10/29 20:39:07 max Exp $ */

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
#include "sfskeymgr.h"

struct schnorr2edit {
  struct key_t {
    key_t (const str &kn) : keyname (kn), ki (NULL), k (NULL) {}
    key_t (const str &kn, sfskeyinfo *i, sfskey *e) 
      : keyname (kn), ki (i), k (e) { set_keyloc (); }

    void set_keyloc () 
    {
      if (ki && ki->exists && !ki->remote)
	keyloc = ki->afn ();
    }
      
    str keyname;
    str server;
    str keyloc;
    ptr<sfscon> con;
    sfskeyinfo *ki;
    sfskey *k;
  };
  u_int32_t opts;
  str srpfile;
  str keylabel;
  vec<key_t *>keys;
  sfskeymgr *kmgr;

  u_int ncb;
  bool cberr;

  schnorr2edit () : opts (0), kmgr (NULL), ncb (0), cberr (false) {}

  void addkey (const str &k) { keys.push_back (New key_t (k)); }

  void start ()
  {
    if (!kmgr)
      kmgr = New sfskeymgr ();
    if (opts & KM_ALL) 
      expand_list ();
    get_keys ();
    if (!(opts & KM_NOSRP) && !kmgr->getsrp (srpfile))
      fatal << "No changes made\nCannot find suitable SRP parameters\n";
    ncb = keys.size ();
    for (u_int i = 0; i < ncb; i++)
      keys[i]->k->key->init (wrap (this, &schnorr2edit::initcb, keys[i]));
  }

  void expand_list ()
  {
    vec<key_t *> nkeys;
    u_int sz = keys.size ();
    for (u_int i = 0; i < sz; i++) {
      str name = keys[i]->keyname;
      if (!(keys[i]->ki = kmgr->getkeyinfo_list (name)))
	fatal << name << ": cannot access key\n";
      kmgr->fetch_all (keys[i]->ki, wrap (this, &schnorr2edit::fetchcb, 
					  &nkeys, keys[i]->keyname));
    }
    while (keys.size ()) {
      key_t *kt = keys.pop_back ();
      if (kt)
	delete kt;
    }
    keys = nkeys;
  }

  void fetchcb (vec<key_t *> *nkeys, str kn, sfskeyinfo *ki, sfskey *k)
  {
    nkeys->push_back (New key_t (kn, ki, k));
  }

  void get_keys ()
  {
    str err;
    if (!keys.size ())
      fatal << "Cannot procede; no keys available\n";
    
    for (u_int i = 0 ; i < keys.size (); i++) {
      str name = keys[i]->keyname;
      if (!keys[i]->ki) { 
	if (!(keys[i]->ki = kmgr->getkeyinfo (name)))
	  fatal << name << ": cannot access key\n";
	keys[i]->set_keyloc ();
      }
      keys[i]->ki->keylabel = keylabel;
      if (!keys[i]->k && !(keys[i]->k = kmgr->fetch (keys[i]->ki, &err)))
	  fatal << name << ": could not fetch key:\n" << err << "\n";
      if (!keys[i]->ki->is_proactive ()) 
	fatal << name << ": is not a proactive key with a standard name\n";
      if (!kmgr->bump_privk_version (keys[i]->ki, opts))
	fatal << keys[i]->ki->fn () << ": cannot write new key\n";
    }
  }

  void initcb (key_t *kt, str err)
  {
    const str &name = kt->keyname;
    if (err) {
      cberr = true;
      warn << name << ": key initialization failed\n" << err << "\n";
    } else if (!kmgr->add_con (kt->k->key, &kt->con, &kt->server)) {
      cberr = true;
      warn << name << ": does not appear to be a proactive key.\n";
    }

    if (--ncb == 0) {
      if (cberr)
	fatal << "Schnorr 2-edit aborted\n";
      edit ();
    }
  }

  void edit ()
  {
    str pwd;
    if (opts & KM_NWPWD) 
      pwd = getpwdconfirm ("  New password: ");
    for (u_int i = 0; i < keys.size (); i++) {
      key_t *kt = keys[i];
      const str &n = kt->keyname;
      if (pwd)
	kt->k->pwd = pwd;
      ptr<sfspriv> ok = kt->k->key;
      if (!(kt->k->key = ok->update ())) {
	warn << n << ": cannot make new key split\n";
	continue;
      }
      ncb++;
      kmgr->update (kt->k, ok, kt->con, kt->server, NULL, opts, 
		    wrap (this, &schnorr2edit::updatecb, kt));
    }
  }

  void updatecb (key_t *kt, str err, bool gotconf)
  {
    const str &n = kt->keyname;
    if (err) {
      cberr = true;
      warn << n << ": " << err << "\n";
    }
    if (!gotconf) {
      kt->k->keyname = keylabel ? keylabel : kt->ki->fn ();
      if (!(kmgr->save (kt->k, kt->ki, opts))) {
	warn << n << ": WARNING: No confirmation from server, "
	     << "and save failed\n";
      } else {
	warn << n << ": WARNING: No confirmation from server.\n";
      }
    } else if (!err) {
      u_int32_t newopts = opts;
      if (!kt->ki->defkey) 
	newopts |= KM_NOLNK;
      kt->k->keyname = keylabel ? keylabel : kt->ki->fn ();
      if (!(kmgr->save (kt->k, kt->ki, newopts))) {
	cberr = true;
	warn << "WARNING: Changed registered but could not save key\n";
      }
      if (kt->keyloc) {
	if (unlink (kt->keyloc)) {
	  warn << kt->keyloc << ": delete failed\n";
	  cberr = true;
	} else {
	  warnx << "key deleted: " << kt->keyloc << "\n";
	}
      }
    }
    if (--ncb == 0) 
      exit (cberr ? 1 : 0);
  }

};

void
sfskey_2edit (int argc, char **argv) {
  schnorr2edit *ed = New schnorr2edit ();
  u_int32_t opts = (KM_DLT | KM_KPPK);

  int ch;
  while ((ch = getopt (argc, argv, "ESmpl:s:")) != -1) {
    switch (ch) {
    case 'm':
      opts |= KM_ALL;
      break;
    case 'p':
      opts |= KM_NWPWD;
      break;
    case 'E':
      opts |= (KM_NOESK | KM_KPESK);
      break;
    case 'S':
      opts |= (KM_NOSRP | KM_KPSRP);
      break;
    case 'l':
      ed->keylabel = optarg;
      break;
    case 's':
      ed->srpfile = optarg;
      break;
    default:
      usage ();
    }
  }
  if (argc == optind)
    ed->addkey ("#");
  else 
    for (int i = optind; i < argc; i++)
      ed->addkey (argv[i]);
  ed->opts = opts;
  ed->start ();
};

struct passwdcmd {
  vec<str> dest;
  sfskeyinfo *oki, *nki;
  sfskey *ok, *nk;
  sfskeymgr *kmgr;
  u_int32_t opts;
  u_int nbits;
  u_int cost;
  str srpfile;
  str keylabel;
  u_int ncb;
  bool cberr;

  passwdcmd () : kmgr (NULL), opts (0), nbits (0), cost (0) {}

  void go_proac () 
  {
    schnorr2edit *ed = New schnorr2edit ();
    for (u_int i = 0; i < dest.size (); i++) 
      ed->addkey (dest[i]);
    ed->opts = (opts | KM_NWPWD | KM_ALL | KM_DLT | KM_KPPK);
    ed->kmgr = kmgr;
    ed->start ();
    
    return;
  }

  void start ()
  {
    if (!kmgr)
      kmgr = New sfskeymgr ();
    if (dest.size () == 0) {
      if (!(oki = kmgr->getkeyinfo ("#")))
	fatal << "No suitable key found.\n";
      if (oki->is_proactive ()) {
	dest.push_back ("#");
	go_proac ();
	return;
      } else {
	dest.push_back ("-");
      }
    } else {
      if (opts & KM_PROAC) {
	go_proac ();
	return;
      }
    }
    std_key_update ();
  }
  
  void std_key_update ()
  {
    str err;
    if (!(nki = kmgr->getkeyinfo ("#", opts)))
      fatal << "No suitable key target found\n";
    nki->keylabel = keylabel;
    if (!(nk = kmgr->fetch_or_gen (nki, &err, nbits, cost, opts)))
      fatal << err << "\n";
    if (!(opts & KM_NOSRP) && !kmgr->getsrp (srpfile))
      fatal << "Cannot find suitable SRP parameters.\n";
    
    bool errf = false;
    vec<str> keys;
    for (u_int i = 0; i < dest.size (); i++) {
      sfskeymgr::user_host_t uh;
      if (!kmgr->get_userhost (dest[i], &uh)) {
	warn << dest[i] << ": cannot parse hostname\n";
	errf = true;
      }
      if (!uh.sfspath)
	keys.push_back (uh.hash);
    }
    if (errf)
      exit (1);
    kmgr->add_keys (keys);

    if (!kmgr->save (nk, nki, opts))
      fatal << "Aborting update; cannot save key\n";

    kmgr->check_connect (dest, wrap (this, &passwdcmd::update));
  }

  void update ()
  {
    ncb = dest.size ();
    for (u_int i = 0; i < ncb; i++) 
      kmgr->update (nk, NULL, dest[i], opts,
		    wrap (this, &passwdcmd::updatecb, dest[i]));
  }
  
  void updatecb (str server, str err, bool gotconf)
  {
    if (err) {
      warn << server << ": updated failed:\n" << err << "\n";
      cberr = true;
    }
    if (--ncb == 0) {
      if (cberr) 
	warn << "WARNING: Not all servers were successfully updated.\n";
      exit (cberr ? 1 : 0);
    }
  }

};

void
sfskey_passwd (int argc, char *argv[])
{
  passwdcmd *pw = New passwdcmd ();
  u_int32_t opts = KM_FGEN;
 
  int ch;
  while ((ch = getopt (argc, argv, "KSpc:b:l:s:")) != -1) 
    switch (ch) {
    case 'K':
      opts |= KM_NOKBD;
      break;
    case 'S':
      opts |= KM_NOSRP;
      break;
    case 'p':
      opts |= KM_PROAC;
      break;
    case 'c':
      if (!convertint (optarg, &pw->cost))
	usage ();
      break;
    case 'b':
      if (!convertint (optarg, &pw->nbits))
	usage ();
      break;
    case 's':
      pw->srpfile = optarg;
      break;
    case 'l':
      pw->keylabel = optarg;
      break;
    default:
      usage ();
      break;
    }
  pw->opts = opts;
  for (int i = optind; i < argc; i++) {
    pw->dest.push_back (argv[i]);
  }
  pw->start ();
}
