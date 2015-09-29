/* $Id: sfskeyctl.C,v 1.40 2004/05/14 23:46:03 max Exp $ */

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
#include "rxx.h"
#include "sfscrypt.h"
#include "sfskeymgr.h"

void sfskey_add_cb1 (sfskeymgr *kmgr, sfskeyinfo *ki, time_t ex, sfskey *k);
void sfskey_add_cb2 (sfskeymgr *kmgr, sfskeyinfo *ki, ptr<bool> res, 
		     clnt_stat err);
void sfskey_add_cb3 (clnt_stat err);

void
sfskey_add (int argc, char **argv)
{
  time_t expire = 0;

  int ch;
  while ((ch = getopt (argc, argv, "2t:")) != -1)
    switch (ch) {
    case 't':
      {
	rxx hmrx ("^((\\d+):)?(\\d+)?$");
	int hrs = 0, min = 0;
	if (!hmrx.search (optarg)
	    || (hmrx[3] && !convertint (hmrx[3], &min))
	    || (hmrx[2] && (!convertint (hmrx[2], &hrs) || min > 60))
	    || min < 0 || hrs < 0)
	  usage ();
	expire = 3600 * hrs + 60 * min;
	if (expire)
	  expire += time (NULL);
	break;
      }
    default:
      usage ();
      break;
    }

  agent_setsock ();
  str keyname;
  if (optind + 1 == argc)
    keyname = argv[optind];
  else if (optind != argc)
    usage ();

  sfskeymgr *kmgr = New sfskeymgr (NULL, (KM_NOCRT | KM_NODCHK));
  sfskeyinfo *ki = kmgr->getkeyinfo_list (keyname, 0);
  if (!ki) 
    fatal << "No suitable key found\n";
  kmgr->fetch_from_list (ki, (wrap (sfskey_add_cb1, kmgr, ki, expire)));
}

void
sfskey_add_cb1 (sfskeymgr *kmgr, sfskeyinfo *ki, time_t expire, sfskey *k)
{
  if (!k) 
    fatal << "No suitable key found\n";

  sfs_addkey_arg arg;
  k->key->export_privkey (&arg.privkey);
  arg.expire = expire;
  arg.name = k->keyname;
  ptr<bool> res = New refcounted<bool> ();
  aconn->cagent_ctl ()->call (AGENTCTL_ADDKEY, &arg, res,
			      wrap (sfskey_add_cb2, kmgr, ki, res));
}

void
sfskey_add_cb2 (sfskeymgr *kmgr, sfskeyinfo *ki, ptr<bool> res, clnt_stat err)
{
  if (err)
    fatal << err << "\n";
  if (!*res)
    warn << "agent refused private key\n";
  ptr<sfscon> sc = kmgr->getsrpcon (ki);
  if (sc) { 
    sfsagent_symlink_arg arg;
    arg.name = sc->servinfo->get_hostname ();
    arg.contents = sc->path;
    aconn->cagent_ctl ()->call (AGENTCTL_SYMLINK, &arg, NULL, 
				wrap (sfskey_add_cb3));
  }
  exit (0);
}

void
sfskey_add_cb3 (clnt_stat err)
{
  exit (0);
}

void
sfskey_list (int argc, char **argv)
{
  bool opt_l = false, opt_q = false;
  int ch;
  while ((ch = getopt (argc, argv, "lq")) != -1)
    switch (ch) {
    case 'l':
      opt_l = true;
      break;
    case 'q':
      opt_q = true;
      break;
    default:
      usage ();
      break;
    }
  if (optind < argc)
    usage ();

  sfs_keylist kl;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_DUMPKEYS, NULL, &kl))
    fatal << "agent: " << err << "\n";

  sfs_time now = time (NULL);
  strbuf list;
  ptr<sfspub> pubkey;
  strbuf kstr;

  if (!opt_q)
    list.fmt ("%-50s  %9s%s\n", "NAME", "EXPIRE",
	      opt_l ? "  KEY/PID" : "");
  for (sfs_keylistelm *e = kl; e; e = e->next) {
    list.fmt ("%-50s", e->name.cstr ());
    if (!e->expire)
      list.fmt ("  %9s", "never");
    else {
      sfs_time life = e->expire < 0 ? 0 : e->expire - now;
      list.fmt ("  % 3" U64F "d:%02" U64F "d'%02" U64F "d",
		life / 3600, life / 60 % 60, life % 60);
    }
    if (opt_l && e->desc)
      list << " " << e->desc ;
    
    list << "\n";
  }

  make_sync (1);
  list.tosuio ()->output (1);
  exit (0);
}

void
sfskey_clear (int argc, char **argv)
{
  nularg (argc, argv);
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_REMALLKEYS, NULL, NULL))
    fatal << "agent: " << err << "\n";
  exit (0);
}

void
sfskey_delete (int argc, char **argv)
{
  if (getopt (argc, argv, "") != -1 || optind + 1 != argc)
    usage ();
  sfs_remauth_arg arg (SFS_REM_NAME);
  *arg.name = argv[optind];
  bool res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_REMAUTH, &arg, &res))
    fatal << "agent: " << err << "\n";
  else if (!res)
    fatal << "agent: could not delete key\n";
  exit (0);
}

void
sfskey_reset (int argc, char **argv)
{
  nularg (argc, argv);
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_RESET, NULL, NULL))
    fatal << "agent: " << err << "\n";
  exit (0);
}

static void
sfskey_gethashcb (int base, int *c, sfskeyinfo *i, int vers,
		  str err, ptr<sfspub> k)
{
  str h;
  if (!k && !err)
    err = "no public key returned from server";
  if (err) {
    if (i) warnx << i->fn () << ": ";
    warnx << err << "\n";
  } else if (!(h = k->get_pubkey_hash (vers))) {
    if (i) warnx << i->fn () << ": ";
    warnx << "error in sha1_hashxdr of public key\n";
  } else {
    h = (base == 32) ? armor32 (h) : armor64 (h);
    if (i) printf ("%s: ", i->fn ().cstr ());
    printf ("%s\n", h.cstr ());
  }
  if (!--(*c))
    exit (0);
}

void
sfskey_gethash (int argc, char **argv)
{
  int ch;
  int base = 32;
  int vers = 2;
  while ((ch = getopt (argc, argv, "6p")) != -1)
    switch (ch) {
    case '6':
      base = 64;
      break;
    default:
      usage ();
    }
  sfskeymgr *km = New sfskeymgr (NULL, (KM_NOCRT | KM_NODCHK));

  int n = argc - optind;
  int *c = New int (n);
  for (int i = optind; i < argc; i++) {
    sfskeyinfo *ki;
    if (!(ki = km->getkeyinfo (argv[i], KM_PKONLY)))
      fatal << "No suitable key found\n";
    km->fetchpub (ki, wrap (&sfskey_gethashcb, base, c, n > 1 ? ki : NULL, 
			    vers));
  }
}

void
sfskey_select (int argc, char **argv)
{
  int ch;
  u_int32_t opts = 0;
  while ((ch = getopt (argc, argv, "f")) != -1)
    switch (ch) {
    case 'f':
      opts |= KM_FRCLNK;
      break;
    default:
      usage ();
    }
  str keyname;
  if (argc == optind + 1)
    keyname = argv[optind];
  else if (argc > optind + 1)
    usage ();
  
  sfskeymgr km;
  sfskeyinfo *ki;

  if (!(ki = km.getkeyinfo (keyname, opts)))
    fatal << "No suitable key found\n";
  if (ki->remote)
    fatal << "Cannot select a remote key\n";
  str raw;
  str fn = ki->afn ();
  if (!(raw = file2str (fn)))
    fatal << fn << ": cannot access key\n";
  ptr<sfspub> p;
  if (!(p = sfscrypt.alloc_from_priv (raw)))
    fatal << fn << ": cannot parse key\n";
  if (!km.select (ki, opts))
    fatal << "Key select failed; consider -f flag to force overwrite\n";
  exit (0);
}

