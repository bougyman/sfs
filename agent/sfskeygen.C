/* $Id: sfskeygen.C,v 1.46 2003/03/01 15:25:33 max Exp $ */

/*
 *
 * Copyright (C) 1999 Michael Kaminsky (kaminsky@lcs.mit.edu)
 * Copyright (C) 1998, 1999 David Mazieres (dm@uun.org)
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

void
sfskey_edit (int argc, char **argv)
{
  bool nopwd = false;
  u_int cost = 0;
  str outfile, comment, keyname;
  u_int32_t opts = 0;

  int ch;
  while ((ch = getopt (argc, argv, "LPo:c:l:")) != -1)
    switch (ch) {
    case 'P':
      nopwd = true;
      break;
    case 'o':
      outfile = optarg;
      break;
    case 'c':
      if (!convertint (optarg, &cost))
	usage ();
      if (cost > sfs_maxpwdcost)
	fatal ("password cost must be far less than %d\n", sfs_mindlogsize);
      break;
    case 'l':
      comment = optarg;
      break;
    case 'L':
      opts |= KM_NOLNK;
      break;
    default:
      usage ();
      break;
    }

  if (argc == optind + 1)
    keyname = argv[optind];
  else if (argc != optind)
    usage ();

  sfskeyinfo *oki, *nki = NULL;
  sfskeymgr kmgr;
  sfskey *k;
  str err;

  if (!(oki = kmgr.getkeyinfo (keyname, opts)))
    fatal << "No suitable input key found\n";
  if (!(k = kmgr.fetch (oki, &err)))
    fatal << err << "\n";
  if (outfile) {
    u_int32_t topts = opts | KM_NOSRC | KM_FGEN;
    if (oki->is_proactive ())
      topts |= KM_PROAC;
    nki = (outfile == "#")  ? kmgr.getkeyinfo (k, topts) : 
      kmgr.getkeyinfo (outfile, topts);
    if (k->key->get_type () == SFS_2SCHNORR)
      topts |= KM_PROAC;
    if (!nki)
      fatal << "No suitable output key location found\n";
    if (nki->exists) 
      fatal << nki->afn () << ": file exists\n";
  } else {
    nki = oki;
    opts |= KM_FRC;
  }

  if (nki->remote)
    fatal ("must specify a local output file with -o\n");

  random_start ();

  if (outfile)
    warnx << "Copying key " << oki->afn () << " to " << nki->afn () << ".\n";
  else if (nopwd)
    warnx << "Removing passphrase from key " << oki->afn () << ".\n";
  else
    warnx << "Editing passphrase on key " << oki->afn () << ".\n";


  nki->gen = true;

  if (cost)
    k->cost = cost;
  if (comment)
    k->keyname = comment;
  if (nopwd)
    k->pwd = NULL;
  else if (!oki->remote)
    k->pwd = getpwdconfirm ("  New passphrase: ");

  random_init ();
  bool rc = kmgr.save (k, nki, opts);
  exit (rc ? 0 : 1);
}

void
sfskey_gen (int argc, char **argv)
{
  u_int nbits = 0, cost = 0;
  str keyname, keylabel, user;
  u_int32_t opts = KM_FGEN;

  int ch;
  while ((ch = getopt (argc, argv, "eb:c:l:u:KP")) != -1)
    switch (ch) {
    case 'e':
      opts |= KM_ESIGN;
      break;
    case 'b':
      if (!convertint (optarg, &nbits))
	usage ();
      break;
    case 'c':
      if (!convertint (optarg, &cost))
	usage ();
      if (cost > sfs_maxpwdcost)
	fatal ("password cost must be far less than %d\n", sfs_mindlogsize);
      break;
    case 'l':
      keylabel = optarg;
      break;
    case 'u':
      user = optarg;
      break;
    case 'K':
      opts |= KM_NOKBD;
      break;
    case 'P':
      opts |= KM_NOPWD;
      break;
    default:
      usage ();
      break;
    }

  if (optind + 1 == argc)
    keyname = argv[optind];
  else if (optind != argc)
    usage ();

  str err;
  sfskeymgr kmgr (user);
  sfskeyinfo *ki;
  sfskey *k;
  if (!(ki = kmgr.getkeyinfo (keyname, opts)))
    fatal << "No suitable key target found\n";
  ki->keylabel = keylabel;
  if (!(k = kmgr.fetch_or_gen (ki, &err, nbits, cost, opts)))
    fatal << err << "\n";
  if (!kmgr.save (k, ki, opts))
    fatal << "Not all key save operations succeeded\n";
  exit (0);
}

void
sfskey_srpgen (int argc, char **argv)
{
  u_int nbits = sfs_dlogsize;
  int ch;
  while ((ch = getopt (argc, argv, "b:")) != -1)
    switch (ch) {
    case 'b':
      if (!convertint (optarg, &nbits))
	usage ();
      if (nbits < srp_base::minprimsize)
	fatal ("srp primes must be at least %d bits\n",
	       srp_base::minprimsize);
      break;
    default:
      usage ();
      break;
    }
  if (optind + 1 != argc)
    usage ();

  random_set_seedfile (RANDOM_SEED);
  random_init ();

  warnx ("Generating SRP parameters.  This can take several minutes...");
  err_flush ();
  bigint N, g;
  srp_base::genparam (nbits, &N, &g);
  warnx (" done\n");

  if (!str2file (argv[optind], export_srp_params (N, g), 0444))
    fatal ("%s: %m\n", argv[optind]);
  exit (0);
}
