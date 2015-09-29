/*
 *
 * Copyright (C) 1999 Frans Kaashoek (kaashoek@lcs.mit.edu)
 * Copyright (C) 1999 David Mazieres (dm@lcs.mit.edu)
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
sfskey_norevokelist (int argc, char **argv)
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

  sfsagent_norevoke_list res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_GETNOREVOKE, NULL, &res))
    fatal << "agent: " << err << "\n";

  strbuf list;
  if (!opt_q)
    list.fmt ("%s\n", "HOSTID");
  for (sfs_hash *p = res.base (); p < res.lim (); p++) {
    list << armor32 (p, sizeof (*p)) << "\n";
  }

  make_sync (1);
  list.tosuio ()->output (1);
  exit (0);
}

void
sfskey_norevokeset (int argc, char **argv)
{
  vec<sfs_hash> revvec;
  sfsagent_norevoke_list arg;
  
  for (int i = optind; i < argc; i++) {
    sfs_hash h;
    if (!sfs_ascii2hostid (&h, argv[i])) {
      warnx << "sfskey_norevokeset: invalid hostid\n";
      exit(-1);
    }
    revvec.push_back (h);
  }
  arg.set (revvec.base (), revvec.size ());
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_SETNOREVOKE, &arg, NULL))
    fatal << "agent: " << err << "\n";
  exit(0);
}

void
sfskey_revokeclear (int argc, char **argv)
{
  nularg (argc, argv);
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_CLRREVOKEPROGS, NULL, NULL))
    fatal << "agent: " << err << "\n";
  exit (0);
}

void 
sfskey_revokegen (int argc, char **argv)
{
  str hostname;
  str keyname;
  sfskey k;
  str newkeyname;
  str newhostname;
  sfskey newk;

  int ch;
  while ((ch = getopt (argc, argv, "n:o:r:")) != -1)
    switch (ch) {
    case 'o':
      hostname = optarg;
      break;
    case 'r':
      newkeyname = optarg;
      break;
    case 'n':
      if (!newkeyname) 
	usage ();
      newhostname = optarg;
    default:
      usage ();
      break;
    }
  if (argc != optind + 1)
    usage ();

  keyname = argv[optind];
  if (!hostname && !(hostname = sfshostname ()))
    fatal ("could not find my own hostname\n");
  if (str err = sfskeyfetch (&k, keyname))
    fatal << err << "\n";
  if (!strchr (hostname, '.')) {
    str dom = mydomain ();
    hostname = hostname << "." << dom;
  }
  if (newkeyname) {
    if (str err = sfskeyfetch (&newk, newkeyname))
      fatal << err << "\n";
    if (!newhostname && !(newhostname = sfshostname ()))
      fatal ("could not find my own hostname\n");
    if (!strchr (newhostname, '.')) {
      str dom = mydomain ();
      newhostname = newhostname << "." << dom;
    }
  }

  sfs_pathrevoke cert;
  cert.msg.type = SFS_PATHREVOKE;
  cert.msg.path.type = SFS_HOSTINFO;
  cert.msg.path.hostname = hostname;
  k.key->export_pubkey (&cert.msg.path.pubkey);
  if (newkeyname) {
    cert.msg.redirect.alloc ();
    cert.msg.redirect->serial = 0;
    cert.msg.redirect->expire = 0;
    cert.msg.redirect->hostinfo.type = SFS_HOSTINFO;
    cert.msg.redirect->hostinfo.hostname = newhostname;
    newk.key->export_pubkey (&cert.msg.redirect->hostinfo.pubkey);
  }

  str rawmsg (xdr2str (cert.msg));
  if (!rawmsg)
    fatal << "revoke: could not marshal cert.msg\n";
  if (!k.key->sign (&cert.sig, rawmsg))
    fatal << "Could not sign revocation certificate\n";
  sfs_pathrevoke_w prw (cert);
  str rawcert (xdr2str (cert));
  if (!rawcert)
    fatal << "revoke: could not marshal cert\n";
  sfs_hash hostid;
  if (!prw.si->mkhostid (&hostid))
    fatal << "Couldn't make hostid\n";
  str p = armor32 (&hostid, sizeof (hostid));
  if (!str2file (p, rawcert, 0444, true))
    fatal << "Couldn't create " << p << "\n";
  exit(0);
}

void
sfskey_revokelist (int argc, char **argv)
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

  sfsagent_revokeprogs res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_DUMPREVOKEPROGS, NULL, &res))
    fatal << "agent: " << err << "\n";

  strbuf list;
  if (!opt_q)
    list.fmt ("%-8s %-8s %-8s %s\n", "BLOCK", "FILTER", "EXCLUDE", "PROGRAM");
  for (sfsagent_revokeprog *p = res.base (); p < res.lim (); p++) {
    if (p->block)
      list.fmt ("%-8s %-8s %-8s", "***", p->block->filter.cstr (), 
		p->block->exclude.cstr ());
    else
      list.fmt ("%-8s %-8s %-8s", "", "", "");
    for (sfsagent_progarg *a = p->av.base (); a < p->av.lim (); a++)
      list << " " << *a;
    list << "\n";
  }

  make_sync (1);
  list.tosuio ()->output (1);
  exit (0);
}

void
sfskey_revokeprog (int argc, char **argv)
{
  sfsagent_revokeprog arg;
  bool block = false;
  str filter;
  str exclude;

  int ch;
  while ((ch = getopt (argc, argv, "bf:e:")) != -1)
    switch (ch) {
    case 'b':
      if (block)
	usage ();
      block = true;
    case 'e':
      if (!block || exclude)
	usage ();
      exclude = optarg;
      break;
    case 'f':
      if (!block || filter)
	usage();
      filter = optarg;
      break;
    default:
      usage ();
      break;
    }
  if (optind >= argc)
    usage ();

  if (block) {
    if (!filter)
      filter = "";
    if (!exclude) 
      exclude = "";
    arg.block.alloc ();
    arg.block->filter = filter;
    arg.block->exclude = exclude;
  }

  arg.av.setsize (argc - optind);
  for (int i = optind; i < argc; i++)
    arg.av[i - optind] = argv[i];
  bool res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_ADDREVOKEPROG, &arg, &res))
    fatal << "agent: " << err << "\n";
  if (!res)
    fatal << "agent refused revoke program\n";
  exit (0);
}

void
sfskey_revoke (int argc, char **argv)
{
  if (getopt (argc, argv, "") != -1 || optind != argc - 1)
    usage ();
  str file (argv[optind]);
  int fd;
  if (file == "-") {
    fd = 0;
    make_sync (fd);
  }
  else if ((fd = open (file, O_RDONLY)) < 0)
    fatal ("%s: %m\n", file.cstr ());
  if (isatty (fd))
    fatal ("cannot read revocation certificate from a tty.\n");

  char buf[8192];
  int n = read (fd, buf, 8192);
  if (n < 0)
    fatal ("read: %m\n");

  xdrmem x (buf, n);
  sfs_pathrevoke cert;
  if (!buf2xdr (cert, buf, n))
    fatal ("invalid revocation certificate\n");
  sfs_pathrevoke_w prw (cert);
  if (!prw.check ()) 
    fatal ("invalid revocation certificate\n");
  if (clnt_stat err = aconn->ccd ()->scall (AGENT_REVOKE, &cert, NULL))
    fatal << "sfscd: " << err << "\n";
  exit (0);
}
