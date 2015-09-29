/* $Id: sfskeylogin.C,v 1.24 2002/12/08 21:40:47 dm Exp $ */

/*
 *
 * Copyright (C) 2002 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

static void
shortsleep ()
{
  struct timeval t;
  t.tv_sec = 0;
  t.tv_usec = 100;
  select (0, NULL, NULL, NULL, &t);
}

str
str2rxx (str s)
{
  vec<char> cbuf;
  cbuf.push_back ('^');
  for (u_int i = 0; i < s.len (); i++) {
    if (!isalnum (s[i]))
      cbuf.push_back ('\\');
      cbuf.push_back (s[i]);
  }
  cbuf.push_back ('$');
  s = str (cbuf.base (), cbuf.size ());
  return s;
}

static void
make_symlink (ptr<sfscon> sc)
{
  struct stat sb;
  str name = strbuf () << sfsroot << "/" 
		       << sc->servinfo->get_hostname () ;
  str contents = strbuf () << sc->path;

  sfsagent_certprog prog;
  prog.filter = str2rxx (sc->servinfo->get_hostname ());
  prog.av.setsize (3);
  prog.av[0] = "/bin/sh";
  prog.av[1] = "-c";
  prog.av[2] = strbuf () << "echo " << contents;
  bool res;
  if (clnt_stat err 
      = aconn->cagent_ctl ()->scall (AGENTCTL_ADDCERTPROG, &prog, &res))
    fatal << "agent: " << err << "\n";
  if (!res)
    fatal << "agent refused certification program\n";
  lstat (name, &sb);
  shortsleep ();
  if (opt_verbose && !lstat (name, &sb))
    warn << "Adding symlink: " << name << " -> " 
	 << contents << "\n";
}

static void
make_realm (ptr<sfscon> sc, ptr<sfsauth_certinfores> ci)
{
  if (opt_verbose)
    warn << "Adding realm: " << ci->name << "\n";

  if (ci->info.certpaths->size () > 0) {
    sfsagent_certprog arg;

    arg.prefix = strbuf () << ci->name << "/";
    arg.av.setsize (ci->info.certpaths->size () + 1);
    arg.av[0] = "dirsearch";
    int i = 1;
    for (sfsauth_certpath *p = ci->info.certpaths->base (); 
	 p < ci->info.certpaths->lim (); p++) {
      if ((*p)[0] == '/')
	arg.av[i] = *p;
      else
	arg.av[i] = strbuf () << sfsroot << "/" << *p;
      i++;
    }

    bool res;
    if (clnt_stat err 
	= aconn->cagent_ctl ()->scall (AGENTCTL_ADDCERTPROG, &arg, &res))
      fatal << "agent: " << err << "\n";
    if (!res)
      fatal << "agent refused certification program\n";

    str realmdir = strbuf () << sfsroot << "/" << ci->name;
    struct stat sb;
    stat (realmdir, &sb);
    shortsleep ();
    if (!stat (realmdir, &sb) && S_ISDIR (sb.st_mode) && opt_verbose)
      warn << "Creating realm directory " << realmdir << "\n";
  }
}

static void
do_certinfo (ptr<sfscon> sc, ptr<sfsauth_certinfores> ci)
{
  assert (sc);
  assert (ci);

  switch (ci->info.status) {
  case SFSAUTH_CERT_SELF:
    make_symlink (sc);
    break;
  case SFSAUTH_CERT_REALM:
    make_realm (sc, ci);
    break;
  default:
    fatal << sc->path << ": invalid certinfo returned from server";
  }

  exit (0);
}

void
sfskey_login (int argc, char **argv)
{
  // Parse command-line args
  time_t expire = 0;
  int version = 1;

  int ch;
  while ((ch = getopt (argc, argv, "2t:")) != -1)
    switch (ch) {
    case '2':
      version = 2;
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

  if (optind + 1 != argc)
    usage ();

  str user;
  str host;
  if (!parse_userhost (argv[optind], &user, &host))
    fatal << "not of form [user@]hostname\n";

  // start agent if needed (sfsagent -c)
  agent_spawn (opt_verbose);

  // fetch keys (call into SRP code)
  str keyname = strbuf () << user << "@" << host;

  sfskey k;
  ptr<sfscon> sc;
  ptr<sfsauth_certinfores> ci;
  if (str err = sfskeyfetch (&k, keyname, &sc, &ci))
    fatal << err << "\n";

  if (!sc)
    fatal << "Invalid connection to authserver.\n";

  keyname = strbuf () << user << "@" 
		      << sc->servinfo->get_hostname ();
  if (!opt_quiet) {
    warnx << "SFS Login as " << keyname << "\n";
    if (ci->info.status == SFSAUTH_CERT_REALM)
      warnx << "Authserver is in realm " << ci->name << "\n";
  }

  sfs_addkey_arg arg;
  k.key->export_privkey (&arg.privkey);
  arg.expire = expire;
  arg.name = k.keyname;
  arg.key_version = version;
  bool res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_ADDKEY, &arg, &res))
    fatal << "agent: " << err << "\n";
  else if (!res && !opt_quiet)
    warn << "agent refused private key\n";

  do_certinfo (sc, ci);
}

void
sfskey_logout (int argc, char **argv)
{
  int ch;
  while ((ch = getopt (argc, argv, "")) != -1)
    switch (ch) {
    default:
      usage ();
      break;
    }

  if (optind + 1 != argc)
    usage ();

  str user;
  str host;
  if (!parse_userhost (argv[optind], &user, &host))
    fatal << "not of form [user@]{host | realm}\n";

  if (opt_verbose)
    warnx << "SFS Logout from host/realm " << host << "\n";

  bool found = false;

  struct stat sb;
  str realmdir = strbuf () << sfsroot << "/" << host;
  if (!lstat (realmdir, &sb)) {
    if (S_ISDIR (sb.st_mode)) {
      if (rmdir (realmdir) < 0) {
	if (!opt_quiet)
	  warn << realmdir << ": " << strerror (errno) << "\n";
      }
      else {
	found = true;
      }
    }
    else {
      if (unlink (realmdir) < 0) {
	if (!opt_quiet)
	  warn << realmdir << ": " << strerror (errno) << "\n";
      }
      else {
	found = true;
      }
    }
  }

  bool res;
  sfsauth_realm cparg = strbuf () << host << "/";
  if (clnt_stat err 
      = aconn->cagent_ctl ()->scall (AGENTCTL_CLRCERTPROG_BYREALM, 
				     &cparg, &res)) {
    if (!opt_quiet)
      warn << "agent: " << err << "\n";
  }
  else if (res)
    found = true;

  sfs_remauth_arg karg (SFS_REM_NAME);
  *karg.name = strbuf () << user << "@" << host;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_REMAUTH, &karg, &res)) {
    if (!opt_quiet)
      warn << "agent: " << err << "\n";
  }
  else if (res)
    found = true;

  if (!found && !opt_quiet)
    warnx << "You don't appear to be logged into realm/host "
	  << host << "!\n";

  exit (0);
}
