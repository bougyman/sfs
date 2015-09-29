/* $Id: sfscd.C,v 1.54 2004/09/19 22:02:29 dm Exp $ */

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
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


#include "sfscd.h"
#include <pwd.h>
#include <grp.h>

#include "parseopt.h"

#if FIX_MNTPOINT
bool opt_fix_mntpoint = true;
#endif /* FIX_MNTPOINT */

rxx namedprotrx ("^(\\w+):[\\x21-\\x7e]+$");

bool nomounting;

ihash<vec<str>, cdaemon, &cdaemon::argv, &cdaemon::hlink> &daemontab
  (*New ihash<vec<str>, cdaemon, &cdaemon::argv, &cdaemon::hlink>);
static itree<const u_int32_t, release, &release::rel, &release::link> &reltab
  (*New itree<const u_int32_t, release, &release::rel, &release::link>);
vec<sfs_extension> sfs_extensions;
bhash<in_addr> badaddrs;
ihash<const str, named_protocol,
  &named_protocol::name, &named_protocol::link> &nptab
    (*New ihash<const str, named_protocol,
     &named_protocol::name, &named_protocol::link>);

#ifdef HAVE_NFS_V3
int v3flag = NMOPT_NFS3;
#else /* !HAVE_NFS_V3 */
int v3flag = 0;
#endif /* !HAVE_NFS_V3 */

static const char *
stripdir (const char *s)
{
  const char *p = strrchr (s, '/');
  return p ? p + 1 : s;
}

cdaemon::cdaemon (const vec<str> &av)
  : argv (av)
{
  daemontab.insert (this);
}

cdaemon::~cdaemon ()
{
  daemontab.remove (this);
}

static void
relaunch (cdaemon *cdp)
{
  cdp->launch (false);
}
void
cdaemon::eof ()
{
  warn << argv[0] << ": EOF\n";
  x = NULL;
  c = NULL;
  s = NULL;
  for (srvinfo *si = servers.first; si; si = servers.next (si))
    si->destroy (true);
  delaycb (5, wrap (relaunch, this));
}

static void
do_newpg ()
{
  setpgid (0, 0);
}
bool
cdaemon::launch (bool sync)
{
  static cbv newpg (wrap (do_newpg));
  if (sync)
    x = axprt_unix_spawnv (argv[0], argv, 0, newpg);
  else
    x = axprt_unix_aspawnv (argv[0], argv, 0, newpg);
  if (x) {
    c = aclnt::alloc (x, sfscd_program_1);
    s = asrv::alloc (x, sfscdcb_program_1, wrap (this, &cdaemon::dispatch));

    sfscd_initarg ia;
    ia.name = name;
    c->call (SFSCDPROC_INIT, &ia, NULL, aclnt_cb_null);
  }
  else
    c = NULL;
  return c;
}

void
cdaemon::dispatch (svccb *sbp)
{
  if (!sbp) {
    eof ();
    return;
  }
  switch (sbp->proc ()) {
  case SFSCDCBPROC_NULL:
    sbp->reply (NULL);
    break;
  case SFSCDCBPROC_AGENTREQ:
    {
      sfscd_agentreq_arg *aa = sbp->Xtmpl getarg<sfscd_agentreq_arg> ();
      if (aa->agentreq.type == AGENTCB_AUTHINIT) {
	  if (aa->agentreq.init->requestor.len ())
	    aa->agentreq.init->requestor
	      = name << "!" << aa->agentreq.init->requestor;
	  else
	    aa->agentreq.init->requestor = name;
      }
      if (usrinfo *ui = usrtab[aa->aid])
	ui->authreq (&aa->agentreq, sbp);
      else
	sbp->replyref (sfsagent_auth_res (false));
      break;
    }
  case SFSCDCBPROC_IDLE:
    srvinfo::idle (*sbp->Xtmpl getarg<nfspath3> (), this);
    sbp->reply (NULL);
    break;
  case SFSCDCBPROC_DELFS:
    srvinfo::destroy (*sbp->Xtmpl getarg<nfspath3> (), this, false);
    sbp->reply (NULL);
    break;
  case SFSCDCBPROC_HIDEFS:
    //flushpath (*sbp->Xtmpl getarg<nfspath3> ());
    srvinfo::show (*sbp->Xtmpl getarg<nfspath3> (), this, false);
    sbp->reply (NULL);
    break;
  case SFSCDCBPROC_SHOWFS:
    srvinfo::show (*sbp->Xtmpl getarg<nfspath3> (), this, true);
    sbp->reply (NULL);
    break;
  }
}

release::release (u_int32_t r)
  : rel (r), libdir (execdir)
{
  reltab.insert (this);
}

release *
release::lookup (u_int32_t r)
{
  release *rp, *ret;
  ret = rp = reltab.root ();
  while (rp) {
    if (r <= rp->rel && rp->rel <= ret->rel)
      ret = rp;
    if (r <= rp->rel)
      rp = reltab.left (rp);
    else
      rp = reltab.right (rp);
  }
  return ret;
}

cdaemon *
release::cdlookup (u_int32_t rel, u_int32_t prog, u_int32_t vers)
{
  for (release *r = lookup (rel); r; r = reltab.next (r))
    if (prot *pp = r->prots (prog, vers))
      return pp->cdp;
  return NULL;
}

static void
parseconfig (str cf)
{
  parseargs pa (cf);
  bool errors = false;

  int line;
  vec<str> av;
  qhash<str, int> dnotab;
  release *r = NULL;

  while (pa.getline (&av, &line)) {
    if (!strcasecmp (av[0], "Extension")) {
      if (av.size () != 2) {
	warn << cf << ":" << line << ": usage Extension name\n";
	errors = true;
	continue;
      }
      sfs_extensions.push_back (av[1]);
    }
    else if (!strcasecmp (av[0], "Release")) {
      static rxx relrx ("^(\\d+)\\.(\\d\\d?)$");
      if (av.size () != 2 || (!relrx.search (av[1]) && av[1] != "*")) {
	warn << cf << ":" << line << ": usage Release { N.NN | * }\n";
	errors = true;
	r = NULL;
	continue;
      }
      u_int32_t rel;
      if (av[1] == "*")
	rel = 0xffffffff;
      else
	rel = strtoi64 (relrx[1]) * 100 + strtoi64 (relrx[2]);
      r = reltab[rel];
      if (!r)
	r = New release (rel);
    }
    else if (!strcasecmp (av[0], "Libdir")) {
      if (av.size () != 2 || av[1][0] != '/') {
	warn << cf << ":" << line << ": usage Libdir /path/to/lib/sfs\n";
	errors = true;
	r = NULL;
	continue;
      }
      if (!r) {
	warn << cf << ":" << line << ": Libdir must follow Release\n";
	errors = true;
	r = NULL;
	continue;
      }
      r->libdir = av[1];
    }
    else if (!strcasecmp (av[0], "Program")) {
      if (!r) {
	warn << cf << ":" << line
	     << ": Program must follow Release\n";
	errors = true;
	continue;
      }
      static rxx progrx ("^(\\d+)\\.(\\d+)$");
      if (av.size () < 3 || !progrx.search (av[1])) {
	warn << cf << ":" << line
	     << ": usage: Program prog.vers daemon [arg ...]\n";
	errors = true;
	continue;
      }
      int32_t prog = strtoi64 (progrx[1]), vers = strtoi64 (progrx[2]);
      av.pop_front ();
      av.pop_front ();
      av[0] = fix_exec_path (av[0], r->libdir);
      if (r->prots (prog, vers)) {
	warn << cf << ":" << line
	     << ": Program " << prog << "." << vers
	     << " already specified\n";
	errors = true;
	continue;
      }
      cdaemon *cdp = daemontab[av];
      if (!cdp) {
	cdp = New cdaemon (av);
	cdp->name = stripdir (av[0]);
	if (!dnotab[cdp->name])
	  dnotab.insert (cdp->name, 0);
	cdp->name = cdp->name << "_" << ++*dnotab[cdp->name];
	if (!cdp->launch (true)) {
	  warn << cf << ":" << line << ": " << av[0] << ": "
	       << strerror (errno) << "\n";
	  // errors = true;	/* Don't make this a fatal error */
	  delete cdp;
	  continue;
	}
      }
      r->prots.insert (New release::prot (prog, vers, cdp));
    }
    else if (!strcasecmp (av[0], "Protocol")) {
      if (av.size () < 3) {
	warn << cf << ":" << line
	     << ": usage: Protocol name daemon [arg ...]\n";
	errors = true;
	continue;
      }
      static rxx protrx ("^\\w+$");
      if (!protrx.search (av[1])) {
	warn << cf << ":" << line << ": '" << av[1]
	     << "' contains non-alphanumeric character\n";
	errors = true;
	continue;
      }
      str name = av[1];
      av.pop_front ();
      av.pop_front ();
      av[0] = fix_exec_path (av[0]);
      if (nptab[name]) {
	warn << cf << ":" << line
	     << ": Protocol " << name << " already specified\n";
	errors = true;
	continue;
      }
      cdaemon *cdp = daemontab[av];
      if (!cdp) {
	cdp = New cdaemon (av);
	cdp->name = stripdir (av[0]);
	if (!dnotab[cdp->name])
	  dnotab.insert (cdp->name, 0);
	cdp->name = cdp->name << "_" << ++*dnotab[cdp->name];
	if (!cdp->launch (true)) {
	  warn << cf << ":" << line << ": " << av[0] << ": "
	       << strerror (errno) << "\n";
	  // errors = true;	/* Don't make this a fatal error */
	  delete cdp;
	  continue;
	}
      }
      nptab.insert (New named_protocol (name, cdp));
    }
    else {
      errors = true;
      warn << cf << ":" << line << ": Unknown directive '"
	   << av[0] << "'\n";
    }
  }

  if (errors)
    fatal << "errors in configuration file\n";
}

static void
nullfn ()
{
}

static void
drop_privs (void)
{
#if 0
  setgid (sfs_gid);
  setgroups (0, NULL);
  setuid (sfs_uid);
#else
  warn << "not dropping privileges for debugging\n";
#endif
  if (chdir (sfsdir) < 0)
    fatal ("%s: %m\n", sfsdir.cstr ());
}

static void
usage ()
{
  warnx << "usage: " << progname << " [-2dl] [-f configfile]\n";
  exit (1);
}

extern char *optarg;
extern int optind;

int
main (int argc, char **argv)
{
  bool opt_allowlocal = false;
  bool opt_nodaemon = false;
  str configfile;
  setprogname (argv[0]);

  int ch;
  while ((ch = getopt (argc, argv, "2df:lL")) != -1)
    switch (ch) {
    case '2':
      v3flag = 0;
      break;
    case 'd':
      opt_nodaemon = true;
      break;
    case 'f':
      configfile = optarg;
      break;
    case 'l':
      opt_allowlocal = true;
      break;
    case 'L':
#if FIX_MNTPOINT
      opt_fix_mntpoint = false;
#endif /* FIX_MNTPOINT */
      break;
    case '?':
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;

  if (argc > 0)
    usage ();

#ifdef MAINTAINER
  if (getenv ("SFS_NOMOUNTING"))
    nomounting = true;
#endif /* MAINTAINER */
  umask (0);
  sfsconst_init ();

  if (!configfile)
    configfile = sfsconst_etcfile_required ("sfscd_config");

  struct stat sb;
  if (stat (sfsroot, &sb) < 0 && errno == ENOENT && mkdir (sfsroot, 0555) < 0)
    fatal ("mkdir (%s): %m\n", sfsroot);

  str mnt (strbuf ("%s/.mnt", sfsroot));
  if (!access (mnt, F_OK))
    fatal << mnt << " exists, sfscd already running\n";

  if (!opt_nodaemon && !runinplace)
    daemonize ();
  parseconfig (configfile);

  if (!opt_allowlocal) {
    vec<in_addr> av;
    if (!myipaddrs (&av))
      fatal ("cannot get by IP addresses: %m\n");
    for (const in_addr *ip = av.base (); ip < av.lim (); ip++)
      badaddrs.insert (*ip);
  }

  warn ("version %s, pid %d\n", VERSION, int (getpid ()));

  mnt_init ();

  drop_privs ();
  random_init_file (sfsdir << "/random_seed");

  usrinfo_init ();
  afs_init (wrap (nullfn));

  amain ();
  return 0;
}
