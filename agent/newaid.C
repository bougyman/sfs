/* $Id: newaid.C,v 1.20 2004/05/05 23:13:22 dm Exp $ */

/*
 *
 * Copyright (C) 1999 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

#include "sfsmisc.h"
#include "parseopt.h"
#include "sfsagent.h"
#include <unistd.h>
#include <grp.h>
#ifdef HAVE_SETUSERCONTEXT
# ifdef HAVE_LOGIN_CAP_H
#  include <login_cap.h>
# endif /* HAVE_LOGIN_CAP_H */
#endif /* HAVE_SETUSERCONTEXT */

int suidprotect = 1;
int execprotect = 1;

extern "C" {
AUTH *authunixint_create (const char *host, u_int32_t uid, u_int32_t gid,
			  u_int32_t ngroups, const u_int32_t *groups);
enum clnt_stat srpc_callraw (int fd,
			     u_int32_t prog, u_int32_t vers, u_int32_t proc,
			     xdrproc_t inproc, void *in,
			     xdrproc_t outproc, void *out, AUTH *auth);
}

static void
sfs_setlogin (uid_t nuid)
{
#if defined (HAVE_SETLOGIN) || defined (HAVE_SETUSERCONTEXT)
  struct passwd *pw;
  char *p;
  if (!(p = getenv ("USER")) || !(pw = getpwnam (p)) || pw->pw_uid != nuid)
    pw = getpwuid (nuid);
  if (!pw)
    fatal ("No pwent for UID %d\n", nuid);

#if defined (HAVE_SETUSERCONTEXT)
  if (setusercontext (NULL, pw, pw->pw_uid,
		      LOGIN_SETALL & ~(LOGIN_SETUSER|LOGIN_SETGROUP)) < 0)
    fatal ("setusercontext failed\n");
#elif defined (HAVE_SETLOGIN)
  if (setlogin (pw->pw_name) < 0)
    fatal ("setlogin %s: %m\n", pw->pw_name);
#endif /* HAVE_SETLOGIN */
#endif /* HAVE_SETLOGIN || HAVE_SETUSERCONTEXT */
}

static bool
gid_alloc (gid_t *gidp, uid_t uid)
{
  str path (sfssockdir << "/agent.sock");
  int fd = unixsocket_connect (path);
  if (fd < 0) {
    warn << path << ": " << strerror (errno) << "\n";
    return false;
  }
  close_on_exec (fd);

  AUTH *auth = authunixint_create ("localhost", uid, getgid (), 0, NULL);
  if (!auth)
    fatal ("could not create RPC authunix credentials\n");

  int32_t res (EIO);
  srpc_callraw (fd, SETUID_PROG, SETUID_VERS, SETUIDPROC_SETUID,
		xdr_void, NULL, xdr_int32_t, &res, auth);
  if (res) {
    close (fd);
    warn ("sfscd rejected credentials: %s\n", strerror (errno));
    return false;
  }

  u_int32_t gid (static_cast<u_int32_t> (sfs_badgid));
  clnt_stat stat = srpc_callraw (fd, AGENT_PROG, AGENT_VERS, AGENT_AIDALLOC,
				 xdr_void, NULL, xdr_u_int32_t, &gid, NULL);
  close (fd);
  if (stat || gid < sfs_resvgid_start
      || gid >= (sfs_resvgid_start + sfs_resvgid_count)) {
    warn << "no free group IDs.\n";
    return false;
  }
  *gidp = static_cast<gid_t> (gid);
  return true;
}

static bool
inrange (gid_t n)
{
  u_int32_t nn (n);
  return (n == (gid_t) nn && nn >= sfs_resvgid_start)
    && (nn < sfs_resvgid_start + sfs_resvgid_count);
}

static void
fixgroups (bool use_uid, uid_t uid, bool use_gid, gid_t gid)
{
  switch (0) case 0: case (NGROUPS_MAX >= 3):;
  if (use_gid && !inrange (gid))
    fatal << "gid " << gid << " not in range of reserved group ids\n";

  GETGROUPS_T group_buf[NGROUPS_MAX + 2];
  GETGROUPS_T *groups = group_buf + 2;
  GETGROUPS_T *grouplim;
  {
    int ngroups = getgroups (NGROUPS_MAX, groups);
    if (ngroups < 0)
      fatal ("getgroups: %m\n");
    grouplim = groups + ngroups;
  }

  gid_t g0 = (gid_t) -1;	// XXX - initialize to placate egcs
  if (sfsaid_shift)
    g0 = groups < grouplim ? *groups++ : getgid ();

  // Clear any old marker groups
  for (GETGROUPS_T *gp = groups; gp < grouplim; gp++)
    if (*gp == sfs_gid) {
      grouplim = groups;
      break;
    }

  if (use_uid) {
    grouplim = groups;
    *grouplim++ = uid;
    if (use_gid)
      *grouplim++ = gid;
    *grouplim++ = sfs_gid;
  }
  else {
    if (groups < grouplim && inrange (*groups))
      groups++;
    if (use_gid)
      *--groups = gid;
  }

  if (sfsaid_shift)
    *--groups = g0;
  if (setgroups (min<int> (grouplim - groups, NGROUPS_MAX), groups) < 0)
    fatal ("setgroups: %m\n");
}

static void
usage ()
{
  warnx << "usage: " << progname
	<< " [-{u|U} uid] [-G | -g gid] [-C dir] [program arg ...]\n";
  exit (1);
}

int
main (int argc, char **argv)
{
#ifdef MAINTAINER
  if (getenv ("SFS_RUNINPLACE")) {
    setgid (getgid ());
    setuid (getuid ());
  }
#endif /* MAINTAINER */
  setprogname (argv[0]);
  sfsconst_init ();

  const uid_t procuid = getuid ();
  uid_t newuid = procuid;
  uid_t uid = myaid () & INT64 (0xffffffff);
  gid_t gid;
  bool opt_gid = false;
  bool opt_login = false;
  bool opt_nogid = false;
  bool opt_U = false;
  str opt_chdir;
  size_t num_u = 0;

  int ch;
  while ((ch = getopt (argc, argv, "lu:U:g:GC:")) != -1)
    switch (ch) {
    case 'l':
      opt_login = true;
      break;
    case 'u':
      if (num_u++ || !convertint (optarg, &uid))
	usage ();
      break;
    case 'U':
      if (num_u++ || !convertint (optarg, &newuid))
	usage ();
      uid = newuid;
      opt_U = true;
      break;
    case 'g':
      if (opt_nogid || !convertint (optarg, &gid))
	usage ();
      opt_gid = true;
      break;
    case 'G':
      if (opt_gid)
	usage ();
      opt_nogid = true;
    case 'C':
      if (opt_chdir)
	usage ();
      opt_chdir = optarg;
      break;
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;

  if (procuid && (newuid != procuid || uid != procuid))
    fatal ("only root can change uids.\n");

  if (!opt_gid && !opt_nogid)
    opt_gid = gid_alloc (&gid, uid);

  fixgroups (newuid != uid, uid, opt_gid, gid);
  if (opt_U)
    sfs_setlogin (newuid);
  if (setgid (getgid ()) < 0 || setuid (newuid) < 0)
    fatal ("setuid/setgid: %m\n");

  vec<char *> av;
  char *path = argc > 0 ? argv[0] : getenv ("SHELL");
  if (!path)
    fatal ("no SHELL environment variable\n");
  av.push_back (path);
  for (int i = 1; i < argc; i++)
    av.push_back (argv[i]);
  av.push_back (NULL);

  str av0;
  if (opt_login) {
    const char *p = strrchr (path, '/');
    p = p ? p + 1 : path;
    av0 = strbuf ("-%s", p);
    av[0] = const_cast<char *> (av0.cstr ());
  }

  if (opt_chdir) {
    if (chdir (opt_chdir) < 0)
      warn << opt_chdir << ": " << strerror (errno) << "\n";
    else if (opt_chdir[0] == '/') {
      str e (strbuf ("PWD=%s", opt_chdir.cstr ()));
      xputenv (e);
    }
    else if (const char *p = getenv ("PWD")) {
      str e (strbuf ("PWD=%s/%s", p, opt_chdir.cstr ()));
      xputenv (e);
    }
  }

  str aidvar (strbuf ("SFS_AID=") << myaid ());
  xputenv (aidvar);

  /* The SFS libraries use asynchronous IO which some programs don't
   * like.  Thus, we remove the O_NONBLOCK flag from stdin/stdout. */
  make_sync (0);
  make_sync (1);

  execvp (path, av.base ());
  warnx ("%s: %m\n", path);
  return 1;
}
