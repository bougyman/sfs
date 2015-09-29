/* $Id: sfsauthd.C,v 1.68 2004/06/28 04:13:25 dm Exp $ */

/*
 *
 * Copyright (C) 2001 David Mazieres (dm@uun.org)
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

#include "authdb.h"
#include "authdb_db.h"
#include "sfsauthd.h"
#include "authgrps.h"
#include "parseopt.h"
#include "rxx.h"

ptr<sfspriv> myprivkey;
sfs_servinfo myservinfo;
ptr<sfs_servinfo_w> siw;
str sfsauthcachedir;
str sfsauthdbcache = "";
sfs_hash myhostid;
vec<dbfile> dbfiles;
str sfsauthrealm = "";
vec<sfsauth_certpath> sfsauthcertpaths;
str logfile = "";
str authd_syslog_priority = "";
int logfd = -1;
str srpparms = NULL;
time_t dbcache_refresh_delay = 0;
str auth_helper;

#ifndef SLEEPYCAT
# define DEFAULT_DBCACHE "dbcache"
#else
# define DEFAULT_DBCACHE "dbcache.db/"
#endif

void
xfer::start ()
{
  static str xferpath;
  if (pid != -1)
    return;
  if (!xferpath)
    xferpath = fix_exec_path ("xfer");
  const char *av[] = { xferpath, "--", src, dst, NULL };
  if ((pid = aspawn (xferpath, av)) != -1)
    chldcb (pid, wrap (mkref (this), &xfer::stop));
}

inline str
path2name (str path)
{
  char hash[sha1::hashsize];
  sha1_hash (hash, path, path.len ());
  str name = armor64A (hash, sizeof (hash));
  if (path.len () > 3 && !strcmp (path.cstr () + path.len () - 3, ".db"))
    name = name << ".db";
  return name;
}

ptr<xfer>
mkcache (str src)
{
  assert (src[0] == '/');
  str hash = path2name (src);
  str srclink =  sfsauthcachedir << "/source." << hash;

  errno = 0;
  char buf[256];
  int n = readlink (srclink, buf, sizeof (buf) - 1);
  if (n >= 0) {
    buf[n] = '\0';
    if (src != buf) {
      unlink (srclink);
      errno = ENOENT;
    }
  }
  if (errno && (errno != ENOENT || symlink (src, srclink) < 0)) {
    warn << srclink << ": " << strerror (errno) << "\n";
    return NULL;
  }
  return New refcounted<xfer> (src, sfsauthcachedir << "/cache." << hash);
}

static str
expandcertpath (str s)
{
  str res;

  if (s[0] == '/') {
    if (s.len () == 1 || s[1] != '/')
      res = strbuf () << siw->mkpath () << s;
    else
      res = substr (s, 1);
  }
  else {
    str s1;
    char *firstslash = strchr (s.cstr (), '/');
    if (!firstslash)
      s1 = s;
    else
      s1 = substr (s, 0, firstslash - s.cstr ());
    if (sfs_parsepath (s1))
      res = s;
  }
  if (!res)
    fatal << "Could not expand certpath: " << s << "\n";
  return res;
}

static void
cleanup ()
{
  write_dbcache ();
  exit (0);
}

void
dbcache_flush ()
{
  write_dbcache ();
  delaycb (600, wrap (dbcache_flush));
}

void
dbcache_refresh ()
{
  warn << "Refreshing authentication server cache...\n";
  for (dbfile *dbp = dbfiles.base (); dbp < dbfiles.lim (); dbp++) {
    if (ptr<authcursor> ac = dbp->db->open (dbp->dbflags))
      update_dbcache (ac, true);
  }
  delaycb (dbcache_refresh_delay, wrap (dbcache_refresh));
}

void
dbcache_setup ()
{
  if (dbcache_refresh_delay == 0) {
    warn << "Disabling authentication server cache refresh...\n";
    return;
  }

  init_dbcache ();
  read_dbcache ();
  dbcache_refresh ();
  delaycb (600, wrap (dbcache_flush));
}

void
cache_refresh ()
{
  for (dbfile *dbp = dbfiles.base (); dbp < dbfiles.lim (); dbp++)
    if (dbp->refresh)
      (*dbp->refresh) ();
  delaycb (60, wrap (cache_refresh));
}

void
dbfile::mkpub ()
{
  u_int mode = geteuid () ? 0644 : 0444;
  if (pubfiles.empty ())
    return;
  vec<ref<authcursor> > acv;
  vec<str> acvpath;
  for (str *np = pubfiles.base (); np < pubfiles.lim (); np++) {
    ptr<authdb> pdb = authdb_alloc (*np);
    if (!pdb)
      continue;
    if (ptr<authcursor> ac = pdb->open (authdb::AUDB_WRITE
					| authdb::AUDB_CREATE
					| authdb::AUDB_TRUNC, mode)) {
      acv.push_back (ac);
      acvpath.push_back (*np);
    }
  }
  if (acv.empty ())
    return;
  ptr<authcursor> ac = db->open (dbflags);
  if (!ac)
    return;
  for (ac->reset (); ac->next ();) {
    aesanitize (&ac->ae, AE_PUBFILE);
    for (ref<authcursor> *acp = acv.base (); acp < acv.lim (); acp++) {
      (*acp)->ae = ac->ae;
      (*acp)->update ();
    }
  }
  for (u_int i = 0; i < acv.size (); i++)
    acv[i]->commit ();
}

str
dbfile::strip_prefix (str name)
{
  assert (name);
  if (!prefix)
    return name;
  if (name.len () <= prefix.len () || name[prefix.len ()] != '/'
      || memcmp (name.cstr (), prefix.cstr (), prefix.len ()))
    return NULL;
  return substr (name, prefix.len () + 1);
}

static void
parseconfig (str cf)
{
  parseargs pa (cf);
  bool errors = false;
  bool empty = true;
  bool unixpwd = false;
  bool userfile_p = false;
  int line;
  vec<str> av;
  ptr<idmap> mygidmap;

  myservinfo.set_sivers (7);
  myservinfo.cr7->release = sfs_release;
  myservinfo.cr7->host.hostname = ""; // XXX - in case inited before 
                                      // rpc_emptystr

  while (pa.getline (&av, &line)) {
    if (!strcasecmp (av[0], "hostname")) {
      if (av.size () != 2) {
	errors = true;
	warn << cf << ":" << line << ": usage: hostname name\n";
      }
      else if (myservinfo.cr7->host.hostname != "") {
	errors = true;
	warn << cf << ":" << line << ": hostname already specified\n";
      }
      else
	myservinfo.cr7->host.hostname = av[1];
    }
    else if (!strcasecmp (av[0], "srpfile")) {
      if (srpparms) {
	errors = true;
	warn << cf << ":" << line << ": srpfile already specified\n";
      } else if (av.size () == 2) {
	str srpfile (av[1]);
	char *cp = strchr (srpfile, '/');
	if (!cp) {
	  srpfile = sfsconst_etcfile (srpfile);
	  if (!srpfile) {
	    errors = true;
	    warn << cf << ":" << line << ": file not found\n";
	  }
	}
	if (!(srpparms = file2str (srpfile))) {
	  errors = true;
	  warn << cf << ":" << line << ": cannot read file\n";
	}
      }
    }
    else if (!strcasecmp (av[0], "keyfile")) {
      if (myprivkey) {
	errors = true;
	warn << cf << ":" << line << ": keyfile already specified\n";
      }
      else if (av.size () == 2) {
	str keyfile (av[1]);
	if (keyfile[0] != '/')
	  keyfile = strbuf ("%s/", etc1dir) << keyfile;
	str key = file2wstr (keyfile);

	if (!key) {
	  errors = true;
	  warn << keyfile << ": " << strerror (errno) << "\n";
	  warn << cf << ":" << line << ": could not read keyfile\n";
	}
	else if (!(myprivkey = sfscrypt.alloc_priv (key, SFS_SIGN))) {
	  errors = true;
	  warn << cf << ":" << line << ": could not decode keyfile\n";
	}
      }
      else {
	errors = true;
	warn << cf << ":" << line << ": usage: keyfile path\n";
      }
    }
    else if (!strcasecmp (av[0], "userfile")) {
      userfile_p = true;
      static rxx pubrx ("^-pub=(.+)$", "i");
      static rxx prefixrx ("^-prefix=([\\w/]+)$", "i");
      static rxx uidid ("-uid=(\\d+)", "i");
      //static rxx uidnam ("-uid=([\w_\-]+)", "i");
      static rxx uidmap ("-uidmap=(\\d+)-(\\d+)\\+(\\d+)", "i");
      static rxx gidid ("-gid=(\\d+)", "i");
      //static rxx gidnam ("-gid=([\w_\-]+)", "i");
      static rxx gidmap ("-gidmap=(\\d+)-(\\d+)\\+(\\d+)", "i");
      static rxx groupsrx ("-groups=(\\d+)-(\\d+)", "i");
      static rxx groupquota ("-groupquota=(\\d+)", "i");
      static rxx refresh ("-refresh=(\\d+)", "i");
      static rxx timeout ("-timeout=(\\d+)", "i");
      dbfile *dbp = &dbfiles.push_back (dbfile ());
      av.pop_front ();
      for (; !av.empty () && av[0][0] == '-'; av.pop_front ())
	if (!strcasecmp (av[0], "-update"))
	  dbp->allow_update = true;
	else if (!strcasecmp (av[0], "-passwd")) {
	  dbp->allow_unix_pwd = true;
	  unixpwd = true;
	} else if (!strcasecmp (av[0], "-create")) {
	  dbp->allow_create = true;
	  dbp->dbflags |= authdb::AUDB_CREATE;
	}
	else if (!strcasecmp (av[0], "-admin"))
	  dbp->allow_admin = true;
	else if (!strcasecmp (av[0], "-hideusers"))
	  dbp->hide_users = true;
	else if (pubrx.match (av[0])) {
	  str path = pubrx[1];
	  if (path[0] != '/')
	    path = strbuf () << etc1dir << "/" << path;
	  dbp->pubfiles.push_back (path);
	}
	else if (prefixrx.match (av[0])) {
	  if (dbp->prefix) {
	    errors = true;
	    warn << cf << ":" << line << ": extra -prefix\n";
	  }
	  dbp->prefix = prefixrx[1];
	}
	else if (uidid.match (av[0])) {
	  u_int32_t id = badid;
	  convertint (uidid[1], &id);
	  if (dbp->uidmap) {
	    errors = true;
	    warn << cf << ":" << line << ": only one uid/uidmap allowed\n";
	  }
	  dbp->uidmap = New refcounted<idmap_const> (id);
	}
	else if (uidmap.match (av[0])) {
	  u_int32_t min, max, offset;
	  convertint (uidid[1], &min);
	  convertint (uidid[2], &max);
	  convertint (uidid[3], &offset);
	  if (dbp->uidmap) {
	    errors = true;
	    warn << cf << ":" << line << ": only one uid/uidmap allowed\n";
	  }
	  dbp->uidmap = New refcounted<idmap_range> (min, max, offset);
	}
	else if (gidid.match (av[0])) {
	  u_int32_t id = badid;
	  convertint (gidid[1], &id);
	  if (dbp->gidmap) {
	    errors = true;
	    warn << cf << ":" << line << ": only one gid/gidmap allowed\n";
	  }
	  dbp->gidmap = New refcounted<idmap_const> (id);
	}
	else if (gidmap.match (av[0])) {
	  u_int32_t min, max, offset;
	  convertint (gidid[1], &min);
	  convertint (gidid[2], &max);
	  convertint (gidid[3], &offset);
	  if (dbp->gidmap) {
	    errors = true;
	    warn << cf << ":" << line << ": only one gid/gidmap allowed\n";
	  }
	  dbp->gidmap = New refcounted<idmap_range> (min, max, offset);
	}
	else if (groupsrx.match (av[0])) {
	  u_int32_t min, max;
	  convertint (groupsrx[1], &min);
	  convertint (groupsrx[2], &max);
	  if (dbp->grprange) {
	    errors = true;
	    warn << cf << ":" << line << ": only one groups allowed\n";
	  }
	  dbp->grprange = New refcounted<idmap_range> (min, max, 0);
	}
	else if (groupquota.match (av[0])) {
	  convertint (groupquota[1], &dbp->default_groupquota);
          if (dbp->default_groupquota < 0) {
            errors = true;
            warn << cf << ":" << line << ": -groupquota value must be "
                 << "greater than or equal to zero\n";
          }
        }
	else if (refresh.match (av[0])) {
	  convertint (refresh[1], &dbp->default_refresh);
          if (dbp->default_refresh < 300 || dbp->default_refresh > 220752000) {
            errors = true;
            warn << cf << ":" << line << ": -refresh value must be between "
                 << "5 minutes (300 seconds) and 1 year (220752000 seconds)\n";
          }
        }
	else if (timeout.match (av[0])) {
	  convertint (timeout[1], &dbp->default_timeout);
          if (dbp->default_timeout < 300 || dbp->default_timeout > 220752000) {
            errors = true;
            warn << cf << ":" << line << ": -timeout value must be between "
                 << "5 minutes (300 seconds) and 1 year (220752000 seconds)\n";
          }
        }
	else {
	  errors = true;
	  warn << cf << ":" << line << ": unknown option " << av[0] << "\n";
	}
#if 0
      if (!dbp->allow_update)
	dbp->dbflags |= authdb::AUDB_NORECOV;
#endif
      if (av.size () == 0 || !av[0].len ()) {
	errors = true;
	warn << cf << ":" << line << ": missing file name\n";
      }
      else if (av.size () > 1) {
	errors = true;
	warn << cf << ":" << line << ": extra arguments after file name\n";
      }
      else if (dbp->allow_unix_pwd && (dbp->uidmap || dbp->gidmap)) {
	errors = true;
	warn << cf << ":" << line
	     << ": same DB cannot have -passwd and -uidmap/-gidmap\n";
      }
      else if (dbp->allow_update && av[0].len () >= 3
	       && !strcmp (av[0].cstr () + av[0].len () - 3, ".db")) {
	errors = true;
	warn << cf << ":" << line << ": '" << av[0]
	     << "' has -update flag; must end '.db/'\n";
      }
      else {
	str path = av[0];
	if (path[0] != '/')
	  path = strbuf () << etc1dir << "/" << path;
	if (!dbp->allow_update) {
	  if (ptr<xfer> xp = mkcache (path)) {
	    dbp->refresh = wrap (xp, &xfer::start);
	    path = xp->dst;
	  }
	  else {
	    errors = true;
	    warn << cf << ":" << line
		 << ": cannot create cache file\n";
	  }
	  dbp->db = New refcounted<authdb_file> (path);
	}
	else
	  dbp->db = authdb_alloc (path);
	if (!dbp->db) {
	  errors = true;
	  warn << cf << ":" << line
	       << ": database type not supported\n";
	}
	if (!dbp->uidmap) {
	  dbp->uidmap = New refcounted<idmap_id> ();
	  if (!dbp->gidmap)
	    dbp->gidmap = New refcounted<idmap_id> ();
	}
	else if (!dbp->gidmap) {
	  warn << cf << ":" << line << ": assuming -gid=-1\n";
	  dbp->gidmap = New refcounted<idmap_const> (badid);
	}
	dbp->mkpub ();
	mygidmap = dbp->gidmap;
      }
    }
    else if (!strcasecmp (av[0], "dbcache")) {
      if (av.size () != 2) {
	errors = true;
	warn << cf << ":" << line << ": usage: dbcache path_to_database\n";
      }
      else if (sfsauthdbcache != "") {
	errors = true;
	warn << cf << ":" << line << ": dbcache already specified\n";
      }
      else {
	sfsauthdbcache = av[1];
	if (sfsauthdbcache[0] != '/')
	  sfsauthdbcache = sfsauthcachedir << "/" << sfsauthdbcache;
      }
    }
    else if (!strcasecmp (av[0], "dbcache_refresh_delay")) {
      if (av.size () != 2) {
	errors = true;
	warn << cf << ":" << line << ": usage: dbcache_refresh_delay seconds\n";
      }
      else {
        if (av[1] == "off")
          dbcache_refresh_delay = 0;
        else {
          time_t t;
          convertint (av[1], &t);
          if (t < 300 || t > 220752000) {
            errors = true;
            warn << cf << ":" << line << ": dbcache_refresh_delay must be "
                 << "between 5 minutes (300 seconds) and 1 year (220752000 "
                 << "seconds) OR the word `off'\n";
          }
          else
            dbcache_refresh_delay = t;
        }
      }
    }
    else if (!strcasecmp (av[0], "realm")) {
      if (av.size () != 2) {
	errors = true;
	warn << cf << ":" << line << ": usage: realm name\n";
      }
      else if (sfsauthrealm != "") {
	errors = true;
	warn << cf << ":" << line << ": realm already specified\n";
      }
      else
	sfsauthrealm = av[1];
    }
    else if (!strcasecmp (av[0], "certpath")) {
      if (av.size () < 2) {
	errors = true;
	warn << cf << ":" << line << ": usage: certpath path1 [path2 ...]\n";
      }
      else {
	for (size_t i = 1; i < av.size (); i++ ) {
	  sfsauthcertpaths.push_back (av[i]);
	}
      }
    }
    else if (!strcasecmp (av[0], "logfile")) {
      if (av.size () < 2) {
	errors = true;
	warn << cf << ":" << line << ": usage: logfile path\n";
      } else if (logfile != "") {
	errors = true;
	warn << cf << ":" << line << ": logfile already specified\n";
      } else 
	logfile = av[1];
    } else if (!strcasecmp (av[0], "syslog_priority")) {
      if (av.size () < 2) {
	errors = true;
	warn << cf << ":" << line << ": usage: syslog_prioriy priority\n";
      } else if (authd_syslog_priority != "") {
	errors = true;
	warn << cf << ":" << line << ": syslog_priority already specified\n";
      } else 
	authd_syslog_priority = av[1];
    } else {
      errors = true;
      warn << cf << ":" << line << ": unknown keyword " << av[0] << "\n";
    }
    empty = false;
  }

  if (logfile == "")
    logfile = sfsdir << "/sign_log";
  if (authd_syslog_priority == "")
    authd_syslog_priority = sfs_authd_syslog_priority;

  if ((logfd = open (logfile, O_CREAT|O_APPEND|O_WRONLY, 0600)) < 0) {
    warn ("%s: %m\n", logfile.cstr ());
    errors = true;
  }

  // Default: Userfile -passwd -update -create -pub=<file>.pub <file>
  if (empty) {
    userfile_p = true;
    warn << "Empty sfsauthd_config file. Using default:\n";
    warn << "  Userfile -passwd -update -create -pub=sfs_users.pub "
	 << "sfs_users\n";
    str userfile = sfsconst_etcfile ("sfs_users");
    if (!userfile) {
      strbuf b;
      b << etc1dir << "/sfs_users";
      userfile = b;
      warn << "Will create userfile on write: " << userfile << "\n";
    }
    unixpwd = true;
    strbuf pubuserfile = userfile << ".pub";
    dbfile *dbp = &dbfiles.push_back (dbfile ());
    dbp->pubfiles.push_back (pubuserfile);
    dbp->allow_update = true;
    dbp->allow_unix_pwd = true;
    dbp->allow_create = true;
    dbp->db = authdb_alloc (userfile);
    if (!dbp->db)
      fatal << userfile << ": database type not supported\n";
    dbp->uidmap = New refcounted<idmap_id> ();
    dbp->gidmap = New refcounted<idmap_id> ();
    dbp->mkpub ();
  }

  if (!userfile_p) 
    fatal << cf << ": no Userfile directive in configuration file\n";

  if (unixpwd) {
    dbfile *dbp = &dbfiles.push_back (dbfile ());
    dbp->allow_update = false;
    dbp->allow_create = false;
    dbp->allow_unix_pwd = true;
    dbp->db = New refcounted<authdb_etc_group> ();
    dbp->uidmap = New refcounted<idmap_id> ();
    if (mygidmap) {
      dbp->gidmap = mygidmap;
    } else {
      dbp->gidmap = New refcounted<idmap_id> ();
    }
  }

  if (!myservinfo.cr7->host.hostname.len ())
    myservinfo.cr7->host.hostname = sfshostname ();
  if (!myprivkey) {
    str keyfile = sfsconst_etcfile ("sfs_host_key");
    if (!keyfile) {
      errors = true;
      warn << "cannot locate default file sfs_host_key\n";
    }
    else {
      str key = file2wstr (keyfile);
      if (!key) {
	errors = true;
	warn << keyfile << ": " << strerror (errno) << "\n";
      }
      else if (!(myprivkey = sfscrypt.alloc_priv (key, SFS_DECRYPT))) { 
	errors = true;
	warn << "could not decode " << keyfile << "\n";
      }
    }
  }
  if (errors)
    fatal ("errors in config file\n");

  myservinfo.cr7->host.type = SFS_HOSTINFO;
  myprivkey->export_pubkey (&myservinfo.cr7->host.pubkey);
  siw = sfs_servinfo_w::alloc (myservinfo);
  if (!siw->mkhostid (&myhostid)) {
    const char *p = siw->get_hostname ();
    if (p) 
      fatal << "Hostname is incomplete or is of invalid syntax: " << p << "\n";
    else 
      fatal << "Cannot determine hostname.\n";
  }
  myservinfo.cr7->prog = SFSAUTH_V2;

  if (sfsauthdbcache == "")
    sfsauthdbcache = sfsauthcachedir << "/" << DEFAULT_DBCACHE;
  if (sfsauthrealm.len () == 0 && sfsauthcertpaths.size () > 0) 
    warn << "certpath specified, but no realm...ignoring certpath\n";
  for (size_t i = 0; i < sfsauthcertpaths.size (); i++ )
    sfsauthcertpaths[i] = expandcertpath (sfsauthcertpaths[i]);

  warn << "dbcache_refresh_delay = " << dbcache_refresh_delay << "\n";

  cache_refresh ();
  dbcache_setup ();
}

void
unixaccept (ptr<axprt_unix> x, const authunix_parms *aup)
{
  if (x) {
    vNew authclnt (axprt_crypt::alloc (x->reclaim ()), aup);
  }
}

ptr<axprt_stream>
cloneaccept (bool primary, int fd)
{
  if (fd < 0) {
    if (primary) {
      warn ("EOF from sfssd\n");
      cleanup ();
    }
    return NULL;
  }
  tcp_nodelay (fd);
  ref<axprt_crypt> x = axprt_crypt::alloc (fd);
  vNew authclnt (x);
  return x;
}

void
clonegen (int fd)
{
  if (fd >= 0)
    if (!cloneserv (fd, wrap (cloneaccept, false))) {
      warn ("clonegen: cloneserv: %m\n");
      close (fd);
    }
}

static void
authcachedir_init ()
{
  static bool initialized;
  if (initialized)
    return;
  initialized = true;
  if (!sfsauthcachedir)
    sfsauthcachedir = sfsdir << "/authdb";
  if (!runinplace)
    mksfsdir (sfsauthcachedir, 0755, NULL, 0);
  else {
    struct stat sb;
    if (stat (sfsdir, &sb) >= 0) {
      if (pid_t pid = fork ())
	waitpid (pid, NULL, 0);
      else {
	umask (0);
	setuid (sb.st_uid);
	mkdir (sfsauthcachedir, sb.st_mode & 0777);
	_exit (0);
      }
    }
  }
}

static void
usage ()
{
  warnx << "usage: " << progname << " [-u sockpath] [-f configfile]\n";
  exit (1);
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);

  // XXX debug code

  str configfile;
  str upath;
  int ch;
  while ((ch = getopt (argc, argv, "u:f:")) != -1)
    switch (ch) {
    case 'u':
      upath = optarg;
      break;
    case 'f':
      configfile = optarg;
      break;
    case '?':
    default:
      usage ();
    }

  argc -= optind;
  argv += optind;
  if (argc > 0)
    usage ();

  warn ("version %s, pid %d\n", VERSION, int (getpid ()));

  sfsconst_init ();

  {
    str ah (fix_exec_path ("auth_helper"));
    if (strchr (ah, '/') && !access (ah, X_OK))
      auth_helper = ah;
  }

  sfs_suidserv ("authd", wrap (unixaccept));

  authcachedir_init ();

  if (!configfile)
    configfile = sfsconst_etcfile_required ("sfsauthd_config");
  parseconfig (configfile);

  // timenow is initialized in amain (); we can only write
  // the initial log line after it is initialized
  delaycb (0, wrap (&siglogv)); 

  random_init_file (sfsdir << "/random_seed");

  warn << "serving " << siw->mkpath () << "\n";
  if (sfsauthrealm.len () > 0)
    warn << "serving realm " << sfsauthrealm << "\n";

  if (!cloneserv (0, wrap (cloneaccept, true)) && !upath)
    warn ("No sfssd detected, only accepting unix-domain clients\n");
  if (upath)
    sfs_unixserv (upath, wrap (clonegen));

  sigcb (SIGINT, wrap (cleanup));
  sigcb (SIGTERM, wrap (cleanup));
  sigcb (SIGUSR1, wrap (write_dbcache));

  amain ();
}
