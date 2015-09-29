/* $Id: authdb_db.C,v 1.47 2004/09/19 22:02:27 dm Exp $ */

/*
 *
 * Copyright (C) 2003 David Mazieres (dm@uun.org)
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

#ifndef SLEEPYCAT

ptr<authdb>
authdb_db_alloc (str path)
{
  static bool warned;
  if (!warned) {
    warn << "no Sleepycat database support compiled in\n";
    warned = true;
  }
  return NULL;
}

#else /* SLEEPYCAT */

#ifndef DB_CHKSUM
#define DB_CHKSUM DB_CHKSUM_SHA1
#endif

struct dbset_entry {
  const char *name;
  DB *dbset::*field;
  u_int32_t flags;
  u_int32_t openflags;
};
dbset_entry dbset_entries[] = {
  { "dbrec", &dbset::dbrec, DB_CHKSUM, 0 },
  { "pkmap", &dbset::pkmap, 0, 0 },
  { "u2gmap", &dbset::u2gmap, 0, 0 },
  { "uidmap", &dbset::uidmap, 0, 0 },
  { "gidmap", &dbset::gidmap, 0, 0 },
  { "delta", &dbset::delta, 0, DB_CREATE },
};
const int dbset_size = sizeof (dbset_entries) / sizeof (dbset_entries[0]);

static ihash<const str, dbenv_t, &dbenv_t::dbenvdir, &dbenv_t::hlink> &envtab
  = *New ihash<const str, dbenv_t, &dbenv_t::dbenvdir, &dbenv_t::hlink>;

dbenv_t::dbenv_t (str p)
  : e (NULL), dbenvdir (p), txn (false), error (false),
    recovlockfd (-1), opened (false), fbstate (0)
{
  envtab.insert (this);
}

dbenv_t::~dbenv_t ()
{
  close ();
  envtab.remove (this);
}

bool
dbenv_t::mkdir ()
{
  if (!access (dbenvdir, 0))
    return true;
  if (errno != ENOENT) {
    warn << dbenvdir << ": " << strerror (errno) << "\n";
    return false;
  }
  if (runinplace && buildtmpdir.len () < dbenvdir.len () 
      && dbenvdir[buildtmpdir.len ()] == '/'
      && !strncmp (buildtmpdir.cstr (), dbenvdir.cstr (),
		   buildtmpdir.len ())) {
    struct stat sb;
    if (stat (buildtmpdir, &sb) >= 0) {
      if (pid_t pid = fork ())
	waitpid (pid, NULL, 0);
      else {
	umask (0);
	setgid (sb.st_gid);
	setuid (sb.st_uid);
	::mkdir (dbenvdir, sb.st_mode & 0777);
	_exit (0);
      }
    }
    else
      warn << buildtmpdir << ": " << strerror (errno) << "\n";
  }
  else
    // mksfsdir (dbenvdir, 0700, NULL, 0);
    ::mkdir (dbenvdir, 0700);
  return true;
}

bool
dbenv_t::recovlock (int flags)
{
  if (!txn)
    return !(flags & LOCK_EX);
  if (flags & LOCK_UN) {
    assert (!opened || error);
    if (recovlockfd >= 0) {
      ::close (recovlockfd);
      recovlockfd = -1;
      /* if flock is implemented in terms of lockf and we are open
       * multiple times, stupid POSIX semantics mean we lose the
       * lock... so relock. */
      for (dbenv_t *ep = envtab[dbenvdir]; ep; ep = envtab.nextkeq (ep))
	if (ep && ep->opened && !ep->error && !ep->recovlock ())
	  fatal ("could not reacquire necessary lock\n");
    }
    return true;
  }

  str rlpath = dbenvdir << "/recov.lock";
  if (recovlockfd < 0) {
    if ((recovlockfd = ::open (rlpath, O_CREAT|O_RDWR, dbmode)) < 0) {
      warn << rlpath << ": " << strerror (errno) << "\n";
      return false;
    }
    close_on_exec (recovlockfd);
  }

  if (!(flags & LOCK_NB)) {
    if (!flock (recovlockfd, flags | LOCK_NB))
      return true;
    warn << "waiting for lock on " << rlpath << "...\n";
  }
  if (flock (recovlockfd, flags)) {
    if (!(flags & LOCK_NB) || errno != EWOULDBLOCK)
      warn << rlpath << ": " << strerror (errno) << "\n";
    return false;
  }
  if (!(flags & LOCK_NB))
    warn << "acquired lock on " << rlpath << "\n";
  return true;
}

static int null_sleep (u_long sec, u_long msec) __attribute__ ((unused));
static int
null_sleep (u_long sec, u_long msec)
{
  return 0;
}
static bool null_sleep_set __attribute__ ((unused));

bool
dbenv_t::open (int fl)
{
  const bool create = fl & DB_CREATE;
  const bool forcerecov = fl & (DB_RECOVER | DB_RECOVER_FATAL);

  assert (!opened);

#if 0
  if (!null_sleep_set) {
    db_env_set_func_sleep (null_sleep);
    null_sleep_set = true;
  }
#endif

  if (create && !mkdir ())
    return false;

  struct stat sb;
  if (stat (dbenvdir, &sb)) {
    warn << dbenvdir << ": " << strerror (errno) << "\n";
    return false;
  }
  dbmode = sb.st_mode & 0666;
  u_int32_t dbflags = fl | DB_INIT_MPOOL | DB_CREATE;
  if (!(fl & DB_PRIVATE)) {
    txn = true;
    dbflags |= DB_INIT_LOG | DB_INIT_LOCK | DB_INIT_TXN;
  }

  bool multi = false;
  for (dbenv_t *ep = envtab[dbenvdir]; ep; ep = envtab.nextkeq (ep))
    if (ep->opened)
      multi = true;

  if (int err = db_env_create (&e, 0)) {
    warn << "db_env_create: " << db_strerror (err) << "\n";
    return false;
  }
  e->app_private = this;
  e->set_paniccall (e, &dbenv_t::seterr);
  if (errfd == 2) {
    e->set_errpfx (e, progname.cstr ());
    e->set_errfile (e, stderr);
  }

  if (!multi && recovlock (LOCK_EX | LOCK_NB)) {
    if (!(dbflags & DB_RECOVER_FATAL))
      dbflags |= DB_RECOVER;
    e->set_feedback (e, &dbenv_t::feedbk);
    feedbk (e, DB_RECOVER, 0);
    if (int err = e->open (e, dbenvdir, dbflags, dbmode)) {
      warn << dbenvdir << ": " << db_strerror (err) << "\n";
      close ();
      return false;
    }
    feedbk (e, 0, 0);
    if (!recovlock (LOCK_SH))
      fatal << "could not downgrade recov.lock\n";
    if (int err = e->txn_checkpoint (e, 0, 0, 0)) {
      warn << dbenvdir << ": " << db_strerror (err) << "\n";
      close ();
      return false;
    }
  }
  else if (!forcerecov && recovlock (LOCK_SH)) {
    if (int err = e->open (e, dbenvdir, dbflags, dbmode)) {
      warn << dbenvdir << ": " << db_strerror (err) << "\n";
      close ();
      return false;
    }
  }
  else {
    if (forcerecov)
      warn << dbenvdir << ": could not recover active database\n"
	   << dbenvdir << ": shut down other processes first\n";
    return false;
  }

  opened = true;
  return true;
}

void
dbenv_t::close ()
{
  if (e) {
    int cperr = 0;
    if (opened && !error && txn) {
      cperr = e->txn_checkpoint (e, 0, 0, 0);
      if (cperr)
	warn << dbenvdir << ": checkpoint failed on environment close ("
	     << db_strerror (cperr) << ")\n";
    }
    int clerr = e->close (e, 0);
    if (clerr && !cperr && !error)
      warn << dbenvdir << ": close failed (" << db_strerror (clerr) << ")\n";
    e = NULL;
  }
  opened = false;
  recovlock (LOCK_UN);
}

void
dbenv_t::seterr (DB_ENV *ee, int errval)
{
  dbenv_t *ep = static_cast<dbenv_t *> (ee->app_private);
  ep->error = true;
  ep->recovlock (LOCK_UN);
}

void
dbenv_t::feedbk (DB_ENV *ee, int opcode, int pct)
{
  dbenv_t *ep = static_cast<dbenv_t *> (ee->app_private);
  if (!opcode) {
    if (ep->fbpct >= 0) {
      if (ep->fbstate == DB_RECOVER)
	warn ("Recovered %s\n", ep->dbenvdir.cstr ());
    }
    ep->fbstate = 0;
    return;
  }
  if (!ep->fbstate) {
    ep->fbstate = opcode;
    ep->fbpct = -1;
    ep->fblast = ep->fbstart = time (NULL);
    return;
  }
  if (ep->fbstate != opcode || pct == ep->fbpct)
    return;

  time_t now = time (NULL);
  if (now < ep->fblast + 5)
    return;
  if (now < ep->fblast + 300
      && now - ep->fblast < (now - ep->fbstart) / 10)
    return;

  if (opcode == DB_RECOVER)
    warn ("Recovering %s (%d%% complete)\n", ep->dbenvdir.cstr (), pct);
  else
    return;

  ep->fbpct = pct;
  ep->fblast = now;
  
  //str percent (strbuf (" % 3d%%\b\b\b\b\b", pct));
  //write (errfd, percent.cstr (), percent.len ());
}


str
abspath (const char *p)
{
  if (p[0] == '/')
    return p;
  if (p[0] == '.' && p[1] == '/')
    p += 2;

  struct stat csb, sb;
  if (stat (".", &csb) < 0) {
    warn (".: %m\n");
    return "";
  }
  const char *cwd = getenv ("PWD");
  if (stat (cwd, &sb) >= 0 && sb.st_dev == csb.st_dev
      && sb.st_ino == csb.st_ino)
    return strbuf ("%s/%s", cwd, p);

  char cwdbuf[PATH_MAX];
  if (!getcwd (cwdbuf, sizeof (cwdbuf)))
    return "";
  return strbuf ("%s/%s", cwdbuf, p);
}

/* DB requires absolute pathnames for files not in envdir */
str
dbenv_t::mkdbpath (str path, str dbenvdir)
{
  if (!strchr (path, '/')) {
    str envpath = strbuf () << dbenvdir << "/" << path;
    if (envpath[0] != '/')
      envpath = abspath (envpath);
    if (!access (envpath, 0)
	|| (access (path, 0) < 0 && errno == ENOENT))
      return envpath;
  }
  if (path[0] != '/')
    return abspath (path);
  return path;
}

ptr<dbenv_t>
dbenv_t::alloc (str path, u_int32_t flags)
{
  if (path) {
    const bool forcerecov = flags & (DB_RECOVER | DB_RECOVER_FATAL);
    if (!forcerecov)
      for (dbenv_t *ep = envtab[path]; ep; ep = envtab.nextkeq (ep))
	if (ep->opened && !ep->error)
	  return mkref (ep);
  }
  else {
    path = strbuf () << sfsdir << "/dbenv";
#if 0
    char *tmpdir = getenv ("TMPDIR");
    path = strbuf ("%s/audbXXXXXXXXXX", tmpdir ? tmpdir : "/tmp");
    char *envbuf = xstrdup (path);
    if (!mktemp (envbuf)) {
      xfree (envbuf);
      return NULL;
    }
    path = envbuf;
    xfree (envbuf);
#endif
    flags |= DB_PRIVATE;
  }
  ref<dbenv_t> ep = New refcounted<dbenv_t> (path);
  if (!ep->open (flags))
    return NULL;
  return ep;
}

dbset::dbset (const char *p)
  : path (p), perm (0600), flags (0)
{
  for (int i = 0; i < dbset_size; i++)
    this->*dbset_entries[i].field = NULL;
}

dbset::~dbset ()
{
  close ();
}

bool
dbset::envinit (u_int32_t envflags)
{
  if (dbenv)
    return true;
  if (!dbenvdir)
    dbenvdir = envdir ();
  if (!dbenvdir)
    dbenv = dbenv_t::alloc (NULL, DB_CREATE|DB_PRIVATE);
  else
    dbenv = dbenv_t::alloc (dbenvdir, DB_CREATE|envflags);
  return dbenv;
}

bool
dbset_mem::open (int perm, u_int32_t flags, u_int32_t envflags)
{
  int err;
  if ((err = db_create (&dbrec, dbenv ? dbenv->e : 0, 0))) {
    warn << "db_create: " << db_strerror (err) << "\n";
    return false;
  }
  if ((err = dbrec->open(dbrec, NULL, NULL, NULL, DB_BTREE,
			 DB_CREATE, 0600))) {
    close ();
    warn << "db_open (tempDB): " << db_strerror (err) << "\n";
    return false;
  }
  return true;
}

bool
dbset::doopen (DB_TXN *tid)
{
  int f = flags;
  f &= ~DB_AUTO_COMMIT;
  if (f & DB_RDONLY)
    f &= ~DB_CREATE;

  DB_ENV *e = (flags & DB_AUTO_COMMIT) && dbenv ? dbenv->e : NULL;

  for (int i = 0; i < dbset_size; i++) {
    DB **dbp = &(this->*dbset_entries[i].field);
    u_int32_t ofl = dbset_entries[i].flags;
    u_int32_t openflags = dbset_entries[i].openflags;
    int err;
    if ((err = db_create (dbp, e, 0))
	|| (ofl && (err = (*dbp)->set_flags (*dbp, ofl)))) {
      if (*dbp)
	warn << path << "(" << dbset_entries[i].name << "): db_setflags: "
	     << db_strerror (err) << "\n";
      else
	warn << "db_create: " << db_strerror (err) << "\n";
      close ();
      errno = err;
      return false;
    }
    const char *subdb = dbset_entries[i].name;
    str file = dbfile (subdb);
    if (file && e && !(file = dbenv->mkdbpath (file))) {
      close ();
      errno = EIO;
      return false;
    }
    else if (file && !e && dbenv && !strchr (file, '/')) {
      file = dbenv->dbenvdir << "/" << file;
    }
    ofl = openflags | f;
    if (ofl & DB_RDONLY)
      ofl &= ~DB_CREATE;
#if DB_VERSION_MAJOR < 4 || (DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR == 0)
    /* XXX - untested */
    err = (*dbp)->open(*dbp, file, dbname (subdb),
		       DB_BTREE, ofl, perm);
#else /* DB version >= 4.1 */
    err = (*dbp)->open(*dbp, tid, file, dbname (subdb),
		       DB_BTREE, ofl, perm);
#endif /* DB version >= 4.1 */
    if (err == ENOENT
	&& (((openflags|f) & (DB_CREATE|DB_RDONLY))
	    == (DB_CREATE|DB_RDONLY))) {
      (*dbp)->close (*dbp, 0);
      *dbp = NULL;
    }
    else if (err) {
      if ((flags & (DB_CREATE|DB_RDONLY)) != (DB_CREATE|DB_RDONLY)
	  || err != ENOENT)
	warn << file << ": db_open: " << db_strerror (err) << "\n";
      close ();
      errno = err;
      return false;
    }
    else if (file) {
      int fd;
      if ((err = (*dbp)->fd (*dbp, &fd))) {
	warn << file << ": db_fd: " << db_strerror (err) << "\n";
	close ();
	errno = err;
	return false;
      }
      if (okvec.empty () || file != okvec.back ().path
	  || fd != okvec.back ().fd) {
	okvec.push_back ();
	if (file[0] == '/')
	  okvec.back ().path = file;
	else if (e)
	  okvec.back ().path = dbenv->dbenvdir << "/" << file;
	else
	  okvec.back ().path = file;
	okvec.back ().fd = fd;
      }
    }
  }

  return true;
}

bool
dbset::open (int p, u_int32_t f, u_int32_t ef)
{
  if (dbrec || !okvec.empty ())
    panic ("dbset opened twice\n");

  if (p != -1)
    perm = p;
  flags = f;
  f &= ~DB_AUTO_COMMIT;
  if (f & DB_RDONLY)
    f &= ~DB_CREATE;

  if ((flags & DB_AUTO_COMMIT) && !envinit (ef) && !(f & DB_RDONLY))
    return false;

  DB_TXN *tid;
  if (!mktxn (&tid))
    return false;

  if (!doopen (tid)) {
    if (tid)
      tid->abort (tid);
    return false;
  }

  if (tid)
    if (int err = tid->commit (tid, 0)) {
      warn << path << ": " << db_strerror (err) << "\n";
      close ();
      errno = err;
      return false;
    }

  return true;
}

void
dbset::close ()
{
  for (int i = 0; i < dbset_size; i++) {
    DB **dbp = &(this->*dbset_entries[i].field);
    if (*dbp) {
      (*dbp)->close (*dbp, 0);
      *dbp = NULL;
    }
  }
  if (dbenv && dbenv->error)
    dbenv = NULL;
  okvec.clear ();
}

bool
dbset::mktxn (DB_TXN **out, u_int32_t fl, DB_TXN *parent)
{
  if (!dbenv || !(this->flags & DB_AUTO_COMMIT) || !dbenv->txn) {
    *out = NULL;
    return true;
  }
  if (dbenv->error) {
    errno = DB_RUNRECOVERY;
    return false;
  }
  if (int err = dbenv->e->txn_begin (dbenv->e, parent, out, fl)) {
    warn << dbenv->dbenvdir << ": txn_begin: " << db_strerror (err) << "\n";
    errno = err;
    return false;
  }
  return true;
}

/* XXX - the DB->truncate method seems busted, so implement our own */
static bool xtruncate (DB *db, DB_TXN *tid, str path) __attribute__ ((unused));
static bool
xtruncate (DB *db, DB_TXN *tid, str path)
{
  int err;

  DBC *c = NULL;
  if ((err = db->cursor (db, tid, &c, 0))) {
    warn << path << ": " << db_strerror (err) << "\n";
    return false;
  }

  db_t k, v;
  v.flags |= DB_DBT_PARTIAL;	// might make things more efficient
  while (!(err = c->c_get (c, &k, &v, DB_NEXT)))
    c->c_del (c, 0);

  if (err == DB_NOTFOUND) {
    c->c_close (c);
    return true;
  }

  c->c_close (c);
  warn << path << ": " << db_strerror (err) << "\n";
  return false;
}

bool
dbset::truncate (DB_TXN *tid)
{
  u_int32_t count;
  int err;
  for (int i = 0; i < dbset_size; i++) {
#if 0
    if (!xtruncate (this->*dbset_entries[i].field, tid, path))
      return false;
#else
    if ((err = (this->*dbset_entries[i].field)->truncate
	 (this->*dbset_entries[i].field, tid, &count, 0))) {
      warn << path << ": " << db_strerror (err) << "\n";
      return false;
    }
#endif
  }
  return true;
}

bool
dbset::sync ()
{
  for (int i = 0; i < dbset_size; i++)
    if (!(this->*dbset_entries[i].field))
      return false;
  if (dbenv && dbenv->txn)
    if (int err = dbenv->e->txn_checkpoint (dbenv->e, 0, 0, 0)) {
      warn << dbenvdir << ": checkpoint failed ("
	   << db_strerror (err) << ")\n";
      return false;
    }
  bool ret = true;
  for (int i = 0; i < dbset_size; i++) {
    DB *db = this->*dbset_entries[i].field;
    if (db->sync (db, 0))
      ret = false;
  }
  return ret;
}

bool
dbset::ok ()
{
  if (dbenv && dbenv->error)
    return false;
#if 0
  for (int i = 0; i < dbset_size; i++) {
    DB **dbp = &(this->*dbset_entries[i].field);
    const char *name = dbset_entries[i].name;
    if (!*dbp)
      return false;
    int fd;
    struct stat sb1, sb2;
    str dbpath = dbfile (name);
    if (dbpath[0] != '/' && dbenv)
      dbpath = dbenvdir << "/" << dbpath;
    if ((*dbp)->fd (*dbp, &fd) || fstat (fd, &sb1) || stat (dbpath, &sb2))
      return false;
    if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)
      return false;
  }
#endif
  for (okvec_t *ovp = okvec.base (); ovp < okvec.lim (); ovp++) {
    struct stat sb1, sb2;
    if (fstat (ovp->fd, &sb1) || stat (ovp->path, &sb2))
      return false;
    if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)
      return false;
  }
  return true;
}

authcursor_db::authcursor_db (ref<dbset> dbs, ptr<audblock> lf, bool t, bool a)
  : dbs (dbs), lf (lf), txncnt (0), error (false),
    trunc (t), async (a), tid (NULL), dbc (NULL)
{
  if (trunc) {
    assert (lf);
    if (!init (true))
      return;
    if (!dbs->truncate (tid)) {
      error = true;
      abort ();
    }
  }
}

authcursor_db::~authcursor_db ()
{
  if (async && txncnt) {
    warn ("~authcursor_db:  discarding uncommitted AUDB_ASYNC operations \n");
    // flushtxn ();
  }
  abort ();
  if (dbs)
    dbs->sync ();
}

bool
authcursor_db::init (bool write)
{
  assert (!write || lf);
  if (error)
    return false;

  if (write && !tid && (dbs->flags & DB_AUTO_COMMIT)) {
    abort ();
    if (!dbs->mktxn (&tid, async ? DB_TXN_NOSYNC : 0)) {
      error = true;
      abort ();
      return false;
    }
  }

  int err;
  if (!dbc && (err = dbs->dbrec->cursor (dbs->dbrec, tid, &dbc, 0))) {
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    error = true;
    abort ();
    return false;
  }

  return true;
}

bool
authcursor_db::flushtxn ()
{
  txncnt = 0;
  if (error)
    return false;
  if (dbc) {
    dbc->c_close (dbc);
    dbc = NULL;
  }
  if (!tid)
    return true;
  int err = tid->commit (tid, async ? DB_TXN_NOSYNC : 0);
  tid = NULL;
  if (err) {
    warn << dbs->path << ": commit: " << db_strerror (err) << "\n";
    error = true;
  }
  else if (dbs->dbenv->txn)
    dbs->dbenv->e->txn_checkpoint (dbs->dbenv->e, 1024, 5, 0);
  return !err;
}

bool
authcursor_db::commit (size_t tot)
{
  bool ret = flushtxn () && dbs->sync ();
  if (tot && ret)
    warnx (" done\n");
  return ret;
}

bool
authcursor_db::remove (str aek)
{
  if (error)
    return false;
  if (!aek) {
    assert (tid);
    /* Assume cursor is in the right place */
    aek = aekey (ae);
  }
  else {
    if (!init (true))
      return false;
    if (!getkey (&ae, aek))
      return false;
  }

  bool ret = true;
  int err;
  if ((err = dbc->c_del (dbc, 0))) {
    warn << dbs->path << ": del " << aek << ": " << db_strerror (err) << "\n";
    ret = false;
  }
  else
    switch (ae.type) {
    case SFSAUTH_USER:
      {
	db_t uid (ae.userinfo->id), pkk (ae.userinfo->pubkey);
	ret = (update_map (dbs->pkmap, &pkk, NULL, aek, "public key map")
	       && update_map (dbs->uidmap, &uid, NULL, aek, "user ID map"));
	break;
      }
    case SFSAUTH_GROUP:
      {
	db_t gid (ae.groupinfo->id);
	ret = (update_map (dbs->gidmap, &gid, NULL, aek, "group ID map")
	       && update_members (dbs->u2gmap, &ae.groupinfo->members,
				  NULL, aek, "user->group map"));

	break;
      }
    case SFSAUTH_CACHEENTRY:
	ret = update_members (dbs->u2gmap, &ae.cacheentry->values,
			      NULL, aek, "user->group map");

	break;
    default:
      warn << "cannot delete unknown record type of " << aek << "\n";
      ret = false;
      break;
    }
  if (ret)
    return complete ();
  abort ();
  return false;
}

bool
authcursor_db::revinfo (sfsauth_revinfo *rip)
{
  rpc_clear (*rip);
  if (!init () || !dbs->delta)
    return false;

  db_t k, v;
  int err = dbs->delta->get (dbs->delta, tid, &k, &v, 0);
  if (err == DB_NOTFOUND)
    return true;
  else if (err) {
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    return false;
  }

  return v.getxdr (rip);
}

bool
authcursor_db::complete ()
{
  if (error)
    return false;
  if (!trunc && (!async || (++txncnt > 10)))
    return flushtxn ();
  return true;
}

void
authcursor_db::abort ()
{
  if (dbc) {
    dbc->c_close (dbc);
    dbc = NULL;
  }
  if (tid) {
    tid->abort (tid);
    tid = NULL;
  }
}

void
authcursor_db::reset ()
{
  if (dbc) {
    dbc->c_close (dbc);
    dbc = NULL;
  }
  init ();
}

bool
authcursor_db::next (bool *pep)
{
  if (!dbc && !init ())
    return false;
  for (;;) {
    db_t k, v;
    int err = dbc->c_get (dbc, &k, &v, DB_NEXT);
    if (err == DB_NOTFOUND)
      return false;
    if (err) {
      warn << dbs->path << ": " << db_strerror (err) << "\n";
      if (pep)
	*pep = true;
      error = true;
      return false;
    }
    if (!v.getxdr (&ae)) {
      if (pep)
	*pep = true;
      warn << dbs->path << ": record `" << k.getstr () << "' corrupted\n";
    }
    else
      return true;
  }
}

bool
authcursor_db::getkey (dbrec_rev *res, str aek)
{
  res->set_type (SFSAUTH_ERROR);
  db_t k (aek), v;
  int err = dbc->c_get (dbc, &k, &v, DB_SET);
  if (err == DB_NOTFOUND)
    return false;
  else if (err) {
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    error = true;
    return false;
  }
  if (!v.getxdr (res) || aek != aekey (*res)) {
    warn << dbs->path << ": record `" << aek << "' corrupted\n";
    error = true;
    return false;
  }
  return true;
}

bool
authcursor_db::getseckey (DB *map, const db_t &k, bool exact)
{
  init ();
  db_t pri;
  int err;
  if (exact)
    err = map->get (map, tid, const_cast<db_t *> (&k), &pri, 0);
  else {
    DBC *c = NULL;
    err = dbs->delta->cursor (dbs->delta, tid, &c, 0);
    if (!err) {
      db_t kk;
      kk.alloc (k.size);
      memcpy (kk.data, k.data, k.size);
      err = c->c_get (c, (&kk), &pri, DB_SET_RANGE);
    }
    if (c)
      c->c_close (c);
  }

  if (err == DB_NOTFOUND)
    return false;
  else if (err) {
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    error = true;
    return false;
  }
  str aek (pri.getstr ());
  if (!getkey (&ae, aek) && !error) {
    warn << dbs->path << ": database missing record " << aek << "\n";
    return false;
  }
  return !error;
}

u_int64_t
authcursor_db::update_rev (str aek, u_int64_t oldrev)
{
  DBC *c = NULL;
  int err = dbs->delta->cursor (dbs->delta, tid, &c, 0);
  if (err) {
    error = true;
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    return 0;
  }

  bool newid = false;
  sfsauth_revinfo rev;
  db_t k, v;

  err = c->c_get (c, &k, &v, DB_SET);
  if (err && err != DB_NOTFOUND) {
    error = true;
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    c->c_close (c);
    return 0;
  }
  else if (err == DB_NOTFOUND || !v.getxdr (&rev)) {
    rev.dbrev = 0;
    rnd.getbytes (rev.dbid.base (), rev.dbid.size ());
    newid = true;
  }

  if (oldrev && oldrev <= rev.dbrev) {
    k.putxdr (oldrev);
    err = c->c_get (c, &k, &v, DB_SET);
    if (!err && aek == v.getstr ())
      err = c->c_del (c, 0);
    if (err && err != DB_NOTFOUND) {
      error = true;
      warn << dbs->path << ": " << db_strerror (err) << "\n";
      c->c_close (c);
      return 0;
    }
  }

  k.putxdr (++rev.dbrev);
  v.putstr (aek);
  err = c->c_put (c, &k, &v, DB_KEYLAST);
  if (err) {
    error = true;
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    c->c_close (c);
    return 0;
  }

  k.alloc (0);
  if (newid)
    v.putxdr (rev);
  else {
    // This *may* reduce the size of log records; should check
    v.putxdr (rev.dbrev);
    v.doff = 0;
    v.dlen = v.size;
    v.flags |= DB_DBT_PARTIAL;
  }
  err = c->c_put (c, &k, &v, DB_KEYLAST);
  if (err) {
    error = true;
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    c->c_close (c);
    return 0;
  }
  c->c_close (c);

  return rev.dbrev;
}

bool
authcursor_db::update_key (str aek, dbrec_rev *val)
{
  db_t k (aek), v;
  if (dbs->delta) {
    if (!(val->dbrev = update_rev (aek, val->dbrev)))
      return false;
    v = *val;
  }
  else
    v = *implicit_cast<sfsauth_dbrec *> (val);

  if (int err = dbc->c_put (dbc, &k, &v, DB_KEYLAST)) {
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    error = true;
    return false;
  }
  return true;
}

bool
authcursor_db::update_map (DB *map, db_t *okey, db_t *nkey, str aek,
			   const char *mapname)
{
  db_t v (aek);
  if (okey && okey->size) {
    db_t ov;
    int err = map->get (map, tid, okey, &ov, 0);
    if (err == DB_NOTFOUND)
      warn << dbs->path << ": " << aek << " was not in " << mapname << "\n";
    else if (err) {
      warn << dbs->path << ": " << db_strerror (err) << "\n";
      error = true;
      return false;
    }
    else if (ov != v) {
      warn << dbs->path << ": " << aek << " not overriding "
	   << ov.getstr () << " in " << mapname << "\n";
      return true;
    }
    else if (nkey && *okey == *nkey)
      return true;
    else if ((err = map->del (map, tid, okey, 0))) {
      warn << dbs->path << ": " << db_strerror (err) << "\n";
      error = true;
      return false;
    }
  }

  if (nkey) {
    if (int err = map->put (map, tid, nkey, &v, DB_NOOVERWRITE)) {
      warn << dbs->path << ": " << db_strerror (err) << "\n";
      error = true;
      return false;
    }
  }
  return true;
}

bool
authcursor_db::update_user ()
{
  str aek = aekey (ae);

  db_t pkk (ae.userinfo->pubkey), opkk;
  db_t uid (ae.userinfo->id), ouid;
  dbrec_rev oldrec;
  if (getkey (&oldrec, aek)) {
    ae.dbrev = oldrec.dbrev;
    opkk = oldrec.userinfo->pubkey;
    ouid = oldrec.userinfo->id;
  }
  if (error
      || !update_map (dbs->pkmap, &opkk, &pkk, aek, "public key map")
      || !update_map (dbs->uidmap, &ouid, &uid, aek, "user ID map"))
    return false;

  return update_key (aek, &ae);
}

static void memberprint (const char *msg, const sfs_groupmembers &gm)
  __attribute__ ((unused));
static void
memberprint (const char *msg, const sfs_groupmembers &gm)
{
  warnx << "===========================\n"
	<< msg << "\n"
	<< "===== dumping members =====\n";
  for (const sfs_groupmember *gmp = gm.base (); gmp < gm.lim (); gmp++)
    warnx << *gmp << "\n";
  warnx << "===========================\n";
}

static int
membercmp (const void *_a, const void *_b)
{
  const sfs_groupmember *a = static_cast<const sfs_groupmember *> (_a);
  const sfs_groupmember *b = static_cast<const sfs_groupmember *> (_b);
  return strcmp (*a, *b);
}

void
membersort (sfs_groupmembers *gms)
{
  size_t oldsize = gms->size ();
  qsort (gms->base (), oldsize, sizeof ((*gms)[0]), membercmp);
  for (ssize_t i = oldsize - 1; i > 0; i--) {
    int j = i;
    while (i > 0 && (*gms)[i-1] == (*gms)[i])
      i--;
    while (j > i) {
      (*gms)[j--] = gms->back ();
      gms->pop_back ();
    }
  }
  if (gms->size () != oldsize)
    qsort (gms->base (), gms->size (), sizeof ((*gms)[0]), membercmp);
}

void
memberdiff (sfs_groupmembers *plus, sfs_groupmembers *minus,
	    sfs_groupmembers &oldlist, sfs_groupmembers &newlist)
{
  plus->clear ();
  minus->clear ();
  membersort (&oldlist);
  membersort (&newlist);
  sfs_groupmember *op = oldlist.base ();
  sfs_groupmember *np = newlist.base ();
  while (op < oldlist.lim () && np < newlist.lim ()) {
    int cmp = strcmp (*op, *np);
    if (!cmp) {
      op++;
      np++;
    }
    else if (cmp < 0)
      minus->push_back (*op++);
    else if (cmp > 0)
      plus->push_back (*np++);
  }
  while (op < oldlist.lim ())
    minus->push_back (*op++);
  while (np < newlist.lim ())
    plus->push_back (*np++);
}

inline void
setgroupkey (DBT *kp, const str &aek, const str &gm)
{
  assert (!memchr (gm, ':', gm.len ()));

  char *data = static_cast<char *> (kp->data);
  u_int n = gm.len ();
  memcpy (data, gm.cstr (), n);
  data[n++] = ':';
  memcpy (data + n, aek.cstr (), aek.len ());
  n += aek.len ();
  data[n++] = '\0';
  kp->size = n;
}

bool
authcursor_db::update_members (DB *map, sfs_groupmembers *oms,
			       sfs_groupmembers *nms, str aek,
			       const char *mapname)
{
  sfs_groupmembers plus, minus;
  if (oms && nms)
    memberdiff (&plus, &minus, *oms, *nms);
  else if (!oms) {
    membersort (nms);
    plus = *nms;
  }
  else if (!nms) {
    membersort (oms);
    minus = *oms;
  }

  if (plus.empty () && minus.empty ())
    return true;

  db_t k, v;
  int err;
  DBC *c = NULL;
  mstr scratch (aek.len () + sfs_groupmember::maxsize + 2);
  k.data = static_cast<void *> (scratch.cstr ());

  if ((err = map->cursor (map, tid, &c, 0)))
    goto bad;
  for (sfs_groupmember *gmp = minus.base (); gmp < minus.lim (); gmp++) {
    setgroupkey (&k, aek, *gmp);
    err = c->c_get (c, &k, &v, DB_SET);
    if (err == DB_NOTFOUND)
      warn << dbs->path << ": " << *gmp << "->" << aek
	   << " was missing from " << mapname << "\n";
    else if (err || (err = c->c_del (c, 0)))
      goto bad;
  }
  v.alloc (0);
  for (sfs_groupmember *gmp = plus.base (); gmp < plus.lim (); gmp++) {
    setgroupkey (&k, aek, *gmp);
    err = c->c_put (c, &k, &v, DB_KEYLAST);
    if (err == DB_KEYEXIST)
      warn << dbs->path << ": " << *gmp << "->" << aek
	   << " appears twice in " << mapname << "\n";
    else if (err)
      goto bad;
  }

  c->c_close (c);
  return true;

 bad:
  warn << dbs->path << ": " << db_strerror (err) << "\n";
  if (c)
    c->c_close (c);
  error = true;
  return false;
}

bool
authcursor_db::update_group ()
{
  str aek = aekey (ae);

  db_t gid (ae.groupinfo->id), ogid;
  sfs_groupmembers *oms = NULL;
  dbrec_rev oldrec;
  if (getkey (&oldrec, aek)) {
    ae.dbrev = oldrec.dbrev;
    ogid = oldrec.groupinfo->id;
    oms = &oldrec.groupinfo->members;
  }
  if (error
      || !update_map (dbs->gidmap, &ogid, &gid, aek, "group ID map")
      || !update_members (dbs->u2gmap, oms, &ae.groupinfo->members, aek,
			  "user->group map"))
    return false;

  return update_key (aek, &ae);
  return true;
}

bool
authcursor_db::update_cacheentry ()
{
  str aek = aekey (ae);

  sfs_groupmembers *oms = NULL;
  dbrec_rev oldrec;
  if (getkey (&oldrec, aek)) {
    ae.dbrev = oldrec.dbrev;
    oms = &oldrec.cacheentry->values;
  }
  if (error
      || !update_members (dbs->u2gmap, oms, &ae.cacheentry->values, aek,
			  "user->group map"))
    return false;

  return update_key (aek, &ae);
}

bool
authcursor_db::update ()
{
  if (!init (true))
    return false;

  bool ret;
  switch (ae.type) {
  case SFSAUTH_USER:
    ret = update_user ();
    break;
  case SFSAUTH_GROUP:
    ret = update_group ();
    break;
  case SFSAUTH_CACHEENTRY:
    ret = update_cacheentry ();
    break;
  default:
    ret = false;
    break;
  }
  if (ret)
    return complete ();
  abort ();
  return false;
}

bool
authcursor_db::find_user_pubkey (const sfspub &pk)
{
  if (!dbs->pkmap)
    return authcursor::find_user_pubkey (pk);
  sfs_pubkey2 pk2;
  if (!pk.export_pubkey (&pk2))
    return false;
  return getseckey (dbs->pkmap, pk2);
}

bool
authcursor_db::find_user_uid (u_int32_t uid)
{
  if (!dbs->uidmap)
    return authcursor::find_user_uid (uid);
  return getseckey (dbs->uidmap, uid);
}

bool
authcursor_db::find_group_gid (u_int32_t gid)
{
  if (!dbs->gidmap)
    return authcursor::find_group_gid (gid);
  return getseckey (dbs->gidmap, gid);
}

inline str
strip2prefix (const str &pref, void *_data, u_int size)
{
  const char *data = static_cast<char *> (_data);
  u_int n = pref.len ();
  if (size <= n || data[n] != ':' || memcmp (pref, data, n))
    return NULL;
  if (!data[size - 1])
    size--;
  if (const char *p = static_cast<char *> (memchr (data + n + 1, ':',
						   size - n - 1))) {
    p++;
    size -= p - data;
    return str (p, size);
  }
  return NULL;
}

bool
authcursor_db::find_rev (u_int64_t dbrev)
{
  if (!dbs->delta)
    return (authcursor::find_rev (dbrev));
  return getseckey (dbs->delta, dbrev, false);
}

void
authcursor_db::find_groups_member (vec<str> *groups, str member)
{
  if (!dbs->u2gmap)
    return authcursor::find_groups_member (groups, member);

  init ();
  DBC *c;
  int err = dbs->u2gmap->cursor (dbs->u2gmap, tid, &c, 0);
  if (err) {
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    error = true;
    return;
  }

  db_t mk, v;
  mk.alloc (member.len () + 2);
  memcpy (mk.data, member.cstr (), member.len ());
  static_cast<char *> (mk.data)[member.len ()] = ':';
  static_cast<char *> (mk.data)[member.len () + 1] = '\0';
  if (!c->c_get (c, &mk, &v, DB_SET_RANGE))
    while (str g = strip2prefix (member, mk.data, mk.size)) {
      groups->push_back (g);
      if (c->c_get (c, &mk, &v, DB_NEXT))
	break;
    }
  c->c_close (c);
}

void
authcursor_db::find_gids_user (vec<u_int32_t> *gids, str user)
{
  vec<str> groups;
  find_groups_member (&groups, strbuf () << "u=" << user);
  bhash<u_int32_t> seen;
  for (str *gp = groups.base (); gp < groups.lim (); gp++)
    if (find_group_name (*gp) && ae.type == SFSAUTH_GROUP) {
      u_int32_t gid = ae.groupinfo->id;
      if (seen.insert (gid))
	gids->push_back (gid);
    }
}

u_int
authcursor_db::count_group_prefix (str pref)
{
  if (!init ())
    return u_int (-1);
  pref = strbuf () << "GROUP:" << pref;
  db_t k (pref), v;
  if (dbc->c_get (dbc, &k, &v, DB_SET_RANGE))
    return 0;
  u_int ret = 0;
  while (k.size > pref.len ()
	 && !strncmp (pref, static_cast<char *> (k.data), pref.len ())) {
    ret++;
    if (dbc->c_get (dbc, &k, &v, DB_NEXT))
      break;
  }
  return ret;
}

bool
authcursor_db::findid (u_int32_t *res, DBC *c, u_int32_t min, u_int32_t max)
{
  if (min > max)
    return false;

  u_int32_t expected = min;
  db_t k (expected), v;
  int err = c->c_get (c, &k, &v, DB_SET_RANGE);
  do {				// Have to iterate 2^32+1 times for [0-,^32]
    if (err == DB_NOTFOUND) {
      *res = expected;
      return true;
    }
    else if (err) {
      warn << dbs->path << ": " << db_strerror (err) << "\n";
      return false;
    }
    u_int32_t val;
    if (!k.getxdr (&val)) {
      warn << dbs->path << ": gidmap contains corrupted key\n";
      return false;
    }
    else if (val > expected) {
      *res = expected;
      return true;
    }
    else if (val < expected) {
      warn << dbs->path << ": gidmap out of order???\n";
      return false;
    }
    err = c->c_get (c, &k, &v, DB_NEXT);
  } while (++expected <= max && expected);

  return false;
}

u_int32_t
authcursor_db::alloc_gid (u_int32_t min, u_int32_t max)
{
  if (!dbs->gidmap)
    return authcursor::alloc_gid (min, max);
  if (min > max || !init (true))
    return badid;

  DBC *c;
  if (int err = dbs->gidmap->cursor (dbs->gidmap, tid, &c, 0)) {
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    return badid;
  }

  /* Store hint under key "" */
  u_int32_t hint;
  db_t k, v;
  if (c->c_get (c, &k, &v, DB_SET) || !v.getxdr (&hint))
    hint = min;
  else if (++hint > max || hint < min)
    hint = min;

  u_int32_t res;
  if (!findid (&res, c, hint, max) && !findid (&res, c, min, hint))
    res = badid;
  else {
    v = res;
    c->c_put (c, &k, &v, DB_KEYFIRST);
  }

  c->c_close (c);
  return res;
}


authcursor_db_trunc::authcursor_db_trunc (ref<dbset> dbs, ref<audblock> lf,
					  ref<dbset> target)
  : authcursor_db (dbs, lf, true), target (target), retargeted (false)
{
}

authcursor_db_trunc::~authcursor_db_trunc ()
{
}

bool
authcursor_db_trunc::update ()
{
  if (retargeted)
    return authcursor_db::update ();

  if (!init (true))
    return false;
  assert (!tid);

  db_t k (aekey (ae)), v (ae);
  if (int err = dbc->c_put (dbc, &k, &v, DB_KEYLAST)) {
    warn << dbs->path << ": " << db_strerror (err) << "\n";
    error = true;
    return false;
  }

  return true;
}

static void
totinc (u_long &ntot, u_int pctval)
{
  ntot++;
  if (pctval && !(ntot % pctval)) {
    pctval = ntot / pctval;
    if (pctval >= 100)
      pctval = 99;
    str percent (strbuf (" % 3d%%\b\b\b\b\b", pctval));
    write (errfd, percent.cstr (), percent.len ());
  }
}

bool
authcursor_db_trunc::commit (size_t totexpect)
{
  if (totexpect)
    totexpect = (totexpect / 100) + 1;

  if (error || retargeted || !dbs->ok () || !target->ok ()) {
    error = true;
    return false;
  }

  assert (!tid);
  abort ();

  ref<dbset> source = dbs;
  DBC *sc;
  if (int err = source->dbrec->cursor (source->dbrec, NULL, &sc, 0)) {
    warn << dbs->path << ": commit: " << db_strerror (err) << "\n";
    error = true;
    return false;
  }

  retargeted = true;
  dbs = target;

  if (!init (true)) {
    sc->c_close (sc);
    error = true;
    return false;
  }

  u_long nadd = 0, ndel = 0, nmod = 0, ntot = 0;
  db_t sk, k, sv, v;
  int serr = sc->c_get (sc, &sk, &sv, DB_NEXT);
  int err = dbc->c_get (dbc, &k, &v, DB_NEXT);
  while (!serr && !err) {
    int r = cmp (sk, k);
    //warnx ("XXX % 2d  %s <==> %s\n", r, (char *) sk.data, (char *) k.data);
    if (r < 0) {
      if (!sv.getxdr (&ae)) {
	warn ("temporary database corrupted\n");
	error = true;
	break;
      }
      if (!update ())
	break;
      serr = sc->c_get (sc, &sk, &sv, DB_NEXT);
      str prevk = k.getstr ();
      err = dbc->c_get (dbc, &k, &v, DB_NEXT);
      assert (prevk = (char *) k.data);
      nadd++;
      totinc (ntot, totexpect);
    }
    else if (r > 0) {
      if (!v.getxdr (&ae)) {
	warn ("%s: could not parse record for %s\n", dbs->path.cstr (),
	      (char *) k.data);
	error = true;
	break;
      }
      if (!remove (NULL))
	break;
      err = dbc->c_get (dbc, &k, &v, DB_NEXT);
      ndel++;
    }
    else {
      if (v != sv) {
	if (!sv.getxdr (&ae)) {
	  warn ("temporary database corrupted\n");
	  error = true;
	  break;
	}
	if (!update ())
	  break;
	nmod++;
      }
      serr = sc->c_get (sc, &sk, &sv, DB_NEXT);
      err = dbc->c_get (dbc, &k, &v, DB_NEXT);
      totinc (ntot, totexpect);
    }
  }
  while (!error && !serr && err == DB_NOTFOUND) {
    if (!sv.getxdr (&ae)) {
      warn ("temporary database corrupted\n");
      error = true;
      break;
    }
    if (!update ())
      break;
    serr = sc->c_get (sc, &sk, &sv, DB_NEXT);
    nadd++;
    totinc (ntot, totexpect);
  }
  while (!error && !err && serr == DB_NOTFOUND) {
    if (!v.getxdr (&ae)) {
      warn ("%s: could not parse record for %s\n", dbs->path.cstr (),
	    (char *) k.data);
      error = true;
      break;
    }
    if (!remove (NULL))
      break;
    err = dbc->c_get (dbc, &k, &v, DB_NEXT);
    ndel++;
  }

  sc->c_close (sc);
  if (error || err != DB_NOTFOUND || serr != DB_NOTFOUND
      || !source->ok () || !dbs->ok ()) {
    source->sync ();
    //clean (source);
    error = true;
    return false;
  }

  bool ret = authcursor_db::commit ();
  if (totexpect)
    warnx << "done \n";
  if (ret)
    warn ("%s: %lu new records, %lu deleted, %lu modified, %lu total\n",
	  dbs->path.cstr (), nadd, ndel, nmod, ntot);
  error = true;			// Can't use after committing
  dbs->sync ();
  return ret;
}

ptr<authcursor_db_trunc>
authcursor_db_trunc::alloc (ref<dbset> targetdbs, ref<audblock> lf)
{
  ref<dbset_mem> dbs = New refcounted<dbset_mem> ();
  dbs->dbenvdir = targetdbs->dbenvdir;
  dbs->dbenv = targetdbs->dbenv;
  if (!dbs->open (targetdbs->perm, DB_CREATE | DB_EXCL, 0))
    return NULL;
  return New refcounted<authcursor_db_trunc> (dbs, lf, targetdbs);
}

authcursor_db_rename::authcursor_db_rename (ref<dbset> dbs,
					    ref<audblock> lf, str t)
  : authcursor_db (dbs, lf, true, true), target (t), renamed (false)
{
  /* Paranoia--don't want to delete/rename any old database.
   * (Rename assumes names have trailing '~'.) */
  for (int i = 0; i < dbset_size; i++)
    if (str path = dbs->dbfile (dbset_entries[i].name))
      if (!path.len () || path[path.len () - 1] != '~')
	panic ("authcursor_db_rename:  database %s must end with '~'\n",
	       path.cstr ());
  init (true);
  if (!dbs->truncate (tid)) {
    error = true;
    abort ();
  }
}

authcursor_db_rename::~authcursor_db_rename ()
{
  clean ();
}

void
authcursor_db_rename::clean ()
{
  if (renamed)
    return;

  abort ();
  dbs->close ();
  dbs->mktxn (&tid);

  bhash<str> paths;
  for (int i = 0; i < dbset_size; i++)
    if (str path = dbs->dbfile (dbset_entries[i].name))
      if (paths.insert (path))
	if (tid) {
	  if (int err = dbs->dbenv->e->dbremove (dbs->dbenv->e,
						 tid, path, NULL, 0))
	    warn << "Removing " << path << ": " << db_strerror (err) << "\n";
	}
	else
	  unlink (path);

  flushtxn ();
}

bool
authcursor_db_rename::rename ()
{
  if (renamed)
    return false;
  if ((dbs->dbenv && (dbs->dbenv->error || !flushtxn ())) || !dbs->sync ())
    return false;
  abort ();
  dbs->close ();
  dbs->mktxn (&tid);

  str path;
  int err;
  bhash<str> paths;
  for (int i = 0; i < dbset_size; i++)
    if ((path = dbs->dbfile (dbset_entries[i].name)) && paths.insert (path)) {
      str dest = substr (path, 0, path.len () - 1);
      if (!tid /*!dbs->dbenv*/) {
	dbs->dbenv = NULL;
	if (::rename (path, dest)) {
	  warn ("rename %s -> %s: %m\n", path.cstr (), dest.cstr ());
	  return false;
	}
      }
      else if ((err = dbs->dbenv->e->dbrename (dbs->dbenv->e, tid,
					       path, NULL, dest, 0))) {
	warn ("rename %s -> %s: %s\n", path.cstr (), dest.cstr (),
	      db_strerror (err));
	abort ();
	return false;
      }
    }

  renamed = flushtxn ();
  error = false;
  return renamed;
}

bool
authcursor_db_rename::commit (size_t tot)
{
  return authcursor_db::commit (tot) && rename ();
}

ptr<authcursor>
authdb_db::open (u_int flags, mode_t perm, ptr<audblock> l)
{
  const bool writable = flags & AUDB_WRITE;
  const bool create = flags & AUDB_CREATE;
  const bool trunc = flags & AUDB_TRUNC;
  const bool wait = flags & AUDB_WAIT;
  const bool norecov = flags & AUDB_NORECOV;
  const bool async = flags & AUDB_ASYNC;

  if (writable & norecov) {
    warn << "cannot open database for writing without recovery\n";
    return NULL;
  }

  u_int32_t dbfl = 0;
  if (!writable)
    dbfl |= DB_RDONLY;
  if (create)
    dbfl |= DB_CREATE;
  if (!norecov)
    dbfl |= DB_AUTO_COMMIT;

  // XXX - multiple opens for writing?
  if (writable && !l && !(l = lock (wait)))
    return NULL;

  if (dbs && !dbs->ok ()) {
    warn << "reopening " << dbs->path << "\n";
    dbs = NULL;
  }
  if (dbs && writable && (dbs->flags & DB_RDONLY))
    dbs = NULL;
  if (dbs && norecov != !(dbs->flags & DB_AUTO_COMMIT))
    dbs = NULL;

  if (!dbs) {
    dbs = getdbs ();
    if (!dbs)
      return NULL;
    if ((!trunc || dbs->envdir ())
	&& !dbs->open (perm, dbfl,
		       (flags & AUDB_RUNRECOV) ? DB_RECOVER_FATAL : 0)) {
      int err = errno;
      dbs = NULL;
      if (create && !writable && err == ENOENT)
	return New refcounted<authcursor_null> ();
      return NULL;
    }
  }

  ptr<dbset> dbstmp;
  if (!trunc)
    return New refcounted<authcursor_db> (dbs, l, trunc, async);
  else if (dbs->dbenv && dbs->dbenv->txn)
    return authcursor_db_trunc::alloc (dbs, l);
  else if ((dbstmp = getdbs (true))
	   && dbstmp->open (perm, DB_CREATE|DB_AUTO_COMMIT, 0))
    return New refcounted<authcursor_db_rename> (dbstmp, l, dbs->path);
  else
    return NULL;
}

ptr<audblock>
authdb_db::lock (bool wait)
{
  if (!lf) {
    str lp = lockpath ();
    if (!lp)
      return NULL;
    lf = New refcounted<lockfile> (lp);
  }
  if (lf->locked ())
    panic ("attempt to lock authdb multiple times\n");
  if (!lf->acquire (wait)) {
#if 0
    if (errno != ENOENT)
      return NULL;
    if (!dbs)
      dbs = getdbs ();
    if (!dbs->open (-1, DB_CREATE | DB_AUTO_COMMIT, 0))
      dbs = NULL;
    if (!lf->acquire (wait))
#endif
      return NULL;
  }
  return New refcounted<audblock_file> (lf);
}

bool
authdb_db::revinfo (sfsauth_revinfo *rip)
{
  if (ptr<authcursor> ac = open (0, 0600, NULL))
    return static_cast<authcursor_db *> (ac.get ())->revinfo (rip);
  rpc_clear (*rip);
  return false;
}

str
authdb_txn::lockpath ()
{
  if (strchr (path, '/'))
    return path << ".lock";
  if (!dbs)
    dbs = getdbs ();
  if (!dbs)
    return NULL;
  return dbenv_t::mkdbpath (path, dbs->dbenvdir) << ".lock";
}

ptr<dbset>
authdb_txn::getdbs (bool tmpname)
{
  str p = tmpname ? str (path << "~") : path;
  return New refcounted<dbset_txn> (p);
}

ptr<dbset>
authdb_dir::getdbs (bool tmpname)
{
  if (tmpname) {
    errno = EINVAL;
    return NULL;
  }
  return New refcounted<dbset_dir> (path);
}

ptr<authdb>
authdb_db_alloc (str path)
{
  struct stat sb;
  if (!stat (path, &sb) && S_ISDIR (sb.st_mode))
    return New refcounted<authdb_dir> (path);
  else if (path.len () && path[path.len () - 1] == '/')
    return New refcounted<authdb_dir> (path);
  else
    return New refcounted<authdb_txn> (path);
}

#endif /* SLEEPYCAT */

ptr<authdb>
authdb_alloc (str path, str fp)
{
  if (!fp)
    fp = path;
  const char *suffix = strrchr (fp, '.');
  if (suffix)
    suffix++;
  else
    suffix = "";
  if (!strcmp (suffix, "db"))
    return authdb_db_alloc (path);
  else if (!strcmp (suffix, "db/"))
    return authdb_db_alloc (path);
  else
    return New refcounted<authdb_file> (path);
}
