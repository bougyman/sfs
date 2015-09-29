/* $Id: vidb.C,v 1.35 2004/06/17 21:10:24 dm Exp $ */

/*
 *
 * Copyright (C) 2001-2003 David Mazieres (dm@uun.org)
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
#include "sfsmisc.h"
#include "sfskeymisc.h"
#include "init.h"
#include "rxx.h"

static str editor;
static str tmppath;
static str db;
static ptr<authdb> targetdb;
static ptr<audblock> dblock;
static struct stat tmpsb;
static bool no_delete;
static ptr<authcursor> targetac;
static int killed;

static bool opt_runrecov;
static bool opt_wait;
static bool opt_salvage;
static bool opt_add;
static str opt_file;

EXITFN (cleanup);
static void
cleanup ()
{
  if (tmppath && !no_delete) {
    unlink (tmppath);
    tmppath = tmppath << "~";
    unlink (tmppath);
  }
  dblock = NULL;
  targetac = NULL;
  targetdb = NULL;
}

static void
setkilled (int sig)
{
  killed = 1;
}

static void
sethandlers ()
{
  signal (SIGINT, setkilled);
  signal (SIGTERM, setkilled);
}

static int
tmpinit ()
{
  const char *tmpdir = getenv ("TMPDIR");
  if (!tmpdir)
    tmpdir = "/tmp";
  char *pathbuf;
  {
    str tmpl (strbuf ("%s/%sXXXXXXXXXX", tmpdir, progname.cstr ()));
    pathbuf = xstrdup (tmpl);
  } 
  mode_t m = umask (077);
  int fd = mkstemp (pathbuf);
  if (fd < 0)
    fatal ("%s: %m\n", pathbuf);
  umask (m);
  tmppath = pathbuf;
  xfree (pathbuf);
  return fd;
}

static void
setdb ()
{
  str file = db;
  if (!file || !file.len ())
    fatal ("missing/invalid database name\n");
  if (!strchr (file, '/'))
    file = strbuf ("./") << db;
  targetdb = authdb_alloc (file);
  if (!targetdb)
    fatal << db << ": file extension not supported type\n";
}

static void
memberquery (str user)
{
  setdb ();
  vec<str> groups;
  
  ptr<authcursor> ac = targetdb->open (0, 0600, dblock);
  ac->find_groups_member (&groups, user);
  for (str *sp = groups.base (); sp < groups.lim (); sp++)
    printf ("%s\n", sp->cstr ());
}

static bool
lockit ()
{
  setdb ();
  if (db[db.len () - 1] == '/' && !opt_salvage
      && access (db, 0) < 0 && errno == ENOENT)
    mkdir (db, 0700);

  dblock = targetdb->lock (false);
  if (!dblock) {
    if (!opt_wait) {
      warn << db << ": could not lock\n";
      return false;
    }
    warn << ": waiting for lock on " << db << "...";
    if (dblock = targetdb->lock (opt_wait))
      warnx << " acquired\n";
  }

  return dblock;
}

static void
copyit (int fd)
{
  u_int32_t flags;
  if (opt_salvage)
    flags = authdb::AUDB_NORECOV;
  else {
    flags = authdb::AUDB_CREATE;
    if (opt_runrecov)
      flags |= authdb::AUDB_RUNRECOV;
  }

  ptr<authcursor> ac = targetdb->open (flags, 0600, dblock);
  if (!ac)
    fatal << db << ": " << strerror (errno) << "\n";

  int n;
  if ((n = fcntl (fd, F_GETFL)) >= 0)
    fcntl (fd, F_SETFL, n & ~O_NONBLOCK);

  bool pe = false;
  FILE *out = fdopen (fd, "w");
  while (ac->next (&pe)) {
    str line = authdbrec2str (&ac->ae);
    assert (line);
    if (fprintf (out, "%s\n", line.cstr ()) < 0) {
      if (tmppath)
	fatal << tmppath << ": " << strerror (errno) << "\n";
      else
	fatal << "stdout: " << strerror (errno) << "\n";
    }
  }
  if (pe)
    fatal << db << ": error reading/parsing file\n";

  fflush (out);
  if (!opt_salvage && fstat (fd, &tmpsb) < 0)
    fatal << tmppath << ": " << strerror (errno) << "\n";
  fclose (out);
}

static void
checklock ()
{
  if (!dblock->ok ()) {
    no_delete = true;
    fatal << "lock was stolen -- file saved in " << tmppath << "\n";
  }
}

static void
addrecords (str file)
{
  bool chatter = isatty (errfd);
  off_t filesize = 0;

  ptr<authcursor_file> vic;
  if (file) {
    if (access (file, R_OK) < 0)
      fatal ("%s: %m\n", file.cstr ());
    vic = New refcounted<authcursor_file> (file, 0, ptr<audblock> (NULL));
  }
  else {
    file = "(stdin)";
    vic = New refcounted<authcursor_file> (file, 0, ptr<audblock> (NULL), 0);
  }
  vic->linemax = 0;

  struct stat sb;
  if (!chatter || fstat (vic->fd, &sb) < 0 || !S_ISREG (sb.st_mode))
    chatter = false;
  else
    filesize = sb.st_size;

  targetac = targetdb->open ((authdb::AUDB_WRITE
			      | authdb::AUDB_CREATE
			      | authdb::AUDB_ASYNC),
			     0600, dblock);
  if (!targetac)
    fatal << db << ": could not open database for writing\n";

  sethandlers ();

  int pct = -1;
  if (chatter)
    warnx ("adding records...");
  while (vic->next () && !killed) {
    targetac->ae = vic->ae;
    if (!targetac->update ())
      fatal ("Database update failed\n");
    if (chatter) {
      int npct = vic->buf.byteno () / (filesize / 100);
      if (npct != pct) {
	pct = npct;
	warnx (" % 3d%%\b\b\b\b\b", pct);
      }
    }
  }
  if (chatter)
    warnx (killed ? " interrupted\n" : " done \n");
  if (killed)
    targetac = NULL;
  else if (!targetac->commit ())
    fatal ("Database update failed\n");

  exit (0);
}

static int
finish ()
{
  struct stat sb;
  if (stat (tmppath, &sb) < 0)
    fatal << tmppath << ": " << strerror (errno) << "\n";
  if (stat_unchanged (&sb, &tmpsb)) {
    if (isatty (1))
      warn << tmppath << " unchanged\n";
    exit (0);
  }

  no_delete = true;
    
  checklock ();

  ptr<authdb> vidb = New refcounted<authdb_file> (tmppath);
  ptr<authcursor> vic = vidb->open (0);
  if (!vic)
    fatal << tmppath << ": " << strerror (errno) << "\n";

  bool chatter = isatty (errfd);
  if (chatter)
    warnx ("copying...");

  targetac = targetdb->open ((authdb::AUDB_WRITE
			      | authdb::AUDB_CREATE
			      | authdb::AUDB_TRUNC),
			     0600, dblock);
  if (!targetac)
    fatal << db << ": could not open database for writing\n"
	  << "file saved in " << tmppath << "\n";

  int badline = 1;
  bool pe = false;
  bhash<str> keys;
  for (vic->reset (); vic->next (&pe) && !pe; badline++) {
    str aek = aekey (vic->ae);
    if (!keys.insert (aek)) {
      warn << tmppath << ":" << badline
	   << ": duplicate entry for " << aek << "\n";
      pe = true;
      break;
    }
    targetac->ae = vic->ae;
    if (!targetac->update ()) {
      targetac = NULL;
      fatal << "database update failed, file saved in " << tmppath << "\n";
    }
  }
  keys.clear ();

  if (chatter)
    warnx (" done\n");

  if (pe) {
    targetac = NULL;
    no_delete = false;
    return badline;
  }

  checklock ();

  if (chatter)
    warnx ("committing...");
  if (!targetac->commit (chatter ? badline : 0))
    fatal << "commit failed, file saved in " << tmppath << "\n";

  no_delete = false;
  targetac = NULL;
  targetdb = NULL;
  exit (0);
}

static void
usage ()
{
  warnx << "usage: " << progname
	<< " [-w] [-R] {-S | -a [-f file] | [-e editor]} dbfile\n";
  exit (1);
}

bool
run_editor (str file, int line)
{
  static rxx edplus ("^(vi|nvi|.*emacs.*|vim|ee|ex|mg|pico)$");

  if (strchr (editor, ' ')) {
    str cmd (strbuf () << editor << " " << file);
    return !system (cmd);
  }

  const char *av[] = { editor, file, NULL, NULL };
  str plusarg;
  if (line > 0 && edplus.match (editor)) {
    plusarg = strbuf ("+%d", line);
    av[1] = plusarg;
    av[2] = file;
  }

  make_sync (0);
  make_sync (1);
  pid_t pid = spawn (editor, av);
  int status;
  return pid != -1 && waitpid (pid, &status, 0) == pid && !status;
}

static bool
get_yesno (const str &prompt) 
{
  for (;;) {
    str r = getline (prompt, NULL);
    if (!r || r.len () == 0) 
      return false;
    const char *cp = r.cstr ();
    if (*cp == 'Y' || *cp == 'y')
      return true;
    if (*cp == 'N' || *cp == 'n')
      return false;
  }
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  sfsconst_init ();

  str opt_memberquery;
  editor = getenv ("EDITOR");
  int ch;
  while ((ch = getopt (argc, argv, "RSwg:m:e:f:a")) != -1)
    switch (ch) {
    case 'S':
      opt_salvage = true;
      break;
    case 'R':
      opt_runrecov = true;
      break;
    case 'w':
      opt_wait = true;
      break;
    case 'g':
      if (opt_memberquery)
	usage ();
      opt_memberquery = optarg;
      break;
    case 'f':
      opt_file = optarg;
      break;
    case 'e':
      editor = optarg;
      break;
    case 'a':
      opt_add = true;
      break;
    default:
      usage ();
    }

  if ((opt_salvage && opt_add) || (opt_file && !opt_add))
    usage ();

  if (optind + 1 != argc)
    usage ();
  db = argv[optind];

  if (!editor)
    editor = "vi";
  if (str edpath = find_program (editor))
    editor = edpath;
  else
    fatal << editor << ": " << strerror (errno) << "\n";

  if (opt_memberquery) {
    if (opt_wait || opt_add || opt_file || opt_salvage)
      usage ();
    memberquery (opt_memberquery);
    exit (0);
  }

  if (!lockit () && !opt_salvage)
    fatal << db << ": could not lock database\n";

  if (opt_salvage) {
    copyit (1);
    exit (0);
  }

  if (opt_add) {
    addrecords (opt_file);
    exit (0);
  }

  int fd = tmpinit ();
  copyit (fd);

  int line = 0;
  for (;;) {
    if (!run_editor (tmppath, line))
      fatal << editor << ": abnormal exit\n";
    line = finish ();
    warn << "Database update refused\n";
    if (!get_yesno ("Retry database edit [y/N]? ")) {
      warn << "Database update aborted.\n";
      exit (0);
    }
  }
}
