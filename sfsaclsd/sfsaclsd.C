/* $Id: sfsaclsd.C,v 1.6 2004/06/17 21:10:23 dm Exp $ */

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

#include "sfsaclsd.h"
#include "parseopt.h"
#include "rxx.h"
#include "sfscrypt.h"

#include "aios.h"

int sfssfd;

static bool opt_dumphandles;
static str configfile;

filesrv *defsrv;

template<size_t max> inline hexdump
bdump (const rpc_bytes<max> &b)
{
  return hexdump (b.base (), b.size ());
}

template<size_t max> inline bool
a2bytes (rpc_bytes<max> &b, str a)
{
  int i = 0;
  b.setsize (a.len () / 2);
  for (const char *p = a.cstr (), *e = p + a.len (); p < e; p += 2) {
    int h, l;
    if (!hexconv (h, p[0]) || !hexconv (l, p[1]))
      return false;
    b[i++] = h << 4 | l;
  }
  return true;
}

static void
start_server (filesrv *fsrv, bool ok)
{
  if (!ok)
    fatal ("file server initialization failed\n");
  warn ("version %s, pid %d\n", VERSION, int (getpid ()));
  warn << "serving " << sfsroot << "/"
       << fsrv->siw->mkpath () << "\n";
  if (opt_dumphandles) {
    for (size_t i = 0; i < fsrv->fstab.size (); i++) {
      aout << (strbuf () << " export " << fsrv->fstab[i].host << ":"
	       << "*" << bdump (fsrv->fstab[i].fh_root.data)
	       << " " << fsrv->fstab[i].path_mntpt << "\n");
      aout << "#       *" << bdump (fsrv->fstab[i].fh_mntpt.data) << "\n";
    }
    exit (0);
  }

  defsrv = fsrv;

  sfssd_slave (wrap (client_accept));
}


static filesrv *
parseconfig (str cf)
{
  parseargs pa (cf);
  bool errors = false;

  filesrv *fsrv = New filesrv;
  int sivers = 7;
  fsrv->servinfo.set_sivers (sivers);
  fsrv->servinfo.cr7->release = sfs_release;

  int line;
  vec<str> av;
  while (pa.getline (&av, &line)) {
    if (!strcasecmp (av[0], "leasetime")) {
      if (av.size () != 2 || !convertint (av[1], &fsrv->leasetime)) {
	errors = true;
	warn << cf << ":" << line << ": usage: LeaseTime <seconds>\n";
      }
    }
    else if (!strcasecmp (av[0], "export")) {
      static rxx export_path ("^(([0-9a-zA-Z\\.\\-]+):)?(/.*)$");
      static rxx export_fh ("^([0-9a-zA-Z\\.\\-]+):\\*(.*)$");
      if (av.size () == 3 && export_path.match (av[1]) && av[2][0] == '/' ) {
	filesys &fs = fsrv->fstab.push_back ();
	fs.host = export_path[1];
	fs.path_root = export_path[3];
	fs.path_mntpt = av[2];
	fs.options = filesys::ANON_READWRITE;
      }
#if 0
      else if (av.size () == 3 && export_fh.match (av[1])
	       && av[2][0] == '/' ) {
	filesys &fs = fsrv->fstab.push_back ();
	fs.host = export_fh[1];
	fs.path_root = NULL;
	str fhstr = export_fh[2];
	if (fhstr.len () > 2 * NFS3_FHSIZE
	    || !a2bytes (fs.fh_root.data, fhstr)) {
	  errors = true;
	  warn << cf << ":" << line << ": invalid file handle\n";
	}
	fs.path_mntpt = av[2];
	fs.options = fsopt;
      }
#endif
      else {
	errors = true;
	warn << cf << ":" << line
	     << ": usage: export localpath name\n";
	warn << "(both localpath and name must start with a '/')\n";
      }
    }
    else if (!strcasecmp (av[0], "hostname")) {
      if (av.size () != 2) {
	errors = true;
	warn << cf << ":" << line << ": usage: hostname name\n";
      }
      else if (fsrv->servinfo.cr7->host.hostname != "") {
	errors = true;
	warn << cf << ":" << line << ": hostname already specified\n";
      }
      else if (!strchr (av[1], '.')) {
	errors = true;
	warn << cf << ":" << line << ": hostname must have domain\n";
      }
      else
	fsrv->servinfo.cr7->host.hostname = av[1];
    }
    else if (!strcasecmp (av[0], "keyfile")) {
      if (fsrv->privkey) {
	  errors = true;
	  warn << cf << ":" << line << ": keyfile already specified\n";
      }
      else if (av.size () == 2) {
	str key = file2wstr (av[1]);
	if (!key) {
	  errors = true;
	  warn << av[1] << ": " << strerror (errno) << "\n";
	  warn << cf << ":" << line << ": could not read keyfile\n";
	}
	else if (!(fsrv->privkey 
		   = sfscrypt.alloc_priv (key, SFS_ENCRYPT | SFS_DECRYPT))) { 
	  errors = true;
	  warn << cf << ":" << line << ": could not decode keyfile\n";
	}
      }
      else {
	errors = true;
	warn << cf << ":" << line << ": usage: keyfile path\n";
      }
    }
    else {
      errors = true;
      warn << cf << ":" << line << ": unknown directive '"
	   << av[0] << "'\n";
    }
  }

  if (!errors && !fsrv->privkey) {
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
      else if (!(fsrv->privkey = 
		 sfscrypt.alloc_priv (key, SFS_DECRYPT | SFS_ENCRYPT))) {
	errors = true;
	warn << "could not decode " << keyfile << "\n";
      }
    }
  }
  if (errors)
    fatal ("errors in config file\n");
  if (!fsrv->fstab.size ())
    fatal ("no 'export' directives in found config file\n");
  if (fsrv->fstab[0].path_mntpt != "/")
    fatal ("first export point must be named '/'\n");

  fsrv->servinfo.cr7->host.type = SFS_HOSTINFO;
  fsrv->servinfo.cr7->host.port = sfs_defport;
  if (fsrv->servinfo.cr7->host.hostname == "")
    fsrv->servinfo.cr7->host.hostname = sfshostname ();
  fsrv->privkey->export_pubkey (&fsrv->servinfo.cr7->host.pubkey);
  fsrv->servinfo.cr7->prog = ex_NFS_PROGRAM;
  fsrv->servinfo.cr7->vers = ex_NFS_V3;

  fsrv->siw = sfs_servinfo_w::alloc (fsrv->servinfo);
  if (!fsrv->siw->mkhostid (&fsrv->hostid))
    fatal ("could not marshal my own hostinfo\n");
  return fsrv;
}

static void usage () __attribute__ ((noreturn));
static void
usage ()
{
  warnx << "usage: " << progname << " [-x] [-f configfile]\n";
  exit (1);
}

int
main (int argc, char **argv)
{

  setprogname (argv[0]);

  int ch;
  while ((ch = getopt (argc, argv, "xf:")) != -1)
    switch (ch) {
    case 'f':
      configfile = optarg;
      break;
    case 'x':
      opt_dumphandles = true;
      break;
    case '?':
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;

  if (argc > 1)
    usage ();

  sfsconst_init ();
  if (!configfile)
    configfile = sfsconst_etcfile_required ("sfsaclsd_config");
  filesrv *fsrv = parseconfig (configfile);

  random_init_file (sfsdir << "/random_seed");

  fsrv->init (wrap (start_server, fsrv));
  amain ();
}
