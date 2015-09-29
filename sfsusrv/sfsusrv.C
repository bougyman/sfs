/*
 *
 * Copyright (C) 2000 Frans Kaashoek (kaashoek@mit.edu)
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

#include "sfsusrv.h"
#include "parseopt.h"
#include "rxx.h"
#include "sfscrypt.h"

filesrv *defsrv;
static str configfile;
static int usrv_standalone;
static short sfsusrv_port;

void 
client_accept (ptr<axprt_crypt> x)
{
  if (!x)
    fatal ("EOF from sfssd\n");
  vNew client (x);
}

static void
sfs_accept_standalone (sfsserv_cb cb, int sfssfd)
{
  sockaddr_in sin;
  bzero (&sin, sizeof (sin));
  socklen_t sinlen = sizeof (sin);
  int fd = accept (sfssfd, reinterpret_cast<sockaddr *> (&sin), &sinlen);
  if (fd >= 0) {
    tcp_nodelay (fd);
    ref<axprt_crypt> x = axprt_crypt::alloc (fd);
    (*cb) (x);
  } else if (errno != EAGAIN)
    warn ("accept: %m\n");
}

static void
start_server (filesrv *fsrv)
{
  setgid (sfs_gid);
  setgroups (0, NULL);

  warn ("version %s, pid %d\n", VERSION, int (getpid ()));
  defsrv = fsrv;

  if (usrv_standalone) {
    int sfssfd = inetsocket (SOCK_STREAM, sfsusrv_port);
    if (sfssfd < 0)
      fatal ("binding TCP port %d: %m\n", sfsusrv_port);
    
    if (sfsusrv_port == 0) {
      struct sockaddr_in addr;
      socklen_t len = sizeof (addr);
      bzero (&addr, sizeof (addr));
      if (getsockname (sfssfd, (sockaddr *) &addr, &len) < 0) 
	fatal ("getsockname failed %m\n");
      sfsusrv_port = ntohs (addr.sin_port);
    }
    
    warn << "No sfssd detected, running in standalone mode.\n";
    warn << "Now exporting directory: " << fsrv->root->path << "\n";
    warn << "serving " << sfsroot << "/"  << sfsusrv_port << "@" 
	 << fsrv->siw->mkpath () << "\n"; 
    
    close_on_exec (sfssfd);
    listen (sfssfd, 5);
    fdcb (sfssfd, selread, wrap (sfs_accept_standalone, wrap (client_accept), sfssfd));
  } else
    sfssd_slave (wrap (client_accept));
  
}


static filesrv *
parseconfig (str cf)
{
  parseargs pa (cf);
  bool errors = false;

  filesrv *fsrv = New filesrv;
  fsrv->servinfo.set_sivers (7);
  fsrv->servinfo.cr7->release = sfs_release;

  int line;
  vec<str> av;
  ptr<rabin_priv> rsk;
  while (pa.getline (&av, &line)) {
    if (!strcasecmp (av[0], "export")) {
       str root (av[1]);
       if ((fsrv->root = fsrv->lookup_add (root)) == NULL) {
 	 errors = true;
	 warn << cf << ":" << line << ": non-existing root\n";
       }
    }
    else if (!strcasecmp (av[0], "hostname")) {
      if (av.size () != 2) {
	errors = true;
	warn << cf << ":" << line << ": usage: hostname name\n";
      }
      else if (fsrv->servinfo.cr7->host.hostname) {
	errors = true;
	warn << cf << ":" << line << ": hostname already specified\n";
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
	else if (!(fsrv->privkey = sfscrypt.alloc_priv (key, SFS_DECRYPT))) {
	  errors = true;
	  warn << cf << ":" << line << ": could not decode keyfile\n";
	}
      }
      else {
	errors = true;
	warn << cf << ":" << line << ": usage: keyfile path\n";
      }
    }
  }
    
  fsrv->servinfo.cr7->host.type = SFS_HOSTINFO;
  if ((fsrv->servinfo.cr7->host.hostname.len () == 0)
      && !(fsrv->servinfo.cr7->host.hostname = myname ()))
    fatal ("could not figure out my host name\n");
  if (!fsrv->privkey)
    fatal ("no Keyfile specified\n");
  if (!fsrv->privkey->export_pubkey (&fsrv->servinfo.cr7->host.pubkey))
    fatal ("Could not load Rabin public key\n");
  fsrv->servinfo.cr7->prog = ex_NFS_PROGRAM;
  fsrv->servinfo.cr7->vers = ex_NFS_V3;
  fsrv->siw = sfs_servinfo_w::alloc (fsrv->servinfo);
  if (!fsrv->siw->mkhostid (&fsrv->hostid))
    fatal ("could not marshal my own hostinfo\n");

  return fsrv;
}


static void
usage ()
{
  warnx << "usage: " << progname << " [-s] [-p port] -f configfile\n";
  exit (1);
}

int
main (int argc, char **argv)
{
  filesrv *fsrv;

  setprogname (argv[0]);
  sfsconst_init ();

  usrv_standalone = 0;
  sfsusrv_port = sfs_defport;

  int ch;
  while ((ch = getopt (argc, argv, "f:sp:")) != -1)
    switch (ch) {
    case 'f':
      configfile = optarg;
      break;
    case 's':
      usrv_standalone = 1;
      break;
    case 'p':
      sfsusrv_port = atoi (optarg);
      break;
    case '?':
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;

  if ( (argc > 0) || (!configfile) )
    usage ();

  fsrv = parseconfig (configfile);

  start_server (fsrv);
  amain ();
}
