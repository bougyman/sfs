/* $Id: sfsacl.c,v 1.1 2002/12/08 15:24:26 dm Exp $ */

/*
 *
 * Copyright (C) 2002 Michael Kaminsky (kaminsky@lcs.mit.edu)
 * Copyright (C) 2002 George Savvides (savvides@pdos.lcs.mit.edu)
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

#include "sfs-internal.h"
#include "hashtab.h"
#include "sfsagent.h"

#define SFSPREF ".SFS "
#define SFSFH SFSPREF "FH"
#define ACLSIZE 512

char *progname;
const char hexchars[] = "0123456789abcdef";

int
get_pos (char c)
{
  u_int i;
  for (i = 0; i < sizeof (hexchars); i ++) {
    if (c == hexchars[i])
      return i;
  }
  return -1;
}

u_char
get_opaquebyte (char d, char u)
{
  int i1, i2, v;
  i1 = get_pos (d);
  i2 = get_pos (u);
  v = i2 + (i1 << 4);
  return (u_char) v;
}

int
fh_lookup (char *path, char *fh, size_t fhlen,
	   char *object, size_t objectlen)
{
  u_int i;
  char *c;
  char dirbuf[MAXPATHLEN];
  char fhbuf[NFS3_FHSIZE];

  assert (fh);
  assert (object);
  assert (sizeof (fhbuf) <= (2 * fhlen));
  assert (objectlen >= 1 + strlen (path));

  /* remove last path component to get the directory */
  bzero (dirbuf, sizeof (dirbuf));
  i = strlen (path);
  while (path[--i] == '/')
    path[i] = '\0';
  c = strrchr (path, '/');
  if (!c) {
    strncpy (dirbuf, SFSFH, sizeof (dirbuf));
    c = path;
  }
  else {
    strncpy (dirbuf, path, c - path + 1);
    strcat (dirbuf, SFSFH);
    c++;
  }

  /* get the fh */
  bzero (fhbuf, sizeof (fhbuf));
  if (readlink (dirbuf, fhbuf, sizeof (fhbuf)) < 0)
    return 0;

  /* decoded fh is half the size (?!) */
  bzero (fh, fhlen);
  for (i = 0; i < (strlen (fhbuf) / 2); i++) {
    fh[i] = get_opaquebyte (fhbuf[2*i], fhbuf[2*i+1]);	
  }

  bzero (object, objectlen);
  strncpy (object, c, objectlen);
  return 1;
}

int
do_get (const char *fs, char *object, u_char *fh, size_t fhlen, int cdfd,
	char *buf, size_t buflen)
{
  int err;

  sfsctl_getacl_arg arg;
  read3res res;

  bzero (&arg, sizeof (arg));
  arg.filesys = (char *) fs;
  arg.arg.name = object;
  arg.arg.dir.data.val = fh;
  arg.arg.dir.data.len = fhlen;

  bzero (&res, sizeof (res));
  err = srpc_call (&sfsctl_prog_1, cdfd, SFSCTL_GETACL, &arg, &res);	

  if (err) {
    printf ("RPC failed: %d\n", err);
    xdr_free ((xdrproc_t) xdr_read3res, (char *) &res);
    return 0;
  }

  if (res.status) {
    printf ("NFS operation failed on server: %d\n", res.status);
    xdr_free ((xdrproc_t) xdr_read3res, (char *) &res);
    return 0;
  }

  if (res.u.resok.data.len > buflen)
    printf ("ACL result too big; truncating...\n");
  strncpy (buf, res.u.resok.data.val, buflen);
  xdr_free ((xdrproc_t) xdr_read3res, (char *) &res);
  return 1;	
}

int
do_set (const char *fs, char *object, u_char *fh, size_t fhlen, int cdfd,
	char *buf, size_t buflen)
{
  int err;

  sfsctl_setacl_arg arg;
  write3res res;

  bzero (&arg, sizeof (arg));
  arg.filesys = (char *) fs;
  arg.arg.dargs.name = object;
  arg.arg.dargs.dir.data.val = fh;
  arg.arg.dargs.dir.data.len = fhlen;
  arg.arg.wargs.data.val = buf;
  arg.arg.wargs.data.len = buflen;
  arg.arg.wargs.file.data.val = 0;			/* ignored */
  arg.arg.wargs.file.data.len = 0;			/* ignored */
  arg.arg.wargs.offset = 0;				/* ignored */
  arg.arg.wargs.count = 0;				/* ignored */
  arg.arg.wargs.stable = 0;				/* ignored */

  bzero (&res, sizeof (res));
  err = srpc_call (&sfsctl_prog_1, cdfd, SFSCTL_SETACL, &arg, &res);	

  if (err) {
    printf ("RPC failed: %d\n", err);
    xdr_free ((xdrproc_t) xdr_write3res, (char *) &res);
    return 0;
  }

  if (res.status) {
    if (res.status == NFS3ERR_ACCES)
      printf ("Permission denied: you are not allowed to modify the ACL\n");
    else
      printf ("NFS operation failed on server: %d\n", res.status);
    xdr_free ((xdrproc_t) xdr_write3res, (char *) &res);
    return 0;
  }

  xdr_free ((xdrproc_t) xdr_write3res, (char *) &res);
  return 1;	
}

int
do_acl (char *path, char *buf, size_t buflen, int set)
{
  struct stat sb;
  int cdfd;

  const char *fs;
  u_char fh[NFS3_FHSIZE];
  char object[MAXPATHLEN];

  if (lstat (path, &sb) < 0) {
    printf ("lstat: %s: %s\n", strerror (errno), path);
    return 0;
  }

  if (S_ISCHR (sb.st_mode) || S_ISBLK (sb.st_mode)) {
    printf ("Character special and block special objects are not supported.\n");
    return 0;
  }

  if (S_ISLNK (sb.st_mode)) {
    printf ("Symbolic links do not have ACLs associated with them.\n");
    return 0;
  }
  
  if (!devcon_lookup (&cdfd, &fs, sb.st_dev)) {
    printf ("Unable to do devcon_lookup for path: %s\n", path);
    return 0;
  }

  if (!fh_lookup (path, fh, sizeof (fh), object, sizeof (object))) {
    printf ("Unable to obtain filehandle (readlink SFSFH failed).\n");
    return 0;
  }

  if (set)
    return do_set (fs, object, fh, strlen (fh), cdfd, buf, buflen);
  else
    return do_get (fs, object, fh, strlen (fh), cdfd, buf, buflen);
}

int
read_acl_file (const char *file, char *buf, size_t buflen)
{
  FILE *in;

  if ((in = fopen (file, "r")) == NULL) {
    printf ("Can't open ACL file \n");
    return 0;
  }
  fread (buf, sizeof (char), buflen-1, in);  /* XXX: check for EOF/errors */
  fclose (in);
  return 1;
}

static void
usage (void)
{
  fprintf (stderr, "usage: %s [-s path-to-ACL-file] path\n", progname);
  exit (1);
}

int
main (int argc, char **argv)
{
  int ch, set = 0;
  char aclbuf[ACLSIZE+1];

  bzero (aclbuf, sizeof (aclbuf));

  if ((progname = strrchr (argv[0], '/')))
    progname++;
  else
    progname = argv[0];

  while ((ch = getopt (argc, argv, "s:")) != -1)
    switch (ch) {
    case 's':
      set = 1;
      if (!read_acl_file (optarg, aclbuf, ACLSIZE))
	return 1;
      break;
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;

  if (argc != 1)
    usage ();

  if (!do_acl (argv[0], aclbuf, ACLSIZE, set)) {
    printf ("Error accessing ACL\n");
    return 1;
  }

  if (set)
    printf ("Successfully set ACL\n");
  else
    printf ("%s", aclbuf);

  return 0;
}
