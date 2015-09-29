/* $Id: sfsdeclog.C,v 1.2 2003/01/02 15:41:44 max Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include "rxx.h"
#include "async.h"
#include "sfs_prot.h"
#include "sfsauth_prot.h"


const int BUFSIZE = 10240;
static rxx colon (":");

bool parse (const str &ln, int lineno);

bool
read_input (FILE *in)
{
  static char buf[BUFSIZE];
  char *p;
  int line = 1;
  bool pe = false;
  bool ret = true;
  while (fgets (buf, BUFSIZE, in)) {
    if (!(p = strchr (buf, '\n'))) {
      ret = false;
      if (!pe) 
	warn << line << ": line too long / no newline\n";
      pe = true;
    } else {
      pe = false;
      *p = '\0';
      if (!parse (str (buf), line))
	ret = false;
    }
    line++;
  }
  if (errno) {
    warn ("read error: %m\n");
    return false;
  }
  return ret;
}

void
writewait (u_int fd)
{
  fd_set fds;
  assert (fd < FD_SETSIZE);
  FD_ZERO (&fds);
  FD_SET (fd, &fds);
  select (fd + 1, NULL, &fds, NULL, NULL);
}

bool
parse (const str &ln, int lineno)
{
  strbuf sb;
  str d;
  bool neednl = false;
  if (strchr (ln, ':')) {
    vec <str> v;
    if (split (&v, colon, ln, 5, true) != 5) {
      warn << lineno << ": parse error\n";
      return false;
    }
    for (int i = 0 ; i < 4; i++) {
      if (i > 0)
	sb << ":";
      sb << v[i];
    }
    sb << "\n";
    neednl = true;
    d = dearmor64 (v[4]);
  } else {
    d = dearmor64 (ln);
  }
  sfsauth2_sign_arg ur;
  if (!d || !str2xdr (ur, d)) {
    warn << lineno << ": parse error\n";
    return false;
  }
  rpc_print (sb, ur);
  if (neednl)
    sb << "\n";
  suio *s = sb.tosuio ();
  int rc;

  while ((rc = s->output (1)) == 0) {
    writewait (1);
  }
  if (rc < 0) {
    fatal ("write error: %m\n");
    return false;
  }
  return true;
}

void
usage ()
{
  warnx << "usage: siglogdec < infile > outfile\n";
  exit (2);
}

int
main (int argc, char **argv)
{
  if (argc > 1) 
    usage ();
  return (read_input (stdin) ? 0 : 2);
}
