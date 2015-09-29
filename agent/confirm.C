/*
 * open a dialog window asking for permission for the agent to sign an
 * authentication request
 */

#include <stdio.h>
#include "smallutils.h"

#include "dialog.C"

stream *
open_file_stream (const char *filename)
{
  FILE *f = fopen (filename, "r");
  return f ? New file_stream (f) : NULL;
}

gsymbol *version1 = g_symbol ("confirm-state-v1");

gob *
get_permits (const char *filename) 
{
  stream *s = open_file_stream (filename);
  if (!s)
    return NULL;

  gob *state = g_read (s);
  if (!state)
    fatal ("%s: error reading s-expression\n", filename);

  gpair *statelist = togpair (state);
  gsymbol *version = statelist ? togsymbol (statelist->first ()) : NULL;
  if (version && g_equal (version, version1)) {
    return statelist->rest ();
  }
  else
    fatal ("%s: unrecognized confirm-state format\n", filename);
  return NULL;
}

void
save_permits (gob *permits, const char *filename)
{
  FILE *f = fopen (filename, "w");
  if (!f) {
    warn ("%s: couldn't write to file\n", filename);
    return;
  }
  gob *state = g_cons (version1, permits);
  if (state->fwrite (f) == -1
      || fprintf (f, "\n") == -1
      || fclose (f) == EOF)
  {
    warn ("%s: error writing state to file\n", filename);
    return;
  }
}

gob *
have_permit (gob *permitsob,
             gob *fqdn_permit, gob *domain_permit, gob *all_permit)
{
  while (gpair *permits = togpair (permitsob)) {
    gob *permit = permits->first ();
    permitsob = permits->rest ();
    if (g_equal (permit, fqdn_permit)) return fqdn_permit;
    if (g_equal (permit, domain_permit)) return domain_permit;
    if (g_equal (permit, all_permit)) return all_permit;
  }
  return NULL;
}

char *
sanitize (const char *s)
{
  str b;
  while (char c = *(s++)) {
    if (!isgraph (c))
      return NULL;
    switch (c) {
      case '\\':
      case '"':
        b.append ('\\');
    }
    b.append (c);
  }
  return b.release ();
}

void 
usage ()
{
  warnx ("usage: %s "
         "[-fn text-font-name] "
         "[-fb button-font-name] "
         "[--] "
         "requestor request service key [all-keys ...]\n",
         progname ? progname : "confirm");
  exit (1);
}

#undef SHIFT
#define SHIFT do { argc--; argv++; } while (0)

int
main (int argc, char **argv)
{
  if (argc) {
    progname = lastpathcomponent (argv[0]);
    SHIFT;
  }

  char **guiopts = &(argv[0]);
  int nguiopts = 0;
  while (argc && argv[0][0] == '-' && argv[0][1] != '-') {
    nguiopts++;
    SHIFT;
  }
  if (argc && argv[0][0] == '-')
    SHIFT;

  if (!process_dialog_args (nguiopts, guiopts))
    usage ();

  if (argc < 4)
    usage ();

  char *requestor = sanitize (argv[0]);
  char *request = sanitize (argv[1]);
  char *service = sanitize (argv[2]);
  char *key = sanitize (argv[3]);

  if (!(requestor && request && service && key))
    fatal ("Bad arguments");

  // warn ("requestor = %s, request = %s, service = %s, key = %s\n",
  //       requestor, request, service, key);

  str fqdn, id;
  str host, domain;
  if (!(request[0] == '@' && request++ && str (request).split (',', fqdn, id)
        && fqdn.split ('.', host, domain)))
    fatal ("Bad request argument");

  gob *gkey = New gstring (key);
  gob *grequestor = New gstring (requestor);

  gob *fqdn_permit = g_list (gkey, grequestor, g_symbol ("fqdn"),
                             New gstring (fqdn));
  gob *domain_permit = g_list (gkey, grequestor, g_symbol ("domain"),
                               New gstring (domain));
  gob *all_permit = g_list (gkey, grequestor, g_symbol ("all"));

  char *home = getenv ("HOME");
  assert (home);
  str state_file;
  state_file << home << "/.sfs/confirm_state_0";

  gob *permits = get_permits (state_file.cstr ());
  if (permits) {
    if (gob *permit = have_permit (permits,
                                   fqdn_permit, domain_permit, all_permit)) {
      warn ("found permit: ");
      permit->fwrite (stderr);
      warnx ("\n");
      return 0;
    }
  }
  else
    permits = bottom;

  const char *vspace = "(vspace 5)";
  const char *hspace = "(hspace 5)";
  str guispec;
  guispec
    << "(window \"SFS Authentication Request\""
    << "\"*** SFS Authentication Request ***\""
    << "(vspace 15)"
    << "\"REQUEST FROM: " << requestor << "\""
    << "\"   TO ACCESS: " << fqdn << "\""
    << "\"WITH SERVICE: " << service << "\""
    << "\"   USING KEY: " << key << "\""
    << "(vspace 15)"
    << "(radioset "
    << "(row (radio 10 selected)"
    <<    hspace << "\"Reject the authentication request\")"
    << vspace
    << "(row (radio 11)" << hspace << "\"Accept the authentication request\")"
    << vspace
    << "(row (radio 12)" << hspace << "\"Accept all authentication requests\n"
    <<    "   from " << requestor << "\n"
    <<    "   to " << fqdn << "\")"
    << vspace
    << "(row (radio 13)" << hspace << "\"Accept all authentication requests\n"
    <<    "   from " << requestor << "\n"
    <<    "   to any host matching *." << domain << "\")"
    << vspace
    << "(row (radio 14)" << hspace << "\"Accept all authentication requests\n"
    <<    "   from " << requestor << "\n"
    <<    "   to any host\")"
    << ")" // radioset
    << "(vspace 10)"
    << "(button \"OK\")"
    << ")";

  int result = dialog_main (guispec.cstr ());
  switch (result) {
    case 11:
      goto accept;
    case 12:
      permits = g_cons (fqdn_permit, permits);
      goto save;
    case 13:
      permits = g_cons (domain_permit, permits);
      goto save;
    case 14:
      permits = g_cons (all_permit, permits);
      goto save;
  }
  warn ("user rejects authentication request\n");
  return 1;

 save:
  save_permits (permits, state_file.cstr ());
 accept:
  warn ("user accepts authentication request\n");
  return 0;
}
