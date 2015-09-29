

#include "sfsextauth.h"
#include "sfskeymisc.h"

class sfsdea : public sfsextauth 
{
public:
  sfsdea () : dur (0) {}
  sfsdea (int d, vec<str> p) : confprog (p) {
    if (d) { d += time (NULL); }
    dur = d;
  }
    
  ~sfsdea () {}
  bool confirmed (sfsextauth_init *aa);
  bool loadkey (str keyloc);
  void authinit (svccb *sbp);
  void authinitcb (svccb *sbp, ref<sfsagent_auth_res> res);
  void set_name (str &n);
  sfs_time get_expire_time () { return dur; }
private:
  int dur;
  key kmeth;
  vec<str> confprog;
};

void
sfsdea::set_name (str &n)
{
  n = "SFS External Agent";
}

bool
sfsdea::confirmed (sfsextauth_init *aa)
{
  str requestor = aa->name << "!" << aa->autharg.requestor;
  str request = strbuf () << "@" << aa->autharg.authinfo.name  << ","
    << armor32 (str (aa->autharg.authinfo.hostid.base (),
          aa->autharg.authinfo.hostid.size ()));
  strbuf service;
  print_sfs_service (&aa->autharg.authinfo.service, &service, 0, NULL, NULL);

  char *p = strrchr (requestor, '@');
  if (p && !strcmp (p, "@LOCALHOST")) {
    warn << "automatically signing authentication request from local machine\n";
    return true;
  }

#if 0
  str msg = strbuf ()
    << "*****  SFS Authentication Request  *****\n"
    << "----------------------------------------"
    << "\n\n"
    << " REQUEST FROM: " << requestor
    << "\n"
    << "    TO ACCESS: " << request
    << "\n"
    << " WITH SERVICE: " << service
    << "\n\n"
    << "***** Do you wish to agree to this signature? ";
#endif

  vec<char *> av;
  for (u_int i = 0; i < confprog.size (); i++)
    av.push_back (const_cast<char *> (confprog[i].cstr ()));
  //av.push_back (const_cast<char *> (msg.cstr ()));
  av.push_back (const_cast<char *> (requestor.cstr ()));
  av.push_back (const_cast<char *> (request.cstr ()));
  av.push_back (const_cast<char *> (str (service).cstr ()));
  av.push_back (NULL);

  int status;
  pid_t pid = spawn (av[0], av.base ());
  if (pid < 0) {
    warn ("Error spawning confirm command: %s: %s\n", av[0], strerror (errno));
    return false;
  }
  waitpid (pid, &status, 0);

  if (!WIFEXITED (status)) {
    warn ("Process did not exit normally: %s\n", av[0]);
    return false;
  }

  warn ("Exit code: %s: %d\n", av[0], WEXITSTATUS (status));
  return WEXITSTATUS (status) ? false : true;
}

void
sfsdea::authinit (svccb *sbp)
{
  ref<sfsagent_auth_res> res = New refcounted<sfsagent_auth_res> ();
  sfsextauth_init *aa = sbp->Xtmpl getarg<sfsextauth_init> ();

  if (confprog.size () > 0 && !confirmed (aa))
    sbp->replyref (sfsagent_auth_res (false));
  else
    kmeth.authinit (&(aa->autharg), res, 
	wrap (this, &sfsdea::authinitcb, sbp, res));
}

void
sfsdea::authinitcb (svccb *sbp, ref<sfsagent_auth_res> res)
{
  sbp->reply(res);
}

bool
sfsdea::loadkey (str keyloc)
{
  sfskey k;
  if (!keyloc || keyloc == "") {
    keyloc = defkey();
  }
  if (str err = sfskeyfetch (&k, keyloc, NULL)) {
    warn << err << "\n";
    return false;
  }
  kmeth.k = k.key;
  kmeth.name = keyloc;
  return true;
}


void 
usage(const char *progname) 
{
  warn << "usage: " <<	progname << " [ -k <keyloc> ] [ -e <seconds> ] "
          "[ -c ] [ <confirm command> ]\n";
  exit (1);
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  sfsconst_init ();
  agent_setsock ();
  str keyloc;
  vec<str> confprog;
  bool opt_confirm = false;
  int expires = 0;

  int ch;
  while ((ch = getopt (argc, argv, "k:e:c")) != -1) {
    switch (ch) {
    case 'k':
      keyloc = optarg;
      break;
    case 'e':
      if (optarg) 
	expires = atoi(optarg);
      break;
    case 'c':
      opt_confirm = true;
      break;
    default:
      usage (progname);
    }
  }
  argc -= optind;
  argv += optind;

  if (opt_confirm) {
    if (argc == 0) {
      warn ("Please specify a confirm command\n");
      usage (progname);
    }
    for (int i = 0; i < argc; i++)
      confprog.push_back (argv[i]);
  }

  sfsdea dea (expires, confprog);

  if (!dea.loadkey (keyloc) || !dea.connect ())
    exit (1);

  dea.register_with_agent ();
  amain ();
}


