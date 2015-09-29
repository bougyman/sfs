#include "sfsrosd.h"
#include "sfsrodb_core.h"
#include "parseopt.h"
#include "rxx.h"

/* Experiment with proxy re-encryption */
#ifdef SFSRO_PROXY
#include "/home/fubob/src/proxyfs/miracl/elliptic.h"
#include "/home/fubob/src/proxyfs/miracl/monty.h"
#include "/home/fubob/src/proxyfs/miracl/zzn2.h"
extern Miracl precision;
#include "/home/fubob/src/proxyfs/pairing.h"
static CurveParams gParams;
extern ProxyPK proxy_PublicKey;
extern ProxySK proxy_SecretKey;
extern ProxyPK proxy_DelegatePublicKey;
extern ProxySK proxy_DelegateSecretKey;
extern CurveParams proxy_params;
extern ECn proxy_delegationKey;
#endif

static str configfile;
int sfssfd;

ptr<axprt_stream>
client_accept (int fd)
{
  if (fd < 0)
    fatal ("EOF from sfssd\n");
  tcp_nodelay (fd);

  ref<axprt_stream> x = axprt_stream::alloc (fd);
  vNew client (x);
  return x;
}

static void
client_accept_standalone ()
{
  sockaddr_in sin;
  bzero (&sin, sizeof (sin));
  socklen_t sinlen = sizeof (sin);
  int fd = accept (sfssfd, reinterpret_cast<sockaddr *> (&sin), &sinlen);
  if (fd >= 0)
    client_accept (fd);
  else if (errno != EAGAIN)
    fatal ("accept: %m\n");
}


static void print_sname (const str &hostname, replica *r) 
{
  warn << "serving " << r->siw->mkpath (2, sfs_defport) << "\n";
}

static void
start_server ()
{
  setgid (sfs_gid);
  setgroups (0, NULL);

  warn ("version %s, pid %d\n", VERSION, int (getpid ()));

  replicatab.traverse (wrap (&print_sname));

  if (cloneserv (0, wrap (&client_accept)))
    return;

  warn ("No sfssd detected, running in standalone mode\n");
  sfssfd = inetsocket (SOCK_STREAM, sfs_defport);
  if (sfssfd < 0)
    fatal ("binding TCP port %d: %m\n", sfs_defport);
  listen (sfssfd, 1000);
  fdcb (sfssfd, selread, wrap (client_accept_standalone));
}

void
parseconfig (str cf)
{
  parseargs pa (cf);
  bool errors = false;
  bool publish = false;

  int line;
  vec<str> av;

  while (pa.getline (&av, &line)) {
    if (!strcasecmp (av[0], "publishfile")) {
      if (av.size () == 2 && av[1][0] == '/' ) {
	replica *r = New replica (av[1]);
	replicatab.insert (r->hostname, *r);
	publish = true;
      } else {
	errors = true;
	warn << cf << ":" << line << ": usage: PublishFile <filepath>\n";
	warn << "(path must start with a '/')\n";
      }
    }
    else {
      errors = true;
      warn << cf << ":" << line << ": unknown directive '"
	   << av[0] << "'\n";
    }
  }

  if (errors)
    fatal ("errors in config file\n");
  if (!publish)
    fatal ("no 'PublishFile' or 'PublishDir' directives in found config file\n");
}

static void usage () __attribute__ ((noreturn));
static void
usage ()
{
  warnx << "usage: " << progname << " [-f configfile]\n";
  exit (1);
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);

  int ch;
  while ((ch = getopt (argc, argv, "f:")) != -1)
    switch (ch) {
    case 'f':
      configfile = optarg;
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
    configfile = sfsconst_etcfile_required ("sfsrosd_config");

  parseconfig (configfile);

  // XXX remove before release, for debugging
  sigcb (SIGINT, wrap (exit, 1));
  sigcb (SIGTERM, wrap (exit, 1));


#ifdef SFSRO_PROXY
    ReadParamsFile("publicparams.cfg", proxy_params);

    //
    // Read in the main recipient's public (and secret) key
    //
    str publickeyfile ("master.pub.key");
    str privatekeyfile ("master.pri.key");

    ReadPublicKeyFile(const_cast<char *> (publickeyfile.cstr()), proxy_PublicKey);
    ReadSecretKeyFile(const_cast<char *> (privatekeyfile.cstr()), proxy_SecretKey);

    str dpublickeyfile ("user.pub.key");
    str dprivatekeyfile ("user.pri.key");
    ReadPublicKeyFile(const_cast<char *> (dpublickeyfile.cstr()),
		      proxy_DelegatePublicKey);
    ReadSecretKeyFile(const_cast<char *> (dprivatekeyfile.cstr()),
		      proxy_DelegateSecretKey);

    if (proxy_delegate(proxy_params, proxy_DelegatePublicKey, 
		       proxy_SecretKey, proxy_delegationKey)
	== FALSE) {
      fatal << "Delegation failed\n";
    }

#endif

  start_server ();

  amain ();
}
