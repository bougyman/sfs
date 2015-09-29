#include "sfsschnorr.h"
#include "sfsauth_prot.h"
#include "sfsextauth.h"
#include "sfskeymisc.h"

class sfsproac : public sfsextauth 
{
private:
  int dur;
  ptr<sfscon> sc;
  ptr<sfspriv> privk;
  ptr<schnorr_client> sclnt;
  str expanded_keyname;
  const str user;

public:
  sfsproac (int d, const str &keyname, const str &u, const str &host) :
    user (u) {

    if (d != 0) 
      d += time (NULL);

    dur = d;

    sfskey k;
    ptr<sfsauth_certinfores> ci;
    if (str err = sfskeyfetch (&k, keyname, &sc, &ci, true))
      fatal << err << "\n";

    if (!k.key) 
      fatal << "Could not get a private key for signing\n";
    /*
    if (!sc)
      fatal << "Invalid connection to authd.\n";
    */
    
    expanded_keyname = k.keyname;
    privk = k.key;
  }
    
  ~sfsproac () {}

  void authinit (svccb *sbp);

  void authinitcb (svccb *sbp, ptr<sfs_authreq2> ar, 
		   str err, ptr<sfs_sig2> sig2);

  void set_name (str &n);

  sfs_time get_expire_time () { return dur; }
};

void
sfsproac::set_name (str &n)
{
  strbuf b;
  b << "proac/2schnr (" << expanded_keyname << ")";
  n = b;
}

void
sfsproac::authinit (svccb *sbp)
{
  sfsextauth_init *aa = sbp->Xtmpl getarg<sfsextauth_init> ();
  ptr<sfs_authreq2> authreq = New refcounted<sfs_authreq2>;

  authreq->type = SFS_SIGNED_AUTHREQ;
  authreq->user = user;
  authreq->seqno = aa->autharg.seqno;
  if (!sha1_hashxdr (authreq->authid.base (), aa->autharg.authinfo)) {
    warn << "Could not hash authinfo into authid.\n";
    sfsagent_auth_res res;
    res.set_authenticate (false);
    sbp->replyref (res);
    return;
  }

  sfsauth2_sigreq sr;
  sr.set_type (SFS_SIGNED_AUTHREQ);
  *sr.authreq = *authreq;
  privk->sign (sr, aa->autharg.authinfo, 
	       wrap (this, &sfsproac::authinitcb, sbp, authreq));
  return;
}

void
sfsproac::authinitcb (svccb *sbp, ptr<sfs_authreq2> ar,
		      str err, ptr<sfs_sig2> sig)
{
  sfsagent_auth_res *res = sbp->Xtmpl getres<sfsagent_auth_res> ();

  if (!sig) {
    warn << "sfsproac::authinit: sign failure on request: " << err << "\n";
    res->set_authenticate (false);
  }
  else {
    res->set_authenticate (true);
    sfs_sigauth sigauth;
    sigauth.sig = *sig;
    sigauth.req = *ar;
    if (!privk->export_pubkey (&sigauth.key)) {
      warn << "Could not export public key\n";
      res->set_authenticate (false);
    } else {
      sfs_autharg2 ar (SFS_AUTHREQ2);
      *ar.sigauth = sigauth;

      if (!xdr2bytes (*(res->certificate), ar)) {
	warn ("sfsproac::authinit: xdr failure on request:\n");
	rpc_print(warn, sbp->Xtmpl getarg<sfsextauth_init> ());
	res->set_authenticate (false);
      }
    }
  }
  sbp->reply (res);
}

void
usage(char *progname) 
{
  warn << "usage: " <<  progname << " [ -e <seconds> ] [<user>@]<hostname>\n";
  exit (1);
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  sfsconst_init ();
  agent_setsock ();
  int expires = 0;

  int ch;
  while ((ch = getopt (argc, argv, "e:")) != -1)
    switch (ch) {
    case 'e':
      expires = atoi (optarg);
      break;
    default:
      usage (argv[0]);
    }
  if (optind >= argc) 
    usage (argv[0]);
   
  str user, host;
  if (!parse_userhost (argv[optind], &user, &host))
    fatal << "not of form [user@]hostname\n";

  sfsproac proac (expires, argv[optind], user, host);

  if (!proac.connect ())
    exit (1);

  proac.register_with_agent ();
  amain ();
}


