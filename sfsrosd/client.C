#include "sfsrosd.h"
#include "rxx.h"
#include "sfsrodb_core.h"

#ifndef MAINTAINER
enum { dumptrace = 0 };
const int asrvtrace (getenv ("ASRV_TRACE") ? atoi (getenv ("ASRV_TRACE")) : 0);
#else /* MAINTAINER */
const bool dumptrace (getenv ("SFSRO_TRACE"));
enum { asrvtrace = 0 };
#endif /* MAINTAINER */


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

client::client (ptr<axprt_stream> _x)
  : x (_x), conargs (NULL), destroyed (New refcounted<bool> (false))
{
  rosrv = asrv::alloc (x, sfsro_program_2,
			 wrap (this, &client::dispatch, destroyed));
  sfssrv = asrv::alloc (x, sfs_program_1,
			wrap (this, &client::dispatch, destroyed));
}

client::~client()
{
  *destroyed = true;
}

void
client::dispatch (ref<bool> d, svccb *sbp)
{
  if (!sbp) {
    if (!*d)
      return;
    delete this;
    return;
  }

  if (sbp->prog () == SFS_PROGRAM) {
    switch (sbp->proc ()) {
    case SFSPROC_NULL:
      sbp->reply (NULL);
      return;
    case SFSPROC_CONNECT:
      {
	if (asrvtrace >= 5) {
	  warnx << "client: handled connect\n";
	}
	conargs = New refcounted<sfs_connectarg>
	  (*sbp->Xtmpl getarg<sfs_connectarg> ());

	replica *r;
	if (conargs->civers == 5) {
	  warnx << "ci5: " << conargs->ci5->sname << "\n";

	  str host;
	  if (!sfs_parsepath (conargs->ci5->sname, &host)) {
	    warnx << "unable to parsepath " << conargs->ci5->sname << "\n";
	    sfs_connectres cres (SFS_NOTSUPP);
	    sbp->reply (&cres);
	  }

	  if ((r = replicatab[host]) != NULL) {
	    sbp->reply (&r->cres);
	  } else {
	    warnx << "unable to find replica with hostname=" << host << "\n";
	    sfs_connectres cres (SFS_NOTSUPP);
	    sbp->reply (&cres);
	  }
	} else if (conargs->civers == 4) {
	  warnx << "ci4: " << conargs->ci4->name << "\n";
	    // << "|" <<  
	    //	    conargs->ci4->hostid << "\n";
	  // XXXX not  supported yet!
	  warn << "unsupported ci4 connect!\n";
	  sfs_connectres cres (SFS_NOTSUPP);
	  sbp->reply (&cres);
	} else {
	  sfs_connectres cres (SFS_NOTSUPP);
	  sbp->reply (&cres);
	}
	return;
      }
    case SFSPROC_GETFSINFO:
      {
	if (asrvtrace >= 5) {
	  warnx << "client: handling request w/ id" << sbp->xid() << "\n";
	}
	
	if (conargs->civers == 5) {
	  warnx << "ci5: " << conargs->ci5->sname << "\n";

	  str host;
	  if (!sfs_parsepath (conargs->ci5->sname, &host)) {
	    warnx << "unable to parsepath " << conargs->ci5->sname << "\n";
	    sfs_connectres cres (SFS_NOTSUPP);
	    sbp->reply (&cres);
	  }

	  replica *r;
	  if ((r = replicatab[host]) != NULL) {
	    sbp->reply (&r->fsinfores, xdr_sfsro_fsinfo);
	  } else {
	    warnx << "unable to find replica with hostname=" << host << "\n";
	    sfsro_fsinfo res (SFSRO_ERRNOENT);
	    sbp->reply (&res, xdr_sfsro_fsinfo);
	  }
	}
      }
      return;
    default:
      warnx << "client: unknown proc\n";
      sbp->reject (PROC_UNAVAIL);
      return;
    }
  }
  else if (sbp->prog () == SFSRO_PROGRAM 
	   && sbp->vers () == SFSRO_VERSION_V2) {
    switch (sbp->proc ()) {
    case SFSROPROC2_NULL:
      sbp->reply (NULL);
      return;
    case SFSROPROC2_GETDATA:
      {
	if (asrvtrace >= 5) {
	  warnx << "client: handling request w/ id" << sbp->xid() << "\n";
	}
	
	sfsro_getdataargs *args = sbp->Xtmpl getarg<sfsro_getdataargs> ();
	
	/*
	if (dumptrace) {
	  u_char *cp = reinterpret_cast<u_char *> (args->fh.base ());
	  u_char *lim = cp + args->fh.size ();
	  printf ("  { 0x%02x", *cp);
	  while (++cp < lim)
	    printf (", 0x%02x", *cp);
	  printf (" },\n");
	}
	*/	
	if (asrvtrace >= 5) {
	  warnx << "calling getdata w fh=" << 
	    hexdump(args->fh.base (), args->fh.size ()) 
		<< "\n";
	}
	sfsro_datares *res = New sfsro_datares();

	str host;
	if (!sfs_parsepath (args->sname, &host)) {
	  warnx << "unable to parsepath " << args->sname << "\n";
	  sfsro_datares res (SFSRO_ERRNOENT);
	  sbp->reply (&res);
	}

	replica *r = replicatab[host];
	if (r)
	  r->getdata (&args->fh, res, wrap (this, &client::getdata_cb, 
					    sbp, res, destroyed));
	else {
	  warnx << "unable to find replica with hostname " << host << "\n";
	  sfsro_datares res (SFSRO_ERRNOENT);
	  sbp->reply (&res);
	}
	return;
      }
    case SFSROPROC2_PROXYREENC:
      {
	sfsro_proxyreenc res;
	
#ifdef SFSRO_PROXY
	sfsro_proxyreenc *pargs = sbp->Xtmpl getarg<sfsro_proxyreenc> ();

	if (dumptrace) {
	  u_char *cp = reinterpret_cast<u_char *> (pargs->data.base ());
	  u_char *lim = cp + pargs->data.size ();
	  printf ("  { 0x%02x", *cp);
	  while (++cp < lim)
	    printf (", 0x%02x", *cp);
	  printf (" },\n");
	}

	// Unmarshall c1 here
	char *bufa = (char*)pargs->data.base ();
	ECn c1;
	ZZn2 Zc1;
	c1 = charToECn (bufa);
	
	if (proxy_reencrypt(proxy_params, c1, proxy_delegationKey, Zc1) 
	    == FALSE) {
	  fatal << "Re-encryption failed\n";
	}

	//return Zc1 here
	char buf[1024];
	int buflen = 0;
	buflen = ZZn2Tochar (Zc1, buf, 1024);
	if (buflen <= 0)
	  fatal << "ZZn2Tochar failed\n";
	res.data.setsize (buflen);
	memcpy (res.data.base (), buf, buflen);
	sbp->reply (&res);
#endif
	return;
      }
    default:
      warnx << "rejected unavailable proc " << sbp->proc () << "version "
	    << sbp->vers () << "\n";
      sbp->reject (PROC_UNAVAIL);
      break;
    }
  } else {
    warnx << "client: unknown program\n";
    sbp->reject (PROC_UNAVAIL);
    return;
  }

}

void
client::getdata_cb(svccb *sbp, sfsro_datares *res, ref<bool> d) {
  if (*d)
    return;
  sbp->reply(res);
  delete (res);
  return;
}
