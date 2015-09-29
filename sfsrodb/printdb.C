/* $Id: printdb.C,v 1.29 2004/08/23 20:18:50 fubob Exp $ */

#include "sfsrodb.h"
#include "keyregression.h"
#include "aios.h"
#include "rxx.h"
#include <string.h>

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
#endif

dbfe *db;
char IV[SFSRO_IVSIZE];
ptr<keyregression> kr = NULL;

static void 
key2fh(ref<dbrec> key, sfs_hash *fh)
{
  aout << "fhsize = " << key->len << "\n";
  bzero (fh->base (), fh->size() );
  memcpy (fh->base (), key->value, key->len);
}


static void
getfsinfo()
{
  sfs_connectres conres;
  if (!sfsrodb_get (db, (void *)"conres", 6, conres))
    fatal << "conres lookup returned failed\n";

  strbuf sb2;
  rpc_print (sb2, conres, 5, NULL, " ");
  aout << "connectres:\n";
  aout << sb2 << "\n"; 
  aout << "================\n";

  sfsro_fsinfo fsinfo;
  if (!sfsrodb_get (db, (void *)"fsinfo", 6, fsinfo))
    fatal << "fsinfo lookup returned failed\n";

  strbuf sb1;
  rpc_print (sb1, fsinfo, RPC_INFINITY, NULL, " ");
  aout << "fsinfo:\n";
  aout << sb1 << "\n"; 
  aout << "================\n";
  
  ref<sfs_servinfo_w> siw = sfs_servinfo_w::alloc (conres.reply->servinfo);
  sfs_pubkey2 pk = siw->get_pubkey ();

  if (!sfscrypt.verify (pk, fsinfo.v2->sig, xdr2str (fsinfo.v2->info))) {
    warnx << "SIGNATURE DOESN'T MATCH\n";
    exit(-1);
  } else {
    aout << "SIGNATURE MATCHES\n";
  }
  
  if (fsinfo.v2->info.type ==  SFSRO_PRIVATE) {
    if (!kr)
      fatal << "No keyupdate\n";

    sfsro_public fsinfopub;
    unseal (kr->gk (fsinfo.v2->info.priv->ct.gk_vers), 
	    &fsinfo.v2->info.priv->ct, &fsinfopub);
    strbuf sb2;
    rpc_print (sb2, fsinfopub, RPC_INFINITY, NULL, " ");
    aout << "fsinfo (dec):\n";
    aout << sb2 << "\n"; 
    aout << "================\n";


    memcpy(IV, (char *) (fsinfopub.iv.base()), SFSRO_IVSIZE);
  } else {
    memcpy(IV, (char *) (fsinfo.v2->info.pub->iv.base()), SFSRO_IVSIZE);
  }
}

static void
walkdb ()
{
  warn << "Walking db\n";
  ptr<dbEnumeration> it = db->enumerate();
  while (it->hasMoreElements()) {
    ptr<dbPair> res = it->nextElement();
    if (res->key->len > 6)  /* skip fsinfo and connectres*/
      {
	sfs_hash fh;
	key2fh(res->key, &fh);
	
	strbuf sb;
	rpc_print (sb, fh, 5, NULL, " ");
	aout << "fh (key): " << sb << "\n";
	
	if (!verify_sfsrofh (&IV[0], SFSRO_IVSIZE, &fh, 
			     (char *) res->data->value,
			     (size_t) res->data->len)) {
	  warnx << "HASH DOESN'T MATCH\n";
	} else {
	  aout << "HASH MATCHES\n";
	}

	xdrmem x (static_cast<char *>(res->data->value), 
		  res->data->len, XDR_DECODE);
	sfsro_data dat;
	if (!xdr_sfsro_data (x.xdrp(), &dat)) {
	  warnx << "couldn't decode sfsro_data\n";
	}

	strbuf sb1;
	rpc_print (sb1, dat, 50, NULL, " ");
	aout << "sfsro_data (" << res->data->len <<  "): " << sb1 << "\n";

	strbuf sb2;
	switch (dat.type) {
	case SFSRO_INODE:
	  {
	    rpc_print (sb2, *dat.inode, 50, NULL, " ");
	    break;
	  }
	case SFSRO_FILEBLK:
	  {
	    rpc_print (sb2, dat.data, 50, NULL, " ");
	    break;
	  }
	case SFSRO_DIRBLK:
	  {
	    rpc_print (sb2, dat.dir, 50, NULL, " ");
	    break;
	  }
	case SFSRO_INDIR:
	  {
	    rpc_print (sb2, dat.indir, 50, NULL, " ");
	    break;
	  }
	case SFSRO_FHDB_DIR:
	  {
	    rpc_print (sb2, dat.fhdb_dir, 50, NULL, " ");
	    break;
	  }
	case SFSRO_FHDB_INDIR:
	  {
	    rpc_print (sb2, dat.fhdb_indir, 50, NULL, " ");
	    break;
	  }
	case SFSRO_SEALED:
	  {
	    rpc_print (sb2, dat.ct, 50, NULL, " ");
	    sfsro_data pt;
	    unseal (kr->gk (dat.ct->gk_vers), dat.ct, &pt);
	    rpc_print (sb2, pt, 50, NULL, " ");
	    break;
	  }
	default:
	  break;
	}
	aout << "sfsro_data.type: " << sb2 << "\n";
	aout << "================\n";
      }
  }
}

void usage (char *f) 
{
  warnx << "Usage: " << f << " <rodb> [<keyupdate file>]\n";
  exit (1);
}

int
main(int argc, char **argv) 
{
  if (argc == 3) {
    kr = New refcounted<keyregression> (argv[2]);
    if (!kr) {
      warn << "file2xdr failed\n";
      usage (argv[0]);
    }

  } else if (argc != 2) {
    usage (argv[0]);
  }
  

  ref<dbImplInfo> info = dbGetImplInfo();

  //print out what it can do
  for (unsigned int i=0; i < info->supportedOptions.size(); i++) 
    aout << info->supportedOptions[i] << "\n";

  //create the generic object
  db = new dbfe();

  //set up the options we want
  dbOptions opts;
  //ideally, we would check the validity of these...
  opts.addOption("opt_async", 0);
  opts.addOption("opt_cachesize", 80000);
  opts.addOption("opt_nodesize", 4096);

  if (db->opendb (argv[1], opts) != 0) {
    warn << "opendb failed " << strerror (errno) << "\n";
    exit (1);
  }

#ifdef SFSRO_PROXY
    ReadParamsFile("publicparams.cfg", proxy_params);

    //
    // Read in the main recipient's public (and secret) key
    //
    str publickeyfile ("master.pub.key");
    str privatekeyfile ("master.pri.key");

    ReadPublicKeyFile(const_cast<char *> (publickeyfile.cstr()), proxy_PublicKey);
    ReadSecretKeyFile(const_cast<char *> (privatekeyfile.cstr()), proxy_SecretKey);
#endif

  getfsinfo();
  walkdb(); 

  return 0;
}
