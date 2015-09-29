#include "sfsrosd.h"
/* #include "str.h" */


replica::replica (const char *dbfile) 
{
  ref<dbImplInfo> info = dbGetImplInfo ();
  //create the generic object
  dbp = new dbfe ();

  //set up the options we want
  dbOptions opts;
  //ideally, we would check the validity of these...
  opts.addOption ("opt_async", 1);
  opts.addOption ("opt_cachesize", 80000);
  opts.addOption ("opt_nodesize", 4096);

  if (dbp->opendb (const_cast < char *>(dbfile), opts) != 0) {
    warn << "opendb on " << dbfile << " failed " << strerror (errno) << "\n";
    exit (1);
    // XXX rude error handling
  }

  ref<dbrec> key = new refcounted<dbrec>((void *) "conres", 6);
  ptr<dbrec> res1;
  if ((res1 = dbp->lookup (key)) == NULL) {
    warnx << "cannot load conres from " << dbfile << "\n";  
    exit (1);
    // XXX rude error handling
  }

  xdrmem x1 (static_cast<char *>(res1->value), res1->len, XDR_DECODE);
  if (!xdr_sfs_connectres (x1.xdrp (), &cres)) {
    warnx << "couldn't decode sfs_connectres from " << dbfile << "\n";
    exit (1);
    // XXX rude error handling
  }

  key = new refcounted<dbrec>((void *) "fsinfo", 6);
  ptr<dbrec> res2;
  if ((res2 = dbp->lookup (key)) == NULL) {
    warnx << "couldn't load fsinfo from " << dbfile << "\n";
    exit (1);
    // XXX rude error handling
  }
  xdrmem x2 (static_cast<char *>(res2->value), res2->len, XDR_DECODE);
  if (!xdr_sfsro_fsinfo (x2.xdrp (), &fsinfores)) {
    warnx << "couldn't decode sfs_fsinfo from " << dbfile << "\n";
    exit (1);
    // XXX rude error handling
  }

  cres.reply->servinfo.cr7->host.port = sfs_defport;
  siw = sfs_servinfo_w::alloc (cres.reply->servinfo);

  hostname = siw->get_hostname ();
}


void
replica::getdata (sfs_hash *fh, sfsro_datares *res,
		  callback<void>::ref cb)
{
  ref<dbrec> key = new refcounted<dbrec>((void *) fh->base (), 
					 fh->size ());
  dbp->lookup (key, wrap (this, &replica::getdata_cb, cb, res));
}

void
replica::getdata_cb (callback<void>::ref cb, sfsro_datares *res, 
		     ptr<dbrec> result)  
{
  if (result == 0) {
    res->set_status (SFSRO_ERRNOENT);
    (*cb) ();
  } else {
    res->set_status (SFSRO_OK);

    res->resok->data.setsize (result->len);
    memcpy (res->resok->data.base (), result->value, result->len);
    
    (*cb) ();
  }
}
