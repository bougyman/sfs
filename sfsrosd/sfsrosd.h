#ifndef _SFSROSD_H_
#define _SFSROSD_H_

#include "sfsmisc.h"
#include "sfsro_prot.h"
#include "arpc.h"
#include "crypt.h"
#include "dbfe.h"
#include "qhash.h"

class replica {
  dbfe *dbp;
  
public:
  str hostname;
  sfs_connectres cres;
  ptr<sfs_servinfo_w> siw;
  sfsro_fsinfo fsinfores;

  replica (const char *dbfile);
  void getdata (sfs_hash *fh, sfsro_datares *res, 
		callback<void>::ref cb);
private:
  void getdata_cb (callback<void>::ref cb, sfsro_datares *res, 
		   ptr<dbrec> result);
};

typedef qhash<str, replica> replicatab_t;
extern replicatab_t replicatab;

class client {
  ptr<axprt_stream> x;
  ptr<asrv> rosrv;
  ptr<asrv> sfssrv;
  ptr<sfs_connectarg> conargs;

  ref<bool> destroyed;

  void dispatch (ref<bool> b, svccb *sbp);
  void getdata_cb (svccb *sbp, sfsro_datares *res, ref<bool> d);

public:
  client (ptr<axprt_stream> _x);
  ~client ();

};

ptr<axprt_stream> client_accept (int fd);

#endif /*_SFSROSD_H_*/

