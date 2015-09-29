/* $Id: pulldb.C,v 1.15 2004/04/05 21:14:17 fubob Exp $ */

/*
 * Copyright (C) 2000 Frans Kaashoek (kaashoek@mit.edu)
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
 * Foundation, Inc.,4 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

//
// This programs pulls the sfsro database from server, incrementally
// (i.e., pull over only the blocks that we don't have in our local
// replica).
// The program works in three main phases:
// 1. Traverse the remote database and pull data in that we don't have into the
//    local database.
//    Add also the keys in the remote database into a temporary
//    key database (fhdb).
// 2. Create a new database that doesn't contain any old data.
//    Sequence through the fhdb, constructing the new db.
// 3. Rename the new database with the name of the old database
//    Delete fhdb.
//
// Phase 1 is highly concurrent: retrieving remote, inserting keys to
// fhdb, and lookups in the local database all run concurrently.  The
// variable out keeps track how many outstanding operations 
// (insert, lookup, or RPCs) we have.
// Phase 2 is also concurrent but is simpler.

#include "async.h"
#include "arpc.h"
#include "sfsmisc.h"
#include "str.h"
#include "sfsro_prot.h"
#include "crypt.h"
#include "sha1.h"
#include "xdrmisc.h"
#include "sfsrodb_core.h"
#include "sfsconnect.h"

struct roconstate {
  str hostname;
  char IV[SFSRO_IVSIZE];
  ptr<axprt_stream> x;
  ptr<aclnt> sfsc;
  ptr<aclnt> sfsroc;
  sfs_connectarg carg;
  sfs_connectres cres;
  ptr<sfs_servinfo_w> siw;
  sfs_pubkey2 spk;
  sfsro_fsinfo si;

  void start ();
  void getfd (int fd);
  void getconres (enum clnt_stat err);
  void getfsinfo (enum clnt_stat err);
  void updatedb ();
  void recurse_cb (ref<sfs_hash> fh, sfsro_datares *res);
  void recurse (sfs_hash *fh);
  void getdata (ref<sfs_hash> fh, sfsro_datares *rores, clnt_stat err);
  void processdata (ref<sfs_hash> fh, sfsro_datares *res);
  void doinode (sfsro_inode *i);
  void dodir (sfsro_directory *dir);
  void doindir (sfsro_indirect *indir);

};

struct dbstate {
  dbfe *dbp;
  dbfe *newdbp;
  str name;
  str tname;
  sfsro_fsinfo si;
  ptr<dbrec> si_res;
  ptr<dbrec> con_res;
  dbstate (str dbfile);
  void getfsinfo_cb (sfsro_fsinfo *si, ptr<dbrec> res);
  void getfsinfo ();
  void present_cb (callback<void,ref<sfs_hash>,sfsro_datares *>::ref cb, 
		   ref<sfs_hash> fh, ptr<dbrec> dat);
  void present (callback<void,ref<sfs_hash>,sfsro_datares *>::ref cb, 
		ref<sfs_hash> fh);
  void add_cb (int err);
  void add (sfs_hash *fh, sfsro_datares *res);
  void newdb ();
};

struct fhdbstate {
  str name;
  bool completed;
  dbfe *dbp;
  fhdbstate (str f);
  void add_cb (int err);
  void addkey (void *val, int len);
  void eleminsert_cb (int err);
  void elemlookup_cb (dbstate *db, ptr<dbrec> key, ptr<dbrec> dat);
  void nextelem_cb (dbstate *db, ptr<dbPair> res);
  void final ();
  void buildnewdb (dbstate *db);
};

dbstate *db;
fhdbstate *fhdb;
char null[SFSRO_FHSIZE];
sfs_hash nullfh;
int nout;

static int 
opendb (dbfe **dbp, str dbfile, int create)
{
  ref<dbImplInfo> info = dbGetImplInfo();

  //create the generic object
  *dbp = new dbfe();

  //set up the options we want
  dbOptions opts;
  //ideally, we would check the validity of these...
  opts.addOption("opt_async", 1);
  opts.addOption("opt_cachesize", 80000);
  opts.addOption("opt_nodesize", 4096);
  opts.addOption("opt_create", 1);

  const char *s = dbfile;
  if (create) {
    if ((*dbp)->createdb(const_cast < char *>(s), opts) != 0) {
      warn << "createdb failed " << dbfile << " " << strerror (errno) << "\n";
      return 0;
    }
  } 
  if ((*dbp)->opendb (const_cast < char *>(s), opts) != 0) {
    warn << "opendb failed " << strerror (errno) << "\n";
    return 0;
  }
  return 1;
}

static
void done ()
{
  if (nout > 0) return;

  fhdb->buildnewdb (db);
}

dbstate::dbstate (str dbfile)
{
  if (!opendb (&dbp, dbfile, 0))
    exit (-1);
  name = dbfile;
  tname = name << "#";
  getfsinfo ();
}

void
dbstate::getfsinfo_cb (sfsro_fsinfo *si, ptr<dbrec> res)
{
  if (res == NULL) {
    warnx << "fsinfo lookup returned failed\n";
    exit (1);
  }
  xdrmem x (static_cast<char *>(res->value), res->len, XDR_DECODE);
  if (!xdr_sfsro_fsinfo (x.xdrp(), si)) {
    warnx << "couldn't decode sfsro_fsinfo\n";
  }
}

void
dbstate::getfsinfo ()
{
  ref<dbrec> key = new refcounted<dbrec>((void *)"fsinfo", 6);
  dbp->lookup (key, wrap (this, &dbstate::getfsinfo_cb, &si));
}


void
dbstate::present_cb (callback<void,ref<sfs_hash>,sfsro_datares *>::ref cb, 
		     ref<sfs_hash> fh, ptr<dbrec> dat)
{
  sfsro_datares *res = NULL;

  if (dat != NULL) {
    res = New sfsro_datares();
    res->set_status (SFSRO_OK);
    res->resok->data.setsize(dat->len);
    memcpy (res->resok->data.base (), dat->value, dat->len);
    (*cb) (fh, res);
  } else {
    (*cb) (fh, res);
  }
}

void
dbstate::present (callback<void,ref<sfs_hash>,sfsro_datares *>::ref cb, 
		  ref<sfs_hash> fh)
{
  ref<dbrec> key = new refcounted<dbrec>((void *)fh->base (), fh->size ());
  dbp->lookup (key, wrap (this, &dbstate::present_cb, cb, fh));
}

void
dbstate::add_cb (int err) 
{
  if (err) {
    warn << "insert returned " << err << strerror(err) << "\n";
    exit (1);
  }
  nout--;
  done ();
}

void
dbstate::add (sfs_hash *fh, sfsro_datares *res)
{
  ref<dbrec> key = new refcounted<dbrec>((void *) fh->base (), fh->size ());
  ref<dbrec> data = new refcounted<dbrec>((void *) res->resok->data.base (), 
					  res->resok->data.size ());
  nout++;
  dbp->insert(key, data, wrap (this, &dbstate::add_cb));
}

void dbstate::newdb ()
{
  if (!opendb (&newdbp, tname, 1))
    exit (-1);
}

void roconstate::start ()
{
  /* XXX - don't hard-code ports */
  tcpconnect (hostname, sfs_defport, wrap (this, &roconstate::getfd));
}

void
roconstate::getfd (int fd)
{
  if (fd < 0) {
    warnx << hostname << ": " << strerror (errno);
    exit (1);
  }
  x = axprt_stream::alloc (fd);
  sfsc = aclnt::alloc (x, sfs_program_1);
  sfsroc = aclnt::alloc (x, sfsro_program_2);
  sfs_initci (&carg, hostname, SFS_SFS);
  sfsc->call (SFSPROC_CONNECT, &carg, &cres,
	      wrap (this, &roconstate::getconres));
}

fhdbstate::fhdbstate (str f)
{
  name = f << "fhdb";
  if (!opendb (&dbp, name, 1)) 
    exit (-1);
}

void
fhdbstate::add_cb (int err)
{
  if (err) {
    warn << "insert failed\n";
    exit (-1);
  }
  nout--;
}

void 
fhdbstate::addkey (void *val, int size)
{
  ref<dbrec> key = new refcounted<dbrec>((void *) val, size);
  ptr<dbrec> dat = new refcounted<dbrec>((void *) 0, 0);
  nout++;
  dbp->insert(key, dat, wrap (this, &fhdbstate::add_cb));
}


void
fhdbstate::eleminsert_cb (int err)
{
  if (err) {
    warn << "insert returned " << err << strerror(err) << "\n";
    exit (-1);
  }
  nout--;
  final();
}

void
fhdbstate::elemlookup_cb (dbstate *db, ptr<dbrec> key, ptr<dbrec> dat)
{
  if (dat != NULL) {
    if (memcmp (key->value, (void *) "fsinfo", 6) == 0) {
      db->newdbp->insert(key, db->si_res, 
			 wrap (this, &fhdbstate::eleminsert_cb));
    } 
    else if (memcmp (key->value, (void *) "conres", 6) == 0) {
      db->newdbp->insert(key, db->con_res, 
			 wrap (this, &fhdbstate::eleminsert_cb));
    } 
    else {
      db->newdbp->insert(key, dat, wrap (this, &fhdbstate::eleminsert_cb));
    }
  } else {
    warnx << "elemlookup_cb: weird the data for this key should be present";
    exit (-1);
  }
}

void
fhdbstate::nextelem_cb (dbstate *db, ptr<dbPair> res)
{
  sfs_hash fh;

  memcpy (fh.base(), res->key->value, res->key->len);
  db->dbp->lookup (res->key, wrap (this, &fhdbstate::elemlookup_cb, db, 
				   res->key));
}

void
fhdbstate::final ()
{
  if (!completed || (nout > 0)) return;

  if (int err = db->dbp->closedb ()) {
    warnx << "dbp->closedb: " << strerror (err) << "\n";
    exit (1);
  }
  if (int err = db->newdbp->closedb ()) {
    warnx << "newdbp->closedb: " << strerror (err) << "\n";
    exit (1);
  }
  if (int err = unlink (name)) {
    warnx << "unlink " << name << ": " << strerror (err) << "\n";
    exit (1);
  }
  if (int err = rename (db->tname, db->name)) {
    warnx << "rename " << db->tname << ": " << strerror (err) << "\n";
    exit (1);
  }
  exit (0);
}

void
fhdbstate::buildnewdb (dbstate *db)
{
  // fhdb contains all the file handles that we should keep.
  // create a new db that contains them all.
  db->newdb ();
  completed = false;
  ptr<dbEnumeration> it = dbp->enumerate();
  while (it->hasMoreElements()) {
    nout++;
    it->nextElement(wrap (this, &fhdbstate::nextelem_cb, db));
  }
  completed = true;
  final ();
}

void
roconstate::getconres (enum clnt_stat err)
{
  if (err) {
    warnx << carg.ci5->sname << ": " << err  << "\n";
    exit (1);
  }
  if (cres.status) {
    warnx << carg.ci5->sname << ": " << cres.status;
    exit (1);
  }

  // check whether the public key supplied by host can verify
  // the sfsro info structure stored in the database.
  siw = sfs_servinfo_w::alloc (cres.reply->servinfo);
  spk = siw->get_pubkey ();
  if (!sfscrypt.verify (spk, db->si.v2->sig, xdr2str (db->si.v2->info))) {
      warnx << "SIGNATURE DOESN'T MATCH\n";
      exit(-1);
  } else {
    warnx << "SIGNATURE MATCHES FOR HOSTINFO IN DB\n";
  }

  // marshal cres so that we can stick it in the database.
  xdrsuio x (XDR_ENCODE);
  if (xdr_sfs_connectres (x.xdrp (), &cres)) {
    int l = x.uio ()->resid ();
    void *v = suio_flatten (x.uio ());
    db->con_res = new refcounted<dbrec>(v, l);
  }

  sfsc->call (SFSPROC_GETFSINFO, NULL, (sfs_fsinfo*)&si, 
	      wrap (this, &roconstate::getfsinfo),
	      NULL, NULL, xdr_sfsro_fsinfo);
}


void
roconstate::getfsinfo (clnt_stat err)
{
  if (err) {
    warnx << carg.ci5->sname << ": " << err  << "\n";
    exit (1);
  }

  // check whether the public key supplied by host can verify
  // the sfsro info structure returned by host.
  if (!sfscrypt.verify (spk, si.v2->sig, xdr2str (si.v2->info))) {
      warnx << "SIGNATURE DOESN'T MATCH\n";
      exit(-1);
  } else {
    warnx << "SIGNATURE MATCHES FOR FSINO AT SERVER\n";
  }
  memcpy (IV, si.v2->info.pub->iv.base (), SFSRO_IVSIZE);

  // at this point, we have two fsinfo structures that both have
  // been verified by the same public key.

  // marshal the received fsinfo so that we can stick it in the database.
  xdrsuio x (XDR_ENCODE);
  if (xdr_sfsro_fsinfo (x.xdrp (), &si)) {
    int l = x.uio ()->resid ();
    void *v = suio_flatten (x.uio ());
    db->si_res = new refcounted<dbrec>(v, l);
  }

  updatedb();
}


void
roconstate::updatedb ()
{
  if (si.v2->info.pub->start < db->si.v2->info.pub->start) {
      warnx << "updatedb: error new data is less fresh\n";
      exit (-1);
  }
  // Add fsinfo and conres to fhdb database so that we copy them later
  fhdb->addkey ((void *) "fsinfo", 6);
  fhdb->addkey ((void *) "conres", 6);
  recurse (&si.v2->info.pub->rootfh);
  done ();
}


void
roconstate::recurse_cb (ref<sfs_hash> fh, sfsro_datares *res)
{
  if (res) {
    processdata (fh, res);
  } else {
    nout++;
    sfsro_datares *res = New sfsro_datares();

    sfsro_getdataargs gdargs;
    gdargs.sname = carg.ci5->sname;
    gdargs.fh = *fh;
    
    sfsroc->call (SFSROPROC2_GETDATA, &gdargs, res,
		  wrap (this, &roconstate::getdata, fh, res));
  }
  nout--;
  done ();
}

void 
roconstate::recurse (sfs_hash *fh)
{
  if (memcmp (fh->base(), nullfh.base (), nullfh.size ()) == 0) {
    return;
  }
  fhdb->addkey ((void *) (fh->base()), fh->size());
  ref<sfs_hash> fh_ref = New refcounted<sfs_hash> (*fh);
  nout++;
  db->present (wrap (this, &roconstate::recurse_cb), fh_ref);
}


void
roconstate::getdata (ref<sfs_hash> fh, sfsro_datares *rores, clnt_stat err)
{
  auto_xdr_delete axd (sfsro_program_2.tbl[SFSROPROC2_GETDATA].xdr_res, rores);

  if (err) {
    warnx << "getdata: " << err  << "\n";
    exit (1);
  }

  if (rores->status) {
    warnx << "getdata: " << rores->status << "\n";
    exit (1);
  }
  db->add (fh, rores);
  processdata (fh, rores);
  nout--;
  done();
}


void roconstate::processdata (ref<sfs_hash> fh, sfsro_datares *rores)
{
  char *resbuf = rores->resok->data.base();
  size_t reslen = rores->resok->data.size();
  sfsro_data data;

  /* check hash of unmarshalled data */
  if (!verify_sfsrofh (IV, SFSRO_IVSIZE, fh, resbuf, reslen)) {
    warnx << "processdata: couldn't verify data\n";
  }

  xdrmem x (resbuf, reslen, XDR_DECODE);
  bool ok = xdr_sfsro_data (x.xdrp (), &data);
  if (!ok) {
    warnx << "processdata: couldn't unmarshall data\n";
    return;
  }

  switch (data.type) {
  case SFSRO_INODE:
    doinode (&(*data.inode));
    break;
  case SFSRO_FILEBLK:
    // no more fh; stop recursing
    break;
  case SFSRO_DIRBLK:
    dodir (&(*data.dir));
    break;
  case SFSRO_INDIR:
    doindir (&(*data.indir));
    break;
  default:
    warnx << "processdata: unknown type " << data.type << "\n";
    exit (1);
  }
}

void
roconstate::doinode (sfsro_inode *inode)
{
  switch (inode->type) {
  case SFSROLNK:
    warnx << "unimplemented\n";
    exit (1);
  default:
    for (unsigned int i = 0; i < inode->reg->direct.size (); i++)
	recurse (&inode->reg->direct[i]);
    recurse (&inode->reg->indirect);
    recurse (&inode->reg->double_indirect);
    recurse (&inode->reg->triple_indirect);
  }
}

void
roconstate::dodir (sfsro_directory *dir)
{
  for (sfsro_dirent *roe = dir->entries; roe; roe = roe->nextentry) {
    recurse (&roe->fh);
  }
}

void
roconstate::doindir (sfsro_indirect *indir)
{
  for (unsigned int i = 0; i < indir->handles.size (); i++) {
    recurse (&indir->handles[i]);
  }
}

int
main(int argc, char **argv) 
{
  if (argc != 3) 
    {
      warnx << "Usage: " << argv[0] << " <rodb> <hostname>\n";
      exit (1);
    }

  sfsconst_init();

  roconstate *sc = New roconstate;
  sc->hostname = argv[2];
  
  db = New dbstate (str (argv[1]));
  fhdb = New fhdbstate (db->name);

  memcpy (nullfh.base(), null, nullfh.size());

  nout = 0;
  sc->start ();

  amain ();

  return 0;
}
