#ifndef _FILESRV_H_
#define _FILESRV_H_

#include "async.h"
#include "sfsmisc.h"
#include "nfs3_prot.h"
#include "nfstrans.h"
#include "sfs_prot.h"
#include "arpc.h"
#include "crypt.h"

void trans_attr (ex_fattr3 *fa, struct stat *sb);

class filesrv;

class fh_entry {
private:
  int fd;

public:
  str path;
  nfs_fh3 fh;
  ex_fattr3 fa;
  filesrv *fsrv;
  time_t lastused;

  ihash_entry<fh_entry> fhlink;
  tailq_entry<fh_entry> timeoutlink;
 
  fh_entry (str p, nfs_fh3 f, ex_fattr3 *a, filesrv *fs);
  ~fh_entry ();
  int closefd (void);
  void setfd (int f) { fd = f;}
  void update_attr (int fd);
  void update_attr (str p);
  void print (void);
};


class filesrv {
private:
  static const int fhe_timer = 5;      // seconds
  static const int fhe_expire = 3600;  // expire time in seconds for fh
  static const int fd_expire = 30;     // expire time in seconds for fd
  static const int fhe_max = 10000;    // max number of file handles
  static const int fd_max = 60;        // max number of file descriptors
  int fhe_n;                           // number of file handles in use
  int fd_n;                            // number of file descriptors in use

  ihash<nfs_fh3, fh_entry, &fh_entry::fh, &fh_entry::fhlink> entries;
  tailq<fh_entry, &fh_entry::timeoutlink> timeoutlist;
  timecb_t *fhetmo;

public:
  sfs_servinfo servinfo;
  ptr<sfs_servinfo_w> siw;
  sfs_hash hostid;
  ptr<sfspriv> privkey;
  fh_entry *root;

  filesrv();
  void fhetimeout (void);
  int lookup_attr (str p, ex_fattr3 *fa);
  void mk_fh (nfs_fh3 *fh, ex_fattr3 *fa);
  int closefd (fh_entry *fh);
  int getfd (fh_entry *fhe, int flags);
  int getfd (str p, int flags, mode_t mode);
  fh_entry *lookup_add (str p);
  fh_entry *lookup (nfs_fh3 *fh);
  void remove (fh_entry *fhe);
  int checkfhe (void);
  void purgefd (int force);
  void purgefhe (void);
  void printfhe (void);
  int checkfd (void);

};

#endif /* _FILESRV_H_ */
