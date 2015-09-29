#ifndef _SFSRWSD_ACLTARGETLIST_H_
#define _SFSRWSD_ACLTARGETLIST_H_ 1

#include "nfstrans.h"
#include "nfsserv.h"
#include "nfs3_nonnul.h"
#include "str.h"
#include "nfs3_prot.h"
#include "acldefs.h"

#define MAXITER 5
enum fhtype { file, dir, other, unknown, not_set };

class acltarget {
  nfs_fh3 objectfh;
  bool objectfhset; 
  fhtype object_type;

  nfs_fh3 aclfh;
  bool aclfhset;

  bool error;
  bool resolved;

  bool aclstrset;
  char aclstrbuf[ACLSIZE];
  time_t expires;
  bool invalid;

public:
  bool match_aclfhp (nfs_fh3 *fhp);
  void set_objectfh (nfs_fh3 *fh, fhtype type);
  void set_objecttype (fhtype t);
  void set_aclfh (nfs_fh3 *fh);
  inline bool aclfh_known () { return aclfhset; }
  inline nfs_fh3 *get_objectfhp () { return objectfhset ? &objectfh : NULL; }
  inline nfs_fh3 *get_aclfhp () { return aclfhset ? &aclfh : NULL; }
  fhtype get_objecttype ();
  inline bool has_error () { return error; }
  inline bool is_done () { return resolved || has_error (); }
  void set_aclstr (str s) ;
  str get_aclstr ();
  inline bool has_aclstr () { return aclstrset; }
  strbuf print ();
  inline void invalidate () { invalid = true; }
  
  inline void set_error () { error = true; }
  void set_error (str s);
  bool match_fhp (nfs_fh3 *fhp);

  acltarget ();
  acltarget (const acltarget &t);
};

class acltargetlist {
  bool error;
  bool resolved;
  bool allowop;
  bool allowop_set;
  acltarget entries[2];
  u_int p1;
  bool p1_set;
  u_int p2;
  bool p2_set;
  static int lastpos;
  static acltarget aclcache[ACLCACHESIZE];
  u_int count;

public:
  bool check_cache ();
  static void insert_cache (acltarget *e);
  static void invalidate_centry (acltarget *e);
  acltarget *next_entry ();
  bool is_done () ;
  inline acltarget *first () { return &entries[0]; }
  inline acltarget *second () { return &entries[1]; }
  inline void set_error () { error = true; }
  inline void set_resolved () { resolved = true; }
  bool has_error ();
  inline void touch () { count++; }
  inline int remaining_iterations () { return MAXITER - count; }
  void set_allowop (bool v);
  bool get_allowop ();
  inline void set_p1 (u_int p) { p1 = p; p1_set = true; }
  inline void set_p2 (u_int p) { p2 = p; p2_set = true; }
  inline u_int get_p1 () { return p1_set ? p1 : 0; }
  inline u_int get_p2 () { return p2_set ? p2 : 0; }
  strbuf print ();

  acltargetlist ();
};

#endif /* _SFSRWSD_ACLTARGETLIST_H_ */
