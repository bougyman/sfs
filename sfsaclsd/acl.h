#ifndef _SFSRWSD_ACL_H_
#define _SFSRWSD_ACL_H_ 1

#include "async.h"
#include "parseopt.h"
#include "str.h"
#include "rxx.h"
#include "acldefs.h"
#include "sfsaclsd.h"
#include "crypt.h"

class aclline {
  str type;
  str entry;
  str permstr;

  bool _parsed_ok;

  u_int permissions;

public:
  bool is_member (vec<str> &credstrings);
  bool parsed_ok () { return _parsed_ok; }
  inline bool has_more (u_int p) { return (permissions & ~p); }
  inline u_int get_permissions () { return permissions; }

  str print ();

  aclline (str s);
};

struct pcache_entry {
  char hashbuf[sha1::hashsize];
  bool key_set;
  u_int perms;

  bool match_key (const char *h, u_int &p);
  bool set (const char *h, u_int p);

  pcache_entry ()
    : key_set (false), perms (0)  {
    bzero (hashbuf, sizeof (hashbuf));	 
  }
};

class acl {
  str aclstr;
  static int lastpos; 
  static pcache_entry pcache[PCACHESIZE];
  char hashbuf[sha1::hashsize];
  char aclhash[sha1::hashsize];
  
  void insert_cache (const char *h, u_int p);
  bool is_cached (const char *h, u_int &p);
  u_int parse_acl (vec<str> &credstrings);

public:
  u_int get_permissions (sfsauth_cred *cred, str *key,
                         vec<sfs_idname> *groups);
  static void fix_aclstr (str s, char *buf);

  acl (str s);
};

#endif /* _SFSRWSD_ACL_H_ */
