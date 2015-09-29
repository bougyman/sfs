/* $Id: authdb_types.x,v 1.4 2001/11/19 06:02:03 dm Exp $ */

/*
 * This file was written by David Mazieres.  Its contents is
 * uncopyrighted and in the public domain.  Of course, standards of
 * academic honesty nonetheless prevent anyone in research from
 * falsely claiming credit for this work.
 */

%#include "sfsauth_prot.h"

#if 0
typedef string authname<32>;
typedef authname authnamelist<>;

struct authidrange {
  u_int32_t low;
  u_int32_t high;
};
typedef authidrange authidlist<>;

struct authids {
  u_int32_t uid;
  u_int32_t gid;
  u_int32_t groups<16>;
};

enum privilege_type {
  PRIV_ADMIN = 1,
  PRIV_LOGIN = 2,
  PRIV_IDS = 3
};
union privilege switch (privilege_type type) {
 case PRIV_ADMIN:
   void;
 case PRIV_LOGIN:
   authname login;
 case PRIV_IDS:
   authids ids;
};
typedef privilege privlist<>;

enum pwauth_type {
  PWAUTH_NONE = 0,
  PWAUTH_SRP = 1
};
union pwauth_info switch (pwauth_type type) {
 case PWAUTH_NONE:
   void;
 case PWAUTH_SRP:
   opaque srp<>;
};

struct authdb_user {
  authname *owner;
  sfs_pubkey pubkey;
  privlist privs;
  pwauth_info pwauth;
  opaque privkey<>;
};

struct authdb_group {
  u_int32_t id;
  authnamelist owners;
  authnamelist members;
};

enum authentry_type {
  AUTHDB_ERROR = 0,
  AUTHDB_USER = 1,
  AUTHDB_GROUP = 2
};
union authentry_info switch (authentry_type type) {
 case AUTHDB_USER:
   authdb_user user;
 case AUTHDB_GROUP:
   authdb_group group;
};
struct authentry {
  authname name;
  u_int32_t vers;
  opaque audit<>;
  authentry_info info;
};
#endif
