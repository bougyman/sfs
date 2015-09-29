/* $Id: authgrps.h,v 1.23 2004/04/15 05:39:50 dm Exp $ */

/*
 *
 * Copyright (C) 2003 Michael Kaminsky (kaminsky@lcs.mit.edu)
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#ifndef _SFSAUTHD_SFSGRPS_H
#define _SFSAUTHD_SFSGRPS_H

#include "async.h"
#include "itree.h"
#include "authdb.h"
#include "sfskeymgr.h"
#include "sfsusermgr.h"
#include "sfsgroupmgr.h"
#include "sfsauth_prot.h"

const u_int32_t def_refresh = 3600;
const u_int32_t def_timeout = 7 * 24 * 3600;

class group_expander : public virtual refcount {
private:
  enum { maxclosuresize = 1000000 };

  str name;
  ptr<sfsusermgr> um;
  ptr<sfsgroupmgr> gm;

  unsigned int pending;
  bool in_do_list;
  bool too_big;

  qhash<str, sfs_groupmembers> cache;
  sfs_groupmembers queue;
  sfs_groupmembers closure;

public:
  void go ();

  group_expander (str _name, ptr<sfsusermgr> _um, ptr<sfsgroupmgr> _gm)
    : name (_name), um (_um), gm (_gm) { };

private:
  void do_list ();
  void do_entry (sfs_groupmember e);
  void fetch_group_local (sfs_groupmember e);
  void fetch_user_remote (sfs_groupmember e);
  void fetch_group_remote (sfs_groupmember e);
  void fetch_user_cb (sfs_groupmember e, bool uptodate,
                      ptr<sfsauth2_query_res> aqr, str sfshost);
  void fetch_group_cb (sfs_groupmember e, unsigned int current, bool uptodate,
                       ptr<sfsauth2_query_res> aqr, str sfshost);
  void done ();
};

struct dbcache {
  virtual ~dbcache () {}
  virtual sfsauth_cacheentry *lookup (const sfs_groupmember &s) = 0;
  virtual void rev_lookup (vec<str> *groups, sfs_groupmember member) = 0;
  virtual void insert (const sfsauth_cacheentry &e) = 0;
  virtual bool remove (sfsauth_cacheentry *e) = 0;
  virtual bool remove (const sfs_groupmember &m)
    { sfsauth_cacheentry *e = lookup (m); return e && remove (e); }
  virtual void read () {}
  virtual void write () {}

  void find_groups (vec<str> *names);
};

struct member_group {
  sfs_groupmember member;
  sfs_groupmember group;
  member_group () {}
  member_group (const str &m, const str &g) : member (m), group (g) {}
};
template<> struct compare<member_group> {
  compare () {}
  int operator() (const member_group &a, const member_group &b) const {
    if (int r = strcmp (a.member, b.member))
      return r;
    return strcmp (a.group, b.group);
  }
};

template<class K, class V, class S, K S::*key,
  ihash_entry<V> V::*field, class H = hashfn<K>, class E = equals<K> >
class ishash
  : public ihash_core<V, field>
{
  const E eq;
  const H hash;

public:
  ishash () {}
  ishash (const E &e, const H &h) : eq (e), hash (h) {}

  void insert (V *elm) { insert_val (elm, hash (elm->*key)); }

  template<class T> V *operator[] (const T &k) const {
    V *v;
    for (v = lookup_val (hash (k));
	 v && !eq (k, v->*key);
	 v = next_val (v))
      ;
    return v;
  }

  V *nextkeq (V *v) {
    const K &k = v->*key;
    while ((v = next_val (v)) && !eq (k, v->*key))
      ;
    return v;
  };
};

class dbcache_mem : public dbcache {
  struct slot : sfsauth_cacheentry {
    ihash_entry<slot> hlink;
    explicit slot (const sfsauth_cacheentry &e) { *this = e; }
    slot &operator= (const sfsauth_cacheentry &e)
      { *static_cast<sfsauth_cacheentry *> (this) = e; return *this; }
    //operator hash_t () const { return key; }
    //bool operator== (const slot &s) { return key == s.key; }
  };
  struct ugslot {
    member_group mg;
    itree_entry<ugslot> tlink;
    ugslot (const sfs_groupmember &m, const sfs_groupmember &g = "")
      { mg.member = m; mg.group = g; }
  };

  bool dirty;
  ptr<authdb> cachedb;
  ishash<sfs_groupmember, slot, sfsauth_cacheentry,
    &dbcache_mem::slot::key, &dbcache_mem::slot::hlink> db;
  itree<member_group, ugslot, &dbcache_mem::ugslot::mg,
    &dbcache_mem::ugslot::tlink> u2gmap;

  void read ();
  void sremove (slot *s);

public:
  dbcache_mem ();
  ~dbcache_mem ();
  sfsauth_cacheentry *lookup (const sfs_groupmember &m) { return db[m]; }
  void print_u2gmap (ugslot *s, int level);
  void rev_lookup (vec<str> *groups, sfs_groupmember member);
  bool remove (sfsauth_cacheentry *e)
    { sremove (static_cast<slot *> (e)); return true; }
  void insert (const sfsauth_cacheentry &e);
  void write ();
};

extern dbcache *global_dbcache;

void process_group_updates (sfs_groupmembers &cur, sfs_groupmembers &updates);
bool write_group_changelog (str name, unsigned int vers,
	                    const sfs_groupmembers &updates, str audit);
unsigned int read_group_changelog (str name, unsigned int client_vers,
                                   sfs_groupmembers &updates);
bool is_a_member (str user, str pkhash, const sfs_groupmembers &list);
void transitive_closure (sfs_groupmembers queue, sfs_groupmembers &closure);
void init_dbcache ();
void write_dbcache ();
void read_dbcache ();
void update_dbcache (ptr<authcursor> ac, bool update_all = false);
void obfuscate_group (sfs_groupmembers &l, bool changelog = false);

#endif /* _SFSAUTHD_SFSGRPS_H */
