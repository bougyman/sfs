/* $Id: authgrps.C,v 1.36 2004/04/15 05:39:50 dm Exp $ */

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

#include "authgrps.h"
#include "sfsauthd.h"

dbcache *global_dbcache;

static void
rem_vec (sfs_groupmembers &v, const sfs_groupmember s)
{
  unsigned int n = v.size ();
  while (n--) {
    sfs_groupmember t = v.pop_front ();
    if (!(t == s))
      v.push_back (t);
  }
}

static bool 
in_vec (const sfs_groupmembers &v, const sfs_groupmember s)
{
  for (unsigned int i = 0; i < v.size (); i++)
    if (v[i] == s)
      return true;
  return false;
}

void
process_group_updates (sfs_groupmembers &cur, sfs_groupmembers &updates)
{
  sfs_groupmembers rej, upd;

  for (unsigned int i = 0; i < updates.size (); i++) {
    const char *p = updates[i].cstr ();
    bool present = in_vec (cur, &p[1]);
    switch (p[0]) {
    case '+':
      if (present)
	rej.push_back (&p[0]);
      else {
	cur.push_back (&p[1]);
	upd.push_back (&p[0]);
      }
      break;
    case '-':
      if (!present)
	rej.push_back (&p[0]);
      else {
	rem_vec (cur, &p[1]);
	upd.push_back (&p[0]);
      }
      break;
    default:
      rej.push_back (&p[0]);
    }
  }

  updates = upd;

  // XXX: don't do anything with rejected updates for
  // now because we have no way in the protocol to report
  // them to the user (UPDATE RPC result only has an error
  // string for failure)
}

static inline str
name2logfile (str name)
{
  assert (sfsauthcachedir);
  assert (name);
  return sfsauthcachedir << "/" << name << ".GROUP_CHANGELOG";
}

static bool
verify_changelog (ptr<authcursor> ac, unsigned int *client_vers = NULL)
{
  bool first = true;
  unsigned int expected = 0, current = 0;

  ac->reset ();
  while (ac->next ()) {
    if (ac->ae.type != SFSAUTH_LOGENTRY) {
      warn << "verify_changelog: ignorning non-changelog entry.\n";
      continue;
    }
    current = ac->ae.logentry->vers;
    if (client_vers && first && current > (*client_vers + 1)) {
      warn << "verify_changelog: oldest changelog version is " << current
	   << "; need history from version " << (*client_vers + 1 ) << "\n";
      return false;
    }
    expected = first ? current : expected + 1;
    if (current != expected) {
      warn << "verify_changelog: changelog entries are not sequential: "
           << current << " != " << expected << " (expected)\n";
      return false;
    }
    first = false;
  }
  // XXX: Verify that lastest changelog version matches that in the
  // DB file's group entry -- probably don't need this since our update
  // scheme ensures that they'll be in synch
  return true;
}

bool
write_group_changelog (str name, unsigned int vers,
	               const sfs_groupmembers &updates, str audit)
{
  str file = name2logfile (name);
  ptr<authdb> cl = New refcounted<authdb_file> (file);
  ptr<authcursor> ac = cl->open (authdb::AUDB_WRITE|authdb::AUDB_CREATE);

  if (!ac) {
    warn << "write_group_changelog: could not open changelog for "
         << name << "\n";
    return false;
  }
  if (!verify_changelog (ac)) {
    warn << "write_group_changelog: could not verify changelog for "
         << name << "\n";
    return false;
  }

  sfsauth_dbrec rec (SFSAUTH_LOGENTRY);
  rec.logentry->vers = vers;
  rec.logentry->members = updates;
  rec.logentry->audit = audit;

  ac->ae = rec;

  if (!ac->update ()) {
    warn << "write_group_changelog: Update failed\n";
    return false;
  }
  return true;
}

unsigned int
read_group_changelog (str name, unsigned int client_vers, sfs_groupmembers &updates)
{
  str file = name2logfile (name);
  ptr<authdb> cl = New refcounted<authdb_file> (file);
  ptr<authcursor> ac = cl->open (authdb::AUDB_WRITE|authdb::AUDB_CREATE);
  unsigned int i, n, latest = 0, spaces = 250;

  if (!ac) {
    warn << "read_group_changelog: could not open changelog for "
         << name << "\n";
    return 0;
  }
  if (!verify_changelog (ac, &client_vers)) {
    warn << "read_group_changelog: could not verify changelog for "
         << name << "\n";
    return 0;
  }

  ac->reset ();
  while (ac->next ()) {
    if (ac->ae.type != SFSAUTH_LOGENTRY) {
      warn << "Ignorning non-changelog entry in " << file << "\n";
      continue;
    }
    latest = ac->ae.logentry->vers;
    if (latest <= client_vers)
      continue;
    n = ac->ae.logentry->members.size ();
    if (n > spaces) {  // don't send more log entries than can fit in an RPC
      latest--;
      break;
    }
    spaces = spaces - n;

    for (i = 0; i < n; i++)
      updates.push_back (ac->ae.logentry->members[i]);
  }

  if (latest < client_vers) {
    warn << "Client said it had version " << client_vers << " but log only "
         << "goes to version " << latest << " for group " << name << "\n";
    latest = 0;
  }

  return latest;
}

bool
is_a_member (str user, str pkhash, const sfs_groupmembers &list)
{
  sfs_groupmembers closure;
  transitive_closure (list, closure);

  str u = add_member_type (user, "u");
  str p = add_member_type (pkhash, "p");

  unsigned int n = closure.size ();
  for (unsigned int i = 0; i < n; i++)
    if (closure[i] == u || closure[i] == p)
      return true;
  return false;
}

void
transitive_closure (sfs_groupmembers queue, sfs_groupmembers &closure)
{
  sfs_groupmembers *vals;
  qhash<sfs_groupmember, sfs_groupmembers> cache;
  sfsauth_cacheentry *dbe;

  // XXX: If !global_dbcache, then the closure will only contain immediate
  // pkhashes and local users; no recursion at all.  This function and the
  // one above are only used to test group ownership during an update and to
  // answer expanded queries.  For this reason expanded queries are disabled
  // if the cache is off (see not there in authclnt.C).

  while (queue.size () > 0) {
    sfs_groupmember e = queue.pop_front ();
    if (cache[e])
      continue;
    cache.insert (e, sfs_groupmembers ());

    if (!isremote (e) && (isuser (e) || ispkhash (e)))
      closure.push_back (e);
    else
      if (global_dbcache && (dbe = global_dbcache->lookup (e))) {
	vals = &dbe->values;
	unsigned int n = vals->size ();
	for (unsigned int i = 0; i < n; i++)
	  queue.push_back ((*vals)[i]);
      }
  }
}

void
init_dbcache ()
{
  if (!global_dbcache)
    global_dbcache = New dbcache_mem;
}

void
write_dbcache ()
{
  if (global_dbcache)
    global_dbcache->write ();
}

void
read_dbcache ()
{
  assert (global_dbcache);

  global_dbcache->read ();
}

void
update_dbcache (ptr<authcursor> ac, bool update_all)
{
  ptr<sfskeymgr> km = New refcounted<sfskeymgr> (str (NULL), (KM_NOCRT | KM_NODCHK | KM_NOHM));
  ptr<sfsusermgr> um = New refcounted<sfsusermgr> (km);
  ptr<sfsgroupmgr> gm = New refcounted<sfsgroupmgr> (km);
  bool done = false;
  unsigned int n, i;

  assert (global_dbcache);

  if (update_all)
    ac->reset ();
  while ((!update_all && !done) || (update_all && ac->next ())) {
    if (ac->ae.type == SFSAUTH_GROUP) {
      ptr<group_expander> ge = New refcounted<group_expander>
	(add_member_type (ac->ae.groupinfo->name, "g"), um, gm);
      ge->go ();

      n = ac->ae.groupinfo->owners.size ();
      for (i = 0; i < n; i++) {
	ptr<group_expander> ge = New refcounted<group_expander>
	  (ac->ae.groupinfo->owners[i], um, gm);
	ge->go ();
      }
    }
    done = true;
  }
}

static str
hash_pubkey (const sfs_pubkey2 &key)
{
  ptr<sfspub> pub = sfscrypt.alloc (key);
  if (!pub)
    return NULL;
  str h = pub->get_pubkey_hash ();
  if (!h)
    return NULL;
  return add_member_type (armor32 (h), "p");
}

void
obfuscate_group (sfs_groupmembers &list, bool changelog)
{
  unsigned int n = list.size ();
  sfsauth2_query_res res;
  sfsauth_dbkey key (SFSAUTH_DBKEY_NAME);
  str h;

  while (n--) {
    sfs_groupmember t = list.pop_front ();
    sfs_groupmember s = changelog ? substr (t, 1) : str (t);
    if (isuser (s) && !isremote (s)) {
      *key.name = rem_member_type (s);
      if (get_user_cursor (NULL, NULL, &res, key)
	  && (h = hash_pubkey (res.userinfo->pubkey)))
	if (changelog)
	  list.push_back (substr (t, 0, 1) << h);
	else
	  list.push_back (h);
    }
    else
      list.push_back (t);
  }
}

void
group_expander::go ()
{
  pending = 0;
  in_do_list = false;
  too_big = false;

  cache.clear ();
  closure.clear ();
  queue.clear ();

  queue.push_back (name);

  do_list ();
}

void
group_expander::do_list ()
{
  /* wait for all outstanding RPCs to return */
  if (pending || in_do_list)
    return;

  in_do_list = true;
  unsigned int n = queue.size ();
  for (unsigned int i = 0; i < n; i++)
    do_entry (queue.pop_front ());
  in_do_list = false;

  if (!pending)
    //if (queue.empty ())
    if (queue.size () == 0)
      done ();
    else
      do_list ();
}

void
group_expander::do_entry (sfs_groupmember e)
{
  if (too_big || cache[e])
    return;

  cache.insert (e, sfs_groupmembers ());

  if (!isremote (e))
    if (ispkhash (e) || isuser (e)) {
      closure.push_back (e);
      too_big = closure.size () >= maxclosuresize;
    }
    else if (isgroup (e))
      fetch_group_local (e);
    else
      panic ("should not be reached!\n");
  else
    if (isuser (e))
      fetch_user_remote (e);
    else if (isgroup (e))
      fetch_group_remote (e);
    else
      panic ("should not be reached!\n");
}

void
group_expander::fetch_group_local (sfs_groupmember e)
{
  pending++;

  ref<sfsauth2_query_res> res = New refcounted<sfsauth2_query_res>;
  sfsauth_dbkey key (SFSAUTH_DBKEY_NAME);
  *key.name = rem_member_type (e);

  get_group_cursor (NULL, NULL, res, key);

  fetch_group_cb (e, 0, false, res, NULL);
}

void
group_expander::fetch_user_remote (sfs_groupmember e)
{
  pending++;

  sfsauth_cacheentry *dbe = global_dbcache->lookup (e);
  sfs_time now = time (NULL);

  /* current version is "new enough"--don't fetch */
  if (dbe && now < dbe->last_update + dbe->refresh) {
    fetch_user_cb (e, true, NULL, NULL);
    return;
  }

  um->query (rem_member_type (e),
             wrap (mkref (this), &group_expander::fetch_user_cb,
                   e, false));
}

void
group_expander::fetch_group_remote (sfs_groupmember e)
{
  pending++;

  sfsauth_cacheentry *dbe = global_dbcache->lookup (e);
  sfs_time now = time (NULL);

  /* current version is "new enough"--don't fetch */
  if (dbe && now < dbe->last_update + dbe->refresh) {
    fetch_group_cb (e, 0, true, NULL, NULL);
    return;
  }

  unsigned int vers = dbe ? dbe->vers : 0;
  gm->changelogquery (rem_member_type (e), vers,
                      wrap (mkref (this), &group_expander::fetch_group_cb,
			    e, vers, false));
}

void
group_expander::fetch_user_cb (sfs_groupmember e, bool uptodate,
                               ptr<sfsauth2_query_res> aqr, str sfshost)
{
  pending--;

  if (too_big) {
    do_list ();
    return;
  }

  sfsauth_cacheentry *dbe = global_dbcache->lookup (e);
  sfs_time now = time (NULL);

  if (uptodate) {
    warn << "Cached user record is new enough: " << e << "\n";
    queue.push_back (dbe->values[0]);
    do_list ();
    return;
  }

  if (!aqr || aqr->type == SFSAUTH_ERROR) {
    if (aqr)
      warn << "fetch_user_cb: " << *aqr->errmsg << ": " << e << "\n";
    else
      warn << "fetch_user_cb: could not fetch user: " << e << "\n";
    if (!aqr && dbe && now < dbe->last_update + dbe->timeout) {
      warn << "Cached user record is not stale yet: " << e << "\n";
      queue.push_back (dbe->values[0]);
    }
    else
      // Currently, the only error strings that sfsauthd returns is "user
      // not found."  In that case, we don't want to use the cached entry
      // until the timeout expires, so we remove it.
      global_dbcache->remove (e);
    do_list ();
    return;
  }

  str pkhash;
  ptr<sfspub> pk = sfscrypt.alloc (aqr->userinfo->pubkey);
  if (!pk)
    warn << "fetch_user_cb: no public key returned from server: " << e << "\n";
  else {
    pkhash = pk->get_pubkey_hash ();
    if (!pkhash)
      warn << "fetch_user_cb: error in sha1_hashxdr of public key: " << e << "\n";
    else
      pkhash = armor32 (pkhash);
  }

  if (!pkhash) {
    // If we can't extract the user's public key from the user record, we
    // remove our locally cached copy (instead of using it until the timeout
    // expires).  The assumption is that this type of error isn't transient.
#if 0
    if (dbe && now < dbe->last_update + dbe->timeout)
      queue.push_back (dbe->values[0]);
    else
#endif
    global_dbcache->remove (e);
    do_list ();
    return;
  }
  sfs_groupmember h = add_member_type (armor32 (pkhash), "p");

  queue.push_back (h);

  sfs_groupmembers v;
  v.push_back (h);
  cache.insert (e, v);

  sfsauth_cacheentry ce;
  ce.key = e;
  ce.values = v;
  ce.vers = 0;
  ce.refresh = extract_u_int_default (aqr->userinfo->privs, refresh_eq,
				      def_refresh);
  ce.timeout = extract_u_int_default (aqr->userinfo->privs, timeout_eq,
				      def_timeout);
  ce.last_update = now;

  global_dbcache->insert (ce);

  warn << "TRANSFERRING `" << e << "'\n";

  do_list ();
}

void
group_expander::fetch_group_cb (sfs_groupmember e, unsigned int current,
                                bool uptodate, ptr<sfsauth2_query_res> aqr,
                                str sfshost)
{
  pending--;

  if (too_big) {
    do_list ();
    return;
  }

  sfsauth_cacheentry *dbe = global_dbcache->lookup (e);
  sfs_time new_refresh, new_timeout, now = time (NULL);

  if (uptodate) {
    warn << "Cached group record is new enough: " << e << "\n";
    for (unsigned int i = 0; i < dbe->values.size (); i++)
      queue.push_back (dbe->values[i]);
    do_list ();
    return;
  }

  if (!aqr || aqr->type == SFSAUTH_ERROR) {
    if (aqr)
      warn << "fetch_group_cb: " << *aqr->errmsg << ": " << e << "\n";
    else
      warn << "fetch_group_cb: could not fetch group: " << e << "\n";
    if (!aqr && dbe && now < dbe->last_update + dbe->timeout) {
      warn << "Cached group record is not stale yet: " << e << "\n";
      for (unsigned int i = 0; i < dbe->values.size (); i++)
        queue.push_back (dbe->values[i]);
    }
    else
      // Currently, the only error strings that sfsauthd returns is "user
      // not found."  In that case, we don't want to use the cached entry
      // until the timeout expires, so we remove it.
      global_dbcache->remove (e);
    do_list ();
    return;
  }

  sfs_groupmembers v;
  unsigned int new_version;

  if (aqr->type == SFSAUTH_LOGENTRY) {
    if (!dbe) {
      warn << "Did not find old version in dbcache (" << e << ")\n";
      sfsauth_cacheentry ce;
      ce.key = e;
      ce.vers = 0;
      // ce.refresh = 0; // XXX: better default
      // ce.timeout = 0; // XXX: better default
      ce.refresh = def_refresh;
      ce.timeout = def_timeout;
      ce.last_update = now;
      global_dbcache->insert (ce);
      dbe = global_dbcache->lookup (e);
    }

    if (dbe->vers != current) {
      // XXX:  Should we call fetch_group_remote/local (e) to retry? limit # retries?
      warn << "Database changed underneath us to version (db=" << dbe->vers
	   << "; curr=" << current << "): " << e << "\n";
      if (dbe->vers >= aqr->logentry->vers)
	warn << "But that is newer or equal to the version from server (="
	     << aqr->logentry->vers << ")...continuing\n";
      do_list ();
      return;
    }

    sfs_groupmembers l, u;
    unsigned int i, n;

    l = dbe->values;

    n = aqr->logentry->members.size ();
    u.setsize (n);
    for (i = 0; i < n; i++) {
      str s = substr (aqr->logentry->members[i], 1);
      if (isremote (e) && !isremote (s) && (isgroup (s) || isuser (s)))
	s = strbuf () << aqr->logentry->members[i] << sfshost;
      else
	s = aqr->logentry->members[i];
      u[i] = s;
    }

    process_group_updates (l, u);

    n = l.size ();
    for (i = 0; i < n; i++) {
      queue.push_back (l[i]);
      v.push_back (l[i]);
    }

    new_version = aqr->logentry->vers;
    new_refresh = aqr->logentry->refresh;
    new_timeout = aqr->logentry->timeout;
  }
  else if (aqr->type == SFSAUTH_GROUP) {
    unsigned int n = aqr->groupinfo->members.size ();
    for (unsigned int i = 0; i < n; i++) {
      str s = aqr->groupinfo->members[i];
      if (isremote (e) && !isremote (s) && (isgroup (s) || isuser (s)))
	s = strbuf () << s << sfshost;
      queue.push_back (s);
      v.push_back (s);
    }
    new_version = aqr->groupinfo->vers;
    new_refresh = extract_u_int_default (aqr->groupinfo->properties,
					 refresh_eq, def_refresh);
    new_timeout = extract_u_int_default (aqr->groupinfo->properties,
					 timeout_eq, def_refresh);
  }
  else
    panic ("shouldn't be reached; type == %d\n", aqr->type);

  cache.insert (e, v);
  sfsauth_cacheentry ce;
  ce.key = e;
  ce.values.set (v.base (), v.size ());
  ce.vers = new_version;
  ce.refresh = new_refresh;
  ce.timeout = new_timeout;
  ce.last_update = now;
  global_dbcache->insert (ce);

  if (isremote (e))
    warn << "TRANSFERRING `" << e << "': " << new_version - current
         << (aqr->type == SFSAUTH_GROUP ? " members\n" : " updates\n");

  do_list ();
}

void
group_expander::done ()
{
  if (too_big)
    warn << "Transitive Closure of `" << name << "' was too big...truncating\n";

#if 0
  warn << "TRANSITIVE CLOSURE FOR " << name << "\n";
  unsigned int n = closure.size ();
  for (unsigned int i = 0; i < n; i++)
    warn << "   " << closure[i] << "\n";
#endif
}


struct group_lookup_state {
  vec<str> todo;
  vec<str> terminals;
  bhash<str> seen;

  group_lookup_state () {}
  void enqueue (const str &name);
  void enqueuev (const vec<str> &names);
};

void
group_lookup_state::enqueue (const str &name)
{
  if (!seen.insert (name))
    return;
  if (!isremote (name) && isgroup (name))
    terminals.push_back (rem_member_type (name));
  todo.push_back (name);
}

void
group_lookup_state::enqueuev (const vec<str> &names)
{
  for (const str *np = names.base (); np < names.lim (); np++)
    enqueue (*np);
}

void
dbcache::find_groups (vec<str> *names)
{
  group_lookup_state gls;
  while (!names->empty ())
    gls.enqueue (names->pop_front ());
  while (!gls.todo.empty ()) {
    vec<str> groups;
    rev_lookup (&groups, gls.todo.pop_front ());
    gls.enqueuev (groups);
  }
  swap (*names, gls.terminals);
}

dbcache_mem::dbcache_mem ()
  : dirty (false)
{
  cachedb = authdb_alloc (sfsauthdbcache);
  if (!cachedb)
    fatal << "Could not allocate dbcache database: " << sfsauthdbcache << "\n";
}

dbcache_mem::~dbcache_mem ()
{
  db.traverse (wrap (this, &dbcache_mem::sremove));
}

void
dbcache_mem::print_u2gmap (ugslot *s, int level)
{
  if (s) {
    print_u2gmap (u2gmap.left (s), level + 1);
    for (int i = 0; i < level; i++)
      warnx << "    ";
    warnx << s->mg.member << "-->" << s->mg.group << "\n";
    print_u2gmap (u2gmap.right (s), level + 1);
  }
}

void
dbcache_mem::sremove (dbcache_mem::slot *s)
{
  for (sfs_groupmember *gmp = s->values.base (); gmp < s->values.lim (); gmp++)
    if (ugslot *ugp = u2gmap[member_group (*gmp, s->key)]) {
      u2gmap.remove (ugp);
      delete ugp;
    }
  db.remove (s);
  delete s;
}

void
dbcache_mem::rev_lookup (vec<str> *groups, sfs_groupmember member)
{
  groups->clear ();
  ugslot *s = u2gmap.root ();
  int r;
  while (s && (r = member.cmp (s->mg.member))) {
    if (r < 0)
      s = u2gmap.left (s);
    else
      s = u2gmap.right (s);
  }
  if (!s)
    return;
  for (ugslot *ss; (ss = u2gmap.prev (s)) && ss->mg.member == member; s = ss)
    ;
  for (; s && s->mg.member == member; s = u2gmap.next (s))
    groups->push_back (s->mg.group);
}

void
dbcache_mem::insert (const sfsauth_cacheentry &e)
{
  dirty = true;
  if (slot *s = db[e.key])
    sremove (s);
  // I'm removing this code because we want empty groups to appear in the
  // cache so we have their refresh and timeout information
  //if (e.values.empty ())
  //  return;
  for (const sfs_groupmember *gmp = e.values.base ();
       gmp < e.values.lim (); gmp++)
    u2gmap.insert (New ugslot (*gmp, e.key));
  db.insert (New slot (e));
}

void
dbcache_mem::write ()
{
  // perhaps we should take a snapshot of the _db so it
  // doesn't get updated while we're writing it out
  // OR fork() and write in the subprocess??

  if (!dirty)
    return;

  ptr<authcursor> ac;
  if (!cachedb
      || !(ac = cachedb->open (authdb::AUDB_WRITE
			       | authdb::AUDB_CREATE
			       | authdb::AUDB_TRUNC, 0600))) {
    warn << "dbcache::write: could not open dbcache\n";
    return;
  }


  for (slot *e = db.first (); e; e = db.next (e)) {
    ac->ae.set_type (SFSAUTH_CACHEENTRY);
    *ac->ae.cacheentry = *e;
    if (!ac->update ())
      warn << "dbcache::write: update failed\n";
  }

  if (!ac->commit ())
    warn << "dbcache::write: commit failed\n";
  else
    dirty = false;
}

void
dbcache_mem::read ()
{
  ptr<authcursor> ac;
  if (!cachedb
      || !(ac = cachedb->open (0, 0600))) {
    warn << "dbcache::read: could not open dbcache\n";
    return;
  }

  db.traverse (wrap (this, &dbcache_mem::sremove));
  ac->reset ();
  while (ac->next ()) {
    if (ac->ae.type != SFSAUTH_CACHEENTRY) {
      warn << "dbcache::read: ignorning non-cache entry\n";
      continue;
    }
    insert (*ac->ae.cacheentry);
  }
}
