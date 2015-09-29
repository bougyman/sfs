// -*-c++-*- /* $Id: dbrec2str.C,v 1.27 2004/06/17 21:10:23 dm Exp $ */

/*
 *
 * Copyright (C) 2001 David Mazieres (dm@uun.org)
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

/*
 * Converts users to/from the following text representation:
 *   USER:name:uid:version:gid:owner:pubkey:privs:srp:privkey:srvprivkey:audit
 *
 * Converts groups to/from the following:
 *   GROUP:name:gid:version:owners:members:properties:audit
 *
 * Converts cache entries to/from the following:
 *   CACHE:remote user name:pkhash:refresh:timeout:last_update
 *   CACHE:remote group name:user1,pkhash1,...:refresh:timeout:last_update
 * 
 */

#include "authdb.h"
#include "wmstr.h"
#include "serial.h"
#include "rxx.h"
#include "parseopt.h"
#include "sfsschnorr.h"

#define AUTHNAME "[A-Za-z][\\-\\w\\./]{0,31}"
#define MEMBERNAME "[\\-\\+]?[ugp]=[\\w,\\$@\\.\\-]{0,255}"
#define BADCHAR "\\x00-\\x1f\\x7f-\\xff:"

static rxx namerx (AUTHNAME);
static rxx memberrx (MEMBERNAME);
static rxx colon (":");
static rxx comma (",");
static rxx commaplus (",+");
static rxx srprx ("SRP,N=(0x[\\da-f]+),g=(0x[\\da-f]+),"
		  "s=(\\d+\\$[A-Za-z0-9+/]+={0,2}\\$[\\w\\.\\-]*),"
		  "v=(0x[\\da-f]+)");
static rxx nobadrx ("[^"BADCHAR"]*");
static rxx badcharrx ("(["BADCHAR"])");
static rxx hexrx ("0x[\\da-fA-F]+");
static rxx decrx ("\\d+");

void err_report (int i, str d, str v);

static bool
printmember (strbuf &sb, sfs_groupmember name)
{
  if (!memberrx.match (name))
    return false;
  sb << single_char_sub (name, ',', "$");
  return true;
}
static bool
parsemember (sfs_groupmember *name, str s)
{
  if (!memberrx.match (s))
    return false;
  *name = single_char_sub (s, '$', ",");
  return true;
}

#if 0
static bool
printname (strbuf &sb, sfs_idname name)
{
  if (!namerx.match (name))
    return false;
  sb << name;
  return true;
}
static bool
parsename (sfs_idname *name, str s)
{
  if (!namerx.match (s))
    return false;
  *name = s;
  return true;
}
static bool
printnum (strbuf &sb, u_int32_t num)
{
  sb.fmt ("%u", num);
  return true;
}
static bool
parsenum (u_int32_t *nump, str s)
{
  return convertint (s, nump);
}
#endif

template<class T, size_t N> static bool
printlist (strbuf &sb, const rpc_vec<T, N> &v, bool (*printfn) (strbuf &, T))
{
  bool first = true;
  for (const T *tp = v.base (); tp < v.lim (); tp++) {
    if (first)
      first = false;
    else
      sb << ",";
    if (!printfn (sb, *tp))
      return false;
  }
  return true;
}

template<class T, size_t N> static bool
parselist (rpc_vec<T, N> *vp, str s, bool (*parsefn) (T *, str))
{
  vec<str> sv;
  split (&sv, commaplus, s);
  if (!sv.empty () && !sv.front ().len ())
    sv.pop_front ();
  if (!sv.empty () && !sv.back ().len ())
    sv.pop_back ();
  vp->setsize (sv.size ());
  for (size_t i = 0; i < vp->size (); i++)
    if (!parsefn (&(*vp)[i], sv[i]))
      return false;
  return true;
}

str
single_char_sub (const str &in, const char find, const str &repl)
{
  const char *cp = in.cstr ();
  int len = in.len ();
  int segstart = 0;
  int seglen = 0;
  strbuf sb;

  for (int i = 0; i < len ; i++) {
    if (cp[i] == find) {
      if (seglen) sb << substr (cp, segstart, seglen);
      sb << repl;
      seglen = 0;
      segstart = i + 1;
    } else {
      seglen ++;
    }
  }
  if (seglen)
    sb << substr (cp, segstart, seglen);
  
  return sb;
}

static bool
userinfo2str (strbuf &sb, const sfsauth_userinfo *ui)
{
  str audit = single_char_sub (ui->audit, ':', ".");

  if (!namerx.match (ui->name) ||
      (ui->owner && !namerx.match (*ui->owner)) ||
      !nobadrx.match (ui->privs) ||
      badcharrx.search (ui->pwauth) ||
      badcharrx.search (audit)) 
    return false;

  sb << ui->name;
  sb.fmt (":%u:%u:%u:", ui->id, ui->vers, ui->gid);
  if (ui->owner)
    sb << *ui->owner;
  sb << ":";
  ptr<sfspub> pk = sfscrypt.alloc (ui->pubkey);
  if (!pk)
    return false;
  pk->export_pubkey (sb);
  
  sb << ":" << ui->privs << ":" << ui->pwauth << ":";
  str priv = str2wstr (armor64 (ui->privkey.base (), ui->privkey.size()));
  sb << priv << ":";
  sfs_2schnorr_priv::export_keyhalf (ui->srvprivkey, sb);
  // sb << ":" << ui->refresh << ":" << ui->timeout;
  sb << ":" << audit;
  return true;
}

bool
groupinfo2str (strbuf &sb, const sfsauth_groupinfo *gi)
{
  str audit = single_char_sub (gi->audit, ':', ".");

  if (!namerx.match (gi->name)
      || badcharrx.search (audit)
      || !nobadrx.match (gi->properties))
    return false;
  sb << gi->name;
  sb.fmt (":%u:%u:", gi->id, gi->vers);
  if (!printlist (sb, gi->owners, printmember))
    return false;
  sb << ":";
  if (!printlist (sb, gi->members, printmember))
    return false;
  // sb << ":" << gi->refresh << ":" << gi->timeout;
  sb << ":" << gi->properties;
  sb << ":" << audit;
  return true;
}

bool
cacheentry2str (strbuf &sb, const sfsauth_cacheentry *ci)
{
  sb << single_char_sub (ci->key, ',', "$") << ":";
  if (!printlist (sb, ci->values, printmember))
    return false;
  sb << ":" << ci->vers
     << ":" << ci->refresh
     << ":" << ci->timeout
     << ":" << ci->last_update;
  return true;
}

bool
logentry2str (strbuf &sb, const sfsauth_logentry *li)
{
  str audit = single_char_sub (li->audit, ':', ".");

  sb.fmt ("%u:", li->vers);
  if (!printlist (sb, li->members, printmember))
    return false;
  sb << ":" << audit;
  return true;
}

str
authdbrec2str (const sfsauth_dbrec *dbr)
{
  strbuf sb;
  switch (dbr->type) {
  case SFSAUTH_REVINFO:
    return strbuf ("REVINFO:")
      << hexdump (dbr->revinfo->dbid.base (), dbr->revinfo->dbid.size ())
      << ":" << strbuf ("%qu", dbr->revinfo->dbrev);
  case SFSAUTH_USER:
    sb << "USER:";
    if (userinfo2str (sb, dbr->userinfo)) {
      str s (sb);
      return str2wstr (s);
    }
    return NULL;
  case SFSAUTH_GROUP:
    sb << "GROUP:";
    if (groupinfo2str (sb, dbr->groupinfo))
      return sb;
    return NULL;
  case SFSAUTH_CACHEENTRY:
    sb << "CACHE:";
    if (cacheentry2str (sb, dbr->cacheentry))
      return sb;
    return NULL;
  case SFSAUTH_LOGENTRY:
    sb << "LOG:";
    if (logentry2str (sb, dbr->logentry))
      return sb;
    return NULL;
  default:
    return NULL;
  }
}

void
err_report (const str &name, int fieldno, const str &desc, str val)
{
  warn << "Name " << name << ", " <<
  warn << "Field " << fieldno 
       << ": '" << desc 
       << "': Bad value: " << val << "\n";
}

bool
str2userinfo (sfsauth_userinfo *ui, str s)
{
  str name;
  vec<str> uv;
  if (split (&uv, colon, s, 12, true) != 11)
    return false;
  str2wstr (uv[7]);
  str2wstr (uv[8]);
  str fields[13] = { "name", "uid", "version", "gid", "owner",
		     "pubkey", "privs", "srp", "privkey", 
		     "srvprivkey", // "refresh", "timeout",
		     "audit" };

  if (!namerx.match (uv[0])) {
    err_report ("<null>", 1, fields[0], uv[0]);
    return false;
  }
  name = uv[0];

  for (int i = 1; i < 4; i++) {
    if (!decrx.match (uv[i])) {
      err_report (name, i+1, fields[i], uv[i]);
      return false;
    }
  }
  if (uv[4].len () && !namerx.match (uv[4])) {
    err_report (name, 5, fields[4], uv[4]);
    return false;
  }
  for (int i = 6; i < 10; i++) {
    if (badcharrx.search (uv[i])) {
      err_report (name, i+1, fields[i], uv[i]);
      return false;
    }
  }
#if 0
  for (int i = 10; i < 12; i++) {
    if (!decrx.match (uv[i])) {
      err_report (name, i+1, fields[i], uv[i]);
      return false;
    }
  }
#endif

  str privkey = dearmor64 (uv[8]);
  if (!privkey) {
    err_report (name, 9, fields[8], "could not dearmor64");
    return false;
  }
  str2wstr (privkey);
  ui->privkey.setsize (privkey.len ());
  memcpy (ui->privkey.base (), privkey, ui->privkey.size ());

  ui->name = uv[0];
  if (!convertint (uv[1], &ui->id)
      || !convertint (uv[2], &ui->vers)
      || !convertint (uv[3], &ui->gid)
      // || !convertint (uv[10], &ui->refresh)
      // || !convertint (uv[11], &ui->timeout)
      )
    return false;
  if (uv[4].len ())
    *ui->owner.alloc () = uv[4];
  else
    ui->owner.clear ();

  ptr<sfspub> pk = sfscrypt.alloc (uv[5]);
  if (!pk)
    return false;

  if (!pk->export_pubkey (&ui->pubkey)) {
    warn << "Cannot load keypair for " << uv[0] << "\n";
    return false;
  }

  ui->privs = uv[6];
  ui->pwauth = uv[7];
  if (uv[9] && uv[9].len ()) {
    if (!sfs_2schnorr_priv::parse_keyhalf (&ui->srvprivkey, uv[9])) {
      warn << "Cannot load server keyhalf for " << uv[0] << "\n";
      return false;
    }
  } else {
    ui->srvprivkey.set_type (SFSAUTH_KEYHALF_NONE);
  }
  // ui->audit = uv[12];
  ui->audit = uv[10];
  return true;
}

bool
str2groupinfo (sfsauth_groupinfo *gi, str s)
{
  vec<str> gv;
  if (split (&gv, colon, s, 8, true) != 7)
    return false;
  if (!namerx.match (gv[0])
      || badcharrx.search (gv[5]))
    return false;
  gi->name = gv[0];
  if (!convertint (gv[1], &gi->id)
      || !convertint (gv[2], &gi->vers)
      || !parselist (&gi->owners, gv[3], parsemember)
      || !parselist (&gi->members, gv[4], parsemember)
      // || !convertint (gv[5], &gi->refresh)
      // || !convertint (gv[6], &gi->timeout)
      )
    return false;
  gi->properties = gv[5];
  gi->audit = gv[6];
  // gi->audit = gv[7];
  return true;
}

bool
str2cacheentry (sfsauth_cacheentry *ci, str s)
{
  vec<str> cv;
  if (split (&cv, colon, s, 7, true) != 6)
    return false;
  ci->key = single_char_sub (cv[0], '$', ",");
  if (!parselist (&ci->values, cv[1], parsemember)
      || !convertint (cv[2], &ci->vers)
      || !convertint (cv[3], &ci->refresh)
      || !convertint (cv[4], &ci->timeout)
      || !convertint (cv[5], &ci->last_update))
    return false;
  return true;
}

bool
str2logentry (sfsauth_logentry *li, str s)
{
  vec<str> lv;
  if (split (&lv, colon, s, 4, true) != 3)
    return false;
  if (!convertint (lv[0], &li->vers)
      || !parselist (&li->members, lv[1], parsemember))
    return false;
  li->audit = lv[2];
  return true;
}

bool
str2authdbrec (sfsauth_dbrec *dbr, str s)
{
  static rxx _userrx ("^USER:(.*)$");
  rxx userrx (_userrx);
  static rxx grouprx ("^GROUP:(.*)$");
  static rxx cacherx ("^CACHE:(.*)$");
  static rxx logrx ("^LOG:(.*)$");
  static rxx revinfo ("^REVINFO:([0-9a-fA-F]+):(\\d+)$");

  if (revinfo.match (s)) {
    str id = hex2bytes (revinfo[1]);
    u_int64_t rev;
    if (!id || id.len () != sizeof (dbr->revinfo->dbid)
	|| !convertint (revinfo[2], &rev))
      return false;
    dbr->set_type (SFSAUTH_REVINFO);
    dbr->revinfo->dbrev = rev;
    memcpy (dbr->revinfo->dbid.base (), id, id.len ());
    return true;
  }
  else if (userrx.match (s)) {
    dbr->set_type (SFSAUTH_USER);
    return str2userinfo (dbr->userinfo, str2wstr (userrx[1]));
  }
  else if (grouprx.match (s)) {
    dbr->set_type (SFSAUTH_GROUP);
    return str2groupinfo (dbr->groupinfo, grouprx[1]);
  }
  else if (cacherx.match (s)) {
    dbr->set_type (SFSAUTH_CACHEENTRY);
    return str2cacheentry (dbr->cacheentry, cacherx[1]);
  }
  else if (logrx.match (s)) {
    dbr->set_type (SFSAUTH_LOGENTRY);
    return str2logentry (dbr->logentry, logrx[1]);
  }
  else
    return false;
}
