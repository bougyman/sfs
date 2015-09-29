#include "acl.h"
#include "acldefs.h"
#include "grp.h"

extern int acl::lastpos;
extern pcache_entry acl::pcache[PCACHESIZE];

static rxx colon (":");

bool
pcache_entry::match_key (const char *h, u_int &p)
{
  if (!key_set) 
   return false;

  if (!memcmp (h, hashbuf, sizeof (hashbuf))) {
    p = perms;
    return true;
  }
  
  return false;
}

bool
pcache_entry::set (const char *h, u_int p)
{
  //copy h -> hashbuf
  bzero (hashbuf, sizeof (hashbuf));
  memcpy (hashbuf, h, sizeof (hashbuf));
  warn << "Setting cache entry perms (" 
       << get_strpermissions (p) << ") for key "
       << armor32 (str (h, sizeof (hashbuf))) << "\n";
  perms = p;
  key_set = true;
  return true; 
}

void
acl::insert_cache (const char *u, u_int p)
{
  lastpos = (lastpos + 1) % PCACHESIZE;
  if (pcache[lastpos].set (u, p)) {
#if ACL_CACHETEST
    warn << "Inserting cache permissions for key "
      << armor32 (str (u, sizeof (hashbuf))) 
      << "\nat cache position " << lastpos << "\n";
#endif
  } else
    warn << "Failed to cache permissions for key " 
      << armor32 (str (u, sizeof (hashbuf))) << "\n";
}

aclline::aclline (str s) 
  : _parsed_ok (false)
{
  vec<str> v;
  if (split (&v, colon, s, 5, true) != 4)
    return;
  if (!allpermsrx.match (v[2]))
    return;

  type = v[0];
  entry = v[1];
  permstr = v[2];
  _parsed_ok = true;

  permissions = get_uintpermissions (permstr);

#if ACL_TEST
  print ();
#endif
}

str
aclline::print ()
{
  return strbuf () << "\nExamining ACL line :\n " 
		   << type << ACLDIV << entry << ACLDIV
		   << permstr << "(" << permissions << ")\n";
}

bool
aclline::is_member (vec<str> &credstrings)
{
  // XXX: kaminsky - right now ANONYMOUS and ANYUSER are the same
  if (type == TYPESYS && (entry == SYS_ANYUSER || entry == SYS_ANONYMOUS)) 
    return true;

  if (type == TYPEPK || type == TYPELOCALUSER || type == TYPELOCALGROUP) {
    for (u_int i = 0; i < credstrings.size (); i++) {
      vec<str> cv;
      if (split (&cv, colon, credstrings[i], 3, true) != 2)
	return false;
      if (cv[0] == type && cv[1] == entry)
	return true;
    }
    return false;
  }

  return false;
}

// ******* class ACL  ******************************

acl::acl (str s)
  : aclstr (s)
{
  assert (aclstr);
  bzero (hashbuf, sizeof (hashbuf));   
  bzero (aclhash, sizeof (aclhash));   
  sha1_hash (aclhash, aclstr.cstr (), aclstr.len ());
}

void
acl::fix_aclstr (str s, char *buf)
{
  char sbuf[ACLSIZE];
  int min = (ACLSIZE > s.len ()) ? s.len () : ACLSIZE;
  bzero (buf, ACLSIZE);
  bzero (sbuf, ACLSIZE);
  
  memcpy (sbuf, s.cstr (), min);

  str aclend (ENDACL "\n");
  int tail = aclend.len ();
  char *c = strstr (sbuf, ENDACL);
  int p = c ? c - sbuf : 0;

  int total = p ? p + tail : s.len () + tail;
  if (!p)
    warn << "ACLEND not found in ACL \n";
  
  if (total <= ACLSIZE) {
    memcpy (buf, s.cstr (), p);
    memcpy (buf + p, aclend.cstr (), aclend.len ());
    return;
  }

  if (total > ACLSIZE) {
    if (p)
      warn << "ACLEND found at position " << p << "\n";
    else
      warn << "ACLEND not found in ACL \n";

    warn << "ACL does not fit in buffer. Truncating \n";
    if ( p && p < (ACLSIZE - tail)) {
      warn << "Removing garbage after ACLEND \n";
      memcpy (buf, s.cstr (), p);
      memcpy (buf + p, aclend.cstr (), aclend.len ());
      return;
    }
    else {
      memcpy (buf, s.cstr (), ACLSIZE - tail);
      memcpy (buf + ACLSIZE - tail, aclend.cstr (), tail);
      return;
    }
  }
}

bool
acl::is_cached (const char *k, u_int &p)
{
  for (int i = 0; i < PCACHESIZE; i++) {
    if (pcache[i].match_key (k, p)){
      return true;
    }
  }
  return false;
}

u_int
acl::parse_acl (vec<str> &credstrings)
{
  str line;
  strbuf aclstrbuf = aclstr;
  suio *aclsuio = aclstrbuf.tosuio ();
  
  bool aclbegin = false;
  bool aclend = false; 
  u_int p = 0;

  while (!aclbegin && (line = suio_getline (aclsuio))) {
    if (line == BEGINACL) {
      aclbegin = true;
      break;
    }
    else
      warn << "Beginning of acl not yet found: " << line << "\n";
  }

  if (!aclbegin) {
    warn << "Couldn't find ACLBEGIN: \n" << aclstr << "\n";
    return 0;
  }
    
  //beginning found
  while ((line = suio_getline (aclsuio)) && !aclend) {
    if (line == ENDACL) {
      aclend = true;
      break;
    }
    else { 
      if (line.len () == 0)
	continue;

      aclline aline (line);
      if (!aline.parsed_ok ()) {
	warn << "Malformed acl line ignored: " << line << "\n";
	continue; 
      }

      if (aline.has_more (p)) {
	if (aline.is_member (credstrings))
	  p |= aline.get_permissions ();
      }
    }
  }

  if (!aclend) {
    warn << "Couldn't find ACLEND: \n" << aclstr << "\n";
    return 0;
  }

  return p;
}

u_int 
acl::get_permissions (sfsauth_cred *cred, str *key,
                      vec<sfs_idname> *groups)
{
  vec<str> credstrings;
  u_int p = 0;

  // 3 kinds of access: anonymous, public key, unix credentials
  // anonymous means that the user wasn't running an agent or
  // for some reason the authd couldn't even return a public key
  if (key)
    credstrings.push_back (strbuf () << TYPEPK << ACLDIV << *key); 
  if (cred)
    credstrings.push_back (strbuf () << TYPELOCALUSER << ACLDIV << cred->unixcred->username);
  if (groups) {
    for (unsigned int i = 0; i < groups->size (); i++)
      credstrings.push_back (strbuf () << TYPELOCALGROUP << ACLDIV << (*groups)[i]);
  }
  if (!cred && !key)
    credstrings.push_back (strbuf () << TYPESYS << ACLDIV << SYS_ANONYMOUS);

  str flattened_creds ("");
  for (u_int i = 0; i < credstrings.size (); i++) {
    warn ("CRED[%d]: %s\n", i, credstrings[i].cstr ());
    flattened_creds = strbuf () << flattened_creds << credstrings[i];
  }

#if PCACHE
  //make hash out of acl and user; ask cache about hash
  str ua = strbuf () << armor32 (str (aclhash, sizeof (aclhash)))
		     << flattened_creds;
  bzero (hashbuf, sizeof (hashbuf));
  sha1_hash (hashbuf, ua.cstr (), ua.len ());

  if (is_cached (hashbuf, p)) {
    warn << "Using cached perms (" << get_strpermissions (p)
      << ") for cache key "<< armor32 (str (hashbuf, sizeof (hashbuf)))
      << "\n";
    return p;
  } 
  else {
    warn << "Did not find cached perms (" << ua << ") for cache key "
      << armor32 (str (hashbuf, sizeof (hashbuf))) << "\n";
  }
#endif

  p = parse_acl (credstrings);

#if PCACHE
  insert_cache (hashbuf, p);
#endif

  return p;
}
