#include "acltargetlist.h"
#include "acl.h"

//cache stuff
int acltargetlist::lastpos;
acltarget acltargetlist::aclcache[ACLCACHESIZE];

//when initialized, acltarget is "done"
//it ceases to be done when the objectfh is first set
//and becomes done again when we get the permissions (or error) 

acltarget::acltarget () :
  objectfhset (false), aclfhset (false), error (false), 
  resolved (true), aclstrset (false), invalid (false){
  expires = time (NULL) + 60*CACHEEXPMINS ;
}

acltarget::acltarget (const acltarget &t)
{
  objectfhset = t.objectfhset;
  if (objectfhset)
    objectfh = t.objectfh;

  aclfhset = t.aclfhset;
  if (aclfhset)
    aclfh = t.aclfh;
  
  error = t.error;
  resolved = t.resolved;
  aclstrset = t.aclstrset;
  if (aclstrset)
    memcpy (aclstrbuf, t.aclstrbuf, sizeof (aclstrbuf));
}

strbuf
acltarget::print ()
{
  strbuf buf;
  buf << "Is Entry Resolved? " << resolved<< " \nEntry Error? " << error
      << " \nEntry Aclfhset? " << aclfhset << "\n";
  if (aclfhset)
    buf << "\n The aclfh is set, the ACL contained herein is: \n"
	<< get_aclstr ();
  
  return buf;
}

fhtype 
acltarget::get_objecttype ()
{
  if (!objectfhset)
    warn << "acltarget: returning unspecified object type\n";
  
  return objectfhset ? object_type : not_set;
}

str 
acltarget::get_aclstr ()
{ 
#if ACL_TEST
  if (!aclstrset)
    warn << "\nTrying to get aclstr from entry, but aclstr is not set. \n"
	 << "Returning emptyaclstr () instead \nThis is BAD\n";
#endif

  return aclstrset ? str (aclstrbuf, sizeof (aclstrbuf)) : get_emptyaclstr (); 
}

void
acltarget::set_objecttype (fhtype t)
{
  switch (t) {
  case dir:
    object_type = t;
    break;
  case file:
    object_type = t;
    set_aclfh (&objectfh);
    break;
  case other:
    object_type = t;
    resolved = true; //nothing to resolve if not file/dir
    break;
  default:
    set_error ("acltarget: unsupported fhtype");
  }
}

void
acltarget::set_aclfh (nfs_fh3 *fh)
{
  aclfh = *fh;
  aclfhset = true;
}

void 
acltarget::set_error (str s) 
{
  set_error ();
  warn << "error: " << s << "\n";
}

void 
acltarget::set_aclstr (str s)
{
  resolved = true;
  aclstrset = true;

  assert (sizeof (aclstrbuf) == ACLSIZE);
  acl::fix_aclstr (s, aclstrbuf);
}

void 
acltarget::set_objectfh (nfs_fh3 *fh, fhtype type)
{
  if (!fh) {
    set_error ("acltarget::set_objectfh passed null file handle"); 
    return;
  }

  objectfh = *fh;
  object_type = type;
  objectfhset = true;
  resolved = false;

  if (type == file) 
    set_aclfh (fh);
}

bool
acltarget::match_fhp (nfs_fh3 *fhp)
{
  if (invalid || !objectfhset || !resolved || !has_aclstr ())
    return false;
  
  time_t now = time (NULL);
  return ((now < expires) && (*fhp == objectfh));
}

bool
acltarget::match_aclfhp (nfs_fh3 *fhp)
{
  if (invalid || !objectfhset || !resolved || !has_aclstr ())
    return false;
  
  time_t now = time (NULL);
  return ((now < expires) && (*fhp == aclfh));
}

// ******************** acltargetlist ************************

//must be created w/resolved = false

bool
acltargetlist::has_error ()
{
  return (error || (remaining_iterations () < 0) ||
	  first ()->has_error () || second ()->has_error ());
}

bool
acltargetlist::is_done () 
{
  return (has_error () || resolved || 
	  (first ()->is_done () && second ()->is_done ()));
}

acltargetlist::acltargetlist () :
  error (false), resolved (false), allowop (false), allowop_set (false),
  p1 (0), p1_set (false), p2 (0), p2_set (false), count (0) {}

strbuf
acltargetlist::print ()
{
  strbuf buf;
  buf << "Targets Error?: "<< error << "\nTargets resolved? "
      << resolved << "\nTargets Count? " << count << "\nFirst entry\n" 
      << first ()->print () << "\n";
  
  return buf;
}

//return the first entry which is not done
acltarget *
acltargetlist::next_entry ()
{
  if (is_done ()) 
    return NULL;
  else if (!first ()->is_done ()) 
    return first ();
  else if (!second ()->is_done ()) 
    return second ();
  else {
    warn << "in acltargetlist::next_entry returning NULL. Should be unreachable \n";
    return NULL;
  }
}

void 
acltargetlist::invalidate_centry (acltarget *e)
{
  nfs_fh3 *o = e->get_objectfhp ();
  nfs_fh3 *a = e->get_aclfhp ();
  
  for (int i = 0; i < ACLCACHESIZE ;i++) {
    if (aclcache[i].match_aclfhp (a)) {
      aclcache[i].invalidate ();
      warn << "Invalidating cache entry for aclfh (1) \n";
    }
    
    if (aclcache[i].match_fhp (o)) {
      aclcache[i].invalidate ();
      warn << "Invalidating cache entry for objfh (2)  \n";
    }
  }
}

bool 
acltargetlist::check_cache ()
{
#if ACL_TEST
  warn << "\n Checking cache .. \n";
#endif
  if (is_done ())
    return true;

  acltarget *entry = next_entry ();
  assert (entry);

  nfs_fh3 *fhp;
  if (!(fhp = entry->get_objectfhp ())) {
    warn << "Entry that needs to have its acl resolved doesn't have"
      <<" its FH pointer set.\n ^^^ shouldn't have happened \n";
    return false;
  }

  for (int i = 0; i < ACLCACHESIZE ;i++) {
    if (aclcache[i].match_fhp (fhp)){
      *entry = aclcache[i];
#if ACL_CACHETEST
      warn << "Using cached entry at position: "<< i <<"\n";
      //    << entry->print () << "\n"
      //  	     << "\n which should be the same as \n"
      //  	     << aclcache[i].print ();

#endif
      return true;
    }
  }

  return false; 
}

void
acltargetlist::insert_cache (acltarget *e)
{
  if (e && !(e->has_error ()) &&  e->has_aclstr ()) 
    lastpos = (lastpos + 1) % ACLCACHESIZE;
  aclcache[lastpos] = *e;
#if ACL_CACHETEST
  warn << "Inserting acl at cache position: " << lastpos << "\n";
#endif
}

void 
acltargetlist::set_allowop (bool v)
{
  allowop_set = true;
  allowop = v; 
}

bool 
acltargetlist::get_allowop ()
{
  if (!allowop_set)
    warn << "Returning default value of allowop \n";
  return allowop;
}
