#include "acldefs.h"

str get_emptyaclstr ()
{
  char emptyaclbuf[ACLSIZE];
  memset (emptyaclbuf, ' ', sizeof (emptyaclbuf));

  str aclbegin (BEGINACL);
  str aclend = (ENDACL);
  int endoffset = ACLSIZE - aclend.len();
  assert (endoffset > 0);

  memcpy (emptyaclbuf, aclbegin.cstr(), aclbegin.len());
  memcpy (emptyaclbuf + endoffset, aclend.cstr(), 
	  aclend.len());
  str emptyaclstr (emptyaclbuf, ACLSIZE);
  return emptyaclstr;
}

str get_strpermissions (u_int p)
{
  strbuf buf;

  if (p & SFSACCESS_READ)
    buf << "r";

  if (p & SFSACCESS_LIST)
    buf << "l";

  if (p & SFSACCESS_DELETE)
    buf << "d";

  if (p & SFSACCESS_INSERT)
    buf << "i";

  if (p & SFSACCESS_WRITE)
    buf << "w";

  if (p & SFSACCESS_LOCK)
    buf << "k";

  if (p & SFSACCESS_ADMINISTER)
    buf << "a";

  return buf;
}

u_int get_uintpermissions (str ps)
{
  u_int p = 0;
  if (ps / readrx)
    p |= SFSACCESS_READ;
  
  if (ps / listrx)
    p |= SFSACCESS_LIST;

  if (ps / deleterx)
    p |= SFSACCESS_DELETE;

  if (ps / insertrx)
    p |= SFSACCESS_INSERT;

  if (ps / writerx)
    p |= SFSACCESS_WRITE;

  if (ps / lockrx)
    p |= SFSACCESS_LOCK;

  if (ps / administerrx)
    p |= SFSACCESS_ADMINISTER;

  return p;
}

u_int 
sfs2nfsperms (u_int p, ftype3 type)
{
  //may not make much sense to have
  //LOOKUP/DELETE for NF3REG
  //or
  //READ/EXECUTE for NF3DIR

  u_int nfsperms = 0;

  switch (type) {
  case NF3REG: 
    {
      nfsperms = 
	(
	 (p & SFSACCESS_READ	? ACCESS3_READ		: 0) |
	 (p & SFSACCESS_WRITE	? ACCESS3_MODIFY	: 0) |
	 (p & SFSACCESS_WRITE	? ACCESS3_EXTEND	: 0) |
	 (p & SFSACCESS_READ	? ACCESS3_EXECUTE	: 0) |
	 (p & SFSACCESS_LIST   	? ACCESS3_LOOKUP	: 0) |
	 (p & SFSACCESS_DELETE 	? ACCESS3_DELETE	: 0) 
	 );     

      break;      
    } 
  case NF3DIR:
    {
      nfsperms = 
	(
	 (p & SFSACCESS_READ	? ACCESS3_READ		: 0) |
	 (p & SFSACCESS_READ	? ACCESS3_EXECUTE	: 0) |
	 (p & SFSACCESS_INSERT	? ACCESS3_EXTEND        : 0) |
	 (p & SFSACCESS_LIST    ? ACCESS3_LOOKUP	: 0) |
	 (p & SFSACCESS_DELETE	? ACCESS3_DELETE	: 0) |
	 ((p & SFSACCESS_INSERT) &&
	  (p & SFSACCESS_DELETE)? ACCESS3_MODIFY	: 0) 
	 );
      break;
    } 
  default: 
    nfsperms = 0;
  }
  
#if ACL_TEST
  warn ("SFS perms %#0x --> NFS perms: %0#x\n", p, nfsperms);
#endif

  return nfsperms;
}

//the mode bits that the remote user sees should not depend on whether
//he considers himself to be owner/group/other
//so when setting the bits based on the SFS acl, the perms for
//(owner, group, other) are set identically
u_int 
sfs2modebits (u_int p, ftype3 type)
{
  u_int r = NFSMODE_ROWN | NFSMODE_RGRP | NFSMODE_ROTH ;
  u_int w = NFSMODE_WOWN | NFSMODE_WGRP | NFSMODE_WOTH ;
  u_int x = NFSMODE_XOWN | NFSMODE_XGRP | NFSMODE_XOTH ;

  u_int modebits = 0;

  switch (type) {
  case NF3REG: 
    {
      modebits = 
	(
	 (p & SFSACCESS_READ	? 	r 	: 0) |
  //     (p & SFSACCESS_READ	? 	x	: 0) |
	 (p & SFSACCESS_WRITE	? 	w	: 0) 

	 );
      
      break;      
    } 
  case NF3DIR:
    {
      modebits = 
	(
	 (p & SFSACCESS_LIST	? 	r 	: 0) |
	 (p & SFSACCESS_INSERT	? 	w	: 0) |
	 (p & SFSACCESS_DELETE	? 	w	: 0) |
	 (p & SFSACCESS_LIST	? 	x	: 0) 
	 );
      break;      
    } 
  case NF3LNK:
    {
      modebits = r | w | x; 
      break;      
    } 
  default: 
    modebits = 0;
  }
  
#if ACL_TEST
  warn ("SFS perms %#0x --> NFS mode bits: %0#o\n", p, modebits);
#endif

  return modebits;
}
