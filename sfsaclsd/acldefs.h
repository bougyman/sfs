#ifndef _SFSRWSD_ACLDEFS_H_
#define _SFSRWSD_ACLDEFS_H_ 1
#include "nfs3_prot.h"

#define SFSDIRACL ".SFSACL"
#define BEGINACL "ACLBEGIN"
#define ENDACL "ACLEND"
#define ACLOFFSET 0
#define ACLSIZE 512
#define MAXRECURSE 3 
#define ACLDIV ":"
#define TYPEPK "pk"
#define TYPELOCALUSER "user"
#define TYPELOCALGROUP "group"
#define TYPESYS "sys"
#define SYS_ANYUSER "anyuser"
#define SYS_ANONYMOUS "anonymous"
#define CREATEACL_MODE 0x0180		//experimental! -rw-------
#define CREATEUMASK 077			//experimental! -rw-------
#define ACL_TEST 0			//redefine later!
#define ACL_FURTHERTEST 0		//redefine later!
#define ACL_CACHETEST 0			//redefine later!
#define ACL_SETFS 0			//redefine later!
#define ACL_CACHE 1			//remove if you don't want cache
#define PCACHE 1			//remove if you don't want perms cache
#define ACLCACHESIZE 500
#define PCACHESIZE 500
#define CACHEEXPMINS 60

#include "str.h"
#include "rxx.h"

#define ANYPERMS TYPESYS ACLDIV SYS_ANYUSER ":rl" ACLDIV
#define SFSOWNER "sfs"

#define SFSACCESS_NONE       0x00
#define SFSACCESS_READ       0x01
#define SFSACCESS_LIST       0x02
#define SFSACCESS_INSERT     0x04
#define SFSACCESS_DELETE     0x08
#define SFSACCESS_WRITE      0x10
#define SFSACCESS_LOCK       0x20
#define SFSACCESS_ADMINISTER 0x40
#define SFSACCESS_ALL        0x7F

#define NFSMODE_SUID 0x00800
#define NFSMODE_SGID 0x00400 
#define NFSMODE_SSW  0x00200 
#define NFSMODE_ROWN 0x00100 
#define NFSMODE_WOWN 0x00080 
#define NFSMODE_XOWN 0x00040 
#define NFSMODE_RGRP 0x00020 
#define NFSMODE_WGRP 0x00010 
#define NFSMODE_XGRP 0x00008 
#define NFSMODE_ROTH 0x00004 
#define NFSMODE_WOTH 0x00002 
#define NFSMODE_XOTH 0x00001 

static rxx allpermsrx   ("[rldiwka]+");
static rxx readrx       ("r");  
static rxx listrx       ("l");  
static rxx deleterx     ("d");  
static rxx insertrx     ("i");  
static rxx writerx      ("w");  
static rxx lockrx       ("k");  
static rxx administerrx ("a");	

u_int get_uintpermissions (str ps);
str get_strpermissions (u_int p); //does the reverse
str get_emptyaclstr ();
u_int sfs2nfsperms (u_int p, ftype3 type);
u_int sfs2modebits (u_int p, ftype3 type);

#endif /* _SFSRWSD_ACLDEFS_H_ */
