/* $Id: client.C,v 1.17 2004/09/19 22:02:25 dm Exp $ */

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
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

#include "sfsaclsd.h"
#include "acldefs.h"
#include <grp.h>

ihash<const u_int64_t, client, &client::generation, &client::glink> clienttab;
vec<str> keytab;
vec<vec<sfs_idname> > groupstab;

u_int64_t
client::nextgen ()
{
  static u_int64_t g;
  while (clienttab[++g] || !g)
    ;
  return g;
}

client::client (ref<axprt_crypt> x)
  : sfsserv (x), fsrv (NULL), generation (nextgen ())
{
  nfssrv = asrv::alloc (x, ex_nfs_program_3,
			wrap (mkref (this), &client::nfs3pre_acl_dispatch));
  nfscbc = aclnt::alloc (x, ex_nfscb_program_3);

  char sfs_owner[] = SFSOWNER;
  struct passwd *pw = getpwnam (sfs_owner);
  
  int u_sfs = pw->pw_uid;  
  int g_sfs = pw->pw_gid; 
  int g_sock = pw->pw_gid; //fixme: put something different!
  int g_fifo = pw->pw_gid; //likewise

  auth_sfs = authunix_create ("localhost", u_sfs, g_sfs, 0, NULL);
  auth_sfssock = authunix_create ("localhost", u_sfs, g_sock, 0, NULL);
  auth_sfsfifo = authunix_create ("localhost", u_sfs, g_fifo, 0, NULL);

  clienttab.insert (this);
}

client::~client ()
{
  clienttab.remove (this);
}

void
client::sfs_getfsinfo (svccb *sbp)
{
  if (fsrv)
    sbp->replyref (fsrv->fsinfo);
  else
    sbp->reject (PROC_UNAVAIL);
}

ptr<sfspriv>
client::doconnect (const sfs_connectarg *ci, sfs_servinfo *si)
{
  fsrv = defsrv;
  *si = fsrv->servinfo;
  return fsrv->privkey;
}

void
client_accept (ptr<axprt_crypt> x)
{
  if (!x)
    fatal ("EOF from sfssd\n");
  client::launch (x);
}

u_int32_t
client::authalloc (const sfsauth_cred *cp, u_int n)
{
  u_int authno = sfsserv::authalloc (cp, n);

  if (keytab.size () <= authno)
    keytab.setsize (authno + 1);
  for (u_int i = 0; i < n; i++) {
    const sfsauth_cred &c = cp[i];
    if (c.type == SFS_PKCRED) {
      if (!authno) {
	warn << "saw user credentials without any UNIXCRED\n";
	if (!(authno = authnoalloc ()))
	  return 0;
	if (keytab.size () <= authno)
	  keytab.setsize (authno + 1);
      }
      warn << "saw user credentials (SFS_PKCRED)\n";
      keytab[authno] = *c.pkhash;
      break;
    }
  }

  if (groupstab.size () <= authno)
    groupstab.setsize (authno + 1);
  for (u_int i = 0; i < n; i++) {
    const sfsauth_cred &c = cp[i];
    if (c.type == SFS_GROUPSCRED) {
      if (!authno) {
	warn << "saw user credentials without any UNIXCRED\n";
	if (!(authno = authnoalloc ()))
	  return 0;
	if (groupstab.size () <= authno)
	  groupstab.setsize (authno + 1);
      }
      warn << "saw user credentials (SFS_GROUPSCRED)\n";
      groupstab[authno].setsize (c.groups->size ());
      for (unsigned int i = 0; i < c.groups->size (); i++)
	groupstab[authno][i] = (*c.groups)[i];
      break;
    }
  }

  return authno;
}

void
client::authfree (size_t n)
{
  keytab[n] = NULL;
  groupstab[n].clear ();  // XXX: is this the correct deletion?
  sfsserv::authfree (n);
}

//the original nfs3dispatch function has been broken into two:
// nfs3pre_acl_dispatch and nfs3post_acl_dispatch
//in between, the ACL is checked and all relevant data collected
//in acltargetlist *targets (basically serves to carry state)

void
client::nfs3pre_acl_dispatch (svccb *sbp)
{
  if (!sbp) {
    fail ();
    return;
  }
  if (sbp->proc () == NFSPROC3_NULL) {
    sbp->reply (NULL);
    return;
  }

  //will never use authtab
  //changed from authtab to credtab-- and keytab (kaminsky)
  //removed !credtab[authno] from tests (generated compiler errors)
  u_int32_t authno = sbp->getaui ();
  if (authno >= credtab.size ()
      && authno >= keytab.size ()
      && authno >= groupstab.size ()) {
    sbp->reject (AUTH_REJECTEDCRED);
    return;
  }
  if (!fsrv) {
    nfs3exp_err (sbp, NFS3ERR_BADHANDLE);
    return;
  }

  filesrv::reqstate rqs;
  ptr<acltargetlist> targets = New refcounted<acltargetlist>;

  if (sbp->proc () == ex_NFSPROC3_GETACL ||
      sbp->proc () == ex_NFSPROC3_SETACL) {
    manipulate_acl_dispatch (sbp, rqs, targets);
  } else {
    if (!fsrv->fixarg (sbp, &rqs)) {
      warn << "failed to fixarg\n";
      return;
    }

    //All of the above same as 1st "half" of the original function
    //Below, determine & evaluate the ACL of the target and move to the 
    // "second half"

    if (!fix_targets (sbp, targets)) {
      warn << "Failed to fix targets \n";
      reject_request (sbp, targets, SYSTEM_ERR);
      return;
    }

    //if all goes well... 
    aclresolve (sbp, rqs, targets); 
  }
}

void
client::fail ()
{
  nfssrv = NULL;
  nfscbc = NULL;
}

void
client::manipulate_acl_dispatch (svccb *sbp, filesrv::reqstate rqs,
				 ptr <acltargetlist> targets)
{
  assert (sbp->proc () == ex_NFSPROC3_GETACL ||
	  sbp->proc () == ex_NFSPROC3_SETACL);
  
  bool g = sbp->proc () == ex_NFSPROC3_GETACL;

  if (!fsrv->acl_fixarg (sbp, &rqs)) {
    warn << "failed to fixarg\n";
    return;
  }
  
  lookup3res *lres = New lookup3res;
  diropargs3 *args = g ?
    sbp->Xtmpl getarg<diropargs3> () :
    &sbp->Xtmpl getarg<setaclargs> ()->dargs; 
    
  rqs.c->call (NFSPROC3_LOOKUP, args, lres,
	       wrap (mkref (this), &client::manipulate_acl_dispatch_cb, 
		     sbp, rqs, lres, targets), 
	       auth_sfs);
}

void 
client::manipulate_acl_dispatch_cb (svccb *sbp, filesrv::reqstate rqs, 
				 lookup3res *lres, 
				 ptr <acltargetlist> targets, clnt_stat err)
{
  if (err || lres->status) {
    warn << "Failed to get FH of file/dir for which ACL was requested \n";
    delete lres;
    reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT);	     
    return;
  }

  assert (targets);
  acltarget *t1 = targets->first ();

  //LOOKUP response gives us the actual fh of the file/dir
  //whose acl we want to see. Set it as the first target
  //and have the aclresolve mechanism figure out what the acl is
  //Since the LOOKUP response (probably) contains attributes,
  //we can save a couple of calls when resolving the ACL by
  //specifying ahead of time what kind of beast (file, dir, etc)
  //that fh corresponds to 
  
  nfs_fh3 fh = lres->resok->object;
  if (lres->resok->obj_attributes.present) {
    ftype3 type =  lres->resok->obj_attributes.attributes->type;
    switch (type){
    case NF3REG:
    case NF3SOCK:
    case NF3FIFO:
      t1->set_objectfh (&fh, file);
      break;
    case NF3DIR: 
      t1->set_objectfh (&fh, dir);
      break;
    default:
      {
	warn << "\nObject is not "
	     << "file, dir, socket, fifo. No ACL available\n";
	delete lres;
	reject_nfs (sbp, targets, NFS3ERR_NOTSUPP);	   
	return;
      }
    }
  } else
      t1->set_objectfh (&fh, unknown);
  
  delete lres;
  aclresolve (sbp, rqs, targets);
}


//for acl manipulation only
void
client::process_aclrequest (svccb *sbp, filesrv::reqstate rqs, 
			       ptr<acltargetlist> targets)
{
  assert (targets);

  assert (sbp->proc () == ex_NFSPROC3_GETACL ||
	  sbp->proc () == ex_NFSPROC3_SETACL);
  
  bool g = (sbp->proc () == ex_NFSPROC3_GETACL) ;

  bool allowop = targets->get_allowop ();

  if (!allowop) {
    assert (!g); //always be able to view the acl
    warn << "Process ACL: Permission denied! \n";
    reject_nfs (sbp, targets, NFS3ERR_ACCES); 
    return;
  }

  acltarget *entry = targets->first ();
  assert (entry);
  if (!entry->aclfh_known ()) {
    warn << "Process ACL: Couldn't not get FH for object's ACL\n";
    reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT);
    return;
  }

  if (g) {
    read3args args;
    
    args.file = *entry->get_aclfhp ();
    args.offset = ACLOFFSET; //0
    args.count = ACLSIZE;  //512
    
    read3res *res = New read3res; 
    rqs.c->call (NFSPROC3_READ, &args, res, 
		 wrap (mkref (this), &client::getacl_reply, sbp,
		       res, rqs, targets),
		 auth_sfs);
    
  } //end getacl case, begin setacl case
  else {
    write3args win = sbp->Xtmpl getarg<setaclargs> ()->wargs;

    str s (win.data.base (), win.data.size ());
    char buf[ACLSIZE];
    acl::fix_aclstr (s, buf);
    
    write3args wargs;
    write3res *wres = New write3res; 

    wargs.file = *entry->get_aclfhp ();
    wargs.offset = ACLOFFSET;
    wargs.count = sizeof (buf);
    wargs.stable = DATA_SYNC;
    wargs.data.setsize (sizeof (buf));
    memcpy (wargs.data.base (), buf, sizeof (buf));
  
  
    rqs.c->call (NFSPROC3_WRITE, &wargs, wres, 
		 wrap (mkref (this), &client::setacl_reply, sbp,
		       wres, rqs, targets),
		 auth_sfs);
  } //end setacl case
}

//gets called after acls have been resolved 
//calls get_aclpermissions to get the associated permissions
//and then calls decide_access to see whether perms are sufficient
//for this type of request. After decision has been made, calls
//nfs3post_decision_dispatch
void
client::nfs3post_acl_dispatch (svccb *sbp, filesrv::reqstate rqs, 
			       ptr<acltargetlist> targets)
{
  assert (targets);
  assert (targets->is_done ());
  if (!get_aclpermissions (sbp, rqs, targets)) {
    //	  warn << "nfs3post_acl_dispatch: couldn't get perms. "
    //	   << "Setting perms to 0 \n";
    targets->set_p1 (0);
    targets->set_p2 (0);
  }

  decide_access (sbp, targets);

  //for manipulating ACL only
  if (sbp->proc () == ex_NFSPROC3_GETACL ||
      sbp->proc () == ex_NFSPROC3_SETACL) {
    process_aclrequest (sbp, rqs, targets);
    return;
  }
  else
    nfs3post_decision_dispatch (sbp, rqs, targets);
}

//makes sure decision is positive
//adjusts args: 
//offset [read/write requests]
//size [setattr for files only]
//apply UMASK to sattr3.mode 
//sends the request to the NFS server
//reply goes to pre_nfs3reply
void
client::nfs3post_decision_dispatch (svccb *sbp, filesrv::reqstate rqs, 
				    ptr<acltargetlist> targets)
{
  if (!targets->get_allowop ()) {
    warn << "Allowop = false. Permission denied! \n";
    reject_nfs (sbp, targets, NFS3ERR_ACCES);        
    return;
  }  

  adjust_arg (sbp, targets); 
  AUTH *auth = auth_sfs; 
  void *res = nfs_program_3.tbl[sbp->proc ()].alloc_res ();
  
  switch (sbp->proc ()){
  case NFSPROC3_RENAME:
    {
      rqs.c->call (sbp->proc (), sbp->Xtmpl getarg<void> (), res,
		   wrap (mkref (this), &client::renamecb_1, 
			 sbp, res, rqs, targets),
		   auth);
    }
    break;
  case NFSPROC3_REMOVE:
    {
      // Don't allow users to remove the .SFSACL file
      diropargs3 *removeargs = sbp->Xtmpl getarg<diropargs3> ();
      if (removeargs->name == SFSDIRACL) {
	// Pretend to succeed so things like rm -rf work
	pre_nfs3reply (sbp, res, rqs, targets, RPC_SUCCESS);
	return;
      }
      else
	rqs.c->call (sbp->proc (), sbp->Xtmpl getarg<void> (), res,
	    wrap (mkref (this), &client::pre_nfs3reply, 
	      sbp, res, rqs, targets),
	    auth);
    }
    break;
  case NFSPROC3_RMDIR:
    {
      // When removing directories, remove the .SFSACL file first
      lookup3res *lres = New lookup3res;
      rqs.c->call (NFSPROC3_LOOKUP, sbp->Xtmpl getarg<void> (), lres,
		   wrap (mkref (this), &client::rmdircb_1, 
	                 sbp, res, lres, rqs, targets),
		   auth);
    }
    break;
  case NFSPROC3_MKNOD:
    {
      mknod3args *nodargs = sbp->Xtmpl getarg<mknod3args> ();
      
      //change auth from auth_sfs to auth_sfssock / auth_sfsfifo
      switch (nodargs->what.type) {
      case NF3SOCK:
	auth = auth_sfssock;
	break;
      case NF3FIFO:
	auth = auth_sfsfifo;
	break;
      case NF3CHR:	
      case NF3BLK:
      default:
	warn << "Trying to create node of unsupported type \n " ;
	reject_nfs (sbp, targets, NFS3ERR_NOTSUPP, res);	
	return;
      }
      
      //instead of a NF3SOCK, NF3FIFO create NF3REG file
      create3args args;
      args.where = nodargs->where;
      args.how.set_mode (UNCHECKED);
      *args.how.obj_attributes = *nodargs->what.pipe_attributes;
      rqs.c->call (NFSPROC3_CREATE, &args, res,
		   wrap (mkref (this), &client::pre_nfs3reply, 
			 sbp, res, rqs, targets),
		   auth);
      break;
    }
  default:
    {
      rqs.c->call (sbp->proc (), sbp->Xtmpl getarg<void> (), res,
		   wrap (mkref (this), &client::pre_nfs3reply, 
			 sbp, res, rqs, targets),
		   auth);
    }
    
  }
}

//gets reply from NFS server, take a detour to write acl 
//if necessary

//the original nfs3reply function has been broken into two:
//pre_nfs3 reply and final_nfs3reply
//in-between, we write the acl for newly-created files or directories
//(mknod, create, mkdir)
void
client::pre_nfs3reply (svccb *sbp, void *res, filesrv::reqstate rqs, 
		   ptr<acltargetlist> targets, clnt_stat err)
{
  if (err) {
    final_nfs3reply (sbp, res, rqs, targets, err);
    return;
  }

  switch (sbp->proc ()){
  case NFSPROC3_CREATE:
  case NFSPROC3_MKNOD:
    {
      //what to write
      str aclstr = targets->first ()->get_aclstr ();	

      //where to write it;
      diropres3 *diropres = static_cast<diropres3 *> (res);
      nfs_fh3 fh;
      if (!get_diropresfh (diropres, fh)) {
	warn << "Failed to get fh for newly created file."
	     << "Can't write acl. \n";
	reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT, res);	    
	return;
      } else
	write_acl (sbp, res, rqs, targets, fh, aclstr);
    }
    break;	
  case NFSPROC3_MKDIR:
    {
      //create acl file inside directory
      //get directory's fh
      diropres3 *diropres = static_cast<diropres3 *> (res);
      nfs_fh3 fh;
      if (!get_diropresfh (diropres, fh)) {
	warn << "Failed to get fh for newly created directory."
	     << "Can't create acl file for directory. \n";
	reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT, res);	    
	return;
      } else
	create_diracl (sbp, res, rqs, targets, fh);
    }
    break;
  default:
    final_nfs3reply (sbp, res, rqs, targets, err);
  }
  
}

//adjust the response and send it
void
client::final_nfs3reply (svccb *sbp, void *res, filesrv::reqstate rqs, 
			  ptr<acltargetlist> targets, clnt_stat err)
{
  xdrproc_t xdr = nfs_program_3.tbl[sbp->proc ()].xdr_res;
  if (err) {
    xdr_delete (xdr, res);
    targets = NULL;
    sbp->reject (SYSTEM_ERR);
    return;
  }

  adjust_res (sbp, res, targets);		   // does exp_enable
  doleases (fsrv, generation, rqs.fsno, sbp, res); // does exp_enable again
  if (fsrv->fixres (sbp, res, &rqs)) {
    nfs3_exp_enable (sbp->proc (), res);	   // and again! is this OK?
    sbp->reply (res);
  }

  targets = NULL;
  xdr_delete (xdr, res);
}

void
client::getacl_reply (svccb *sbp, read3res *res, filesrv::reqstate rqs, 
		      ptr<acltargetlist> targets, clnt_stat err)
{
  xdrproc_t xdr = nfs_program_3.tbl[NFSPROC3_READ].xdr_res;
  if (err) {
    xdr_delete (xdr, res);
    targets = NULL;
    sbp->reject (SYSTEM_ERR);
    return;
  }
  
  adjust_res (sbp, res, targets);	// does exp_enable
  sbp->reply (res);			// forget about leases
  targets = NULL;
  xdr_delete (xdr, res);
}

void
client::setacl_reply (svccb *sbp, write3res *res, filesrv::reqstate rqs, 
		      ptr<acltargetlist> targets, clnt_stat err)
{
  xdrproc_t xdr = nfs_program_3.tbl[NFSPROC3_WRITE].xdr_res;
  if (err) {
    xdr_delete (xdr, res);
    targets = NULL;
    sbp->reject (SYSTEM_ERR);
    return;
  }
  
  acltarget *entry = targets->first ();
  acltargetlist::invalidate_centry (entry);

  adjust_res (sbp, res, targets);	// does exp_enable
  sbp->reply (res);			// forget about leases
  targets = NULL;
  xdr_delete (xdr, res);
}

void
client::reject_cleanup (svccb *sbp, void *res, ptr<acltargetlist> targets)
{
  targets = NULL;
  if (res){
    xdrproc_t xdr = nfs_program_3.tbl[sbp->proc ()].xdr_res;
    xdr_delete (xdr, res);
  }
}

void
client::reject_request (svccb *sbp, ptr<acltargetlist> targets, 
			accept_stat stat, void *res)
{
  sbp->reject (stat);
  reject_cleanup (sbp, res, targets);
}

void
client::reject_nfs (svccb *sbp, ptr<acltargetlist> targets, 
		    nfsstat3 status, void *res)
{
  nfs3exp_err (sbp, status);
  reject_cleanup (sbp, res, targets);
}

void
client::reject_request (svccb *sbp, ptr<acltargetlist> targets, 
			auth_stat stat, void *res)
{
  sbp->reject (stat);
  reject_cleanup (sbp, res, targets);
}

void
client::rmdircb_3 (svccb *sbp, void *_res, wccstat3 *wres,
                    filesrv::reqstate rqs,
		    ptr<acltargetlist> targets, clnt_stat err)
{
  AUTH *auth = auth_sfs;

  if (err || !wres || !auth) {
    warn << "RMDIR: failed because REMOVE of .SFSACL failed\n";
    reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT);
    if (wres)
      delete wres;
    return;
  }
  if (wres->status == NFS3ERR_NOENT)
    warn << "RMDIR: REMOVE couldn't find .SFSACL; trying RMDIR anyway\n";

  rqs.c->call (sbp->proc (), sbp->Xtmpl getarg<void> (), _res,
	       wrap (mkref (this), &client::pre_nfs3reply, 
		     sbp, _res, rqs, targets),
	       auth);

  delete wres;
}

void
client::rmdircb_2 (ptr<sbpandres> sr, readdir3res *rres,
                   ptr<nfs_fh3> fhp, filesrv::reqstate rqs,
                   ptr<acltargetlist> targets, clnt_stat err)
{
  AUTH *auth = auth_sfs;

  if (err || !rres || rres->status || !auth) {
    warn << "RMDIR: failed because READDIR failed\n";
    reject_nfs (sr->sbp, targets, NFS3ERR_SERVERFAULT);
    if (rres)
      delete rres;
    return;
  }

  int n = 0;
  entry3 *ep = rres->resok->reply.entries;
  if (ep)
    for (;;) {
      n++;
      entry3 *nep = ep->nextentry;
      if (!nep)
	break;
      ep = nep;
    }

  // assume that 3 means ".", "..", and ".SFSACL"
  if (n > 3) {
    warn << "RMDIR: directory isn't empty\n";
    reject_nfs (sr->sbp, targets, NFS3ERR_NOTEMPTY);
    delete rres;
    return;
  }

  diropargs3 removeargs;
  removeargs.dir = *fhp;
  removeargs.name = SFSDIRACL;

  wccstat3 *wres = New wccstat3;
  rqs.c->call (NFSPROC3_REMOVE, &removeargs, wres,
	       wrap (mkref (this), &client::rmdircb_3,
		     sr->sbp, sr->res, wres, rqs, targets), 
	       auth);

  delete rres;
}

void
client::rmdircb_1 (svccb *sbp, void *_res, lookup3res *lres, 
                   filesrv::reqstate rqs,
		   ptr<acltargetlist> targets, clnt_stat err)
{
  AUTH *auth = auth_sfs;

  if (err || !lres || lres->status || !auth) {
    warn << "RMDIR: failed because LOOKUP failed\n";
    reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT);
    if (lres)
      delete lres;
    return;
  }

  ptr<nfs_fh3> fhp = New refcounted<nfs_fh3>;
  if (!get_lookupresfh (lres, fhp)) {
    warn << "RMDIR: Failed to get fh for the dir we're deleting.";
    delete lres;
    reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT);
    return;
  }
  if (lres->resok->obj_attributes.present
      && lres->resok->obj_attributes.attributes->type != NF3DIR) {
    warn << "RMDIR: Lookup did not return a fh for a directory\n";
    delete lres;
    reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT);
    return;
  }

  // this is a workaround wrap()'s 7 argument limitation
  ref<sbpandres> sr = New refcounted<sbpandres>;
  sr->sbp = sbp;
  sr->res = _res;

  readdir3args readdirargs;
  readdirargs.dir = *fhp;
  readdirargs.cookie = 0;
  readdirargs.count = 8192;

  readdir3res *rres = New readdir3res;
  rqs.c->call (NFSPROC3_READDIR, &readdirargs, rres,
	       wrap (mkref (this), &client::rmdircb_2,
		     sr, rres, fhp, rqs, targets), 
	       auth);

  delete lres;
}

// if the response to LOOKUP indicates that object == NF3REG,
// adjust the size before dolease (probably doesn't matter: won't
// be seen by anyone (?)
void
client::renamecb_2 (svccb *sbp, rename3res *rres, filesrv::reqstate rqs,
		    lookup3res *ares, ptr<acltargetlist> targets, 
		    clnt_stat err)
{
  if (!err && !ares->status) {
    xattr xa;
    xa.fh = &ares->resok->object;
    if (ares->resok->obj_attributes.present) {
      xa.fattr = reinterpret_cast<ex_fattr3 *>
	(ares->resok->obj_attributes.attributes.addr ());
      if (xa.fattr->type == NF3REG)
	xa.fattr->size -= ACLSIZE;
    }
    dolease (fsrv, 0, static_cast<u_int32_t> (-1), &xa);
  }
  pre_nfs3reply (sbp, rres, rqs, targets, RPC_SUCCESS);
  delete ares;
}

void
client::renamecb_1 (svccb *sbp, void *_res, filesrv::reqstate rqs,
		    ptr<acltargetlist> targets, clnt_stat err)
{
  rename3res *res = static_cast<rename3res *> (_res);
  AUTH *auth = auth_sfs;

  if (err || !res || res->status || !auth) {
    pre_nfs3reply (sbp, res, rqs, targets, err);
    return;
  }

  // otherwise, wrap needs 8 args: bad
  //   targets->set_allowop (allowop); 
  // moved to point where decision is made
  lookup3res *ares = New lookup3res;
  rqs.c->call (NFSPROC3_LOOKUP, &sbp->Xtmpl getarg<rename3args> ()->to,
	       ares, wrap (mkref (this), &client::renamecb_2,  
			   sbp, res, rqs, ares, targets), 
	       auth);
}

// gets the acl (s) needed for the type of request [if any]
// when done, it calls nfs3post_acl_dispatch
void
client::aclresolve (svccb *sbp, filesrv::reqstate rqs, 
		    ptr<acltargetlist> targets) 
{
#if ACL_TEST
  str userkey;
  get_userkey (sbp, userkey);
  warn << "\nConnected user is "<< userkey << "\n";
#endif 

  assert (targets);
  
#if ACL_CACHE 
  if (!targets->is_done ())
    targets->check_cache ();
#endif
  if (targets->is_done ()) {
    nfs3post_acl_dispatch (sbp, rqs, targets);	  
    return;
  }
  else { 
    targets->touch ();	  
    acltarget *entry = targets->next_entry ();
    assert (entry);
    
    //if we know the fh of the file where the ACL lives,
    //go read the file. 
    //Otherwise, if we have the fh of a directory
    //proceed to get fh for /.SFSACL
    //Else, if we have no idea what kind of fh we are dealing with, 
    //go figure it out.
    //note: types of fh are set by fix_targets ()
 
    if (entry->aclfh_known ()) 
      aclresolve_file (sbp, rqs, targets);
    else {
      switch (entry->get_objecttype ()) {
      case unknown:
	aclresolve_type (sbp, rqs, targets);
	break;
      case dir:
	aclresolve_dir (sbp, rqs, targets);
	break;
      default: 
	entry->set_error ();
	aclresolve (sbp, rqs, targets);
      }  
    }
  }
}

void 
client::aclresolve_type (svccb *sbp, filesrv::reqstate rqs,
			 ptr<acltargetlist> targets)
{
  acltarget *entry = targets->next_entry (); 
  assert (entry);
  assert (entry->get_objecttype () == unknown);
  
  nfs_fh3 *args =  entry->get_objectfhp (); 
  getattr3res *res = New getattr3res; 
  
  rqs.c->call (NFSPROC3_GETATTR, args ,res, 
	       wrap (mkref (this), &client::aclresolve_type_cb, sbp, rqs, res,
		     targets), 
	       auth_sfs);
}

void
client::aclresolve_type_cb (svccb *sbp, filesrv::reqstate rqs,
			    getattr3res *res, ptr<acltargetlist> targets, 
			    clnt_stat err)
{
#if ACL_TEST
  warn << "aclresolve_type \n";
#endif
  acltarget *entry = targets->next_entry (); 
  assert (entry);
  assert (entry->get_objecttype () == unknown);

  if (err || !res || res->status) { 
    entry->set_error ();
    warn << "In aclresolve_type_cb:\n"
	 << "error when issuing GETATTR to determine obj type\n";
  }
  else {
    switch (res->attributes->type) {
    case NF3REG:
      entry->set_objecttype (file);
      break;
    case NF3DIR:
      entry->set_objecttype (dir);
      break;
    default:
      entry->set_objecttype (other);
      break;
    }
  }
  delete res;  
  aclresolve (sbp, rqs, targets);
  
}

//we have a dir, so get fh for /.SFSACL
void 
client::aclresolve_dir (svccb *sbp, filesrv::reqstate rqs,
			 ptr<acltargetlist> targets)
{ 
  acltarget *entry = targets->next_entry ();
  assert (entry);
  assert (entry->get_objecttype () == dir);
  
  diropargs3 args;
  args.dir = *entry->get_objectfhp ();
  args.name = SFSDIRACL;

  lookup3res *res = New lookup3res;
  
  rqs.c->call (NFSPROC3_LOOKUP, &args ,res, 
	       wrap (mkref (this), &client::aclresolve_dir_cb, sbp, rqs, res,
		     targets), 
	       auth_sfs);
}

void
client::aclresolve_dir_cb (svccb *sbp, filesrv::reqstate rqs,
			   lookup3res *res, ptr<acltargetlist> targets, 
			   clnt_stat err)
{
#if ACL_TEST
  warn << "aclresolve_dir \n";
#endif

  acltarget *entry = targets->next_entry ();
  assert (entry);
  assert (entry->get_objecttype () == dir);

  if (err || !res || res->status) {
    entry->set_error ();
    warn << "In aclresolve_dir_cb: NFS error when doing LOOKUP to determine " 
	    "fh storing dir's acl\n";
  }
  else 
    entry->set_aclfh (&res->resok->object);
  
  delete res;  
  aclresolve (sbp, rqs, targets);
}

//go read the acl
void 
client::aclresolve_file (svccb *sbp, filesrv::reqstate rqs,
			 ptr<acltargetlist> targets)
{
  acltarget *entry = targets->next_entry ();
  assert (entry);
  assert (entry->aclfh_known ());
  
  read3args args;
  args.file = *entry->get_aclfhp ();
  args.offset = ACLOFFSET;
  args.count = ACLSIZE;
  
  read3res *res = New read3res; 
  rqs.c->call (NFSPROC3_READ, &args, res, 
	       wrap (mkref (this), &client::aclresolve_file_cb, sbp,rqs, res,
		     targets),
	       auth_sfs);
}

void
client::aclresolve_file_cb (svccb *sbp, filesrv::reqstate rqs,
			    read3res *res, ptr<acltargetlist> targets,
			    clnt_stat err)
{
#if ACL_TEST
  warn << "aclresolve_file (reading ACL)\n";
#endif
  acltarget *entry = targets->next_entry ();
  assert (entry);
  assert (entry->aclfh_known ());
  
  if (err || !res || res->status) {
    entry->set_error ();
    warn << "aclresolve_file_cb:\n"
	 << "NFS error when doing READ to get file's acl\n";
  } 
 else {
    size_t reslen = res->resok->data.size ();
    char *resbuf = res->resok->data.base ();   
    str aclcontents (resbuf, reslen);
  
    if (reslen <= 0) 
      entry->set_error ();
    else 
      entry->set_aclstr (aclcontents);	 
  }
#if ACL_CACHE
  acltargetlist::insert_cache (entry);
#endif

  delete res;
  aclresolve (sbp, rqs, targets);
}

//gets the credtab entry corresponding to the user
//gets the acl (s) corresponding to what he's trying to access
//checks the perms corresponding to (user, acl)
//sets the perms in targets
//returns true if completed correctly
bool  
client::get_aclpermissions (svccb *sbp, filesrv::reqstate rqs,
			    ptr<acltargetlist> targets)
{
  if (targets->has_error ())
    return false;

  u_int32_t authno = sbp->getaui ();
  sfsauth_cred *cred = NULL;
  str *key = NULL;
  vec<sfs_idname> *groups = NULL;
 
  if (authno < 0)  
    return false;
 
  if (authno == 0) // anonymous
    cred = NULL;
  
  /* changed by kaminsky */
  if (authno > 0) {
    if (authno < credtab.size ())
      cred = &credtab[authno];
    if (authno < keytab.size ())
      key = &keytab[authno];
    if (authno < groupstab.size ())
      groups = &groupstab[authno];

    if (!cred && !key && !groups) {
      warn << "Invalid authno corresponding to user. Aborting \n";
      return false;
    }
    if (cred && cred->type != SFS_UNIXCRED)
      cred = NULL;
    if (!cred && !key && !groups)
      warn << "non-anonymous user lacks any known credential type\n";
  }
  
  if (targets->first ()->has_aclstr ()) {
    str first_aclstr = targets->first ()->get_aclstr ();
    acl first_acl (first_aclstr);
    u_int p1 = first_acl.get_permissions (cred, key, groups);
    targets->set_p1 (p1);
  } else {
    if (!sbp->proc () == NFSPROC3_FSINFO)
      warn << "ACL not set for first (default) ACL target \n" ;
    return false;
  }

  if (sbp->proc () == NFSPROC3_RENAME) {
    if (targets->second ()->has_aclstr ()) {
      str second_aclstr = targets->second ()->get_aclstr ();
      acl second_acl (second_aclstr);
      u_int p2 = second_acl.get_permissions (cred, key, groups);
      targets->set_p2 (p2);
    } else {
      warn << "ACL not set for second ACL target (for rename) \n" ;
      return false;
    }
    
  }
  return true;
}

bool
client::decide_access (svccb *sbp, ptr<acltargetlist> targets)
{
  assert (targets);
  u_int p1 = targets->get_p1 ();
  u_int p2 = targets->get_p2 ();

  bool d = false;  

  switch (sbp->proc ()) {
  case NFSPROC3_NULL:
    d = true; //unreachable
    break;
  case NFSPROC3_GETATTR:
    d = true; 
    break;
  case NFSPROC3_SETATTR:  
    d = (p1 & SFSACCESS_WRITE) || // (p1 & SFSACCESS_READ) ||
      (p1 & SFSACCESS_ADMINISTER) ;
    break;
  case NFSPROC3_LOOKUP:
    d = p1 & SFSACCESS_LIST;
    break;
  case NFSPROC3_ACCESS:
    d = true; 
    break;
  case NFSPROC3_READLINK: // always allow (dm's suggestion)
    d = true; 
    break;
  case NFSPROC3_READ:
    d = p1 & SFSACCESS_READ;
    break;
  case NFSPROC3_WRITE:
    d = p1 & SFSACCESS_WRITE;
    break;
  case NFSPROC3_CREATE:
    d = p1 & SFSACCESS_INSERT;
    break;
  case NFSPROC3_MKDIR:
    d = p1 & SFSACCESS_INSERT;
    break;
  case NFSPROC3_SYMLINK:
    d = p1 & SFSACCESS_INSERT;
    break;
  case NFSPROC3_MKNOD: 
    d = p1 & SFSACCESS_INSERT;
    break;
  case NFSPROC3_REMOVE:
    d = (p1 & SFSACCESS_DELETE) || (p1 & SFSACCESS_ADMINISTER);
    break;   
  case NFSPROC3_RMDIR:
    d = (p1 & SFSACCESS_DELETE) || (p1 & SFSACCESS_ADMINISTER);
    break;   
  case NFSPROC3_RENAME:
    d = ((p1 & SFSACCESS_DELETE) || (p1 & SFSACCESS_ADMINISTER)) 
      && (p2 & SFSACCESS_INSERT);
    break;
  case NFSPROC3_LINK:
    d = p1 & SFSACCESS_INSERT;
    break;   
  case NFSPROC3_READDIR:
    d = p1 & SFSACCESS_LIST;
    break;    
  case NFSPROC3_READDIRPLUS:
    d = p1 & SFSACCESS_LIST;
    break;    
  case NFSPROC3_FSSTAT:
    d = true;
    break;
  case NFSPROC3_FSINFO:
    d = true;
    break;
  case NFSPROC3_PATHCONF:
    d = true;
    break;
  case NFSPROC3_COMMIT:
    d = true;
    break;
  case ex_NFSPROC3_GETACL:
    d = true; //p1 & SFSACCESS_ADMINISTER;
    break;
  case ex_NFSPROC3_SETACL:
    d = p1 & SFSACCESS_ADMINISTER;
    break;
  default:
    d = false;
    break;
  }
 
  targets->set_allowop (d);
  return d;
}

bool
client::get_userkey (svccb *sbp, str &pk)
{
  u_int32_t authno = sbp->getaui ();
  str *key;

  pk = "";

  /* changed by kaminsky from what savvides had */
  if (authno > 0) {
    if (authno >= keytab.size () || !(key = &keytab[authno])) {
      warn << "authno does not correspond to a user with a PK hash\n";
      return false;
    }
    pk = strbuf () << TYPEPK << ACLDIV << *key; 
  }
  else if (authno == 0)
    pk = strbuf () << TYPESYS << ACLDIV << SYS_ANONYMOUS;
  else
    return false;

  return true;
}

//after mkdir, we must write the new dir's acl
//first, create the new file and in create_diracl_cb
//if creation worked, use write_acl (as in the case of newly-created file)
//to write the acl
void
client::create_diracl (svccb *sbp, void *res, filesrv::reqstate rqs, 
		       ptr<acltargetlist> targets, nfs_fh3 fh)
{
  create3args cargs;
  diropres3 *cres = New diropres3;

  cargs.where.dir = fh;
  cargs.where.name = SFSDIRACL;
  cargs.how.set_mode (UNCHECKED);

  cargs.how.obj_attributes->mode.set_set (true); 
  *cargs.how.obj_attributes->mode.val = CREATEACL_MODE;

  rqs.c->call (NFSPROC3_CREATE, &cargs, cres,
	       wrap (mkref (this), &client::create_diracl_cb, 
		     sbp, res, rqs, targets, cres),
	       auth_sfs);  
}

void
client::create_diracl_cb (svccb *sbp, void *res, filesrv::reqstate rqs, 
			  ptr<acltargetlist> targets, diropres3 *cres, 
			  clnt_stat err)
{
  if (err || !cres) {
    warn << "Failed to create ACL for newly created directory \n ";
    delete cres;
    reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT, res);    
    return;
  } else {

    //get fh of newly created file
    //get acl string you want to write	 
    //and write it...
    
    nfs_fh3 fh;
    if (!get_diropresfh (cres, fh)) {
      warn << "Failed to get fh for dir's acl file."
	   <<"Can't write acl. \n";
      delete cres;
      reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT, res);    
      return;
    }
    str aclstr = targets->first ()->get_aclstr ();     
    write_acl (sbp, res, rqs, targets, fh, aclstr);
  } 

  delete cres; //gets deleted in all cases, good and bad
}

void
client::write_acl (svccb *sbp, void *res, filesrv::reqstate rqs, 
		   ptr<acltargetlist> targets, nfs_fh3 fh, str aclstr)
{
  write3args wargs;
  write3res *wres = New write3res; 
  wargs.file = fh;
  wargs.offset = ACLOFFSET;
  wargs.count = aclstr.len ();
  wargs.stable = DATA_SYNC;
  wargs.data.setsize (aclstr.len ());
  memcpy (wargs.data.base (), aclstr.cstr (), aclstr.len ());
  
  if (aclstr.len () != ACLSIZE){
    warn << "ACL size mismatch.\nExpected: " << ACLSIZE
	 << "\nActual: " << aclstr.len ();
  }
     
  rqs.c->call (NFSPROC3_WRITE, &wargs, wres,
	       wrap (mkref (this), &client::write_acl_cb, 
		     sbp, res, rqs, targets, wres),
	       auth_sfs);
}

void
client::write_acl_cb (svccb *sbp, void *res, filesrv::reqstate rqs, 
		   ptr<acltargetlist> targets, write3res *wres, clnt_stat err)
{
  if (err || wres->status) {
    warn << "Failed to write ACL \n";
    delete wres;
    reject_nfs (sbp, targets, NFS3ERR_SERVERFAULT, res);    
    return;
  } 

  if (wres->status == NFS3_OK && wres->resok->count < ACLSIZE) {
    //short write, but don't abort
    warn << "When writing ACL, bytes written = " 
      << wres->resok->count
      << "\nExpected: " << ACLSIZE;

  }
  else //everything's fine 
    final_nfs3reply (sbp, res, rqs, targets, RPC_SUCCESS);
  
  delete wres; //gets deleted in all cases
}

bool
client::get_diropresfh (diropres3 *diropres, nfs_fh3 &fh)
{
  if (!diropres || diropres->status || !diropres->resok->obj.present)
    return false;
  else {
    fh = *diropres->resok->obj.handle;
    return true;
  }
}

bool
client::get_lookupresfh (lookup3res *lookupres, ptr<nfs_fh3> fhp)
{
  if (!lookupres || lookupres->status)
    return false;
  else {
    *fhp = lookupres->resok->object;
    return true;
  }
}

// for each type of NFS call, identify:
// the fh of the object (two of them in rename)
// the type of object (file, dir, other, unknown)
bool
client::fix_targets (svccb *sbp, ptr<acltargetlist> targets) 
{
  acltarget *t1 = targets->first ();
  acltarget *t2 = targets->second ();
  assert (t1);
  assert (t2);
 
  switch (sbp->proc ()) {
  case NFSPROC3_NULL:  //unreachable
    targets->set_resolved ();
    break;
  case NFSPROC3_GETATTR:
    targets->set_resolved ();
    break;
  case NFSPROC3_SETATTR:
    t1->set_objectfh (&sbp->Xtmpl getarg<setattr3args> ()->object,
		      unknown);  
    break;
  case NFSPROC3_LOOKUP:
    t1->set_objectfh (&sbp->Xtmpl getarg<diropargs3> ()->dir, 
		      dir);
    break;
  case NFSPROC3_ACCESS: 
    t1->set_objectfh (&sbp->Xtmpl getarg<access3args> ()->object,
		      unknown);
    break;
  case NFSPROC3_READLINK: //won't store ACL for each link
    targets->set_resolved ();
    break;
  case NFSPROC3_READ:
    t1->set_objectfh (&sbp->Xtmpl getarg<read3args> ()->file,
		      file);
    break;
  case NFSPROC3_WRITE:
    t1->set_objectfh (&sbp->Xtmpl getarg<write3args> ()->file, 
		      file);
   break;
  case NFSPROC3_CREATE:
    t1->set_objectfh (&sbp->Xtmpl getarg<create3args> ()->where.dir,
		      dir);
    break;
  case NFSPROC3_MKDIR:
    t1->set_objectfh (&sbp->Xtmpl getarg<mkdir3args> ()->where.dir, 
		      dir);
    break;
  case NFSPROC3_SYMLINK:
    t1->set_objectfh (&sbp->Xtmpl getarg<symlink3args> ()->where.dir, 
		      dir);
    break;
 case NFSPROC3_MKNOD:
    t1->set_objectfh (&sbp->Xtmpl getarg<mknod3args> ()->where.dir, 
		      dir);
   break;
  case NFSPROC3_REMOVE:
    t1->set_objectfh (&sbp->Xtmpl getarg<diropargs3> ()->dir, 
		      dir);  
    break;
 case NFSPROC3_RMDIR:
    t1->set_objectfh (&sbp->Xtmpl getarg<diropargs3> ()->dir,
		      dir);
   break;
  case NFSPROC3_RENAME:
    t1->set_objectfh (&sbp->Xtmpl getarg<rename3args> ()->from.dir, 
		      dir);
    t2->set_objectfh (&sbp->Xtmpl getarg<rename3args> ()->to.dir, 
		      dir);
    break;
  case NFSPROC3_LINK:
    t1->set_objectfh (&sbp->Xtmpl getarg<link3args> ()->link.dir, 
		      dir);
    break;
  case NFSPROC3_READDIR:
    t1->set_objectfh (&sbp->Xtmpl getarg<readdir3args> ()->dir, 
		      dir);
    break;
  case NFSPROC3_READDIRPLUS:
    t1->set_objectfh (&sbp->Xtmpl getarg<readdirplus3args> ()->dir, 
		      dir);
    break;
  case NFSPROC3_FSSTAT:
    targets->set_resolved ();
    break;
  case NFSPROC3_FSINFO:
    targets->set_resolved ();
    break;
  case NFSPROC3_PATHCONF:
    targets->set_resolved ();
    break;
  case NFSPROC3_COMMIT:
    targets->set_resolved ();
    break;
  default:
    targets->set_resolved ();
  } 
  return true;
}

// ************** rpc traversal functions ***************

// 1. ADJUST ARGUMENTS TO NFS PROC. CALL
// read3args, write3args :  offset += ACLSIZE
// sattr3 : if size.set, size.val += ACLSIZE
//also: give perms to sfs-owner only (in sattr structures)

struct adjust_rw_arg {
};

DUMBTRAVERSE (adjust_rw_arg)

bool
rpc_traverse (adjust_rw_arg &rwa, read3args &arg)
{
  arg.offset += ACLSIZE;
  return true;
}

bool
rpc_traverse (adjust_rw_arg &rwa, write3args &arg)
{
  arg.offset += ACLSIZE;
  return true;
}

struct adjust_sattr_arg {
  u_int p;
  bool isdir;
  
  adjust_sattr_arg (u_int a, bool d) 
    : p (a), isdir (d) {}
};

DUMBTRAVERSE (adjust_sattr_arg)
  
bool
rpc_traverse (adjust_sattr_arg &sarg, sattr3 &arg)
{
#define ADMINUMASK 0077
#define OTHERUMASK 0777
  bool has_admin  = sarg.p & SFSACCESS_ADMINISTER;  
  
  //nobody can set uid, gid
  arg.uid.set_set (false);
  arg.gid.set_set (false);
  
  if (arg.size.set)
    *arg.size.val += ACLSIZE;

      //for directories (which need the x bit to be on)
      //treat everyone as an administrator

      //for files, let admin do whatever he wants with the x bit
      //and remove the bits of others

  if (arg.mode.set) {
    if (sarg.isdir) {
      *arg.mode.val &= ~ADMINUMASK;
      *arg.mode.val |= 0600; //owner always has r/w perms
    }
    if (!sarg.isdir) {
      if (has_admin) {
	*arg.mode.val &= ~ADMINUMASK;
	*arg.mode.val |= 0600; //owner always has r/w perms
      }
      else 
	arg.mode.set_set (false);
    }
  }
  
  //only admin can set atime/mtime to client time.
  if ((arg.atime.set == SET_TO_CLIENT_TIME) &&
      (!has_admin)) 
    arg.atime.set_set (DONT_CHANGE);
  
  if ((arg.mtime.set == SET_TO_CLIENT_TIME) &&
      (!has_admin)) 
    arg.mtime.set_set (DONT_CHANGE);

  return true;
}

//    arg.mode.set_set (false);	
//
//    if (arg.mode.set)
//	{
//	  if (has_admin)
//	*arg.mode.val &= ~ADMINUMASK;
//	  else
//	*arg.mode.val &= ~OTHERUMASK;
//	  *arg.mode.val |= 0600; //owner always has r/w perms

//	}

  //worked
//    if (arg.mode.set)
//	  {
//	    *arg.mode.val &= (~CREATEUMASK); //077 to remove all but owner
//	    *arg.mode.val |= 600; // make sure owner has r/w permissions
//	  }

// the following causes trouble...

//    if (arg.mode.set && !sarg.has_administer)
//	arg.mode.set_set (false); 

  
  //	if (! sarg.has_administer) {
  
  //	  arg.atime.set_set (DONT_CHANGE);
  //	  arg.mtime.set_set (DONT_CHANGE);

  //	}

void
adjust_arg (svccb *sbp,  ptr<acltargetlist> targets)
{
  u_int p = targets->get_p1 ();
  bool isdir = false;
  if (p) {
    acltarget *t1 = targets->first ();
    assert (t1);
    if (t1->get_objecttype () == dir)
      isdir = true;
    else
      isdir = false;	    
  }

//  bool administer = p & SFSACCESS_ADMINISTER; 
  
  adjust_rw_arg arw; // read/write offsets += ACLSIZE
  adjust_sattr_arg asattr (p, isdir); // if size.set, size.val += ACLSIZE
  
  nfs3_traverse_arg (arw, sbp->proc (), sbp->Xtmpl getarg<void> ());
  nfs3_traverse_arg (asattr, sbp->proc (), sbp->Xtmpl getarg<void> ());
}

// 2. ADJUST RESPONSES: 
// fattr, wattr : if NF3REG, size -= ACLSIZE (remove wattr if ftype missing)
// add acl permissions to access3resok.access

struct adjust_access3res 
{
  u_int p;
  u_int requested;

  adjust_access3res (u_int _p, u_int _r) 
    : p (_p), requested (_r) {
  }

  //change to give unconditional access
  //	adjust_access3res (u_int _p, u_int _r) 
  //	  : p (SFSACCESS_ALL), requested (_r) {}
};

DUMBTRAVERSE (adjust_access3res)

//  bool
//  rpc_traverse (adjust_access3res &acc, access3resok &res)
//  {

//    res.access = acc.requested;
//    return true;

//  }

bool
rpc_traverse (adjust_access3res &acc, access3resok &res)
{
  if (res.obj_attributes.present) {
    u_int nfsperms = sfs2nfsperms (acc.p, res.obj_attributes.attributes->type);
    res.access = nfsperms & acc.requested;

#if ACL_TEST
    warn ("Setting access bits to %#0x\n", res.access);
    warn ("Requested access bits were %#0x\n", acc.requested);
#endif
  }
  else
    warn << "\nObj attributes not present\n";
   
  return true;
}

void
adjust_res_size (svccb *sbp, void *res)
{
  xattrvec xv;
  nfs3_getxattr (&xv, sbp->proc (), sbp->getvoidarg (), res);
  for (xattr *xp = xv.base (); xp < xv.lim (); xp++) {
    if (xp->fattr && (xp->fattr->type == NF3REG)) {
      xp->fattr->size -= ACLSIZE;
      if (xp->wattr) 
	xp->wattr->size -= ACLSIZE;
    }
    if (xp->wattr && !xp->fattr) 
      xp->wdata->before.set_present (false);
  }
}

void
adjust_res_mode (svccb *sbp, void *res, adjust_access3res &acc)
{
  //  u_int nfsperms = sfs2nfsperms (acc.p, res.obj_attributes.attributes->type);
  u_int m;
  u_int x = NFSMODE_XOWN | NFSMODE_XGRP | NFSMODE_XOTH ;
  xattrvec xv;
  nfs3_getxattr (&xv, sbp->proc (), sbp->getvoidarg (), res);
  for (xattr *xp = xv.base (); xp < xv.lim (); xp++) {
    if (xp->fattr) {
      m = xp->fattr->mode;
      xp->fattr->mode = sfs2modebits (acc.p, xp->fattr->type);
      if (xp->fattr->type == NF3REG)
	xp->fattr->mode |= (m &  NFSMODE_XOWN ? x : 0 );
    }
  }
}

void 
adjust_res (svccb *sbp, void *res, ptr<acltargetlist> targets)
{
  assert (targets);
#if ACL_SETFS
  u_int sfsperms = SFSACCESS_ALL ;
#else
  u_int sfsperms = targets->get_p1 ();
#endif

  u_int requested; //either 0 or whatever perms were requested
  
  if (sbp->proc () == NFSPROC3_ACCESS)
    requested = sbp->Xtmpl getarg<access3args> ()-> access;
  else 
    requested = 0;
  
  adjust_access3res acc (sfsperms, requested); 
  
  if (sbp->proc () == NFSPROC3_ACCESS)
    nfs3_traverse_res (acc, sbp->proc (), res); 

  nfs3_exp_enable (sbp->proc (), res); //ok to do multiple times?
  adjust_res_size (sbp, res); // -= ACLSIZE for files only
  adjust_res_mode (sbp, res, acc);
}
