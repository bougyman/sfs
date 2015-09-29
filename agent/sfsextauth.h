/* $Id: sfsextauth.h,v 1.3 2002/08/21 13:54:45 max Exp $ */
/*
 *
 * Copyright (C) 2002 David Mazieres 
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
 */
#ifndef _SFSAGENT_SFSEXTAUTH_H
#define _SFSAGENT_SFSEXTAUTH_H 1

#include "agent.h"
#include "sfsmisc.h"
#include "arpc.h"
#include "agentconn.h"

// is there a way to make all methods "virtual" by default?
class sfsextauth {

 public:
  sfsextauth ();

  // XXX - important to close our axprt ?
  virtual ~sfsextauth () {}

  virtual bool connect ();
  virtual void register_with_agent () ;
  virtual void registration_cb (ptr<bool> res, clnt_stat err);
  virtual void dispatch (svccb *sbp);
  virtual void authinit (svccb *sbp) = 0;
  virtual void authmore (svccb *sbp)  
    { sbp->replyref (sfsagent_auth_res (false)); }
  virtual void set_name (str &s) = 0;
  virtual void clnt_eof () { eof = true; }
  virtual sfs_time get_expire_time () { return 0; }

  virtual void eofcb ();
    

 protected:
  int fd;
  bool eof;
  ref<agentconn> aconn;
  ptr<axprt_stream> ax;
  ptr<aclnt> ac;
  ptr<asrv> as;
  bool registered;

};

#endif /* _SFSAGENT_SFSEXTAUTH_H */
