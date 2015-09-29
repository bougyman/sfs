
/* $Id: sfsextauth.C,v 1.5 2002/08/30 06:04:27 max Exp $ */

/*
 *
 * Copyright (C) 1998, 1999 David Mazieres (dm@uun.org)
 * Copyright (C) 1999, 2000 Michael Kaminsky (kaminsky@lcs.mit.edu)
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


#include "sfskey.h"
#include "sfsextauth.h"
#include "agentconn.h"
#include "agentmisc.h"


sfsextauth::sfsextauth () : aconn (New refcounted<agentconn> ())
{
  registered = false;
}

void 
sfsextauth::eofcb () 
{ 
  warn ("Encountered EOF. Shutting down\n"); 
  exit (0); 
}


bool
sfsextauth::connect () 
{
  fd = aconn->cagent_fd();
  if (fd < 0) {
    warn << "Could not open Unix socket to sfsagent\n" ;
    return false;
  }
  close_on_exec (fd);

  ax = axprt_stream::alloc (fd);
  ac = aclnt::alloc (ax, agentctl_prog_1);
  eof = false;
  ac->seteofcb (wrap (this, &sfsextauth::clnt_eof));
  as = asrv::alloc (ax, sfsextauth_prog_1, wrap (this, &sfsextauth::dispatch));

  if (!ax || !ac || !as) {
    warn << "Could not open connection with sfsagent\n";
    return false;
  }
  return true;
}

void
sfsextauth::register_with_agent ()
{

  sfsagent_addextauth_arg arg;
  arg.pid = getpid ();
  set_name (arg.name);
  u_int i = get_expire_time ();
  arg.expire = i;
  
  ref<bool> res = New refcounted<bool> ();
  ac->call (AGENTCTL_ADDEXTAUTH, &arg, res, 
	    wrap (this, &sfsextauth::registration_cb, res));

}

void
sfsextauth::registration_cb (ptr<bool> res, clnt_stat err)
{
  if (!*res || err) {
    fatal << "Could not register with sfsagent\n";
  }
  registered = true;
}

void
sfsextauth::dispatch (svccb *sbp) 
{
  if (eof || !sbp) {
    eofcb ();
  }
  if (!registered) {
    warn ("This sfsextauth hasn't registered with the sfsagent yet!\n");
    sbp->reject (PROC_UNAVAIL);
  }

  switch (sbp->proc ()) {
  case SFSEXTAUTH_NULL:
    sbp->reply (NULL);
    break;
  case SFSEXTAUTH_AUTHINIT:
    authinit (sbp);
    break;
  case SFSEXTAUTH_AUTHMORE:
    authmore (sbp);
    break;
  default:
    warn ("invalid SFSEXTAUTH procno %d\n", sbp->proc ());
    sbp->reject (PROC_UNAVAIL);
  }
}

