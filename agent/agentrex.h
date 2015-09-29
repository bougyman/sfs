// -*-c++-*-
/* $Id: agentrex.h,v 1.8 2004/09/19 22:02:20 dm Exp $ */

/*
 *
 * Copyright (C) 2000 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

#include "agent.h"
#include "rex_prot.h"
#include "rex.h"
#include "rexcommon.h"

class agentstartfd : public rexfd {
  // schost where first rexconnect came from
  str schost;
  cbi succeedcb;
  bool waitnewfd;
  sfsagent *a;
  int recvfd;

  void
  agentstarted (int *resp, clnt_stat err)
  {
    if (*resp || err) {
      warn << "could not start agent on " << schost << " : ";
      if (err)
	warn << err << "\n";
      else
	warn << strerror (*resp) << "\n";
      // should still succeed even if there's an agent already running
      succeedcb (1);
    }
    else {
      succeedcb (0);
      warn << "agent forwarding connection started\n";
    }
  }
  
public:

  agentstartfd (rexchannel *pch, int fd, cbi succeedcb, str schost)
    : rexfd (pch, fd), schost (schost), succeedcb (succeedcb),
      waitnewfd (true), a (NULL), recvfd (-1)
  {}

  ~agentstartfd () {
    if (recvfd >= 0)
      pch->remove_fd (recvfd);
    if (a)
      delete a;
  }
    
  virtual void
  newfd (svccb *sbp)
  {
    rexcb_newfd_arg *argp = sbp->Xtmpl getarg<rexcb_newfd_arg> ();

    waitnewfd = false;
    
    int s[2];

    if (socketpair (AF_UNIX, SOCK_STREAM, 0, s)) {
      warn << "error creating socketpair for agent forwarding\n";
      sbp->replyref (false);
      return;
    }

    make_async (s[1]);
    make_async (s[0]);

    a = New sfsagent (s[1]);
    a->setname (schost);
    a->cs = NULL;

    int *resp = New int;
    a->ac->call (AGENT_START, NULL, resp, wrap (this,
						&agentstartfd::agentstarted,
						resp)); 

    recvfd = argp->newfd;
    vNew refcounted<unixfd> (pch, recvfd, s[0]);

    sbp->replyref (true);
  }

  virtual void data (svccb *sbp) {
    rex_payload *argp = sbp->Xtmpl getarg<rex_payload> ();
    if (waitnewfd && !argp->data.size ()) {
      warn ("agent forward channel failure: EOF from suidconnect agent\n");
      warn ("NOTE: sfscd must be running on the remote machine for agent "
	    "forwarding to work.\n");
      succeedcb (1);
      rexfd::data (sbp);
      return;
    }
    sbp->replyref (true);
  }
};

class agentchannel : public rexchannel {
  str schost;
  cbi succeedcb;
public:
  agentchannel (rexsession *sess, vec<str> command, str schost,
		cbi succeedcb)
    : rexchannel (sess, 1, command), schost (schost), succeedcb (succeedcb)
    {}

  void madechannel (int error) {
    if (error) {
      //should probably still succeed even if we can't run "suidconnect agent"
      succeedcb (1);
    }
    else {
      vNew refcounted<agentstartfd> (this, 0, succeedcb, schost);
    }
  }
};

struct rexreq {
  callback<void, int>::ref cb;
  bool forwardagent;
  bool blockactive;
  bool resumable;
  rexreq (callback<void, int>::ref cb, bool fa, bool ba, bool r)
    : cb (cb), forwardagent (fa), blockactive (ba), resumable (r) {}
};

class rexsess {
  friend void knockout (rexsess *);

  ptr<sfscon> sessconn;
  sfs_connect_t *conpending;
  sfs_reconnect_t *rcpending;
  callbase *cbase;
  ptr<aclnt> sessclnt;
  ptr<aclnt> sfsclnt;
  sfs_sessinfo sessinfo;

  sfs_hash sessid;
  sfs_kmsg skeys;
  sfs_kmsg ckeys;
  sfs_seqno rex_seqno;

  vec<rexreq *> reqs;
  vec<rexreq *> afreqs;

  u_int32_t clients;
  u_int32_t resumable_clients;
  timecb_t *reaper;

  bool afpending;	    //  agent forwarding channel is being made
  rexsession *sess;
  callbase *probecall;
  timecb_t *probetmo;
  time_t probetime;
  time_t retry_delay;
  timecb_t *backoffcb;
  callbase *resumepending;

  ref<bool> destroyed;

  void connect_init ();
  bool connecting ();
  void connect_cancel ();

  void connect (bool force = true);
  void connect_inner (bool force);
  void connected (bool force, ptr<sfscon> sc, str err);
  void connected_crypt (bool force, ptr<sfscon> sc, str err);
  void spawn ();
  void spawned (ref<rexd_spawn_res> resp, clnt_stat err);
  void attach ();
  void attached (ref<rexd_attach_res> resp, clnt_stat err);
  void resumed (bool success);

  void fail ();
  bool proxy_fail ();
  bool proxy_timeout ();
  void reaped ();
  void probe ();
  void probed (clnt_stat err);
  void probetimeout ();
 
  bool active (time_t);
  void setresumable (bool);
  void rex_reply (cb_rex::ref cb, bool resumable, int error);
  void take_request (callback<void, int>::ref cb,
                     bool forwardagent, bool blockactive, bool resumable);
  void finish (rexreq *req, int error = 0);
  void af_init ();
  void af_init_done (int err);
  void alert_forwardedagent ();
  void alert_active ();
  void alert_badconnect ();
  void alert_fail ();
 
public:
  bool agentforwarded;	//  agent forwarding has been established
  str dest;
  str destuser;
  str path;
  str rexconnect_origin;
  ihash_entry<rexsess> link;

  rexsess (str dest, str path, str pathfrom,
           bool forwardagent, bool blockactive, bool resumable,
	   cb_rex::ptr firstcb);
  ~rexsess ();
  void client_died (sfs_seqno, bool resumable);
  void abort () { sess->abort (); }

  void rex_request (bool forwardagent, bool blockactive, bool resumable,
                    cb_rex::ref cb);
  void keepalive (svccb *);
};

